"""
Master Orchestrator.

Two responsibilities:
  1. Get a repo onto local disk safely, from either an uploaded ZIP or a
     public GitHub URL (via codeload.github.com's zip endpoint — no git
     binary needed, no auth needed for public repos).
  2. Run the full repo-investigation pipeline (repo_intel -> threat_model
     -> attack_path) and hand back one combined result.

Security notes — both are real vulnerability classes for a tool whose
whole job is accepting untrusted archives, not hypothetical concerns:
  - Zip-slip path traversal: _safe_extract refuses any archive member
    whose resolved path would land outside the extraction directory.
  - Zip bombs: a malicious archive can be a few KB compressed and
    expand to gigabytes. _safe_extract enforces MAX_ZIP_UNCOMPRESSED_BYTES
    and MAX_ZIP_FILE_COUNT by counting actual bytes written during a
    streamed copy — not by trusting the zip's own declared file_size
    metadata, which a crafted archive can misreport.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
import zipfile

import requests

from . import attack_path, config, repo_intel, threat_model

_GITHUB_REPO_URL_RE = re.compile(
    r"^https?://github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$"
)

_COPY_CHUNK_BYTES = 1024 * 1024  # 1 MB per read — bounds peak memory regardless of member size


def _safe_extract(zf: zipfile.ZipFile, dest_dir: str) -> None:
    members = zf.infolist()

    if len(members) > config.MAX_ZIP_FILE_COUNT:
        raise ValueError(
            f"Refusing to extract: archive contains {len(members)} entries, "
            f"over the {config.MAX_ZIP_FILE_COUNT} limit."
        )

    dest_root = os.path.realpath(dest_dir)
    for member in members:
        target_path = os.path.realpath(os.path.join(dest_dir, member.filename))
        if target_path != dest_root and not target_path.startswith(dest_root + os.sep):
            raise ValueError(f"Refusing to extract unsafe zip entry (path traversal): {member.filename!r}")

    total_bytes_written = 0
    for member in members:
        target_path = os.path.join(dest_dir, member.filename)
        if member.is_dir():
            os.makedirs(target_path, exist_ok=True)
            continue

        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with zf.open(member) as source, open(target_path, "wb") as dest:
            while True:
                chunk = source.read(_COPY_CHUNK_BYTES)
                if not chunk:
                    break
                total_bytes_written += len(chunk)
                if total_bytes_written > config.MAX_ZIP_UNCOMPRESSED_BYTES:
                    raise ValueError(
                        f"Refusing to extract: archive exceeds the "
                        f"{config.MAX_ZIP_UNCOMPRESSED_BYTES // (1024 * 1024)}MB uncompressed size "
                        f"limit (zip-bomb protection). This is enforced by counting real bytes "
                        f"written during extraction, not the archive's own declared size."
                    )
                dest.write(chunk)


def extract_uploaded_zip(zip_path: str) -> str:
    """Extracts an uploaded ZIP to a fresh temp directory, returns that
    directory's path. Caller owns cleanup (shutil.rmtree) once done. On
    any safety-limit violation, the partial extraction is cleaned up
    before raising — never leaves a half-extracted zip bomb on disk."""
    dest_dir = tempfile.mkdtemp(prefix="repo_upload_")
    try:
        with zipfile.ZipFile(zip_path) as zf:
            _safe_extract(zf, dest_dir)
    except Exception:
        shutil.rmtree(dest_dir, ignore_errors=True)
        raise
    return dest_dir


def fetch_github_repo(repo_url: str, branch: str = "main") -> str:
    """Downloads a public GitHub repo's zip via codeload.github.com and
    extracts it to a fresh temp directory. Falls back to 'master' once if
    'main' 404s, since older repos still default to it. Caller owns
    cleanup (shutil.rmtree) once done."""
    match = _GITHUB_REPO_URL_RE.match(repo_url.strip())
    if not match:
        raise ValueError(f"Not a recognizable GitHub repo URL: {repo_url!r}")
    owner, repo = match.group("owner"), match.group("repo")

    zip_url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"
    try:
        resp = requests.get(zip_url, timeout=30)
        if resp.status_code == 404 and branch == "main":
            zip_url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/master"
            resp = requests.get(zip_url, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"Could not fetch {repo_url!r} (branch {branch!r}) from GitHub: {exc}") from exc

    dest_dir = tempfile.mkdtemp(prefix="repo_github_")
    tmp_zip_path = os.path.join(tempfile.gettempdir(), next(tempfile._get_candidate_names()) + ".zip")
    try:
        with open(tmp_zip_path, "wb") as fh:
            fh.write(resp.content)
        with zipfile.ZipFile(tmp_zip_path) as zf:
            _safe_extract(zf, dest_dir)
    finally:
        if os.path.exists(tmp_zip_path):
            os.remove(tmp_zip_path)

    # GitHub's codeload zip wraps everything in a single "<repo>-<branch>/"
    # folder — unwrap it so scan_repo sees the actual repo root.
    entries = os.listdir(dest_dir)
    if len(entries) == 1 and os.path.isdir(os.path.join(dest_dir, entries[0])):
        return os.path.join(dest_dir, entries[0])
    return dest_dir


def investigate_repo(root_path: str) -> dict:
    """Runs the full repo-investigation pipeline. Returns a plain dict
    ready to jsonify. Does not delete root_path — caller owns cleanup."""
    intel = repo_intel.scan_repo(root_path)
    tm = threat_model.build_threat_model(intel)
    ap = attack_path.build_attack_path(tm)
    return {
        "repo_intel": intel.to_dict(),
        "threat_model": tm.to_dict(),
        "attack_path": ap.to_dict(),
    }
