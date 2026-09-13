from __future__ import annotations

import os
import shutil
import zipfile
from unittest.mock import Mock, patch

import pytest

from src import orchestrator


def _make_zip(path, entries: dict[str, str]):
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)


def test_extract_uploaded_zip_normal_case(tmp_path):
    zip_path = tmp_path / "repo.zip"
    _make_zip(zip_path, {"app.py": "print('hi')\n", "requirements.txt": "flask==3.0.0\n"})

    extracted = orchestrator.extract_uploaded_zip(str(zip_path))
    try:
        assert os.path.isfile(os.path.join(extracted, "app.py"))
        assert os.path.isfile(os.path.join(extracted, "requirements.txt"))
    finally:
        import shutil
        shutil.rmtree(extracted)


def test_extract_uploaded_zip_rejects_path_traversal(tmp_path):
    """A real zip-slip payload: an entry named to escape the extraction
    directory via '../'. Must be rejected, not silently written outside."""
    zip_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../../etc/evil_payload", "malicious content")

    with pytest.raises(ValueError, match="path traversal"):
        orchestrator.extract_uploaded_zip(str(zip_path))


def test_extract_uploaded_zip_rejects_absolute_path(tmp_path):
    zip_path = tmp_path / "evil_abs.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("/tmp/evil_payload_abs", "malicious content")

    with pytest.raises(ValueError, match="path traversal"):
        orchestrator.extract_uploaded_zip(str(zip_path))


def test_extract_uploaded_zip_rejects_zip_bomb(tmp_path, monkeypatch):
    """A real zip bomb, not a mock: one highly-compressible file whose
    declared uncompressed size is over the limit. Uses a small limit
    here so the test runs fast without needing to actually write
    hundreds of MB to disk during the test itself — the point under
    test is the enforcement logic, which doesn't care about scale."""
    monkeypatch.setattr(orchestrator.config, "MAX_ZIP_UNCOMPRESSED_BYTES", 1024 * 1024)  # 1MB cap for this test

    zip_path = tmp_path / "bomb.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("huge.bin", b"\x00" * (5 * 1024 * 1024))  # 5MB of zeros, compresses to ~KB

    with pytest.raises(ValueError, match="zip-bomb protection"):
        orchestrator.extract_uploaded_zip(str(zip_path))


def test_extract_uploaded_zip_rejects_too_many_files(tmp_path, monkeypatch):
    monkeypatch.setattr(orchestrator.config, "MAX_ZIP_FILE_COUNT", 5)

    zip_path = tmp_path / "many_files.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for i in range(10):
            zf.writestr(f"file_{i}.txt", "x")

    with pytest.raises(ValueError, match="entries"):
        orchestrator.extract_uploaded_zip(str(zip_path))


def test_blocked_extraction_leaves_no_partial_directory_on_disk(tmp_path, monkeypatch):
    """A blocked zip bomb must not leave a half-extracted mess behind —
    verified by checking no repo_upload_* temp dir survives the failure."""
    import glob
    import tempfile

    monkeypatch.setattr(orchestrator.config, "MAX_ZIP_UNCOMPRESSED_BYTES", 1024)  # tiny cap, will definitely trip

    zip_path = tmp_path / "bomb2.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("file.bin", b"\x00" * (10 * 1024))

    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "repo_upload_*")))
    with pytest.raises(ValueError):
        orchestrator.extract_uploaded_zip(str(zip_path))
    after = set(glob.glob(os.path.join(tempfile.gettempdir(), "repo_upload_*")))
    assert after == before  # no new leftover directory


def test_extract_uploaded_zip_allows_reasonable_repo(tmp_path):
    """Sanity check the limits don't accidentally reject normal, small
    repos — a real (if tiny) zip well under both limits."""
    zip_path = tmp_path / "normal_repo.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("app.py", "print('hello')\n" * 100)
        zf.writestr("README.md", "# Hello\n")

    extracted = orchestrator.extract_uploaded_zip(str(zip_path))
    try:
        assert os.path.isfile(os.path.join(extracted, "app.py"))
    finally:
        shutil.rmtree(extracted)


def test_fetch_github_repo_rejects_non_github_url():
    with pytest.raises(ValueError, match="Not a recognizable GitHub repo URL"):
        orchestrator.fetch_github_repo("https://example.com/not/github")


def test_fetch_github_repo_downloads_and_unwraps_codeload_folder(tmp_path, monkeypatch):
    # Real codeload zips wrap everything in "<repo>-<branch>/" — build one
    # to prove the unwrap step works, not just the download.
    inner_zip_path = tmp_path / "codeload.zip"
    _make_zip(inner_zip_path, {
        "myrepo-main/app.py": "print('hi')\n",
        "myrepo-main/requirements.txt": "flask==3.0.0\n",
    })
    fake_response = Mock(status_code=200, content=inner_zip_path.read_bytes())
    fake_response.raise_for_status = Mock()

    monkeypatch.setattr(orchestrator.requests, "get", lambda url, timeout: fake_response)

    result_path = orchestrator.fetch_github_repo("https://github.com/someone/myrepo")
    try:
        assert os.path.isfile(os.path.join(result_path, "app.py"))
        assert "myrepo-main" in result_path  # unwrapped into the inner folder
    finally:
        import shutil
        shutil.rmtree(os.path.dirname(result_path) if "myrepo-main" in result_path else result_path)


def test_fetch_github_repo_falls_back_to_master_branch(tmp_path, monkeypatch):
    inner_zip_path = tmp_path / "codeload_master.zip"
    _make_zip(inner_zip_path, {"myrepo-master/app.py": "print('hi')\n"})

    calls = {"n": 0}

    def fake_get(url, timeout):
        calls["n"] += 1
        if "refs/heads/main" in url:
            resp = Mock(status_code=404)
            resp.raise_for_status = Mock(side_effect=Exception("404"))
            return resp
        resp = Mock(status_code=200, content=inner_zip_path.read_bytes())
        resp.raise_for_status = Mock()
        return resp

    monkeypatch.setattr(orchestrator.requests, "get", fake_get)
    result_path = orchestrator.fetch_github_repo("https://github.com/someone/myrepo")
    try:
        assert calls["n"] == 2  # tried main, fell back to master
        assert os.path.isfile(os.path.join(result_path, "app.py"))
    finally:
        import shutil
        shutil.rmtree(os.path.dirname(result_path))


def test_investigate_repo_wires_all_three_agents(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")
    (tmp_path / "app.py").write_text(
        '@app.route("/admin/x", methods=["POST"])\ndef x(): pass\n'
    )

    fake_tm_llm = {"repo_summary": "s", "additional_threats": [], "risk_score": "low", "recommendations": []}
    fake_ap_llm = {"narrative": "n", "steps": []}

    with patch("src.groq_client.generate_threat_model", return_value=fake_tm_llm), \
         patch("src.groq_client.generate_attack_path", return_value=fake_ap_llm):
        result = orchestrator.investigate_repo(str(tmp_path))

    assert "repo_intel" in result
    assert "threat_model" in result
    assert "attack_path" in result
    assert result["repo_intel"]["frameworks"] == ["Flask"]
