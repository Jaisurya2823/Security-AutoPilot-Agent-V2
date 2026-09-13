"""
Supply Chain Security agent.

Real vulnerability data from OSV.dev's public API (https://osv.dev/docs/)
via POST /v1/querybatch (bulk lookup, returns matching vuln IDs only) then
GET /v1/vulns/{id} to hydrate full details for only the packages that
actually had hits. No mock vulnerability data, no simulated results — if
OSV is unreachable, analyze_manifest raises rather than fabricating a
clean bill of health.

Known limitations (stated, not hidden):
- Only requirements.txt and package.json are parsed (see manifest_parser.py)
- Typosquat detection compares against a small starter list of well-known
  package names, not a live popularity feed — misses are expected for
  less common legitimate packages
- CVSS v3.0/v3.1 vectors are scored for real via src/cvss.py (the
  official base-score formula). CVSS v2 vectors use a materially
  different formula that isn't implemented — those still report
  severity as "unknown" rather than being scored with the wrong formula.
"""
from __future__ import annotations

import time
from typing import Optional

import requests

from . import config, cvss, manifest_parser
from .models import PackageFinding, PackageRef, Severity, SupplyChainReport, VulnMatch

_MAX_RETRIES = 3
_BASE_DELAY_SECONDS = 1.0
_BATCH_SIZE = 1000  # OSV's own limit per querybatch request

# Starter reference list of well-known package names per ecosystem, used
# only for typosquat-distance comparison. NOT an exhaustive popularity
# list — a production deployment should refresh this from a live
# download-count feed (PyPI's public BigQuery dataset / npm registry
# download API) instead of this static set.
_POPULAR_PACKAGES = {
    "PyPI": {
        "requests", "numpy", "pandas", "flask", "django", "boto3", "urllib3",
        "click", "pyyaml", "cryptography", "pillow", "setuptools", "pip",
        "certifi", "charset-normalizer", "idna", "six", "python-dateutil",
        "pytz", "sqlalchemy", "jinja2", "markupsafe", "werkzeug", "pydantic",
        "attrs", "packaging", "wheel", "typing-extensions", "protobuf",
        "grpcio", "cffi", "pyjwt", "redis", "celery", "gunicorn", "scipy",
        "matplotlib", "beautifulsoup4", "lxml", "psycopg2",
    },
    "npm": {
        "react", "react-dom", "lodash", "express", "axios", "webpack",
        "babel-core", "eslint", "chalk", "commander", "moment", "vue",
        "typescript", "jest", "next", "tailwindcss", "prettier", "dotenv",
        "uuid", "yargs", "semver", "glob", "chokidar", "async", "rxjs",
        "socket.io", "mongoose", "cors", "body-parser", "jsonwebtoken",
        "bcrypt", "nodemon", "vite", "vitest",
    },
}

_SEVERITY_RANK = {"critical": 40, "high": 25, "medium": 10, "low": 5, "unknown": 8}
_SEVERITY_STRING_MAP = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def _levenshtein(a: str, b: str) -> int:
    """Standard edit-distance DP — no external dependency needed for the
    short package-name strings this runs on."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def _typosquat_suspect(name: str, ecosystem: str) -> Optional[str]:
    """Returns the popular package name this one suspiciously resembles,
    or None. Exact matches to a popular name are never flagged (that's
    the real package); only near-misses (edit distance 1-2) are."""
    pool = _POPULAR_PACKAGES.get(ecosystem, set())
    lname = name.lower()
    if lname in pool:
        return None
    best_match, best_dist = None, 3  # only accept distance 1 or 2
    for popular in pool:
        dist = _levenshtein(lname, popular)
        if 0 < dist < best_dist:
            best_match, best_dist = popular, dist
    return best_match


def _request_with_retry(method: str, url: str, **kwargs) -> dict:
    last_error: Optional[Exception] = None
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            resp = requests.request(method, url, timeout=15, **kwargs)
            if resp.status_code >= 500:
                raise requests.HTTPError(f"OSV.dev returned {resp.status_code}", response=resp)
            resp.raise_for_status()
            return resp.json()
        except (requests.ConnectionError, requests.Timeout, requests.HTTPError) as exc:
            last_error = exc
            if attempt == _MAX_RETRIES:
                break
            time.sleep(_BASE_DELAY_SECONDS * (2 ** (attempt - 1)))
    raise RuntimeError(f"OSV.dev {method} {url} failed after {_MAX_RETRIES} attempts: {last_error}") from last_error


def _query_osv_batch(packages: list[PackageRef], base_url: str) -> dict[tuple[str, str, str], list[str]]:
    """Returns {(ecosystem, name, version): [vuln_id, ...]} for every
    package, even ones with no hits (empty list)."""
    id_map: dict[tuple[str, str, str], list[str]] = {}
    for i in range(0, len(packages), _BATCH_SIZE):
        chunk = packages[i:i + _BATCH_SIZE]
        body = {
            "queries": [
                {"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version}
                for p in chunk
            ]
        }
        data = _request_with_retry("POST", f"{base_url}/querybatch", json=body)
        results = data.get("results", [])
        for pkg, result in zip(chunk, results):
            id_map[(pkg.ecosystem, pkg.name, pkg.version)] = [v["id"] for v in result.get("vulns", [])]
    return id_map


def _extract_severity(vuln_data: dict) -> str:
    db_specific = vuln_data.get("database_specific", {}) or {}
    raw = db_specific.get("severity")
    if raw:
        mapped = _SEVERITY_STRING_MAP.get(str(raw).upper())
        if mapped:
            return mapped
    # No plain severity string — OSV's `severity` field holds CVSS
    # vector strings. For CVSS v3.x these are now computed for real via
    # src/cvss.py (the official base-score formula, not a guess).
    # CVSS v2 vectors use a materially different formula that isn't
    # implemented here, so those still fall through to "unknown" rather
    # than being scored with the wrong formula.
    for severity_entry in vuln_data.get("severity", []) or []:
        vector = severity_entry.get("score", "")
        score = cvss.cvss3_base_score(vector)
        if score is not None:
            return cvss.severity_bucket_from_score(score)
    return "unknown"


def _extract_fixed_version(vuln_data: dict) -> Optional[str]:
    for affected in vuln_data.get("affected", []) or []:
        for rng in affected.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                if "fixed" in event:
                    return event["fixed"]
    return None


def _hydrate_vuln(vuln_id: str, base_url: str) -> VulnMatch:
    data = _request_with_retry("GET", f"{base_url}/vulns/{vuln_id}")
    summary = data.get("summary") or data.get("details", "") or ""
    return VulnMatch(
        id=vuln_id,
        summary=summary[:300],
        severity=_extract_severity(data),
        aliases=data.get("aliases", []) or [],
        fixed_version=_extract_fixed_version(data),
    )


def _package_trust_score(vulns: list[VulnMatch], is_typosquat: bool) -> int:
    score = 100
    for v in vulns:
        score -= _SEVERITY_RANK.get(v.severity, 8)
    if is_typosquat:
        score -= 50
    return max(0, score)


def _overall_trust_score(findings: list[PackageFinding]) -> int:
    if not findings:
        return 100
    # Weakest-link scoring: one severely compromised dependency undermines
    # the whole install regardless of how many other packages are clean,
    # so overall trust is bounded by the worst finding, not averaged down.
    return min(f.trust_score for f in findings)


def _risk_from_trust(score: int) -> Severity:
    if score >= 85:
        return Severity.INFO
    if score >= 65:
        return Severity.LOW
    if score >= 40:
        return Severity.MEDIUM
    if score >= 15:
        return Severity.HIGH
    return Severity.CRITICAL


def analyze_manifest(path: str, content: str) -> SupplyChainReport:
    """Entry point: parse a manifest by filename, query real vulnerability
    data for every pinned package, and score it. Raises ValueError for
    unsupported manifest types, RuntimeError if OSV.dev can't be reached."""
    filename = path.replace("\\", "/").rsplit("/", 1)[-1]
    suspicious_scripts: list[str] = []

    if filename == "requirements.txt":
        resolved, unresolved = manifest_parser.parse_requirements_txt(content)
        ecosystem = "PyPI"
    elif filename == "package.json":
        resolved, unresolved, suspicious_scripts = manifest_parser.parse_package_json(content)
        ecosystem = "npm"
    else:
        raise ValueError(
            f"Unsupported manifest type: {filename!r}. Currently supported: "
            "requirements.txt, package.json."
        )

    vuln_id_map = _query_osv_batch(resolved, config.OSV_API_URL) if resolved else {}

    # Hydrate only the distinct IDs that actually matched something, not
    # a full record for every package regardless of whether it had hits.
    distinct_ids = {vid for ids in vuln_id_map.values() for vid in ids}
    hydrated: dict[str, VulnMatch] = {vid: _hydrate_vuln(vid, config.OSV_API_URL) for vid in distinct_ids}

    findings: list[PackageFinding] = []
    for pkg in resolved:
        vuln_ids = vuln_id_map.get((pkg.ecosystem, pkg.name, pkg.version), [])
        vulns = [hydrated[vid] for vid in vuln_ids if vid in hydrated]
        typosquat = _typosquat_suspect(pkg.name, pkg.ecosystem)
        findings.append(PackageFinding(
            package=pkg,
            vulns=vulns,
            typosquat_suspect_of=typosquat,
            trust_score=_package_trust_score(vulns, typosquat is not None),
        ))

    # Lifecycle install scripts are manifest-wide, not tied to one
    # package — surfaced as their own finding for human review. Scored at
    # 40 (not 0): many are legitimate (native module builds, postinstall
    # setup), so this flags for review rather than auto-condemning.
    for script in suspicious_scripts:
        findings.append(PackageFinding(
            package=PackageRef(name="(package.json lifecycle script)", ecosystem=ecosystem, raw_spec=script),
            suspicious_install_script=script,
            trust_score=40,
        ))

    overall = _overall_trust_score(findings)
    return SupplyChainReport(
        manifest_path=path,
        ecosystem=ecosystem,
        findings=findings,
        unresolved_packages=unresolved,
        overall_trust_score=overall,
        risk_score=_risk_from_trust(overall),
    )
