"""
Tests for web_scanner.py.

_is_safe_target's SSRF protection is tested against real IP/hostname
resolution — no mocking, since that's exactly the logic that must not
have a hole in it. The higher-level checks (_check_headers, _check_tls,
etc.) mock only requests.get, following this project's existing
convention (test_supply_chain.py, test_ioc_feed.py).
"""
from __future__ import annotations

from unittest.mock import Mock

import pytest

from src import web_scanner
from src.models import Severity


def _mock_response(status=200, headers=None, content=b"hello", url="https://example.com/", cookies=None):
    resp = Mock()
    resp.status_code = status
    resp.headers = headers or {}
    resp.content = content
    resp.url = url
    resp.is_redirect = False
    resp.is_permanent_redirect = False
    resp.raw = Mock()
    resp.raw.headers = Mock()
    resp.raw.headers.get_all = Mock(return_value=cookies or [])
    return resp


# ---------- SSRF protection: the security-critical part ----------

def test_is_safe_target_rejects_cloud_metadata_endpoint():
    safe, reason = web_scanner._is_safe_target("http://169.254.169.254/")
    assert safe is False
    assert "SSRF" in reason


def test_is_safe_target_rejects_loopback_hostname():
    safe, _ = web_scanner._is_safe_target("http://localhost:8080/")
    assert safe is False


def test_is_safe_target_rejects_loopback_ip():
    safe, _ = web_scanner._is_safe_target("http://127.0.0.1/")
    assert safe is False


def test_is_safe_target_rejects_private_ranges():
    for host in ("192.168.1.1", "10.0.0.5", "172.16.0.1"):
        safe, _ = web_scanner._is_safe_target(f"http://{host}/")
        assert safe is False, f"{host} should be rejected as private"


def test_is_safe_target_rejects_unspecified_address():
    safe, _ = web_scanner._is_safe_target("http://0.0.0.0/")
    assert safe is False


def test_is_safe_target_rejects_disallowed_scheme():
    safe, reason = web_scanner._is_safe_target("ftp://example.com/")
    assert safe is False
    assert "scheme" in reason.lower()


def test_is_safe_target_allows_real_public_site():
    safe, reason = web_scanner._is_safe_target("https://www.google.com/")
    assert safe is True
    assert reason == ""


def test_is_safe_target_rejects_unresolvable_hostname():
    safe, reason = web_scanner._is_safe_target("http://this-does-not-resolve-at-all.invalid/")
    assert safe is False


def test_scan_url_raises_before_fetching_unsafe_target():
    with pytest.raises(RuntimeError, match="Refusing to scan"):
        web_scanner.scan_url("http://169.254.169.254/")


# ---------- Header / cookie / TLS / disclosure checks ----------

def test_check_headers_flags_all_missing():
    resp = _mock_response(headers={})
    findings = web_scanner._check_headers(resp)
    assert len(findings) == len(web_scanner._SECURITY_HEADERS)


def test_check_headers_no_findings_when_all_present():
    resp = _mock_response(headers={h: "1" for h in web_scanner._SECURITY_HEADERS})
    assert web_scanner._check_headers(resp) == []


def test_check_cookies_flags_missing_flags():
    resp = _mock_response(url="https://example.com/", cookies=["session=abc123; Path=/"])
    findings = web_scanner._check_cookies(resp)
    assert len(findings) == 1
    assert "Secure" in findings[0].title
    assert "HttpOnly" in findings[0].title


def test_check_cookies_no_finding_when_flags_present():
    resp = _mock_response(url="https://example.com/", cookies=["session=abc123; Secure; HttpOnly; SameSite=Strict"])
    assert web_scanner._check_cookies(resp) == []


def test_check_tls_flags_plain_http():
    findings = web_scanner._check_tls("http://example.com/")
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_check_server_disclosure_flags_version_string():
    resp = _mock_response(headers={"Server": "nginx/1.18.0"})
    findings = web_scanner._check_server_disclosure(resp)
    assert len(findings) == 1


def test_check_server_disclosure_no_finding_for_generic_value():
    resp = _mock_response(headers={"Server": "nginx"})
    assert web_scanner._check_server_disclosure(resp) == []


# ---------- Exposed-path scanning with soft-404 guard ----------

def test_check_exposed_paths_ignores_soft_404_sites(monkeypatch):
    """A SPA that returns 200 for every path (with the same body) must
    not be flagged for every entry in the common-paths list."""
    def fake_fetch(url, **kwargs):
        return _mock_response(status=200, content=b"<html>not found spa page</html>")
    monkeypatch.setattr(web_scanner, "_fetch", fake_fetch)
    assert web_scanner._check_exposed_paths("https://example.com") == []


def test_check_exposed_paths_flags_genuine_exposure(monkeypatch):
    def fake_fetch(url, **kwargs):
        if ".env" in url:
            return _mock_response(status=200, content=b"DB_PASSWORD=supersecret123\nAPI_KEY=abc")
        return _mock_response(status=404, content=b"not found")
    monkeypatch.setattr(web_scanner, "_fetch", fake_fetch)
    findings = web_scanner._check_exposed_paths("https://example.com")
    assert any(".env" in f.title for f in findings)
    assert findings[0].severity == Severity.CRITICAL


# ---------- CORS ----------

def test_check_cors_flags_wildcard_with_credentials(monkeypatch):
    def fake_fetch(url, **kwargs):
        return _mock_response(headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
    monkeypatch.setattr(web_scanner, "_fetch", fake_fetch)
    findings = web_scanner._check_cors("https://example.com")
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_check_cors_no_finding_for_proper_config(monkeypatch):
    def fake_fetch(url, **kwargs):
        return _mock_response(headers={})
    monkeypatch.setattr(web_scanner, "_fetch", fake_fetch)
    assert web_scanner._check_cors("https://example.com") == []


# ---------- scan_url end-to-end (mocked transport) ----------

def test_scan_url_normalizes_missing_scheme(monkeypatch):
    def fake_fetch(url, **kwargs):
        return _mock_response(headers={h: "1" for h in web_scanner._SECURITY_HEADERS}, url="https://example.com/")
    monkeypatch.setattr(web_scanner, "_fetch", fake_fetch)
    report = web_scanner.scan_url("example.com")
    assert report.url == "https://example.com"


def test_scan_url_raises_runtime_error_when_unreachable(monkeypatch):
    # example.com resolves in real DNS, so this exercises the "fetch
    # failed" path specifically — not the (separately, correctly
    # tested) "hostname doesn't resolve" SSRF-check path.
    monkeypatch.setattr(web_scanner, "_is_safe_target", lambda url: (True, ""))
    monkeypatch.setattr(web_scanner, "_fetch", lambda url, **kw: None)
    with pytest.raises(RuntimeError, match="Could not reach"):
        web_scanner.scan_url("https://example.com")
