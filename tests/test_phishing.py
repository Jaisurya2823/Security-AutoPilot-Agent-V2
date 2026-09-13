"""
Tests for phishing.py.

groq_client.classify_phishing_message is monkeypatched (no real network
call), matching the same convention as test_graph.py for the LLM
boundary. Every heuristic — URL parsing, keyword matching, brand
similarity — runs for real; nothing about the *detection logic* itself
is mocked, only the LLM round-trip.
"""
from __future__ import annotations

from src import phishing


def _fake_llm(is_phishing=True, confidence=0.9, reasoning="test reasoning", action="Do not click; report and delete"):
    return {
        "is_likely_phishing": is_phishing,
        "confidence": confidence,
        "reasoning": reasoning,
        "recommended_action": action,
    }


def test_extract_urls_finds_all_urls_in_text():
    text = "Check http://example.com/a and also https://foo.bar/b?x=1 please."
    urls = phishing._extract_urls(text)
    assert urls == ["http://example.com/a", "https://foo.bar/b?x=1"]


def test_registrable_domain_strips_subdomains():
    assert phishing._registrable_domain("login.paypal.com") == "paypal.com"
    assert phishing._registrable_domain("paypal.com") == "paypal.com"


def test_registrable_domain_handles_multipart_suffix():
    """Regression test: the old last-two-labels heuristic would have
    returned 'co.uk' (wrong) for a .co.uk domain. tldextract's public
    suffix list gets this right."""
    assert phishing._registrable_domain("login.paypal.co.uk") == "paypal.co.uk"
    assert phishing._registrable_domain("mail.example.com.au") == "example.com.au"


def test_brand_impersonation_nested_subdomain_with_multipart_suffix():
    """Subdomain-nesting detection must still work correctly when the
    *attacker's* domain also has a multi-part suffix — the old labels[:-2]
    slicing would have miscounted which labels are "subdomain" here."""
    brand, nested = phishing._brand_impersonation_check("paypal.com.security-check.co.uk")
    assert brand == "paypal.com"
    assert nested is True


def test_analyze_url_flags_ip_literal():
    finding = phishing._analyze_url("http://192.168.1.1/login")
    assert finding.is_ip_literal is True
    assert finding.risk_score >= 30


def test_analyze_url_flags_punycode():
    finding = phishing._analyze_url("http://xn--pypal-4ve.com/login")
    assert finding.is_punycode is True


def test_analyze_url_flags_suspicious_tld():
    finding = phishing._analyze_url("http://secure-update.top/login")
    assert finding.suspicious_tld is True


def test_analyze_url_flags_typosquat_brand():
    finding = phishing._analyze_url("http://paypa1.com/signin")
    assert finding.brand_impersonation_of == "paypal.com"
    assert finding.suspicious_subdomain_nesting is False


def test_analyze_url_flags_subdomain_nesting():
    finding = phishing._analyze_url("http://paypal.com.security-check.xyz/login")
    assert finding.brand_impersonation_of == "paypal.com"
    assert finding.suspicious_subdomain_nesting is True


def test_analyze_url_no_false_positive_on_real_brand_domain():
    finding = phishing._analyze_url("https://www.paypal.com/signin")
    assert finding.brand_impersonation_of is None
    assert finding.suspicious_subdomain_nesting is False
    assert finding.risk_score == 0


def test_analyze_url_shortener_flagged_but_not_brand_checked():
    finding = phishing._analyze_url("http://bit.ly/abc123")
    assert finding.is_shortener is True
    assert finding.brand_impersonation_of is None  # shorteners are skipped for brand-similarity, not applicable


def test_heuristic_message_score_matches_urgency_and_credential_keywords():
    text = "URGENT: verify your account immediately or it will be suspended."
    score, matched = phishing._heuristic_message_score(text, [])
    assert score > 0
    assert any("urgency" in m for m in matched)


def test_heuristic_message_score_zero_for_benign_text():
    score, matched = phishing._heuristic_message_score("Hey, are we still on for lunch tomorrow?", [])
    assert score == 0
    assert matched == []


def test_analyze_message_combines_heuristics_and_llm(monkeypatch):
    monkeypatch.setattr(
        phishing.groq_client, "classify_phishing_message",
        lambda text, urls: _fake_llm(is_phishing=True, confidence=0.95)
    )
    text = "URGENT: your account will be suspended. Verify now: http://paypa1.com/signin"
    report = phishing.analyze_message(text)

    assert report.heuristic_score > 0
    assert len(report.url_findings) == 1
    assert report.url_findings[0].brand_impersonation_of == "paypal.com"
    assert report.llm_confidence == 0.95
    assert report.risk_score == phishing.Severity.CRITICAL
    assert "report" in report.recommended_action.lower() or "click" in report.recommended_action.lower()


def test_analyze_message_benign_text_low_risk(monkeypatch):
    monkeypatch.setattr(
        phishing.groq_client, "classify_phishing_message",
        lambda text, urls: _fake_llm(is_phishing=False, confidence=0.05, action="Appears benign; no action needed")
    )
    report = phishing.analyze_message("Hey, are we still on for lunch tomorrow?")
    assert report.heuristic_score == 0
    assert report.risk_score == phishing.Severity.INFO


def test_analyze_message_truncates_excerpt():
    monkeypatch_text = "a" * 500
    import unittest.mock
    with unittest.mock.patch.object(
        phishing.groq_client, "classify_phishing_message", return_value=_fake_llm(is_phishing=False, confidence=0.0)
    ):
        report = phishing.analyze_message(monkeypatch_text)
    assert len(report.input_excerpt) == 280
