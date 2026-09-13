"""
Phishing / Scam Investigation agent.

Combines two independent signals into one report:
  1. Deterministic heuristics over the message text and any URLs in it
     (keyword matching, URL structure analysis, brand-domain similarity)
  2. A Groq LLM pass that reads the message + the heuristic findings and
     gives a semantic judgment + confidence + recommended action

Neither signal on its own is treated as ground truth — the heuristic
score catches things an LLM might rationalize away, and the LLM catches
scams with no exploitable URL and no keyword match (e.g. a fake prize
notification asking only for a phone callback).

Known limitations (stated, not hidden):
- No live blocklist check (PhishTank/OpenPhish/Google Safe Browsing) —
  this only analyzes structure and language, not domain reputation or
  registration age. Wiring in a live feed needs a real API key this
  project doesn't have configured; see the roadmap in README.md.
- Brand-domain list and suspicious-TLD list are small curated starter
  sets, not exhaustive.
- No visual/screenshot analysis (this only handles text/URL input, per
  the current scope — see the project roadmap for screenshot/QR input).
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import urlsplit

import tldextract

from . import groq_client
from .models import PhishingReport, Severity, URLFinding
from .supply_chain import _levenshtein  # reuse the same edit-distance helper

# suffix_list_urls=() disables live fetching from publicsuffix.org and
# uses the bundled snapshot only — deterministic and works offline,
# rather than depending on reaching a third party at request time.
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())

_URL_REGEX = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
# Catches bare domains pasted with no protocol (e.g. "paypa1.com" or
# "paypa1.com/signin") so a single-URL paste still gets full structural
# analysis, not just keyword scoring. Validated against tldextract's
# real public-suffix list in _extract_urls below — not a loose regex
# guess at what a TLD looks like, which would false-positive on
# ordinary prose ("Wait. Really?" is not a domain).
_BARE_DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:/[^\s<>\"')\]]*)?\b"
)

# TLDs disproportionately abused for phishing/scam infrastructure because
# they're cheap and require little to no identity verification to register.
# Not a claim that every domain on these TLDs is malicious.
_SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "work", "support", "click", "country", "gq",
    "cf", "tk", "ml", "ga", "loan", "win", "review", "download", "stream",
    "men", "science", "party", "trade",
}

_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
}

# Real, high-value phishing targets used only for edit-distance comparison
# (typosquat/impersonation detection), same convention as supply_chain.py's
# popular-package list. Starter set, not exhaustive.
_BRAND_DOMAINS = {
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "netflix.com",
    "facebook.com", "instagram.com", "whatsapp.com", "irs.gov", "usps.com",
    "dhl.com", "fedex.com", "linkedin.com", "ebay.com", "dropbox.com",
    "docusign.com", "outlook.com", "coinbase.com",
}

# Real, commonly-cited social-engineering language patterns. Kept at the
# pattern level intentionally (see mentor-mode guidance) — this is a
# detector, not an exhaustive phrasebook to copy.
_URGENCY_PATTERNS = [
    r"\bact now\b", r"\bimmediately\b", r"\bwithin 24 hours\b",
    r"\bsuspend(ed)?\b", r"\byour account will be (locked|closed|terminated)\b",
    r"\burgent(ly)?\b", r"\bfinal notice\b", r"\bverify (your|now)\b",
]
_CREDENTIAL_PATTERNS = [
    r"\bconfirm your password\b", r"\bverify your (account|identity|card)\b",
    r"\blogin to (your|update)\b", r"\bre-?enter your (password|pin|ssn)\b",
    r"\bsocial security number\b", r"\bcard verification\b", r"\bone.?time (code|password)\b",
]
_FINANCIAL_PATTERNS = [
    r"\bgift card\b", r"\bwire transfer\b", r"\bclaim your (prize|refund|reward)\b",
    r"\btax refund\b", r"\bpay(ment)? (overdue|failed|declined)\b",
    r"\bunusual (activity|sign-?in|login)\b", r"\bsuspicious (activity|login)\b",
]
_KEYWORD_GROUPS = {
    "urgency": _URGENCY_PATTERNS,
    "credential_request": _CREDENTIAL_PATTERNS,
    "financial": _FINANCIAL_PATTERNS,
}


def _extract_urls(text: str) -> list[str]:
    urls = list(_URL_REGEX.findall(text))
    covered_spans = [m.span() for m in _URL_REGEX.finditer(text)]

    def _already_covered(start: int, end: int) -> bool:
        return any(start >= s and end <= e for s, e in covered_spans)

    for match in _BARE_DOMAIN_REGEX.finditer(text):
        if _already_covered(*match.span()):
            continue  # already caught by the http(s):// regex above
        candidate = match.group(0)
        parsed = _tld_extractor(candidate.split("/", 1)[0].lower())
        if parsed.domain and parsed.suffix:  # a real recognized public suffix, not a guess
            urls.append(f"http://{candidate}")

    return urls


def _registrable_domain(hostname: str) -> str:
    """Public-suffix-aware: correctly handles multi-part suffixes like
    .co.uk, .com.au, .github.io (e.g. "login.paypal.co.uk" ->
    "paypal.co.uk", not the old last-two-labels guess of "co.uk")."""
    result = _tld_extractor(hostname.lower())
    if result.domain and result.suffix:
        return f"{result.domain}.{result.suffix}"
    return hostname.lower()  # no recognized suffix (e.g. a bare IP or intranet host) — return as-is


def _brand_impersonation_check(hostname: str) -> tuple[Optional[str], bool]:
    """Returns (brand_domain_suspected, suspicious_subdomain_nesting).
    Two distinct attack patterns:
    1. Typosquat: the registrable domain itself is a near-miss of a real
       brand domain (paypa1.com).
    2. Subdomain nesting: the real brand name appears as a *subdomain*
       label while the actual registrable domain is unrelated
       (paypal.com.security-check.xyz — registrable domain is
       security-check.xyz, "paypal" is just a subdomain label chosen to
       deceive at a glance)."""
    parsed = _tld_extractor(hostname.lower())
    registrable = f"{parsed.domain}.{parsed.suffix}" if parsed.domain and parsed.suffix else hostname.lower()
    base_name = parsed.domain or registrable  # tldextract's actual base label, not a rsplit guess — correct even for "paypal.co.uk"

    for brand in _BRAND_DOMAINS:
        brand_base = brand.rsplit(".", 1)[0]
        if registrable == brand:
            continue  # the real domain, not impersonation
        dist = _levenshtein(base_name, brand_base)
        if 0 < dist <= 2:
            return brand, False

    subdomain_labels = parsed.subdomain.split(".") if parsed.subdomain else []
    for brand in _BRAND_DOMAINS:
        brand_base = brand.rsplit(".", 1)[0]
        if brand_base in subdomain_labels and registrable != brand:
            return brand, True

    return None, False


def _analyze_url(url: str) -> URLFinding:
    parts = urlsplit(url)
    hostname = parts.hostname or ""

    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        pass

    is_punycode = hostname.lower().startswith("xn--") or ".xn--" in hostname.lower()
    registrable = _registrable_domain(hostname) if not is_ip else hostname
    tld = registrable.rsplit(".", 1)[-1] if "." in registrable else ""
    is_shortener = registrable in _URL_SHORTENERS
    brand, nested = (None, False) if is_ip or is_shortener else _brand_impersonation_check(hostname)

    score = 0
    if is_ip:
        score += 30
    if is_punycode:
        score += 35
    if tld in _SUSPICIOUS_TLDS:
        score += 15
    if is_shortener:
        score += 10  # not inherently malicious, but hides the real destination
    if brand:
        score += 40
    if nested:
        score += 25

    return URLFinding(
        url=url,
        domain=hostname,
        is_ip_literal=is_ip,
        is_punycode=is_punycode,
        is_shortener=is_shortener,
        suspicious_tld=tld in _SUSPICIOUS_TLDS,
        brand_impersonation_of=brand,
        suspicious_subdomain_nesting=nested,
        risk_score=min(100, score),
    )


def _heuristic_message_score(text: str, url_findings: list[URLFinding]) -> tuple[int, list[str]]:
    matched: list[str] = []
    score = 0
    lower = text.lower()
    for group_name, patterns in _KEYWORD_GROUPS.items():
        for pattern in patterns:
            if re.search(pattern, lower):
                matched.append(f"{group_name}:{pattern.strip(chr(92) + 'b')}")
                score += 12

    if url_findings:
        score += max(u.risk_score for u in url_findings) // 2  # URL risk contributes, doesn't dominate

    return min(100, score), matched


def _risk_from_combined(heuristic_score: int, llm_confidence: float, llm_says_phishing: bool) -> Severity:
    combined = max(heuristic_score, int(llm_confidence * 100) if llm_says_phishing else 0)
    if combined >= 80:
        return Severity.CRITICAL
    if combined >= 60:
        return Severity.HIGH
    if combined >= 35:
        return Severity.MEDIUM
    if combined >= 15:
        return Severity.LOW
    return Severity.INFO


def analyze_message(text: str) -> PhishingReport:
    """Entry point. `text` is the raw message body (email/SMS/WhatsApp/
    pasted text) — URLs inside it are extracted and analyzed automatically."""
    urls = _extract_urls(text)
    url_findings = [_analyze_url(u) for u in urls]
    heuristic_score, matched_keywords = _heuristic_message_score(text, url_findings)

    llm_result = groq_client.classify_phishing_message(text, [u.to_dict() for u in url_findings])

    return PhishingReport(
        input_excerpt=text[:280],
        matched_keywords=matched_keywords,
        url_findings=url_findings,
        heuristic_score=heuristic_score,
        llm_confidence=float(llm_result["confidence"]),
        llm_reasoning=llm_result["reasoning"],
        risk_score=_risk_from_combined(
            heuristic_score, float(llm_result["confidence"]), bool(llm_result["is_likely_phishing"])
        ),
        recommended_action=llm_result["recommended_action"],
    )
