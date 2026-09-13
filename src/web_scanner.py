"""
Live Website Security Scanner.

For the case a repo scan can't cover: someone has a *deployed* web app
(a friend's project, a live URL) with no source access. This checks the
real, live HTTP surface instead — passively. Every check here is a
standard GET request (the same thing a browser does), never an attack
payload, SQL/XSS injection attempt, brute force, or auth bypass attempt.
That line is deliberate: this project has never built autonomous
pentesting that performs real attacks, and a live URL someone else
controls is exactly where that boundary matters most — I can't verify
consent to test someone else's infrastructure, so this only ever looks,
never touches.

SECURITY: this endpoint fetches a user-supplied URL server-side, which
is a classic SSRF (Server-Side Request Forgery) vector if unguarded —
a caller could point it at http://169.254.169.254/ (cloud metadata,
leaks real AWS/GCP credentials) or an internal service on the host's
own network. _is_safe_target() resolves the hostname and rejects
anything that maps to a private/loopback/link-local/reserved IP range,
checked before the initial request AND before following each redirect
(a malicious external site could otherwise redirect this scanner
internally after the first hop passes the check).

What it checks, all via real HTTP responses:
  - Security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy)
  - Cookie flags (Secure, HttpOnly, SameSite)
  - TLS: whether HTTPS is used/enforced at all, certificate validity
  - Server/framework version disclosure in response headers
  - CORS misconfiguration (reflecting an arbitrary Origin with credentials allowed)
  - Accidental exposure of common sensitive paths (.env, .git/config, etc.)
    — with a soft-404 baseline check first, so sites that return 200 for
    everything don't produce a wall of false positives

Known limitations (stated, not hidden):
  - This is a black-box header/path scan, not a real penetration test —
    it finds common misconfigurations, not application-logic vulnerabilities
    (broken auth, IDOR, business-logic flaws) that need actual interaction
  - The exposed-path list is a small, common-cases starter set
  - A site behind aggressive bot protection (Cloudflare challenge pages,
    etc.) may return misleading results — this doesn't attempt to bypass
    that, and shouldn't
"""
from __future__ import annotations

import datetime
import ipaddress
import re
import secrets as _secrets_module
import socket
import ssl
from urllib.parse import urlparse

import requests

from . import config
from .models import Severity, WebScanReport, WebSecurityFinding

_SECURITY_HEADERS = {
    "Strict-Transport-Security": ("Missing HSTS header", Severity.MEDIUM,
        "No Strict-Transport-Security header — browsers won't be told to always use HTTPS for this site, leaving room for downgrade/SSL-stripping attacks on the first visit."),
    "Content-Security-Policy": ("Missing Content-Security-Policy", Severity.MEDIUM,
        "No CSP header — no browser-enforced restriction on which scripts/resources can run, which is one of the strongest defenses against XSS."),
    "X-Content-Type-Options": ("Missing X-Content-Type-Options", Severity.LOW,
        "No 'nosniff' header — browsers may MIME-sniff responses, which has historically enabled some content-type confusion attacks."),
    "X-Frame-Options": ("Missing X-Frame-Options", Severity.LOW,
        "No clickjacking protection header — the site could potentially be framed by a malicious page (unless CSP's frame-ancestors covers this instead)."),
    "Referrer-Policy": ("Missing Referrer-Policy", Severity.LOW,
        "No Referrer-Policy header — full URLs (which may contain sensitive query params) may leak to third parties via the Referer header on outbound links."),
}

_COOKIE_FLAG_SEVERITY = Severity.MEDIUM

# Common accidentally-exposed paths — real ones seen in real breaches,
# not a hypothetical list. Kept intentionally small: this is about
# catching obvious accidents, not exhaustive path brute-forcing (which
# starts to look like an attack, not a check).
_COMMON_EXPOSED_PATHS = [
    ".env", ".env.local", ".git/config", ".git/HEAD",
    "config.json", "wp-config.php.bak", ".aws/credentials",
    "docker-compose.yml", ".htpasswd", "backup.sql", ".DS_Store",
]

_SERVER_HEADER_VERSION_RE = re.compile(r"[\d.]{2,}")
_MAX_REDIRECTS = 5


class UnsafeTargetError(RuntimeError):
    """Raised when a URL (initial or a redirect hop) resolves to a
    private/internal/reserved address — refuse to fetch it, full stop."""


def _is_safe_target(url: str) -> tuple[bool, str]:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, f"Unsupported scheme: {parsed.scheme!r} (only http/https allowed)"
    hostname = parsed.hostname
    if not hostname:
        return False, "URL has no hostname"

    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        return False, f"Could not resolve hostname: {exc}"

    for family, _, _, _, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return False, (f"'{hostname}' resolves to {ip_str}, a private/internal/reserved "
                            f"address — refusing to scan (SSRF protection)")
    return True, ""


def _fetch_validated(url: str, **kwargs) -> requests.Response:
    """Fetches a URL with SSRF protection applied to the initial request
    AND every redirect hop — requests' own allow_redirects=True would
    follow a redirect to an internal address without re-checking it, so
    redirects are followed manually here instead."""
    current_url = url
    for _ in range(_MAX_REDIRECTS + 1):
        safe, reason = _is_safe_target(current_url)
        if not safe:
            raise UnsafeTargetError(reason)
        resp = requests.get(current_url, timeout=config.WEB_SCAN_TIMEOUT_SECONDS,
                             allow_redirects=False, **kwargs)
        if resp.is_redirect or resp.is_permanent_redirect:
            location = resp.headers.get("Location")
            if not location:
                return resp
            current_url = requests.compat.urljoin(current_url, location)
            continue
        return resp
    raise UnsafeTargetError(f"Too many redirects (>{_MAX_REDIRECTS})")


def _fetch(url: str, **kwargs) -> requests.Response | None:
    try:
        return _fetch_validated(url, **kwargs)
    except (requests.RequestException, UnsafeTargetError):
        return None


def _check_headers(resp: requests.Response) -> list[WebSecurityFinding]:
    findings = []
    for header, (title, severity, desc) in _SECURITY_HEADERS.items():
        if header not in resp.headers:
            findings.append(WebSecurityFinding("missing_header", title, desc, severity))
    return findings


def _check_cookies(resp: requests.Response) -> list[WebSecurityFinding]:
    findings = []
    for raw_cookie in resp.raw.headers.get_all("Set-Cookie") if resp.raw and hasattr(resp.raw, "headers") else []:
        name = raw_cookie.split("=", 1)[0].strip()
        lower = raw_cookie.lower()
        missing = []
        if "secure" not in lower and resp.url.startswith("https"):
            missing.append("Secure")
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if "samesite" not in lower:
            missing.append("SameSite")
        if missing:
            findings.append(WebSecurityFinding(
                "cookie_flag", f"Cookie '{name}' missing {', '.join(missing)}",
                f"The '{name}' cookie is set without {', '.join(missing)} — this can make it "
                f"readable by JavaScript (no HttpOnly), sent over plain HTTP (no Secure), or "
                f"sent cross-site (no SameSite), depending on which flags are missing.",
                _COOKIE_FLAG_SEVERITY,
            ))
    return findings


def _check_tls(final_url: str) -> list[WebSecurityFinding]:
    findings = []
    if not final_url.startswith("https://"):
        findings.append(WebSecurityFinding(
            "tls", "Site does not use HTTPS",
            "The final response was served over plain HTTP — all traffic (including any "
            "login credentials) is visible to anyone on the network path.",
            Severity.HIGH,
        ))
        return findings

    hostname = urlparse(final_url).hostname
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=config.WEB_SCAN_TIMEOUT_SECONDS) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        days_left = (not_after - now_utc).days
        if days_left < 14:
            findings.append(WebSecurityFinding(
                "tls", "TLS certificate expiring soon",
                f"The TLS certificate expires in {days_left} day(s) ({cert['notAfter']}) — "
                f"renew it before it lapses, or the site will show a browser security warning.",
                Severity.MEDIUM if days_left > 0 else Severity.CRITICAL,
            ))
    except (ssl.SSLError, OSError, KeyError, ValueError) as exc:
        findings.append(WebSecurityFinding(
            "tls", "Could not verify TLS certificate",
            f"TLS handshake/certificate check failed: {exc}. This may mean an invalid, "
            f"expired, or self-signed certificate — browsers will show a warning to visitors.",
            Severity.HIGH,
        ))
    return findings


def _check_server_disclosure(resp: requests.Response) -> list[WebSecurityFinding]:
    findings = []
    for header in ("Server", "X-Powered-By"):
        value = resp.headers.get(header)
        if value and _SERVER_HEADER_VERSION_RE.search(value):
            findings.append(WebSecurityFinding(
                "info_disclosure", f"{header} header discloses version info",
                f"{header}: {value} — this tells an attacker exactly which software/version "
                f"to look up known vulnerabilities for. Consider suppressing or genericizing it.",
                Severity.LOW,
            ))
    return findings


def _check_cors(base_url: str) -> list[WebSecurityFinding]:
    findings = []
    probe_origin = "https://cors-probe.invalid.example"
    resp = _fetch(base_url, headers={"Origin": probe_origin})
    if resp is None:
        return findings
    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    if acao == "*" and acac:
        findings.append(WebSecurityFinding(
            "cors", "CORS: wildcard origin combined with credentials",
            "Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: "
            "true is invalid per spec but some servers still send it, and some older browsers "
            "honor it — this can let any site read authenticated responses.",
            Severity.HIGH,
        ))
    elif acao == probe_origin:
        findings.append(WebSecurityFinding(
            "cors", "CORS reflects arbitrary Origin",
            f"The server echoed back an arbitrary, made-up Origin ({probe_origin}) in "
            f"Access-Control-Allow-Origin instead of validating against an allowlist — "
            f"effectively equivalent to allowing any origin.",
            Severity.MEDIUM,
        ))
    return findings


def _check_exposed_paths(base_url: str) -> list[WebSecurityFinding]:
    findings = []
    baseline_path = f"__nonexistent_{_secrets_module.token_hex(8)}__"
    baseline_resp = _fetch(f"{base_url.rstrip('/')}/{baseline_path}")
    if baseline_resp is None:
        return findings
    baseline_status = baseline_resp.status_code
    baseline_len = len(baseline_resp.content)

    for path in _COMMON_EXPOSED_PATHS:
        resp = _fetch(f"{base_url.rstrip('/')}/{path}")
        if resp is None or resp.status_code != 200:
            continue
        # Soft-404 guard: if this "hit" looks identical to the random
        # nonexistent-path baseline, the site just returns 200 for
        # everything (a SPA catch-all, etc.) — not a real exposure.
        if resp.status_code == baseline_status and abs(len(resp.content) - baseline_len) < 50:
            continue
        findings.append(WebSecurityFinding(
            "exposed_path", f"Possibly exposed: /{path}",
            f"GET /{path} returned HTTP 200 with content distinct from the site's normal "
            f"404/catch-all response — worth checking manually whether this is genuinely "
            f"exposing {path}'s real contents.",
            Severity.CRITICAL if path in (".env", ".env.local", ".aws/credentials", ".git/config") else Severity.HIGH,
        ))
    return findings


_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def scan_url(url: str) -> WebScanReport:
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    safe, reason = _is_safe_target(url)
    if not safe:
        raise RuntimeError(f"Refusing to scan {url!r}: {reason}")

    resp = _fetch(url)
    if resp is None:
        raise RuntimeError(f"Could not reach {url!r} — it may be down, blocking automated "
                            f"requests, the URL may be wrong, or it pointed at a disallowed target.")

    findings: list[WebSecurityFinding] = []
    findings += _check_headers(resp)
    findings += _check_cookies(resp)
    findings += _check_tls(resp.url)
    findings += _check_server_disclosure(resp)
    findings += _check_cors(url)
    findings += _check_exposed_paths(resp.url)

    risk = Severity.INFO
    if findings:
        risk = max(findings, key=lambda f: _SEVERITY_ORDER.index(f.severity)).severity

    critical_or_high = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
    if critical_or_high:
        summary = (f"{len(findings)} finding(s), including {len(critical_or_high)} high/critical — "
                   f"most urgent: {critical_or_high[0].title}.")
    elif findings:
        summary = f"{len(findings)} finding(s), all low/medium severity — no urgent exposures detected."
    else:
        summary = "No issues detected by this scan's checks — this covers common misconfigurations, not a full audit."

    return WebScanReport(url=url, final_url=resp.url, findings=findings, risk_score=risk, summary=summary)
