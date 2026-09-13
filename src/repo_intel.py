"""
Repository Intelligence agent.

Static analysis only — walks an already-extracted repo directory on disk
and pattern-matches real file contents. Nothing here is simulated: every
finding traces back to an actual file/line in the repo handed to it.

Does NOT clone/download repos itself — `app.py` is responsible for
getting a GitHub repo or uploaded ZIP onto disk first (git clone or
zipfile.extract) and passing the resulting directory path in here. That
split keeps this module pure/testable against a plain directory instead
of coupling it to network or archive-extraction concerns.

Known limitations (stated, not hidden):
- Secret detection is regex-based (same category of technique as
  gitleaks/trufflehog default rules), not a full entropy-analysis
  scanner — it will miss secrets that don't match a known key-format
  pattern, and can false-positive on high-entropy non-secret strings.
- Endpoint detection is regex-based per-framework, not a real AST parse
  — dynamically constructed routes (e.g. built from a loop or config
  table) will be missed.
- `requires_auth` on an endpoint is best-effort (checks for common
  decorator/middleware names near the route) and is None when it can't
  be determined — never guessed as a hard True/False.
"""
from __future__ import annotations

import math
import os
import re

from .models import Endpoint, RepoIntelReport, SecretFinding

# Directories never worth scanning — noise and/or huge (vendored deps).
_SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
    ".pytest_cache", ".mypy_cache", "vendor", "target", ".next", "coverage",
}

_LANGUAGE_BY_EXTENSION = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".jsx": "JavaScript",
    ".tsx": "TypeScript", ".go": "Go", ".rb": "Ruby", ".java": "Java",
    ".rs": "Rust", ".php": "PHP", ".cs": "C#",
}

_FRAMEWORK_MANIFEST_HINTS = {
    "requirements.txt": None,   # needs content check, handled separately
    "package.json": None,
    "Gemfile": "Ruby on Rails (or other Rack app)",
    "go.mod": "Go (net/http or a Go web framework)",
    "Cargo.toml": "Rust (Actix/Axum/Rocket — check Cargo.toml for which)",
    "composer.json": "PHP (Laravel/Symfony — check composer.json for which)",
}

# (regex, framework_label) — matched against requirements.txt / package.json content
_PY_FRAMEWORK_PATTERNS = [
    (re.compile(r"\bflask\b", re.IGNORECASE), "Flask"),
    (re.compile(r"\bdjango\b", re.IGNORECASE), "Django"),
    (re.compile(r"\bfastapi\b", re.IGNORECASE), "FastAPI"),
]
_JS_FRAMEWORK_PATTERNS = [
    (re.compile(r'"express"'), "Express"),
    (re.compile(r'"next"'), "Next.js"),
    (re.compile(r'"@nestjs/core"'), "NestJS"),
    (re.compile(r'"koa"'), "Koa"),
]

_DB_IMPORT_PATTERNS = [
    (re.compile(r"\bpsycopg2\b|\bsqlalchemy\b"), "PostgreSQL (via psycopg2/SQLAlchemy)"),
    (re.compile(r"\bpymongo\b|\bmongoose\b"), "MongoDB"),
    (re.compile(r"\bmysqlclient\b|\bpymysql\b|\bmysql2\b"), "MySQL"),
    (re.compile(r"\bredis\b"), "Redis"),
    (re.compile(r"\bsqlite3\b"), "SQLite"),
]

_AUTH_PATTERNS = [
    re.compile(r"\bjwt\b", re.IGNORECASE),
    re.compile(r"\boauth\b", re.IGNORECASE),
    re.compile(r"\bpassport\b"),
    re.compile(r"@login_required\b"),
    re.compile(r"\bsession\[.?['\"]user"),
    re.compile(r"\bbcrypt\b|\bargon2\b"),
]

# Endpoint patterns: (regex, framework, method_group, path_group)
_ENDPOINT_PATTERNS = [
    (re.compile(r'@app\.route\(\s*["\']([^"\']+)["\']\s*(?:,\s*methods\s*=\s*\[([^\]]*)\])?'), "Flask"),
    (re.compile(r'@(?:app|router)\.(get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']', re.IGNORECASE), "FastAPI/Express-style"),
    (re.compile(r'(?:app|router)\.(get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']', re.IGNORECASE), "Express"),
]

def _shannon_entropy(s: str) -> float:
    """Standard Shannon entropy in bits/char — higher means more random.
    Real secrets (API keys, tokens) are machine-generated and near-random;
    English words, common config values, and repeated characters score
    much lower. This is the same core technique TruffleHog/Gitleaks use
    for their entropy-detection mode — a genuinely different signal from
    the format-based regexes below, catching secrets with no recognizable
    prefix/shape at all."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


_HEX_CHARSET = set("0123456789abcdefABCDEF")
# Hex has a lower theoretical max entropy (16 symbols) than base64/mixed
# charsets (64+ symbols), so it needs its own, lower threshold — using
# one threshold for both charsets would either miss real hex secrets or
# flood results with base64 false positives.
_MIN_ENTROPY_HEX = 3.0
_MIN_ENTROPY_GENERAL = 4.3
_MIN_SECRET_LENGTH = 20

# Matches `name = "value"` / `name: "value"` generically — not tied to
# any known secret's naming convention, unlike the format-based
# _SECRET_PATTERNS below. The entropy check decides whether the
# captured value actually looks like a real secret.
_ASSIGNMENT_STRING_RE = re.compile(
    r"""[A-Za-z_][A-Za-z0-9_]*\s*[:=]\s*["']([A-Za-z0-9+/=_\-\.]{%d,})["']""" % _MIN_SECRET_LENGTH
)

# Common high-entropy-looking values that are NOT secrets — without this,
# entropy detection alone floods results with these.
_ENTROPY_FALSE_POSITIVE_RE = re.compile(
    r"^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|"  # UUID
    r"\d+\.\d+\.\d+(?:\.\d+)?|"  # version strings / IP-shaped
    r"[a-z]+(?:[-_][a-z]+)+)$",  # kebab/snake_case identifiers, e.g. my-project-name
    re.IGNORECASE,
)


def _is_high_entropy_secret(value: str) -> bool:
    if _ENTROPY_FALSE_POSITIVE_RE.match(value):
        return False
    if all(c in _HEX_CHARSET for c in value):
        return len(value) >= 32 and _shannon_entropy(value) >= _MIN_ENTROPY_HEX
    return _shannon_entropy(value) >= _MIN_ENTROPY_GENERAL


# Secret patterns: (regex, kind). Format-specific (like gitleaks'
# default ruleset) — catches well-known key/token shapes. Paired below
# with entropy-based detection (_is_high_entropy_secret) as a second,
# independent layer that catches secrets with no recognizable format at
# all, which format-only regexes structurally cannot.
_SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key_id"),
    (re.compile(r"-----BEGIN (RSA|OPENSSH|EC|PGP) PRIVATE KEY-----"), "private_key_header"),
    (re.compile(r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']'), "generic_api_key"),
    (re.compile(r'(?i)password\s*=\s*["\'][^"\']{6,}["\']'), "hardcoded_password"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "openai_style_api_key"),
    (re.compile(r"gsk_[A-Za-z0-9]{20,}"), "groq_api_key"),
]

_CI_CD_FILENAMES = {"Jenkinsfile", ".gitlab-ci.yml", ".travis.yml", "azure-pipelines.yml"}
_CLOUD_HINT_FILENAMES = {
    "Dockerfile": "Docker", "docker-compose.yml": "Docker Compose",
    "render.yaml": "Render", "serverless.yml": "Serverless Framework",
    "vercel.json": "Vercel", "netlify.toml": "Netlify",
    "app.yaml": "Google App Engine",
}
_TERRAFORM_EXTENSION = ".tf"
_K8S_HINT = re.compile(r"^\s*apiVersion:\s*\S", re.MULTILINE)

_TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".java", ".rs", ".php",
    ".cs", ".json", ".yml", ".yaml", ".env", ".txt", ".toml", ".cfg", ".ini",
}
_MAX_FILE_BYTES = 2_000_000  # skip anything absurdly large (generated bundles, data files)


def _mask(secret: str) -> str:
    if len(secret) <= 6:
        return "*" * len(secret)
    return secret[:4] + "*" * (len(secret) - 4)


def _iter_text_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            try:
                if os.path.getsize(full_path) > _MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield full_path, filename


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def _extract_auth_context(lines: list[str], line_no: int) -> str:
    """Lines around a route declaration to check for nearby auth checks.
    Looks a few lines backward (decorator-stacking, e.g. @login_required
    above @app.route) and forward until the *next* route declaration or a
    small cap — whichever comes first. Capping only at a fixed line count
    (without the boundary) was pulling the next route's auth check into
    this route's context and produced a false "requires_auth: True" on an
    actually-unprotected endpoint — caught via the fixture-repo smoke test."""
    start_idx = max(0, line_no - 3)
    scan_limit = min(len(lines), line_no + 8)
    forward_end = scan_limit
    for idx in range(line_no, scan_limit):  # 0-indexed lines after the route declaration
        stripped = lines[idx].strip()
        if stripped.startswith("@") or any(p.search(lines[idx]) for p, _fw in _ENDPOINT_PATTERNS):
            forward_end = idx
            break
    return "\n".join(lines[start_idx:forward_end])


def scan_repo(root: str) -> RepoIntelReport:
    """Walks `root` (an already-extracted repo directory) and builds a
    RepoIntelReport from real pattern matches against real file contents."""
    if not os.path.isdir(root):
        raise ValueError(f"Not a directory: {root!r}")

    report = RepoIntelReport(root_path=root)
    languages: set[str] = set()
    frameworks: set[str] = set()
    databases: set[str] = set()
    auth_hits: set[str] = set()
    has_terraform = False
    has_k8s = False

    for full_path, filename in _iter_text_files(root):
        # Normalized once, here, so every field derived from rel_path below
        # (ci_cd_files, config_files, endpoint.file, secret.file, etc.) is
        # OS-independent — a report generated on Windows and one generated
        # on Linux for the same repo are now byte-identical, which matters
        # for anything downstream that compares/dedupes paths.
        rel_path = os.path.relpath(full_path, root).replace(os.sep, "/")
        _, ext = os.path.splitext(filename)

        if filename in _CI_CD_FILENAMES or "/.github/workflows/" in ("/" + rel_path):
            report.ci_cd_files.append(rel_path)
        if filename in _CLOUD_HINT_FILENAMES:
            report.cloud_hints.append(f"{rel_path} ({_CLOUD_HINT_FILENAMES[filename]})")
        if ext == _TERRAFORM_EXTENSION:
            has_terraform = True
        if filename in ("requirements.txt", "package.json", "Gemfile", "go.mod", "Cargo.toml", "composer.json", "pyproject.toml"):
            report.dependency_manifests.append(rel_path)
        if filename in (".env", ".env.example", "config.py", "config.yml", "config.yaml", "settings.py"):
            report.config_files.append(rel_path)

        if ext not in _TEXT_EXTENSIONS and filename not in _CI_CD_FILENAMES and filename not in _CLOUD_HINT_FILENAMES:
            continue

        if ext in _LANGUAGE_BY_EXTENSION:
            languages.add(_LANGUAGE_BY_EXTENSION[ext])

        content = _read_text(full_path)
        if not content:
            continue

        if (ext in (".yml", ".yaml")) and _K8S_HINT.search(content) and "kind:" in content:
            has_k8s = True

        if filename == "requirements.txt":
            for pattern, label in _PY_FRAMEWORK_PATTERNS:
                if pattern.search(content):
                    frameworks.add(label)
            for pattern, label in _DB_IMPORT_PATTERNS:
                if pattern.search(content):
                    databases.add(label)
        if filename == "package.json":
            for pattern, label in _JS_FRAMEWORK_PATTERNS:
                if pattern.search(content):
                    frameworks.add(label)

        for pattern, label in _DB_IMPORT_PATTERNS:
            if pattern.search(content):
                databases.add(label)

        for pattern in _AUTH_PATTERNS:
            if pattern.search(content):
                auth_hits.add(pattern.pattern)

        for line_no, line in enumerate(content.splitlines(), start=1):
            for pattern, framework in _ENDPOINT_PATTERNS:
                for match in pattern.finditer(line):
                    groups = match.groups()
                    if len(groups) == 2 and groups[0] and groups[0].upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                        method, path = groups[0].upper(), groups[1]
                    elif len(groups) == 2:
                        path, methods_str = groups[0], groups[1]
                        method = methods_str.strip().strip("'\"").upper() if methods_str else "GET"
                    else:
                        continue
                    requires_auth = None
                    lines = content.splitlines()
                    context = _extract_auth_context(lines, line_no)
                    if any(p.search(context) for p in _AUTH_PATTERNS):
                        requires_auth = True
                    report.endpoints.append(Endpoint(
                        method=method, path=path, file=rel_path, line=line_no,
                        framework=framework, requires_auth=requires_auth,
                    ))

            already_flagged_spans = []
            for pattern, kind in _SECRET_PATTERNS:
                for match in pattern.finditer(line):
                    secret_text = match.group(0)
                    already_flagged_spans.append(match.span())
                    report.secrets.append(SecretFinding(
                        kind=kind, file=rel_path, line=line_no, masked_preview=_mask(secret_text),
                    ))

            # Second, independent layer: entropy-based detection catches
            # secrets with no recognizable prefix/shape at all. Skips
            # anything already flagged by a format match on this line so
            # the same token isn't double-reported under two labels.
            for match in _ASSIGNMENT_STRING_RE.finditer(line):
                span = match.span()
                if any(span[0] >= s and span[1] <= e for s, e in already_flagged_spans):
                    continue
                candidate = match.group(1)
                if _is_high_entropy_secret(candidate):
                    report.secrets.append(SecretFinding(
                        kind="high_entropy_token", file=rel_path, line=line_no,
                        masked_preview=_mask(candidate),
                    ))

    report.languages = sorted(languages)
    report.frameworks = sorted(frameworks)
    report.database_usage = sorted(databases)
    report.auth_indicators = sorted(auth_hits)
    if has_terraform:
        report.cloud_hints.append("Terraform (.tf files present)")
    if has_k8s:
        report.cloud_hints.append("Kubernetes manifests present")

    return report
