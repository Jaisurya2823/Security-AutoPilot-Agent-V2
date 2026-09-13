"""
Parses dependency manifest files into normalized PackageRef objects.

Supports requirements.txt (PyPI) and package.json (npm) — the two
highest-coverage formats. Cargo.toml/pyproject.toml/lockfiles are not
yet implemented; see the roadmap. Nothing here is simulated: this parses
whatever text is actually handed to it, and packages with no pinned
version are reported as unresolved rather than silently guessed at.
"""
from __future__ import annotations

import json
import re

from .models import PackageRef

# Matches `name==1.2.3`, `name>=1.2.3`, `name~=1.2`, `name` (unpinned),
# with optional extras (`name[extra]==1.2.3`) and inline comments.
_REQUIREMENTS_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)"        # package name
    r"(?:\[[^\]]*\])?"                          # optional extras, e.g. [security]
    r"\s*(==|>=|<=|~=|!=|>|<)?\s*"               # optional version operator
    r"([A-Za-z0-9.*+!-]+)?"                      # optional version
)


def parse_requirements_txt(content: str) -> tuple[list[PackageRef], list[str]]:
    """Returns (resolved, unresolved_names). A package is unresolved if
    it has no exact pinned version (OSV can't be queried without one) —
    e.g. unpinned, a range like >=1.0, or a VCS/URL requirement."""
    resolved: list[PackageRef] = []
    unresolved: list[str] = []

    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")):
            continue  # blank, comment-only, or pip option flag (-r, --index-url, etc.)
        if "://" in line or line.startswith("git+"):
            unresolved.append(line)  # VCS/URL requirement — no OSV-queryable version
            continue

        match = _REQUIREMENTS_LINE.match(line)
        if not match:
            unresolved.append(line)
            continue

        name, operator, version = match.groups()
        if operator == "==" and version:
            resolved.append(PackageRef(name=name, ecosystem="PyPI", version=version, raw_spec=line))
        else:
            unresolved.append(line)

    return resolved, unresolved


def parse_package_json(content: str) -> tuple[list[PackageRef], list[str], list[str]]:
    """Returns (resolved, unresolved_names, suspicious_scripts). A version
    like "^1.2.3" or "~1.2.3" is treated as unresolved (range, not exact),
    matching the same OSV-needs-an-exact-version rule as requirements.txt."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"package.json is not valid JSON: {exc}") from exc

    resolved: list[PackageRef] = []
    unresolved: list[str] = []

    deps = {}
    deps.update(data.get("dependencies", {}) or {})
    deps.update(data.get("devDependencies", {}) or {})

    for name, spec in deps.items():
        spec = str(spec).strip()
        if re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?", spec):
            resolved.append(PackageRef(name=name, ecosystem="npm", version=spec, raw_spec=f"{name}@{spec}"))
        else:
            unresolved.append(f"{name}@{spec}")

    suspicious_scripts = []
    scripts = data.get("scripts", {}) or {}
    # Lifecycle scripts that run automatically on `npm install` without the
    # developer explicitly invoking them — the classic supply-chain-attack
    # vector (steal env vars/tokens, drop a payload, phone home).
    for hook in ("preinstall", "install", "postinstall"):
        if hook in scripts and scripts[hook].strip():
            suspicious_scripts.append(f"{hook}: {scripts[hook]}")

    return resolved, unresolved, suspicious_scripts
