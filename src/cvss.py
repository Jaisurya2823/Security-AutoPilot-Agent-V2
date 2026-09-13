"""
CVSS v3.0/v3.1 base score calculator.

Implements the official base-score formula from the CVSS v3.1
specification (FIRST.org) directly from a vector string like
"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" — this is deterministic
published math, not a heuristic or a guess. Verified against known
reference vectors with published scores (see tests/test_cvss.py) —
e.g. the vector above scores exactly 9.8, matching FIRST.org's own
calculator and widely-cited CVE examples.

Deliberately does NOT attempt CVSS v2 (different formula entirely) or
CVSS v3 temporal/environmental metrics (context this project doesn't
have) — only the base score, which is what a vulnerability's inherent
severity is graded on.
"""
from __future__ import annotations

import math
import re
from typing import Optional

# Metric weights straight from the CVSS v3.1 specification tables.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}

_REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_VECTOR_RE = re.compile(r"CVSS:3\.[01]/(.+)")


def _roundup(value: float) -> float:
    """The CVSS spec's own rounding rule: round UP to the nearest 0.1,
    computed via an integer trick to sidestep binary floating-point
    representation error (e.g. naive round(x, 1) can round 4.35 down to
    4.3 instead of up to 4.4 depending on how 4.35 is actually
    represented in binary). This is the official algorithm, not our own
    invention — see the CVSS v3.1 spec appendix."""
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000.0
    return (math.floor(int_value / 10000) + 1) / 10.0


def parse_cvss3_vector(vector: str) -> Optional[dict]:
    """Parses a CVSS v3.0/3.1 vector string into a metric dict, or
    returns None if it isn't a well-formed v3 vector with all required
    base metrics present. Never raises on malformed input — a
    malformed vector is reported as unparseable, not guessed at."""
    match = _VECTOR_RE.match(vector.strip())
    if not match:
        return None

    metrics: dict[str, str] = {}
    for part in match.group(1).split("/"):
        if ":" not in part:
            return None
        key, value = part.split(":", 1)
        metrics[key] = value

    if not all(m in metrics for m in _REQUIRED_METRICS):
        return None
    return metrics


def cvss3_base_score(vector: str) -> Optional[float]:
    """Returns the CVSS v3 base score (0.0-10.0), or None if the vector
    can't be parsed or uses a metric value outside the defined set."""
    metrics = parse_cvss3_vector(vector)
    if metrics is None:
        return None

    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        scope_changed = metrics["S"] == "C"
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        c = _CIA[metrics["C"]]
        i = _CIA[metrics["I"]]
        a = _CIA[metrics["A"]]
    except KeyError:
        return None  # a metric value not in the defined set (e.g. a typo or future CVSS version's letters)

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui

    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def severity_bucket_from_score(score: float) -> str:
    """Standard CVSS v3 qualitative severity rating scale."""
    if score <= 0.0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"
