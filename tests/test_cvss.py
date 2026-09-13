"""
Tests for cvss.py.

Expected scores here are either (a) well-documented, widely-cited real
CVE scores, or (b) independently hand-derived from the CVSS v3.1 spec
formula and shown in the comment so they're re-checkable — not values
pulled from memory and assumed correct. An earlier draft of this test
file used two remembered-but-wrong "expected" scores; they were caught
by the mismatch against this module's actual (verified-correct)
output and replaced with real derivations.
"""
from __future__ import annotations

from src.cvss import cvss3_base_score, parse_cvss3_vector, severity_bucket_from_score


def test_canonical_critical_vector():
    # AV:N=.85 AC:L=.77 PR:N=.85 UI:N=.85 C=I=A:H=.56, scope unchanged
    # ISS = 1-(1-.56)^3 = .914816; Impact = 6.42*.914816 = 5.873119
    # Exploitability = 8.22*.85*.77*.85*.85 = 3.887051
    # Sum = 9.760169 -> roundup -> 9.8
    score = cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score == 9.8
    assert severity_bucket_from_score(score) == "critical"


def test_log4shell_reference_vector():
    # CVE-2021-44228 (Log4Shell) — NVD's published CVSS v3.1 base score
    # is 10.0, one of the most widely-cited CVSS scores in the industry.
    score = cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert score == 10.0
    assert severity_bucket_from_score(score) == "critical"


def test_low_complexity_local_vector_hand_derived():
    # AV:L=.55 AC:H=.44 PR:H(unchanged)=.27 UI:R=.62 C:L=.22 I=A:N=0
    # ISS = 1-(1-.22) = .22; Impact = 6.42*.22 = 1.4124
    # Exploitability = 8.22*.55*.44*.27*.62 = 0.333008...
    # Sum = 1.745408 -> roundup -> 1.8
    score = cvss3_base_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
    assert score == 1.8
    assert severity_bucket_from_score(score) == "low"


def test_scope_changed_vector_hand_derived():
    # AV:N=.85 AC:L=.77 PR:N(changed)=.85 UI:N=.85 C:N=0 I:N=0 A:L=.22
    # ISS = 1-(1-0)(1-0)(1-.22) = .22
    # Impact(changed) = 7.52*(.22-.029) - 3.25*(.22-.02)^15
    #   = 7.52*.191 - 3.25*(.2^15) = 1.43632 - (negligible) ~= 1.43632
    # Exploitability = 8.22*.85*.77*.85*.85 = 3.887051
    # Sum = 5.323 -> *1.08 = 5.749 -> roundup -> 5.8
    score = cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L")
    assert score == 5.8
    assert severity_bucket_from_score(score) == "medium"


def test_no_impact_scores_zero():
    score = cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert score == 0.0
    assert severity_bucket_from_score(score) == "info"


def test_cvss_v3_0_vector_also_supported():
    # v3.0 uses the identical base-score formula to v3.1 — only the
    # version tag in the vector string differs.
    score = cvss3_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score == 9.8


def test_parse_rejects_cvss_v2_vector():
    # A bare CVSS v2 vector (no "CVSS:3.x/" prefix at all) — different
    # formula entirely, deliberately not supported (see module docstring).
    assert parse_cvss3_vector("AV:N/AC:L/Au:N/C:C/I:C/A:C") is None


def test_parse_rejects_incomplete_vector():
    assert parse_cvss3_vector("CVSS:3.1/AV:N/AC:L") is None  # missing required base metrics


def test_parse_rejects_garbage():
    assert parse_cvss3_vector("not a vector at all") is None


def test_base_score_none_for_unparseable_vector():
    assert cvss3_base_score("garbage") is None


def test_base_score_none_for_invalid_metric_value():
    # 'X' is not a defined AV value
    assert cvss3_base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None


def test_severity_bucket_boundaries():
    assert severity_bucket_from_score(0.0) == "info"
    assert severity_bucket_from_score(3.9) == "low"
    assert severity_bucket_from_score(4.0) == "medium"
    assert severity_bucket_from_score(6.9) == "medium"
    assert severity_bucket_from_score(7.0) == "high"
    assert severity_bucket_from_score(8.9) == "high"
    assert severity_bucket_from_score(9.0) == "critical"
    assert severity_bucket_from_score(10.0) == "critical"
