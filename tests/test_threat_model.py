from __future__ import annotations

from src import threat_model
from src.models import Endpoint, RepoIntelReport, SecretFinding, Severity


def _fake_llm_result(additional_threats=None, risk_score="low", recommendations=None):
    return {
        "repo_summary": "A small Flask app with PostgreSQL.",
        "additional_threats": additional_threats or [],
        "risk_score": risk_score,
        "recommendations": recommendations or [],
    }


def test_deterministic_flags_unauthenticated_sensitive_endpoint():
    intel = RepoIntelReport(
        root_path="/x",
        endpoints=[Endpoint(method="POST", path="/admin/delete-user", file="app.py", line=6, framework="Flask", requires_auth=None)],
    )
    threats = threat_model._deterministic_threats(intel)
    assert len(threats) == 1
    assert threats[0].stride_category == "elevation_of_privilege"
    assert threats[0].severity == Severity.HIGH


def test_deterministic_no_threat_for_authenticated_sensitive_endpoint():
    intel = RepoIntelReport(
        root_path="/x",
        endpoints=[Endpoint(method="POST", path="/admin/delete-user", file="app.py", line=6, framework="Flask", requires_auth=True)],
    )
    threats = threat_model._deterministic_threats(intel)
    assert threats == []


def test_deterministic_low_severity_for_unclear_nonsensitive_endpoint():
    intel = RepoIntelReport(
        root_path="/x",
        endpoints=[Endpoint(method="GET", path="/public/health", file="app.py", line=1, framework="Flask", requires_auth=None)],
    )
    threats = threat_model._deterministic_threats(intel)
    assert len(threats) == 1
    assert threats[0].stride_category == "spoofing"
    assert threats[0].severity == Severity.LOW


def test_deterministic_flags_hardcoded_secret():
    intel = RepoIntelReport(
        root_path="/x",
        secrets=[SecretFinding(kind="aws_access_key_id", file="app.py", line=4, masked_preview="AKIA****")],
    )
    threats = threat_model._deterministic_threats(intel)
    assert len(threats) == 1
    assert threats[0].stride_category == "info_disclosure"
    assert threats[0].severity == Severity.CRITICAL


def test_deterministic_flags_raw_db_access_without_orm():
    intel = RepoIntelReport(root_path="/x", database_usage=["PostgreSQL (via psycopg2/SQLAlchemy)"])
    threats = threat_model._deterministic_threats(intel)
    # This particular label mentions SQLAlchemy so should NOT be flagged (ORM present)
    assert threats == []


def test_deterministic_flags_raw_mysql_without_orm_label():
    intel = RepoIntelReport(root_path="/x", database_usage=["MySQL"])
    threats = threat_model._deterministic_threats(intel)
    assert len(threats) == 1
    assert threats[0].stride_category == "tampering"


def test_build_threat_model_merges_deterministic_and_llm(monkeypatch):
    intel = RepoIntelReport(
        root_path="/x",
        endpoints=[Endpoint(method="POST", path="/admin/delete-user", file="app.py", line=6, framework="Flask", requires_auth=None)],
    )
    monkeypatch.setattr(
        threat_model.groq_client, "generate_threat_model",
        lambda repo_intel, det: _fake_llm_result(
            additional_threats=[{
                "stride_category": "denial_of_service",
                "title": "No rate limiting detected",
                "description": "No rate-limiting middleware detected across endpoints.",
                "related_entry_point": "(repo-wide)",
                "severity": "low",
            }],
            risk_score="low",
        )
    )
    report = threat_model.build_threat_model(intel)
    assert len(report.threats) == 2  # 1 deterministic + 1 LLM
    # Overall risk must not be talked down below the worst deterministic finding (HIGH)
    assert report.risk_score == Severity.HIGH


def test_build_threat_model_llm_can_raise_risk_above_deterministic(monkeypatch):
    intel = RepoIntelReport(root_path="/x")  # no findings at all
    monkeypatch.setattr(
        threat_model.groq_client, "generate_threat_model",
        lambda repo_intel, det: _fake_llm_result(risk_score="critical")
    )
    report = threat_model.build_threat_model(intel)
    assert report.risk_score == Severity.CRITICAL


def test_trust_boundaries_empty_repo_gives_honest_fallback():
    intel = RepoIntelReport(root_path="/x")
    boundaries = threat_model._trust_boundaries(intel)
    assert "manual review recommended" in boundaries[0]


def test_entry_points_deduplicated_and_sorted():
    intel = RepoIntelReport(
        root_path="/x",
        endpoints=[
            Endpoint(method="GET", path="/b", file="a.py", line=1, framework="Flask"),
            Endpoint(method="GET", path="/a", file="a.py", line=2, framework="Flask"),
            Endpoint(method="GET", path="/a", file="a.py", line=2, framework="Flask"),  # duplicate
        ],
    )
    assert threat_model._entry_points(intel) == ["GET /a", "GET /b"]
