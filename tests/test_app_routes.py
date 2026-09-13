from __future__ import annotations

import io
import zipfile
from unittest.mock import patch

import pytest

import app as app_module


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


def _make_zip_bytes(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


class _FakeOsvResponse:
    def __init__(self, json_body, status_code=200):
        self._json_body = json_body
        self.status_code = status_code

    def json(self):
        return self._json_body

    def raise_for_status(self):
        pass


def test_investigate_repo_via_zip_upload(client):
    zip_bytes = _make_zip_bytes({
        "requirements.txt": "flask==3.0.0\n",
        "app.py": '@app.route("/admin/x", methods=["POST"])\ndef x(): pass\n',
    })
    fake_tm_llm = {"repo_summary": "s", "additional_threats": [], "risk_score": "low", "recommendations": []}
    fake_ap_llm = {"narrative": "n", "steps": []}

    with patch("src.groq_client.generate_threat_model", return_value=fake_tm_llm), \
         patch("src.groq_client.generate_attack_path", return_value=fake_ap_llm):
        resp = client.post(
            "/investigate/repo",
            data={"zip": (io.BytesIO(zip_bytes), "repo.zip")},
            content_type="multipart/form-data",
        )

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["repo_intel"]["frameworks"] == ["Flask"]
    assert "threat_model" in body
    assert "attack_path" in body


def test_investigate_repo_requires_zip_or_url(client):
    resp = client.post("/investigate/repo", json={})
    assert resp.status_code == 400
    assert "repo_url" in resp.get_json()["error"]


def test_investigate_repo_rejects_malicious_zip(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/evil", "malicious")
    resp = client.post(
        "/investigate/repo",
        data={"zip": (io.BytesIO(buf.getvalue()), "evil.zip")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    assert "traversal" in resp.get_json()["error"]


def test_investigate_dependencies_via_json(client):
    querybatch_response = _FakeOsvResponse({"results": [{"vulns": []}]})
    with patch("src.supply_chain.requests.request", lambda method, url, **kw: querybatch_response):
        resp = client.post("/investigate/dependencies", json={
            "filename": "requirements.txt",
            "content": "requests==2.31.0\n",
        })
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ecosystem"] == "PyPI"
    assert body["overall_trust_score"] == 100


def test_investigate_dependencies_via_file_upload(client):
    querybatch_response = _FakeOsvResponse({"results": [{"vulns": []}]})
    with patch("src.supply_chain.requests.request", lambda method, url, **kw: querybatch_response):
        resp = client.post(
            "/investigate/dependencies",
            data={"manifest": (io.BytesIO(b"requests==2.31.0\n"), "requirements.txt")},
            content_type="multipart/form-data",
        )
    assert resp.status_code == 200
    assert resp.get_json()["ecosystem"] == "PyPI"


def test_investigate_dependencies_rejects_unsupported_manifest(client):
    resp = client.post("/investigate/dependencies", json={"filename": "Cargo.toml", "content": "[dependencies]"})
    assert resp.status_code == 400


def test_investigate_phishing_requires_text(client):
    resp = client.post("/investigate/phishing", json={})
    assert resp.status_code == 400


def test_investigate_phishing_returns_report(client):
    fake_llm = {"is_likely_phishing": False, "confidence": 0.1, "reasoning": "benign", "recommended_action": "none"}
    with patch("src.groq_client.classify_phishing_message", return_value=fake_llm):
        resp = client.post("/investigate/phishing", json={"text": "Hey, lunch tomorrow?"})
    assert resp.status_code == 200
    assert resp.get_json()["risk_score"] == "info"


def test_dashboard_serves_all_investigation_tabs(client):
    resp = client.get("/")
    assert resp.status_code == 200
    for marker in (b"tab-repo", b"tab-deps", b"tab-phishing", b"tab-alerts"):
        assert marker in resp.data


# ---------------------------------------------------------------------------
# Crash-hardening regression tests.
#
# Every case here was found by an actual crash-test battery run against
# the live app (malformed JSON shapes, wrong types, missing fields,
# huge/unicode/null-byte payloads) — not hypothetical edge cases. Each
# assertion is "must not be a raw 500/unhandled exception", and where
# applicable "must be the specific clean status code", never just
# "the app didn't literally fall over".
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_body", [
    [1, 2, 3],           # JSON array instead of object
    "just a string",     # JSON string instead of object
    42,                  # JSON number instead of object
    None,                # JSON null
])
@pytest.mark.parametrize("path", ["/alerts", "/investigate/repo", "/investigate/dependencies", "/investigate/phishing"])
def test_every_post_route_rejects_non_object_json_cleanly(client, path, bad_body):
    resp = client.post(path, json=bad_body)
    assert resp.status_code == 400
    assert resp.is_json
    assert "error" in resp.get_json()


def test_alerts_rejects_missing_required_fields(client):
    for body in ({}, {"description": "d"}, {"asset_id": "a"}):
        resp = client.post("/alerts", json=body)
        assert resp.status_code == 400


def test_alerts_rejects_wrong_field_types(client):
    cases = [
        {"description": 123, "asset_id": "x"},
        {"description": {"a": 1}, "asset_id": "x"},
        {"description": "d", "asset_id": None},
        {"description": "d", "asset_id": "x", "asset_ip": [1, 2, 3]},
        {"description": "d", "asset_id": "x", "source": 5},
        {"description": "d", "asset_id": "x", "raw_log": {"a": 1}},
    ]
    for body in cases:
        resp = client.post("/alerts", json=body)
        assert resp.status_code == 400, f"expected 400 for {body}"


def test_alerts_rejects_empty_string_fields(client):
    resp = client.post("/alerts", json={"description": "", "asset_id": "x"})
    assert resp.status_code == 400
    resp = client.post("/alerts", json={"description": "   ", "asset_id": "x"})
    assert resp.status_code == 400


def test_alerts_accepts_unicode_and_special_characters(client, monkeypatch):
    """These are legitimate inputs, not malformed ones — must pass
    validation and reach the triage logic, not be rejected as bad input."""
    from src.models import ActionType, RemediationPlan, Severity, TriageResult
    fake_triage = TriageResult(severity=Severity.LOW, threat_category="benign", confidence=0.2, reasoning="r")
    fake_plan = RemediationPlan(action=ActionType.NOTIFY_ONLY, target="x", justification="j", requires_approval=False)
    monkeypatch.setattr("src.graph.groq_client.classify_alert", lambda a, i: fake_triage)
    monkeypatch.setattr("src.graph.groq_client.plan_remediation", lambda a, t, i: fake_plan)

    resp = client.post("/alerts", json={
        "description": "🔥💀 admin'; DROP TABLE users--",
        "asset_id": "héllo-wörld",
        "raw_log": "line with\x00null byte and \t\n whitespace",
    })
    assert resp.status_code == 200


def test_alerts_handles_large_description_without_crashing(client, monkeypatch):
    from src.models import ActionType, RemediationPlan, Severity, TriageResult
    fake_triage = TriageResult(severity=Severity.LOW, threat_category="benign", confidence=0.2, reasoning="r")
    fake_plan = RemediationPlan(action=ActionType.NOTIFY_ONLY, target="x", justification="j", requires_approval=False)
    monkeypatch.setattr("src.graph.groq_client.classify_alert", lambda a, i: fake_triage)
    monkeypatch.setattr("src.graph.groq_client.plan_remediation", lambda a, t, i: fake_plan)

    resp = client.post("/alerts", json={"description": "A" * 500_000, "asset_id": "x"})
    assert resp.status_code == 200


def test_alerts_reports_llm_failure_as_clean_502_not_a_crash(client, monkeypatch):
    def _raise(*a, **kw):
        raise RuntimeError("Groq call failed after 3 attempts: simulated outage")
    monkeypatch.setattr("src.graph.groq_client.classify_alert", _raise)

    resp = client.post("/alerts", json={"description": "d", "asset_id": "x"})
    assert resp.status_code == 502
    assert "error" in resp.get_json()


def test_approve_handles_nonexistent_id_and_malformed_body(client):
    resp = client.post("/approve/does-not-exist", json={"approved": True})
    assert resp.status_code == 404

    resp = client.post("/approve/does-not-exist", json=[1, 2, 3])
    assert resp.status_code == 404  # nonexistent id short-circuits before body is even parsed


def test_investigate_repo_rejects_wrong_field_types(client):
    resp = client.post("/investigate/repo", json={"repo_url": 12345})
    assert resp.status_code == 400

    resp = client.post("/investigate/repo", json={"repo_url": "https://evil.com/not/github"})
    assert resp.status_code == 400


def test_investigate_repo_no_body_no_files(client):
    resp = client.post("/investigate/repo")
    assert resp.status_code == 400


def test_investigate_dependencies_rejects_wrong_field_types(client):
    resp = client.post("/investigate/dependencies", json={"filename": 123, "content": "x"})
    assert resp.status_code == 400

    resp = client.post("/investigate/dependencies", json={"filename": "requirements.txt", "content": None})
    assert resp.status_code == 400


def test_investigate_phishing_rejects_wrong_field_types(client):
    for body in ({"text": 12345}, {"text": None}, {"text": ""}, {"text": "   "}):
        resp = client.post("/investigate/phishing", json=body)
        assert resp.status_code == 400


def test_wrong_http_method_returns_405_not_a_crash(client):
    resp = client.delete("/alerts")
    assert resp.status_code == 405


def test_nonexistent_route_returns_404_not_a_crash(client):
    resp = client.get("/this-route-does-not-exist")
    assert resp.status_code == 404


def test_get_routes_never_crash_on_empty_state(client):
    """/pending and /history must return a clean empty list, never crash,
    when nothing has ever been submitted."""
    assert client.get("/pending").status_code == 200
    assert client.get("/pending").get_json() == []
    assert client.get("/history").status_code == 200
    assert client.get("/history").get_json() == []


def test_healthz_always_ok(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}
