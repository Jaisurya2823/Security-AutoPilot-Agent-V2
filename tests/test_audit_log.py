from unittest.mock import patch

from src import audit_log, graph
from src.models import ActionType, Alert, RemediationPlan, Severity, TriageResult


def test_audit_log_captures_full_decision_trail():
    triage = TriageResult(severity=Severity.HIGH, threat_category="c2", confidence=0.9, reasoning="r")
    plan = RemediationPlan(action=ActionType.NOTIFY_ONLY, target="1.2.3.4", justification="j", requires_approval=True)
    alert = Alert(source="firewall", description="d", raw_log="l", asset_id="host-9", asset_ip="1.2.3.4")

    with patch("src.graph.groq_client.classify_alert", return_value=triage), \
         patch("src.graph.groq_client.plan_remediation", return_value=plan):
        compiled, config, result = graph.run_alert(alert)
        graph.resume_alert(compiled, config, approved=True, note="confirmed")

    entries = audit_log.read_for_alert(alert.id)
    event_types = [e["event"] for e in entries]

    assert event_types == ["enrich", "triage", "decide", "human_gate", "execute"]
    assert entries[1]["triage"]["severity"] == "high"
    assert entries[3]["approved"] is True
    # notify_only always truthfully succeeds — it's the agent's own
    # decision record, not a claim about an external system (see
    # remediation.py's module docstring on the fail-closed design).
    assert "EXECUTED" in entries[4]["log_line"]
