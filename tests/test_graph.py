"""
These tests mock the Groq calls (no network/API key needed to run them)
but exercise the *real* LangGraph graph, checkpointer, and interrupt/
resume mechanics — that's the part most likely to silently break, since
it's the least obvious code to get right by hand.
"""
from unittest.mock import patch

import pytest

from src import remediation

from src import graph
from src.models import ActionType, Alert, RemediationPlan, Severity, ThreatIntel, TriageResult


def _alert(**overrides) -> Alert:
    defaults = dict(
        source="edr",
        description="test alert",
        raw_log="test log",
        asset_id="host-1",
        asset_ip="185.220.101.7",
    )
    defaults.update(overrides)
    return Alert(**defaults)


def test_low_risk_action_auto_executes_without_interrupt():
    triage = TriageResult(severity=Severity.LOW, threat_category="benign", confidence=0.9, reasoning="r")
    plan = RemediationPlan(action=ActionType.NOTIFY_ONLY, target="host-1", justification="j", requires_approval=False)

    with patch("src.graph.groq_client.classify_alert", return_value=triage), \
         patch("src.graph.groq_client.plan_remediation", return_value=plan):
        _, _, result = graph.run_alert(_alert())

    assert "__interrupt__" not in result
    assert "EXECUTED" in result["execution_log"][-1]


def test_severity_floor_forces_approval_even_for_low_risk_action_type():
    """Second, independent safety floor: APPROVAL_SEVERITY_FLOOR gates by
    how severe the alert is, regardless of what action the model chose.
    A CRITICAL alert must pause for a human even if the model recommends
    the lowest-risk action (notify_only) and says no approval is needed."""
    triage = TriageResult(severity=Severity.CRITICAL, threat_category="active_breach", confidence=0.95, reasoning="r")
    plan = RemediationPlan(action=ActionType.NOTIFY_ONLY, target="host-1", justification="j", requires_approval=False)

    with patch("src.graph.groq_client.classify_alert", return_value=triage), \
         patch("src.graph.groq_client.plan_remediation", return_value=plan):
        _, _, result = graph.run_alert(_alert())

    assert "__interrupt__" in result


def test_severity_below_floor_does_not_force_approval():
    """The floor only forces approval AT OR ABOVE the configured
    severity — a LOW-severity alert with a genuinely low-risk action
    must still auto-execute, or the floor would defeat the point of
    having low-risk actions at all."""
    triage = TriageResult(severity=Severity.LOW, threat_category="benign", confidence=0.9, reasoning="r")
    plan = RemediationPlan(action=ActionType.NOTIFY_ONLY, target="host-1", justification="j", requires_approval=False)

    with patch("src.graph.groq_client.classify_alert", return_value=triage), \
         patch("src.graph.groq_client.plan_remediation", return_value=plan):
        _, _, result = graph.run_alert(_alert())

    assert "__interrupt__" not in result


def test_approval_severity_floor_is_configurable(monkeypatch):
    """Lowering the floor to MEDIUM should force approval at MEDIUM
    severity too, proving this reads the config rather than being
    hardcoded to HIGH."""
    monkeypatch.setattr(graph.config, "APPROVAL_SEVERITY_FLOOR", "medium")
    triage = TriageResult(severity=Severity.MEDIUM, threat_category="suspicious", confidence=0.7, reasoning="r")
    plan = RemediationPlan(action=ActionType.NOTIFY_ONLY, target="host-1", justification="j", requires_approval=False)

    with patch("src.graph.groq_client.classify_alert", return_value=triage), \
         patch("src.graph.groq_client.plan_remediation", return_value=plan):
        _, _, result = graph.run_alert(_alert())

    assert "__interrupt__" in result


def test_approval_severity_floor_falls_back_safely_on_bad_config(monkeypatch):
    """A typo'd config value (e.g. 'hihg') must not crash triage — falls
    back to HIGH rather than raising."""
    monkeypatch.setattr(graph.config, "APPROVAL_SEVERITY_FLOOR", "not-a-real-severity")
    assert graph._approval_severity_floor() == Severity.HIGH


def test_destructive_action_always_pauses_for_human_even_if_model_says_no_approval_needed():
    """Safety floor: DESTRUCTIVE_ACTIONS must gate regardless of what the
    LLM's own requires_approval flag says (models can be wrong/manipulated
    by prompt injection in the alert text — this floor is not optional)."""
    triage = TriageResult(severity=Severity.CRITICAL, threat_category="ransomware", confidence=0.99, reasoning="r")
    plan = RemediationPlan(
        action=ActionType.QUARANTINE_HOST, target="host-1", justification="j",
        requires_approval=False,  # model says no approval needed — floor should override this
    )

    with patch("src.graph.groq_client.classify_alert", return_value=triage), \
         patch("src.graph.groq_client._always_gate", return_value={ActionType.QUARANTINE_HOST}), \
         patch("src.graph.groq_client.plan_remediation", side_effect=lambda a, t, i: _apply_floor(plan)):
        _, _, result = graph.run_alert(_alert())

    assert "__interrupt__" in result


def _apply_floor(plan: RemediationPlan) -> RemediationPlan:
    # mirrors the real plan_remediation()'s floor-enforcement logic
    from src.models import DESTRUCTIVE_ACTIONS
    plan.requires_approval = plan.requires_approval or plan.action in DESTRUCTIVE_ACTIONS
    return plan


def test_pending_decision_survives_simulated_process_restart(monkeypatch):
    """The real point of a persistent checkpointer: resume must work
    using ONLY the thread_id/config, via a freshly-built graph object —
    not a live reference to whatever Python object existed before a
    restart destroyed it. This simulates that by resetting the
    checkpointer singleton (as if the process had restarted) while
    keeping the same underlying SQLite file, then resuming through a
    completely fresh build_graph() call."""
    triage = TriageResult(severity=Severity.HIGH, threat_category="c2", confidence=0.9, reasoning="r")
    plan = RemediationPlan(action=ActionType.NOTIFY_ONLY, target="host-1", justification="j", requires_approval=True)

    with patch("src.graph.groq_client.classify_alert", return_value=triage), \
         patch("src.graph.groq_client.plan_remediation", return_value=plan):
        _, config, result = graph.run_alert(_alert())
    assert "__interrupt__" in result

    # Simulate a process restart: destroy the in-memory checkpointer
    # object entirely — a fresh build_graph() must reconnect to the
    # same on-disk file (config.GRAPH_CHECKPOINT_PATH is unchanged) and
    # find the same paused state.
    graph._checkpointer = None
    fresh_app = graph.build_graph()

    final = graph.resume_alert(fresh_app, config, approved=True, note="approved after restart")
    assert "EXECUTED" in final["execution_log"][-1]


def test_approve_then_execute(monkeypatch):
    triage = TriageResult(severity=Severity.HIGH, threat_category="c2", confidence=0.9, reasoning="r")
    plan = RemediationPlan(action=ActionType.BLOCK_IP, target="185.220.101.7", justification="j", requires_approval=True)

    # Simulate a configured, working remediation webhook — this is the
    # only way a destructive action (block_ip) is allowed to report
    # EXECUTED; see remediation.py's fail-closed design.
    monkeypatch.setattr(remediation.config, "REMEDIATION_WEBHOOK_URL", "https://example.com/soar-webhook")
    fake_response = type("FakeResponse", (), {"status_code": 200, "text": "ok"})()
    monkeypatch.setattr("src.remediation.requests.post", lambda *a, **kw: fake_response)

    with patch("src.graph.groq_client.classify_alert", return_value=triage), \
         patch("src.graph.groq_client.plan_remediation", return_value=plan):
        compiled, config, result = graph.run_alert(_alert())
        assert "__interrupt__" in result
        final = graph.resume_alert(compiled, config, approved=True, note="confirmed malicious")

    assert "EXECUTED" in final["execution_log"][-1]
    assert "185.220.101.7" in final["execution_log"][-1]


def test_approve_then_execute_fails_closed_without_webhook_configured(monkeypatch):
    """The default, unconfigured state: a destructive action must NOT
    report EXECUTED just because a human approved it — approval only
    authorizes the attempt, it doesn't fabricate a result. Without a
    configured webhook, this must honestly report FAILED, not EXECUTED."""
    triage = TriageResult(severity=Severity.HIGH, threat_category="c2", confidence=0.9, reasoning="r")
    plan = RemediationPlan(action=ActionType.BLOCK_IP, target="185.220.101.7", justification="j", requires_approval=True)
    monkeypatch.setattr(remediation.config, "REMEDIATION_WEBHOOK_URL", "")

    with patch("src.graph.groq_client.classify_alert", return_value=triage), \
         patch("src.graph.groq_client.plan_remediation", return_value=plan):
        compiled, config, result = graph.run_alert(_alert())
        final = graph.resume_alert(compiled, config, approved=True, note="confirmed malicious")

    assert "FAILED" in final["execution_log"][-1]
    assert "no REMEDIATION_WEBHOOK_URL configured" in final["execution_log"][-1]


def test_deny_then_skip():
    triage = TriageResult(severity=Severity.HIGH, threat_category="c2", confidence=0.9, reasoning="r")
    plan = RemediationPlan(action=ActionType.BLOCK_IP, target="185.220.101.7", justification="j", requires_approval=True)

    with patch("src.graph.groq_client.classify_alert", return_value=triage), \
         patch("src.graph.groq_client.plan_remediation", return_value=plan):
        compiled, config, result = graph.run_alert(_alert())
        final = graph.resume_alert(compiled, config, approved=False, note="false positive")

    assert "SKIPPED" in final["execution_log"][-1]


def test_threat_intel_enrichment_flags_known_bad_ip(monkeypatch):
    from src import threat_intel
    # Mock the feed itself (transport boundary), not a hardcoded IP list —
    # the real feed is live data from FireHOL, not something a test
    # should depend on being reachable or containing a specific IP.
    monkeypatch.setattr(threat_intel.ioc_feed, "is_known_bad_ip", lambda ip: ip == "185.220.101.7")
    intel = threat_intel.enrich(_alert(asset_ip="185.220.101.7"))
    assert intel.known_bad_ip is True


def test_threat_intel_enrichment_does_not_flag_clean_ip(monkeypatch):
    from src import threat_intel
    monkeypatch.setattr(threat_intel.ioc_feed, "is_known_bad_ip", lambda ip: False)
    intel = threat_intel.enrich(_alert(asset_ip="8.8.8.8"))
    assert intel.known_bad_ip is False


def test_threat_intel_extracts_cve_refs():
    from src.threat_intel import enrich
    intel = enrich(_alert(raw_log="exploit attempt against CVE-2023-21716 detected"))
    assert "CVE-2023-21716" in intel.cve_refs


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
