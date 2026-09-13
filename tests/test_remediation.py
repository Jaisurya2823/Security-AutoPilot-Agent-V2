"""
Tests for remediation.py.

The core property under test: a destructive action (block_ip,
quarantine_host, disable_account) or an externally-visible one
(open_ticket) must NEVER report success unless a real, configured
webhook call actually succeeded. notify_only and escalate_to_human are
the two actions that don't claim an external system changed state, so
they always truthfully succeed.
"""
from __future__ import annotations

from src import remediation
from src.models import ActionType, RemediationPlan


def _plan(action: ActionType) -> RemediationPlan:
    return RemediationPlan(action=action, target="185.220.101.7", justification="test", requires_approval=True)


def test_notify_only_always_succeeds_without_webhook(monkeypatch):
    monkeypatch.setattr(remediation.config, "REMEDIATION_WEBHOOK_URL", "")
    result = remediation.execute(_plan(ActionType.NOTIFY_ONLY))
    assert result.success is True


def test_escalate_always_succeeds_without_webhook(monkeypatch):
    monkeypatch.setattr(remediation.config, "REMEDIATION_WEBHOOK_URL", "")
    result = remediation.execute(_plan(ActionType.ESCALATE_TO_HUMAN))
    assert result.success is True


def test_block_ip_fails_closed_without_webhook_configured(monkeypatch):
    monkeypatch.setattr(remediation.config, "REMEDIATION_WEBHOOK_URL", "")
    result = remediation.execute(_plan(ActionType.BLOCK_IP))
    assert result.success is False
    assert "no REMEDIATION_WEBHOOK_URL configured" in result.detail


def test_quarantine_host_fails_closed_without_webhook_configured(monkeypatch):
    monkeypatch.setattr(remediation.config, "REMEDIATION_WEBHOOK_URL", "")
    result = remediation.execute(_plan(ActionType.QUARANTINE_HOST))
    assert result.success is False


def test_disable_account_fails_closed_without_webhook_configured(monkeypatch):
    monkeypatch.setattr(remediation.config, "REMEDIATION_WEBHOOK_URL", "")
    result = remediation.execute(_plan(ActionType.DISABLE_ACCOUNT))
    assert result.success is False


def test_open_ticket_fails_closed_without_webhook_configured(monkeypatch):
    monkeypatch.setattr(remediation.config, "REMEDIATION_WEBHOOK_URL", "")
    result = remediation.execute(_plan(ActionType.OPEN_TICKET))
    assert result.success is False


def test_block_ip_succeeds_with_configured_webhook_returning_2xx(monkeypatch):
    monkeypatch.setattr(remediation.config, "REMEDIATION_WEBHOOK_URL", "https://example.com/webhook")
    fake_response = type("FakeResponse", (), {"status_code": 200, "text": "ok"})()
    monkeypatch.setattr(remediation.requests, "post", lambda *a, **kw: fake_response)

    result = remediation.execute(_plan(ActionType.BLOCK_IP))
    assert result.success is True
    assert "185.220.101.7" in result.detail


def test_block_ip_fails_when_webhook_returns_error_status(monkeypatch):
    monkeypatch.setattr(remediation.config, "REMEDIATION_WEBHOOK_URL", "https://example.com/webhook")
    fake_response = type("FakeResponse", (), {"status_code": 500, "text": "internal error"})()
    monkeypatch.setattr(remediation.requests, "post", lambda *a, **kw: fake_response)

    result = remediation.execute(_plan(ActionType.BLOCK_IP))
    assert result.success is False
    assert "500" in result.detail


def test_block_ip_fails_when_webhook_raises_network_error(monkeypatch):
    import requests as requests_module

    monkeypatch.setattr(remediation.config, "REMEDIATION_WEBHOOK_URL", "https://example.com/webhook")

    def _raise(*args, **kwargs):
        raise requests_module.ConnectionError("connection refused")

    monkeypatch.setattr(remediation.requests, "post", _raise)

    result = remediation.execute(_plan(ActionType.BLOCK_IP))
    assert result.success is False
    assert "connection refused" in result.detail


def test_execute_result_to_dict_shape():
    result = remediation.ExecutionResult(True, "detail text")
    d = result.to_dict()
    assert d["success"] is True
    assert d["detail"] == "detail text"
    assert isinstance(d["executed_at"], float)
