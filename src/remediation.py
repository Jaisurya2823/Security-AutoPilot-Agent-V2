"""
External tool call #2: executing the chosen remediation action.

There is no single API that works across every firewall/EDR/IdP/
ticketing vendor, so this doesn't hardcode one. Instead: destructive
and externally-visible actions (block_ip, quarantine_host,
disable_account, open_ticket) POST to a webhook you configure
(REMEDIATION_WEBHOOK_URL) — point it at your SOAR platform, your own
automation, or a vendor-specific adapter you own.

This is deliberately fail-closed: if no webhook is configured, or the
call fails, execute() returns success=False with an honest message.
It never reports a firewall rule was added, a host was quarantined, or
an account was disabled unless a real HTTP call to a real endpoint you
configured actually returned success. A security tool that lies about
having executed a block is worse than one that admits it didn't.

notify_only and escalate_to_human are the two actions that don't claim
an external system changed state — they describe the agent's own
internal decision record, which this process can always truthfully
make regardless of webhook configuration.
"""
from __future__ import annotations

import time
from typing import Callable

import requests

from . import config
from .models import ActionType, RemediationPlan


class ExecutionResult:
    def __init__(self, success: bool, detail: str):
        self.success = success
        self.detail = detail
        self.executed_at = time.time()

    def to_dict(self) -> dict:
        return {"success": self.success, "detail": self.detail, "executed_at": self.executed_at}


def _call_webhook(action: ActionType, plan: RemediationPlan) -> ExecutionResult:
    """Shared path for every action that claims to touch a real external
    system. Fails closed: no configured webhook, a non-2xx response, or
    a network error all produce success=False, never a fabricated
    success message."""
    if not config.REMEDIATION_WEBHOOK_URL:
        return ExecutionResult(
            False,
            f"Not executed: no REMEDIATION_WEBHOOK_URL configured to carry out "
            f"'{action.value}' against {plan.target}. Set it to your SOAR/firewall/"
            f"EDR/IdP automation endpoint, or handle this action manually.",
        )

    payload = {
        "action": action.value,
        "target": plan.target,
        "justification": plan.justification,
    }
    try:
        resp = requests.post(
            config.REMEDIATION_WEBHOOK_URL,
            json=payload,
            timeout=config.REMEDIATION_WEBHOOK_TIMEOUT_SECONDS,
        )
        if 200 <= resp.status_code < 300:
            return ExecutionResult(True, f"{action.value} on {plan.target}: webhook accepted ({resp.status_code})")
        return ExecutionResult(
            False,
            f"Webhook rejected '{action.value}' on {plan.target}: HTTP {resp.status_code} — {resp.text[:200]}",
        )
    except requests.RequestException as exc:
        return ExecutionResult(False, f"Webhook call failed for '{action.value}' on {plan.target}: {exc}")


def _notify_only(plan: RemediationPlan) -> ExecutionResult:
    # This is the agent's own decision record, not a claim that an
    # external notification system fired — always truthfully sayable.
    return ExecutionResult(True, f"Recorded: notification regarding {plan.target} — {plan.justification}")


def _open_ticket(plan: RemediationPlan) -> ExecutionResult:
    return _call_webhook(ActionType.OPEN_TICKET, plan)


def _block_ip(plan: RemediationPlan) -> ExecutionResult:
    return _call_webhook(ActionType.BLOCK_IP, plan)


def _quarantine_host(plan: RemediationPlan) -> ExecutionResult:
    return _call_webhook(ActionType.QUARANTINE_HOST, plan)


def _disable_account(plan: RemediationPlan) -> ExecutionResult:
    return _call_webhook(ActionType.DISABLE_ACCOUNT, plan)


def _escalate(plan: RemediationPlan) -> ExecutionResult:
    # Same as notify_only: describes the agent handing this off, not a
    # claim about a paging/on-call system — always truthfully sayable.
    return ExecutionResult(True, f"Recorded: escalated {plan.target} to on-call security engineer — {plan.justification}")


EXECUTORS: dict[ActionType, Callable[[RemediationPlan], ExecutionResult]] = {
    ActionType.NOTIFY_ONLY: _notify_only,
    ActionType.OPEN_TICKET: _open_ticket,
    ActionType.BLOCK_IP: _block_ip,
    ActionType.QUARANTINE_HOST: _quarantine_host,
    ActionType.DISABLE_ACCOUNT: _disable_account,
    ActionType.ESCALATE_TO_HUMAN: _escalate,
}


def execute(plan: RemediationPlan) -> ExecutionResult:
    executor = EXECUTORS.get(plan.action)
    if executor is None:
        return ExecutionResult(False, f"No executor registered for action {plan.action}")
    return executor(plan)
