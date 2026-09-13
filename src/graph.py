"""
The agent's control flow, as a LangGraph StateGraph.

    ingest -> enrich -> triage -> decide -> human_gate -> execute -> END

human_gate is the human-in-the-loop checkpoint: it uses LangGraph's
dynamic `interrupt()` so the graph actually pauses execution and
returns control to the caller when (and only when) the remediation
plan needs sign-off. Low-risk actions (notify/ticket) sail through with
no pause.

State is checkpointed to a local SQLite file (src/config.py's
GRAPH_CHECKPOINT_PATH), not the default in-memory-only checkpointer —
so a paused decision genuinely survives a process restart. Resuming
only needs the thread_id (the alert's own id), not a live reference to
whichever Python object was compiled before the restart — build_graph()
always binds to the same on-disk checkpoint store, so any freshly-built
graph sees exactly the state a pre-restart one would have.
"""
from __future__ import annotations

import sqlite3
from typing import Optional, TypedDict

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, StateGraph
from langgraph.types import Command, interrupt

from . import audit_log, config, groq_client, remediation, threat_intel
from .models import Alert, RemediationPlan, Severity, ThreatIntel, TriageResult

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _approval_severity_floor() -> Severity:
    """Reads APPROVAL_SEVERITY_FLOOR fresh each time (not just at import)
    so tests can monkeypatch it, and falls back safely to HIGH if the
    env var holds something that isn't a real Severity value, rather
    than crashing triage over a config typo."""
    try:
        return Severity(config.APPROVAL_SEVERITY_FLOOR)
    except ValueError:
        return Severity.HIGH


class AgentState(TypedDict, total=False):
    alert: Alert
    intel: ThreatIntel
    triage: TriageResult
    plan: RemediationPlan
    approved: Optional[bool]
    approver_note: Optional[str]
    execution_log: list[str]


def _enrich_node(state: AgentState) -> AgentState:
    intel = threat_intel.enrich(state["alert"])
    audit_log.record("enrich", state["alert"].id, threat_intel=intel.to_dict())
    return {"intel": intel}


def _triage_node(state: AgentState) -> AgentState:
    triage = groq_client.classify_alert(state["alert"], state["intel"])
    audit_log.record("triage", state["alert"].id, triage=triage.to_dict())
    return {"triage": triage}


def _decide_node(state: AgentState) -> AgentState:
    plan = groq_client.plan_remediation(state["alert"], state["triage"], state["intel"])

    # Two independent floors the model can't lower, checked here (not
    # left to plan_remediation's own requires_approval judgment):
    # DESTRUCTIVE_ACTIONS gates by *what* the action is; this gates by
    # *how severe* the underlying alert is, regardless of what action
    # the model chose. A model that recommends "notify_only" for a
    # CRITICAL alert still forces human eyes on it.
    floor = _approval_severity_floor()
    if _SEVERITY_ORDER.index(state["triage"].severity) >= _SEVERITY_ORDER.index(floor):
        plan.requires_approval = True

    audit_log.record("decide", state["alert"].id, plan=plan.to_dict())
    return {"plan": plan}


def _human_gate_node(state: AgentState) -> AgentState:
    plan = state["plan"]
    if not plan.requires_approval:
        audit_log.record("human_gate", state["alert"].id, approved=True, note="auto-approved: low-risk action")
        return {"approved": True, "approver_note": "auto-approved: low-risk action"}

    # This is where execution actually pauses. `interrupt()` raises a
    # GraphInterrupt under the hood; LangGraph catches it, checkpoints the
    # state, and returns it to the caller as an __interrupt__ payload.
    # Calling code resumes later with Command(resume=<decision>).
    decision = interrupt({
        "alert_id": state["alert"].id,
        "asset": state["alert"].asset_id,
        "action": plan.action.value,
        "target": plan.target,
        "justification": plan.justification,
        "prompt": "Approve this remediation action? (approve/deny)",
    })
    approved = bool(decision.get("approved", False))
    note = decision.get("note", "")
    audit_log.record("human_gate", state["alert"].id, approved=approved, note=note)
    return {"approved": approved, "approver_note": note}


def _execute_node(state: AgentState) -> AgentState:
    log = list(state.get("execution_log", []))
    if state.get("approved"):
        result = remediation.execute(state["plan"])
        log.append(f"EXECUTED: {result.detail}" if result.success else f"FAILED: {result.detail}")
    else:
        log.append(f"SKIPPED: action denied by human reviewer ({state.get('approver_note', '')})")
    audit_log.record("execute", state["alert"].id, log_line=log[-1])
    return {"execution_log": log}


_checkpointer: Optional[SqliteSaver] = None


def _get_checkpointer() -> SqliteSaver:
    """Shared for the lifetime of the process: every build_graph() call
    binds to the same on-disk store, so state set by one request is
    visible to a later request (or a later process, once the process
    restarts and this is rebuilt from the same file) resuming the same
    thread_id. check_same_thread=False because Flask may serve requests
    from more than one thread depending on how it's run."""
    global _checkpointer
    if _checkpointer is None:
        conn = sqlite3.connect(config.GRAPH_CHECKPOINT_PATH, check_same_thread=False)
        allowed = [
            ("src.models", "Alert"),
            ("src.models", "ThreatIntel"),
            ("src.models", "TriageResult"),
            ("src.models", "RemediationPlan"),
            ("src.models", "Severity"),
            ("src.models", "ActionType"),
        ]
        _checkpointer = SqliteSaver(conn, serde=JsonPlusSerializer(allowed_msgpack_modules=allowed))
    return _checkpointer


def build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("enrich", _enrich_node)
    graph.add_node("triage", _triage_node)
    graph.add_node("decide", _decide_node)
    graph.add_node("human_gate", _human_gate_node)
    graph.add_node("execute", _execute_node)

    graph.set_entry_point("enrich")
    graph.add_edge("enrich", "triage")
    graph.add_edge("triage", "decide")
    graph.add_edge("decide", "human_gate")
    graph.add_edge("human_gate", "execute")
    graph.add_edge("execute", END)

    # Our state holds plain dataclasses (Alert, TriageResult, etc.), not
    # msgpack-registered types — allow-listing them is handled inside
    # _get_checkpointer(), which builds the serde once for the shared
    # checkpointer rather than re-registering it on every compile.
    return graph.compile(checkpointer=_get_checkpointer())


def run_alert(alert: Alert, thread_id: str | None = None):
    """Starts a fresh run for one alert. Returns either a final state
    (if no approval was needed) or an interrupt payload the caller must
    resolve via resume_alert()."""
    app = build_graph()
    config = {"configurable": {"thread_id": thread_id or alert.id}}
    result = app.invoke({"alert": alert, "execution_log": []}, config=config)
    return app, config, result


def resume_alert(app, config, approved: bool, note: str = ""):
    """Resumes a paused run after a human decision."""
    return app.invoke(Command(resume={"approved": approved, "note": note}), config=config)
