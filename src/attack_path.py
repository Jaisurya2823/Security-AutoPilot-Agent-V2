"""
Attack Path Discovery agent.

Takes a ThreatModelReport's findings and asks the LLM to chain the ones
that could realistically combine into an end-to-end attacker path — not
just list them again. This is investigation/explanation only: nothing
here executes an attack, sends a request, or touches the target system
in any way (see the project's stated "no autonomous pentesting" scope).

If there are no threats, or only one isolated low-severity issue, the
correct output is a short/empty path — the LLM is explicitly told not to
force a dramatic narrative onto weak evidence (see
groq_client.ATTACK_PATH_SYSTEM_PROMPT).
"""
from __future__ import annotations

from . import groq_client
from .models import AttackPathReport, AttackStep, Severity, ThreatModelReport

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_MAX_THREATS_IN_PROMPT = 10  # cap prompt size; only the most severe findings are worth chaining anyway


def build_attack_path(threat_model: ThreatModelReport) -> AttackPathReport:
    if not threat_model.threats:
        return AttackPathReport(
            narrative="No threats were identified in the threat model, so there is no attack path to chain.",
            steps=[],
            risk_score=Severity.INFO,
        )

    ranked = sorted(threat_model.threats, key=lambda t: _SEVERITY_ORDER.index(t.severity), reverse=True)
    top_threats = ranked[:_MAX_THREATS_IN_PROMPT]

    llm_result = groq_client.generate_attack_path([t.to_dict() for t in top_threats])

    steps = [
        AttackStep(
            order=int(s["order"]),
            title=s["title"],
            description=s["description"],
            exploits=s.get("exploits", []),
        )
        for s in llm_result.get("steps", [])
    ]
    steps.sort(key=lambda s: s.order)

    return AttackPathReport(
        narrative=llm_result["narrative"],
        steps=steps,
        # The path can only be as severe as the worst finding it chains —
        # reuse the threat model's own risk score rather than letting the
        # LLM assign a second, potentially inconsistent one.
        risk_score=threat_model.risk_score,
    )
