from __future__ import annotations

from src import attack_path
from src.models import Severity, ThreatFinding, ThreatModelReport


def _threat(title, severity, category="tampering"):
    return ThreatFinding(
        stride_category=category, title=title, description=f"desc for {title}",
        related_entry_point="/x", severity=severity,
    )


def test_no_threats_returns_empty_path_no_llm_call(monkeypatch):
    def fail_if_called(*a, **kw):
        raise AssertionError("should not call the LLM when there are no threats")
    monkeypatch.setattr(attack_path.groq_client, "generate_attack_path", fail_if_called)

    report = ThreatModelReport(repo_summary="x", risk_score=Severity.INFO)
    result = attack_path.build_attack_path(report)

    assert result.steps == []
    assert result.risk_score == Severity.INFO


def test_chains_threats_into_ordered_steps(monkeypatch):
    monkeypatch.setattr(
        attack_path.groq_client, "generate_attack_path",
        lambda threats: {
            "narrative": "Attacker exploits weak auth then exfiltrates data.",
            "steps": [
                {"order": 2, "title": "Exfiltrate DB", "description": "...", "exploits": ["Raw DB access"]},
                {"order": 1, "title": "Access admin endpoint", "description": "...", "exploits": ["No auth on admin endpoint"]},
            ],
        }
    )
    report = ThreatModelReport(
        repo_summary="x",
        threats=[_threat("No auth on admin endpoint", Severity.HIGH), _threat("Raw DB access", Severity.MEDIUM)],
        risk_score=Severity.HIGH,
    )
    result = attack_path.build_attack_path(report)

    assert [s.order for s in result.steps] == [1, 2]  # sorted by order even though LLM returned out of order
    assert result.steps[0].title == "Access admin endpoint"
    assert result.risk_score == Severity.HIGH  # reused from the threat model, not re-derived


def test_caps_prompt_to_top_severity_threats(monkeypatch):
    captured = {}

    def fake_generate(threats):
        captured["threats"] = threats
        return {"narrative": "n", "steps": []}

    monkeypatch.setattr(attack_path.groq_client, "generate_attack_path", fake_generate)

    many_threats = [_threat(f"t{i}", Severity.LOW) for i in range(15)]
    many_threats.append(_threat("the critical one", Severity.CRITICAL))
    report = ThreatModelReport(repo_summary="x", threats=many_threats, risk_score=Severity.CRITICAL)
    attack_path.build_attack_path(report)

    assert len(captured["threats"]) == 10  # capped
    assert captured["threats"][0]["title"] == "the critical one"  # highest severity first
