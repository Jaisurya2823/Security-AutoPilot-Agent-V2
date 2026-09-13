"""
Threat Modeling agent (STRIDE).

Two layers, both grounded in RepoIntelReport's real findings:
  1. Deterministic rules — mechanical, always-correct-given-the-input
     mappings from a specific finding (unauthenticated sensitive
     endpoint, hardcoded secret, etc.) to a STRIDE threat. These run
     with no LLM call and are what you'd get even if Groq is down.
  2. LLM augmentation — reads the same findings plus the deterministic
     threats and adds anything a human analyst would catch from the
     *combination* of findings that a fixed rule can't express, writes
     the architecture summary, and assigns the overall risk score.

The LLM is explicitly instructed not to invent findings not present in
the input — see groq_client.THREAT_MODEL_SYSTEM_PROMPT.
"""
from __future__ import annotations

import re

from . import groq_client
from .models import RepoIntelReport, Severity, ThreatFinding, ThreatModelReport

_SENSITIVE_PATH_KEYWORDS = re.compile(
    r"/(admin|delete|internal|config|settings|debug|users?|accounts?|billing|payment)s?(/|$)",
    re.IGNORECASE,
)


def _deterministic_threats(intel: RepoIntelReport) -> list[ThreatFinding]:
    threats: list[ThreatFinding] = []

    for ep in intel.endpoints:
        is_sensitive = bool(_SENSITIVE_PATH_KEYWORDS.search(ep.path))
        if ep.requires_auth is None and is_sensitive:
            threats.append(ThreatFinding(
                stride_category="elevation_of_privilege",
                title=f"Unauthenticated access to sensitive endpoint {ep.method} {ep.path}",
                description=(
                    f"{ep.file}:{ep.line} defines {ep.method} {ep.path}, a path suggesting a "
                    "sensitive/administrative action, with no authentication check detected "
                    "nearby in static analysis. If this endpoint truly has no auth, any caller "
                    "can invoke it directly."
                ),
                related_entry_point=f"{ep.method} {ep.path}",
                severity=Severity.HIGH,
            ))
        elif ep.requires_auth is None:
            threats.append(ThreatFinding(
                stride_category="spoofing",
                title=f"Unclear authentication status for {ep.method} {ep.path}",
                description=(
                    f"{ep.file}:{ep.line} defines {ep.method} {ep.path} with no authentication "
                    "check detected nearby. Static analysis could not confirm whether auth is "
                    "enforced elsewhere (e.g. global middleware) — needs manual confirmation."
                ),
                related_entry_point=f"{ep.method} {ep.path}",
                severity=Severity.LOW,
            ))

    for secret in intel.secrets:
        kind_label = secret.kind.replace("_", " ")
        title_label = kind_label if kind_label.startswith("hardcoded") else f"hardcoded {kind_label}"
        threats.append(ThreatFinding(
            stride_category="info_disclosure",
            title=f"{title_label.capitalize()} in source",
            description=(
                f"{secret.file}:{secret.line} contains what appears to be a "
                f"{kind_label} ({secret.masked_preview}) committed directly "
                "in source. If this repository or a build artifact containing it is ever "
                "exposed, this credential is compromised."
            ),
            related_entry_point="(repo-wide)",
            severity=Severity.CRITICAL if "key" in secret.kind or "password" in secret.kind else Severity.HIGH,
        ))

    if intel.database_usage and not any(
        "sqlalchemy" in db.lower() or "mongoose" in db.lower() for db in intel.database_usage
    ):
        threats.append(ThreatFinding(
            stride_category="tampering",
            title="Direct database access without a detected ORM/query-builder",
            description=(
                f"Database usage detected ({', '.join(intel.database_usage)}) without an ORM "
                "layer that would typically parameterize queries by default. This does not "
                "confirm a SQL injection vulnerability — it flags code that needs manual review "
                "to confirm queries are parameterized rather than string-built."
            ),
            related_entry_point="(repo-wide)",
            severity=Severity.MEDIUM,
        ))

    return threats


def _entry_points(intel: RepoIntelReport) -> list[str]:
    return sorted({f"{ep.method} {ep.path}" for ep in intel.endpoints})


def _assets(intel: RepoIntelReport) -> list[str]:
    assets = list(intel.database_usage)
    if intel.secrets:
        assets.append(f"{len(intel.secrets)} hardcoded credential(s) in source")
    if intel.cloud_hints:
        assets.append(f"Deployment/cloud config: {', '.join(intel.cloud_hints)}")
    return assets


def _trust_boundaries(intel: RepoIntelReport) -> list[str]:
    boundaries = []
    if intel.auth_indicators:
        boundaries.append("Authenticated vs. unauthenticated request boundary")
    if intel.database_usage:
        boundaries.append("Application <-> database boundary")
    if intel.cloud_hints:
        boundaries.append("Local/dev <-> deployed cloud environment boundary")
    if not boundaries:
        boundaries.append("No clear trust boundaries detected from static analysis alone — manual review recommended")
    return boundaries


_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _highest_severity(threats: list[ThreatFinding], fallback: Severity) -> Severity:
    if not threats:
        return fallback
    return max(threats, key=lambda t: _SEVERITY_ORDER.index(t.severity)).severity


def build_threat_model(intel: RepoIntelReport) -> ThreatModelReport:
    deterministic = _deterministic_threats(intel)

    llm_result = groq_client.generate_threat_model(
        intel.to_dict(), [t.to_dict() for t in deterministic]
    )

    llm_threats = [
        ThreatFinding(
            stride_category=t["stride_category"],
            title=t["title"],
            description=t["description"],
            related_entry_point=t["related_entry_point"],
            severity=Severity(t["severity"]),
        )
        for t in llm_result.get("additional_threats", [])
    ]

    all_threats = deterministic + llm_threats
    llm_risk = Severity(llm_result["risk_score"])
    # Never let the LLM's overall risk score be lower than the worst
    # mechanically-detected finding — the deterministic layer is ground
    # truth from real static analysis and shouldn't be talked down.
    risk_score = max([llm_risk, _highest_severity(deterministic, Severity.INFO)], key=_SEVERITY_ORDER.index)

    return ThreatModelReport(
        repo_summary=llm_result["repo_summary"],
        assets=_assets(intel),
        trust_boundaries=_trust_boundaries(intel),
        entry_points=_entry_points(intel),
        threats=all_threats,
        risk_score=risk_score,
        recommendations=llm_result.get("recommendations", []),
    )
