"""
Core data models for the Security Alert Autopilot Agent.

These are intentionally plain dataclasses (not pydantic) so the LangGraph
state dict stays JSON-serializable end to end, which matters once we hand
state through the interrupt/resume cycle for the human-in-the-loop gate.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self)


class ActionType(str, Enum):
    NOTIFY_ONLY = "notify_only"
    OPEN_TICKET = "open_ticket"
    BLOCK_IP = "block_ip"
    QUARANTINE_HOST = "quarantine_host"
    DISABLE_ACCOUNT = "disable_account"
    ESCALATE_TO_HUMAN = "escalate_to_human"


# Actions that touch live infrastructure and must never fire without a human
# sign-off, regardless of what the model's own requires_approval flag says.
# This is a hard safety floor, not something the LLM gets to override.
DESTRUCTIVE_ACTIONS = {ActionType.BLOCK_IP, ActionType.QUARANTINE_HOST, ActionType.DISABLE_ACCOUNT}


@dataclass
class Alert:
    source: str                     # e.g. "edr", "firewall", "siem", "cve-feed"
    description: str
    raw_log: str
    asset_id: str
    asset_ip: Optional[str] = None
    id: str = field(default_factory=lambda: f"alert-{uuid.uuid4().hex[:8]}")
    received_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source,
            "description": self.description,
            "raw_log": self.raw_log,
            "asset_id": self.asset_id,
            "asset_ip": self.asset_ip,
            "received_at": self.received_at,
        }


@dataclass
class ThreatIntel:
    matched_indicators: list[str] = field(default_factory=list)
    known_bad_ip: bool = False
    cve_refs: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "matched_indicators": self.matched_indicators,
            "known_bad_ip": self.known_bad_ip,
            "cve_refs": self.cve_refs,
            "notes": self.notes,
        }


@dataclass
class TriageResult:
    severity: Severity
    threat_category: str
    confidence: float               # 0.0 - 1.0, self-reported by the model
    reasoning: str

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "threat_category": self.threat_category,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
        }


@dataclass
class RemediationPlan:
    action: ActionType
    target: str                     # asset_id, IP, or account name being acted on
    justification: str
    requires_approval: bool

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "target": self.target,
            "justification": self.justification,
            "requires_approval": self.requires_approval,
        }


@dataclass
class PackageRef:
    """A single dependency as declared in a manifest file, normalized to
    the ecosystem names OSV.dev's API expects (e.g. "PyPI", "npm")."""
    name: str
    ecosystem: str
    version: Optional[str] = None   # None if unpinned/range — can't query OSV without one
    raw_spec: str = ""              # the exact line/entry as written, for display

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "ecosystem": self.ecosystem,
            "version": self.version,
            "raw_spec": self.raw_spec,
        }


@dataclass
class VulnMatch:
    id: str                         # OSV/GHSA/PYSEC id
    summary: str
    severity: str                   # "low"|"medium"|"high"|"critical"|"unknown"
    aliases: list[str] = field(default_factory=list)
    fixed_version: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "summary": self.summary,
            "severity": self.severity,
            "aliases": self.aliases,
            "fixed_version": self.fixed_version,
        }


@dataclass
class PackageFinding:
    package: PackageRef
    vulns: list[VulnMatch] = field(default_factory=list)
    typosquat_suspect_of: Optional[str] = None   # name of the popular package it resembles, if any
    suspicious_install_script: Optional[str] = None  # the script text, if flagged
    trust_score: int = 100           # 0-100, 100 = no findings against this package

    def to_dict(self) -> dict:
        return {
            "package": self.package.to_dict(),
            "vulns": [v.to_dict() for v in self.vulns],
            "typosquat_suspect_of": self.typosquat_suspect_of,
            "suspicious_install_script": self.suspicious_install_script,
            "trust_score": self.trust_score,
        }


@dataclass
class Endpoint:
    method: str                      # HTTP verb, or "N/A" for non-HTTP entry points
    path: str
    file: str
    line: int
    framework: str
    requires_auth: Optional[bool] = None   # None = couldn't determine from static analysis

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "path": self.path,
            "file": self.file,
            "line": self.line,
            "framework": self.framework,
            "requires_auth": self.requires_auth,
        }


@dataclass
class SecretFinding:
    kind: str                        # e.g. "aws_access_key", "generic_api_key", "private_key_header"
    file: str
    line: int
    masked_preview: str               # first few chars + asterisks — never the full secret

    def to_dict(self) -> dict:
        return {"kind": self.kind, "file": self.file, "line": self.line, "masked_preview": self.masked_preview}


@dataclass
class RepoIntelReport:
    root_path: str
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    database_usage: list[str] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    config_files: list[str] = field(default_factory=list)
    ci_cd_files: list[str] = field(default_factory=list)
    dependency_manifests: list[str] = field(default_factory=list)
    cloud_hints: list[str] = field(default_factory=list)
    auth_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "root_path": self.root_path,
            "languages": self.languages,
            "frameworks": self.frameworks,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "database_usage": self.database_usage,
            "secrets": [s.to_dict() for s in self.secrets],
            "config_files": self.config_files,
            "ci_cd_files": self.ci_cd_files,
            "dependency_manifests": self.dependency_manifests,
            "cloud_hints": self.cloud_hints,
            "auth_indicators": self.auth_indicators,
        }


@dataclass
class ThreatFinding:
    stride_category: str              # "spoofing"|"tampering"|"repudiation"|"info_disclosure"|"denial_of_service"|"elevation_of_privilege"
    title: str
    description: str
    related_entry_point: str          # e.g. an endpoint path, or "(repo-wide)"
    severity: Severity

    def to_dict(self) -> dict:
        return {
            "stride_category": self.stride_category,
            "title": self.title,
            "description": self.description,
            "related_entry_point": self.related_entry_point,
            "severity": self.severity.value,
        }


@dataclass
class ThreatModelReport:
    repo_summary: str
    assets: list[str] = field(default_factory=list)
    trust_boundaries: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    threats: list[ThreatFinding] = field(default_factory=list)
    risk_score: Severity = Severity.INFO
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "repo_summary": self.repo_summary,
            "assets": self.assets,
            "trust_boundaries": self.trust_boundaries,
            "entry_points": self.entry_points,
            "threats": [t.to_dict() for t in self.threats],
            "risk_score": self.risk_score.value if self.risk_score else None,
            "recommendations": self.recommendations,
        }


@dataclass
class AttackStep:
    order: int
    title: str
    description: str
    exploits: list[str] = field(default_factory=list)   # threat titles this step relies on

    def to_dict(self) -> dict:
        return {"order": self.order, "title": self.title, "description": self.description, "exploits": self.exploits}


@dataclass
class AttackPathReport:
    narrative: str
    steps: list[AttackStep] = field(default_factory=list)
    risk_score: Severity = Severity.INFO

    def to_dict(self) -> dict:
        return {
            "narrative": self.narrative,
            "steps": [s.to_dict() for s in self.steps],
            "risk_score": self.risk_score.value if self.risk_score else None,
        }


@dataclass
class URLFinding:
    url: str
    domain: str
    is_ip_literal: bool = False
    is_punycode: bool = False
    is_shortener: bool = False
    suspicious_tld: bool = False
    brand_impersonation_of: Optional[str] = None   # real brand domain this one resembles, if any
    suspicious_subdomain_nesting: bool = False      # e.g. paypal.com.security-check.xyz
    risk_score: int = 0                              # 0-100, higher = more suspicious

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "domain": self.domain,
            "is_ip_literal": self.is_ip_literal,
            "is_punycode": self.is_punycode,
            "is_shortener": self.is_shortener,
            "suspicious_tld": self.suspicious_tld,
            "brand_impersonation_of": self.brand_impersonation_of,
            "suspicious_subdomain_nesting": self.suspicious_subdomain_nesting,
            "risk_score": self.risk_score,
        }


@dataclass
class PhishingReport:
    input_excerpt: str               # truncated for the report, never logged in full elsewhere
    matched_keywords: list[str] = field(default_factory=list)
    url_findings: list[URLFinding] = field(default_factory=list)
    heuristic_score: int = 0          # 0-100 from keyword + URL heuristics only
    llm_confidence: float = 0.0       # 0.0-1.0, model's own confidence
    llm_reasoning: str = ""
    risk_score: Severity = Severity.INFO
    recommended_action: str = ""

    def to_dict(self) -> dict:
        return {
            "input_excerpt": self.input_excerpt,
            "matched_keywords": self.matched_keywords,
            "url_findings": [u.to_dict() for u in self.url_findings],
            "heuristic_score": self.heuristic_score,
            "llm_confidence": self.llm_confidence,
            "llm_reasoning": self.llm_reasoning,
            "risk_score": self.risk_score.value,
            "recommended_action": self.recommended_action,
        }


@dataclass
class SupplyChainReport:
    manifest_path: str
    ecosystem: str
    findings: list[PackageFinding] = field(default_factory=list)
    unresolved_packages: list[str] = field(default_factory=list)  # e.g. unpinned, couldn't query
    overall_trust_score: int = 100   # 0-100 across the whole manifest
    risk_score: Severity = Severity.INFO

    def to_dict(self) -> dict:
        return {
            "manifest_path": self.manifest_path,
            "ecosystem": self.ecosystem,
            "findings": [f.to_dict() for f in self.findings],
            "unresolved_packages": self.unresolved_packages,
            "overall_trust_score": self.overall_trust_score,
            "risk_score": self.risk_score.value,
        }

@dataclass
class WebSecurityFinding:
    category: str          # "missing_header"|"cookie_flag"|"exposed_path"|"tls"|"cors"|"info_disclosure"
    title: str
    description: str
    severity: Severity

    def to_dict(self) -> dict:
        return {"category": self.category, "title": self.title,
                "description": self.description, "severity": self.severity.value}


@dataclass
class WebScanReport:
    url: str
    final_url: str
    findings: list[WebSecurityFinding] = field(default_factory=list)
    risk_score: Severity = Severity.INFO
    summary: str = ""

    def to_dict(self) -> dict:
        return {"url": self.url, "final_url": self.final_url,
                "findings": [f.to_dict() for f in self.findings],
                "risk_score": self.risk_score.value, "summary": self.summary}
