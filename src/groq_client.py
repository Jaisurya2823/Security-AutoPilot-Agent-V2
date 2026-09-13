"""
Thin wrapper around the Groq API (native Groq SDK, OpenAI-schema chat
completions under the hood). Two responsibilities live here: getting the
model to reliably return structured JSON, and repairing the common ways
it doesn't (markdown fences, trailing commentary, single quotes).

This replaces qwen_client.py. Same public interface (classify_alert,
plan_remediation) so graph.py did not need to change its call sites,
only its import.
"""
from __future__ import annotations

import json
import re
import time

from groq import APIConnectionError, APIError, APIStatusError, APITimeoutError, Groq, RateLimitError

from . import config
from .models import Alert, ActionType, RemediationPlan, Severity, ThreatIntel, TriageResult

_client: Groq | None = None
_MAX_RETRIES = 3
_BASE_DELAY_SECONDS = 1.5


def _get_client() -> Groq:
    global _client
    if _client is None:
        config.require_groq_key()
        _client = Groq(api_key=config.GROQ_API_KEY)
    return _client


def _extract_json(text: str) -> dict:
    """Chat models sometimes wrap JSON in ```json fences or add a sentence
    before/after it even when told not to. Pull the first {...} block out
    rather than failing the whole pipeline on it."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    else:
        brace = re.search(r"\{.*\}", text, re.DOTALL)
        if brace:
            text = brace.group(0)
    return json.loads(text)


def _is_retryable(exc: Exception) -> bool:
    """RateLimitError (429) and APITimeoutError/APIConnectionError are
    transient — retry those. APIStatusError covers all other 4xx/5xx;
    only 5xx (server-side) is worth retrying there. Anything else
    (bad request shape, bad model name, auth failure) will fail
    identically on retry, so it's raised immediately instead."""
    if isinstance(exc, RateLimitError):
        return True
    if isinstance(exc, (APIConnectionError, APITimeoutError)):
        return True
    if isinstance(exc, APIStatusError):
        return exc.status_code >= 500
    return isinstance(exc, APIError)


def _chat_json(system_prompt: str, user_prompt: str, model: str | None = None) -> dict:
    client = _get_client()
    last_error: Exception | None = None
    model_name = model or config.GROQ_MODEL

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            completion = client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,  # triage/remediation should be near-deterministic
            )
            raw = completion.choices[0].message.content or ""
            try:
                return _extract_json(raw)
            except (json.JSONDecodeError, AttributeError) as exc:
                # A malformed-JSON response is a model-quality problem, not a
                # transport problem — retrying with the exact same prompt is
                # unlikely to help, so we don't burn retries on it.
                raise ValueError(f"Groq response was not valid JSON after repair attempts: {raw!r}") from exc
        except APIError as exc:
            if not _is_retryable(exc):
                status = getattr(exc, "status_code", "n/a")
                raise RuntimeError(f"Groq API rejected the request ({status}): {exc}") from exc
            last_error = exc
            if attempt == _MAX_RETRIES:
                break
            time.sleep(_BASE_DELAY_SECONDS * (2 ** (attempt - 1)))

    raise RuntimeError(
        f"Groq call failed after {_MAX_RETRIES} attempts: {last_error}"
    ) from last_error


TRIAGE_SYSTEM_PROMPT = """You are a security triage analyst. Given a raw \
alert, classify it. Respond with ONLY a JSON object, no prose, no markdown \
fences, in exactly this shape:

{
  "severity": "info|low|medium|high|critical",
  "threat_category": "short label, e.g. brute_force, lateral_movement, data_exfil, benign, misconfiguration",
  "confidence": 0.0-1.0,
  "reasoning": "1-3 sentences explaining the classification, referencing specific evidence from the alert"
}

Be conservative: ambiguous alerts with no clear malicious signal should be \
"low" or "info", not inflated to justify action. Alerts corroborated by \
threat intel matches should be scored higher."""


def classify_alert(alert: Alert, intel: ThreatIntel) -> TriageResult:
    user_prompt = json.dumps({
        "alert": alert.to_dict(),
        "threat_intel": intel.to_dict(),
    }, indent=2)
    # Triage runs on every alert (highest volume), so it uses the fast model.
    result = _chat_json(TRIAGE_SYSTEM_PROMPT, user_prompt, model=config.GROQ_MODEL_FAST)
    return TriageResult(
        severity=Severity(result["severity"]),
        threat_category=result["threat_category"],
        confidence=float(result["confidence"]),
        reasoning=result["reasoning"],
    )


REMEDIATION_SYSTEM_PROMPT = """You are a security remediation planner. \
Given a triaged alert, choose exactly one remediation action. Respond \
with ONLY a JSON object, no prose, no markdown fences, in exactly this \
shape:

{
  "action": "notify_only|open_ticket|block_ip|quarantine_host|disable_account|escalate_to_human",
  "target": "the asset_id, IP, or account the action applies to",
  "justification": "1-2 sentences",
  "requires_approval": true|false
}

Rules of thumb: "notify_only" and "open_ticket" are low-risk and rarely \
need approval. "block_ip", "quarantine_host", and "disable_account" are \
disruptive to real infrastructure or users and should almost always \
require_approval unless confidence and severity are both very high. If \
you are unsure what to do, choose "escalate_to_human"."""


def plan_remediation(alert: Alert, triage: TriageResult, intel: ThreatIntel) -> RemediationPlan:
    user_prompt = json.dumps({
        "alert": alert.to_dict(),
        "triage": triage.to_dict(),
        "threat_intel": intel.to_dict(),
    }, indent=2)
    # Remediation planning is lower-volume and higher-stakes than triage
    # (it decides what to do, including destructive actions), so it uses
    # the full reasoning model rather than the fast one.
    result = _chat_json(REMEDIATION_SYSTEM_PROMPT, user_prompt, model=config.GROQ_MODEL)
    action = ActionType(result["action"])
    requires_approval = bool(result["requires_approval"]) or action in _always_gate()
    return RemediationPlan(
        action=action,
        target=result["target"],
        justification=result["justification"],
        requires_approval=requires_approval,
    )


def _always_gate():
    from .models import DESTRUCTIVE_ACTIONS
    return DESTRUCTIVE_ACTIONS


PHISHING_SYSTEM_PROMPT = """You are a phishing and scam investigation analyst. \
Given a message (email/SMS/chat text) and a list of URL indicators already \
extracted from it by heuristic analysis, assess whether this is a phishing \
or scam attempt. Respond with ONLY a JSON object, no prose, no markdown \
fences, in exactly this shape:

{
  "is_likely_phishing": true|false,
  "confidence": 0.0-1.0,
  "reasoning": "2-4 sentences citing specific evidence from the message and URL indicators",
  "recommended_action": "short imperative, e.g. 'Do not click any links; report to IT security and delete' or 'Appears benign; no action needed'"
}

Weigh both the message's own language (urgency manipulation, impersonation, \
requests for credentials/payment/personal info) and the URL indicators \
provided. A message with no URLs can still be a scam (e.g. a fake prize \
notification asking for a callback). Do not inflate confidence when \
evidence is thin — reserve confidence above 0.8 for cases with multiple \
independent red flags."""


def classify_phishing_message(text: str, url_findings: list[dict]) -> dict:
    """Returns the raw parsed JSON (not wrapped in a dataclass here — the
    phishing agent module combines this with its own heuristic scoring
    before building the final PhishingReport)."""
    user_prompt = json.dumps({
        "message_text": text,
        "url_indicators": url_findings,
    }, indent=2)
    return _chat_json(PHISHING_SYSTEM_PROMPT, user_prompt, model=config.GROQ_MODEL)


THREAT_MODEL_SYSTEM_PROMPT = """You are a threat-modeling analyst using \
STRIDE. You will be given real static-analysis findings from a codebase \
(languages, frameworks, endpoints, database usage, secrets found, auth \
indicators) plus a list of threats already derived mechanically from \
those findings. Your job is NOT to re-list the mechanical threats — it \
is to (a) write a short plain-English architecture summary, (b) add any \
threats a mechanical rule-based scan would miss but a human analyst \
would catch from the combination of findings, (c) assign one overall \
risk score, and (d) give concrete remediation recommendations.

Respond with ONLY a JSON object, no prose, no markdown fences, in \
exactly this shape:

{
  "repo_summary": "2-4 sentences describing what this application appears to be and how it's built, grounded only in the findings given",
  "additional_threats": [
    {
      "stride_category": "spoofing|tampering|repudiation|info_disclosure|denial_of_service|elevation_of_privilege",
      "title": "short title",
      "description": "1-3 sentences, must reference specific findings (an endpoint path, a detected framework, a secret kind) — never invent a finding not present in the input",
      "related_entry_point": "an endpoint path from the input, or '(repo-wide)'",
      "severity": "info|low|medium|high|critical"
    }
  ],
  "risk_score": "info|low|medium|high|critical",
  "recommendations": ["short imperative sentence", "..."]
}

Ground every claim in the findings you were given. Do not invent \
endpoints, secrets, or frameworks that are not in the input. If the \
findings are minimal (e.g. no secrets, no auth issues detected), it is \
correct to return few or zero additional_threats and a low risk_score —
do not inflate severity to seem thorough."""


def generate_threat_model(repo_intel: dict, deterministic_threats: list[dict]) -> dict:
    user_prompt = json.dumps({
        "repo_intel": repo_intel,
        "deterministic_threats_already_found": deterministic_threats,
    }, indent=2)
    return _chat_json(THREAT_MODEL_SYSTEM_PROMPT, user_prompt, model=config.GROQ_MODEL)


ATTACK_PATH_SYSTEM_PROMPT = """You are an attacker-path reasoning analyst. \
You will be given a list of confirmed threat findings for an \
application (from a STRIDE threat model, each grounded in real static- \
analysis evidence). Chain the findings that could realistically be \
combined by an attacker into a plausible end-to-end attack path — from \
initial access to impact. Only use findings actually provided; do not \
invent steps that aren't supported by at least one given finding. If the \
findings don't chain into a coherent path (e.g. only one isolated, \
low-severity issue), it is correct to return a short 1-2 step path or \
say no realistic chained path exists — do not force a dramatic narrative \
onto weak evidence.

Respond with ONLY a JSON object, no prose, no markdown fences, in \
exactly this shape:

{
  "narrative": "2-4 sentence high-level summary of the attack path, or a note that no realistic chained path exists",
  "steps": [
    {
      "order": 1,
      "title": "short step title",
      "description": "1-2 sentences explaining this step and which specific finding(s) it relies on",
      "exploits": ["title of a finding this step depends on"]
    }
  ]
}"""


def generate_attack_path(threats: list[dict]) -> dict:
    user_prompt = json.dumps({"threats": threats}, indent=2)
    return _chat_json(ATTACK_PATH_SYSTEM_PROMPT, user_prompt, model=config.GROQ_MODEL)
