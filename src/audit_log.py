"""
Append-only structured audit log.

A security agent that acts on infrastructure without a defensible,
timestamped record of *why* it acted is not production-ready, no
matter how good the triage logic is. Every node in the graph writes
one line here: what it saw, what it decided, and why. JSONL so it's
both human-greppable and trivially machine-parseable for a SIEM
ingestion pipeline later.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

_LOG_PATH = Path(os.getenv("AUDIT_LOG_PATH", "audit_log.jsonl"))


def record(event_type: str, alert_id: str, **fields) -> None:
    entry = {
        "ts": time.time(),
        "event": event_type,
        "alert_id": alert_id,
        **fields,
    }
    with _LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")


def read_all() -> list[dict]:
    if not _LOG_PATH.exists():
        return []
    with _LOG_PATH.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def read_for_alert(alert_id: str) -> list[dict]:
    return [e for e in read_all() if e["alert_id"] == alert_id]
