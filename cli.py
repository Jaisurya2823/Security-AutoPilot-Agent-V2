"""
CLI alert-triage runner — reads REAL alerts (JSON) from a file or stdin
and runs them through the autopilot agent, prompting interactively for
any action that hits the human gate.

This makes the triage -> decide -> pause -> human decision -> execute
flow visible without needing the Flask layer running, and — since it
reads real alert JSON rather than generating synthetic ones — it's a
genuine ingestion path: pipe alerts from your SIEM's export, a
syslog-to-JSON converter, or anything else that can produce this shape.

Usage:
    python cli.py --file alerts.json
    cat alerts.json | python cli.py
    echo '{"source":"edr","description":"...","raw_log":"...","asset_id":"host-1"}' | python cli.py

Input shape: either a single JSON object, or a JSON array of objects,
each with at least: source, description, raw_log, asset_id
(asset_ip is optional but needed for IOC-feed matching to do anything).
"""
from __future__ import annotations

import argparse
import json
import sys

from src import graph
from src.models import Alert


def _load_alerts(raw_text: str) -> list[Alert]:
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Input is not valid JSON: {exc}")

    records = data if isinstance(data, list) else [data]
    alerts = []
    for i, record in enumerate(records):
        missing = [f for f in ("source", "description", "raw_log", "asset_id") if f not in record]
        if missing:
            raise SystemExit(f"Alert #{i + 1} is missing required field(s): {', '.join(missing)}")
        alerts.append(Alert(
            source=record["source"],
            description=record["description"],
            raw_log=record["raw_log"],
            asset_id=record["asset_id"],
            asset_ip=record.get("asset_ip"),
        ))
    return alerts


def main():
    parser = argparse.ArgumentParser(description="Security Autopilot Agent — alert triage CLI")
    parser.add_argument("--file", type=str, default=None, help="path to a JSON file (single alert or array); reads stdin if omitted")
    args = parser.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            raw_text = fh.read()
    elif not sys.stdin.isatty():
        raw_text = sys.stdin.read()
    else:
        raise SystemExit(
            "No input given. Provide --file alerts.json, or pipe JSON via stdin:\n"
            '  echo \'{"source":"edr","description":"...","raw_log":"...","asset_id":"host-1"}\' | python cli.py'
        )

    alerts = _load_alerts(raw_text)
    print(f"\n=== Running {len(alerts)} alert(s) through the autopilot agent ===\n")

    for alert in alerts:
        print(f"--- Alert {alert.id} ({alert.source}) ---")
        print(f"  {alert.description}")

        compiled, config, result = graph.run_alert(alert)

        print(f"  Triage:      {result['triage'].severity.value.upper()} / "
              f"{result['triage'].threat_category} (confidence {result['triage'].confidence:.2f})")
        print(f"  Reasoning:   {result['triage'].reasoning}")
        print(f"  Plan:        {result['plan'].action.value} -> {result['plan'].target}")

        if "__interrupt__" in result:
            payload = result["__interrupt__"][0].value
            print(f"  [HUMAN GATE] {payload['prompt']}")
            print(f"               action={payload['action']} target={payload['target']}")
            print(f"               justification: {payload['justification']}")
            raw = input("               approve/deny? > ").strip().lower()
            approved = raw in ("approve", "a", "yes", "y")
            note = input("               note (optional): ").strip()
            final = graph.resume_alert(compiled, config, approved=approved, note=note)
            print(f"  Result:      {final['execution_log'][-1]}")
        else:
            print(f"  Result:      {result['execution_log'][-1]} (no approval needed)")

        print()


if __name__ == "__main__":
    main()
