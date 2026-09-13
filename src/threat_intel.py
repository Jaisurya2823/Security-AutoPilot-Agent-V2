"""
External tool call #1: threat intel enrichment.

Two sources, both degrade independently so a network hiccup on one never
kills the pipeline:
  1. src/ioc_feed.py — FireHOL's level1 netset, a real, currently-live
     aggregate blocklist (Spamhaus DROP, DShield top attackers, etc.),
     cached and refreshed periodically rather than a hardcoded stand-in list.
  2. Optional live CVE lookup against NVD's public API, when the alert
     text references a CVE ID and ENABLE_LIVE_CVE_LOOKUP is on.
"""
from __future__ import annotations

import re

import requests

from . import config, ioc_feed
from .models import Alert, ThreatIntel

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _lookup_cve_nvd(cve_id: str) -> str | None:
    """Best-effort live lookup. Returns a short description or None."""
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        descriptions = vulns[0]["cve"]["descriptions"]
        for d in descriptions:
            if d.get("lang") == "en":
                return d["value"][:300]
    except (requests.RequestException, KeyError, ValueError, IndexError):
        return None
    return None


def enrich(alert: Alert) -> ThreatIntel:
    intel = ThreatIntel()

    if alert.asset_ip and ioc_feed.is_known_bad_ip(alert.asset_ip):
        intel.known_bad_ip = True
        intel.matched_indicators.append(f"ip:{alert.asset_ip}")

    cve_ids = _CVE_PATTERN.findall(alert.raw_log) or _CVE_PATTERN.findall(alert.description)
    cve_ids = sorted(set(c.upper() for c in cve_ids))
    intel.cve_refs = cve_ids

    if cve_ids and config.ENABLE_LIVE_CVE_LOOKUP:
        notes = []
        for cve in cve_ids[:3]:  # cap external calls per alert
            desc = _lookup_cve_nvd(cve)
            if desc:
                notes.append(f"{cve}: {desc}")
        intel.notes = " | ".join(notes)
    elif cve_ids:
        intel.notes = f"{len(cve_ids)} CVE reference(s) found; live lookup disabled"

    return intel
