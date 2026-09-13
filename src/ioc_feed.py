"""
Real threat-intel IOC feed: FireHOL's level1 netset.

https://github.com/firehol/blocklist-ipsets (CC-BY-SA) — an aggregate
of several long-standing, high-confidence malicious-network blocklists
(Spamhaus DROP, DShield top attackers, known fullbogon ranges, etc.)
maintained specifically to be low-false-positive enough for direct
firewall use. This replaces what used to be a 3-IP hardcoded stand-in
list with real, currently-live data — thousands of real CIDR ranges,
refreshed periodically, not 3 IPs that happened to match the demo data.

Fetched once per IOC_FEED_CACHE_SECONDS (default 6h) and cached
in-memory, not re-fetched per alert — this is a shared public resource,
and blocklist membership doesn't change fast enough to justify hitting
it on every request.

Fails honestly: if the feed has never been successfully fetched, IP
matching returns False (no fabricated match) rather than crashing the
whole enrichment pipeline. If a previous fetch succeeded, a later
fetch failure keeps serving the last good data rather than going dark.
"""
from __future__ import annotations

import ipaddress
import time

import requests

from . import config

_cache: dict = {"networks": [], "fetched_at": 0.0}


def _parse_netset(text: str) -> list[ipaddress.IPv4Network]:
    networks = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            networks.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue  # a malformed/unexpected line (e.g. an IPv6 entry in a IPv4-only file) — skip, don't crash the feed
    return networks


def _refresh() -> None:
    try:
        resp = requests.get(config.IOC_FEED_URL, timeout=15)
        resp.raise_for_status()
        networks = _parse_netset(resp.text)
        if networks:  # only replace the cache with a non-empty, successfully-parsed result
            _cache["networks"] = networks
            _cache["fetched_at"] = time.time()
    except requests.RequestException:
        # Network hiccup: keep serving whatever's already cached (even if
        # stale) rather than raising and taking down alert enrichment.
        pass


def get_networks() -> list[ipaddress.IPv4Network]:
    age = time.time() - _cache["fetched_at"]
    if age > config.IOC_FEED_CACHE_SECONDS:
        _refresh()
    return _cache["networks"]


def is_known_bad_ip(ip: str) -> bool:
    """Returns False (not True) for anything that isn't a real match —
    including when the feed has never been fetched, and when the input
    itself isn't a parseable IP. No fabricated matches, ever."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for network in get_networks():
        if addr in network:
            return True
    return False


def feed_status() -> dict:
    """Diagnostic info — how many networks are loaded and how stale the
    cache is, useful for a healthz-style check or the dashboard."""
    age_seconds = time.time() - _cache["fetched_at"] if _cache["fetched_at"] else None
    return {
        "networks_loaded": len(_cache["networks"]),
        "cache_age_seconds": age_seconds,
        "ever_fetched": _cache["fetched_at"] > 0,
    }
