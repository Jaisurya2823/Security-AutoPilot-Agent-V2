"""
Tests for ioc_feed.py.

requests.get is mocked (transport boundary only, same convention as
test_supply_chain.py) — the CIDR-parsing and matching logic underneath
is real and exercised for real. Each test resets the module-level cache
first, since it's shared process-wide state.
"""
from __future__ import annotations

from src import ioc_feed


def _reset_cache():
    ioc_feed._cache["networks"] = []
    ioc_feed._cache["fetched_at"] = 0.0


class _FakeResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(str(self.status_code))


def test_parse_netset_skips_comments_and_blank_lines():
    text = "# comment\n\n10.0.0.0/8\n# another comment\n192.168.1.0/24\n"
    networks = ioc_feed._parse_netset(text)
    assert len(networks) == 2
    assert str(networks[0]) == "10.0.0.0/8"


def test_parse_netset_skips_malformed_lines_without_crashing():
    text = "10.0.0.0/8\nnot-a-cidr-at-all\n192.168.1.0/24\n"
    networks = ioc_feed._parse_netset(text)
    assert len(networks) == 2  # the malformed line is skipped, not fatal


def test_is_known_bad_ip_real_match(monkeypatch):
    _reset_cache()
    monkeypatch.setattr(ioc_feed.requests, "get", lambda *a, **kw: _FakeResponse("10.0.0.0/8\n"))
    assert ioc_feed.is_known_bad_ip("10.1.2.3") is True


def test_is_known_bad_ip_no_match(monkeypatch):
    _reset_cache()
    monkeypatch.setattr(ioc_feed.requests, "get", lambda *a, **kw: _FakeResponse("10.0.0.0/8\n"))
    assert ioc_feed.is_known_bad_ip("8.8.8.8") is False


def test_is_known_bad_ip_false_for_unparseable_input(monkeypatch):
    _reset_cache()
    monkeypatch.setattr(ioc_feed.requests, "get", lambda *a, **kw: _FakeResponse("10.0.0.0/8\n"))
    assert ioc_feed.is_known_bad_ip("not-an-ip-address") is False


def test_never_fetched_returns_false_not_a_crash(monkeypatch):
    """Before any successful fetch, matching must fail safe (False),
    never fabricate a match and never raise."""
    _reset_cache()

    def _raise(*a, **kw):
        import requests
        raise requests.ConnectionError("network down")

    monkeypatch.setattr(ioc_feed.requests, "get", _raise)
    assert ioc_feed.is_known_bad_ip("10.1.2.3") is False
    assert ioc_feed.feed_status()["ever_fetched"] is False


def test_stale_cache_still_served_when_refresh_fails(monkeypatch):
    """A successful fetch followed by a later failed refresh should keep
    serving the last good data, not go dark."""
    _reset_cache()
    monkeypatch.setattr(ioc_feed.requests, "get", lambda *a, **kw: _FakeResponse("10.0.0.0/8\n"))
    assert ioc_feed.is_known_bad_ip("10.1.2.3") is True  # populates the cache

    # Force a refresh attempt (as if the TTL expired) that fails
    monkeypatch.setattr(ioc_feed.config, "IOC_FEED_CACHE_SECONDS", -1)  # force "stale" on next check

    def _raise(*a, **kw):
        import requests
        raise requests.ConnectionError("network down")

    monkeypatch.setattr(ioc_feed.requests, "get", _raise)
    assert ioc_feed.is_known_bad_ip("10.1.2.3") is True  # still served from the last good cache


def test_cache_not_refetched_within_ttl(monkeypatch):
    _reset_cache()
    calls = {"n": 0}

    def _get(*a, **kw):
        calls["n"] += 1
        return _FakeResponse("10.0.0.0/8\n")

    monkeypatch.setattr(ioc_feed.requests, "get", _get)
    monkeypatch.setattr(ioc_feed.config, "IOC_FEED_CACHE_SECONDS", 3600)

    ioc_feed.is_known_bad_ip("10.1.2.3")
    ioc_feed.is_known_bad_ip("10.1.2.4")
    ioc_feed.is_known_bad_ip("10.1.2.5")
    assert calls["n"] == 1  # only fetched once despite three lookups


def test_empty_fetch_result_does_not_overwrite_good_cache(monkeypatch):
    """If a refresh returns a response that parses to zero networks
    (e.g. the feed is temporarily served empty/broken upstream), don't
    let that wipe out previously-good data."""
    _reset_cache()
    monkeypatch.setattr(ioc_feed.requests, "get", lambda *a, **kw: _FakeResponse("10.0.0.0/8\n"))
    ioc_feed.is_known_bad_ip("10.1.2.3")  # populate cache with real data
    assert len(ioc_feed.get_networks()) == 1

    monkeypatch.setattr(ioc_feed.config, "IOC_FEED_CACHE_SECONDS", -1)
    monkeypatch.setattr(ioc_feed.requests, "get", lambda *a, **kw: _FakeResponse("# only comments, no data\n"))
    ioc_feed.get_networks()
    assert len(ioc_feed.get_networks()) == 1  # unchanged, not wiped to zero
