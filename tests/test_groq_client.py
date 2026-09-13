"""
Tests for groq_client's JSON-repair and error-handling logic.

These mock the Groq SDK's transport layer only (no real network call) —
same convention test_graph.py already uses for the LLM call boundary.
Nothing about a security finding, score, or verdict is ever faked; this
file only proves the client parses/retries correctly around real model
output shapes.
"""
from __future__ import annotations

import json

import httpx
import pytest
from groq import APIConnectionError, APIStatusError, RateLimitError

from src import groq_client

_FAKE_REQUEST = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
_FAKE_429_RESPONSE = httpx.Response(429, request=_FAKE_REQUEST, json={"error": "rate limited"})


def test_extract_json_plain():
    assert groq_client._extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_with_markdown_fence():
    text = '```json\n{"a": 1, "b": "two"}\n```'
    assert groq_client._extract_json(text) == {"a": 1, "b": "two"}


def test_extract_json_with_leading_prose():
    text = 'Sure, here is the result:\n{"a": 1}\nLet me know if you need anything else.'
    assert groq_client._extract_json(text) == {"a": 1}


def test_extract_json_raises_on_garbage():
    with pytest.raises(json.JSONDecodeError):
        groq_client._extract_json("not json at all")


def test_chat_json_retries_on_transient_error_then_succeeds(monkeypatch):
    calls = {"n": 0}

    class _FakeMessage:
        content = '{"ok": true}'

    class _FakeChoice:
        message = _FakeMessage()

    class _FakeCompletion:
        choices = [_FakeChoice()]

    class _FakeCompletions:
        def create(self, **kwargs):
            calls["n"] += 1
            if calls["n"] < 2:
                raise APIConnectionError(request=_FAKE_REQUEST)
            return _FakeCompletion()

    class _FakeChat:
        completions = _FakeCompletions()

    class _FakeClient:
        chat = _FakeChat()

    monkeypatch.setattr(groq_client, "_get_client", lambda: _FakeClient())
    monkeypatch.setattr(groq_client.time, "sleep", lambda _seconds: None)

    result = groq_client._chat_json("system", "user")
    assert result == {"ok": True}
    assert calls["n"] == 2


def test_chat_json_retries_rate_limit_then_gives_up(monkeypatch):
    """429 is transient — must retry _MAX_RETRIES times, not fail fast."""
    calls = {"n": 0}

    class _FakeCompletions:
        def create(self, **kwargs):
            calls["n"] += 1
            raise RateLimitError(message="rate limited", response=_FAKE_429_RESPONSE, body=None)

    class _FakeChat:
        completions = _FakeCompletions()

    class _FakeClient:
        chat = _FakeChat()

    monkeypatch.setattr(groq_client, "_get_client", lambda: _FakeClient())
    monkeypatch.setattr(groq_client.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match="Groq call failed after 3 attempts"):
        groq_client._chat_json("system", "user")
    assert calls["n"] == 3  # actually retried, didn't fail on the first 429


def test_chat_json_fails_fast_on_bad_request(monkeypatch):
    """A genuine 400 (bad model name, malformed request) should not be
    retried — identical retries would fail identically."""
    calls = {"n": 0}
    fake_400_response = httpx.Response(400, request=_FAKE_REQUEST, json={"error": "bad request"})

    class _FakeCompletions:
        def create(self, **kwargs):
            calls["n"] += 1
            raise APIStatusError(message="bad request", response=fake_400_response, body=None)

    class _FakeChat:
        completions = _FakeCompletions()

    class _FakeClient:
        chat = _FakeChat()

    monkeypatch.setattr(groq_client, "_get_client", lambda: _FakeClient())
    monkeypatch.setattr(groq_client.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match=r"Groq API rejected the request \(400\)"):
        groq_client._chat_json("system", "user")
    assert calls["n"] == 1  # no retry burned on a non-transient error
