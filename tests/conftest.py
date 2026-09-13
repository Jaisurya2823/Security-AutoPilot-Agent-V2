import pytest

import app as app_module
from src import audit_log, graph


@pytest.fixture(autouse=True)
def _isolated_audit_log(tmp_path, monkeypatch):
    """Every test gets its own throwaway audit log file so test runs never
    pollute (or read stale data from) the real audit_log.jsonl."""
    monkeypatch.setattr(audit_log, "_LOG_PATH", tmp_path / "audit_log.jsonl")


@pytest.fixture(autouse=True)
def _isolated_graph_checkpoints(tmp_path, monkeypatch):
    """Every test gets its own throwaway SQLite checkpoint file, and the
    module-level checkpointer singleton is reset so each test starts
    from a clean, isolated store instead of accumulating state (or
    leaking file handles) across the whole test run."""
    monkeypatch.setattr(graph.config, "GRAPH_CHECKPOINT_PATH", str(tmp_path / "graph_checkpoints.sqlite3"))
    graph._checkpointer = None
    yield
    graph._checkpointer = None


@pytest.fixture(autouse=True)
def _isolated_rate_limiter():
    """The rate limiter's request-count buckets are module-level state
    (deliberately in-memory — see app.py's docstring on why this stays
    a plain dict rather than a separate service). Without resetting it
    between tests, running the full suite trips the real 429 limit
    against tests that have nothing to do with rate limiting, since
    they all share one Flask test client hitting the same routes within
    the same 60-second window. This is the rate limiter correctly doing
    its job — the fix belongs in test isolation, not in loosening the
    real limit."""
    app_module._rate_limit_buckets.clear()
    yield
    app_module._rate_limit_buckets.clear()
