"""
Tests for repo_intel.py.

Every test writes real files to a pytest tmp_path fixture and scans the
real directory — nothing here is mocked. This is the same shape of test
that caught two real bugs during development (auth-context window
overshooting into the next route's body).
"""
from __future__ import annotations

import textwrap

from src.repo_intel import scan_repo


def _write(path, name, content):
    file_path = path / name
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(textwrap.dedent(content))
    return file_path


def test_detects_flask_and_python(tmp_path):
    _write(tmp_path, "requirements.txt", "flask==3.0.0\n")
    _write(tmp_path, "app.py", "from flask import Flask\napp = Flask(__name__)\n")
    report = scan_repo(str(tmp_path))
    assert "Python" in report.languages
    assert "Flask" in report.frameworks


def test_full_fixture_repo(tmp_path):
    _write(tmp_path, "requirements.txt", "flask==3.0.0\npsycopg2==2.9.9\npyjwt==2.8.0\n")
    _write(tmp_path, "app.py", """
        from flask import Flask
        app = Flask(__name__)

        AWS_KEY = "AKIAABCDEFGHIJKLMNOP"

        @app.route("/admin/delete-user", methods=["POST"])
        def delete_user():
            return "deleted"

        @app.route("/login", methods=["POST"])
        def login():
            # uses jwt for session tokens
            return "ok"

        @app.route("/public/health")
        def health():
            return "ok"
        """)
    _write(tmp_path, ".github/workflows/ci.yml", "name: CI\non: [push]\n")
    _write(tmp_path, "Dockerfile", "FROM python:3.12-slim\n")
    _write(tmp_path, "config.py", 'password = "hunter2ishorrible"\n')

    report = scan_repo(str(tmp_path))

    assert "Python" in report.languages
    assert "Flask" in report.frameworks
    assert "PostgreSQL (via psycopg2/SQLAlchemy)" in report.database_usage

    endpoints_by_path = {e.path: e for e in report.endpoints}
    assert set(endpoints_by_path) == {"/admin/delete-user", "/login", "/public/health"}
    assert endpoints_by_path["/admin/delete-user"].method == "POST"

    # Regression test for the bug caught during development: the admin
    # endpoint has NO auth check nearby and must not be marked True just
    # because a *different* route two lines later happens to mention jwt.
    assert endpoints_by_path["/admin/delete-user"].requires_auth is None
    assert endpoints_by_path["/login"].requires_auth is True
    assert endpoints_by_path["/public/health"].requires_auth is None

    secret_kinds = {s.kind for s in report.secrets}
    assert "aws_access_key_id" in secret_kinds
    assert "hardcoded_password" in secret_kinds
    # Never store the full secret, only a masked preview
    for s in report.secrets:
        assert "AKIAABCDEFGHIJKLMNOP" not in s.masked_preview
        assert "hunter2ishorrible" not in s.masked_preview

    assert ".github/workflows/ci.yml" in report.ci_cd_files
    assert any("Docker" in h for h in report.cloud_hints)
    assert "requirements.txt" in report.dependency_manifests


def test_skips_vendored_directories(tmp_path):
    _write(tmp_path, "node_modules/some_pkg/index.js", 'const SECRET = "AKIAABCDEFGHIJKLMNOP";\n')
    _write(tmp_path, "app.py", "print('hello')\n")
    report = scan_repo(str(tmp_path))
    assert report.secrets == []  # the fake secret lives only inside node_modules, must be skipped


def test_no_endpoints_no_false_positives_on_clean_repo(tmp_path):
    _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
    _write(tmp_path, "utils.py", "def add(a, b):\n    return a + b\n")
    report = scan_repo(str(tmp_path))
    assert report.endpoints == []
    assert report.secrets == []


def test_all_reported_paths_use_forward_slashes(tmp_path):
    """Regression test for a real bug: on Windows, os.path.relpath returns
    backslash-separated paths, so a report generated there didn't match
    forward-slash comparisons (e.g. ci_cd_files detection) and wouldn't
    match a report of the same repo generated on Linux/Mac. This asserts
    the invariant directly so it's caught on any OS, not just Windows."""
    _write(tmp_path, "nested/dir/app.py", "print('hi')\n")
    _write(tmp_path, ".github/workflows/ci.yml", "name: CI\non: [push]\n")
    report = scan_repo(str(tmp_path))

    all_paths = (
        report.ci_cd_files + report.config_files + report.dependency_manifests
        + [e.file for e in report.endpoints] + [s.file for s in report.secrets]
    )
    assert all("\\" not in p for p in all_paths), f"found backslash in a stored path: {all_paths}"
    assert ".github/workflows/ci.yml" in report.ci_cd_files


def test_raises_on_nonexistent_directory():
    import pytest
    with pytest.raises(ValueError, match="Not a directory"):
        scan_repo("/this/path/does/not/exist")


def test_masked_preview_never_contains_full_short_secret(tmp_path):
    _write(tmp_path, "app.py", 'password = "abc123"\n')
    report = scan_repo(str(tmp_path))
    assert len(report.secrets) == 1
    assert "abc123" not in report.secrets[0].masked_preview
