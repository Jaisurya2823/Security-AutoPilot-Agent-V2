"""
Flask API for the Security Autopilot Agent.

POST /alerts                submit a raw alert, runs it through the triage graph
GET  /pending                list alerts currently paused at the human gate
POST /approve/<id>           approve or deny a pending action, resumes the graph
GET  /history                 full decision ledger (audit log) for the dashboard
POST /investigate/repo        analyze a GitHub repo URL or uploaded ZIP (threat model + attack path)
POST /investigate/dependencies analyze a requirements.txt/package.json for supply-chain risk
POST /investigate/phishing    analyze a message/email for phishing/scam indicators
GET  /healthz                  liveness check (also what Render's health check pings)

Deployment: served by gunicorn in Docker/Render (see Dockerfile), not
this file's own __main__ block — that's local-dev only. gunicorn runs
with --workers 1 --threads 4 deliberately: _PENDING below and the graph
checkpointer's SQLite connection (src/graph.py) are both process-local
state. Multiple worker *processes* would silently desync (an alert
submitted to worker A wouldn't be visible to worker B's /pending), so
this stays single-process until that state is made shared (e.g. moving
_PENDING into the same SQLite file) — a real roadmap item, not an
oversight. Multiple *threads* within that one process are safe: Flask/
Werkzeug's request handling and Python's GIL make the plain dict
operations on _PENDING atomic, and the SQLite connection was opened
with check_same_thread=False specifically to allow it.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, request, send_from_directory

from src import config, graph, orchestrator, phishing, supply_chain, web_scanner
from src.audit_log import read_all
from src.models import Alert

app = Flask(__name__, static_folder="static")

# Caps the size Flask will even buffer before a route runs — a request
# body over this is rejected with a 413 before /investigate/repo's own
# zip-bomb protection or anything else has to deal with it. Generous
# enough for a real repo ZIP, small enough to bound worst-case memory.
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB

# In-memory, per-process sliding-window rate limiter. Deliberately not a
# separate package (Flask-Limiter etc.) — this project already documents
# why it runs as a single worker process (see the docstring above), so a
# plain in-memory dict is consistent with that constraint rather than a
# new one. Protects the routes that make outbound network calls
# (Groq/OSV.dev/GitHub/live websites) from being used to burn API quota
# or as a request-flooding vector against arbitrary third-party targets.
_rate_limit_buckets: dict[str, deque] = defaultdict(deque)


def _rate_limited(key: str, limit: int, window_seconds: int = 60) -> bool:
    now = time.time()
    bucket = _rate_limit_buckets[key]
    while bucket and now - bucket[0] > window_seconds:
        bucket.popleft()
    if len(bucket) >= limit:
        return True
    bucket.append(now)
    return False


def _client_ip() -> str:
    # X-Forwarded-For is only trusted because Render (this project's
    # documented deployment target) sits in front as the proxy that sets
    # it — if self-hosting directly with no trusted proxy in front,
    # request.remote_addr alone should be used instead.
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() if forwarded else (request.remote_addr or "unknown")


@app.before_request
def _enforce_rate_limit():
    if not request.path.startswith("/investigate/") and request.path != "/alerts":
        return  # only the network-calling / LLM-calling routes are limited
    if _rate_limited(_client_ip(), config.RATE_LIMIT_PER_MINUTE):
        return jsonify({"error": "Rate limit exceeded — try again in a minute."}), 429


@app.errorhandler(Exception)
def _handle_uncaught_exception(exc):
    """Safety net: no uncaught exception should ever reach the client as
    a raw stack trace or a framework HTML error page. Every route below
    validates its own input, but this exists in case something still
    slips through — an API should always fail as clean JSON."""
    from werkzeug.exceptions import HTTPException
    if isinstance(exc, HTTPException):
        return jsonify({"error": exc.description}), exc.code
    app.logger.exception("Unhandled exception")
    return jsonify({"error": "Internal server error."}), 500


def _require_json_object() -> dict | None:
    """Returns the parsed JSON body if it's a genuine object, else None.
    Centralizes the check every route needs — a body that's missing,
    malformed, or a JSON array/string/number instead of an object must
    never reach route logic that assumes .get()/dict-key access works."""
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else None


def _require_nonempty_str(body: dict, field: str) -> str | None:
    value = body.get(field)
    return value if isinstance(value, str) and value.strip() else None


# thread_id -> (compiled_app, config, interrupt_payload)
# This dict itself is process-local — it's a convenience index for the
# /pending listing, and is lost on restart. The underlying decision
# state it points at is NOT lost: src/graph.py's checkpointer is
# SQLite-backed (GRAPH_CHECKPOINT_PATH), so /approve/<id> still resumes
# correctly after a restart as long as the caller has the alert_id —
# see src/graph.py's module docstring. A full production deployment at
# scale would also persist this index (e.g. a small table alongside the
# checkpoint DB) so /pending itself survives a restart, not just resume.
_PENDING: dict[str, dict] = {}


def _run_and_track(alert: Alert):
    compiled, config, result = graph.run_alert(alert)
    if "__interrupt__" in result:
        payload = result["__interrupt__"][0].value
        _PENDING[alert.id] = {"app": compiled, "config": config, "payload": payload}
        return {"status": "pending_approval", "alert_id": alert.id, "approval_request": payload}
    return {
        "status": "completed",
        "alert_id": alert.id,
        "triage": result["triage"].to_dict(),
        "plan": result["plan"].to_dict(),
        "execution_log": result["execution_log"],
    }


@app.get("/")
def dashboard():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok"})


@app.get("/history")
def history():
    return jsonify(read_all())


@app.post("/alerts")
def submit_alert():
    body = _require_json_object()
    if body is None:
        return jsonify({"error": "Request body must be a JSON object."}), 400

    description = _require_nonempty_str(body, "description")
    asset_id = _require_nonempty_str(body, "asset_id")
    if description is None or asset_id is None:
        return jsonify({"error": "'description' and 'asset_id' are required non-empty strings."}), 400

    source = body.get("source", "manual")
    if not isinstance(source, str):
        return jsonify({"error": "'source' must be a string if provided."}), 400

    raw_log = body.get("raw_log", description)
    if not isinstance(raw_log, str):
        return jsonify({"error": "'raw_log' must be a string if provided."}), 400

    asset_ip = body.get("asset_ip")
    if asset_ip is not None and not isinstance(asset_ip, str):
        return jsonify({"error": "'asset_ip' must be a string if provided."}), 400

    alert = Alert(source=source, description=description, raw_log=raw_log, asset_id=asset_id, asset_ip=asset_ip)
    try:
        return jsonify(_run_and_track(alert))
    except RuntimeError as exc:
        return jsonify({"error": f"Triage could not complete: {exc}"}), 502


@app.get("/pending")
def list_pending():
    return jsonify([
        {"alert_id": aid, "approval_request": v["payload"]}
        for aid, v in _PENDING.items()
    ])


@app.post("/approve/<alert_id>")
def approve(alert_id: str):
    entry = _PENDING.pop(alert_id, None)
    if entry is None:
        return jsonify({"error": f"no pending action for {alert_id}"}), 404

    body = _require_json_object() or {}
    approved = bool(body.get("approved", False))
    note = body.get("note", "")
    if not isinstance(note, str):
        note = ""

    try:
        final = graph.resume_alert(entry["app"], entry["config"], approved=approved, note=note)
    except RuntimeError as exc:
        return jsonify({"error": f"Resuming this decision failed: {exc}"}), 502
    return jsonify({
        "status": "completed",
        "alert_id": alert_id,
        "execution_log": final["execution_log"],
    })


@app.post("/investigate/repo")
def investigate_repo():
    """Accepts EITHER a multipart file upload under the 'zip' field, OR a
    JSON body {"repo_url": "https://github.com/owner/repo", "branch": "main"}.
    Always cleans up the extracted temp directory when done, success or not."""
    root_path: str | None = None
    is_uploaded_temp = False
    try:
        if "zip" in request.files:
            uploaded = request.files["zip"]
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                uploaded.save(tmp.name)
                tmp_zip_path = tmp.name
            try:
                root_path = orchestrator.extract_uploaded_zip(tmp_zip_path)
                is_uploaded_temp = True
            finally:
                os.remove(tmp_zip_path)
        else:
            body = _require_json_object() or {}
            repo_url = body.get("repo_url")
            if not isinstance(repo_url, str) or not repo_url.strip():
                return jsonify({"error": "Provide either a 'zip' file upload or a JSON 'repo_url'."}), 400
            branch = body.get("branch", "main")
            if not isinstance(branch, str) or not branch.strip():
                branch = "main"
            root_path = orchestrator.fetch_github_repo(repo_url, branch=branch)
            is_uploaded_temp = True

        result = orchestrator.investigate_repo(root_path)
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 502
    finally:
        if is_uploaded_temp and root_path:
            # fetch_github_repo returns the unwrapped inner folder; its
            # parent is the actual temp dir that needs removing.
            cleanup_target = root_path
            parent = os.path.dirname(root_path)
            if os.path.basename(parent).startswith(("repo_upload_", "repo_github_")):
                cleanup_target = parent
            shutil.rmtree(cleanup_target, ignore_errors=True)


@app.post("/investigate/dependencies")
def investigate_dependencies():
    """Accepts EITHER a multipart file upload under the 'manifest' field,
    OR a JSON body {"filename": "requirements.txt", "content": "..."}."""
    if "manifest" in request.files:
        uploaded = request.files["manifest"]
        filename = uploaded.filename or "requirements.txt"
        content = uploaded.read().decode("utf-8", errors="ignore")
    else:
        body = _require_json_object() or {}
        filename = body.get("filename")
        content = body.get("content")
        if not isinstance(filename, str) or not filename.strip() or not isinstance(content, str):
            return jsonify({"error": "Provide either a 'manifest' file upload or JSON {filename, content} (both strings)."}), 400

    try:
        report = supply_chain.analyze_manifest(filename, content)
        return jsonify(report.to_dict())
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 502


@app.post("/investigate/phishing")
def investigate_phishing():
    body = _require_json_object()
    if body is None:
        return jsonify({"error": "Request body must be a JSON object."}), 400
    text = _require_nonempty_str(body, "text")
    if text is None:
        return jsonify({"error": "'text' is required and must be a non-empty string."}), 400
    report = phishing.analyze_message(text)
    return jsonify(report.to_dict())


@app.post("/investigate/website")
def investigate_website():
    """Live website security scan — passive checks only (headers,
    cookies, TLS, common exposed paths, CORS). See web_scanner.py's
    module docstring for the SSRF protection this depends on: the
    scanner refuses to fetch a URL that resolves to a private/internal/
    reserved IP, checked before the initial request and every redirect."""
    body = _require_json_object()
    if body is None:
        return jsonify({"error": "Request body must be a JSON object."}), 400
    url = _require_nonempty_str(body, "url")
    if url is None:
        return jsonify({"error": "'url' is required and must be a non-empty string."}), 400
    try:
        report = web_scanner.scan_url(url)
        return jsonify(report.to_dict())
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 502


if __name__ == "__main__":
    # Local development convenience only. Real deployment (Docker/Render)
    # runs this app under gunicorn instead — see the Dockerfile's CMD —
    # since Flask's built-in server is single-request-at-a-time and says
    # so itself. `python app.py` still works fine for local testing.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)), debug=False)
