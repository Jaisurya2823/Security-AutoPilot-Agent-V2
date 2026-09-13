FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
EXPOSE 8080

# Render (or any Docker-based host) execs this exact command inside the
# container, so building/running this image locally is a faithful preview
# of deployed behavior.
#
# gunicorn, not `python3 app.py` — the Flask dev server is explicitly
# single-request-at-a-time and prints its own warning against production
# use. --workers 1 is intentional, not a scaling oversight: _PENDING (the
# pending-approvals index in app.py) is an in-memory dict and the graph
# checkpointer holds one SQLite connection — both are process-local, so
# more than one worker process would silently desync between requests
# routed to different workers. --threads 4 still gives real I/O
# concurrency (a slow Groq call no longer blocks /healthz or /pending)
# within that single process. See app.py's module docstring for the
# roadmap item to make _PENDING shared (unlocking multi-worker) later.
#
# Shell form (not JSON-array) is deliberate here — Render injects $PORT
# at runtime, and only shell form expands it; ${PORT:-8080} keeps
# `docker run` locally working the same way app.py's own fallback does.
CMD gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 1 --threads 4 --timeout 120 app:app
