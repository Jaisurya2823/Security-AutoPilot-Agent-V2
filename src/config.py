"""
Central config. Everything is read from environment variables so the same
code runs unmodified locally and on Render (which injects env vars from
its own dashboard/render.yaml, not a .env file).
"""
import os

from dotenv import load_dotenv

load_dotenv()

# --- Groq (LLM inference) ---
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
# gpt-oss-120b is Groq's current production-tier reasoning model (Groq
# deprecated llama-3.3-70b-versatile and kimi-k2 in its favor in 2026).
# Override via env if Groq's lineup changes again.
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
# Cheaper/faster model for high-volume, low-complexity calls (alert
# triage classification). Same model family as GROQ_MODEL so output
# shape/behavior stays consistent if you fail over between them.
GROQ_MODEL_FAST = os.getenv("GROQ_MODEL_FAST", "openai/gpt-oss-20b")

# --- Supply chain agent: OSV.dev (Open Source Vulnerabilities, public API) ---
OSV_API_URL = os.getenv("OSV_API_URL", "https://api.osv.dev/v1")

# --- Agent behavior ---
# Any action at or above this severity always routes through the human
# gate, even if the model or the destructive-action floor wouldn't have
# forced it. Tunable per deployment risk appetite.
APPROVAL_SEVERITY_FLOOR = os.getenv("APPROVAL_SEVERITY_FLOOR", "high")

# Live external enrichment (NVD CVE lookups) is optional — the agent must
# degrade gracefully if this is off or the network call fails, since a
# threat-intel outage should never silently block triage.
ENABLE_LIVE_CVE_LOOKUP = os.getenv("ENABLE_LIVE_CVE_LOOKUP", "false").lower() == "true"

# --- Alert-triage graph state persistence ---
# SQLite-backed (not the default in-memory checkpointer): a paused
# human-gate decision survives a process restart, as long as the
# database file itself does (a single-instance deployment's local disk;
# see the README's "real vs. requires-your-configuration" table for
# what this does and doesn't protect against).
GRAPH_CHECKPOINT_PATH = os.getenv("GRAPH_CHECKPOINT_PATH", "graph_checkpoints.sqlite3")

# --- Remediation execution ---
# There is no universal API across firewalls/EDR/IdP vendors, so
# destructive remediation actions (block_ip, quarantine_host,
# disable_account, open_ticket) are executed by POSTing to a webhook you
# control — point it at your SOAR platform, your own automation, or a
# vendor-specific adapter. If this is unset, those actions fail closed
# (execute() reports success=False) rather than claiming to have
# touched real infrastructure when nothing happened.
REMEDIATION_WEBHOOK_URL = os.getenv("REMEDIATION_WEBHOOK_URL", "")
REMEDIATION_WEBHOOK_TIMEOUT_SECONDS = float(os.getenv("REMEDIATION_WEBHOOK_TIMEOUT_SECONDS", "10"))

# --- Repo ZIP upload safety limits (zip-bomb protection) ---
# A malicious zip can be a few KB compressed and expand to gigabytes —
# enforced during extraction by counting actual bytes written, not by
# trusting the zip's own (spoofable) declared size metadata.
MAX_ZIP_UNCOMPRESSED_BYTES = int(os.getenv("MAX_ZIP_UNCOMPRESSED_BYTES", str(500 * 1024 * 1024)))  # 500 MB
MAX_ZIP_FILE_COUNT = int(os.getenv("MAX_ZIP_FILE_COUNT", "20000"))

# --- Threat intel: known-bad-IP feed ---
# FireHOL's level1 netset (CC-BY-SA, github.com/firehol/blocklist-ipsets)
# aggregates several long-standing, high-confidence malicious network
# blocklists (Spamhaus DROP, DShield top attackers, etc.) into one file.
# Cached locally and refreshed on this interval rather than fetched on
# every alert.
IOC_FEED_URL = os.getenv(
    "IOC_FEED_URL",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
)
IOC_FEED_CACHE_SECONDS = int(os.getenv("IOC_FEED_CACHE_SECONDS", str(6 * 3600)))  # 6 hours

# --- Live website security scanner ---
WEB_SCAN_TIMEOUT_SECONDS = float(os.getenv("WEB_SCAN_TIMEOUT_SECONDS", "12"))

# --- Rate limiting (in-memory, per-process — see app.py's module docstring
# for why this matches the existing single-worker deployment constraint) ---
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "20"))


def require_groq_key() -> None:
    if not GROQ_API_KEY:
        raise RuntimeError(
            "GROQ_API_KEY is not set. Get one from https://console.groq.com/keys "
            "and put it in your .env file."
        )
