# Security Autopilot Agent

**An autonomous AI security platform for alert triage, threat modeling,
attack-path reasoning, supply-chain analysis, phishing/scam investigation,
live website security scanning, and human-approved remediation.**

Not a scanner — an investigator. Point it at a security alert, a GitHub
repo or ZIP, a dependency manifest, a suspicious message, or a live URL,
and it reasons through the finding, chains evidence into a realistic
attack story, scores risk, and recommends next steps — pausing for a
human's sign-off before anything destructive happens.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design,
[`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) for the demo walkthrough,
and [`docs/PITCH.md`](docs/PITCH.md) for the positioning pitch.

## What it does

| Capability | Input | Output |
|---|---|---|
| **Alert triage** | Raw security alert (EDR/SIEM/firewall/IOC) | Severity, remediation plan, human-gated execution |
| **Threat modeling** | GitHub repo URL or ZIP upload | STRIDE threats, trust boundaries, entry points, risk score |
| **Attack path discovery** | (chained from threat model) | Ordered attacker path from initial access to impact |
| **Supply chain security** | `requirements.txt` / `package.json` | Real OSV.dev vuln matches, typosquat detection, real CVSS v3 |
| **Phishing/scam investigation** | Email/SMS/chat text or bare domain | URL red-flag analysis, heuristics, LLM verdict + confidence |
| **Website security scan** | Any live URL | Headers, cookies, TLS, CORS, exposed paths — passive, SSRF-protected |

Every capability produces the same shape of answer: an executive
summary, a risk score, the evidence behind it, and a recommended next
step — shown live in the dashboard at `/` (5 tabs).

## Safety spine shared by all six capabilities

- **Dual human-gate floors** — action-type (`DESTRUCTIVE_ACTIONS`) and
  severity (`APPROVAL_SEVERITY_FLOOR`), both checked in code after the
  LLM call, neither can be talked down by the model
- **SQLite-backed checkpointer** — paused approvals survive process
  restarts; resuming needs only the alert ID, not a live Python object
- **Append-only audit log** — every decision timestamped and logged
- **Grounded reasoning** — every LLM prompt is instructed never to
  invent a finding the deterministic layer did not actually detect
- **Real data** — live FireHOL IOC feed, live OSV.dev vuln DB, real
  CVSS v3 formula (verified against Log4Shell's published 10.0 score)
- **Rate limiting** — per-IP sliding window on all network-calling routes
- **SSRF protection** — website scanner checks resolved IPs before
  every fetch, rejects private/loopback/cloud-metadata ranges
- **XSS protection** — all dynamic values HTML-escaped before rendering

## Setup

```bash
python -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env              # fill in GROQ_API_KEY
python app.py                     # open http://localhost:8080
```

Get a Groq API key from https://console.groq.com/keys

## Run tests

```bash
pip install pytest
python -m pytest -q
# 184 passed
```

184 tests. Every LLM and network call is mocked at the transport
boundary only — not security results. Includes real zip-bomb payloads,
real crash-test battery, and real SSRF protection probes.

## Run with Docker

```bash
docker build -t security-autopilot-agent .
docker run -p 8080:8080 --env-file .env security-autopilot-agent
```

Served by gunicorn (`--workers 1 --threads 4`). Single worker is
deliberate — see `app.py` module docstring.

## Deploy to Render

`render.yaml` at the repo root — "New +" → "Blueprint", point at this
repo. Set `GROQ_API_KEY` in the Render dashboard (never committed).

## API routes

```
POST /alerts                     Submit a real alert for triage
GET  /pending                    List alerts awaiting human approval
POST /approve/<id>               Approve or deny a pending action
GET  /history                    Full decision ledger
POST /investigate/repo           Analyze a GitHub repo or ZIP upload
POST /investigate/dependencies   Supply chain scan (manifest file)
POST /investigate/phishing       Phishing/scam message analysis
POST /investigate/website        Live website security scan
GET  /healthz                    Health check
```

## Known limitations (stated, not hidden)

- Repo analysis is regex + entropy based — not a real AST parse
- Supply chain: `requirements.txt` and `package.json` only; CVSS v2 not scored
- Phishing: no live blocklist (PhishTank/Safe Browsing); text/URL only
- Website scan: passive misconfig check only, not a penetration test
- Remediation: fail-closed without `REMEDIATION_WEBHOOK_URL` configured
- Nothing here executes an attack or touches a real target system

## Roadmap

- SOAR integrations (real EDR/SIEM webhooks)
- Live phishing blocklist feed
- Screenshot/QR phishing analysis
- Multi-feed IOC (abuse.ch URLhaus, Feodo Tracker)
- CVSS v2 scoring
- Cargo.toml / pyproject.toml manifest support
- Multi-repo supply-chain dashboard

## Project structure

```
app.py                    Flask API + rate limiting + all 6 investigation routes
cli.py                    CLI runner — accepts real alert JSON from file or stdin
render.yaml               Render deployment config
Dockerfile                Container build (gunicorn)
static/index.html         Dashboard — 5 tabs, XSS-escaped throughout
src/
  models.py               All data models + DESTRUCTIVE_ACTIONS safety floor
  config.py               All env-var config
  groq_client.py          All LLM prompts
  graph.py                LangGraph triage flow + dual gates + SQLite checkpointer
  threat_intel.py         Live IOC feed + NVD CVE enrichment
  ioc_feed.py             FireHOL blocklist fetch/cache/CIDR matching
  remediation.py          Fail-closed webhook executors
  audit_log.py            Append-only JSONL decision log
  repo_intel.py           Static analysis + Shannon entropy secret detection
  manifest_parser.py      requirements.txt / package.json parsing
  supply_chain.py         OSV.dev + typosquat + real CVSS v3 trust scoring
  cvss.py                 Real CVSS v3.0/v3.1 base-score calculator
  threat_model.py         STRIDE rules + LLM augmentation
  attack_path.py          Threat chaining → attacker path
  phishing.py             URL heuristics + bare-domain support + LLM
  orchestrator.py         GitHub fetch + zip-slip/bomb-safe extraction
  web_scanner.py          Passive website scanner with real SSRF protection
tests/                    184 tests
docs/ARCHITECTURE.md      Design doc + flow diagram
docs/DEMO_SCRIPT.md       5-minute demo walkthrough
docs/PITCH.md             Positioning pitch
```

## Real vs. requires-your-configuration

| | Status |
|---|---|
| IOC matching (FireHOL) | Zero config — live feed |
| Supply chain (OSV.dev) | Zero config — live public DB |
| Repo static analysis | Zero config — reads real files |
| CVSS scoring | Zero config — real formula |
| Website scanner | Zero config — hits live URLs |
| Pending approvals durability | Zero config — SQLite-backed |
| LLM reasoning | Needs `GROQ_API_KEY` |
| Remediation execution | Needs `REMEDIATION_WEBHOOK_URL` |
| Phishing blocklist | Not implemented |

## License

MIT — Copyright (c) 2026 Jai Surya P — see [LICENSE](LICENSE).
