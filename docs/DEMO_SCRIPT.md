# Demo Script

~5 minutes, four capabilities, one safety spine. Run `python app.py` and
have the dashboard open at `http://localhost:8080` before you start —
don't demo the setup, demo the product.

Every step below is a *real* call — real Groq inference, real OSV.dev
lookups, real static analysis on real files. Nothing in this script is
a canned/simulated response.

---

## 1. Open on the thesis (15s)

> "Most security tools flag things. This one investigates them —
> chains evidence into a story, and won't act on anything destructive
> without a human saying yes."

Show the four tabs. Don't click yet — just let the judge see the shape
of the product before you dive into one capability.

## 2. Alert Triage — the safety spine (60s)

This is the part every other capability shares, so establish it first.

1. Click **Alert Triage**. Click **run demo batch**.
2. Point at the decision ledger as it fills in real time — each alert
   goes through `enrich → triage → decide`, all real Groq calls.
3. When a **high/critical** alert lands in **Pending Approvals**, stop.
   Read the reasoning out loud — it's grounded in the specific
   evidence (a matched IOC, a CVE reference), not generic text.
4. Click **Approve**. Narrate: *"This is the one place in the system
   that can touch real infrastructure — block an IP, quarantine a
   host, disable an account — and it's hard-gated in code, not left to
   the model's judgment. The model can recommend; only a human executes."*

## 3. Repo Investigation — the strongest differentiator (2 min)

This is where you spend the most time — it's Priority 1 for a reason.

1. Click **Repo Investigation**. Paste a real GitHub URL (use a small
   repo with at least one real issue — an intentionally-vulnerable
   sample repo works well here, or your own project's early commit
   history if it has one).
2. Click **Analyze repository**. While it runs, narrate what's
   happening: *"Real static analysis first — languages, frameworks,
   every endpoint, every hardcoded secret, all from real file content
   on disk. Then a STRIDE threat model, then the findings get chained
   into a plausible attacker path."*
3. When results land:
   - Point at the **risk gauge** — sweep-in animation draws the eye.
   - Read one **STRIDE threat** aloud, emphasizing that it cites a real
     file and line number, not a vague warning.
   - Walk the **attack path** node by node: *"This isn't five
     disconnected findings — it's 'an attacker would do this, then
     this, then this,' each step naming the specific finding it relies on."*
4. Close with the **recommendations** list — concrete, not generic.

## 4. Supply Chain — practical, familiar problem (60s)

1. Click **Supply Chain**. Paste a `requirements.txt` with one
   known-vulnerable pinned package (e.g. an old `jinja2` or `flask`
   version) and one near-miss of a popular name (e.g. `reqeusts`
   instead of `requests`).
2. Click **Analyze dependencies**.
3. Point at the **trust score gauge**, then the flagged package cards:
   *"That vulnerability match is real — it just queried OSV.dev's
   actual database live. And that's a typosquat catch — one character
   off from a real package, the kind of thing that's easy to miss
   scrolling a lockfile by eye."*

## 5. Phishing/Scam — the cybercrime angle (45s)

1. Click **Phishing / Scam**. Paste a short urgency-styled message with
   a lookalike URL (e.g. `paypa1.com` or a brand name used as a
   subdomain of an unrelated domain).
2. Click **Analyze message**.
3. Read the **analyst reasoning** aloud — it cites both the language
   pattern *and* the specific URL red flag, not just one signal.

## 6. Close on the spine, not the features (30s)

> "Four investigation modes, one audit trail, one hard-gated approval
> point for anything destructive. It doesn't just flag things — it
> reasons about them, the way an analyst would, and it knows the
> difference between 'here's what I think you should do' and 'here's
> what I'm about to do.'"

If time allows, show the **decision ledger** one more time — the
append-only audit trail is the thing judges remember when they're
comparing five projects an hour later.

---

## If something goes wrong live

- **A Groq call is slow/rate-limited**: narrate through it — "this is
  hitting a real inference API, not a canned response, so latency
  varies" — and have a second, smaller repo/manifest/message ready as
  a fallback so you're not stuck waiting on one input.
- **A repo has zero findings**: that's a fine outcome to show too —
  point out the system says so honestly rather than inventing a threat
  to seem thorough (this is a stated design principle, not a
  fallback excuse — see `docs/ARCHITECTURE.md`).
- **Network drops**: the dashboard now shows a connection-lost banner
  and recovers automatically once the backend's back — no need to
  refresh or re-explain what happened.
