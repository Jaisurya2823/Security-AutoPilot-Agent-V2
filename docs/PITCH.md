# Pitch — Security Autopilot Agent

## The one-liner

**Security Autopilot Agent doesn't just flag alerts — it investigates.**
Point it at an alert, a repo, a dependency file, or a suspicious
message, and it reasons like an analyst: builds a threat model, chains
findings into a realistic attack path, scores supply-chain trust, and
catches phishing — then explains every finding like a mentor and
refuses to act without human sign-off.

## The problem

Most security tooling in this space falls into one of two failure modes:

1. **Scanners that flag without reasoning** — a list of isolated
   findings with no story connecting them, so a human still has to do
   the actual analytical work of figuring out what matters and why.
2. **"AI security" demos that are unsafe by construction** — agents
   that take real action (block, quarantine, delete) with no hard
   gate stopping a wrong or manipulated model output from executing
   against real infrastructure.

## What we built instead

One platform, four investigation modes, one shared safety spine:

| | |
|---|---|
| **Alert triage** | Real IOC/CVE enrichment → LLM triage → remediation plan → **hard-gated human approval** before anything destructive executes |
| **Threat modeling + attack path** | Real static analysis of a repo (endpoints, secrets, frameworks, auth) → STRIDE threats grounded in actual findings → chained into a plausible attacker path |
| **Supply chain security** | Every pinned dependency checked against OSV.dev's real vulnerability database, plus typosquat detection and lifecycle-script flagging |
| **Phishing/scam investigation** | URL structure analysis (homograph domains, brand impersonation, IP literals) combined with LLM language-pattern reasoning |

The unifying idea: **every capability produces the same shape of
answer** — an executive summary, a risk score, the evidence behind it,
and a recommended next step. That's what makes it a platform instead
of four unrelated tools bolted together.

## Why the safety design is the actual differentiator

Anyone can wire an LLM to a security alert and ask it to "decide what
to do." The harder, more valuable engineering problem is: **what
happens when the model is wrong, or the input is adversarial?**

- Destructive actions (`block_ip`, `quarantine_host`, `disable_account`)
  are gated in *code*, not by asking the model nicely — a hard floor
  the model cannot talk itself out of, even if the alert text is
  crafted to manipulate it.
- Every LLM prompt in the investigation flows is explicitly instructed
  to reason only from real findings a deterministic layer already
  found — never to invent an endpoint, secret, or vulnerability that
  static analysis didn't actually detect.
- The threat model's risk score is never allowed to be talked down
  below the worst mechanically-detected finding, even by the model's
  own summary judgment.
- Every decision — what was seen, what was decided, whether a human
  approved it, what executed — lands in an append-only audit log.

## What makes it real, not a demo

- Supply-chain checks hit OSV.dev's actual public vulnerability database.
- Repo analysis is real regex/pattern-based static analysis against
  real file content on disk — not a scripted response to a known input.
- The repo-analysis pipeline is hardened against zip-slip path
  traversal on uploaded archives — tested against an actual malicious
  zip payload, not assumed safe.
- 86 automated tests, every external network/LLM call mocked at the
  transport boundary only — never a faked security *result*.

## Where we drew the line (and why)

Deliberately **not** in scope for this build: autonomous penetration
testing that performs real attacks, full malware reverse engineering,
long-term cross-incident correlation. Each of those needs the same
hard-gated-approval pattern proven here before it should be built —
see `docs/ARCHITECTURE.md`'s roadmap. A platform that does five things
safely beats one that does fifteen things recklessly.

## The 5-minute takeaway

If a judge remembers exactly one thing: **this system knows the
difference between "here's what I think you should do" and "here's
what I'm about to do,"** and that boundary is enforced in code, not
just promised in a system prompt.
