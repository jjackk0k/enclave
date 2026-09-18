# VARVEL campaign pipeline

A *campaign* is a phase state machine that runs autonomously and builds one shared
attack-surface model, an OPSEC ledger, and a lenient operator activity feed.

```
recon ──► validate ──► exploit ──► post-ex ──► report
              (gate: sigil)   (gate: sigil)
```

## Phases

| Phase | Gate | What it does |
|---|---|---|
| recon | none | discover hosts/services/tech/subdomains/endpoints |
| validate | none | vet exposed services into evidence-backed findings (sev) |
| exploit | **sigil** (HITL) | with a countersignature, prove exploitability minimally |
| post-ex | **sigil** (HITL) | minimum proof of impact; record every artifact for cleanup |
| report | none | synthesize a client-ready report |

Phase prompts are **lenient** — they describe intent, not restrictions. The hard,
unbypassable limits are the Enclave's (L2). Exploit + post-ex carry `gate: 'sigil'`:
the campaign obtains a human countersignature (`hooks.approve`) before the phase
runs — and the platform enforces the same gate again, independently.

## Three recon modes

`recon` can run in any of three modes (the rest of the pipeline is unchanged):

1. **LLM-driven** (default): the phase drives one `runGovernedAgent` loop; the agent
   uses authorized tools via the enclave shell and returns a structured JSON block
   that is ingested into the surface.
2. **Fireteam** (`fireteam: true`): parallel specialist sub-agents (port-sweeper /
   web-prober / surface-mapper) run concurrently, each governed, results merged.
3. **Tooled** (`tooledRecon: true, targets`): VARVEL's own native tools run
   deterministically — scan → version detect → HTTP/TLS fingerprint → web content
   discovery → subdomain discovery — no LLM required.

A campaign may also set **`reconOnly: true`** to stop after recon — a real,
discovery-only sweep whose surface is 100% genuine (no downstream agent output). This
is how `POST /api/breach-demo` breaches the bundled Acme demo target live with no API
key (see docs/DEMO-TARGET.md).

## Autonomy + resilience

- The human signs the engagement scope once (out of band) and approves the gated
  moments; the agent runs free inside the signed box the rest of the time.
- **A failing phase never crashes the campaign.** An agent error (LLM/network) or a
  tooled-recon exception is caught, logged as a `phase.error` activity event, and the
  campaign proceeds to the next phase (proven by `test/pipeline.test.mjs`).
- **Budget:** an operator-set `maxSteps` stops later phases when exhausted.
- **Cross-session memory:** prior findings are carried forward so a new session does
  not redo them.

## Autonomy integrity (honesty auditor) — the RedAmon-beating edge

RedAmon's standout autonomy trait is a honesty engine that downgrades dishonest
progress. VARVEL does the same thing as **deterministic, governed verification** — no
trust required:

- **Every discovery phase is audited.** After the phase, VARVEL compares the agent's
  CLAIMED progress (its text) against the REAL attack-surface delta. An agent that
  says "found / exploited / recovered X" while changing nothing is flagged
  `dishonest-or-stalled` and downgraded — hallucinated progress is never reported as
  fact (a `progress.flag` event; counted in `productivity.dishonest`).
- **Deny/stall backout (re-plan).** A recon/validate phase that produced NO new
  results is retried once (bounded by `maxReplan`) with a re-plan hint that tells the
  agent to change approach — RedAmon's LATS dead-end backout, minus the tree search.
- **Productivity + honesty rate** roll up into `getState().productivity` and the
  client report's **Autonomy integrity** section — a trust claim RedAmon can't make:
  "N phases, M productive, 0 hallucinated, honesty rate 100%."
- **Confidence-gated exploitation.** Findings carry a `confidence` (confirmed vs
  suspected); VARVEL only exploits **confirmed** findings — an unverified/hallucinated
  finding is never acted on. RedAmon exploits whatever the model asserts.
- **EvoGraph cross-session memory** (`carryForward`). A new session inherits the prior
  engagement's attack surface (hosts + confirmed findings, marked carried-forward so
  this session's real delta stays clean) and builds on it.

## Governance split (why lenient is safe)

- **L1 — VARVEL:** lenient. Workflow, HITL courtesy gates, native tools, activity
  feed. No governance friction, and **no audit of record** — that is deliberately not
  VARVEL's job.
- **L2 — Enclave:** strict + unbypassable. Every tool call in a live campaign crosses
  the `govern → classify → Cedar → audit` seam; the tamper-evident audit and hard
  enforcement live here. VARVEL inherits them for free and only *surfaces* them.

Rule of thumb: if a feature restricts / enforces / proves-for-compliance, it belongs
to the Enclave, not VARVEL.

## State + API

`Campaign.getState()` → `{ surface, opsec, activity, budget, inheritedFindings }`
(no `audit` key — that's the enclave's). The service exposes it at `GET /api/state`
(+ SSE `GET /api/events`), with `POST /api/campaign|approve|opsec/cleanup|message`
and `GET /api/report|remediation`. The live console renders this in real time.
