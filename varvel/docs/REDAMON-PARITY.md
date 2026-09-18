# VARVEL vs RedAmon — agent process parity

An honest, sourced comparison of how each system's AI actually operates, and what
VARVEL did to be **as good or better** on every axis. Primary source: RedAmon's own
Agentic-System whitepaper + wiki (github.com/samugit83/redamon).

## How RedAmon's agent works (the short version)

A LangGraph ReAct state machine ("SG-ReAct", 14 nodes). Each `think` step emits one
structured decision (use a tool, plan a wave, deploy a fireteam, transition phase, ask
the user, or complete). Notable machinery:

- **Exploit-Path Search (LATS):** a real value-guided MCTS over exploit probes — UCT
  selection, depth ~6, a 24-class outcome→[0,1] value function, prune floor ~0.15,
  scoring **real** probes (no rollout), auto-activated only when ≥2 credible paths exist.
- **Anti-stuck / honesty suite:** (1) a productivity audit that cross-checks the agent's
  "new info" claim against the real state delta; (2) a **deterministic state-growth
  counter** ("iterations since state last grew") — their most reliable, LLM-independent
  stuck signal; (3) **axis lock-in** detection for repetitive tools; feeding a 5-tier
  ladder up to "reject the next expensive repeat".
- **Fireteam:** parallel specialist sub-agents for any decomposable objective.
- **EvoGraph:** cross-session memory that carries prior **failures/decisions**, injected
  before the first reasoning step.
- **OPSEC:** a prompt-level "Stealth Mode" only — the whitepaper concedes *"no explicit
  modeling of detection footprint, noise accumulation, or evasion."*
- **No confidence-gated exploitation:** it will exploit low-confidence findings if a
  human approves the dangerous tool.

## Where VARVEL now stands

| Axis | RedAmon | VARVEL | Status |
|---|---|---|---|
| Value-guided search (LATS) | real MCTS over probes | **`engine/pathsearch.mjs`** — UCT, outcome→[0,1] value fn, prune floor, bounded depth, **auto-activate on ≥2 credible paths**, real probes (no rollout). **Wired into the exploit phase** via `engine/webpaths.mjs` (non-destructive GET/OPTIONS discovery) → the agent gets a ranked focus list | **parity + more** (see below) |
| Honesty audit (claim vs real) | productivity verdict audit | honesty auditor (claimed-vs-surface-delta) | parity |
| Deterministic stuck signal | state-growth counter | **`productivity.stuckStreak`** + live `campaign.stuck` — longest no-growth run, from the real delta, LLM-independent | **parity** |
| Escape-the-rut reasoning | 5-tier ladder + Deep Think | **escalating re-plan**: tier 1 change-approach → **tier 2 Deep-Think** (force ≥2 competing hypotheses), auto-escalated by the stuck counter | parity (lighter ladder) |
| Confidence-gated exploitation | **none** | **numeric confidence 0–100** (`surface.conf`) with a tunable `CONFIRM_AT` gate; only confirmed-tier findings get exploited | **VARVEL ahead** |
| Modeled OPSEC footprint | prompt-only | **`engine/footprint.mjs`** — per-activity detection/exposure model, scored, surfaced | **VARVEL ahead** |
| Explicit validate phase | folded into recon | separate `validate` phase | VARVEL cleaner |
| Predictable/auditable control | free-routing state machine | fixed phase FSM + HITL gates | VARVEL cleaner (certifiable) |
| Cross-session memory | surface **+ failures** | surface (carryForward) **+ failure ledger** (`store.recordFailures`/`priorFailures` — held actions, failed exploits, dead-end phases; inherited + injected before the next run) | **parity** |
| Fireteam generality | any objective | recon-only | RedAmon ahead — *see roadmap* |
| NL → graph query | agent queries Neo4j via NL (`query_graph`) | **`engine/graphquery.mjs`** — native NL→structured-filter over the in-memory surface (`GET /api/query`); answers trace to the producing node | **parity + more** (provenance) |

### Two ways VARVEL's search goes beyond RedAmon's

`pathSearch`'s value function has two hooks their design does not claim:

- **`opsecCost(descriptor)`** — a noise penalty subtracted from a probe's value, so among
  equally-promising paths the **quieter** one wins. RedAmon's OPSEC can't influence its
  search (it's prompt-only).
- **`prior(descriptor)`** — a cross-session prior *boost*, so a path a previous engagement
  found useful is explored sooner. RedAmon's EvoGraph feeds the prompt, not the search's
  value estimates.

## Roadmap (to stay ahead)

- ✅ **Wire `pathSearch` into the live exploit phase** — DONE (`guidedExploitPrep`; the
  agent gets a ranked, actionable focus list; non-destructive; detonation stays HITL).
- ✅ **Failure memory** — DONE (`store` failure ledger; inherited + injected).
- ✅ **NL → graph query** — DONE (`engine/graphquery.mjs`, native NL→structured-filter
  over the in-memory surface; `GET /api/query`). Beats RedAmon's Neo4j round-trip:
  answers trace straight to the producing node (the honesty auditor's provenance).
- ✅ **Numeric confidence (0–100)** — DONE (`surface` stores `conf`; `CONFIRM_AT`
  threshold derives the confirmed-only exploit gate; shown in the report).
- ✅ **Claude CLI backend** — DONE (`engine/claude-cli.mjs`): VARVEL's live agent can be
  the real `claude -p`, governed by the same hook, **running host-side** so it reaches
  the host-local demo with no container. Readiness auto-prefers it.
- **NL → tool-command translation** (cautious): suggest tool invocations from NL — always
  behind the enclave hook. Not yet built.
- **Generalize the fireteam** beyond recon (hard caps, source-tagged fan-in).
- **Governance hardening to copy** (Enclave layer, not VARVEL): per-call nonce sentinels
  around tool output (prompt-injection defense); code-before-LLM phase/technique gating.
