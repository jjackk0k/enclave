# Autopilot build — 2026-09-01

Jack's directive: *"make it automated so VARVEL AI starts getting results and vuls."*
The wide-first playbook's pieces all existed but were separately invoked; this build is
**the orchestrator that glues them** — `tools/autopilot.mjs`, a durable scheduler that
runs the loop without human babysitting. Honesty contract, stated up front: the
autopilot **never submits and never files anything anywhere** (there is no submission
code path in the file — its own HTTP client talks to the loopback console ONLY, and any
other host is refused before a request is built), unknowns are recorded **UNKNOWN**,
every refusal is logged with its reason, and a clean cycle is reported clean.
Tests: `test/autopilot.test.mjs` (17); neighbor suites re-run green (widerecon,
commitwatch, privemap, reachprove, bountyline — the modules it glues).

## Layout

- **`tools/autopilot.mjs`** — the scheduler. Imports the existing pieces in-process
  (the same functions the CLIs call): `widerecon sweep()`, `commitwatch scan(live)`,
  `privemap()`, `reachproveRescore()`, bountyline's `CADENCE_MAP` / `loadProgram` /
  `verifyScopeFixture`. Drives the console server through its EXISTING HTTP endpoints
  (`GET /api/ghost`, `GET /api/state`, `POST /api/message`, `POST /api/campaign`) —
  no server changes.
- **`test/autopilot.test.mjs`** — hermetic: fixture corpus/bountyline dirs, injected
  fakes for the sweep/scan/miners, a fake loopback console; the launch gates, the
  coverage tracking, the ONE-brief serialization, and the never-submits static pin.
- **`.tmp/autopilot/`** (created on the first wet run) — everything the autopilot
  writes: `state.json` (coverage, last sweep, launches, refusals — write-through after
  every phase), `autopilot.jsonl` (the run log, one event per line),
  `sweeps/widerecon-<ts>.json` (each sweep report), `hunt/{privemap,reachprove}/<slug>.json`
  (the WP-lane reports), and `digest-YYYY-MM-DD.md` (per cycle: what ran, what found,
  what was refused and why).

## What one cycle does

```
node tools/autopilot.mjs run [--once] [--interval h] [--dry]
```

1. **widerecon sweep + diff** — `sweep()` over the whole roster (policy-aware:
   prohibited programs get zero requests and are named SKIPPED-POLICY). The report is
   diffed against the previous sweep in state: new catches / gone catches / score moves
   land in the log and digest. A failed sweep is a named error; the previous sweep
   stays on record (nothing fabricated).
2. **commitwatch live scan** — `scan({ source: liveSource({ allow: true }) })` (the
   same gated path as `commitwatch scan --live`: wordpress.org hosts only, read-only).
   NEW leads (slug@revision not seen before) are reported REVIEW-ONLY — the watcher
   doctrine stands: a fix commit is a map to a bug class, not a finding.
3. **WP lane** — the corpus roots (`VARVEL_AUTOPILOT_CORPUS`, default the two
   varvel-kimi trees, 101 plugins today) minus slugs already covered by an existing
   hunt report (`.tmp/hunt-*/privemap/*.json` ∪ the autopilot's own) — the remainder is
   swept with `privemap` + `reachprove --rescore`, capped per cycle
   (`VARVEL_AUTOPILOT_WP_MAX_PER_CYCLE`, default 20; the backlog drains over cycles; a
   failed plugin is NOT marked covered). Top candidates (reachprove CONFIRMED|UNCERTAIN
   at unauth/subscriber reach, doctrine-gated classes dropped, ranked by penalized
   newScore) go to the console chat agent for AI adjudication: **ONE brief per cycle**
   via `POST /api/message` (≤4000 chars, review-only doctrine embedded), then the
   autopilot polls `GET /api/state` until `agentThinking` clears (cap
   `VARVEL_AUTOPILOT_MESSAGE_WAIT_MS`, default 30 min). A busy chat defers the brief
   and KEEPS the queue; a completed adjudication drains the briefed candidates.
4. **Campaign launcher** — for programs in the sweep whose bountyline record
   (`data/bountyline/programs/<id>.json`) carries automation `full|human-cadence` AND a
   signed scope on record: the signed scope is re-verified (`verifyScopeFixture` —
   shape + seam signature when importable), then `POST /api/campaign` with the record's
   engagement, the scope fixture's CIDRs, the sweep's top catch hosts as seeded
   targets, `approveTimeoutMs: 0` (HITL gates park for the operator — the bykea
   lesson), `carryForward: true`, and the program's attestation `extraHeaders` when the
   record carries them. `human-cadence` forces the CADENCE_MAP ceiling (stealth
   paranoid, maxSteps 50, crawl 5 pages, vuln 3 probes); `full` adds no ceiling. One
   launch per cycle at most, ranked by the program's best catch score; the
   last-launched program yields to the next eligible one (rotation — breadth over the
   roster).

## The hard rules (code, test-pinned)

- **NEVER SUBMITS / NEVER FILES.** No submit-drive import, no platform API, no
  submission verbs — pinned by a static scan. The autopilot's console client enforces
  the loopback allowlist (127.0.0.1 / localhost / [::1]) BEFORE any request is built
  (`console-host-not-allowed`). Findings surface to the operator (digest + state +
  chat); the send click is the operator's, always.
- **GHOST-OFF = NO LAUNCHES.** `GET /api/ghost` must answer `mode != 'off'` AND
  `verified.ok === true`, or every launch is REFUSED with the reason named, loudly
  (`ghost-off` / `ghost-unverified` / `ghost-status-unknown`).
- **ONE CAMPAIGN, NEVER A CLOBBER.** The server has a single campaign global; the
  autopilot reads `GET /api/state` first and launches ONLY on `idle|interactive|done`.
  Anything else (running/stalled/errored/chat-busy) SKIPS with the status named.
- **PROHIBITED IS NAMED, VISA IS HARD-EXCLUDED** (Jack's rule).
  `LAUNCH_EXCLUDED_PROGRAMS = ['visa', ...widerecon PROHIBITED_PROGRAMS]` refuses in
  code — even with a valid roster record and signed scope. Prohibited records refuse
  with their basis and evidence quoted. No record / no signed scope / an empty scope
  CSV are named refusals (`no-program-record` / `no-signed-scope`), never silent skips.
- **Every refusal is logged** — state ring (200), the JSONL run log, and the daily
  digest, each with its reason.

## CLI

```
node tools/autopilot.mjs run            # loop forever (default 4h; SIGINT stops cleanly)
node tools/autopilot.mjs run --once     # a single cycle, then exit
node tools/autopilot.mjs run --interval 2   # hours between cycles (env VARVEL_AUTOPILOT_INTERVAL_H)
node tools/autopilot.mjs run --once --dry   # the plan ONLY — nothing written, no requests
```

`--dry` computes the plan from the state on record (local reads only): what the sweep
would re-cover, which corpus plugins are NEW, the standing per-program refusals, and
the top launch candidate IF the runtime gates pass — with ghost/campaign status named
UNKNOWN (not queried). Dry never writes state, logs, or digests.

Env: `VARVEL_AUTOPILOT_INTERVAL_H` (4) · `VARVEL_AUTOPILOT_DIR` (`.tmp/autopilot`) ·
`VARVEL_AUTOPILOT_API` (`http://127.0.0.1:8971` — loopback enforced regardless) ·
`VARVEL_AUTOPILOT_CORPUS` (CSV of corpus roots) · `VARVEL_AUTOPILOT_WP_MAX_PER_CYCLE`
(20) · `VARVEL_AUTOPILOT_ADJUDICATE_TOP` (5) · `VARVEL_AUTOPILOT_MESSAGE_WAIT_MS`
(1800000) · `VARVEL_AUTOPILOT_LAUNCH=off` (launcher disabled — the rest of the cycle
still runs).

## Limits (stated, not hidden)

- The launch decision is only as fresh as the sweep — a program whose policy changed
  since the last intake gets caught at the NEXT sweep, not mid-cycle.
- The chat adjudication rides the console's single chat singleton: one brief at a
  time, and an operator mid-conversation defers the autopilot's brief (queue kept).
- The autopilot launches campaigns; it does not watch them. Progress, findings, and
  the coverage gate are the campaign's own (`GET /api/state`, the console) — the
  autopilot's digest records the launch and moves on.
- A wet `--once` against the live console really posts the brief and (gates
  permitting) really launches a campaign. That first run is the operator's deliberate
  act — the dry mode exists to rehearse it.
