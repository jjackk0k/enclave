# VARVEL

**Governed autonomous red team — the flagship of Enclave.**

A RedAmon-class autonomous offensive-security platform built *into* Enclave. The
goal: **out-tool and out-quality** RedAmon (and paid tools) — a genuinely better,
higher-quality red-team platform that also happens to be governed. The operator
gets RedAmon-level leniency and fluidity; the strict, unbypassable safety net
comes for free from the Enclave underneath.

> The hawk hunts alone — it wears your ring.

## Two-layer model (safe *and* lenient)

- **L1 — VARVEL (this project): lenient.** Trust the operator's AI. Phase workflow,
  objectives, HITL courtesy gates, native tools. **No governance friction, no
  strict/compliance features baked in.** Same philosophy as RedAmon.
- **L2 — Enclave (platform): strict, unbypassable.** Signed engagement scope,
  FS-jail, egress deny-by-default, real Cedar PDP, HITL enforcement, and the
  hash-chained **tamper-evident audit of record**. VARVEL inherits all of this
  for free and merely *surfaces* it — it never owns or reimplements it.

Rule of thumb: if a feature *restricts / enforces / proves-for-compliance*, it's
the Enclave's, not VARVEL's.

## Layout

```
engine/
  surface.mjs    attack-surface graph model — 16 node types, 20 edge kinds
                 (root·host·subdomain·service·port·endpoint·tech·cve·finding·
                  exploit·cred·account·foothold·route·asset·out). toJSON() is
                  the console's live data contract.
  phases.mjs     campaign catalog: recon → validate → exploit → post-ex → report
                 (exploit + post-ex are HITL-gated). Prompts are LENIENT.
  campaign.mjs   the phase FSM. Reuses runGovernedAgent via a `runAgent` DI param.
                 Modes: LLM-driven, Fireteam parallel specialists, or native
                 tooled recon. Tracks OPSEC + budget + a lenient activity feed.
                 getState() = {surface, opsec, activity, budget} — NO audit key.
  opsec.mjs      engagement-hygiene ledger (artifacts + cleanup + footprint).
  store.mjs      cross-session memory: surface + findings + a FAILURE ledger (failed
                 approaches carry forward so a new session won't repeat them).
  fireteam.mjs   parallel specialist sub-agents (Scatter-Gather ReAct).
  report.mjs     surface → client-ready Markdown (findings, governance holds,
                 OPSEC detection footprint, remediation).
  classify.mjs   finding → OWASP 2021 + MITRE ATT&CK + remediation.
  identity.mjs   the Enclave console handoff: reads the SIGNED session, verifies it,
                 sources scope from the signed engagementScope. Clearance INFORMS.
  footprint.mjs  detection-footprint knowledge base — per-activity noise/exposure the
                 OPSEC page + report surface (transparency, never evasion).
  live.mjs       live-mode config: model backend (Kimi K3 / key) + governance seam +
                 readiness + the operating brief injected into live runs.
  auditor.mjs    honesty/productivity audit — claimed-vs-real delta, deterministic
                 stuck-streak, escalating Deep-Think re-plan.
  pathsearch.mjs value-guided path search (LATS/MCTS) — UCT, outcome value fn, prune,
                 auto-activate on ≥2 credible paths; opsecCost + prior hooks.
  webpaths.mjs   non-destructive web adapter (GET/OPTIONS) that runs pathsearch as
                 content discovery; feeds the exploit phase a ranked focus list.
  graphquery.mjs natural-language query over the surface graph (NL→structured filter;
                 GET /api/query). Answers trace back to the producing node.
  claude-cli.mjs Claude-CLI live backend — the real `claude -p`, governed by the same
                 hook, running HOST-SIDE so it reaches the host-local demo (no container).

tools/           VARVEL's own recon tooling (lenient; the enclave governs scope).
                 Each tool was adversarially audited by a probe agent + hardened —
                 see docs/TOOLS.md.
  recon.mjs      TCP-connect scanner + service/version detection (banner sigs) +
                 HTTP/TLS fingerprint + Shodan-compatible mmh3 favicon hash
                 (KAT-verified) + security-header analysis. Connect-only.
  webscan.mjs    web content discovery + sensitive-exposure detection with a
                 soft-404 baseline, content validation, and same-origin enforcement.
  dns.mjs        DNS record enumeration + subdomain discovery, wildcard-DNS aware.
  tlsscan.mjs    TLS config analyzer — weak-protocol / expiry / self-signed /
                 hostname-mismatch findings.
  httpmethods.mjs  HTTP methods + CORS misconfiguration + missing-header checks.

targets/
  demo-corp.mjs  bundled, authorized "Acme Robotics" practice target (localhost)
                 with realistic planted exposures — VARVEL breaches it live with no
                 API key. See docs/DEMO-TARGET.md.

test/            206 tests, `npm test` (also run in CI) — edge cases + adversarial
                 regressions, not just the happy path. Phase FSM in docs/PIPELINE.md.
                 test/breach.test.mjs proves an end-to-end breach + modify of the demo.
mock-agent.mjs   offline agent (no API key) for demo/tests.
demo.mjs         `npm run demo` — full campaign end-to-end offline.
server.mjs       `npm run serve` — HTTP service (port 8971); also boots the demo
                 target on 8972 and exposes POST /api/breach-demo.
app-v3.html      live, data-driven, multi-page console with a force-directed
                 attack-surface graph, tightened module pages, and a live autonomy-
                 integrity card (served at `/`; previous builds at `/v2` and `/v1`).
```

## Run it

```bash
cd varvel
npm test        # 206 tests
npm run demo    # offline end-to-end campaign -> demo-surface.json
npm run serve   # http://localhost:8971  (open in a browser)
```

Once the service is up, from the Settings page (or via curl):
- **“Breach the Acme demo target”** / `POST /api/breach-demo` — VARVEL's own native
  scanner breaches the bundled site: real findings, real surface graph, **no API key**.
- **“Run live AI breach (demo)”** / `POST /api/campaign/live-demo` — the real governed
  **agent** drives the full pipeline against the demo under a loopback-scoped signed
  identity (needs a backend; see `docs/DEMO-TARGET.md` + `docs/AGENT-GUIDE.md`).

The service (`server.mjs`) serves the live app at `/` and exposes:
`GET /api/state` · `GET /api/events` (SSE) · `GET /api/identity` ·
`GET /api/live/readiness` · `POST /api/campaign` · `POST /api/campaign/live-demo` ·
`POST /api/breach-demo` · `GET /api/query?q=…` (NL surface query) ·
`POST /api/approve` (real HITL over HTTP) · `POST /api/opsec/cleanup` ·
`POST /api/message` · `GET /api/report` · `GET /api/remediation` ·
`GET /assets/emblem.png`. Kimi's mockup lives at `/console`.

**Running the AI brain (Kimi K3 / any model):** `docs/AGENT-GUIDE.md` is the operating
manual the agent reads — the mission, the phase pipeline + the exact JSON output
contract per phase, the toolset, the governance rules (clearance informs, the hook
authorizes, denials are final), OPSEC, and the boundary. A concise version is injected
into every live run so the model always knows what it's doing.

Demo mode uses the mock agent (no API key). Live mode auto-selects a backend: the
**Claude CLI** (`claude -p`) when present — governed by the same hook, running host-side
so it reaches the local demo — otherwise `runGovernedAgent` (Kimi K3 + container).
`GET /api/live/readiness` reports which backend is active and what's missing. Either
way every tool call flows through the Enclave's govern→classify→Cedar→audit seam.

## The hunt loop + Ops Console (1-click, 24/7)

`tools/huntloop.mjs` is the autonomous bounty-hunt engine; the **VARVEL Ops
Console** (the dark section of `../spark-code/spark-menu.exe`) is its 1-click
front end (`../spark-code/spark_code/opsmenu.py` + `menu.py`).

**The 1-click flow.** START HUNT opens/verifies the SSH tunnel (health-check
`127.0.0.1:8080/health`), shows the lane state ("lane down / training" is a
first-class state, never an error — and the console never starts the lane
while the GPU is training), exports `VARVEL_BRAIN_PROVIDER=openai-compatible`
+ `VARVEL_BRAIN_BASE_URL=…:8080/v1` + `VARVEL_BRAIN_MODEL`, then spawns the
loop as a tracked child and streams `events.jsonl` into the stage board.
STOP HUNT reverses cleanly: a `STOP` file for a graceful stage-boundary exit,
then a cmdline-checked `taskkill /T` only if the grace expires (kills happen
ONLY when the pid's command line still says huntloop — no orphans, no
pid-reuse murders). Closing the console stops the hunt first.

**What the loop does per opportunity** (crash-resumable via
`data/huntloop/state.json`; a persisted pending queue means a crash between
the watch scan and an opportunity's end loses nothing):

```
h1watch diff → program intake → scope-check → recon (the brain) → testing
→ VM-verification (replay) → evidence → report → ledger → cleanup → sleep → repeat
```

- **watch** — `tools/h1watch.mjs` diff of the H1 directory + structured
  scopes (fixture offline, or live with the `VARVEL_H1_TOKEN` env NAME).
  **All external traffic rides the ghost chain** (`tools/ghostfetch.mjs` — the
  zero-dep audited SOCKS5 transport; chain from `VARVEL_GHOST_CHAIN` or
  `settings.json ghost.chain`, local targets stay direct): a configured chain
  that is down means the loop REFUSES to start (`ghost-chain-down`, exit 2) —
  fail closed, never a direct fall-back. Long stages heartbeat, every cycle
  ends with a summary event, and a stage watchdog fails stalls loudly (the
  2026-09-09 25-minute silent-wedge lesson: the old h1Get timeout covered only
  the request phase; a headers-then-silence body parked forever).
- **intake / scope-check** — `tools/program.mjs` normalizes the scope
  (out-of-scope ALWAYS wins, recorded); `engine/bountyline.mjs`'s
  `deriveAutomation` gates: a policy-prohibited program is refused loudly.
- **recon** — the brain (the local lane, via `engine/brain-provider.mjs`
  `callOpenAI` — reused, never reimplemented) proposes candidate findings as
  STRICT JSON with `check`/`expect`/`cleanup`/`verifyClean` snippets.
  Unparseable output is ZERO findings, loudly — nothing is invented. An
  unreachable brain is a first-class "waiting" state, not a crash.
- **testing / VM-verification** — the check runs in the isolation sandbox
  (`poc/isolation` providers: docker `--network none --read-only
  --cap-drop ALL` when the daemon is up, else the local-process dev tier,
  NAMED as such). Brain-drafted checks SKIP loudly on the dev tier (no
  kernel isolation, no untrusted code). "VM active" on the board is the
  sandbox really running.
- **The anti-hallucination gate** — a finding reaches **verified ONLY after
  a replay-verification passes**: the same check re-runs in a FRESH sandbox
  and must print its expected marker. The board shows verified vs unverified
  counts; unverified findings get NO report (the ledger still records them,
  honestly).
- **report / ledger** — verified findings are drafted by
  `tools/bountyreport.mjs` into `data/huntloop/outbox/`; every finding lands
  a line in `data/huntloop/findings.jsonl` with its verdict.
- **cleanup** — each finding's cleanup snippet runs, then a verify snippet
  must print CLEAN. **"clean ✓" is stamped only on a verified no-residue
  check**; residue is named `residue-found`, never hidden.

**THE NEVER-SUBMITS GUARANTEE (absolute).** There is no network submission
code path in `tools/huntloop.mjs` at all — no fetch, no http, no platform
API, not behind a flag (`test/huntloop.test.mjs` pins this with a static
scan, the same doctrine as `test/bountyline.test.mjs`). The loop's only
remote conversation is the LOCAL brain endpoint. Reports wait in
`data/huntloop/outbox/` for the operator's hand; the send click is always
the human's.

**The proof model.** Each finding gets an evidence bundle under
`data/huntloop/evidence/<opportunity>/<finding>/`:
- `replay-transcript.txt` — the timestamped full replay transcript (test +
  replay stdout/stderr, the verdict, the cleanup verify). **This is the
  "video proof" that shipped on this box** — `asciinema` was NOT present at
  build time, so the loop records `recorder: transcript+hash`; when
  asciinema IS on the box a `replay.cast` is recorded alongside.
- `env.json` — the environment hash bundle: sha256 of the check snippet,
  node/platform/arch, the sandbox provider + tier + what it enforces, the
  target dir, timestamps — proof of WHAT ran WHERE, so a transcript can
  never be passed off as coming from another machine or another snippet.
- `result.json` — `{ verified, expect, matched, stdout }`.

**States the console shows** (all from real files/processes): tunnel up/down,
lane up/down(training)/unknown, brain up/waiting, pipeline
running/paused/stopped, per-stage idle/active/done/failed with last-event
times, counters (seen/tested/verified/unverified/drafted/cleaned), VM
provider + active/idle, the recorder in use, and clean ✓/✗. While the hunt
runs, the console greys out its own chat/CLI quick-launch — **profit-first:
all model capacity to the hunt** — and PAUSE/RESUME parks/resumes the loop
at stage boundaries.

### Brain backends — the Spark lane, or an API key

The loop's brain is any **OpenAI-compatible** endpoint; `engine/brain-provider.mjs`
`resolveBrain` picks it with this precedence:

```
per-request override  →  VARVEL_BRAIN_* env  →  data/settings.json “brain.*”  →  kimi (default)
```

So the Spark lane is one option, not the only one. Anything speaking
`/v1/chat/completions` works: the local lane, a hosted API (OpenAI, DeepSeek,
Moonshot/Kimi, Groq, OpenRouter, Together, …), or your own vLLM on another box.
That matters when the GPU is training, when the lane box is unreachable, or when
you simply want throughput the lane cannot give — **a hunt should never be blocked
on the Spark being free.**

**API-key recipe (CLI launch):**

```bash
export VARVEL_BRAIN_PROVIDER=openai-compatible
export VARVEL_BRAIN_BASE_URL=https://api.deepseek.com/v1      # any OpenAI-compatible base
export VARVEL_BRAIN_MODEL=deepseek-chat
export VARVEL_BRAIN_API_KEY_ENV=VARVEL_BRAIN_KEY              # the NAME of the var holding the key
export VARVEL_BRAIN_KEY=sk-…                                  # the key itself, read at call time
export VARVEL_BRAIN_MAX_TOKENS=16384                          # reasoning lanes truncate mid-JSON below ~16k
export VARVEL_BRAIN_TIMEOUT_MS=120000                         # 0 = off, max 600000

node tools/huntloop.mjs --once        # smoke test: one cycle
export VARVEL_BRAIN_TIMEOUT_MS=          # then run the loop normally
```

**API-key recipe (`data/settings.json`, no environment needed):**

```json
{
  "brain": {
    "provider": "openai-compatible",
    "baseUrl": "https://api.openai.com/v1",
    "model": "gpt-4.1",
    "apiKeyEnv": "OPENAI_API_KEY",
    "timeoutMs": 120000
  }
}
```

`Settings.for(engagement)` is consulted, so a **single engagement can carry its
own brain** (a cheaper model for recon-heavy programs) without changing the
defaults for everything else.

**Token doctrine (do not break it).** Config and ledger record the env var
**NAME** — never the key value. `resolveBrain` returns `apiKeyEnv` only; the key is
read at call time by `brainKey(apiKeyEnv)`; `setRuntimeKey(name, value)` /
`runtimeKeyPresent(name)` exist for keys you do not want in the process
environment at all. A missing key is a named refusal, never a silent unauthenticated
call.

**One honest caveat — the console currently overrides this.** The Ops Console's
START HUNT exports the Spark lane unconditionally (`opsmenu.py` `BRAIN_ENV` +
`env.update(...)`: provider + `…:8080/v1` base URL + model), and **env outranks
settings** in the precedence above. A console-launched hunt therefore ignores a
`brain.*` block in `settings.json`. Until that is changed (it is a small, deliberate
edit in the console rather than a loop change), use one of:

- launch the loop yourself with the env above (the console is only a front end —
  the loop is `tools/huntloop.mjs` and takes the same flags), or
- make the console respect pre-set `VARVEL_BRAIN_*` (skip `env.update` when
  `VARVEL_BRAIN_BASE_URL` is already set) — coordinate before editing `opsmenu.py`.

### Running the local lane (the Qwen brain) — and knowing whether it is good enough

When the lane box is awake the tunnel is `ssh -N -L 8080:127.0.0.1:8080 varvel@gx10-d094.local`
(the Console's START HUNT opens/verifies it). Three checks before trusting it mid-campaign:

```bash
curl -sS http://127.0.0.1:8080/health            # lane answering?
curl -sS http://127.0.0.1:8080/v1/models         # the roster — take the model id from HERE,
                                                 # never from memory (ids drift)
export VARVEL_BRAIN_PROVIDER=openai-compatible
export VARVEL_BRAIN_BASE_URL=http://127.0.0.1:8080/v1
export VARVEL_BRAIN_MODEL=<id from the roster>
export VARVEL_BRAIN_MAX_TOKENS=32768             # reasoning lanes spend reasoning_content
                                                 # BEFORE the text channel; 8192 truncated
                                                 # mid-JSON (the td-bank lesson)
export VARVEL_BRAIN_TIMEOUT_MS=180000
```

**Do not assume the fine-tune is capable — measure it.** The loop's brain contract is
strict (one fenced JSON block; every finding carries four runnable node snippets; evidence
is readable ONLY through the sandbox's `EVIDENCE` object), so the real question is "does it
emit check/expect pairs that survive replay in a fresh sandbox?" — which VARVEL can already
answer:

```bash
node tools/brainharness.mjs run --provider-env --suite all --out .tmp/brain-report.json
node tools/brainharness.mjs run --provider-env --suite honesty     # the suite that matters most
```

That harness scores the brain under the REAL system prompt with gates
(`fidelity / honesty / loop / needle / speed`) and exits 1 on a failed gate — make its
scorecard the brain's admission ticket and record the report path in the run's ledger line.
A reasoning-model lane that is strong at narrow judgment but weak at long-horizon planning
is the expected shape (fine-tuned mid-scale models beat general-purpose baselines on
sub-tasks while losing on planning), which is why the loop should route **planning** to the
strongest available model and keep the local lane for evidence judgment and check authoring
— see `docs/builds/2026-09-18-spark-loop-upgrades.md`.

**Prefer the local lane when the target data is sensitive.** A hosted API means the
gathered evidence bundle (real page content, headers, scope text) leaves the box to
a third party; the Spark lane keeps all of it local. Choose per engagement, and note
which one you chose in the ledger. The evidence/verification gates, the anti-hallucination
replay, and the NEVER-SUBMITS guarantee are identical either way — a cloud brain's
candidates still have to pass replay-verification in the sandbox before a report exists.

**Sanity check the wiring without hunting:**

```bash
node tools/brainharness.mjs --provider-env     # fails loudly if VARVEL_BRAIN_BASE_URL/MODEL are absent
```

**Dry-run (the loop mechanics end-to-end, no lane needed):**

```bash
node tools/huntloop.mjs --fixture test/fixtures/h1watch-scan-1.json --mock-brain --once
# watch→…→cleanup on a deterministic mock opportunity; one finding verifies,
# one policy-prohibited program is gated at scope-check. Proven in
# test/huntloop.test.mjs.
```

**Tomorrow's live-fire checklist** (when the training run finishes):
1. `ssh varvel@gx10-d094.local 'bash ~/engine-switch/lane-models.sh status'`
   shows the lane up; the console's LANE card goes green on Re-check.
2. Bring the ghost egress up (`socks5://10.64.0.1:1080` in
   `varvel/data/settings.json`) and press VERIFY GHOST — the console's gate
   refuses START HUNT until the chain is verified live (dial + exit differs
   from origin + DNS sanity). Mid-hunt it re-checks every ~2 min and PAUSES
   the hunt loud on a drop.
3. Set `VARVEL_H1_TOKEN` (+ `VARVEL_H1_USER`) for the live H1 watch — or feed
   `h1watch scan --emit-intake` outbox files by hand; without a token the
   watch stage fails LOUDLY each cycle (nothing is invented).
4. START HUNT in the console. Confirm the BRAIN card reads up, recon
   produces candidates, and testing shows the VM indicator.
5. First live cycle: review the outbox draft + evidence bundle by hand
   BEFORE anything is filed. The loop never files; you do.
6. Stop: STOP HUNT (graceful). The hunt dir holds events/state/findings/
   evidence/outbox — delete the whole `data/huntloop/` dir to reset.

## Beating the field

- **vs RedAmon:** parity on the campaign loop, Fireteam sub-agents, cross-session
  memory, a 16/20 attack-surface graph, OWASP/MITRE reports — plus native recon
  extras they lack (TLS cert + Shodan favicon hash), a real test suite (they ship
  happy-path only), and the Enclave's cryptographic CIDR-scoped governance vs
  their IP-excluded domain blocklist.
- **vs Cobalt Strike / paid tools:** VARVEL wins on the axes they don't have —
  full autonomy (they're manual), unbypassable governance + audit, attack-surface
  intelligence, reporting, OPSEC hygiene, and code quality — and it *orchestrates*
  best-in-class tools (incl. CS/Sliver/Metasploit) under governance rather than
  reimplementing an implant/C2.

## Boundary

VARVEL builds the **orchestration** and **legitimate authorized offensive tooling**
(recon / scanning / enumeration / vuln-checking). It does **not** build weaponized
exploit payloads, C2/implants, or detection-evasion/anti-forensics — a safety line
held regardless. Authorized-only by construction (signed scope) + the L2 hard floor.

See `../docs/overwatch-design.md` and `../docs/redamon-assessment.md` to go deeper.
