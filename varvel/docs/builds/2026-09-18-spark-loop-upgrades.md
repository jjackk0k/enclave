# BUILD — 24/7 loop upgrades: the local Qwen brain, a validator pass, a planner, and parallelism

Date: 2026-09-18. Author: Buffy session. Status: **§1 IMPLEMENTED 2026-09-18** — the validator
pass lives in `tools/refuter.mjs` (resolveRefuter / refuteFinding / parseValidatorVerdict /
citationHolds), wired into `runOpportunity` behind `--validate` (or `runLoop { validate: true }`):
refute ⇒ PARK + ledger line (`verdict: 'refuted'`, refutation + cited span), hold ⇒ proceeds,
unavailable/unconfigured ⇒ the finding runs UN-REFUTED, loudly on the event stream, never deleted.
The anti-vibe citation gate applies to BOTH transports (API lane and injected validator).
Pinned: `test/huntloop.test.mjs` (6 validator tests + a refuter never-submits pin), 44/44.
Everything below remains **SPEC — not implemented.**
Companion reading: `docs/research/autonomous-pentest-platforms-2026-09-18.md` (where each
item comes from), README §"Brain backends — the Spark lane, or an API key".

> **Coordination note (read first).** `tools/huntloop.mjs` and `test/huntloop.test.mjs`
> were being edited by another agent while this was written (5/29 loop tests failing at
> 2026-09-17 23:43, files rewritten 23:44). Do not start this work without checking
> `git status` and re-running `node --test test/huntloop.test.mjs` on a quiet tree —
> every hook below lands inside that file.

## 0. Does the local Qwen 3.8 27B work as the hunt brain?

**Yes by contract, unknown by measurement.** The loop drives any **OpenAI-compatible**
endpoint (`engine/brain-provider.mjs` `resolveBrain`); the local lane is already the
default shape (`opsmenu.py` exports `VARVEL_BRAIN_PROVIDER=openai-compatible`,
`_BASE_URL=…:8080/v1`, `_MODEL`). What is *not* established is whether the fine-tune can
hold the brain's actual contract, which is demanding:

- it must answer with **one fenced JSON block and nothing else** (`BRAIN_SYSTEM`),
- each finding needs `title`/`sev`/`evidence` + **four node snippets** (`check`, `expect`,
  `cleanup`, `verifyClean`) that run in the `--network none`, read-only sandbox and read
  evidence **only** from the predefined `EVIDENCE` object,
- a check that reads a file path is **dropped at intake** as a contract defect,
- and the finding is worthless unless `check` actually prints `expect` when replayed in a
  *fresh* sandbox.

So the acceptance question is not "is it smart?" but "does it emit runnable check/expect
pairs that survive replay?" — which is measurable.

**Where the fine-tune should be strong vs weak (from the 2026 research):** fine-tuned
mid-scale models win *narrow, well-specified* sub-tasks — xOffense (fine-tuned Qwen3-32B)
hit **79.17%** sub-task completion, beating general-purpose GPT-4 baselines — while
long-horizon planning is where every local model loses (CHECKMATE beat Claude Code's native
agent by >20% by *not* asking the LLM to plan). Expectation to test, not assume: **good as
the evidence judge and check author; weak as the planner.**

### 0.1 Prerequisite — the lane box is currently OFFLINE

Checked 2026-09-18: `tailscale status` → `gx10-d094 … offline, last seen 14h ago`; the SSH
tunnel process exists (`ssh -N -L 8080:127.0.0.1:8080 varvel@gx10-d094.local`) but
`127.0.0.1:8080/health` resets, and `https://gx10-d094.tail55d3b6.ts.net/` does not connect.
Also note `mullvad lan get` → **allow** and this Mullvad build has only `lan get|set`
(no per-range add), so under DAITA the tailnet CGNAT range stays blocked; the tunnel over
`gx10-d094.local` is the path that works when the box is awake.

Nothing can be calibrated until the box is up. **While it is down, use the API-key brain**
(README section) — that is the whole point of that section, and it is the difference
between the loop idling and the loop working.

### 0.2 Calibration protocol (the acceptance gate)

```bash
# 1. the lane must answer its own roster (this is also the loop's mid-hunt model recovery)
curl -sS http://127.0.0.1:8080/v1/models
export VARVEL_BRAIN_PROVIDER=openai-compatible
export VARVEL_BRAIN_BASE_URL=http://127.0.0.1:8080/v1
export VARVEL_BRAIN_MODEL=<id from the roster>
export VARVEL_BRAIN_MAX_TOKENS=32768      # reasoning lanes burn reasoning_content BEFORE
                                          # the text channel; 8192 truncated mid-JSON (td-bank lesson)
export VARVEL_BRAIN_TIMEOUT_MS=180000

# 2. score it under the REAL system prompt, before it is trusted with governed tools
node tools/brainharness.mjs run --provider-env --suite all --out .tmp/qwen38-27b-brain-report.json
node tools/brainharness.mjs run --provider-env --suite honesty    # the suite that matters most here
node tools/brainharness.mjs run --provider-env --suite fidelity   # tool-call fidelity
```

`brainharness` already gates `fidelity / honesty / loop / needle / speed` and exits
`0 = all gates passed, 1 = a gate failed, 2 = usage/config`. **Make its scorecard the
brain's admission ticket**: a model that fails `honesty` may not be trusted mid-engagement,
and the report path should be recorded in the run's ledger entry.

**Publish the number.** Store the scorecard under `data/` and reference it from
`docs/STATE-OF-VARVEL.md`. Today "is our brain good?" is argued; with one number it is
falsifiable — which is exactly the discipline the platform already applies to findings.

### 0.3 Which brain for which job (the split that makes a 27B viable)

| role | model | why |
|---|---|---|
| evidence judge + check author | local Qwen 3.8 27B fine-tune | narrow, well-specified, cheap, local — measurably competitive on sub-tasks |
| planner (ordered plan, no snippets) | strongest available (API key) or a classical planner | planning is where small models fail |
| validator (refute the finding) | **a different model than the author** | self-review is not review |

## 1. Add a validator pass (XBOW's "validators", applied to reasoning)

**Where:** after `parseBrainFindings()` returns `kept`, before the sandbox stage.

**Contract:** one extra call to a *different* brain config whose only job is refutation:

```
SYSTEM: you are the VARVEL validator. You do not propose. You refute.
INPUT:  the candidate finding, its evidence quotes, its check/expect pair, and the raw
        evidence bundle.
OUTPUT: one fenced json block — { "verdict": "hold|refute", "why": "...",
        "contradiction": "<quote from the bundle that the finding misreads, or null>" }
RULES:  default to refute when the evidence does not directly support the claim;
        a finding whose severity depends on an unquoted assumption is refuted;
        refutation must cite the bundle — a vibe refutation is discarded, not obeyed.
```

**Semantics that keep the anti-hallucination doctrine intact:**
- `refute` **parks** the candidate (recorded in the ledger with the refutation text); it is
  never deleted, and it never becomes a report.
- The validator being unavailable leaves the finding **unverified** — never promoted.
- The validator never sees the outbox and has no submission path (NEVER-SUBMITS unaffected).
- Cost control: validate only candidates that passed the intake gate (see the 2026-09-16
  intake work) and cap at one refutation attempt.

**Why it pays:** the expensive failure mode is a plausible finding that wastes a human
triage cycle. A second model with a *refuting* prior is the cheapest filter that exists.

## 2. Split planner from executor (CHECKMATE's lesson)

Today the brain both plans and authors checks in one call, so a weak planner degrades
everything downstream. Proposed:

1. **Plan call** — returns an ordered list of `{ intent, asset, why, stopWhen }` steps. No
   snippets. Small output, easy to validate, and *this* is the call to route to the
   strongest model available.
2. **Deterministic dispatcher** — walks the plan; for each step asks the (cheap, local)
   brain only for that step's `check/expect/cleanup/verifyClean`.
3. Plans are journaled next to the evidence bundle, so a bad plan is reviewable
   independently of a bad check.

Bonus from the same research: for known-shaped work do not ask an LLM to plan at all —
the mechanical lane (CVE pack, takeover, S3-style checks) is already a hard-coded plan and
should stay one.

## 3. Parallel opportunity workers — with GLOBAL pacing

**Why:** XBOW runs thousands of agents; the loop walks one opportunity at a time, and the
h1watch baseline holds 611 programs (53 legally automatable). Throughput, not intelligence,
is the bottleneck.

**Design constraints that must not be broken:**
- **Pacing is a per-program+host budget, shared across workers.** The programs that permit
  automation do so with a stated ceiling (inDrive: 5 rps, 5 threads; others 2–5 rps,
  "throttled", "no more than 100 requests"). N workers must consume that budget from a
  single accounting point, or parallelism becomes a policy violation. This is the
  single most important safety property of the whole feature.
- One ghost chain, one chain-health gate: a chain failure fails the whole run closed
  (`ghost-chain-down`), never a per-worker direct fallback.
- The ledger append must be atomic (`findings.jsonl` is the audit surface).
- Crash-resume must be per-opportunity (`data/huntloop/state.json` keys), so a killed
  worker loses one opportunity, not the queue.
- The console greys out chat during a hunt "profit-first: all model capacity to the hunt" —
  with N workers that assumption breaks; the console needs a worker-count display and the
  model-endpoint concurrency limit should gate the worker count, not the other way round.

Start with `--workers 1` (today's behavior) and make the default explicit, so the
capability ships without silently changing pacing.

## 4. Brain-offline policy (make it explicit, not emergent)

Three states today are honest but implicit. Name them in the ledger:

1. **lane down / training** → hold in `brain-wait` (current behavior: first-class state,
   never an error) — correct, keep it.
2. **operator-declared API-key brain** → allowed, but **fixed for the whole run** and
   recorded (`provider`, base-url host, model id — never the key). Reason: an evidence
   bundle's provenance matters, and a report that silently changed models mid-engagement
   cannot be defended at triage.
3. **mid-hunt model recovery** — the existing `listOpenAIModels()` fallback when only the
   model id is missing is good; keep it, and log that it happened (it already does).

## 5. Retest loop (cheap, additive)

Verified findings are never revisited, so "the vendor fixed it — was our claim right?"
never gets answered. A periodic `--retest` pass that re-runs a verified finding's
`check`/`expect` against the same asset and records the transition
(`still-present | fixed | asset-gone`) costs almost nothing, keeps the ledger current,
and produces the retest evidence programs like (NodeZero sells exactly this).

## Acceptance criteria for this build

- `node --test test/huntloop.test.mjs` green, plus new tests: validator parks on refute;
  validator unavailable ⇒ finding stays unverified; parallel workers never exceed the
  program's declared rps (assert against a mock counter); planner call is used when
  configured and absent otherwise; a model swap mid-run is refused.
- The static NEVER-SUBMITS pin still passes (no fetch, no submission path added).
- `brainharness` scorecard for whatever brain is default, stored and linked from
  `STATE-OF-VARVEL.md`.
- README §"Brain backends" stays accurate — if the console stops forcing `BRAIN_ENV`, update
  the caveat in the same commit.
