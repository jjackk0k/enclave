# VARVEL — the Auto-Remediation PR Loop (roadmap #7)

**Validated finding → verified fix → one-click PR.** VARVEL already proves
vulnerabilities (the validator gate) and ranks their fixes (`engine/remediate.mjs`
triage); this loop closes the last rung — turning a **validated** finding into a
ready-to-merge pull request against the client's own repository. For an enterprise
CISO this is the difference between a PDF of problems and a queue of *proven fixes,
each with its reproduction probe now failing, one click from merged*. That is the
platform's irresistible shape: every PR carries its own evidence, its own validation
proof, and its own measured verification — the client reviews and merges; VARVEL
never merges anything.

Everything here is **governed, default-off, and human-approved**. The loop produces a
local branch/patch and a PR **draft** (title/body/diff preview). A PR is **never**
opened autonomously: the operator's explicit `remediate open-pr <id>` is the only
push/open path in the platform.

## The lifecycle

A remediation record (`{engagement}-*.remediations.json` under the VARVEL data dir,
the store.mjs per-engagement discipline):

```
{ id: 'rem-xxxxxxxx', engagement, findingRef,
  status: 'draft' | 'patched' | 'pr-opened' | 'merged' | 'rejected',
  patch, diff, diffstat, files, verify, verifyResult, pr, pushed,
  createdAt, updatedAt, provenance, audit[] }
```

The rail is forward-only and enforced on every transition:

```
draft ──► patched ──► pr-opened ──► merged
   │          │            │
   └──────────┴────►───────┴──► rejected      (merged/rejected are terminal)
```

- `draft` — intake. The **eligibility gate fires here**: only findings in the
  validator state **`validated`** may enter. Claimed-unvalidated, `refuted`, and
  `untestable` findings are refused as data (refused = nothing stored). A validated
  finding past its freshness window (`validator.staleDays`) is still eligible —
  `stale` is a rendering of validated — but the provenance flags it and the PR draft
  advises revalidation.
- `patched` — the patch was materialized against a local checkout and the record's
  declared probe was **run and read** (below). `pr-opened` is reachable only from
  here: no push without a materialized patch.
- `pr-opened` — the operator opened the PR. Re-running `open-pr` is idempotent
  (never re-pushes, never double-opens).
- `merged` / `rejected` — the client's acts, recorded by the operator
  (`remediate mark <id> merged|rejected`). **The merge is always the client's act.**

Every transition and every leg appends to `record.audit` — draft → patch → verify →
push → open is replayable from the record alone.

## The gates (all default OFF)

Three settings keys (`settings set …`), enforced in order in `tools/rempr.mjs`, each
refusal data (`{ ok:false, gate, reason }`), each landing **before any spawn or
network call**:

| key | default | what it gates |
|---|---|---|
| `remediate.prEnabled` | **false** | the whole loop: `draft`, `verify`, `open-pr` all refuse until the engagement opts in |
| `remediate.remoteAllow` | **false** | the REMOTE leg only (`open-pr`): git push + PR open. A **second, separate** gate — draft/verify stay local-only even with the loop on |
| `remediate.ghToken` | `''` (secret-class) | the burner PAT for the push + REST legs (below) |

Plus the lifecycle gate: only a **`patched`** record (materialized + measured) can be
pushed/opened.

## HITL — the wall that makes it approvable

`openRemediationPr` has exactly one call site in the platform: the operator's
explicit `remediate open-pr <id>` CLI action (asserted in tests). `list`, `draft`,
and `verify` make **zero** network calls and spawn nothing but local git/probe
processes — `engine/remediate.mjs` imports no network stack at all (also asserted).
Nothing schedules, watches, or retries the push leg. If the human never runs
`open-pr`, the loop's entire output is local: records, diffs, and PR drafts.

## Patch materialization + MEASURED verify

`remediate verify <id> --repo <path>` against an **operator-supplied local checkout**
(VARVEL never clones autonomously):

1. **Apply** — `git apply` for a stored unified diff; full-file writes for a patched
   file set (every path validated inside the checkout *before any write* — escape =
   refusal).
2. **Capture** — the unified diff, diffstat, and patched contents are read back
   **from git itself** (`git diff` after intent-to-add), not restated from the intake.
   An empty result = `patch-failed` ("nothing to PR").
3. **Verify** — the record's declared probe runs against the **patched** tree:
   `verify: { cmd, expect: 'nonzero' (default) | 'zero' }`. The default models the
   finding's *reproduction* probe: it should **fail** once the fix lands. Verdicts:
   - `patch-works` — the probe met its expectation (exit code read, not assumed);
   - `patch-fails` — it did not (the fix does not close the finding — said plainly);
   - `undeclared` — no probe was declared, so patch-works is **not claimed**.
4. **Revert** — the working tree is restored exactly as found (reverse-apply / a
   rollback journal). The checkout is a measurement chamber, never a side effect.

The verdict rides the PR body verbatim — including `patch-fails` and `undeclared`.
The operator may still open such a PR (HITL is the human's prerogative); the report
and the PR body both carry the loud warning.

## The PR leg (`tools/rempr.mjs`)

On `open-pr`, against the local checkout:

1. `git checkout -b varvel/<id>` (retry-safe: an existing branch is checked out),
2. `git apply` the materialized diff, `git add` the touched paths,
3. commit with a **transient identity** (`-c user.name='VARVEL Remediation'` — the
   commit is attributable to the loop, impersonating no one; house-style message
   carrying finding ref + measured verdict),
4. push to `https://github.com/<owner>/<repo>.git` — the **token is never in the
   URL**, never in argv, never persisted to `.git/config`. It rides the push child's
   **environment** as a transient git config
   (`GIT_CONFIG_COUNT/KEY_0/VALUE_0 = http.extraHeader: Authorization: Bearer …`,
   git ≥ 2.31) with `GIT_TERMINAL_PROMPT=0` (fail-closed, never an interactive
   prompt). All git output is defensively **scrubbed** (token → `<redacted>`) before
   it can reach a report or an audit entry — tested with a poisoned-stderr case.
5. `POST /repos/:owner/:repo/pulls` (the loop's only api.github.com call) with the
   draft title/body. 401/403/404/422 map to honest, token-free operator messages.

**Idempotent + resumable:** a `pr-opened` record returns its PR without touching
git or the API. If the PR-open REST call fails after a good push, the push is
journaled (`record.pushed`) and a re-run resumes at the REST leg — no re-push.

The PR body is built for a client reviewer: the finding + evidence, the **validation
proof** (validator state + oracle line, staleness flagged), the **fix verification**
verdict (measured, or honestly undeclared), the **diffstat**, and a **rollback**
note (closing the PR abandons the fix with zero residue; after merge a single
`git revert` restores the prior state).

## Burner token doctrine (same as ghc2)

`remediate.ghToken` is an **operator-supplied burner account PAT** (repo scope),
never the operator's real account, never committed, never logged. It lives in the
secret-class settings key (the settings API/console render presence only,
`<redacted:set>`). Reports and audit entries carry `tokenMeta()` — **presence +
class** (fine-grained vs classic), never the value, never a slice of it. The value
leaves the process exactly twice: in the push child's environment and in the REST
`Authorization` header. The negative scan (token in no record, report, or audit
entry) is a test, not a hope.

## Ghost threading — the decision, and why

Remediation PR traffic is **overt client work** — the client's own repo, the client's
reviewers, an attributable fix. The ghost chain therefore does **not** apply by
default: ghost off → direct, labeled honestly (`overt client work`). But the posture
is identical to ghc2 the moment ghost is armed — some engagements attribute nothing,
ever:

- loopback/private API base → direct, always (lab traffic never leaves the lab; also
  the hermetic-test path);
- ghost on + chain → the REST leg rides `ghost.agents()`;
- ghost on, no chain → direct, labeled best-effort;
- ghost **required** + missing/unverified chain to a public API base → **REFUSED,
  fail-closed** — the operator egress never touches the SaaS remote directly.

## Operator flow

```bash
# opt in (both gates, plus the burner token) — the console Settings page, or:
curl -X POST localhost:8971/api/settings -H 'content-type: application/json' \
  -d '{"engagement":"<eng>","key":"remediate.prEnabled","value":true}'
# …same for remediate.remoteAllow (true) and remediate.ghToken ("<burner-pat>" —
# secret-class: the API echoes `<redacted:set>`, never the value)

# draft a remediation for a VALIDATED finding (patch as a unified diff and/or files)
node tools/cli.mjs remediate draft F-117 --engagement <eng> \
  --file app.js:/path/to/fixed-app.js --verify 'node probe.js'   # probe: nonzero = no longer reproduces

# materialize + MEASURE against a local checkout (tree is reverted after)
node tools/cli.mjs remediate verify rem-1a2b3c4d --repo /path/to/client-checkout

# review the record, then — and only then — open the PR (the human act)
node tools/cli.mjs remediate open-pr rem-1a2b3c4d --repo /path/to/client-checkout \
  --gh client-org/client-repo [--base main] [--branch varvel/rem-1a2b3c4d]

node tools/cli.mjs remediate list --engagement <eng>
node tools/cli.mjs remediate mark rem-1a2b3c4d merged     # or rejected — the client's act, recorded
```

## Honest limits (this wave)

- **No autonomous clone.** The operator supplies the checkout path; VARVEL never
  clones, and never will without an explicit governance wave.
- **Single-repo.** One record → one checkout → one PR. Multi-repo fixes are N records.
- **The merge is the client's act.** VARVEL opens drafts of record; it never merges,
  never approves, never force-pushes.
- **Verify is only as good as the declared probe.** The loop measures what the record
  declares; an `undeclared` record's PR says patch-works is not claimed. Writing the
  probe is the operator's craft (the finding's own reproduction is the canonical one).
- **The push targets a fork/branch the burner can reach** (`--gh owner/repo`); a 404
  means the burner can't see it — said so, not retried silently.
- The branch commits as `VARVEL Remediation` — attributable automation, never
  impersonating the operator or the client.
- GitHub's authenticated REST budget (~5,000 req/hr per token) is a non-issue here:
  the loop spends exactly **one** API call per PR.

## Tests

`test/rempr.test.mjs` (hermetic — artifacts under `varvel/.tmp/`, the GitHub API
mocked on loopback, the push leg on an injected spawn spy, real git against a tiny
in-test fixture repo): the eligibility gate, the lifecycle rail, draft shape,
apply+verify with measured verdicts and a clean-tree assertion, the HITL wall
(gates refuse before any spawn; one `openRemediationPr` call site), token-secrecy
negative scans (incl. a poisoned-stderr scrub), PR-body completeness, idempotent
open-pr, push-resume, error mapping, the ghost resolver, and the CLI surface
end-to-end.
