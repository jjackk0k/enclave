# Winner copyables build — 2026-08-31

Three mechanisms the verified earners on the platform use and we lacked, built as
first-class VARVEL primitives: **(1) a real-browser session broker** (sessions
harvested from the operator's own browser runs, canary-health-checked, recovered
refresh→relogin, never handed out dead), **(2) replayable-evidence binding**
(every filed authz differential gets a `replay.json` + `replay.sh` bundle that
re-asserts the capture through the ghost chain), and **(3) coverage-completion
gates** (a campaign reports DONE-CLEAN only when every recon-harvested endpoint
was actually exercised by a testing lane). Tests: `test/sessionbroker.test.mjs`
(15), `test/replaybind.test.mjs` (9), `test/coverage-gate.test.mjs` (8), plus the
wiring pin in `test/bountyline.test.mjs` (12).

## Layout

- **`tools/sessionbroker.mjs`** — Tool 1. Managed-session store at
  `.tmp/sessions/<program>-<label>.json` (env override `VARVEL_SESSIONS_DIR`),
  canary death-detection, refresh→relogin recovery ladder, legacy-journal
  migration, and a CLI (`list | migrate | check <p> <l> | print-cookie <p> <l>`).
- **`tools/replaybind.mjs`** — Tool 2. Pure planning core (`planFromPairs`,
  `planFromMatrix`), bundle emission (`emitBundle`), and the re-run executor
  (`runPlan`) that asserts each leg still REPRODUCES its capture.
- **`engine/coverage.mjs`** — Tool 3's PURE core (zero network/fs). Placed in
  `engine/` per the `engine/novelcore.mjs` precedent (the manager's note said
  `tools/coverage.mjs`; the ledger is pure logic and the novelty-gate build
  established that pure cores live in `engine/`).
- **Wiring** — `engine/campaign.mjs` (broker seam + coverage lanes + gate),
  `tools/authzsweep.mjs` (`sessionRef` passthrough), `engine/report.mjs` +
  `server.mjs` (coverage section + state), `engine/bountyline.mjs` (replay
  bundle emission on draft, checklist line on queue).

## Tool 1 — session broker

Rules:

1. **A session is `live` ONLY on an expected canary status.** Transport failure
   is `unknown` — never dead, never alive, and an unknown session is never
   handed out as live. The canary is a harvested authenticated-read endpoint
   (e.g. zomato's `get_user_notifications.php?…&user_id=447585412`, harvested
   from the `.tmp/zom-harvest-<side>.json` XHR journals — routes are never
   invented) with `expectStatus` and a `denyBodyRe` (e.g. `Unauthorized request`).
2. **Recovery ladder: refresh → relogin.** A dead canary first tries the
   entry's refresh recipe. Frontegg entries are refresh-only: POST
   `https://frontegg-prod.au.frontegg.com/frontegg/identity/resources/auth/v1/user/token/refresh`
   with the `fe_refresh_*` cookie, 24 h TTL, `set-cookie` rotation merged into
   the stored cookie jar. A script relogin fires ONLY under `allowSpawn: true`
   (off by default — no headless browser unless the operator opts in).
3. **Secrets stay on disk, masked in `listSessions`.** `print-cookie` is the
   only exfil path, and it exists so replay bundles can resolve `CRED_<REF>`
   variables at replay time instead of embedding credentials.
4. **Target HTTP rides the ghost chain** when the campaign passes its bridged
   agents (`defaultProbe({ agents, extraHeaders })`) with the
   `X-HackerOne: varvel` attestation header — fail-closed like every other tool.

CLI:

```bash
node tools/sessionbroker.mjs migrate            # harvest .tmp/zom-harvest-*.json + fe-login-*-result.json
node tools/sessionbroker.mjs list               # masked inventory
node tools/sessionbroker.mjs check zomato a     # exit 0 live / 2 dead-or-unknown (rides ghost socks5)
node tools/sessionbroker.mjs print-cookie zomato a
```

## Tool 2 — replayable-evidence binding

- `planFromPairs(bundle)` consumes the authzsweep evidence-bundle shape
  (`finding.authz.bundle.pairs`); `planFromMatrix(matrix)` consumes today's
  `.tmp/*matrix.json` captures. Routes are NEVER invented — matrix keys without
  caller-supplied paths are skipped and NAMED in the plan.
- `emitBundle(plan, dir)` writes `replay.json` + `replay.sh`. The shell script
  rides `socks5h://10.64.0.1:1080` and the attestation header; credentials are
  redacted-but-referenced as `CRED_<REF>` variables resolved via
  `node tools/sessionbroker.mjs print-cookie …`, so the bundle carries no
  secrets and still replays.
- `runPlan(plan)` re-fires each leg and asserts it REPRODUCES its capture
  (status equal + body marker). Verdicts: `REPRODUCED` / `FIXED-OR-CHANGED` /
  `INCOMPLETE`. Unresolved credentials SKIP the leg — never guessed.
- Wiring: `bountyline.draftReports` emits a bundle under
  `programs/<id>/reports/replay/<nn>-<slug>/` whenever a finding carries
  `authz.bundle.pairs`, appends a `## Replay bundle` section to the draft, and
  `queueProgram` adds a replay step to the submission checklist only when the
  bundle exists. The submission-side static scan (no `fetch(`/`node:https`/
  `XMLHttpRequest`/`net.connect`/`.submit(` in bountyline) still passes.

## Tool 3 — coverage-completion gates

- `CoverageLedger` (pure core, `engine/coverage.mjs`): `queue` / `mark` /
  `status` / `gate`. Every endpoint recon puts on the surface is QUEUED; the
  exploit lanes MARK what they actually exercised — authz harvest + replay
  (`oracle`, candidates marked only when `r.pairs.length > 0` — inconclusive
  stays untested), OOB pass (`oob`), browser agent (`browseragent`), AI surface
  (`aisurface`, plus `/.well-known/ai-plugin.json` queued).
- `run()` computes the gate before `campaign.done`: `NO-SURFACE-QUEUED`,
  `DONE-CLEAN`, or `COVERAGE-INCOMPLETE` with the remaining queue itemized.
  Orphan marks (lane marked something recon never queued) are kept VISIBLE;
  overflow is counted. The verdict lands in the activity log
  (`coverage.gate`), the surface note, `getState().coverage` /
  `.completion`, and the rendered report's
  `## Coverage — testing-completeness ledger` section.

## Wiring points (for the next builder)

- `new Campaign({ sessionBroker: { dir?, allowSpawn?, getLiveSessionImpl? } })`
  — the broker seam. `getLiveSessionImpl` is the hermetic test seam; production
  uses `getLiveSession` with `defaultProbe({ agents: this._bridgedAgents(), extraHeaders })`.
- authz accounts accept `sessionRef: 'program:label'` instead of a literal
  cookie (`sanitizeAuthzCfg` passes it through; the provisioning loop resolves
  it). A dead/unverifiable broker session fails the sweep CLOSED with
  `authz.session-dead` on the activity record — no stale credential ever
  reaches the wire.
- `renderReport(md, { coverage })` and the server route pass
  `campaign.coverage.status() + campaign.coverageVerdict`.

## Honest limitations

- **Broker:** no automatic browser spawn by default (`allowSpawn` is opt-in);
  canary harvest quality depends on the captured XHR journals; the store is
  single-user local JSON (no locking across concurrent campaigns);
  `unknown` canary state (e.g. ghost chain down) blocks handout — by design,
  but it means a dead proxy reads as "unverifiable", not "live".
- **Replaybind:** matrix captures need caller-supplied paths (keys without
  routes are skipped, not guessed); `runPlan` asserts a leg REPRODUCES its
  capture — it does not re-prove impact (a WAF rule change that keeps status
  codes identical reads as REPRODUCED); `replay.sh` assumes `curl` with
  socks5h support on the replayer's box.
- **Coverage:** exercise ≠ safety — a marked lane proves the endpoint was
  TESTED, not that it is clean; mock/manual lanes mark only what they touch;
  the ledger is in-memory per campaign run (no cross-run persistence, so a
  resumed campaign starts a fresh queue).
