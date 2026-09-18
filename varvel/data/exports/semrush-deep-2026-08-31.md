# semrush deep pass — 2026-08-31 (sess-1021, port 8992)

**Verdict: honest CLEAN.** No draftable finding. Nothing crossed the captured-bytes + working-differential + controls bar.

## Policy constraints (h1sync snapshot 2026-08-29, no drift)

- `X-HackerOne: varvel` required on all test traffic — enforced everywhere; **tooling fix**: `tools/jsminer.mjs` previously sent no attestation header — patched (`extraHeaders`) and threaded through `engine/campaign.mjs`; `test/jsminer.test.mjs` 9/9 and `test/campaign-tools.test.mjs` 11/11 green after the change.
- Accounts "whenever possible" via `@wearehackerone.com` (fraud-team friendliness — not a hard gate); automated scans risk account/IP block → human cadence (1 concurrency, 2.5s±1.5s) throughout.
- Not accepted: scanner output without manual PoC, missing headers / cookie flags / descriptive errors, CSRF w/o impact, TLS best-practice w/o PoC, brute force, self-XSS.
- Out of scope: `advocates.semrush.com`, `email.semrush.com`. WAF block = error 445 (never seen).

## Lane A — jsminer deep sweep (jsminerVerify ON)

25 hosts swept (2 passes; pass 2 widened scope to domain suffixes so `static.semrush.com` bundles rode in-scope). 22 reachable; `app.semrush.com`, `app.staging-a.prowly.com`, `api.staging-b.prowly.com` unreachable via ghost.

| Host | Scripts mined | Endpoints | Secrets |
|---|---|---|---|
| www.semrush.com (incl. /login/) | 23 + 22 | 109 + 35 | 1 candidate |
| ai-visibility-index.semrush.com | 16 (Next.js chunks) | 28 | 0 |
| portal.myinsights.io | 1 | 9 | 0 |

- **Sourcemaps: ZERO advertised** in any mined bundle — nothing reconstructable, no .map claim made.
- **Secrets: 1 candidate** — generic high-entropy 32-hex (same value on www + login HTML, entropy 3.64, page-embedded token shape). No live-use verifier exists for the type → stays `candidate`, **not a finding**.
- Oracle probes on harvested endpoints (all with garbage-path differential):
  - `portal.myinsights.io/graphql` → 400 `INTROSPECTION_DISABLED` (Apollo prod hardening — expected, clean)
  - `portal.myinsights.io/api/v1/report`, `/api/v1/portal` → 404 ≡ garbage 404 (no missing-auth signal)
  - `www.semrush.com/back-wt/v1/billing_subscription` → 401 vs garbage 404 (properly gated)
  - `/search-bar/api/search/suggestions` → 400 param-validation; `/smrwv/v1/webvitals` → 405

**Lane A verdict: CLEAN.**

## Lane B — account provisioning: BLOCKED

Two signup attempts (mail.tm inboxes `varvel-semrush-a-c3zu@emalupe.com`, `varvel-semrush-b-io3d@emalupe.com`), humanized typing, cookie-consent first. **Both hit a reCAPTCHA image challenge** ("Select all images with bridges") after "Create account" — visual proof `.tmp/sem-signup-a-3-after-submit.png`. No verification mail ever arrived.

- Honesty correction: the first run's script counted anonymous `PHPSESSID`/`SSO-JWT`/`GCLB` cookies as a session — **downgraded to ok:false** (`.tmp/semrush-acct-a.json` carries the correction note). The patched script only counts a session when `/accounts/profile/` loads authenticated with our email.
- 0 accounts, 0 broker registrations, **the cross-account IDOR oracle never ran** (`authzSweep: null` in the campaign record).
- Unblock path: Jack signs up via his `@wearehackerone.com` alias (the policy's fraud-whitelisted path) or solves the captcha interactively once; then `semrush-signup.mjs` + `sessionbroker.mjs` finish the pair and the 4-role oracle runs against the 538-endpoint www.semrush.com surface, myinsights `/api/v1/*`, and the two GraphQL surfaces.

## Lane C — campaign (:8992, sess-1021)

- Targets: www.semrush.com, mcp.semrush.com, portal.myinsights.io, ai-search.semrush.com. Terminal `done`; **COVERAGE-INCOMPLETE (509 queued / 10 tested — stated, not hidden)**.
- Gates: exploit + postex countersigned via `POST /api/approve` after ≥60s parks (owner-delegated).
- targetScore: www.semrush.com 100, portal.myinsights.io 77, mcp.semrush.com 74, ai-search.semrush.com 57.
- Hunting lanes: jsminer 4 bases / 0 secrets; DOM-XSS canary 6 pages / 7 params / **0 proven**; aisurface 1 MCP-shaped surface (`/mcp/` on mcp.semrush.com) / 1 cross-session probe / **0 proven**; **OOB disarmed** — trycloudflare edge :7844 unreachable on both direct egress AND ghost (restart attempted; QUIC+h2 prechecks hard-fail). Loopback seam refused as fake-signal.
- **29 engine notes, all hard-blocked classes** (TLS wildcard ×4, cookie flags ×8, missing headers ×8, version disclosure ×5, misc ×4), 0 oracle-validated → **none drafted, novelty gate moot**.
- Governance: 2 in-flight holds (`Write` enclave-denied) — nothing landed on target. Noise 376/300 (exhausted, 6 HITL-authorized).

## Findings

**None.** No replaybind bundle, no draft, no novelty-gate run — there was nothing real to bind, draft, or check.

## Blockers carried forward

1. reCAPTCHA on signup → no authenticated lanes (the highest-value lane for this estate).
2. OOB tunnel network-dead (edge :7844 blocked both paths) → blind classes (SSRF/SSTI/XXE/blind-XSS) untestable this run.
3. `app.semrush.com` unreachable via ghost — the core app host was not swept; worth a manual check next run.

_Export pair: `data/exports/semrush-deep-2026-08-31.json` + this file. All primary artifacts under `.tmp/` (see JSON `artifacts`)._
