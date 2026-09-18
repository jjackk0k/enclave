# STATE OF VARVEL — operational handoff

**Written:** 2026-09-01 (after the 2026-08-31 ~23:55 captcha-rail checkpoint)
**Purpose:** cold-start document. A future agent with ZERO context should be able to
operate varvel from this file alone. Primary sources: `C:\Users\Jack\Downloads\varvel-kimi\KIMI-NOTES.md`
(milestones log, read it for anything this file summarizes), `docs/builds/*.md`,
`research/2026-08-31-ai-hunter-practitioner-brief.md`. Project root:
`C:\Users\Jack\Downloads\enclave\varvel`.

VARVEL is an authorized HackerOne bug-bounty hunting platform (Jack's H1 researcher
handle: **varvel**). It is an OFFENSIVE red-team platform first; governance exists to
make the offense trustworthy. The standing bar is nation-state-grade quality with a
hard honesty contract. Absolute boundaries: signed scope before any contact, PreToolUse
hook, HITL gates, tamper-evident audit, no anti-forensics, no EDR-evasion internals.

---

## 1. Operating rules (HARD — never relax)

- **Node PATH:** every Git Bash call starts in `C:\WINDOWS\System32`. Always
  `export PATH="/c/Program Files/nodejs:$PATH"` and `cd /c/Users/Jack/Downloads/enclave/varvel`
  first, every call.
- **Tests:** NEVER run full `npm test` (`node --test test/` FAILS by design — the
  package.json `test` script is a pinned list). Run individual files only:
  `node --test test/<file>.test.mjs`. Full-suite green is a historical data point, not
  a routine check.
- **Data dirs:** never edit `.data/` or `data/` contents. The ONLY permitted write is
  NEW files into `data/exports/`. `.tmp/` = deliverables, NEVER bulk-clean. No git
  mutations.
- **Target traffic:** ALL target contact rides the ghost chain
  `socks5://10.64.0.1:1080` with header `X-HackerOne: varvel` (attestation), fail-closed
  (no chain = no request, ever). Ghost exit pinned per engagement (e.g.
  `expectExit 135.136.21.33`, pinStrict). VPN (Mullvad) ON for H1/target contact;
  wp.org / localhost / patchstack / wordfence forms are fine without.
- **Hidden launches:** servers/tunnels launch via
  `wscript C:\Users\Jack\Downloads\enclave\run-hidden.vbs "<absolute .bat path>"`.
  ABSOLUTE bat paths only — relative paths silently no-op. Never spawn visible console
  windows. (Restart gotcha: taskkill via python subprocess needs `/PID` in list form;
  `//PID` only works in interactive Git Bash.)
- **Honesty contract:** a bare 200 is NOT proof; every differential needs a
  garbage-path control (and unauth control where applicable); scanner "confirmed" =
  scanner confidence, NOT a validator verdict; an honest CLEAN is an acceptable,
  reportable outcome; fabrication is NEVER acceptable (Wordfence permabans at 4
  hallucinated reports; the GiveWP/Patchstack rejection lesson is law at 4 layers —
  scopecheck `--impact significant` is FILE-or-drop). Soft-404/catch-all artifacts must
  be baselined before any content-discovery claim; evidence strings must bind to
  captured bytes, never model prose.
- **Submission:** Jack's hand clicks Submit. NEVER auto-submit. The pipeline fills
  everything (submit-drive / Firefox); the AI stops at the filled form.
- **HITL gate countersign (owner-delegated 2026-08-30):** when a campaign gate parks,
  the agent may self-countersign via `POST /api/approve` after the gate has been parked
  ≥60 seconds (Jack: "you authorise it", 15:59 UTC+1 2026-08-30; 1-min rule set 14:41).
  `pendingApproval` is NOT exposed by current server builds — detect parked gates from
  the activity feed (`.tmp/monitor-batch2.py` pattern). Visa-class supervised programs
  are EXCLUDED — those are Jack at the keys, always.
- **Silent freezing is a BANNED failure mode.** If varvel looks quiet >10 min, check
  `/api/state` stall field first; cross-check the enforcement-seam ledger before
  believing a stall flag (known false positives when a busy agent's tool calls don't
  hit the campaign feed).
- AI-usage question on H1 forms = **NO** for now (Jack's call; don't re-litigate).

---

## 2. Tool inventory

All tools are zero-dep ES modules under `tools/` with pinned `node:test` suites under
`test/`; pure cores live in `engine/` per the novelcore precedent. Every governed tool:
ghost-chain agents, pacer before every request, scope/path-prefix fail-closed
confinement, budget caps with honest `budget.exhausted` logs, never throws.

- **acctfactory** (`tools/acctfactory.mjs`) — the account factory. Declarative recipe
  (`signupUrl`, selector hints, `activation: email-code|email-link`, `mfa: totp`,
  `sessionCapture`) drives mail.tm inbox (`MailTmClient`; CLI rides
  `curlJsonTransport` because mail.tm's edge throttles Node's TLS fingerprint on
  `POST /accounts`) → signup → activation → RFC6238 TOTP enrollment → session capture.
  `provisionAccount()` is `ok:true` only on ≥1 cookie or bearer captured.
  `mintRoleMatrix()` → owner/member/lowpriv/unauth-control; `toAuthzAccounts()` emits
  exactly what the authz oracle consumes. Tests: `test/acctfactory.test.mjs` (16).
  Doc: `docs/builds/2026-08-30-hunting-tools.md`.
- **sessionbroker** (`tools/sessionbroker.mjs`) — real-browser managed-session store at
  `.tmp/sessions/<program>-<label>.json`. A session is `live` ONLY on an expected
  canary status (transport failure = `unknown`, never handed out as live). Recovery
  ladder refresh→relogin (script relogin only under `allowSpawn:true`, off by default).
  Secrets on disk, masked in list; `print-cookie` is the only exfil path (replay
  bundles resolve `CRED_<REF>` at replay time). CLI: `list | migrate | check <p> <l> |
  print-cookie <p> <l>`. Tests: 15. Doc: `docs/builds/2026-08-31-winner-copyables.md`.
- **captchaassist** (`tools/captchaassist.mjs`) — human-in-the-loop captcha rail.
  Detects reCAPTCHA/hCaptcha/Cloudflare by signature, pauses the headed Firefox,
  writes `.tmp/captcha-needed-<program>.json`, polls for a verified solve (challenge
  gone AND one corroborating signal: url-change / success-marker / submit-re-enabled),
  resumes, verifies auth, registers the session in the broker. NEVER auto-solves.
  Wired into acctfactory as the `captcha:'handoff'` recipe primitive;
  `recipes/semrush-signup.json` is migrated onto it. Tests: 20.
  Doc: `docs/builds/2026-08-31-captcha-handoff.md`. **Has an OPEN BUG — see §4.**
- **authzsweep / idorprobe / race / logicprobe** (the oracle family;
  `tools/authzsweep.mjs`, `tools/idorprobe.mjs`, `tools/race.mjs`,
  `tools/logicprobe.mjs`) — productized two-/four-account authorization oracle:
  harvest real refs from both sessions' traffic → templatize → cross-replay
  authed-other + unauth-control both directions → classify read/write/delete →
  mass-assignment ladder with before/control/after readback → best-effort revert →
  redacted evidence bundles labeled observation/inference/impact. NEVER status-only
  (kills ownership-enforced-404 and public-identical-body false positives);
  inconclusive without controls, never a claim. `race.mjs`: last-byte-sync over raw
  sockets with a sequential-replay control that MUST NOT violate the invariant.
  `logicprobe.mjs`: control → violation → state readback for business-logic
  invariants. All lab-proven on `targets/authzlab.mjs` / `targets/logiclab.mjs` /
  chainyard; writes/deletes default OFF on real engagements.
- **detoracle / fporacle** (`tools/detoracle.mjs`, `tools/fporacle.mjs`) — measurement
  oracles, never verdicts. detoracle: "did the defender see it?" (Defender
  threat-detection/Operational-1116 snapshot-diff-classify over the governed channel,
  no guest code, no EDR tampering). fporacle: "what do we look like on the wire?" —
  JA4/JA4S/JA4H fingerprints of our own ClientHello / server ServerHello / governed
  requests (math in `engine/fingerprint.mjs`).
- **soft-404 baselining** (`engine/soft404.mjs`, wired into webscan/vulncheck +
  surface debunk ledger + report "Soft-404 debunked" section) — baseline signature
  check so catch-all HTML on 404s can never again become a "confirmed" finding (born
  from the localizejs "9 HIGH" debunk, 2026-08-30).
- **param-harvest** — apisurface/crawl extract JS fetch/axios/XHR params → surface
  `?param=` endpoints feed the OOB / DOM-XSS gates (shipped 2026-08-30 23:59 with
  soft-404; 150/150 tests that round).
- **killfast / budget** (`engine/budget.mjs` + `Campaign._killfast`) — per-hypothesis
  early-stop (default 40 calls / 300s; tripped cap logs `killfast.stop`, partials
  marked `{stopped:'killfast'}`). `budget.tools {maxRequests, maxMs}` (default
  {200, 600000}) is a SEPARATE bucket for jsminer/oob/browseragent/authz-seeding —
  never floods `budget.maxSteps`; noise ledger intact. Spent host budget → REAL
  countersign approval (pendingApproval), refused → host marked budgetExhausted and
  recon completes honestly.
- **jsminer (+verify)** (`tools/jsminer.mjs`) — JS/sourcemap mining: HTML → script
  srcs (scope-confined) → endpoint + secret extraction (trufflehog/gitleaks regex set
  + Shannon-gated assignments, placeholder-denylisted) → follow `sourceMappingURL` →
  mine `sourcesContent`. Secrets stay `status:'candidate'`; graduation to `verified`
  is `verifySecret()` — OPT-IN (`jsminerVerify:true`), exactly ONE governed request
  (AWS STS GetCallerIdentity unsigned differential / Google AIza key-invalid
  differential). Sends the X-HackerOne attestation header (fixed 2026-08-31 — it
  previously didn't). Tests: 9.
- **OOB stack** (`tools/oob.mjs` + infra) — self-hosted interactsh-style listener
  `OobServer` on `127.0.0.1:8977` (loopback-only) + cloudflared quick tunnel for the
  public base. Dual-form canary addressing, bearer-authed `/_oob/poll`. `oobProbe()`:
  SSRF/SSTI/XXE/blind-XSS payload template sets, canary→payload→request journaling.
  **Verdict `proven` ONLY on a correlated callback.** Config/creds in
  `.tmp/oob-stack.json` (authToken). Runner `.tmp/oob-stack.mjs`; launchers
  `.tmp/start-oob.bat` (node side, has the tunnel URL hardcoded) and
  `.tmp/start-cf.bat` (cloudflared, now `--protocol http2`), both hidden via
  run-hidden.vbs. Known gap: remoteAddr shows the tunnel hop; CF-Connecting-IP parsing
  is backlog.
- **browseragent** (`tools/browseragent.mjs`) — headless-crawl + DOM-XSS execution
  canary. BFS of links/forms/XHRs; cross-origin = recorded refusal, never queued.
  `proven` ONLY on execution (`window.__varvelCanary` readback or marker callback);
  reflection alone = `unproven`, ZERO findings. Real driver = playwright-core Firefox,
  persistent profile, ghost-proxied. Tests use fakes + loopback labs.
- **targetscore** (`tools/targetscore.mjs`) — deterministic target-scoring/ROI layer,
  NO I/O, NO LLM. Signals: non-prod hostnames, API density, parameterized endpoints,
  edge-walled (scores DOWN), known-buggy stacks, SPA, soft-404 behavior, GraphQL/AI/WS
  hints. Output `{score 0-100, reasons[], classes[]}` — every reason names its signal.
  Default ON under tooledRecon; REORDERS only, never skips/hides in-scope hosts.
  Tests: 9.
- **aisurface** (`tools/aisurface.mjs`) — AI/LLM attack-surface module. Passive-ish
  detection (endpoint shapes, `/.well-known/ai-plugin.json`, benign MCP
  initialize/tools/list) files NOTHING (inventory note only). Active probes OFF by
  default; `aiProbe:true` arms canary-proof-only probes: OOB tool-exfil (correlated
  callback oracle) and cross-session differential (fresh control must answer clean; a
  tainted control = oracle cannot speak = NO finding). A model complying with a naughty
  string is NEVER a finding. Tests: 18.
- **novelgate** (`tools/novelgate.mjs` + `engine/novelcore.mjs`) — the novelty gate,
  born from semrush #2666357 closed-DUPLICATE. Hacktivity duplicate search (H1 public
  GraphQL via ghost, fail-closed — UNVERIFIABLE never faked), edge-generated-behavior
  detector (x-goog-iap / cloudfront / akamai / awselb / fastly / cf-challenge on unauth
  302/401/403), per-class impact bar (CORS=authenticated-read, TLS=never submittable,
  SSRF=OOB callback, IDOR=cross-account with BOTH controls), internal SimHash dedup,
  admission patterns ("not included: post-auth…") hard-fail. Verdicts BLOCKED >
  UNVERIFIABLE > REVIEW-NEEDED > CLEAR. `queueProgram` REFUSES drafts with no novelty
  section or a BLOCKED verdict. Limitation embedded in every section: undisclosed dupes
  are unsearchable — the gate reduces, cannot eliminate. Tests: 16.
  Doc: `docs/builds/2026-08-31-novelty-gate.md`.
- **replaybind** (`tools/replaybind.mjs`) — replayable-evidence binding. Every filed
  authz differential gets `replay.json` + `replay.sh` (rides `socks5h://10.64.0.1:1080`
  + attestation header; creds as `CRED_<REF>` resolved via sessionbroker — bundles
  carry no secrets). `runPlan` re-fires each leg asserting it REPRODUCES its capture
  (REPRODUCED / FIXED-OR-CHANGED / INCOMPLETE; unresolved creds SKIP, never guessed).
  Routes never invented. bountyline.draftReports emits bundles on draft. Tests: 9.
- **coverage gates** (`engine/coverage.mjs` — pure core) — per-target coverage ledger:
  recon-queued endpoints must be MARKED exercised by a testing lane (authz oracle, oob,
  browseragent, aisurface) before a campaign may report DONE-CLEAN; otherwise
  COVERAGE-INCOMPLETE with the remaining queue itemized. Exercise ≠ safety (marked =
  TESTED, not clean); in-memory per run. Tests: 8 (`test/coverage-gate.test.mjs`).
- **widerecon** (`tools/widerecon.mjs`) — policy-aware roster-wide PASSIVE sweep:
  crt.sh + Wayback CDX + DoH (through the chain — no local DNS of targets) + TLS cert
  metadata + a tiny cadence-permitting fingerprint (`/` + ≤2 well-known files).
  `PROHIBITED_PROGRAMS = ['udemy','wordpress','matomo']` hard-pinned → zero requests,
  SKIPPED-POLICY named. Human-cadence programs: concurrency 1, ≥5s between
  target-contact requests. Ranked via targetscore + fresh-subdomain / version-disclosed
  / tls-origin-hint / jsminer-fodder signals. Verdict NOTHING-TESTED — it enumerates,
  never tests. Tests: 11. Doc: `docs/builds/2026-08-31-wide-recon-cve.md`.
- **cvelane** (`tools/cvelane.mjs`) — KEV + NVD-30d feeds (cached ≥12h, polite:
  5 req/30s, 3-page cap, truncation NAMED; EPSS null unless caller provides a map —
  never fabricated) → (software, version) → CVE matching via CPE 2.3 + alias bridging.
  Outputs `status:'HYPOTHESIS'` items ONLY, routed to the campaign validator via the
  `cveHypotheses` launch option (they queue into the coverage ledger; undrained =
  COVERAGE-INCOMPLETE). NEVER enters the draft path; a version match ≠ a vulnerability.
  Tests: 16.
- **bountyline** (`engine/bountyline.mjs`) — the per-program state machine:
  imported → scoped → hunted → triaged → reported → QUEUED-FOR-SEND → operator marks
  outcome. Offline by doctrine (no network code — static-scan pinned). Persistence:
  `data/bountyline/roster.json` + `programs/<id>.json` + `ledger.json` + `intel.jsonl`.
  Owns draftReports (runs the offline novelty half before persisting; emits replay
  bundles) and queueProgram (novelty-gate + replay-bundle checklist enforcement).
- **h1watch / h1sync** (`tools/h1watch.mjs`; h1sync is built into
  `tools/submit-drive.mjs`) — h1watch: the pipeline's EYES — watches H1's public
  program directory + structured scopes, diffs against recorded state, ranks fresh
  ground, writes operator-REVIEWABLE intake outbox files (NEVER signs, NEVER runs:
  "fresh ground is an opportunity list, not authorization"). h1sync:
  `h1sync <handle[,handle...]|all> [--edge]` snapshots H1 scope (`/<handle>`) + policy
  (`?view_policy=true`) pages through the persistent browser, diffs vs previous
  snapshot, saves `data/bountyline/h1sync/<handle>.json`; Cloudflare beaten by
  `sync-firefox hackerone.com` (imports real Firefox cookies incl. cf_clearance —
  IP/UA-bound; VPN exit change = re-sync). **h1watch cron currently DELETED — re-arm
  only after Jack rotates the H1 API token (old token 401-dead).**

Also present and relevant: `tools/submit-drive.mjs` (submission automation incl.
scopecheck gate + form fill; Jack clicks), `tools/pocvid.mjs` (PoC video recorder,
sandbox doctrine ≤90s 720p human-looking), `tools/apisurface.mjs`, `engine/ghost.mjs`
(multi-hop chain, probeHops health, shaper, rotation-set exitSet, substatus
correlation-resistance report), `engine/autogate.mjs` (time-boxed operator
pre-authorization for exploit/postex sigil gates), `engine/campaign.mjs` (the
phase-FSM spine; stall detector; all lane wiring).

---

## 3. Program ledger

- **localizejs** — DONE, honest CLEAN, oracle-enforced. Fast-lane campaign clean; the
  console's "9 HIGH" was debunked by manual re-probes (soft-404 catch-alls + empty
  evidence — the lesson that forced soft-404 baselining + evidence binding). Two
  accounts provisioned via mail.tm (`varvel-a-x7q2@` / `varvel-b-m4p8@emalupe.com`),
  tenants seeded. Two-account authZ oracle fired live 2026-08-30 (countersigned exploit
  window, READ-ONLY, 18 governed requests): `/api/user|project|organization/{id}` all
  **enforced**, 0 violations. Exports `data/exports/localizejs-*-2026-08-30.*`.
- **zomato** — EXHAUSTED, provably CLEAN. Two accounts (uids 447585412 / 447585565,
  mail.tm OTP). Read matrix: cross-user denied, garbage+unauth controls identical.
  Writes window (own accounts, Jack-approved): cart `user_id` override never honored;
  B-posts-A's-address_id created a NEW address in B's own book — hard session-scoped;
  all test data reverted. OAuth gate proper; MCP server inventory-noted (aiProbe
  budget exhausted before firing — a dedicated MCP pass is residual). Sessions
  **zomato-a + zomato-b LIVE in the broker** (canary 200). Exports incl.
  `data/exports/zomato-writes-2026-08-31.*`.
- **hubspot** — unauth lane CLEAN (22 TLS-wildcard-only scanner findings, all
  ineligible classes; OOB/DOM-XSS loud-skipped — no params exposed behind the login
  wall). Authenticated lane needs program-conventional `@wearehackerone.com` test
  accounts — **Jack manual step**, not yet done.
- **mercadolibre** — BLOCKED. Registration wall "max-attempts 24h" on the ghost exit
  before first form render (pre-burned exit), and signup ultimately needs **+54
  (Argentina) SMS**. Program file created + unauth hunt recorded; retry needs rotated
  exit AND the SMS answer.
- **frontegg** — 2 tenants provisioned (A `55376959-…`, B `3d9b36f3-…`, AU entry,
  mail.tm inboxes, TOTP MFA enrolled, refresh-cookie → 24h access-token mint verified;
  material in `.tmp/fe-login-{a,b}-result.json`, `.tmp/fe-tokens.json`). Sessions now
  **DEAD** (broker: frontegg-a canary 403 / refresh 401 — refresh credential itself
  dead, relogin recipe stored but `allowSpawn:false`; frontegg-b never registered — no
  cookie material). Worse: `api.au.frontegg.com` CloudFront WAF **403s ALL Mullvad
  exits tried** (135.136.21.33, 45.66.219.45, 103.141.60.144 — curl AND real Firefox;
  range-level block, not one dirty IP). Oracle armed, parked until clean egress.
  Program asks @wearehackerone.com signup emails — flag before any filing.
- **semrush** — unauth swept CLEAN: jsminer over **62 bundles / 25 hosts** (zero
  sourcemaps, 1 unverifiable secret candidate), DOM-XSS 0/7, MCP 0/1, 29 notes all
  hard-blocked hygiene classes; campaign reported COVERAGE-INCOMPLETE honestly (sess
  -1021, :8992). The earlier CORS report was closed **DUPLICATE (#2666357)** —
  Google-IAP edge behavior, which is exactly why novelgate exists. Authenticated lane
  **BLOCKED on reCAPTCHA at signup submit** — see §4, the exact next task.
- **wolt** — picked as best fresh target (fresh-lane scan of 591 programs: only 3
  fresh ≤90d bountied+open — vercel_sandbox, wolt, agoda-public; wolt scored
  targetscore 80, idor-candidate, self-signup allowed). **BLOCKED: Wolt suppresses
  verification email to ALL disposable domains** (mail.tm / guerrilla×5 /
  tempmail.lol / maildrop; 45-min polling, 0 delivered; mail.tm received zomato mail
  same day → suppression is Wolt-side). Unblock = Jack registers with his real mailbox
  or an @wearehackerone.com address and forwards the magic link. Signup script ready:
  `.tmp/wolt-signup.mjs` (headful Firefox through ghost, scout-heavy); intake staged
  (`.tmp/wolt-intake.json`, unsigned).
- **agoda-public** — hunted 2026-08-30 (with bykea/blendlabs in that handoff's
  scoreboard): nothing filable, all hygiene-class, 0 validator-confirmed.
- **automation-prohibited** — **udemy, wordpress, matomo**. Hard-pinned in widerecon
  (`PROHIBITED_PROGRAMS`) → zero requests, SKIPPED-POLICY. The 2026-08-30 udemy
  campaign should never have launched; bountyline refused the record. Do not campaign
  these. (Wordfence/Patchstack WP *plugin* hunting is a separate, permitted lane.)

Closed/background: smtp2go, mergify, moderntreasury, homebargains, sheer, alsco,
tripcom, bykea — all hunted, all honest CLEAN / nothing filable. Madara
option-overwrite (Wordfence ticket f26140c9) in triage — the only live ticket.
GiveWP rejected by Patchstack (strictness lesson now law). Semrush CORS duplicate —
closed.

---

## 4. OPEN BUG — captchaassist early-detection (THE exact next task)

**Symptom:** the rail pauses on an INERT `iframe:recaptcha` present on page load (step
0 `goto`, before any fill/submit). Jack sees a blank form and a paused flow. The
2026-08-31 23:36Z live run proved it: reCAPTCHA detected ON THE LANDING PAGE, handoff
entered correctly per current logic, Jack was away → OPERATOR-TIMEOUT at 23:46Z
(correct timeout behavior; nothing registered, state clean).

**Required fix (fully specified; was about to be implemented when work stopped):**

1. **Discriminate inert anchor iframe from a live challenge.** A reCAPTCHA *anchor*
   iframe sitting in the page from load is not a challenge. Check for the challenge
   (`bframe`) frame / visibility / interactivity before declaring NEEDED. Only
   auto-handoff on a VISIBLE challenge, or after the recipe's submit step.
2. **Broaden solve-detection.** Current RESOLVED pin (signature gone AND
   url-change/success-marker/submit-re-enabled) missed the real-world case: Jack
   manually filled the form and that didn't trigger resume. Accept: challenge gone OR
   URL navigates OR next-step elements appear.
3. **Regression tests for all three** (inert-anchor no-pause; visible-challenge pause;
   manual-fill resume), in `test/captchaassist.test.mjs` (currently 20/20).
4. **Then refire, with Jack at the keyboard (10-min solve window from window open):**

```bash
export PATH="/c/Program Files/nodejs:$PATH"
cd /c/Users/Jack/Downloads/enclave/varvel
node tools/captchaassist.mjs run --program semrush --label a \
  --recipe recipes/semrush-signup.json --timeout 600000 \
  --inbox varvel-probe-q9x@emalupe.com --inbox-pass 'VarvelProbe!9'
```

Exit 0 = verified+brokered session (`.tmp/sessions/semrush-a.json`); 3 = flow failure;
4 = OPERATOR-TIMEOUT. Evidence: `.tmp/semrush-signup-a-result.json`. Watch for wedged
`ff-semrush-a` profiles — the rail self-quarantines them (three quarantine dirs already
exist in `.tmp/`, renamed never deleted).

**Context note:** agent-16 (the captcha-rail builder) holds full context if resumable
in the originating runtime; agent-17 built widerecon/cvelane.

---

## 5. Blockers needing JACK (his hands, not ours)

1. **Semrush captcha solve** — after the §4 fix lands, fire the command above and
   solve the reCAPTCHA in the Firefox window within the 10-min window.
2. **Wolt mailbox** — register with Jack's real mailbox or @wearehackerone.com and
   forward the magic link; then `.tmp/wolt-signup.mjs a|b` can run.
3. **Mullvad relay switch (OOB tunnel DOWN)** — Cloudflare edge port 7844 (QUIC *and*
   TCP/http2) i/o-times-out on every edge IP from the current AU path
   (`.tmp/cf-tunnel.log`: `dial tcp 198.41.200.113:7844: i/o timeout`). cloudflared is
   left retrying and `.tmp/start-cf.bat` already has `--protocol http2`. After a relay
   switch: it self-connects → parse the NEW `*.trycloudflare.com` URL from
   `.tmp/cf-tunnel.log` → update the hardcoded URL in `.tmp/start-oob.bat` (currently
   `common-phys-arranged-product.trycloudflare.com`) → restart the listener via
   run-hidden.vbs.
4. **Frontegg clean egress** — all Mullvad exits WAF-blocked at api.au. Options on
   record: more hops (low odds), residential egress (policy call), or shelve.
5. **DAITA toggle question** — ghost shaper/rotation-set/substatus shipped engine-side;
   constant-rate padding is impossible at app layer, so the ISP-correlation answer is
   Mullvad's DAITA — app-side, **Jack to enable** (or say no).
6. **H1 API token rotation** (Settings → API; old token 401-dead) → then re-arm
   h1watch.

---

## 6. Strategy state

- **Research conclusions** (`research/2026-08-31-ai-hunter-practitioner-brief.md`,
  claim-ledger labeled VERIFIED / SELF-REPORTED / UNSOURCED): the winning pattern is
  **harness > model** — persistent auth, coverage queues, adversarial validation,
  per-program judges, commodity models inside. Classes that PAY: IDOR/BOLA at API
  scale, missing-auth on staging/internal APIs, guest/partial-auth token bugs,
  third-party auth misconfig (Cognito/Firebase/Supabase), OAuth/MCP flaws, JS-bundle
  secrets. Dup bait (never file): CORS without authenticated-read, self-XSS, existence
  enumeration, GraphQL 403→401 flips. Copyables 1–3 are SHIPPED (replaybind,
  sessionbroker, coverage gates); 4–8 (adversarial validator w/ per-program memory,
  fresh-scope+JS-diff trigger, third-party-auth class pack, report judge,
  incentive-arbitrage scoring) are the ranked backlog.
- **Freshness doctrine:** deltas, not sweeps — commitwatch expansion + release-diff
  hunting (diff new plugin versions, hunt only changed files). Full-estate sweeps
  proved 0-yield; timing lanes are where daily volume honestly lives.
- **The goal:** Jack's spec is **1–3 ACCEPTED filings/day** → income → fund varvel
  24/7 self-improvement. Hard truth recorded and accepted by Jack: that's a
  full-time-researcher workload; expect 0–3; acceptance rate is the metric (protect
  Patchstack ≥50%); NEVER force a filing to hit a number.
- **Honest throughput assessment (2026-08-31):** tooling is COMPLETE and verified
  (oracles, broker, novelty gate, coverage gates, OOB, captcha rail, wide recon, CVE
  lane). **The bottleneck is signup barriers** — the highest-value lanes (authenticated
  IDOR on fresh programs) are gated by captchas, disposable-mail suppression, SMS
  walls, and WAF-blocked egress, all of which need Jack's hands or infra decisions.
  Scoreboard to date: 1 live ticket (Madara, Wordfence triage), 1 duplicate
  (semrush CORS), everything else honest clean.

---

## 7. Key file paths

All under `C:\Users\Jack\Downloads\enclave\varvel` unless noted.

- **Accounts / credentials:**
  - `.tmp/mailtm-accounts.json` — mail.tm inbox address → password + API token (all
    temp inboxes incl. frontegg/localizejs/semrush probe accounts).
  - `.tmp/fe-login-a-result.json`, `.tmp/fe-login-b-result.json`, `.tmp/fe-tokens.json`,
    `.tmp/fe-token-{a,b}.{json,hdr}` — frontegg tenant/session/token material (DEAD —
    see §3). `.tmp/fe-login.mjs` = the zero-dep RFC6238 login script.
  - `.tmp/authz-*.json` — per-program oracle configs (localizejs provisioned:true;
    zomato real harvested IDs; mercadolibre staged).
  - `.tmp/sessions/<program>-<label>.json` — sessionbroker store (zomato-a/b live;
    frontegg-a dead). Broker CLI: `node tools/sessionbroker.mjs list|check|print-cookie`.
  - `.tmp/oob-stack.json` — OOB listener config + authToken.
  - Known-good pre-provisioned semrush inbox: `varvel-probe-q9x@emalupe.com` /
    `VarvelProbe!9`.
- **Exports pattern:** `data/exports/<program>-<kind>-YYYY-MM-DD.{json,md}` (state,
  surface, writes, widerecon, cve-hypotheses). New files only, never edit.
- **Evidence standards:** `.tmp/wordfence-madara-option-overwrite-submission.md` is the
  gold-standard submission (the one in triage). Replay bundles live under
  `data/bountyline/programs/<id>/reports/replay/`. PoC video doctrine:
  sandbox→normal→fire→change→impact→revert→restored, ≤90s 720p, human-looking
  (`tools/pocvid.mjs`; sandbox creds `.tmp/sandbox/creds.txt`).
- **Monitor scripts:** `.tmp/monitor-batch2.py` (feed-based parked-gate detection —
  pendingApproval is NOT in /api/state), `.tmp/monitor-zomato.py`,
  `.tmp/monitor-hubspot.py`, `.tmp/watch-semrush.py`, `.tmp/monitor.log`.
- **Ledgers:** `.tmp/SUBMISSIONS.md` (full submissions ledger),
  `data/bountyline/ledger.json` + `intel.jsonl` + `roster.json`,
  `data/autogate-log.jsonl`.
- **Launchers:** `.tmp/start-*.bat` per instance (absolute paths, via
  `C:\Users\Jack\Downloads\enclave\run-hidden.vbs`), `.tmp/start-cf.bat` +
  `.tmp/start-oob.bat` for the OOB stack. Server launch shape:
  `ENCLAVE_SESSION="C:\Users\Jack\Downloads\enclave\poc\enforcement-seam\session\marcus.json" node server.mjs`.
- **Milestones log (external):** `C:\Users\Jack\Downloads\varvel-kimi\KIMI-NOTES.md` —
  append running memory there; this file supersedes it for cold-start.
- **Crons:** commitwatch 6h (wp.org only, healthy) + Semrush daily 09:17 (delete after
  the semrush filing lands). h1watch + Visa check-in DELETED (token / no live Visa
  campaign).

*Handoff ends. If anything here conflicts with a file on disk, the file on disk wins —
verify before acting.*

## 8. Owner queue — 2026-09-18 (evening)

Note on freshness: this document was last reconciled 2026-09-01. For submissions and
hunt outcomes the fresher ledger is `.tmp/SUBMISSIONS.md`; for the loop's own state it is
`data/huntloop/state.json`. Where this file disagrees with a file on disk, the file wins.

1. **API keys — Jack's offer ("if you need me to put in your api key … let me know").**
   Honest answer: keys are NOT needed to hunt, and not needed to keep the pipeline honest.
   They are needed for exactly two things, both of which are *measurements*:
   - **Scoring a candidate brain** with `node tools/brainharness.mjs run --provider-env
     --suite fidelity,honesty,loop` — the gate that decides whether a cheap lane may drive
     the loop at all (the 300M-token lesson, now enforced fail-closed in `runLoop`).
   - **Running a cheap lane as burst capacity** once — and only once — it passes that gate.
   Handling: the console's Brain card keeps the value in process memory only; the durable
   path is an environment variable whose NAME is stored (`brain.apiKeyEnv`), never the value.
   Nothing here needs the operator's real account keys.
2. **Spark lane is DOWN** (`lane-models.sh status` = `health=000000 model=none`; no listener
   on :8080, stale pid). Nothing is being served — not even our Q6 baseline — so any
   model comparison needs `bash ~/engine-switch/lane-models.sh load <model>` first.
3. **CUDA toolkit on the Spark — a decision only Jack can make.** Ternary Bonsai 2's low-bit
   kernels ship in the vendor's llama.cpp fork; the box is stock `ggml-org/llama.cpp`
   b81c99b with no `nvcc`. Either install the CUDA toolkit and build
   `PrismML-Eng/llama.cpp` for GB10, or park the Bonsai experiment as downloaded-but-unrunnable.
   Disk is not the constraint (303 GB free); toolchain and appetite are.

