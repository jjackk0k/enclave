# Hunting tools build — 2026-08-30

Four standalone governed tools (ES modules under `tools/`, pinned `node:test`
tests under `test/`). Every module: header comment with purpose/oracle/caps/
usage, `fire()` transport that never throws, `agents: {http,https}` ghost-chain
plumbing (authzsweep shape), pacer hook before every request, path-prefix +
scope fail-closed confinement, `budget: {maxRequests, maxMs}` with honest
`budget.exhausted` log entries via `onLog`, structured results, NEVER throws.
Browser access is behind injectable driver interfaces; the real factories are
playwright-core Firefox, persistent profile, `headless:false`, proxy pinned to
`socks5://10.64.0.1:1080` (manual smoke only — tests use fakes + 127.0.0.1 labs).

## tools/acctfactory.mjs — the account factory
Declarative RECIPE (`{signupUrl, emailSelectorHints, submitButtonText,
activation: {type: email-code|email-link, …}, mfa: {required, strategy: totp},
sessionCapture: {cookieDomains, bearerFrom}}`) drives
inbox (mail.tm REST, `MailTmClient`) → signup → activation → TOTP enrollment
(RFC6238 zero-dep, pinned to the Appendix B vectors) → session capture.
**Contract:** `provisionAccount()` is `ok:true` only when capture yields ≥1
cookie OR a bearer — otherwise `ok:false` with the dying step named.
`mintRoleMatrix()` assigns `['owner','member','lowpriv','unauth-control']`
(the control is a sessionless placeholder by design); `toAuthzAccounts()`
emits the exact `{label,cookie}` / `{label,headers}` shapes
`sanitizeAuthzCfg` consumes. Caps: `ACCT_CAPS`.

## tools/jsminer.mjs — JS/sourcemap mining, zero-dep
`mine(baseUrl, opts)`: fetch HTML → script srcs (scope-confined, refusals
recorded) → extract endpoints (`extractEndpoints`) and secrets
(`extractSecrets`: the trufflehog/gitleaks regex set + Shannon-gated generic
assignments, placeholder-denylisted) → follow `sourceMappingURL` → mine every
`sourcesContent` again. `endpointsToCandidates()` folds id-bearing paths into
the `{path:'/x/{id}', refs:{a:[],b:[]}}` shape `synthesizeCandidates()` consumes.
**Oracle:** secrets stay `status:'candidate'`; graduation to `verified` is
`verifySecret()` — OPT-IN, exactly ONE governed request (AWS STS
GetCallerIdentity unsigned differential: `SignatureDoesNotMatch` = key ID known
to AWS; `InvalidClientTokenId` = dead; Google AIza key-invalid differential).
`mine()` verifies only with `verify:true` — pinned by test. Caps: `JSMINER_CAPS`.

## tools/oob.mjs — OOB callback correlation (interactsh-style)
`OobServer`: self-hostable HTTP listener, mints crypto-random canaries, records
every hit `{canary, at, remoteAddr, method, path, headers, body}`, dual-form
addressing (`<canary>.<host>` via Host header, or `/c/<canary>/…` path),
bearer-authed `/_oob/poll` API. `urlFor()` **fails with a clear error when
`publicBaseUrl` is unset** — production needs an operator-provided public
IP/VPS. `oobProbe()`: payload template sets (SSRF/SSTI/XXE/blind-XSS,
`{CANARY_URL}` substituted), canary→payload→request journaling, ghost-riding
probe, poll-with-deadline. **Oracle: verdict `proven` ONLY on a correlated
callback — no callback, no finding.** Caps: `OOB_CAPS`.

## tools/browseragent.mjs — crawl + DOM-XSS canary
`crawl(startUrl, {driver, scopeHosts, pathPrefixes, …})`: BFS graph of
links/forms/XHRs; cross-origin links are recorded refusals, NEVER queued.
`domXssCanary(baseUrl, {params, driver, markerUrl, markerHit})`: unique canary
payload per parameter. **Oracle: `proven` ONLY on execution** — the driver reads
`window.__varvelCanary === <id>` or the marker callback correlates; reflection
alone is `unproven` and emits ZERO findings; screenshot + console log attached
as evidence on proven hits. Caps: `BROWSER_CAPS`.

## Wiring notes for the engine pass
- `agents` everywhere = `{ http: ghost.agents().httpAgent, https: ghost.agents().httpsAgent }`
  (authzsweep key shape; ghost.agents() returns `{httpAgent, httpsAgent}`).
- All four accept `pacer` (`await pacer.pace()` before every request), `scope`
  (`{hosts: []}`, fail-closed when present), `pathPrefixes` (scopepath), and
  `budget`/`onLog`.
- jsminer `candidates` → `synthesizeCandidates(harvested, candidates)`;
  acctfactory accounts → `sanitizeAuthzCfg({accounts: toAuthzAccounts(matrix.accounts)})`.

## Wired (engine integration, 2026-08-30 follow-up)
The four tools are campaign lanes in `engine/campaign.mjs`; the IDOR oracle is the
generalized 4-role sweep. Ghost agents are bridged at the seam
(`Campaign._bridgedAgents()`), every lane is paced + path-prefix confined +
fail-closed on scope, and every governed request still counts noise via `_noise()`.

**Launch-body options** (all optional; a lane whose option is absent logs
`jsminer.skip` / `oob.skip` / `browseragent.skip` with the reason — a dormant lane
is never silent):

- `jsminer: true` — recon phase, after crawl/apisurface. Mines in-scope web bases'
  JS/sourcemaps; harvested endpoints land as ENDPOINT nodes (the authz harvest pass
  sees them); secrets land as findings ONLY when verified.
  ```json
  { "targets": ["app.example.com"], "tooledRecon": true, "reconOpts": { "ports": [443] }, "jsminer": true }
  ```
- `jsminerVerify: true` — opt-in live-use secret oracle (exactly one governed
  request per candidate, under killfast). Without it, secret candidates are surface
  notes, never findings.
  ```json
  { "targets": ["app.example.com"], "tooledRecon": true, "reconOpts": { "ports": [443] }, "jsminer": true, "jsminerVerify": true }
  ```
- `oob: { publicBaseUrl, adminToken }` — exploit phase (countersigned window). OOB
  probes (SSRF/SSTI/XXE/blind-XSS) against harvested parameterized endpoints;
  'proven' verdicts file CONFIRMED (ssrf high, ssti crit, xxe high, blind-xss med)
  with the canary journal. No callback = zero findings + an honest surface note.
  `publicBaseUrl: "auto"` is the loopback LAB seam (logged as such); production
  needs the operator's publicly reachable base.
  ```json
  { "targets": ["app.example.com"], "oob": { "publicBaseUrl": "https://oob.operator-vps.example", "adminToken": "…", "kinds": ["ssrf", "ssti"], "deadlineMs": 15000 } }
  ```
- `browseragent: true` — exploit phase. DOM-XSS canary over reflected params recon
  surfaced (GET forms / query params); files CONFIRMED med ONLY on execution
  (`window.__varvelCanary` readback or marker callback). Real driver =
  playwright-core Firefox, ghost-proxied.
  ```json
  { "targets": ["app.example.com"], "browseragent": true }
  ```
- `budget.tools: { maxRequests, maxMs }` (default `{200, 600000}`) — the SEPARATE
  bucket the jsminer/oob/browseragent/authz-seeding requests charge. Never touches
  `budget.maxSteps`; exhaustion emits `budget.exhausted {bucket:'tools'}` and is
  recorded in `getState().budget.tools` and the report's governance section.
  ```json
  { "targets": ["app.example.com"], "jsminer": true, "budget": { "maxSteps": 200, "tools": { "maxRequests": 120, "maxMs": 300000 } } }
  ```

**Kill-fast hypothesis budgets**: every lane run is wrapped in
`Campaign._killfast(name, fn, { maxCalls, maxMs })` (defaults 40 calls / 300s; the
tool's own budget hook is the counter). A tripped cap logs `killfast.stop` with the
reason and returns partial results marked `{ stopped: 'killfast' }`.

**4-role IDOR oracle**: `authz.accounts` accepts up to 4 accounts with optional
`role` ('owner'|'member'|'lowpriv'); the read differential runs the full cross
product (worst verdict per template wins) while writes/deletes/ladder stay on the
first pair. Candidates/templates may declare `seed: { '<accountLabel>': { method,
path, body } }` — with `writes: true`, an account with empty refs gets ONE object
provisioned before replay (honest `authz.seed` events; a failed seed degrades the
candidate to 'inconclusive', refs never fabricated). acctfactory's
`mintRoleMatrix()` + `toAuthzAccounts()` emit exactly this shape.
  ```json
  { "authz": { "accounts": [ { "label": "owner", "role": "owner", "login": { "path": "/login", "body": "user=o&pass=…" } }, { "label": "member", "role": "member", "cookie": "sess=…" }, { "label": "lowpriv", "role": "lowpriv", "headers": { "authorization": "Bearer …" } } ], "writes": true, "templates": [ { "path": "/api/items/{id}", "methods": ["GET"], "seed": { "lowpriv": { "method": "POST", "path": "/api/items", "body": "{\"title\":\"probe\"}" } } } ] } }
  ```

---

# Build 3 — research-driven queue follow-up (2026-08-31)

Two engine capabilities, driven by `docs/research/h1-latest-submissions-2026-08-30.md`
(AI-in-scope reports +210% YoY, prompt injection +540%) and
`docs/research/ai-hunter-throughput-2026-08-30.md` (spend budget on soft,
high-value surface first; proof is the filing bar). Tests:
`test/targetscore.test.mjs` (9), `test/aisurface.test.mjs` (18).

## tools/targetscore.mjs — the target scoring / ROI layer
`scoreHost(ctx)` / `scoreSurface(surface)` / `preScoreTargets(targets, prior)` —
pure functions over data recon already gathered (surface nodes, tech nodes,
response-behavior samples). Deterministic, NO I/O, NO LLM call. Signals:
non-prod hostname keywords (admin|staging|dev|internal|test|sandbox), API-role
hostnames, login/auth endpoints, API surface density, parameterized endpoint
count (?param= / {id}), non-CDN origin vs fingerprinted CDN/WAF edge
(Cloudflare/Akamai/… score DOWN), TLS origin hints, known-buggy stacks
(WordPress/Drupal/Laravel/PHP/… score UP, family-capped), SPA frameworks,
soft-404 behavioral sampling, GraphQL / AI / WebSocket hints. Output per host:
`{ score 0-100, reasons[], classes[] }` — every reason NAMES its signal and
cites the observed evidence; class hints route downstream lanes
('idor-candidate', 'ai-surface', 'api-heavy', 'soft-env', 'spa',
'edge-walled'). Caps: `TARGETSCORE_CAPS`.

**Wiring.** Default ON under `tooledRecon` (kill: `targetScore:false`). A
pre-sweep pass orders `sweepTargets` score-descending (hostname keywords +
fresh inherited surface detail — `targetscore.preorder` on the record); the
full scoring runs after recon (+jsminer) and lands ON the host nodes as
`n.targetScore` (persisted with the surface, rendered by the report's
**Target scoring** section). The OOB, DOM-XSS, and AI-surface lanes order
their per-host endpoint/page/base iteration score-descending from the rollup.
REORDERS ONLY — never skips an in-scope host, never hides one, refusal rules
unchanged. Exposed as `getState().targetScore`.

## tools/aisurface.mjs — the AI/LLM attack-surface module
`aiSurfacePass(base, { endpoints, probe, server, agents, pacer, scope,
pathPrefixes, budget, onLog })` + `aiHintKind(path)`. DETECTION is passive-ish:
endpoint shapes recon harvested (`/ai`, `/llm`, `/copilot`, `/chat`,
`/completions`, `/mcp`, `/sse`) + one `/.well-known/ai-plugin.json` read per
web base, an OPTIONS banner, and a benign JSON-RPC `initialize`/`tools/list`
on MCP-shaped paths. Detection files NOTHING — a confirmed MCP server is an
inventory surface note, never a finding. ACTIVE probes are OFF by default and
CANARY-PROOF ONLY when armed:

1. **OOB tool-exfil** — a planted instruction asks the model to use its
   fetch/browse/tool capability on a canary URL; the oracle is a correlated
   callback at the OOB listener (`tools/oob.mjs` — the launch's `oob` config
   is reused, `publicBaseUrl:"auto"` lab seam included).
2. **Cross-session differential** — mint a canary; a FRESH control session is
   asked first (must answer clean); the canary is planted in a SECOND session;
   a THIRD fresh session is asked. Leaked = fresh returns the canary AND the
   control did not. A tainted control (endpoint parrots tokens) = the oracle
   cannot speak = NO finding.

A model merely **complying with a naughty string is NEVER a finding** — the
AI-slop pattern triagers reject, pinned by test. Caps: `AI_CAPS`
(maxEndpoints 8, maxProbes 4); the lane rides `budget.tools` + killfast
(40 calls / 300s) like the other lanes. Never throws.

**Wiring.** Exploit-phase lane `runAiSurfacePass()` inside the countersigned
window, next to OOB/DOM-XSS. Detection default ON (kill: `aiSurface:false`);
`aiProbe:true` arms the canary-proof probes. Ghost agents bridged
(`_bridgedAgents()`), paced, path-prefix confined, scope fail-closed; dormant
lane = loud `aisurface.skip` with the reason; a missing OOB listener while
armed = loud `aisurface.skip-oob` (the cross-session leg still runs). Proven
findings file CONFIRMED high with the canary journal attached
(`aisurface:ai-cross-session-leak:<canary>` / `aisurface:ai-oob-exfil:<canary>`);
rollup exposed as `getState().hunting.aisurface`.

## Launch-body options (Build 3)

- `targetScore: true|false` — the ROI layer; default ON under tooledRecon.
  ```json
  { "targets": ["www.example.com", "staging.example.com"], "tooledRecon": true, "reconOpts": { "ports": [443] }, "targetScore": true }
  ```
- `aiProbe: true` — arm the canary-proof active probes (detection runs in the
  gated exploit phase regardless; `aiSurface:false` kills the lane outright).
  The OOB tool-exfil leg reuses the `oob` config; without it only the
  cross-session differential runs (logged, not hidden).
  ```json
  { "targets": ["app.example.com"], "tooledRecon": true, "aiProbe": true, "oob": { "publicBaseUrl": "https://oob.operator-vps.example", "adminToken": "…" } }
  ```
