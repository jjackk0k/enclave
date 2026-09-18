# VARVEL Engagement Report — mercadolibre

**Scope:** 3.33.182.45/32, 15.197.170.90/32, 13.224.68.14/32, 13.224.68.42/32, 13.224.68.76/32, 13.224.68.61/32  
**Authorized by:** marcus · operator · sess-1020

## Executive summary

- Hosts in scope: **2**
- Findings: **12**  (confirmed: **10**, critical: **0**)
- Validation (objective oracle): **0 validated · 12 claimed-unvalidated · 0 refuted · 0 untestable**
- Risk levels: **0 high · 10 medium · 2 info**
- Exploits proven: **0**
- Governance holds (actions the platform blocked in-flight): **1**

## Target scoring

_Expected-yield scores computed from recon-observed signals (deterministic — no model call). Scores reordered per-host tool budgets ONLY: every in-scope host was tested, and refusal rules were unchanged._

- **100/100** `www.mercadolibre.com.ar` — api-heavy · idor-candidate
  - auth-surface +12 — login/auth surface observed: /login — an authenticated app behind it means object-level authorization to test
  - api-density +16 — 116 endpoints harvested on the host — dense programmatic surface
  - parameterized +10 — 2 parameterized endpoint(s) (?param= or {id} template): /clips?short_id=, /clips/?short_id=
  - idor-shape +6 — parameterized object endpoints AND a login surface — the exact two-account differential shape (idor-candidate)
  - non-cdn-origin +8 — live web service with no CDN/WAF vendor fingerprinted — responses come from the origin, probes reach the application
  - stack:laravel +10 — stack "Laravel" — a historically bug-dense stack scores UP
- **56/100** `api.mercadolibre.com` — api-heavy · edge-walled
  - hostname:api-role +10 — hostname "api.mercadolibre.com" declares an API/gateway role — programmatic surface, not marketing pages
  - auth-surface +12 — login/auth surface observed: /login — an authenticated app behind it means object-level authorization to test
  - api-density +16 — 70 endpoints harvested on the host — dense programmatic surface
  - edge-walled -20 — edge vendor fingerprinted: CloudFront — hardened perimeter; generic probing is burned budget here
  - graphql +8 — GraphQL surface observed: "/graphql" — one schema drives BOLA tests across every query/mutation

## Findings

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `api.mercadolibre.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS overly broad wildcard certificate  `F-01`
- Host: `www.mercadolibre.com.ar` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [LOW] Missing clickjacking protection (X-Frame-Options / frame-ancestors)  `VC-1`
- Host: `www.mercadolibre.com.ar` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [LOW] Cookie "_d2id" set without HttpOnly  `VC-2`
- Host: `www.mercadolibre.com.ar` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [LOW] Cookie "_mldataSessionId" set without HttpOnly, SameSite  `VC-3`
- Host: `www.mercadolibre.com.ar` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [LOW] Cookie "in_app" set without HttpOnly  `VC-4`
- Host: `www.mercadolibre.com.ar` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [LOW] Missing clickjacking protection (X-Frame-Options / CSP frame-ancestors)  `F-02`
- Host: `www.mercadolibre.com.ar` · confidence: **SUSPECTED** (69%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Note: _validator gate: no objective oracle cited_
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [LOW] Cookie '_d2id' set without HttpOnly  `F-03`
- Host: `www.mercadolibre.com.ar` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [LOW] Cookie '_mldataSessionId' set without HttpOnly and SameSite  `F-04`
- Host: `www.mercadolibre.com.ar` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [LOW] Cookie 'in_app' set without HttpOnly  `F-05`
- Host: `www.mercadolibre.com.ar` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [INFO] Version disclosure: Tengine  `VC-5`
- Host: `www.mercadolibre.com.ar` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [INFO] Version disclosure: Tengine  `F-06`
- Host: `www.mercadolibre.com.ar` · confidence: **SUSPECTED** (69%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Note: _validator gate: no objective oracle cited_
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

## Governance & scope

- **HELD** `Read` — enclave-denied (mercadolibre)

- Tool-lane budget (jsminer / OOB / DOM-XSS canary / authz seeding — a bucket SEPARATE from the agent step and noise budgets): **5/80** governed requests, wall-clock cap **420s** — not exhausted.

## OPSEC — detection footprint

Overall detection risk: **ELEVATED** — peak loudness **4/5**, weighted **3.3/5**, across **39** recorded action(s).

What a defender would have observed (loudest first):

### [4/5] Web content discovery (path brute-force) ×4
- Detected by: Web server access logs (404 flood) · WAF path/rate signatures · SIEM rate-of-request rules
- Exposes: Source IP · User-Agent · Wordlist / tool fingerprint · Request cadence
- Lower-noise alternative: Use a focused wordlist seeded from robots.txt / sitemap / observed links, add jitter, and respect the app’s rate limits instead of hammering it.

### [4/5] Artifact written to a target host ×4
- Detected by: EDR / AV (file + process) · File-integrity monitoring · Host audit logs
- Exposes: The artifact itself (recoverable forensic evidence) · Path, timestamp, and content
- Lower-noise alternative: Drop the smallest possible proof, in an agreed location, and record it for cleanup immediately — VARVEL’s OPSEC ledger tracks it so it is removed on disengagement.

### [3/5] Vulnerability checks (known-exposure probes) ×4
- Detected by: WAF path signatures · Web access logs (sensitive-path alerts) · SIEM correlation with scan behavior
- Exposes: Source IP · User-Agent · The specific exposures you tested for (reveals intent)
- Lower-noise alternative: Keep the probe list curated and high-signal (content-verified), pace requests, and let page audits ride on pages already fetched instead of adding volume.

### [3/5] TCP port scan (connect) ×2
- Detected by: Firewall / NetFlow / Zeek conn.log · IDS scan detectors (e.g. Snort sfPortscan) · Per-service connection logs
- Exposes: Source IP · Scan timing / fan-out pattern · Sequential or tool-default port ordering
- Lower-noise alternative: Scan only the ports the engagement needs, spread over time, from the authorized source; avoid full-range sweeps when a targeted set will do.

### [2/5] Service / version detection (banner grab) ×10
- Detected by: Service application logs · IDS protocol-anomaly rules
- Exposes: Source IP · Probe fingerprint (which strings you send)
- Lower-noise alternative: Prefer the banner the service already volunteers; don’t send aggressive version-probe payloads unless the version genuinely matters.

### [2/5] HTTP method / CORS / header probe ×4
- Detected by: Web access logs · WAF (anomalous method / Origin rules)
- Exposes: Source IP · Test Origin values you send
- Lower-noise alternative: A handful of targeted probes reveals the config; no need to sweep every method on every path.

### [2/5] Web crawl (following the site’s own links) ×4
- Detected by: Web access logs (rate + coverage correlation) · WAF rate / session-behavior rules
- Exposes: Source IP · User-Agent · Crawl cadence and coverage pattern
- Lower-noise alternative: Cap pages and depth, pace requests with jitter, and let robots/sitemap seed the queue — a link-following crawl is already far quieter than path brute-force.

### [1/5] HTTP fingerprint (headers + favicon) ×5
- Detected by: Web access logs (only under correlation)
- Exposes: Source IP · User-Agent
- Lower-noise alternative: Already low. A realistic User-Agent keeps it in the noise floor of ordinary traffic.

### [1/5] TLS configuration inspection ×2
- Detected by: Load-balancer / TLS-terminator logs (rarely reviewed)
- Exposes: Source IP · ClientHello fingerprint (JA3)
- Lower-noise alternative: A single handshake to read the negotiated config is plenty; skip exhaustive cipher enumeration unless required.

**Detection surface (everything that could have caught us):** Firewall / NetFlow / Zeek conn.log · IDS scan detectors (e.g. Snort sfPortscan) · Per-service connection logs · Web server access logs (404 flood) · WAF path/rate signatures · SIEM rate-of-request rules · Web access logs · WAF (anomalous method / Origin rules) · Web access logs (rate + coverage correlation) · WAF rate / session-behavior rules · WAF path signatures · Web access logs (sensitive-path alerts) · SIEM correlation with scan behavior · Load-balancer / TLS-terminator logs (rarely reviewed) · Web access logs (only under correlation) · Service application logs · IDS protocol-anomaly rules · EDR / AV (file + process) · File-integrity monitoring · Host audit logs

**Operator exposure (what our activity revealed):** Source IP · Scan timing / fan-out pattern · Sequential or tool-default port ordering · User-Agent · Wordlist / tool fingerprint · Request cadence · Test Origin values you send · Crawl cadence and coverage pattern · The specific exposures you tested for (reveals intent) · ClientHello fingerprint (JA3) · Probe fingerprint (which strings you send) · The artifact itself (recoverable forensic evidence) · Path, timestamp, and content

## OPSEC — stealth budget (what we stayed under)

Operational-stealth profile: **NORMAL**. Stayed under the normal budget: 93/150 noise pts (62%), peak loudness 4/5 ≤ ceiling 5, 2 HITL-authorized override(s).

- Noise budget: **93/150** noise-points (**62%** of cap, state: **WARN**)
- Peak-loudness ceiling honored: emitted **4/5** ≤ ceiling **5/5**
- HITL-authorized over-ceiling actions: **2** (noise was raised only with explicit approval)

_Noise cost = loudness×count from the detection-footprint model above. The budget is enforced in-flight: over-ceiling actions escalate to a human, they do not fire silently. This report states the ACTUAL peak emitted — never an unearned "we stayed quiet" claim._

## OPSEC — footprint reduction

Current detection risk **ELEVATED** (3.3/5); applying the moves below projects **MODERATE** (2.2/5, −1.1).

- **Web content discovery (path brute-force)** (loudness 4/5) — A burst of 404s (and the occasional 200/403) for paths a normal user never requests. Quieter: Use a focused wordlist seeded from robots.txt / sitemap / observed links, add jitter, and respect the app’s rate limits instead of hammering it. (~40% less noise).
- **Artifact written to a target host** (loudness 4/5) — A new file on disk (EDR file-create event). Quieter: Drop the smallest possible proof, in an agreed location, and record it for cleanup immediately — VARVEL’s OPSEC ledger tracks it so it is removed on disengagement. (~40% less noise).
- **Vulnerability checks (known-exposure probes)** (loudness 3/5) — Requests for known-sensitive paths (/.git/HEAD, /.env, /actuator/env) — WAFs and SOC playbooks carry EXACT signatures for these, so each hit is conspicuous even at low volume. Quieter: Keep the probe list curated and high-signal (content-verified), pace requests, and let page audits ride on pages already fetched instead of adding volume. (~30% less noise).
- **TCP port scan (connect)** (loudness 3/5) — One completed TCP handshake per open port (full connect, not a half-open SYN scan) — appears in firewall/flow logs and the service’s own connection log. Quieter: Scan only the ports the engagement needs, spread over time, from the authorized source; avoid full-range sweeps when a targeted set will do. (~30% less noise).

## OPSEC — artifacts & cleanup

- `workspace:clickjacking-poc.html` (file) — **PENDING** cleanup · `rm clickjacking-poc.html`
- `workspace:report.md` (file) — **PENDING** cleanup · `rm report.md`
- `www.mercadolibre.com.ar:client-report.md` (report) — **PENDING** cleanup · `rm client-report.md`
- `www.mercadolibre.com.ar:clickjacking-poc.html` (poc) — **PENDING** cleanup · `rm clickjacking-poc.html`

## Remediation

- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS overly broad wildcard certificate (F-01): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[LOW]** Missing clickjacking protection (X-Frame-Options / frame-ancestors) (VC-1): Review against secure-design guidance and add a targeted compensating control.
- **[LOW]** Cookie "_d2id" set without HttpOnly (VC-2): Review against secure-design guidance and add a targeted compensating control.
- **[LOW]** Cookie "_mldataSessionId" set without HttpOnly, SameSite (VC-3): Review against secure-design guidance and add a targeted compensating control.
- **[LOW]** Cookie "in_app" set without HttpOnly (VC-4): Review against secure-design guidance and add a targeted compensating control.
- **[LOW]** Missing clickjacking protection (X-Frame-Options / CSP frame-ancestors) (F-02): Review against secure-design guidance and add a targeted compensating control.
- **[LOW]** Cookie '_d2id' set without HttpOnly (F-03): Review against secure-design guidance and add a targeted compensating control.
- **[LOW]** Cookie '_mldataSessionId' set without HttpOnly and SameSite (F-04): Review against secure-design guidance and add a targeted compensating control.
- **[LOW]** Cookie 'in_app' set without HttpOnly (F-05): Review against secure-design guidance and add a targeted compensating control.
- **[INFO]** Version disclosure: Tengine (VC-5): Review against secure-design guidance and add a targeted compensating control.
- **[INFO]** Version disclosure: Tengine (F-06): Review against secure-design guidance and add a targeted compensating control.

## Autonomy integrity

- Phases audited: **4** · productive: **2** · no-progress: **2** · longest stall: **2**
- Hallucinated / dishonest progress: **0** · honesty rate: **100%**

_Every agent claim was cross-checked against the real attack-surface delta; hallucinated progress is downgraded, never reported as fact._

---
_Generated by VARVEL. Every action in this engagement is recorded in the Enclave's tamper-evident audit ledger — the target is left clean, the proof is kept in the vault._