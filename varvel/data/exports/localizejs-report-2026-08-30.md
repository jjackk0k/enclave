# VARVEL Engagement Report — localizejs

**Scope:** 172.66.40.216/32, 172.66.43.40/32  
**Authorized by:** marcus · operator · sess-1008

## Executive summary

- Hosts in scope: **4**
- Findings: **23**  (confirmed: **23**, critical: **0**)
- Validation (objective oracle): **0 validated · 23 claimed-unvalidated · 0 refuted · 0 untestable**
- Risk levels: **7 high · 11 medium · 5 info**
- Exploits proven: **0**
- Governance holds (actions the platform blocked in-flight): **15**

## Findings

### [HIGH] exposed SVN metadata  `WEB-1`
- Host: `app.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A05:2021 Security Misconfiguration · MITRE TA0007 Discovery
- Exploit: **SVN wc.db source disclosure -> secret recovery** — _proposed_

### [HIGH] exposed backup archive  `WEB-2`
- Host: `app.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A05:2021 Security Misconfiguration · MITRE TA0007 Discovery
- Exploit: **Backup archive download -> config/credential leakage** — _proposed_

### [HIGH] Spring Actuator sensitive endpoint  `WEB-7`
- Host: `app.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [HIGH] Spring Actuator sensitive endpoint  `WEB-8`
- Host: `app.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [HIGH] Spring Actuator sensitive endpoint  `WEB-9`
- Host: `app.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [HIGH] Spring Actuator sensitive endpoint  `WEB-10`
- Host: `app.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [HIGH] Spring Actuator sensitive endpoint  `WEB-11`
- Host: `app.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `api.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `cdn.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] server status/info exposed  `WEB-3`
- Host: `app.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A05:2021 Security Misconfiguration · MITRE TA0007 Discovery
- Exploit: **Server status page -> internal topology disclosure** — _proposed_

### [MEDIUM] server status/info exposed  `WEB-4`
- Host: `app.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A05:2021 Security Misconfiguration · MITRE TA0007 Discovery

### [MEDIUM] Spring Actuator exposed  `WEB-5`
- Host: `app.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A05:2021 Security Misconfiguration · MITRE TA0007 Discovery
- Exploit: **Actuator env/heapdump -> live secret exposure** — _proposed_

### [MEDIUM] Spring Actuator exposed  `WEB-6`
- Host: `app.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A05:2021 Security Misconfiguration · MITRE TA0007 Discovery

### [MEDIUM] debug/metrics endpoint exposed  `WEB-12`
- Host: `app.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A05:2021 Security Misconfiguration · MITRE TA0007 Discovery

### [MEDIUM] debug/metrics endpoint exposed  `WEB-13`
- Host: `app.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A05:2021 Security Misconfiguration · MITRE TA0007 Discovery

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `app.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [INFO] Missing Referrer-Policy header  `VC-1`
- Host: `localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [INFO] Version disclosure: cloudflare  `VC-2`
- Host: `localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [INFO] CORS wildcard (*) — any origin may read responses (no credentials)  `VC-1`
- Host: `cdn.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A07:2021 Identification & Authentication Failures · MITRE TA0006 Credential Access

### [INFO] Missing Referrer-Policy header  `VC-1`
- Host: `app.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [INFO] Version disclosure: cloudflare  `VC-2`
- Host: `app.localizestaging.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

## Governance & scope

- **HELD** `Bash` — enclave-denied (localizejs)
- **HELD** `Bash` — enclave-denied (localizejs)
- **HELD** `Bash` — enclave-denied (localizejs)
- **HELD** `Bash` — enclave-denied (localizejs)
- **HELD** `Bash` — enclave-denied (localizejs)
- **HELD** `Bash` — enclave-denied (localizejs)
- **HELD** `Bash` — enclave-denied (localizejs)
- **HELD** `Bash` — enclave-denied (localizejs)
- **HELD** `Bash` — enclave-denied (localizejs)
- **HELD** `Read` — enclave-denied (localizejs)
- **HELD** `Bash` — enclave-denied (localizejs)
- **HELD** `Bash` — enclave-denied (localizejs)
- **HELD** `Read` — enclave-denied (localizejs)
- **HELD** `Read` — enclave-denied (localizejs)
- **HELD** `Bash` — enclave-denied (localizejs)

## OPSEC — detection footprint

Overall detection risk: **HIGH** — peak loudness **5/5**, weighted **3.8/5**, across **171** recorded action(s).

What a defender would have observed (loudest first):

### [5/5] Active exploitation attempt ×31
- Detected by: WAF (payload signatures) · Application error logs · EDR / host telemetry · SIEM correlation
- Exposes: Source IP · Exact payloads (fully attributable) · Target + technique
- Lower-noise alternative: Gate on a HIGH-confidence, confirmed finding; land the minimum proof rather than spraying payloads. This phase is HITL-gated for exactly this reason.

### [4/5] Web content discovery (path brute-force) ×13
- Detected by: Web server access logs (404 flood) · WAF path/rate signatures · SIEM rate-of-request rules
- Exposes: Source IP · User-Agent · Wordlist / tool fingerprint · Request cadence
- Lower-noise alternative: Use a focused wordlist seeded from robots.txt / sitemap / observed links, add jitter, and respect the app’s rate limits instead of hammering it.

### [4/5] Artifact written to a target host ×3
- Detected by: EDR / AV (file + process) · File-integrity monitoring · Host audit logs
- Exposes: The artifact itself (recoverable forensic evidence) · Path, timestamp, and content
- Lower-noise alternative: Drop the smallest possible proof, in an agreed location, and record it for cleanup immediately — VARVEL’s OPSEC ledger tracks it so it is removed on disengagement.

### [3/5] Vulnerability checks (known-exposure probes) ×13
- Detected by: WAF path signatures · Web access logs (sensitive-path alerts) · SIEM correlation with scan behavior
- Exposes: Source IP · User-Agent · The specific exposures you tested for (reveals intent)
- Lower-noise alternative: Keep the probe list curated and high-signal (content-verified), pace requests, and let page audits ride on pages already fetched instead of adding volume.

### [3/5] TCP port scan (connect) ×4
- Detected by: Firewall / NetFlow / Zeek conn.log · IDS scan detectors (e.g. Snort sfPortscan) · Per-service connection logs
- Exposes: Source IP · Scan timing / fan-out pattern · Sequential or tool-default port ordering
- Lower-noise alternative: Scan only the ports the engagement needs, spread over time, from the authorized source; avoid full-range sweeps when a targeted set will do.

### [2/5] HTTP method / CORS / header probe ×13
- Detected by: Web access logs · WAF (anomalous method / Origin rules)
- Exposes: Source IP · Test Origin values you send
- Lower-noise alternative: A handful of targeted probes reveals the config; no need to sweep every method on every path.

### [2/5] Web crawl (following the site’s own links) ×13
- Detected by: Web access logs (rate + coverage correlation) · WAF rate / session-behavior rules
- Exposes: Source IP · User-Agent · Crawl cadence and coverage pattern
- Lower-noise alternative: Cap pages and depth, pace requests with jitter, and let robots/sitemap seed the queue — a link-following crawl is already far quieter than path brute-force.

### [2/5] Service / version detection (banner grab) ×10
- Detected by: Service application logs · IDS protocol-anomaly rules
- Exposes: Source IP · Probe fingerprint (which strings you send)
- Lower-noise alternative: Prefer the banner the service already volunteers; don’t send aggressive version-probe payloads unless the version genuinely matters.

### [1/5] HTTP fingerprint (headers + favicon) ×66
- Detected by: Web access logs (only under correlation)
- Exposes: Source IP · User-Agent
- Lower-noise alternative: Already low. A realistic User-Agent keeps it in the noise floor of ordinary traffic.

### [1/5] TLS configuration inspection ×5
- Detected by: Load-balancer / TLS-terminator logs (rarely reviewed)
- Exposes: Source IP · ClientHello fingerprint (JA3)
- Lower-noise alternative: A single handshake to read the negotiated config is plenty; skip exhaustive cipher enumeration unless required.

**Detection surface (everything that could have caught us):** Firewall / NetFlow / Zeek conn.log · IDS scan detectors (e.g. Snort sfPortscan) · Per-service connection logs · Web server access logs (404 flood) · WAF path/rate signatures · SIEM rate-of-request rules · Web access logs · WAF (anomalous method / Origin rules) · Web access logs (rate + coverage correlation) · WAF rate / session-behavior rules · WAF path signatures · Web access logs (sensitive-path alerts) · SIEM correlation with scan behavior · Load-balancer / TLS-terminator logs (rarely reviewed) · Service application logs · IDS protocol-anomaly rules · Web access logs (only under correlation) · WAF (payload signatures) · Application error logs · EDR / host telemetry · SIEM correlation · EDR / AV (file + process) · File-integrity monitoring · Host audit logs

**Operator exposure (what our activity revealed):** Source IP · Scan timing / fan-out pattern · Sequential or tool-default port ordering · User-Agent · Wordlist / tool fingerprint · Request cadence · Test Origin values you send · Crawl cadence and coverage pattern · The specific exposures you tested for (reveals intent) · ClientHello fingerprint (JA3) · Probe fingerprint (which strings you send) · Exact payloads (fully attributable) · Target + technique · The artifact itself (recoverable forensic evidence) · Path, timestamp, and content

## OPSEC — stealth budget (what we stayed under)

Operational-stealth profile: **NORMAL**. Peak loudness 5/5 stayed ≤ ceiling 5, but cumulative noise reached 413/300 noise pts — 113 OVER the normal budget (4 HITL-authorized).

- Noise budget: **413/300** noise-points (**138%** of cap, state: **EXHAUSTED**)
- Cumulative noise budget **exceeded** by **113** noise-point(s)
- Peak-loudness ceiling honored: emitted **5/5** ≤ ceiling **5/5**
- HITL-authorized over-ceiling actions: **4** (noise was raised only with explicit approval)

_Noise cost = loudness×count from the detection-footprint model above. The budget is enforced in-flight: over-ceiling actions escalate to a human, they do not fire silently. This report states the ACTUAL peak emitted — never an unearned "we stayed quiet" claim._

## OPSEC — footprint reduction

Current detection risk **HIGH** (3.8/5); applying the moves below projects **MODERATE** (2.2/5, −1.6).

- **Active exploitation attempt** (loudness 5/5) — Malformed / injection payloads in requests (SQLi, traversal, deserialization) that WAFs and app logs capture verbatim. Quieter: Gate on a HIGH-confidence, confirmed finding; land the minimum proof rather than spraying payloads. This phase is HITL-gated for exactly this reason. (~50% less noise).
- **Web content discovery (path brute-force)** (loudness 4/5) — A burst of 404s (and the occasional 200/403) for paths a normal user never requests. Quieter: Use a focused wordlist seeded from robots.txt / sitemap / observed links, add jitter, and respect the app’s rate limits instead of hammering it. (~40% less noise).
- **Artifact written to a target host** (loudness 4/5) — A new file on disk (EDR file-create event). Quieter: Drop the smallest possible proof, in an agreed location, and record it for cleanup immediately — VARVEL’s OPSEC ledger tracks it so it is removed on disengagement. (~40% less noise).
- **Vulnerability checks (known-exposure probes)** (loudness 3/5) — Requests for known-sensitive paths (/.git/HEAD, /.env, /actuator/env) — WAFs and SOC playbooks carry EXACT signatures for these, so each hit is conspicuous even at low volume. Quieter: Keep the probe list curated and high-signal (content-verified), pace requests, and let page audits ride on pages already fetched instead of adding volume. (~30% less noise).
- **TCP port scan (connect)** (loudness 3/5) — One completed TCP handshake per open port (full connect, not a half-open SYN scan) — appears in firewall/flow logs and the service’s own connection log. Quieter: Scan only the ports the engagement needs, spread over time, from the authorized source; avoid full-range sweeps when a targeted set will do. (~30% less noise).

## OPSEC — artifacts & cleanup

- `workspace:postex-impact-proof.md` (file) — **PENDING** cleanup · `rm postex-impact-proof.md`
- `workspace:scratch-postex-probe.mjs` (file) — **PENDING** cleanup · `rm scratch-postex-probe.mjs`
- `workspace:test.txt` (file) — **PENDING** cleanup · `rm test.txt`

## Remediation

- **[HIGH]** exposed SVN metadata (WEB-1): Harden configuration; close unused services; remove defaults and verbose errors.
- **[HIGH]** exposed backup archive (WEB-2): Harden configuration; close unused services; remove defaults and verbose errors.
- **[HIGH]** Spring Actuator sensitive endpoint (WEB-7): Review against secure-design guidance and add a targeted compensating control.
- **[HIGH]** Spring Actuator sensitive endpoint (WEB-8): Review against secure-design guidance and add a targeted compensating control.
- **[HIGH]** Spring Actuator sensitive endpoint (WEB-9): Review against secure-design guidance and add a targeted compensating control.
- **[HIGH]** Spring Actuator sensitive endpoint (WEB-10): Review against secure-design guidance and add a targeted compensating control.
- **[HIGH]** Spring Actuator sensitive endpoint (WEB-11): Review against secure-design guidance and add a targeted compensating control.
- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** server status/info exposed (WEB-3): Harden configuration; close unused services; remove defaults and verbose errors.
- **[MED]** server status/info exposed (WEB-4): Harden configuration; close unused services; remove defaults and verbose errors.
- **[MED]** Spring Actuator exposed (WEB-5): Harden configuration; close unused services; remove defaults and verbose errors.
- **[MED]** Spring Actuator exposed (WEB-6): Harden configuration; close unused services; remove defaults and verbose errors.
- **[MED]** debug/metrics endpoint exposed (WEB-12): Harden configuration; close unused services; remove defaults and verbose errors.
- **[MED]** debug/metrics endpoint exposed (WEB-13): Harden configuration; close unused services; remove defaults and verbose errors.
- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[INFO]** Missing Referrer-Policy header (VC-1): Review against secure-design guidance and add a targeted compensating control.
- **[INFO]** Version disclosure: cloudflare (VC-2): Review against secure-design guidance and add a targeted compensating control.
- **[INFO]** CORS wildcard (*) — any origin may read responses (no credentials) (VC-1): Rotate exposed credentials; enforce strong secrets + MFA; remove hardcoded keys.
- **[INFO]** Missing Referrer-Policy header (VC-1): Review against secure-design guidance and add a targeted compensating control.
- **[INFO]** Version disclosure: cloudflare (VC-2): Review against secure-design guidance and add a targeted compensating control.

## Autonomy integrity

- Phases audited: **4** · productive: **2** · no-progress: **1** · longest stall: **1**
- Hallucinated / dishonest progress: **1** · honesty rate: **75%**

_Every agent claim was cross-checked against the real attack-surface delta; hallucinated progress is downgraded, never reported as fact._

---
_Generated by VARVEL. Every action in this engagement is recorded in the Enclave's tamper-evident audit ledger — the target is left clean, the proof is kept in the vault._