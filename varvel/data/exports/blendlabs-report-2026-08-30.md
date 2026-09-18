# VARVEL Engagement Report — blendlabs

**Scope:** 172.65.228.100/32  
**Authorized by:** marcus · operator · sess-1006

## Executive summary

- Hosts in scope: **1**
- Findings: **6**  (confirmed: **6**, critical: **0**)
- Validation (objective oracle): **0 validated · 6 claimed-unvalidated · 0 refuted · 0 untestable**
- Risk levels: **0 high · 5 medium · 1 info**
- Exploits proven: **0**
- Governance holds (actions the platform blocked in-flight): **40**

## Findings

### [LOW] Cookie "device-id" set without Secure  `VC-1`
- Host: `knox.beta.blendlabs.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [LOW] Cookie "selectedProductId" set without HttpOnly, Secure, SameSite  `VC-2`
- Host: `knox.beta.blendlabs.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [LOW] Cookie "previousSelectedProductId" set without HttpOnly, Secure, SameSite  `VC-3`
- Host: `knox.beta.blendlabs.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [LOW] Cookie "loanHydrating" set without HttpOnly, Secure, SameSite  `VC-4`
- Host: `knox.beta.blendlabs.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

### [LOW] Cookie "XSRF-TOKEN" set without HttpOnly  `VC-5`
- Host: `knox.beta.blendlabs.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A07:2021 Identification & Authentication Failures · MITRE TA0006 Credential Access

### [INFO] enclave identity mismatch blocked all in-scope validation  `F-OP-01`
- Host: `knox.beta.blendlabs.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A04:2021 Insecure Design · MITRE TA0043 Reconnaissance

## Governance & scope

- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Glob` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Write` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Read` — enclave-denied (blendlabs)
- **HELD** `Grep` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Write` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Glob` — enclave-denied (blendlabs)
- **HELD** `Glob` — enclave-denied (blendlabs)
- **HELD** `Read` — enclave-denied (blendlabs)
- **HELD** `Read` — enclave-denied (blendlabs)
- **HELD** `Glob` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Write` — enclave-denied (blendlabs)
- **HELD** `Grep` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Glob` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Read` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)
- **HELD** `Read` — enclave-denied (blendlabs)
- **HELD** `Bash` — enclave-denied (blendlabs)

## OPSEC — detection footprint

Overall detection risk: **HIGH** — peak loudness **5/5**, weighted **4/5**, across **29** recorded action(s).

What a defender would have observed (loudest first):

### [5/5] Active exploitation attempt ×6
- Detected by: WAF (payload signatures) · Application error logs · EDR / host telemetry · SIEM correlation
- Exposes: Source IP · Exact payloads (fully attributable) · Target + technique
- Lower-noise alternative: Gate on a HIGH-confidence, confirmed finding; land the minimum proof rather than spraying payloads. This phase is HITL-gated for exactly this reason.

### [4/5] Web content discovery (path brute-force) ×2
- Detected by: Web server access logs (404 flood) · WAF path/rate signatures · SIEM rate-of-request rules
- Exposes: Source IP · User-Agent · Wordlist / tool fingerprint · Request cadence
- Lower-noise alternative: Use a focused wordlist seeded from robots.txt / sitemap / observed links, add jitter, and respect the app’s rate limits instead of hammering it.

### [3/5] Vulnerability checks (known-exposure probes) ×2
- Detected by: WAF path signatures · Web access logs (sensitive-path alerts) · SIEM correlation with scan behavior
- Exposes: Source IP · User-Agent · The specific exposures you tested for (reveals intent)
- Lower-noise alternative: Keep the probe list curated and high-signal (content-verified), pace requests, and let page audits ride on pages already fetched instead of adding volume.

### [3/5] TCP port scan (connect)
- Detected by: Firewall / NetFlow / Zeek conn.log · IDS scan detectors (e.g. Snort sfPortscan) · Per-service connection logs
- Exposes: Source IP · Scan timing / fan-out pattern · Sequential or tool-default port ordering
- Lower-noise alternative: Scan only the ports the engagement needs, spread over time, from the authorized source; avoid full-range sweeps when a targeted set will do.

### [2/5] Service / version detection (banner grab) ×13
- Detected by: Service application logs · IDS protocol-anomaly rules
- Exposes: Source IP · Probe fingerprint (which strings you send)
- Lower-noise alternative: Prefer the banner the service already volunteers; don’t send aggressive version-probe payloads unless the version genuinely matters.

### [2/5] HTTP method / CORS / header probe ×2
- Detected by: Web access logs · WAF (anomalous method / Origin rules)
- Exposes: Source IP · Test Origin values you send
- Lower-noise alternative: A handful of targeted probes reveals the config; no need to sweep every method on every path.

### [2/5] Web crawl (following the site’s own links) ×2
- Detected by: Web access logs (rate + coverage correlation) · WAF rate / session-behavior rules
- Exposes: Source IP · User-Agent · Crawl cadence and coverage pattern
- Lower-noise alternative: Cap pages and depth, pace requests with jitter, and let robots/sitemap seed the queue — a link-following crawl is already far quieter than path brute-force.

### [1/5] TLS configuration inspection
- Detected by: Load-balancer / TLS-terminator logs (rarely reviewed)
- Exposes: Source IP · ClientHello fingerprint (JA3)
- Lower-noise alternative: A single handshake to read the negotiated config is plenty; skip exhaustive cipher enumeration unless required.

**Detection surface (everything that could have caught us):** Firewall / NetFlow / Zeek conn.log · IDS scan detectors (e.g. Snort sfPortscan) · Per-service connection logs · Web server access logs (404 flood) · WAF path/rate signatures · SIEM rate-of-request rules · Web access logs · WAF (anomalous method / Origin rules) · Web access logs (rate + coverage correlation) · WAF rate / session-behavior rules · WAF path signatures · Web access logs (sensitive-path alerts) · SIEM correlation with scan behavior · Load-balancer / TLS-terminator logs (rarely reviewed) · Service application logs · IDS protocol-anomaly rules · WAF (payload signatures) · Application error logs · EDR / host telemetry · SIEM correlation

**Operator exposure (what our activity revealed):** Source IP · Scan timing / fan-out pattern · Sequential or tool-default port ordering · User-Agent · Wordlist / tool fingerprint · Request cadence · Test Origin values you send · Crawl cadence and coverage pattern · The specific exposures you tested for (reveals intent) · ClientHello fingerprint (JA3) · Probe fingerprint (which strings you send) · Exact payloads (fully attributable) · Target + technique

## OPSEC — stealth budget (what we stayed under)

Operational-stealth profile: **NORMAL**. Stayed under the normal budget: 82/250 noise pts (33%), peak loudness 5/5 ≤ ceiling 5, 1 HITL-authorized override(s).

- Noise budget: **82/250** noise-points (**33%** of cap, state: **OK**)
- Peak-loudness ceiling honored: emitted **5/5** ≤ ceiling **5/5**
- HITL-authorized over-ceiling actions: **1** (noise was raised only with explicit approval)

_Noise cost = loudness×count from the detection-footprint model above. The budget is enforced in-flight: over-ceiling actions escalate to a human, they do not fire silently. This report states the ACTUAL peak emitted — never an unearned "we stayed quiet" claim._

## OPSEC — footprint reduction

Current detection risk **HIGH** (4/5); applying the moves below projects **MODERATE** (2.3/5, −1.7).

- **Active exploitation attempt** (loudness 5/5) — Malformed / injection payloads in requests (SQLi, traversal, deserialization) that WAFs and app logs capture verbatim. Quieter: Gate on a HIGH-confidence, confirmed finding; land the minimum proof rather than spraying payloads. This phase is HITL-gated for exactly this reason. (~50% less noise).
- **Web content discovery (path brute-force)** (loudness 4/5) — A burst of 404s (and the occasional 200/403) for paths a normal user never requests. Quieter: Use a focused wordlist seeded from robots.txt / sitemap / observed links, add jitter, and respect the app’s rate limits instead of hammering it. (~40% less noise).
- **Vulnerability checks (known-exposure probes)** (loudness 3/5) — Requests for known-sensitive paths (/.git/HEAD, /.env, /actuator/env) — WAFs and SOC playbooks carry EXACT signatures for these, so each hit is conspicuous even at low volume. Quieter: Keep the probe list curated and high-signal (content-verified), pace requests, and let page audits ride on pages already fetched instead of adding volume. (~30% less noise).
- **TCP port scan (connect)** (loudness 3/5) — One completed TCP handshake per open port (full connect, not a half-open SYN scan) — appears in firewall/flow logs and the service’s own connection log. Quieter: Scan only the ports the engagement needs, spread over time, from the authorized source; avoid full-range sweeps when a targeted set will do. (~30% less noise).

## OPSEC — artifacts & cleanup

_No artifacts were dropped on client systems._

## Remediation

- **[LOW]** Cookie "device-id" set without Secure (VC-1): Review against secure-design guidance and add a targeted compensating control.
- **[LOW]** Cookie "selectedProductId" set without HttpOnly, Secure, SameSite (VC-2): Review against secure-design guidance and add a targeted compensating control.
- **[LOW]** Cookie "previousSelectedProductId" set without HttpOnly, Secure, SameSite (VC-3): Review against secure-design guidance and add a targeted compensating control.
- **[LOW]** Cookie "loanHydrating" set without HttpOnly, Secure, SameSite (VC-4): Review against secure-design guidance and add a targeted compensating control.
- **[LOW]** Cookie "XSRF-TOKEN" set without HttpOnly (VC-5): Rotate exposed credentials; enforce strong secrets + MFA; remove hardcoded keys.
- **[INFO]** enclave identity mismatch blocked all in-scope validation (F-OP-01): Review against secure-design guidance and add a targeted compensating control.

## Autonomy integrity

- Phases audited: **4** · productive: **3** · no-progress: **0** · longest stall: **1**
- Hallucinated / dishonest progress: **1** · honesty rate: **75%**

_Every agent claim was cross-checked against the real attack-surface delta; hallucinated progress is downgraded, never reported as fact._

---
_Generated by VARVEL. Every action in this engagement is recorded in the Enclave's tamper-evident audit ledger — the target is left clean, the proof is kept in the vault._