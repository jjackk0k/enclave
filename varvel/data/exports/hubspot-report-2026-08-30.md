# VARVEL Engagement Report — hubspot

**Scope:** 100.57.9.83/32, 104.17.91.187/32, 104.17.92.187/32, 104.18.33.148/32, 104.18.36.53/32, 104.18.40.10/32, 104.18.41.33/32, 104.21.48.60/32, 104.21.93.135/32, 141.101.90.96/32, 141.101.90.97/32, 141.101.90.98/32, 141.101.90.99/32, 158.247.21.105/32, 158.247.24.219/32, 158.247.30.48/32, 172.64.146.223/32, 172.64.147.246/32, 172.64.151.203/32, 172.64.154.108/32, 172.65.193.34/32, 172.65.202.85/32, 172.67.179.211/32, 172.67.210.49/32, 18.155.153.111/32, 18.155.153.120/32, 18.155.153.16/32, 18.155.153.78/32, 198.37.146.112/32, 199.60.103.2/32, 199.60.103.225/32, 199.60.103.226/32, 199.60.103.228/32, 199.60.103.254/32, 199.60.103.28/32, 199.60.103.30/32, 199.60.103.31/32, 216.139.84.161/32, 216.139.84.162/32, 216.139.84.163/32, 2606:2c40::c73c:6702/128, 2606:2c40::c73c:671c/128, 2606:2c40::c73c:671e/128, 2606:2c40::c73c:671f/128, 2606:2c40::c73c:67e1/128, 2606:2c40::c73c:67e2/128, 2606:2c40::c73c:67e4/128, 2606:2c40::c73c:67fe/128, 2606:4700:4401::ac40:92df/128, 2606:4700:4407::6812:2194/128, 2606:4700:4408::6812:2921/128, 2606:4700:440a::ac40:9a6c/128, 2606:4700:440c::ac40:97cb/128, 2606:4700::6811:5bbb/128, 2606:4700::6811:5cbb/128, 2a06:98c1:3109::6812:2435/128, 2a06:98c1:310a::6812:280a/128, 2a06:98c1:310a::ac40:93f6/128, 2a06:98c1:3200::90:0/128, 2a06:98c1:3200::90:1/128, 2a06:98c1:3200::90:2/128, 2a06:98c1:3200::90:3/128, 3.222.100.45/32, 3.93.157.191/32, 32.193.106.79/32, 32.196.13.194/32, 35.168.196.219/32, 50.31.44.101/32, 52.207.31.93/32, 54.174.52.33/32, 54.174.52.34/32  
**Authorized by:** marcus · operator · sess-1018

## Executive summary

- Hosts in scope: **26**
- Findings: **22**  (confirmed: **12**, critical: **0**)
- Validation (objective oracle): **0 validated · 22 claimed-unvalidated · 0 refuted · 0 untestable**
- Risk levels: **0 high · 22 medium · 0 info**
- Exploits proven: **0**
- Governance holds (actions the platform blocked in-flight): **3**

## Findings

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `app.hubspot.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection
- Exploit: **virtual-host confusion via shared edge IP** — _proposed_

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `app.hubspot.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `app-na1.hubspot.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `app-na1.hubspot.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `app-na2.hubspot.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `app-na2.hubspot.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `app-eu1.hubspot.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `app-eu1.hubspot.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `app-ap1.hubspot.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `app-ap1.hubspot.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `api.hubspot.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `TLS-WILDCARD-BROAD`
- Host: `api.hubspot.com` · confidence: **CONFIRMED** (85%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `F-TLS-01`
- Host: `admins.hubspot.com` · confidence: **SUSPECTED** (69%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Note: _validator gate: no objective oracle cited_
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `F-TLS-02`
- Host: `app.hubspot.com` · confidence: **SUSPECTED** (69%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Note: _validator gate: no objective oracle cited_
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `F-TLS-03`
- Host: `app-na1.hubspot.com` · confidence: **SUSPECTED** (69%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Note: _validator gate: no objective oracle cited_
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `F-TLS-04`
- Host: `app-na2.hubspot.com` · confidence: **SUSPECTED** (69%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Note: _validator gate: no objective oracle cited_
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `F-TLS-05`
- Host: `app-eu1.hubspot.com` · confidence: **SUSPECTED** (69%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Note: _validator gate: no objective oracle cited_
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `F-TLS-06`
- Host: `app-ap1.hubspot.com` · confidence: **SUSPECTED** (69%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Note: _validator gate: no objective oracle cited_
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `F-TLS-07`
- Host: `api.hubspot.com` · confidence: **SUSPECTED** (69%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Note: _validator gate: no objective oracle cited_
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `F-TLS-08`
- Host: `api-na1.hubspot.com` · confidence: **SUSPECTED** (69%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Note: _validator gate: no objective oracle cited_
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `F-TLS-09`
- Host: `api-na2.hubspot.com` · confidence: **SUSPECTED** (69%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Note: _validator gate: no objective oracle cited_
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

### [MEDIUM] TLS: overly broad wildcard certificate  `F-TLS-10`
- Host: `api-eu1.hubspot.com` · confidence: **SUSPECTED** (69%)
- Validation: **CLAIMED-UNVALIDATED** — never reproduced by the validator gate
- Note: _validator gate: no objective oracle cited_
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

## Governance & scope

- **HELD** `Read` — enclave-denied (hubspot)
- **HELD** `Write` — enclave-denied (hubspot)
- **HELD** `Bash` — enclave-denied (hubspot)

- Tool-lane budget (jsminer / OOB / DOM-XSS canary / authz seeding — a bucket SEPARATE from the agent step and noise budgets): **0/200** governed requests, wall-clock cap **600s** — not exhausted.

## OPSEC — detection footprint

Overall detection risk: **HIGH** — peak loudness **5/5**, weighted **4/5**, across **198** recorded action(s).

What a defender would have observed (loudest first):

### [5/5] Active exploitation attempt ×22
- Detected by: WAF (payload signatures) · Application error logs · EDR / host telemetry · SIEM correlation
- Exposes: Source IP · Exact payloads (fully attributable) · Target + technique
- Lower-noise alternative: Gate on a HIGH-confidence, confirmed finding; land the minimum proof rather than spraying payloads. This phase is HITL-gated for exactly this reason.

### [4/5] Web content discovery (path brute-force) ×28
- Detected by: Web server access logs (404 flood) · WAF path/rate signatures · SIEM rate-of-request rules
- Exposes: Source IP · User-Agent · Wordlist / tool fingerprint · Request cadence
- Lower-noise alternative: Use a focused wordlist seeded from robots.txt / sitemap / observed links, add jitter, and respect the app’s rate limits instead of hammering it.

### [4/5] Artifact written to a target host ×4
- Detected by: EDR / AV (file + process) · File-integrity monitoring · Host audit logs
- Exposes: The artifact itself (recoverable forensic evidence) · Path, timestamp, and content
- Lower-noise alternative: Drop the smallest possible proof, in an agreed location, and record it for cleanup immediately — VARVEL’s OPSEC ledger tracks it so it is removed on disengagement.

### [3/5] Vulnerability checks (known-exposure probes) ×28
- Detected by: WAF path signatures · Web access logs (sensitive-path alerts) · SIEM correlation with scan behavior
- Exposes: Source IP · User-Agent · The specific exposures you tested for (reveals intent)
- Lower-noise alternative: Keep the probe list curated and high-signal (content-verified), pace requests, and let page audits ride on pages already fetched instead of adding volume.

### [3/5] TCP port scan (connect) ×26
- Detected by: Firewall / NetFlow / Zeek conn.log · IDS scan detectors (e.g. Snort sfPortscan) · Per-service connection logs
- Exposes: Source IP · Scan timing / fan-out pattern · Sequential or tool-default port ordering
- Lower-noise alternative: Scan only the ports the engagement needs, spread over time, from the authorized source; avoid full-range sweeps when a targeted set will do.

### [2/5] HTTP method / CORS / header probe ×28
- Detected by: Web access logs · WAF (anomalous method / Origin rules)
- Exposes: Source IP · Test Origin values you send
- Lower-noise alternative: A handful of targeted probes reveals the config; no need to sweep every method on every path.

### [2/5] Web crawl (following the site’s own links) ×28
- Detected by: Web access logs (rate + coverage correlation) · WAF rate / session-behavior rules
- Exposes: Source IP · User-Agent · Crawl cadence and coverage pattern
- Lower-noise alternative: Cap pages and depth, pace requests with jitter, and let robots/sitemap seed the queue — a link-following crawl is already far quieter than path brute-force.

### [2/5] Service / version detection (banner grab) ×20
- Detected by: Service application logs · IDS protocol-anomaly rules
- Exposes: Source IP · Probe fingerprint (which strings you send)
- Lower-noise alternative: Prefer the banner the service already volunteers; don’t send aggressive version-probe payloads unless the version genuinely matters.

### [1/5] TLS configuration inspection ×14
- Detected by: Load-balancer / TLS-terminator logs (rarely reviewed)
- Exposes: Source IP · ClientHello fingerprint (JA3)
- Lower-noise alternative: A single handshake to read the negotiated config is plenty; skip exhaustive cipher enumeration unless required.

**Detection surface (everything that could have caught us):** Firewall / NetFlow / Zeek conn.log · IDS scan detectors (e.g. Snort sfPortscan) · Per-service connection logs · Web server access logs (404 flood) · WAF path/rate signatures · SIEM rate-of-request rules · Web access logs · WAF (anomalous method / Origin rules) · Web access logs (rate + coverage correlation) · WAF rate / session-behavior rules · WAF path signatures · Web access logs (sensitive-path alerts) · SIEM correlation with scan behavior · Load-balancer / TLS-terminator logs (rarely reviewed) · Service application logs · IDS protocol-anomaly rules · WAF (payload signatures) · Application error logs · EDR / host telemetry · SIEM correlation · EDR / AV (file + process) · File-integrity monitoring · Host audit logs

**Operator exposure (what our activity revealed):** Source IP · Scan timing / fan-out pattern · Sequential or tool-default port ordering · User-Agent · Wordlist / tool fingerprint · Request cadence · Test Origin values you send · Crawl cadence and coverage pattern · The specific exposures you tested for (reveals intent) · ClientHello fingerprint (JA3) · Probe fingerprint (which strings you send) · Exact payloads (fully attributable) · Target + technique · The artifact itself (recoverable forensic evidence) · Path, timestamp, and content

## OPSEC — stealth budget (what we stayed under)

Operational-stealth profile: **NORMAL**. Peak loudness 5/5 stayed ≤ ceiling 5, but cumulative noise reached 566/300 noise pts — 266 OVER the normal budget (5 HITL-authorized).

- Noise budget: **566/300** noise-points (**189%** of cap, state: **EXHAUSTED**)
- Cumulative noise budget **exceeded** by **266** noise-point(s)
- Peak-loudness ceiling honored: emitted **5/5** ≤ ceiling **5/5**
- HITL-authorized over-ceiling actions: **5** (noise was raised only with explicit approval)

_Noise cost = loudness×count from the detection-footprint model above. The budget is enforced in-flight: over-ceiling actions escalate to a human, they do not fire silently. This report states the ACTUAL peak emitted — never an unearned "we stayed quiet" claim._

## OPSEC — footprint reduction

Current detection risk **HIGH** (4/5); applying the moves below projects **MODERATE** (2.3/5, −1.7).

- **Active exploitation attempt** (loudness 5/5) — Malformed / injection payloads in requests (SQLi, traversal, deserialization) that WAFs and app logs capture verbatim. Quieter: Gate on a HIGH-confidence, confirmed finding; land the minimum proof rather than spraying payloads. This phase is HITL-gated for exactly this reason. (~50% less noise).
- **Web content discovery (path brute-force)** (loudness 4/5) — A burst of 404s (and the occasional 200/403) for paths a normal user never requests. Quieter: Use a focused wordlist seeded from robots.txt / sitemap / observed links, add jitter, and respect the app’s rate limits instead of hammering it. (~40% less noise).
- **Artifact written to a target host** (loudness 4/5) — A new file on disk (EDR file-create event). Quieter: Drop the smallest possible proof, in an agreed location, and record it for cleanup immediately — VARVEL’s OPSEC ledger tracks it so it is removed on disengagement. (~40% less noise).
- **Vulnerability checks (known-exposure probes)** (loudness 3/5) — Requests for known-sensitive paths (/.git/HEAD, /.env, /actuator/env) — WAFs and SOC playbooks carry EXACT signatures for these, so each hit is conspicuous even at low volume. Quieter: Keep the probe list curated and high-signal (content-verified), pace requests, and let page audits ride on pages already fetched instead of adding volume. (~30% less noise).
- **TCP port scan (connect)** (loudness 3/5) — One completed TCP handshake per open port (full connect, not a half-open SYN scan) — appears in firewall/flow logs and the service’s own connection log. Quieter: Scan only the ports the engagement needs, spread over time, from the authorized source; avoid full-range sweeps when a targeted set will do. (~30% less noise).

## OPSEC — artifacts & cleanup

- `n/a:exploit-wildcard.json` (chain-plan) — **PENDING** cleanup · `rm exploit-wildcard.json`
- `n/a:test.txt` (probe-file) — **PENDING** cleanup · `rm test.txt`
- `workspace:postex-wildcard-proof.sh` (file) — **PENDING** cleanup · `rm postex-wildcard-proof.sh`
- `workspace:STATUS.md` (file) — **PENDING** cleanup · `rm STATUS.md`

## Remediation

- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (TLS-WILDCARD-BROAD): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (F-TLS-01): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (F-TLS-02): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (F-TLS-03): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (F-TLS-04): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (F-TLS-05): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (F-TLS-06): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (F-TLS-07): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (F-TLS-08): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (F-TLS-09): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- **[MED]** TLS: overly broad wildcard certificate (F-TLS-10): Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.

## Autonomy integrity

- Phases audited: **4** · productive: **3** · no-progress: **0** · longest stall: **1**
- Hallucinated / dishonest progress: **1** · honesty rate: **75%**

_Every agent claim was cross-checked against the real attack-surface delta; hallucinated progress is downgraded, never reported as fact._

---
_Generated by VARVEL. Every action in this engagement is recorded in the Enclave's tamper-evident audit ledger — the target is left clean, the proof is kept in the vault._