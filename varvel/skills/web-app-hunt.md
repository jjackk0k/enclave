---
name: Web application hunt (national-level chain)
category: web
keywords: [web, hunt, recon, nuclei, httpx, katana, ffuf, cors, idor, jwt, ssrf, authz, xss, sqli, chain, poc, report]
---
A full external web-app hunt run as a governed chain: scope → passive recon → active recon → template scan → manual exploitation → chained impact → report. Every step is read-mostly and in-scope; exploit + post-ex are HITL-gated (Enclave rule). The goal is a *chained, demonstrated* impact, not a list of findings.

## Where to look
- Entry points: subdomains (subfinder/amass + certificate transparency), vhosts, admin surfaces (/admin, /api, /wp-admin, /actuator, /.env, /backup.zip), old subdomains still resolving, CDN vs origin split.
- Parameters that change data: auth boundaries (IDOR), upload paths, redirect params (open redirect → token theft), CORS config, JWT claims, rate-limited auth endpoints.
- Business logic: price fields, coupon/race conditions, privilege escalation paths, workflow skips. This is where scanners stop and value begins.
- Third-party: SRI-less scripts, exposed panes (GraphQL introspection, swagger, debug endpoints), dependency CVEs (nuclei exposure templates).

## How to detect (tools + signals)
1. **Recon**: `subfinder -d target` → `httpx -l subs.txt -title -tech-detect -status-code` → alive map. `katana` crawl for endpoints + params. `ffuf` only on explicitly scoped paths.
2. **Template scan**: `nuclei -l alive.txt -t exposures/,misconfiguration/,cves/` first (low-noise, high-signal). Then targeted tech templates (sqli, xss, ssrf, idor, rce) — never the full aggressive set on a live client site.
3. **Manual passes** (where the real findings live):
   - CORS: `Origin: https://evil.test` on sensitive endpoints → check `Access-Control-Allow-Credentials: true` reflection. Prove with a read of a victim-only resource (cors-prover pattern).
   - IDOR: enumerate sibling IDs across roles; prove *significant* impact only (no PII-only IDOR outside mVDP — see bounty doctrine).
   - Auth: JWT alg-confusion / none / weak secret; session fixation; password-reset token reuse; 2FA skip paths.
   - Chaining: open-redirect + token in URL → full session theft. This is the classic "low+low=high".
4. **LLM layer (you)**: triage the template output (most is noise), write the PoC scripts, review authz code paths when source is available, draft the report. You do NOT invent findings — every claim needs a captured request/response or a deterministic repro.

## How to confirm
- Reproduce each finding twice, capture exact request + response, timestamp it.
- For chained impact, demonstrate the end state (e.g., read another org's resource), then stop — no data exfiltration, no modification, no persistence.
- Least-invasive proof first: a version string beats a dump; a boolean pair beats a UNION of user rows.
- If a "finding" cannot be re-proven in one command, it is not a finding — log it in the failure ledger so the next session doesn't repeat it.

## LLM reality check (measured, Aug-2026 behavioural audits)
- LLMs are strong at: triage speed, PoC scripting, code-review of authz boundaries, report writing, cross-finding chaining *when given the evidence*.
- LLMs are weak at: end-to-end reliability without a tool harness (agents drift off-goal), impact inflation (hallucinated severity), scope discipline, and anything requiring a live interactive browser session with JS-heavy auth.
- Rule: an LLM finding ships only with deterministic evidence. A human (operator) decides severity and files it. Never click Submit.

## National-level bar (NCSC / MITRE alignment)
- Map every confirmed finding to MITRE ATT&CK tactic + OWASP 2021 category in the report (engine/classify.mjs does this — use it).
- Severity = exploitability × impact × prevalence. A CVSS number without a demonstrated chain is a starting point, not a conclusion.
- Context that matters in 2026: ~50k CVEs/year and median time-to-exploit now *before* disclosure — patch-urgency framing is what makes a report actionable to a client.

## Report shape
1. Executive summary (one paragraph: what, impact, urgency).
2. Findings table: id, title, severity, MITRE/OWASP, affected asset.
3. Per finding: reproduction (copy-paste commands), evidence (request/response excerpts, redacted), impact, remediation (concrete config, not "be careful").
4. Governance appendix: scope, timestamps, cleanup status, detection-footprint notes.

## Common variations
- **Prospect scan (commercial, lightweight)**: alive map + security headers + TLS config + CORS + exposure templates ONLY. No active injection. This is the "free scan" offer — safe to run on a prospect's own site with their permission, and the output maps 1:1 to our security-hardening add-on.
- **WordPress bounty lane**: follow AGENTS.md scope doctrine (kill classes, auth bands, rejection-rate math) — see docs/AGENT-GUIDE.md.
- **Internal network**: after web foothold; CIDR-locked, callback-channel governed (varvel-channel), verified teardown mandatory.