# How Leading AI Vulnerability Hunters Actually Produce Validated Findings — and What varvel Is Missing

**Date:** 2026-08-30 · **Prepared for:** varvel platform gap analysis · **Accessed dates:** all sources fetched 2026-08-30

**Scope note.** A same-day companion brief already covered XBOW leaderboard numbers, H1 hackbot XSS-noise stats, IDOR payout growth, interactsh OOB infra, SimHash dedup, and kill-fast budgets. This brief deliberately goes deeper on *mechanics*: pipeline stages, authentication handling, per-class economics, and a build list. XBOW's "1,060 submissions / #1 H1 US" facts are referenced only where needed for context, not re-analyzed.

---

## 1. Mechanics of throughput: what the top systems actually do end-to-end

### 1.1 XBOW — autonomous black-box web/API hunter

Public loop (per third-party feature breakdown, consistent with XBOW's own site): **Learn → Map → Coordinate → Attack → Prove**, with many short-lived parallel agents per attack vector, and findings labeled Validated / Informational / Preview. Attack classes: LFI, RCE, cache poisoning, open redirect, SSRF, XSS, SQLi, CVE/misconfig checks, and (Enterprise preview) IDOR.
[Source: codeant.ai XBOW feature breakdown, 2026-07-27, https://codeant.ai/blogs/xbow-features, accessed 2026-08-30]

Key mechanics visible from primary material:

- **Deterministic validators are separate from the AI.** "AI discovers — logic validates. If it can't be proven, it doesn't ship." Validators re-execute exploits (headless-browser checks, byte-by-byte decryption of a padding oracle, etc.) before a finding is shown.
  [Source: getastra.com agentic pentest guide, 2026-06-19, https://www.getastra.com/blog/penetration-testing/autonomous-ai-agents-for-penetration-testing/; simbian.ai vendor comparison, 2026-06-19, https://simbian.ai/blog/best-continuous-penetration-testing-vendors-2026; both accessed 2026-08-30]
- **Canary-based ground truth in evaluation:** XBOW embeds unique canary values in target code; agent success = canary exfiltrated. Binary oracle, no LLM judgment.
  [Source: ironhackers.es retrospective, 2026-05-15, https://ironhackers.es/agentic-red-team-pentestgpt-xbow-2023-2026/, accessed 2026-08-30]
- **Multi-account IDOR via UI-reasoning + differential object access.** XBOW's Feb-2026 Spree Commerce post shows the actual recipe: agent establishes a *baseline* by creating victim-owned objects (guest Cart A → address ID 15), then an attacker entity (Cart B), then probes cross-reference (`PATCH` attacker's checkout with victim's `bill_address_id`, `?include=billing_address`) and *read back victim PII in attacker's response*. It uses screenshots for navigation when direct URL guessing 404s/502s, and drops session cookies to test unauthenticated state. Two 0-days (CVE-2026-22588 / CVE-2026-22589) resulted.
  [Source: xbow.com blog "Tales from the trace: how XBOW reasons its way into finding IDORs", 2026-02-04, https://xbow.com/blog/tales-from-the-trace-how-xbow-reasons-its-way-into-finding-idors, accessed 2026-08-30]
- **Self-correction is the differentiator vs. scanners**: on 403/502 it pivots paths instead of halting.
  [Source: same xbow.com IDOR post, accessed 2026-08-30]
- **Whitebox option:** source code accepted as *context* for blackbox-style testing ("code is context, never a scanned asset"), plus optional headless browsing.
  [Source: codeant.ai breakdown, accessed 2026-08-30]

### 1.2 ZeroPath — AI-native SAST (source → validated finding → patch PR)

Six-stage pipeline (primary engineering blog): **trigger → tree-sitter AST → enriched code graph → vulnerability discovery → multi-agent validation → patch generation.** Details:

- No Semgrep rules at the core; AI identifies *sources and sinks*, then traces data flow across the call graph, accounting for sanitizers and auth checks ("reachability-aware").
- **Business-logic/authz bugs** use Tree-of-Thoughts + a ReAct-adapted loop: multi-path scenario exploration, then structured tool use.
- **Validation:** candidate attack paths are enumerated, plausibility/impact scored (CVSS 4.0 heuristics), then routed to a **specialized verification agent per vuln class** (SSTI, SQLi, XSS, business logic); below-threshold confidence triggers evidence-gathering, not filing.
- Patchable findings become auto-PRs; PR scans run <60s. It also *imports* Semgrep/Snyk/Checkmarx/etc. output and re-validates it (typical 5,000 → 127 reduction).
  [Source: zeropath.com/blog/how-zeropath-works, https://zeropath.com/blog/how-zeropath-works, accessed 2026-08-30; zeropath.com/solutions/ai-sast, accessed 2026-08-30]
- **Receipts:** independently corroborated CVE ledger — Apache NiFi CVE-2026-39816, ProFTPD CVE-2026-42167 (pre-auth SQLi→RCE), Spinnaker CVE-2026-32604/32613 RCEs, better-auth CVE-2025-61928, FFmpeg fixes, sudo/Qualys-credited fix, Linux ksmbd/svcrdma CVEs.
  [Source: bugflation.com ZeroPath ledger, https://bugflation.com/systems/zeropath-ai-sast/, accessed 2026-08-30; zeropath.com blog index, accessed 2026-08-30]

### 1.3 Google Project Naptime → Big Sleep — white-box variant analysis at scale

- Architecture (primary, Project Zero): LLM agent + **Code Browser** (semantic code navigation), **Python tool** (sandboxed script/fuzz-input generation), **Debugger** (breakpoints, expression eval; target compiled with **AddressSanitizer** so memory-safety crashes are the ground-truth signal), **Reporter** (structured completion/abort; Controller verifies success condition — *typically a crash*).
  [Source: Project Zero "From Naptime to Big Sleep", 2024-11-01, https://projectzero.google/2024/10/from-naptime-to-big-sleep.html, accessed 2026-08-30]
- Results: first real-world find = SQLite stack buffer underflow (later CVE-2025-6965, found before in-the-wild exploitation was weaponized). By Aug 2025: **20 vulnerabilities** across FFmpeg/ImageMagick etc., each *found and reproduced autonomously*; a human reviews only before disclosure.
  [Source: TechCrunch, 2025-08-04, https://techcrunch.com/2025/08/04/google-says-its-ai-based-bug-hunter-found-20-security-vulnerabilities/; Google blog via computing.co.uk, 2025-08-07, https://www.computing.co.uk/news/2025/security/big-sleep-finds-20-flaws-in-open-source-software; both accessed 2026-08-30]
- The oracle lesson: **ASan crash + debugger repro** is their "validator layer." varvel's equivalent for web is the objective oracle gate it already has — the gap is feeding it richer *proof channels* (see §4, §6).

### 1.4 CAI (Alias Robotics) — open framework, ReAct-pattern agents

- Open-source (MIT→custom), 300+ LLM backends via LiteLLM, agent patterns (ReAct, hierarchical, swarm-style handoffs), HITL checkpoints, OpenTelemetry tracing, tools like LinuxCmd/Code/SSHTunnel. Its "Retester" agent directly inspired HackerOne's production dedup agent.
  [Source: arXiv:2504.06017, https://arxiv.org/html/2504.06017v1; github.com/aliasrobotics/CAI; both accessed 2026-08-30]
- **Bug-bounty receipts are modest:** non-professional users reported **6 valid vulnerabilities in one week** (CVSS 4.3–7.5); professional hunters using CAI found 4 more. Claimed 3,600× faster / 156× cheaper than human pentesters on CTF-style tasks — treat as vendor-adjacent paper claims.
  [Source: arXiv:2504.06017 §3.5, §4, accessed 2026-08-30]
- Significance for varvel: CAI shows an *open* stack reaches ~1 valid finding/day with non-expert operators — a realistic floor for a 2-week build, not the XBOW ceiling.

### 1.5 ARTEMIS (Stanford/CMU/Gray Swan) — the best public head-to-head data

- Multi-agent scaffold: dynamic prompt generation, arbitrary sub-agents, **automatic vulnerability triage module**. On a live ~8,000-host university network it placed **2nd overall vs 10 professional pentesters**, with **9 valid vulns at an 82% valid-submission rate** — i.e., its FP rate is managed by a dedicated triage agent, not by filing everything.
  [Source: arXiv:2512.09882, https://arxiv.org/html/2512.09882v1, accessed 2026-08-30]
- **Cost:** A1 config $18.21/hr (~$291 over the evaluated window); A2 $59/hr. Sub-agents were the biggest cost center, then supervisor, then triage. Early-stopping matters: MAPTA's independent 104-challenge accounting found success *negatively* correlated with tool calls (r=-0.661), cost (-0.606), tokens (-0.587), time (-0.557); practical kill thresholds about **40 tool calls / $0.30 / 300s** per CTF-scale task.
  [Source: arXiv:2512.09882 sec.5.4; MAPTA arXiv:2508.20816 sec.3.2-3.3, https://arxiv.org/html/2508.20816v1; both accessed 2026-08-30]
- Capability gap the paper names: agents "struggle with GUI-based tasks" and have higher FP rates than the best humans. Both are closed by a headless browser + deterministic validators (what XBOW/Strix do).

### 1.6 Strix — open-source reference architecture varvel can crib today

- Graph of specialized agents (recon -> vuln-class agents -> validation -> report). Toolkit: **Caido HTTP interception proxy**, **automated browser** (XSS/CSRF/clickjacking/auth-bypass flows), terminal, **Python sandbox exploit runtime** for PoC writing/validation, SAST+DAST, CVSS/OWASP knowledge base. Real scans cost **~$3-5 quick / $10-20 deep** in LLM tokens. Third-party testing ranked it (with CAI) among the only OSS tools producing actionable results on a banking app.
  [Source: github.com/usestrix/strix README, accessed 2026-08-30; appsecsanta.com "AI Pentesting Agents 2026", 2026-06-10, https://appsecsanta.com/research/ai-pentesting-agents-2026; aiccore-uno.ai Strix review, 2026-03-01; all accessed 2026-08-30]

**Roster notes / UNVERIFIED:** "Tilde" and "Verible" as 2025-26 vuln-hunting agents could not be verified in public sources — UNVERIFIED (Verible is a SystemVerilog parser, likely a mix-up). Adjacent verified systems not detailed here: RunSybil (named alongside XBOW/Big Sleep; its CTO warns publicly about AI "slop" reports, https://www.scworld.com/brief/multiple-open-source-flaws-discovered-by-googles-big-sleep-tool, accessed 2026-08-30), AISLE (13 of 14 OpenSSL CVEs in 2025 per CSA research note, https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-autonomous-vuln-discovery-economics-202/, accessed 2026-08-30), Terra Security, Aikido, Escape.

---

## 2. The auth gap — this is varvel's single biggest structural deficit

XBOW's public docs are the clearest primary spec of what "solved" authenticated testing looks like:

- **Supported login methods:** username+password; **TOTP MFA via uploaded QR image or otpauth:// URL**; **email-based MFA and magic links via a temporary XBOW-hosted inbox**; SSO (Okta-style) via email link; social login (GitHub, Microsoft — *not* Google, which blocks it); static bearer token / API key / basic auth; free-text step-by-step auth instructions with "signals of successful login."
- **Multi-account IDOR:** up to **5 credential sets** with free-text **role descriptions**; account 1 attacks, others (horizontal peer, vertical admin, etc.) build the authorization model. Explicitly Enterprise-preview.
- **Session resilience:** auto-detects logout and re-authenticates; understands/maintains tokens; avoids destructive endpoints (password change, account deletion); sequential mode for lockout-prone apps.
- **Unsupported:** self-service account registration, SMS MFA, CAPTCHA-gated flows, partially-onboarded accounts.
  [Source: docs.xbow.com "Define authentication for testing", https://docs.xbow.com/console/how-to/define-authentication/; "Authentication methods", https://docs.xbow.com/console/reference/authentication-methods/; "Protecting targets", https://docs.xbow.com/console/guidance/protecting-targets/; all accessed 2026-08-30]

**Read-across:** nobody fully automates signup -> MFA -> session at scale (even XBOW requires the human to pre-create accounts). But bounty hunting against public programs *requires* self-signup — so an **account factory** (program-aware signup automation + disposable email inbox + TOTP enrollment + session keepalive + role matrix) is a genuine differentiator, not table stakes. varvel already has the 2-account IDOR differential oracle; without automated provisioning it can't run at campaign scale. ARTEMIS's data reinforces this: agents' weaknesses were GUI interaction — a browser-driven signup/login layer removes exactly that bottleneck.
[Source: arXiv:2512.09882 sec.5, accessed 2026-08-30]

---

## 3. High-yield vuln classes in 2025-2026 bounty data

| Class | 2025-26 evidence | Yield signal |
|---|---|---|
| **Broken access control / IDOR / BOLA** | Bugcrowd CISO 2025: broken access control critical vulns **+36%, now the top critical category**; critical payouts **+32%**; API vulns +10%. H1 9th HPSR: authorization flaws (improper access control, IDOR) rising and among fastest-growing while XSS/SQLi decline. [bugcrowd.com press release 2026-08-10, https://www.bugcrowd.com/press-release/bugcrowd-reports-an-88-increase-in-hardware-vulnerabilities-and-a-2x-spike-in-network-vulnerabilities-2025-ciso-report-reveals/; hackerone.com/report/hacker-powered-security; hackerone.com/blog/2025-hpsr-researcher-signals, 2026-01-06; all accessed 2026-08-30] | Highest payout-per-effort for an agent with multi-account auth + differential oracle — exactly varvel's strength *if* auth is solved |
| **Sensitive data exposure / secrets / PII** | Bugcrowd CISO 2025: sensitive-data-exposure criticals **+42%**. Independent 3-year corpus study of >$1k reports names SSRF, PII exposure, ATO, business logic, IDOR as where big bounties concentrate. [same Bugcrowd release; github.com/ReddCrow12/documents-BBP, 2026-05-13, accessed 2026-08-30] | JS/sourcemap secrets + exposed-PII IDORs are cheap to verify objectively |
| **SSRF with OOB proof** | Bugcrowd VRT: internal SSRF tiers up to P1/P2; *external DNS-query-only SSRF = P5* — proof depth determines pay. [bugcrowd.com/vulnerability-rating-taxonomy, accessed 2026-08-30] | Needs OOB callback infra + escalation ladder (cloud metadata, internal data) |
| **Business logic / ATO chains** | H1 HPSR: architecture and logic flaws increasing in value, earn stronger payout. [hackerone.com/blog/2025-hpsr-researcher-signals, accessed 2026-08-30] | Chained narratives (sourcemap -> JWT-in-localStorage -> CORS -> ATO) convert mediums into highs [systemweakness.com sourcemap ATO writeup, 2026-05-28, accessed 2026-08-30] |
| **AI/LLM vulns (prompt injection etc.)** | H1 9th HPSR: AI vulns +200%, prompt injection +540%. [hackerone.com/report/hacker-powered-security, accessed 2026-08-30] | Fast-growing but triage bar unsettled; opportunistic only |
| **XSS** | Declining per H1 HPSR; hackbot-flooded (prior brief). Stored-XSS-with-impact still pays; reflected self-XSS = VRT P5. [bugcrowd VRT, accessed 2026-08-30] | Only file with execution-proof + impact context (session/PII read) |

Race conditions, GraphQL, JWT, cache deception, subdomain takeover: no 2025-26 platform-level payout stats found in this pass — individual-writeup evidence only — **UNVERIFIED at population level**.

---

## 4. Cheap force multipliers varvel is missing (effort = engineer-time to first realistic finding; ESTIMATE = my estimate, not sourced)

| # | Multiplier | What it is / evidence | Effort to first finding |
|---|---|---|---|
| 1 | **JS bundle + sourcemap mining** | `.js.map` in prod -> full source reconstruction (sourcemapper) -> endpoints, API schemas, hardcoded tokens, localStorage-JWT patterns. Documented real-world ATO chain payout. [intigriti.com Bug Bytes #55, 2025-03-06; systemweakness.com, 2026-05-28; both accessed 2026-08-30] | **~1-2 days build; findings within first campaign (ESTIMATE)** |
| 2 | **Secrets scanning on JS/assets** (trufflehog/gitleaks/SecretFinder/Mantra-style regex+entropy) | Standard hunter method; wayback'd old JS builds leak removed secrets. [infosecwriteups.com "JavaScript Secret Hunting: 11 Methods", 2026-02-09; blog.stackademic.com JS hunting, 2024-03-19; both accessed 2026-08-30] | **1 day build; verify-by-live-use oracle same day (ESTIMATE)** |
| 3 | **Wayback/gau endpoint diffing** | Archived endpoints/params absent from current crawl = forgotten attack surface; custom API wordlists a la Frans Rosen. [javascript.plainenglish.io, 2025-07-14; intigriti Bug Bytes #55; both accessed 2026-08-30] | **1-2 days; high hit rate on older programs (ESTIMATE)** |
| 4 | **Headless-browser crawl + traffic capture (Playwright) feeding the LLM** | XBOW's IDOR post shows UI-screenshot reasoning + network capture finds endpoints URL-guessing misses; Strix ships a browser agent for XSS/auth flows. [xbow.com IDOR post, 2026-02-04; github.com/usestrix/strix; accessed 2026-08-30] | **2-3 days; multiplies every other item (ESTIMATE)** |
| 5 | **GraphQL introspection + swagger/OpenAPI hunting** | Introspection alone is VRT P5, but the *schema* drives BOLA tests across every mutation/query. [bugcrowd VRT, accessed 2026-08-30] | **1 day; pays only when chained to IDOR oracle (ESTIMATE)** |
| 6 | **Nuclei exposure templates against JS + hosts; takeover fingerprints** | Hunters run nuclei exposures templates over JS files. [blog.stackademic.com, accessed 2026-08-30] | **0.5 day; takeover needs provider fingerprint + CNAME oracle, never claim-by-registering (ESTIMATE)** |
| 7 | **OOB callback (interactsh) wired to SSRF/SSTI/XXE/XSS probes** | Prior brief covered infra; the *new* point: VRT prices SSRF by proof depth, so OOB is the difference between P5 noise and P1/P2. [bugcrowd VRT, accessed 2026-08-30] | **1-2 days; unblocks 4 vuln classes' validators (ESTIMATE)** |
| 8 | **LLM triage of proxied traffic (Burp/Caido-style)** | Strix's architecture: full request/response capture into agent context. [github.com/usestrix/strix, accessed 2026-08-30] | **2 days; converts recon data into hypotheses (ESTIMATE)** |
| 9 | **Payload mutation engine tied to oracle** (SQLi boolean/time differential, SSTI arithmetic, XSS polyglot -> headless execution canary) | Big Sleep/MAPTA lesson: objective success signal per attempt enables kill-fast + mutate loops. [projectzero.google, 2024-11-01; arXiv:2508.20816; accessed 2026-08-30] | **3-4 days; this is what turns "probes" into "proofs" (ESTIMATE)** |

---

## 5. What NOT to waste time on (triager-sentiment-backed)

Bugcrowd's VRT assigns **P5/informational (about $0)** to: all missing security headers (CSP, HSTS, X-Frame-Options...), insecure SSL/cipher/cert issues, banner/version disclosure, GraphQL introspection alone, robots.txt, internal IP disclosure, self-XSS, cookie-scope complaints, open redirects (flash/header/POST variants), non-session cookie flags, OPTIONS/TRACE methods, external-DNS-only SSRF. [Source: bugcrowd.com/vulnerability-rating-taxonomy, accessed 2026-08-30]

Intigriti's triage team explicitly buckets "non-exploitable findings... missing info/context" and "**spam and AI-slop**" as noise, and notes the platform-side problem has shifted from bad reports to faster good-enough research — i.e., the bar is *proof*, and unproven scanner output damages sender reputation. [Source: intigriti.com signal-to-noise post + "The AI impact: a triager's perspective", both 2026-08, accessed 2026-08-30] RunSybil's CTO on AI submissions: "a lot of stuff that looks like gold, but it's actually just crap." [scworld.com, 2025-08-05, accessed 2026-08-30]

**Operational rule for varvel:** anything whose entire evidence is a TLS/cert observation, a header absence, or a version string -> auto-demote to an internal "hygiene" bucket, never enter the filing queue. (Yesterday's zero-finding run was exactly this failure mode.)

---

## 6. Concrete 2-week build list for varvel -> 3 filable submissions/day

Ordering = payout-per-engineering-hour. Every item lists its **verification oracle**; nothing ships to the filing queue without its oracle green. Prerequisites varvel already has: phased agent loop, HITL gates, validator gate, 2-account IDOR differential replay, ghost proxy, bountyline tracker.

| Day(s) | Build item | Oracle required before filing | Why this order |
|---|---|---|---|
| 1-3 | **Account factory:** program-aware signup automation (Playwright), disposable-email inbox, TOTP enrollment from otpauth://, session keepalive/re-login detection, 4-role credential matrix (attacker, horizontal peer, vertical admin, unauth control). Modeled directly on XBOW's documented auth surface + ARTEMIS's GUI-gap finding. [docs.xbow.com, accessed 2026-08-30] | Login-success signal per account (status/element/redirect), session-alive probe each campaign tick | Unlocks the *highest-paying class* (access control) which Bugcrowd says is the top critical category; without it the IDOR oracle is decoration |
| 3-4 | **JS/sourcemap mining pipeline:** katana/gau JS collection -> .map probe -> sourcemapper reconstruct -> LinkFinder/SecretFinder + trufflehog/gitleaks on reconstructed source -> endpoint & secret inventory into campaign context | Secret = live-use probe against its provider returns authenticated 200; endpoint = unauth or cross-account data response | Cheapest new surface; feeds IDOR and browser items with real endpoints |
| 4-5 | **OOB callback infra (self-hosted interactsh) + wire into SSRF/SSTI/XXE/XSS payloads** with per-campaign canary tokens | Callback hit carrying the unique canary, correlated to the probe request | Small build, upgrades 4 classes from "unverifiable" to "objective oracle" (per VRT proof-depth pricing) |
| 5-6 | **Multi-account IDOR generalization:** extend the 2-account differential replay to the 4-role matrix; add **victim-object seeding** (auto-create victim artifacts — orders, addresses, docs — before attack, a la XBOW's Cart A/Cart B method) | Existing oracle (own/cross/unauth + victim readback) at each role pair; filing requires victim PII/data in attacker's response body | Directly replicates the method behind XBOW's Feb-2026 CVEs |
| 6-7 | **Headless browser agent:** authenticated crawl, screenshot-reasoning for navigation, full request/response capture to LLM context (Strix/Caido pattern) | DOM-XSS: payload executes in headless browser + exfil canary observed; auth flows: replay succeeds cross-session | Fixes agents' documented GUI weakness; finds endpoints no fuzzer guesses |
| 7-8 | **Wayback/gau diffing:** archived endpoints & params minus current crawl -> probe list; custom per-target wordlists from mined JS | Diffed endpoint returns 200 with data/behavior delta vs. control | Legacy endpoints are disproportionately BOLA/auth-bypass-prone |
| 8-9 | **Payload mutation engine with oracle loop** for SQLi (boolean/time differential), SSTI (arithmetic evaluation), template probes; MAPTA-style kill-fast budget per hypothesis (~40 tool calls / ~300s) | Class-specific objective signal only (differential response, computed arithmetic, OOB hit) — no LLM "looks vulnerable" | Converts probe noise into proofs; kill-fast keeps cost per campaign in the ARTEMIS A1 band (~$18/hr) |
| 9-10 | **Nuclei exposure/takeover pass + hygiene demoter:** run exposures templates over JS/hosts; takeover = DNS CNAME + provider fingerprint only (no registration); hard-demote TLS/headers/version findings to internal bucket | Takeover: fingerprint + dangling CNAME; everything hygiene-class never enters filing queue | Stops yesterday's failure mode (unvalidated TLS observations) permanently |
| 10 | **Report chainer:** bundle primitives into single chained narratives (sourcemap -> JWT-storage -> CORS -> ATO pattern) with per-step evidence | Every step has its own oracle artifact; chain fileable only if the terminal impact (ATO/PII read) is proven | Chained reports get approved at higher severity than 5 separate mediums |

**Throughput math (ESTIMATE):** CAI's open stack produced ~1 valid finding/day with non-expert users; items 1-5 are the delta between varvel and that floor. 3 filable/day across 10+ programs requires ~1 validated finding per 3-4 program-days — plausible only once authenticated coverage exists, because access-control findings dominate 2025-26 payouts. [arXiv:2504.06017 sec.3.5; bugcrowd.com CISO 2025 press release; accessed 2026-08-30]

**Deliberately NOT in the 2-week list:** SAST/source analysis (no source access in black-box bounty; ZeroPath's model needs repos), memory-safety fuzzing (Big Sleep's domain, not web bounty), business-logic AI-vuln hunting (triage bar unsettled).

---

## Appendix: source register (all accessed 2026-08-30)

1. XBOW docs — auth methods, IDOR multi-account, target protection: docs.xbow.com/console/how-to/define-authentication/ ; /reference/authentication-methods/ ; /guidance/protecting-targets/
2. XBOW IDOR trace (Spree CVE-2026-22588/22589): xbow.com/blog/tales-from-the-trace-how-xbow-reasons-its-way-into-finding-idors
3. ZeroPath pipeline: zeropath.com/blog/how-zeropath-works ; zeropath.com/solutions/ai-sast ; bugflation.com ledger
4. Big Sleep/Naptime: projectzero.google/2024/10/from-naptime-to-big-sleep.html ; techcrunch.com/2025/08/04/google-says-its-ai-based-bug-hunter-found-20-security-vulnerabilities/
5. CAI: arxiv.org/abs/2504.06017 ; github.com/aliasrobotics/CAI
6. ARTEMIS: arxiv.org/abs/2512.09882 ; MAPTA cost accounting: arxiv.org/abs/2508.20816
7. Strix: github.com/usestrix/strix ; appsecsanta.com/research/ai-pentesting-agents-2026
8. Market data: hackerone.com/report/hacker-powered-security ; hackerone.com/blog/2025-hpsr-researcher-signals ; bugcrowd.com CISO-2025 press release ; bugcrowd.com/vulnerability-rating-taxonomy
9. Hunter methodology: infosecwriteups.com JS secret hunting (2026-02-09) ; intigriti.com Bug Bytes #55 ; systemweakness.com sourcemap ATO chain ; intigriti.com triager perspective / signal-to-noise
10. Comparative: getastra.com agentic pentest guide ; codeant.ai XBOW features ; escape.tech XBOW alternatives ; ironhackers.es retrospective ; scworld.com Big Sleep brief (RunSybil slop quote) ; CSA research note (AISLE/OpenSSL)
