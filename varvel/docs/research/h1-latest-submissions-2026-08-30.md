# HackerOne Latest Submissions Research — 2026-08-30

**Question:** What are the latest accepted/paid H1 submissions (last ~90 days) about, and what are researchers doing that our autonomous platform might be missing?

**Access note / limitation:** HackerOne hacktivity (hackerone.com/hacktivity) is a JS-only SPA; both FetchURL and kimi_fetch returned an empty shell on 2026-08-30, and individual report pages (hackerone.com/reports/NNN) also render no content server-side. A direct 20–30 report sample of the last 90 days was therefore **not possible**; the picture below is built from: (a) platform-level data in HackerOne's 9th HPSR (Oct 2025), (b) a 2026 arXiv paper that sampled 200 H1 disclosures, (c) verified individual 2026 disclosures/CVEs traceable to H1/bounty activity, and (d) practitioner write-ups. Anything not from those is marked UNVERIFIED.

---

## 1. What recent accepted reports are actually about

**Platform-level signals (HackerOne 9th Hacker-Powered Security Report, Oct 2025):**
- Valid AI-related findings up **210% YoY**; valid **prompt-injection reports up 540%**; **1,121 programs** had AI in scope or a valid AI report in 2025 (+270%). [hackerone.com/blog/2025-hpsr-researcher-signals, accessed 2026-08-30]
- **1,100+ "hackbot" submissions** received, ~half valid; **78% of valid hackbot findings were XSS** — i.e., baseline pattern-class bugs are now machine-saturated. [same source]
- Five-year trend: **XSS declining from its 2024 peak; improper access control, IDOR variants, and misconfigurations rising** and earning stronger payouts. "Architecture and logic flaws are increasing in value." [same source]
- Programs that cut rewards saw 73% drop in valid submissions; strongest sectors: financial services, crypto, government, AI SaaS. [same source]
- H1 paid **$81M in 2025**. [penligent.ai/hackinglabs/bug-bounty-hunter-software-in-2026, accessed 2026-08-30 — secondary, UNVERIFIED against H1 primary]

**Empirical IDOR/BOLA sample (arXiv 2605.25865, May 2026 — 200 H1 disclosures tagged IDOR/Improper Access Control, 2021–2026, 107 classified):**
- 78.5% confirmed in-scope BOLA; **Action-Level BOLA (unauthorized state-changing actions on other users' objects) = 41.7%** of confirmed cases — co-dominant with classic direct-reference BOLA.
- **11.9% vertical (user→admin) privilege failures**; systematic exploitation of **GraphQL Global IDs** across major platforms.
- ~21.5% of tag-matched reports were out-of-scope under strict criteria — raw H1 tag counts overstate BOLA signal. [arxiv.org/abs/2605.25865, accessed 2026-08-30]

**Specific verified recent disclosures (2026):**
- **Rocket.Chat CVE-2026-32995** — AutoTranslate IDOR exposing private messages; H1 report submitted 2026-05-14, triaged same day, severity *raised* Medium 6.5 → High 7.5, fix merged same day, disclosed 2026-05-25 (no bounty). [zeropath.com/blog/cve-2026-32995-rocketchat-autotranslate-idor, accessed 2026-08-30]
- **XBOW → Microsoft Bing CVE-2026-32194 & CVE-2026-32191** (July 2026) — two unauth CVSS 9.8 RCEs: command injection via "Search by Image" upload; a one-pixel SVG whose image ref begins with a pipe char escaped ImageMagick's delegate handler → SYSTEM/root on Bing workers. [aiweekly.co/node/7944, accessed 2026-08-30 — secondary writeup]
- **XBOW → Exim CVE-2026-45185** ("Dead.Letter", May 2026) — CVSS 9.8 RCE (CWE-416) in Exim 4.97–4.99.2, fixed 4.99.3. [stingrai.io/blog/xbow-exim-deadletter-rce-cve-2026-45185 + NVD, accessed 2026-08-30]
- **Langflow CVE-2026-55255** — CVSS 9.9 API IDOR enabling credential theft; observed chained in-the-wild with an older RCE (CVE-2026-33017). AI-app stack target. [blog.securelayer7.net/cve-2026-55255-langflow-idor, accessed 2026-08-25/30]
- Practitioner indexes of Aug-2026 H1 writeups (rix4uni/medium-writeups repo, updated every 10 min) show recent paid themes: IDOR on restore-deleted-resources flows, CAPTCHA bypass, open-redirect chains, rate-limit gaps. [github.com/rix4uni/medium-writeups, accessed 2026-08-30]

**What made reports accepted (proof that wins):** concrete cross-account data reads or state changes (Rocket.Chat: read another room's messages; XBOW: actual command execution as SYSTEM), exact repro with request/response pairs, and business-impact framing. H1's managed triage (85%+ of programs) validates **reproducibility, business impact, in-scope relevance** — nothing else passes. [hackerone.com/blog/beyond-the-noise-hai-triage-insight-agent, accessed 2026-08-30]

## 2. What top hunters' current methodology looks like (2025–2026)

- hakluke (June 2026): a "huge chunk" of submissions are now AI-found (partly or fully); frontier models need *less* harnessing than a year ago — "point one at a program, say find bugs, and it will"; human edge is now **validation + steering + novel bug classes**. Top hunters spend **hundreds–thousands USD/month on AI tokens**. [hakluke.com/are-bug-bounties-cooked, accessed 2026-08-30]
- >2/3 of surveyed H1 researchers use AI/automation for recon acceleration and repetitive checks; 58% are actively upskilling in AI/ML-system auditing. [hackerone.com/blog/2025-hpsr-researcher-signals, accessed 2026-08-30]
- Standard 2026 kit (per redfoxsec deep dive, Dec 2025): Burp Authz for two-session IDOR diffing, Turbo Intruder for UUID harvesting + race conditions, Interactsh OOB for blind SSRF, sqlmap with WAF tamper scripts against **API/GraphQL endpoints (not forms)**, InQL for schema mining, DOM Invader for DOM-XSS, Arjun for hidden params, local LLM (Ollama) for response triage; mass-assignment and JWT alg-confusion still pay. [redfoxsec.com/blog/common-bug-bounty-vulnerabilities-a-technical-deep-dive-for-hunters-in-2026, accessed 2026-08-30]

## 3. AI tooling: who's using what, and public "AI found this" cases

- **XBOW**: #1 on H1 US leaderboard June 2025 (~1,060 reports in ~90 days: 54 critical / 242 high / 524 medium / 65 low; 130 resolved, 303 triaged, 208 dup, 209 informative). Key mechanics we should study: (a) **target-scoring infra** over program scopes — WAF presence, auth forms, endpoint counts, redirect/status behavior; (b) **SimHash + screenshot imagehash dedup** of cloned/staging hosts; (c) **validators as automated peer reviewers** — e.g. headless-browser XSS execution proof before filing; (d) human pre-submission review to comply with H1 automated-tooling policy; (e) removed from ≥1 program for "automatic scanners" — policy parsing matters. [xbow.com/blog/top-1-how-xbow-did-it, accessed 2026-08-30]
- XBOW 2026 CVE cases with detail: Bing RCEs (above) and Exim 9.8 — both autonomous discovery, whitebox-ish source review + blackbox confirmation. [aiweekly.co/node/7944; stingrai.io/blog/xbow-exim-deadletter-rce-cve-2026-45185, accessed 2026-08-30]
- Benchmarks that bound expectations: CVE-Bench — best agents exploit only **13% of critical web CVEs zero-day / 25% one-day** [arxiv.org/abs/2503.17332]; ARTEMIS (Dec 2025) — agent placed 2nd vs 10 pros on a live 8,000-host network at 82% valid rate but **higher false-positive rate than every human** [arxiv.org/abs/2512.09882]. [via stingrai.io/blog/ai-pentest-benchmark-results-2026, accessed 2026-08-30]
- Fully-AI-written reports are "polished but technically shallow" and triagers spot them fast — narrative must be human/verified. [hackerone.com/blog/2025-hpsr-researcher-signals, accessed 2026-08-30]
- Community harnesses exist (e.g. Claude-BugHunter skills, hackerone-mcp GraphQL server) — UNVERIFIED quality. [github.com/elementalsouls/Claude-BugHunter; github.com/lordx64/hackerone-mcp, accessed 2026-08-30]

## 4. Classes trending UP vs DOWN

**UP (acceptance + payouts):**
- AI/LLM-app bugs: prompt injection (+540%), agent/plugin misuse, retrieval failures; 1,121 AI-in-scope programs. MCP ecosystem CVEs growing (mcp-remote CVE-2025-6514 cmd injection; Figma MCP CVE-2025-53967). [hackerone.com/blog/2025-hpsr-researcher-signals; labs.cloudsecurityalliance.org/research/csa-whitepaper-ai-agent-disclosure-accountability-gap-202604; agentthreatrule.org/en/rules/ATR-2026-01928, accessed 2026-08-30]
- IDOR/BOLA � esp. action-level/state-changing BOLA, vertical privesc, GraphQL global IDs. [arxiv.org/abs/2605.25865]
- Business logic / race conditions (coupons, withdrawals, referral abuse) � no scanner finds these; 58% of researchers say business logic is AI's weakest class -> least competition. [redfoxsec.com deep dive; stingrai benchmark post citing HPSR Fig.10 p.9, accessed 2026-08-30]
- Access control + misconfiguration broadly rising per 5-yr H1 trend. [HPSR blog]
- API/GraphQL SQLi (moved off forms), mass assignment, JWT confusion. [redfoxsec]

**DOWN / noise-prone:**
- Reflected/stored XSS on vanilla surfaces � declining since 2024 peak; 78% of valid hackbot findings are XSS -> saturated, dup-heavy. [HPSR blog]
- Nuclei known-CVE spraying and cache-poisoning classes � XBOW's informative/N-A buckets dominated by policy-excluded classes (third-party, cache poisoning). [xbow.com/blog/top-1-how-xbow-did-it]
- AI-slop reports: hallucinated, non-reproducible; Hai Triage + a new submission agent block out-of-scope/ineligible/low-quality reports at the gate. [hackerone.com/blog/beyond-the-noise-hai-triage-insight-agent]

## 5. Proof standards triagers demand (2026)

- Managed triage validates three things: reproducibility, business impact, in-scope relevance. [H1 Hai Triage blog]
- Report anatomy that pays: one-line summary, step-by-step repro, exact HTTP requests/responses showing impact, business-impact statement, suggested remediation; automated-looking narratives get downgraded. [redfoxsec]
- OOB callback (Interactsh-style) is the accepted standard for blind SSRF/RCE proof. [redfoxsec]
- Execution proof beats assertion: headless-browser confirmation of XSS execution is XBOW's validator bar; Rocket.Chat fix landed same-day on a clean cross-room read repro.
- No universal video-PoC requirement found in primary sources � UNVERIFIED whether specific programs demand video.

---

## Implications for OUR stack (edge-fronted estates, unauth-only, CLEAN days)

| # | Gap | Evidence |
|---|-----|----------|
| 1 | No AI/LLM-attack-surface capability (prompt injection, MCP/agent-tool abuse, retrieval flaws). Fastest-growing accepted class (+540% prompt injection, +210% valid AI reports; $890K+ AI payouts 2025 � secondary, UNVERIFIED). Zero coverage in our module list. | HPSR blog; CSA whitepaper |
| 2 | Unauthenticated-only scope. Everything trending up (action-level BOLA 41.7%, vertical privesc 11.9%, GraphQL global-ID BOLA, race conditions, business logic, mass assignment) lives behind login. Our account factory + 2-account IDOR oracle can't fire without session material; unauth-only on Cloudflare/Akamai fronts structurally yields CLEAN days. Winners hunt post-auth. | arXiv 2605.25865; redfoxsec; HPSR |
| 3 | No target-scoring/ROI layer and no multi-step chaining. XBOW's edge is picking targets (WAF present? auth forms? endpoint count? SimHash/imagehash dedup of clones) and chaining (48-step exploit chains). We grind hardened edges indiscriminately and file single-oracle findings only. | xbow.com/blog/top-1-how-xbow-did-it |

Secondary gaps: no race-condition module (Turbo-Intruder-style single-packet attacks), no GraphQL-aware BOLA (global IDs), no mass-assignment/JWT-confusion probes, no program-policy parser (XBOW was ejected from a program for scanner-policy violation � scope/rules compliance checking is table stakes).

*Compiled 2026-08-30. All URLs accessed 2026-08-30 unless noted. UNVERIFIED items flagged inline.*
