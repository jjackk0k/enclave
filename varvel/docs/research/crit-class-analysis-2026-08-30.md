# VARVEL Research: Critical/High HackerOne Class Analysis (2024-2026)

**Date:** 2026-08-30
**Purpose:** Aim VARVEL's lab and hunting pipeline at the vulnerability classes that actually get rated Critical/High and paid on live programs. Grounded against our honest gap: 0 validator-confirmed exploitable findings on live targets across 4 engagements.

---

## 1. Ranked class table — what dominates recent Critical/High submissions

Sources: HackerOne 8th/9th Hacker-Powered Security Reports (HPSR), the `ReddCrow12/documents-BBP` survey of $1,000+ disclosed reports (2024-2025), the scgajge12 compilations of H1's most-upvoted reports (2023-2025), XBOW's autonomous-agent submission data, and an Oxford thesis analysis of 3,000 disclosed H1 reports.

### Frequency ranking (all severities, H1 platform)

From HackerOne's 8th HPSR (2024 data): (1) XSS ~20% of reports, (2) Information Disclosure, (3) Improper Access Control, (4) Misconfiguration, (5) IDOR, (6) Improper Authentication, (7) Privilege Escalation, (8) Open Redirect, (9) Business Logic Errors, (10) SQLi. Source: https://scgajge12.hatenablog.com/entry/bugbounty_reports_2024 and https://flatt.tech/research/posts/why-xss-persists-in-this-frameworks-era/

The 9th HPSR (mid-2024 to mid-2025, $81M paid, +13% YoY, ~1,950 programs) reports **authorization flaws (improper access control + IDOR) as one of the fastest-growing classes while XSS and SQLi decline**; AI-related valid reports +210%, prompt injection +540%. Sources: https://cyberprivateinvestigations.com/2025/10/02/hackerone-paid-81-million-in-bug-bounties-over-the-past-year/ and https://www.hackerone.com/report/hacker-powered-security and https://www.hendryadrian.com/hackerone-hacker-powered-security-report-2025/

### Critical/High-weighted ranking (what actually gets rated high and paid)

| Rank | Class | Frequency signal | Payout signal | Feasible for VARVEL (black-box HTTP agent)? |
|------|-------|------------------|---------------|----------------------------------------------|
| 1 | **IDOR / BOLA / Improper Access Control** | Top-3 in every 2023-2025 H1 top-10 list; "fastest-growing" per 9th HPSR; 4 of top-10 most-upvoted H1 reports in 2024 were IDOR/access-control. A secondary source claims ~49% of high/critical H1 findings are IDOR/BAC — could not verify against H1 primary data, treat as directional. | Shopify GraphQL IDOR $5,000; PayPal cross-tenant IDOR $10,500; H1 self-platform IDOR $12,500; Reddit mod-log IDOR $5,000; GitLab improper access control $25,000 (2024 upvote list) | **YES — this is our wheelhouse.** Two-account differential oracle over HTTP is exactly the shape these reports use. |
| 2 | **Account Takeover (auth/recovery-flow flaws)** | Recurring in every $1k+ survey; TikTok recovery-flow ATO, GitLab password-reset ATO (report #2293343), Remitly 0-click ATO (#2831902), SteamGuard brute-force ATO. | TikTok ATO $12,000; GitLab ATO paid in critical band (~$10K+ per survey, figure not posted on public page); Remitly critical (amount not public). | **YES**, partially — recovery/reset/email-change flows are pure HTTP; needs multi-account + flow-state modeling we haven't built. |
| 3 | **SSRF (incl. blind, webhook, IMDS pivots)** | Every disclosed SSRF in the 2024-25 survey lives in a URL-accepting feature: webhooks, image proxies, "import from URL", PDF renderers, OAuth callbacks. H1 #2262382 reached AWS metadata/IAM creds. | H1 SSRF→AWS creds: critical (figure not public); IBB Apache UNC SSRF CVE-2024-38472 $4,920 + fix-bypass CVE-2024-40898 $4,263; libuv SSRF $4,860; Aiven Kafka chain $5,000; webhook SSRFs $2,500 each. | **YES**, with infra: needs an out-of-band listener (interactsh-style) for blind SSRF + an IMDS-pivot checklist. Pure HTTP otherwise. |
| 4 | **Business Logic / workflow-invariant violations** | Rising but "often undervalued" per 9th HPSR; 58% of researchers surveyed say AI misses business logic and chained exploits — i.e., the field is conceding this to whoever can do it. | Stripe unlimited discount redemption $5,000 (H1-attested via corporate blog, report not on Hacktivity); Eternal/Zomato OTP listing-claim $3,250; Cloudflare transform-rule smuggling $6,000. Crypto sector pays ~45% of bounties on logic flaws per H1 commentary. | **YES — our invariant-discovery work targets exactly this.** Hardest to automate generically, but our oracle-first discipline is the right frame. |
| 5 | **Race conditions / TOCTOU (limit overrun)** | PortSwigger research (2023) + YesWeHack 2025 guide both describe microservices/serverless making this MORE prevalent; classic shapes: double-redeem gift cards, over-withdraw, rate-limit bypass, coupon multi-apply. | PortSwigger's James Kettle notes personally missing ~$5k on one exploit avenue; payouts typically ride on the business value of the limit broken (financial endpoints = high/critical). | **YES** — HTTP/2 single-packet attack is a pure-HTTP capability; Burp Repeater parallel groups / Turbo Intruder prove it's scriptable. Our race harness already exists in lab. |
| 6 | **Injection family (RCE/SQLi/XXE/path traversal) & secrets exposure** | XBOW's 1,060 autonomous submissions spanned RCE, SQLi, XXE, path traversal, SSRF, XSS, info disclosure, cache poisoning, secret exposure — 54 critical + 242 high in 90 days. Declining share of human reports but still the bulk of machine-found crits. | Highest single-report ceiling in the data: critical payouts range $200-$200,000 per Oxford thesis; XXE is critical/high 67% of the time (H1 2019 data, dated). | **PARTIAL** — error-based/reflected cases yes; blind SQLi/OS-timing, memory-corruption, and most RCE chains need fuzzing scale or source access we don't have. |
| 7 | **XSS (declining but voluminous)** | Still #1 by volume (~20% of H1 reports in 2024) but payouts skew medium; stored/DOM on high-value surfaces can still rate high. | Top-upvoted 2024 XSS: $5,000; most fall in the medium band. | YES technically, but **low EV for us** — crowded, dup-heavy, medium-rated. Deprioritize. |

### Payout-by-severity anchor points (for calibration)

- Critical reports (Oxford thesis, 3,000 disclosed H1 reports): avg payout band $3,324-$12,524; High: $2,046-$3,174; Medium: $618-$954. Critical payouts vary $200-$200,000. Source: https://ora.ox.ac.uk/objects/uuid:4a828bbb-8ff4-4cac-9e09-5699b30c6d52/files/d1r66j1703
- H1 4th HPSR (dated but structural): median critical bounty $2,500, 2.5x a high, 6x a medium. Source: https://www.fstech.co.uk/fst/hacker-powered-security-report/the-4th-annual-hacker-powered-security-report-financial-services.pdf

---

## 2. Mechanical shape of the exploit (top classes), in request/response + control terms

All shapes below are provable with captured request/response pairs plus a control — matching our oracle-first discipline.

### 2.1 IDOR / BOLA
**Shape:** Two accounts, A (attacker) and B (victim). Capture B's object reference (id/uuid) in a normal request. Replay the same request with A's session/token. `200` + B's data = confirmed. Control: same request with A's own id (must succeed), and an unauthenticated replay (must 401/403) to prove the check that exists vs. the check that's missing.
- Variants: horizontal read (PII), horizontal write/delete (higher severity), vertical (role-gated endpoint reachable with low-priv token), mass assignment (extra JSON field in a PATCH changes privilege/ownership).
- UUIDs don't kill it: top hunters leak the victim UUID through a second endpoint (search, comments, public profile), then exploit. Source: https://breachvex.com/learn/idor-overview and https://github.com/ReddCrow12/documents-BBP
- Escalation ladder that turns medium into critical: read to write to cross-tenant to account deletion / password change. Synack walkthrough: IDOR on user-update + adding `password` param to the body leads to full ATO of a high-priv account. Source: https://www.synack.com/exploits-explained/exploits-explained-going-from-idor-to-account-takeover-for-fun-and-profit/

### 2.2 Account Takeover (recovery/reset flows)
**Shape:** Instrument every step of password-reset / email-change / OTP / OAuth-callback flows. The money primitives:
- Reset token or reset link leaked in the HTTP response body (GitLab #2293343 — intercept the response, link is in it; zero user interaction).
- Rate-limit bypass on OTP/recovery codes via duplicate `X-Forwarded-For` headers or race conditions (SteamGuard ATO $2,500; rate-limit-bypass ATO writeup: https://readmedium.com/account-takeover-through-rate-limit-bypass-bug-bounty-tuesday-01229168dd89).
- Session misbinding: SSO session + victim email leads to delete/take over victim account (Mozilla IDOR-to-account-deletion, rated critical).
- Missing email verification on account linking (Shopify Collabs ATO).

**Control:** the same flow for the legitimate account must behave correctly; the victim account must be provably accessible with attacker-set credentials at the end (login as victim = the proof).

### 2.3 SSRF
**Shape:** Enumerate every feature that accepts a URL (webhooks, import-from-URL, image proxy, PDF generation, OAuth discovery, SAML metadata). Supply a canary URL to an OOB listener. Confirmation = inbound HTTP/DNS hit at the listener. Escalation that moves medium to critical: pivot to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS IMDS) and show returned temporary credentials; or reach an internal admin port and show its banner. Control: same feature with an external, non-sensitive URL (must work) and with a private-range IP (blocked = fixed; fetched = vulnerable). Blind SSRF without OOB infra is unprovable — the listener is mandatory. Sources: H1 #2262382 description in https://github.com/ReddCrow12/documents-BBP; IMDSv2 non-enforcement context (68% of EC2s, Datadog 2024, cited therein).

### 2.4 Business Logic / invariant violation
**Shape:** Derive an invariant from observed traffic ("a promo code applies once per order", "balance decreases exactly once per transfer", "a listing can only be claimed by its owner"). Then violate it: replay the redemption call, reorder workflow steps, skip a step, or invoke a step twice. Stripe's unlimited-discount bug = redemption function invocable N times. Proof = before/after state diff (discount total, balance, order state) captured in responses. Control: normal single invocation behaving correctly. Sources: https://github.com/ReddCrow12/documents-BBP (Stripe $5,000, Eternal OTP $3,250).

### 2.5 Race condition / TOCTOU
**Shape:** Identify a single-use or rate-limited endpoint with financial/authorization impact. Send 20-30 copies of the identical request in one TCP packet (HTTP/2 single-packet attack; last-byte sync for HTTP/1). Vulnerable = limit overruns (coupon applied twice, balance over-withdrawn). PortSwigger: single-packet succeeded in ~30s where last-byte sync took 2+ hours on a real target; two requests are often sufficient. Control: sequential replay of the same requests must NOT overrun. Sources: https://portswigger.net/research/smashing-the-state-machine and https://portswigger.net/web-security/race-conditions

### 2.6 Injection/RCE/secrets (machine-finds-crits class)
**Shape (what's feasible black-box):** error-based SQLi (payload triggers SQL error in response), reflected/stored XSS with a unique canary token, template injection with arithmetic oracle (`{{7*7}}` renders `49`), path traversal with `/etc/passwd` or known-file canary, exposed secrets via JS-bundle/.git/.env checks. **Control:** neutral payload returning unchanged output. What's NOT feasible at our scale: blind/time-based SQLi at fuzzing volume, deserialization chains, memory corruption, most full RCE. XBOW's data proves an autonomous agent CAN land these (54 crits/90 days) but they run fuzzing infrastructure at a scale we don't. Source: https://xbow.com/blog/top-1-how-xbow-did-it

---

## 3. Feasibility for an AI agent with HTTP tooling on black-box targets

**Fully feasible at human cadence (pure HTTP + multi-account + OOB listener):**
- IDOR/BOLA in all variants — this is literally a diff over two sessions. Highest EV per unit of engineering.
- ATO via recovery/reset flow analysis — needs flow-state instrumentation but no exotic tooling.
- SSRF with OOB callback — needs one piece of infra (listener) then it's pattern-matching over URL-accepting features.
- Limit-overrun races — single-packet attack is scriptable HTTP/2.
- Reflected injection canaries, secrets exposure, error-based SQLi.

**Feasible but harder (needs what we're building):**
- Business-logic invariant violations — requires learning the invariant from traffic first (our invariant-discovery work), then generating a violation. H1's own survey says 58% of researchers believe AI misses these — this is whitespace, and it's where payouts are climbing.
- Chained escalation (IDOR to ATO, SSRF to IMDS to cloud creds) — chains are what separate $1.5k mediums from $12k criticals; they require holding primitives and composing them, which is our chaining capability.

**Not realistically feasible for us now:**
- Blind SQLi/RCE at fuzzing scale (needs XBOW-class infra).
- Mobile-app-specific surface, source-assisted audits, binary/native.
- Cache poisoning / request smuggling at CDN level — detectable (Cloudflare $6,000 report) but validation without side effects is risky on live targets.
- Prompt-injection-class AI bugs: +540% growth and in scope at 1,121 programs, but payout norms are immature and evidence standards differ (e.g., OpenAI requires >=50% reproducibility). Watch, don't build yet.

---

## 4. What the best critical reports include that mediocre ones lack

Synthesized from H1 Help Center criteria, Bugcrowd docs, and triager-facing guidance (sources: https://www.penligent.ai/hackinglabs/de/how-to-use-ai-for-bug-bounty-in-2026/ , https://poccraft.com/bug-bounty-report-template/ , https://amrelsagaei.com/the-bug-bounty-report-blueprint-triagers-dont-ignore , https://www.yeswehack.com/learn-bug-bounty/llm-bug-bounty-hunting-agentic-cli ):

1. **Two-account / cross-tenant proof of scale.** Same-tenant IDOR reads as Low; "works for ANY user, demonstrated on two separate tenants" reads as Critical. Mediocre reports show one screenshot; best reports show the control and the violation side by side.
2. **Raw HTTP request/response pairs** with the exact field that changes highlighted — a triager can replicate in under 60 seconds / 5 minutes. Not prose, not video-only.
3. **Impact framed in business terms, not CVSS adjectives.** "Leaks GDPR-class PII of all 50k users", "$X of discount per request, unlimited", "credentials grant access to production AWS account". Repeatedly cited as the difference between $200 and $2,000 for the SAME bug. (https://bug-bounties.as93.net/learn/idor-and-broken-access-control-hunting/)
4. **Explicit separation of observation vs. inference vs. impact.** Label each claim as observed fact, inference, or interpretation. Overstated severity gets downgraded and burns reputation; honest instability disclosure ("reproduces 7/10 times") builds trust.
5. **Endpoint family mapping.** "This missing-check pattern exists on 14 endpoints across users/billing/documents APIs" beats a single endpoint — programs pay more for the comprehensive report.
6. **Scope of the invariant.** Best logic-flaw reports state the invariant the developer assumed and exactly which step breaks it — that's what makes it fixable.
7. **No AI slop.** Triagers (H1's Director of Triage, quoted in H1's own blog) flag AI-generated reports that "seem valid on the surface". The PoC must come from real testing: our own request/response captures. Source: https://www.hackerone.com/blog/ai-security-trends-2025

This is directly relevant to VARVEL: our oracle-first discipline (claim + control + captured evidence) already matches the winning report shape. The gap is not report craft — it's landing the primitive on a live target.

---

## 5. Recommended next builds (2-3), grounded in the data above

### Build 1 — Two-account authorization oracle as a production primitive (targets classes #1 and #2; the top of every ranking)
**What:** Productize the lab IDOR differential oracle into a pipeline stage: given a target with two provisioned accounts (cross-tenant where possible), automatically (a) harvest every object reference (id, uuid, tenant_id, document_id) from both sessions' traffic, (b) cross-replay each reference across sessions and unauthenticated, (c) classify read/write/delete/cross-tenant, (d) auto-attempt the escalation ladder (add `password`/`role`/`email` params — mass assignment), (e) emit a report-ready evidence bundle (control + violation + raw HTTP).
**Why:** IDOR/access-control is the fastest-growing class on H1 (9th HPSR), the most-upvoted class in 2023-2024 disclosures, and carries documented $5,000-$25,000 payouts. It is the single class where our existing oracle discipline maps 1:1 onto the winning mechanical shape. It requires zero new infrastructure — just multi-account provisioning and traffic replay we mostly have.

### Build 2 — OOB interaction listener + SSRF sink hunter (targets class #3)
**What:** Stand up a self-hosted interactsh-equivalent listener; build a crawler pass that inventories every URL-accepting feature (webhooks, import/fetch-from-URL, image proxies, PDF renderers, OAuth/SAML metadata endpoints) and injects unique canary URLs; on callback, auto-pivot through a fixed escalation checklist (IMDS v1/v2, common internal ports, cloud metadata for GCP/Azure) and capture the response body as evidence.
**Why:** SSRF holds the most consistent $2,500-$5,000 band in the 2024-25 disclosed data with a crisp, mechanical proof (callback + internal response body). It is the cheapest possible infrastructure addition, and blind-SSRF capability is currently a hard wall for us — without a listener we cannot even detect the class.

### Build 3 — Race harness + single-use endpoint inventory (targets class #5, feeds class #4)
**What:** Port the lab race harness to HTTP/2 single-packet attack (Burp's "send group in parallel" equivalent) and pair it with an inventory pass that flags single-use/rate-limited endpoints with security impact: coupon/credit redemption, transfer/withdraw, OTP verify, invite accept, vote/review submission. Proof shape: N parallel requests vs. sequential control, with before/after state diff.
**Why:** Race conditions are structurally undetectable by scanners and sit at the intersection of business logic and authorization — exactly the "AI misses this" whitespace per H1's 58% figure. The tooling is documented and scriptable (PortSwigger single-packet; ~30s vs 2h vs older techniques). Payout rides on the broken limit's business value, which aligns with our oracle-first evidence model.

**Explicitly deferred:** prompt-injection hunting (immature payout norms, different evidence standards), blind-injection fuzzing at scale (infra cost), mobile (no capability). Revisit after first validator-confirmed high/critical.

---

## Source-quality notes

- Exact bounty figures on individual H1 report pages are increasingly redacted; dollar figures above come from the `ReddCrow12/documents-BBP` survey (which corroborates via reddelexc/hackerone-reports and RedPacket Security mirrors), the scgajge12 upvote-list compilations, and H1-attested corporate blogs. Where a figure wasn't public, we say so rather than guess.
- The "49% of high/critical findings are IDOR/BAC" figure is from breachvex.com (secondary, no methodology shown) — directional only.
- The Oxford thesis severity/payout table is from ~3,000 disclosed reports; collection date not stated on the extract, so treat bands as approximate.
- H1 HPSR statistics are H1's own self-reported numbers.
- XBOW's severity counts (54 critical / 242 high in 90 days) are classifications by program owners of XBOW-submitted reports, per XBOW's blog; their human-review pre-submission is noted.
