# AI-Assisted Bug Bounty: Practitioner State of the Art — August 2026

**Prepared for:** varvel · **Date anchor:** 2026-08-31
**Scope note:** Builds on prior internal research (XBOW 2025 validator architecture, H1 hacktivity stats, AI attack-surface growth). This brief covers the *practitioner community* — named hunters, their stacks, classes that pay, economics, and copyable techniques. Every claim is labeled **[VERIFIED-DISCLOSED]** (vendor advisory / disclosed report / patch), **[SELF-REPORTED]** (hunter's own blog/podcast, checkable leaderboard), or **[UNSOURCED]** (claim without verifiable artifact).

**Source-access caveat:** X/Twitter is effectively login-walled for content. `site:x.com` web searches returned nothing usable; a direct fetch of `x.com/ctbbpodcast` rendered only the profile bio, no tweets. All X-origin claims below come via podcasts, blogs, and news mirrors. No quotes or handles were fabricated.

---

## TL;DR

In 2026 the winning pattern is **not** "autonomous bot finds bug." It is: a skilled hunter builds a *harness* — persistent auth, exhaustive endpoint coverage queues, adversarial validation, per-program report judges — and lets commodity models run inside it. The top published results ($500k/3 months at Google VRP; 728 H1 reports in 6 months part-time; 126 bugs/5 months by a two-person team where one is a full-time cardiologist) all share that shape. Meanwhile the *slop* side collapsed programs: curl closed its bounty (confirmed rate fell below 5%), HackerOne paused Internet Bug Bounty. The moat is validation + fresh scope + post-auth access, not model choice.

---

## 1. Who is publicly landing AI-assisted findings

### Tier 1 — evidence-backed, high impact

| Hunter | Claim | Verification | Sources |
|---|---|---|---|
| **Brutecat (Arvin Shivram)** + collaborator "Michael" | **$500,000 from Google VRP in <3 months**, 20+ bugs across ~1,500 Google APIs, using a Claude-driven pipeline over discovery documents + 3,600 harvested API keys. Google Voice/Fiber unauth PII + number-assignment ATO marked **P0/S0, patched within hours, $20,000**; AdExchange staging→prod data exposure **$30,000**; Eldar (internal privacy tool) API exposure **$26,674**; more at $9k/$6k | **[VERIFIED-DISCLOSED]** — full request/response evidence in his own writeup; Google patched; corroborated by TechRepublic and CTBB podcast Eps 177–178 | [brutecat.com writeup](https://brutecat.com/articles/hacking-google-with-ai/) · [TechRepublic](https://www.techrepublic.com/article/news-google-ai-bug-bounty-pipeline/) · [CTBB Ep 178](https://www.criticalthinkingpodcast.io/600k-in-3-months-brutecat-pt-2/) |
| **Joseph Thacker (rez0) + JD (xssdoctor)** | Two-person hackbot: **126 bugs in 5 months** (H1 + Google VRP + direct). 70% High/Critical; **89% true-positive** (77 accepted + 35 dup, only 14 info/NA); largest bounty **$15,000** (one-click ATO). Notables: Western Union unauthenticated customer-PII API (enumeration of full customer DB), Google Delivery Readiness Portal full partner-platform takeover via expired partner domain + role-escalation, Raydium on-chain stored XSS → Solana wallet-drain primitive, Gmail MCP server OAuth scope escalation **$7,500** (incl. 50% bugSWAT bonus), multiple paid $4.5k–$6.5k IDOR/secret-leak crits with H1 report IDs listed | **[VERIFIED-DISCLOSED]** — report IDs + bounty amounts published; Western Union/Raydium chains described to request level | [josephthacker.com — "The Bug Bounty Singularity: Our Hackbot"](https://josephthacker.com/hacking/2026/07/01/we-built-a-hackbot.html) |
| **Ads Dawson (0xMoose)** (Dreadnode) | **728 reports Jan 1–Jul 7 2026** (vs 124 in all of 2025), 853+ submissions across 270+ programs, 223 high/critical, 78 unique CWEs, accepted-findings avg CVSS 6.38, non-accepted closures *fell* 32%→24% as volume 6x'd. Peak day: 21 reports (3C/7H/7M, 3 paid same day). #3 USA BBP leaderboard, #1 USA VDP response, ~#30 Meta all-time, #4 Bugcrowd US (June). Two awards at a live hacking event (most-unique VRT classes, most-unique targets) | **[SELF-REPORTED]** but granular and leaderboard-checkable | [Signal Over Noise: AI Agents and the Operator Moat](https://0xmoose.substack.com/p/signal-over-noise-ai-agents-and-the) · [HackerNotes Ep 184](https://blog.criticalthinkingpodcast.io/p/hackernotes-ep-184-hackbots-at-scale-with-ads-dawson-smaller-models-bigger-signal) |
| **Team Xint Code** (Tim Becker, Jacob Newman, Juno IM) running Theori's Xint Code | **CVE-2026-23479** — Redis use-after-free RCE, 2+ years undetected in all stable branches; working exploit demonstrated at a live-hacking event Dec 2025; patched 5 May 2026 (NVD 8.8) | **[VERIFIED-DISCLOSED]** — Redis advisory names the humans + tool | [Stingrai curl/Redis analysis with full refs](https://www.stingrai.io/blog/curl-bug-bounty-ai-slop-triage-real-findings) |
| **AISLE** (Stanford spinout, Stanislav Fort et al.) | **12 of 12 OpenSSL CVEs** in the Jan 2026 coordinated release (incl. CVE-2025-15467, CVSS 9.8 pre-auth RCE potential); 5 curl CVEs in 8.18.0; **20 OpenSSL zero-days in 6 months**; first-ever double-independent-discovery of an OpenSSL 0-day (CVE-2026-28386). Claim of 180+ externally validated CVEs across 30+ projects | **Mixed:** CVE-credited findings **[VERIFIED-DISCLOSED]** (OpenSSL/curl/libpng/OpenEMR advisories); the "180+" aggregate is **[SELF-REPORTED]** | [Sonatype AI Vulnerability Storm evidence ledger](https://www.sonatype.com/resources/research/ai-vulnerability-storm) · [AISLE blog](https://aisle.com/blog/aisle-discovers-20-openssl-zero-days-in-6-months) · [Schneier](https://www.schneier.com/blog/archives/2026/02/ai-found-twelve-new-vulnerabilities-in-openssl.html) |
| **Anthropic (Opus 4.6 → Mythos Preview)** | 22 Claude-credited Firefox CVEs (MFSA 2026-13), 6 more (MFSA 2026-20), then **271 vulnerabilities in Firefox 150** from the initial Mythos eval (MFSA 2026-30; Mozilla CTO: "we've found no category of vulnerability that humans can find that this model can't"); FreeBSD 17-year kernel RCE CVE-2026-4747 with auto-generated ROP chain; OpenBSD 27-year SACK overflow; FFmpeg 16-year OOB write that survived 5M fuzzer iterations | Mozilla/FreeBSD/OpenBSD items **[VERIFIED-DISCLOSED]** (vendor-credited). The "thousands of zero-days" claim is **[SELF-REPORTED]** — >99% under SHA3-224 hash commitments (Project Glasswing, ~40 vendors, mandatory disclosure window Jul 7–Sep 5 2026); The Register/Anchore could tie only one CVE directly to Glasswing as of mid-April | [Sonatype ledger](https://www.sonatype.com/resources/research/ai-vulnerability-storm) |
| **XBOW** (2026 follow-on, not the 2025 story) | 3 Microsoft March 2026 Patch Tuesday critical RCEs: CVE-2026-21536 (CVSS 9.8, unauth RCE), CVE-2026-32194, CVE-2026-32191 (Bing, SYSTEM-level). Cumulative 1,060 H1 submissions over 90 days: 54C / 242H / 524M / 65L | **[VERIFIED-DISCLOSED]** (MSRC CVEs) | [Sonatype ledger](https://www.sonatype.com/resources/research/ai-vulnerability-storm) |
| **Horizon3.ai** (Naveen Sunkavally, Claude-assisted) | CVE-2026-34197 — Apache ActiveMQ 13-year-old chained unauthenticated RCE | **[VERIFIED-DISCLOSED]** | [Sonatype ledger](https://www.sonatype.com/resources/research/ai-vulnerability-storm) |

### Tier 2 — credible practitioner accounts (self-reported)

- **Rhynorater (Justin Gardner)** — runs 4 tmux panes of Claude Code alongside manual hacking plus an autonomous background attack env; custom skills (caido-mode, JS analysis, IaC) + a validator agent. Best find: XSS on "one of the most well-known domains" where AI handled the protobuf binary-format exploitation. Reports volume up, quality/dup rate unchanged. **[SELF-REPORTED]** — [YesWeHack interview](https://www.yeswehack.com/community/llms-bug-bounty-interview-rhynorater)
- **Tsvetan Stoychev** (ex-Akamai principal engineer) — 6 months auditing ClickHouse with Copilot + Claude Opus + Gemini; multiple paid Bugcrowd findings (OOB read/write class); first paid bug ~6–8 weeks in; 3–4 h manual verification+report per finding. **[SELF-REPORTED, vendor-hosted]** — [ClickHouse guest post](https://clickhouse.com/blog/how-i-hunt-for-vulnerabilities-with-ai)
- **FireCompass** (vendor, transparent data) — agent `firecompass-ai` reached **H1 top-3 US** on **~$5,000/month** all-in. 150 reports in the quarter: **38.7% duplicate, 32.7% informative, 12.7% accepted** (13 triaged + 6 resolved), 4.0% N/A; counting dupes as genuine, **51.3% of filings were real bugs**. 64% of severity-rated reports were High/Critical. **[SELF-REPORTED vendor data with leaderboard snapshots]** — [FireCompass methodology post](https://firecompass.com/blog-ai-penetration-testing-hackerone-top-3/)
- **Autonomous Cyber "FUZZ E"** — single overnight run produced a $5,000 ICU i18n stored XSS in a major OSS web framework (patch merged) and a $4,580 file-read, per rez0's blog with report IDs. **[SELF-REPORTED via third party]**
- **Bronxi** (Bugcrowd guest author) — the counterpoint: built a CrewAI 4-agent pipeline for info-disclosure in indexed PDFs/XLSX, got buried in false positives, and reverted to his validated Bash automation with AI only writing the report. Uses AI for code-path review and IDOR hunting; "AI is an amplifier of proven personal methodology, not a substitute." **[SELF-REPORTED]** — [Bugcrowd blog](https://www.bugcrowd.com/blog/what-i-learned-building-ai-agents-for-bug-bounty-hunting/)

### The slop side (skepticism baseline)

- **curl killed its bounty (Jan 31 2026)**: confirmed-vulnerability rate fell from >15% to **<5% in 2025** ("not even one in twenty was real" — Stenberg). 87 confirmed vulns and >$100k paid over the program's life. [Stingrai analysis](https://www.stingrai.io/blog/curl-bug-bounty-ai-slop-triage-real-findings) · [Socket](https://socket.dev/blog/curl-shuts-down-bug-bounty-program-after-flood-of-ai-slop-reports) · [Bugcrowd op-ed](https://www.bugcrowd.com/blog/hacker-opinion-piece-how-lazy-hacking-killed-curls-bug-bounty/) **[VERIFIED]**
- **HackerOne paused Internet Bug Bounty (Mar 27 2026)** citing AI-slop overwhelm. [Sonatype timeline](https://www.sonatype.com/resources/research/ai-vulnerability-storm) **[VERIFIED]**
- **Elastic (defender side)**: H1 2026 report volume (>1,390 in H1) exceeded 2024+2025 combined; built an AI triage pipeline at **~$2/report** (85% agreement with humans, calibrated on 3,317 historical reports; adversarial review caught ~15% errors). [Elastic Security Labs](https://www.elastic.co/security-labs/ai-vulnerability-triage-bug-bounty-hackerone) **[VERIFIED — defender-published]**
- A 53-program census found **zero** programs ban AI-written reports outright — the gate is reproducibility, not authorship. [Stingrai census](https://www.stingrai.io/blog/ai-generated-vulnerability-report-policies-census)
- r/bugbounty sentiment (via weekly aggregators): frustration with dup/informative closures, "bug hunting is dominated by programming skills," platform-abuse threads — the community mood is post-hype. [Zenn Bug Bounty Weekly, 2026-05-11](https://zenn.dev/scgajge12/articles/cc10adcbf73784?locale=en)

---

## 2. Tooling stacks in actual use

**The meta-finding: everyone serious is homegrown-on-top-of-Claude-Code/Codex. Off-the-shelf agents (Strix, CAI) are entry points, not what the leaderboard operators run.**

| Layer | What practitioners use |
|---|---|
| **Agent runtime** | Claude Code (dominant — Rhynorater, rez0/xssdoctor, Ads, YesWeHack's lab tests all converge on it; "Claude by a long shot"), Codex desktop/CLI (rising, `/goal` mode), GitHub Copilot agent mode (ClickHouse case). Open-source stack: **Strix** (usestrix) and **CAI** are the named OSS frameworks; Strix explicitly credited by rez0/JD as lowering the barrier |
| **Models** | Opus for chaining/verification, Sonnet for recon/mapping, Haiku-class for bulk parsing (YesWeHack's role split). Ads Dawson's notable move: **open-weight GLM as the main driver + Qwen-class tiny sub-agents** for JS analysis/note-taking/queue work, behind a LiteLLM SDK so any model drops in; inference bills "low thousands/month" at *real* token cost. Frontier-lab access gates matter: Anthropic **Cyber Verification Program** and OpenAI trusted-access are prerequisites for sustained offensive use (both the ClickHouse researcher and YesWeHack describe the process); Opus refusal spikes were observed when new cyber-capable models shipped |
| **Proxy/tool bridge** | **Burp Suite MCP server** (official BApp) and **Caido skills** (curl-first rewrite: export request→curl config w/ cookie jar, match-and-replace generation); GhidraMCP for RE; agentmail.to or Cloudflare custom-domain inboxes for agent email flows |
| **Orchestration** | Ralph loops (agent self-generates follow-up tasks until a stop condition) + `confirm_testing_complete()` coverage gates; an **orchestrator bot** that watches the worker, kills thin targets ("kill-fast" validated in the wild), and pushes hard on rich ones; Discord log streaming as observability (rez0/JD: "the logs became more valuable than the findings") |
| **Validation** | Dedicated **validator/adversary bots rewarded for killing findings** (rez0/JD: FP 80%→60%); Ads's `assess-confidence` tool with a stronger reflection model + **per-program JSON memory** ("six agents already thought they found XSS here; move on"); Elastic's defender-side mirror: 8-stage pipeline + independent adversarial review |
| **Skills management** | 65–96 skills at maturity; generated HTML skill-reviewer UI (edit/approve/trash cards); **GEPA**-style hill-climbing of skill definitions; linting front matter (broken routing metadata silently kills skills); diffing human report edits back into the report skill via the H1 API |
| **Session/auth infra** | The unglamorous winner: a **real browser on a physical machine** acting as a login agent (rez0/JD burned **80% of tokens on auth** before this fix; anti-bot kills datacenter headless Chrome; Browserbase "never reliably worked"). Meta's agentic **FBDL MCP** (provision accounts/groups/test data programmatically; 20% report bonus up to $500) is the vendor-side version |
| **Homegrown vs off-the-shelf verdict** | Every top result is homegrown harness; default harnesses (bare Claude Code/Codex) now find mediums unassisted but the edge is shrinking — Ads calls this out explicitly. Brutecat's pipeline (custom API Explorer + MCP tools) is fully bespoke. Bronxi's CrewAI experience is the cautionary off-the-shelf tale |

Sources: [HackerNotes 184](https://blog.criticalthinkingpodcast.io/p/hackernotes-ep-184-hackbots-at-scale-with-ads-dawson-smaller-models-bigger-signal) · [HackerNotes 182](https://blog.criticalthinkingpodcast.io/p/hackernotes-ep-182-what-hackbots-keep-finding-guest-tokens-graphql-and-cognito-bugs) · [YesWeHack Claude Code guide](https://www.yeswehack.com/learn-bug-bounty/llm-series-claude) · [rez0 hackbot post](https://josephthacker.com/hacking/2026/07/01/we-built-a-hackbot.html) · [brutecat writeup](https://brutecat.com/articles/hacking-google-with-ai/) · [ClickHouse post](https://clickhouse.com/blog/how-i-hunt-for-vulnerabilities-with-ai) · [Strix](https://github.com/usestrix/strix) · [AppSec Santa 39-tool survey](https://appsecsanta.com/research/ai-pentesting-agents-2026)

---

## 3. Vuln classes: what's actually paying vs what's dup/NA bait

**Paying (accepted/resolved or paid, with evidence):**

1. **Broken access control / IDOR / BOLA at API scale** — the dominant paid class. FireCompass: 48/150 reports. Brutecat's entire $500k is access-control on APIs. rez0/JD's list is a wall of IDOR/authz crits (customer search, site contacts w/ cleartext PICs, billing IVR, cross-merchant settlements). *Prior research noted IDOR payouts +29% YoY — 2026 practitioner data says the trend held.*
2. **Missing authentication on internal/staging APIs** — Western Union multiparam lookup, POS-lending Heroku backends, AdExchange staging pointing at prod data, `*.corp`-origin-whitelisted internal APIs. Pattern: *the staging/preprod/autopush host is weaker than prod but serves prod data.*
3. **Guest / partial-auth token bugs on legacy routes** — Wayback → legacy API mints a guest token → token reads/writes objects it shouldn't. "Three or four of these in the last month or two" per HackerNotes 182. Directive: *get the agent SOME form of auth first.*
4. **Third-party auth misconfig** — Cognito writable custom attributes → self-promote to admin (a **five-figure crit on a public program** the week of Ep 182); Firebase anonymous auth + permissive Firestore rules (multiple crits in rez0's list); Supabase RLS `.eq()` mistakes in vibe-coded apps.
5. **OAuth/MCP-server flaws** — the new-money class: Gmail MCP `label_thread` scope escalation ($7,500), full OAuth ATO via open Dynamic Client Registration on an enterprise MCP server, Google operating **700+ MCP servers** with hidden (non-enumerated) tools, X shipped an MCP as fresh surface.
6. **JS-bundle secrets** — hardcoded bearer tokens in shipped JS ($6,561), sourcemap `sourcesContent` greps revealing committed `/dummyData/` PII ($5,500), Contentful preview tokens in sourcemaps.
7. **XSS, but only the weird ones pay** — checksum-gated reflected XSS (code-golf payload), CSS-injection char-by-char exfil via `@font-face` + `unicode-range` when CSP blocks script (works on observability/AI-logging tools that render JSON), postMessage `window.opener` code leaks, on-chain stored XSS. Generic reflected XSS is dup-central.
8. **Memory safety in C/C++** (AISLE/Mythos/ClickHouse lane): OOB r/w, UAF — including bugs 16–27 years old that fuzzers missed. Highest per-bug CVE value; requires codebase access and a Docker repro harness.
9. **SSRF chains via internal proxy/"agent" gateway endpoints** that forward attacker URLs server-side.

**Dup/NA/informative bait (what to NOT submit):** existence enumeration oracles (explicitly "NOT a vulnerability" in Brutecat's prompt), self-XSS, non-exploitable CORS, volumetric DoS, info-disclosure in open-source products (sourcemaps, version numbers — Elastic rejects these categorically), 403→401 middleware flips mistaken for authz bypass (**GraphQL is the #1 FP source**), anything asserted-without-repro (curl's <5% lesson). **Dupes are exploding community-wide** — depth commoditized (HackerNotes 187), and FireCompass's data shows ~3/4 of genuine findings arrived second.

---

## 4. Throughput & economics (reported numbers)

| Operator | Throughput | Acceptance / quality | Cost |
|---|---|---|---|
| Brutecat + Michael | ~$500k / <3 months; 20+ bugs over 1,500 APIs | ">50% accuracy" after validator+prompt iteration; review reduced to "click Play, see if it still works" | Not disclosed (Claude API; 2 people) |
| rez0 + xssdoctor | 126 bugs / 5 months, part-time (one is a full-time cardiologist) | 89% true-positive (77 accepted + 35 dup; 14 info/NA); largest $15k | "Hundreds in token cost to find thousands in bounties" |
| Ads Dawson | 9–13 reports/day part-time; 728 in ~6 months; peak 21/day | Non-accepted closures 32%→24% while volume 6x'd; accepted avg CVSS 6.38 | "Low thousands/month" at real token cost; warns subscription-ROI math is subsidized |
| FireCompass | 150 reports/quarter | 12.7% accepted, 51.3% genuine incl. dupes; **bottleneck was human review shift capacity — dupes lost by minutes/hours** | ~$5,000/month all-in (infra + tokens + review) |
| Tsvetan (ClickHouse) | First paid bug ~6–8 weeks in; now "finds vulnerabilities more often" | 3–4 h manual verification+writeup per finding; dual-model fact-check on reports | $400/month (Claude Max 20x + ChatGPT Pro) |
| Defender context (Elastic) | 1,390+ inbound reports H1 2026 (>2024+2025 combined) | AI triage at 85% human agreement | **~$2/report triaged** ($0.50–1.15 analysis; +$0.80–4.90 repro on ~30%) |

**Macro pressure on payouts:** GitHub cut public bounty payouts (Jul 2026), CTBB Ep 186 references "the Shrinking Bounty Table," dupes exploding, live-event bonuses (bugSWAT 50%, Meta FBDL 20%) increasingly material to ROI. Speed-to-file and program-incentive arbitrage now determine realized $ as much as find-rate. [Cyber Replay on GitHub changes](https://cyberreplay.com/blog/what-security-teams-should-do-now-github-bug-bounty-changes-2026/)

---

## 5. Concrete techniques worth copying

1. **Evidence-bound reporting.** Every probe returns an `operation_id`; reports must cite op-IDs that link to the *actual* stored request/response, replayable with one click. Kills hallucination at review and made Brutecat's >50% accuracy possible. (varvel's OOB infra already half-builds this.)
2. **Coverage gates, not vibes.** `confirm_testing_complete()` refuses to let the agent finish until every in-scope endpoint has ≥1 probe; endpoint classification into logical groups with findings passed forward to subsequent groups; multi-key/multi-identity probing with response-hash grouping.
3. **Ralph loops + orchestrator kill-switch.** Agent self-extends investigation on weak signals; a supervisor cuts thin targets and pushes on rich ones ("there is definitely a bug here. find it!"). Matches varvel's kill-fast budgets.
4. **Adversarial validator rewarded for kills** + **per-program rejection memory** (JSON log of "this class was NA here before") — but keep it call-when-needed, not always-on (always-on reflection injects FPs and can kill the 5th-try success). Tune for *impact*, not *bypass*.
5. **Real-browser session broker.** Physical machine, real Chrome profile/fingerprint, proactive token refresh; cloud agents never touch login pages. Biggest single quality jump rez0/JD saw — crits are post-auth. (Direct synergy with varvel's account factory.)
6. **Fresh-scope + change detection as dup defense.** Ingest newly published scope immediately (lowest dup probability); diff JS bundles over time ("JS changed → retest this endpoint now").
7. **Report-as-product.** 80% AI-written from a refined skill; a judge model checks format/length/program-rubric; per-program rubrics (Google VRP's report-quality multiplier deserves its own skill); diff your manual edits back into the skill monthly. PoC as HTML page or `curl | python3` with a proxied toggle; **always show the negatives** ("I cannot X, but with the same token I can Y").
8. **Codebase hygiene for source audits.** Delete `.claude/`, `.cursor/`, `.github/`, `AGENTS.md`, tests/docs/benchmarks before pointing agents at a repo (prevents instruction pollution and test-path FPs); write PoCs in **Python** (Node syntax errors burned a month); use **handoff prompts** to escape bad trajectories ("we must not use /proc/pid/mem; describe direction, restart fresh").
9. **Hill-climb everything narrow.** GEPA-style optimization of report length, skill routing, tool choice; write model failure modes back into prompts at two levels (instance: "curl installs in a weird dir here"; meta: "I struggle with this bug class this way").
10. **Program-incentive arbitrage.** Meta FBDL MCP = +20% (≤$500) per report with a reusable repro script; bugSWAT/live events = 50% bonuses; Google pays premiums for fully automated PoCs (learn the target's CLI so the agent can provision its own test objects); targets that let you spin up/tear down accounts are where to invest tooling.
11. **Model routing & subsidy discipline.** Small/open models (GLM, Qwen-class) for sub-agents; frontier only where chaining/verification earns it. Track bounties-per-real-token-dollar; subscription-subsidized ROI is tech debt.
12. **Frontier access as logistics.** Anthropic CVP / OpenAI trusted-access verification are gating items — budget lead time; keep an OpenRouter fallback for outages/refusal spikes.

---

## 6. Skepticism check — claim ledger

**[VERIFIED-DISCLOSED]**
- Brutecat $500k Google campaign (evidence-rich writeup; Google patched P0/S0 within hours; press corroboration)
- rez0/xssdoctor 126-bug portfolio with report IDs and $ amounts
- CVE-2026-23479 (Redis, Xint Code/Theori); AISLE's OpenSSL/curl/libpng CVEs; Anthropic's Mozilla/FreeBSD/OpenBSD/FFmpeg items; XBOW's 3 MSRC CVEs; CVE-2026-34197 (ActiveMQ/Horizon3)
- curl closure metrics; H1 pausing IBB; Elastic triage economics (defender-published)

**[SELF-REPORTED]** (credible, checkable, but hunter/vendor-supplied)
- Ads Dawson's 728-report dataset and leaderboard ranks; FireCompass's disposition table and "$5k/month → top-3" (vendor with marketing incentive, but unusually transparent); Rhynorater's workflow; Tsvetan/ClickHouse payouts (vendor-hosted guest post); FUZZ E overnight-run figures

**[UNSOURCED / treat with suspicion]**
- Anthropic "thousands of zero-days" — >99% embargoed under hash commitments; independent tally (Register/Anchore, Apr 15) tied exactly **one** CVE to Glasswing at that date. The Jul 7–Sep 5 mandatory-disclosure window (closing *this week*) is the natural verification checkpoint — watch it.
- AISLE's "180+ externally validated CVEs" (≈26 public with credit at last ledger update)
- FireCompass "sub-2% FP in production"
- Content-farm claims like "$50K+/month with Claude/Grok" ([example](https://www.buildmvpfast.com/blog/ai-bug-bounty-hunting-claude-grok-vulnerability-2026)) — no named hunter, no disclosed reports; ignore.
- X/Twitter-first claims generally: content is login-walled; nothing in this brief rests on an unverifiable tweet.

---

## 7. What varvel should copy next — ranked by expected payout impact

Given existing capabilities: account factory, 4-role IDOR oracle, OOB callback infra, headless browser lane, jsminer, soft-404 baselining, kill-fast budgets, target scoring, novelty gate.

1. **Replayable-evidence binding for every finding** (operation_id → stored request/response → one-click replay, incl. OOB hits). This is the single highest-leverage move: it's what turned Brutecat's review into "click Play" and it directly raises acceptance rate while cutting your own triage time. You already have OOB infra — extend it into a full interaction/evidence store.
2. **Real-browser persistent-session broker** feeding your account factory. Post-auth is where the crits are (rez0/JD's single biggest quality jump; 80% of their tokens were dying on login walls). Headless lane stays for recon; a real-fingerprint lane owns login + token refresh; agents request live sessions as a service. Then point the 4-role IDOR oracle at the *guest/partial-auth token* class specifically — it's the freshest paying pattern.
3. **Coverage queue with completion gates.** Turn jsminer output into a per-target endpoint queue the agent must drain (`confirm_testing_complete` semantics), with multi-identity probing and response-hash grouping across your 4 roles. This converts jsminer from recon into a systematic IDOR/BOLA machine — the class that dominated every 2026 payout dataset.
4. **Adversarial validator with per-program memory.** A kill-rewarded second model + per-program JSON of rejected classes/patterns, wired into your novelty gate. Call-when-needed, impact-tuned. Target: cut NA/informative rate before submission (FireCompass lost 32.7% to informative; curl died at <5% real).
5. **Fresh-scope + JS-diff trigger.** Immediate ingestion of newly published scope + JS bundle diffing ("this endpoint's code changed, retest now"). Dupes are the #1 value leak (38.7% at FireCompass, ~3/4 of genuine findings arriving second; community-wide dup explosion). Speed-to-file on fresh surface beats deeper testing on stale surface.
6. **Third-party auth/config class pack.** Cognito writable-attribute privesc, Firebase anon-auth + Firestore rules, Supabase RLS, open OAuth Dynamic Client Registration on MCP servers. Still paying five-figure crits with near-zero scanner competition.
7. **Per-program report judge + rubric loop.** 80% AI-drafted reports graded against per-program rubrics (length, code-callout preferences, Google-VRP-quality-multiplier skill); monthly diff of your manual edits back into the skill. Cheap to build, directly moves payout-per-accepted-report.
8. **Program-incentive arbitrage in target scoring.** Weight: FBDL-MCP-eligible Meta reports (+20%), live-event/bugSWAT windows (+50%), targets with programmatic account provisioning (agent can self-provision test objects), programs with published quality multipliers. Fold into target scoring as a payout-multiplier feature.

**Not worth copying:** multi-agent orchestration for its own sake (Bronxi's CrewAI lesson — revert to deterministic automation wherever a Bash-equivalent works); always-on reflection loops; spraying >10 targets at once (depth-per-program won for Ads); chasing generic reflected XSS (dup bait).

**Watch item for next 30 days:** the Anthropic/Glasswing mandatory-disclosure window closes ~Sep 5 — if even the lower bound of the "thousands" claim verifies, expect a second-order flood of patches, re-disclosed techniques, and fresh copycat hunting on the same classes; if it doesn't, expect a credibility reset that makes platform triagers harsher on all AI-flavored reports.

---

*Research completed 2026-08-31. All URLs verified reachable during research unless noted. X/Twitter primary content was inaccessible (login wall); no quotes or handles were fabricated.*
