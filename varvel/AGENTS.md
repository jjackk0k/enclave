# VARVEL — agent instructions

Governed red-team + WordPress bug-bounty platform. The AI operating manual is
`docs/AGENT-GUIDE.md` — read its **"Bounty hunting — the scope doctrine"** section
before ANY hunting, drafting, or filing work. Then read
`docs/WP-HUNT-PLAYBOOK.md` — **where** to look and how to tell a real bug from a
ranked shape (the measured market, the entry-point inventory, the seven
discriminators, the signature sweep, the calibration rule). The doctrine is
enforced in code: `engine/lanes.mjs` (`classifyLane`, lane + riskLevel on every
finding) and `tools/submit-drive.mjs scopecheck` (the mandatory pre-filing gate).

## CAMPAIGNS — the only sanctioned path (read before any hunt/loop/campaign)

A "hunt", "campaign", "loop" or "run" means **running VARVEL'S OWN pipeline**. It does
**not** mean writing a bespoke loop in `.tmp/` — that is the exact mistake this section
exists to prevent (measured 2026-09-18/19: a hand-rolled `.tmp` loop spent ~80 validator
passes to produce 4 admin-gated holds, all UNFILEABLE). Full detail, exact commands and
every measured failure mode: **`docs/CAMPAIGN-DOCTRINE.md`** — read it before starting any
campaign.

1. **RECON BEFORE READING.** `node tools/cli.mjs privemap <dir> --json` (sinks) **and**
   `node tools/cli.mjs reachprove <dir> --json` (proven-reachable entry points). Live
   targets additionally use the tool shelf (`crawl`, `apisurface`, `vulncheck`, `ssrf`,
   `wappalyze`, `webpaths`, `jsmap`, `variantsweep`, `commitwatch`) — **only under a signed
   scope**. Reading code without entry-point recon is not a campaign, it is a guess.
2. **BAND-FILTER BEFORE ANY LLM JUDGEMENT.** Only `unauth` / `subscriber` / `contributor`
   candidates may reach the validator. The miner's band labels are the known weak link
   (measured: 100% of its "unauth" claims were refuted on read; every surviving candidate
   was admin-gated = UNFILEABLE). Filter first or the whole budget is wasted.
3. **THE READER IS A LANE, NOT A RIVAL.** opencode + DeepSeek reads code **inside** the
   pipeline as the reading stage, handed the **reachable entry points** and sink hints — not
   a bespoke harness beside the pipeline. Model ids: author = `deepseek-flash`
   (**this IS DeepSeek-V4.1-Flash**; `deepseek-v4-pro` is a different, ~4x pricier model) and
   **author != validator** (validator = `deepseek-v4-pro`, or the local Qwen lane on Spark).
4. **EVERY CANDIDATE RUNS THE FULL CHAIN:** refuter (`tools/refuter.mjs`, citation gate — a
   refutation that cannot quote the bundle is DISCARDED) → `classifyLane` → `scopecheck` →
   and **confirmation happens in the local lab** (`.tmp/wp-demo-lab`: WordPress + SQLite +
   bundled PHP) or the VM range. Never confirm by reading alone. Live proof > lab proof >
   nothing.
5. **GHOST CHAIN MUST BE UP FOR ANY HackerOne / live / target traffic.** Verify BOTH:
   `mullvad status` **and** `10.64.0.1:1080` dialable, plus `curl https://api.ipify.org`
   must NOT return the operator's real IP. `h1watch` fails closed without the chain — never
   work around that, and never "just run it directly". Source audits may run offline but
   must be **labelled offline** in the log.
6. **NEVER SUBMIT.** Log every outcome (including kills and rejections with their cited
   clauses) in `.tmp/SUBMISSIONS.md` the same day, and fold the lesson into
   `docs/CAMPAIGN-DOCTRINE.md`.

## Hard rules (all work in this repo)
- Tests: `npm test` is the pinned list — 0 fail is the bar. Never `node --test test/`.
- No git mutations without the operator's explicit say-so.
- `.tmp/` is deliverables — never bulk-clean.
- The submission driver NEVER clicks Submit — the operator's hand does, always.
- Honesty contract: nothing fabricated; unverified claims are reported as
  unverified; clean days are reported clean. Hallucinated code is the one
  unforgivable sin on every bounty platform.

## Bounty filings (non-negotiable)
1. Every finding is lane-classified and scopechecked BEFORE drafting. A FILE
   verdict or it does not proceed; PARK means qualify-first-or-drop.
2. Auth bands: Wordfence / Patchstack-standard = unauthenticated or
   Subscriber/Customer only (≥50k installs for Wordfence); Patchstack mVDP adds
   Contributor. Everything else = direct vendor disclosure, never a bounty form.
3. Kill classes and impact bars per the June-2026 doctrine (AGENT-GUIDE.md):
   cronjob/scheduled-task/cache/reorder sinks, minor-impact subscriber/unauth
   findings, broken access control without significant/sensitive objects, and the
   whole §4.x list (open redirect, FPD, enumeration, rate-limit, CAPTCHA, IP
   spoof, 2FA, blind SSRF, CSV/CSS injection, clickjacking, draft-post
   disclosure, AI token exhaustion, AC:H, PII-only IDOR outside mVDP,
   contributor-stored XSS, HTML-only injection) are NO-FILE.
4. Account jeopardy: Patchstack ≥50% monthly rejection rate = leaderboard
   removal + cooldown, ≥67% = XP zeroed, one clearly-out-of-rules report =
   one-week ban; Wordfence 10 OOS in 7d = 7-day block, 4 AI-hallucinated =
   permaban. When in doubt, PARK — a parked finding costs nothing, a rejection
   costs rate.
5. Log every outcome (including rejections with their exact cited clauses) in
   `.tmp/SUBMISSIONS.md` and fold the lesson into the doctrine the same day.
6. Know the market before proposing a hunt: `docs/WP-HUNT-PLAYBOOK.md` §1 is
   measured from the pinned NVD snapshot (Wordfence writes 79% of WP-plugin
   CVEs; the most common unauth shape is an unnonced settings write at 18.9%;
   44.5% of all WP-plugin CVEs are the low-impact band we must not file).
