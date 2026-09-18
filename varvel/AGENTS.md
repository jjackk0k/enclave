# VARVEL — agent instructions

Governed red-team + WordPress bug-bounty platform. The AI operating manual is
`docs/AGENT-GUIDE.md` — read its **"Bounty hunting — the scope doctrine"** section
before ANY hunting, drafting, or filing work. Then read
`docs/WP-HUNT-PLAYBOOK.md` — **where** to look and how to tell a real bug from a
ranked shape (the measured market, the entry-point inventory, the seven
discriminators, the signature sweep, the calibration rule). The doctrine is
enforced in code: `engine/lanes.mjs` (`classifyLane`, lane + riskLevel on every
finding) and `tools/submit-drive.mjs scopecheck` (the mandatory pre-filing gate).

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
