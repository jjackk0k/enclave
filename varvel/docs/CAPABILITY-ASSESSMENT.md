# VARVEL capability assessment — the honest "national level" ledger

**Date:** 2026-08-29 · **Audience:** future AIs and operators. **Rule:** this file grades
VARVEL like an adversary would. Overclaiming here is the one unforgivable sin — same as
on a bounty platform. When something on this page improves, update the line WITH the
evidence (test run, campaign artifact, filing id), or leave it alone.

## What "national level" would actually mean

A state-grade offensive capability combines: (1) stealth that survives a capable,
alerted defender; (2) novel-capability generation — its own research pipeline producing
bugs/techniques the defender has never seen; (3) scale — many concurrent operations
with consistent quality; (4) discipline — perfect operational records, zero
attribution, zero self-inflicted exposure; (5) persistence of knowledge — nothing
learned is ever lost between operators or years.

## Where VARVEL genuinely stands today

| Axis | Grade | Evidence |
|---|---|---|
| Governance / discipline | **Beyond commercial tools; architecturally national-grade** | Signed scope seam + PreToolUse hook (`poc/enforcement-seam/`), hash-chained tamper-evident audit, egress deny-by-default, fail-closed ghost exit pinning. No public offensive platform (incl. PentAGI, 22k★) has code-level scope enforcement — theirs is prompt-level (`docs/competitive-pentagi.md`). |
| Operational stealth | **Strong by design, partially proven** | Human-cadence pacing, noise governor with phase reserves, chain identity. Proven fail-closed in anger (2026-08-29 stale-pin event: zero un-VPN'd traffic). NOT yet measured against an alerted blue team — that claim is untested. |
| Finding real bugs | **Proven, human-scale** | Semrush CORS High (H1 #290218, submitted 2026-08-29); WordPress static-audit rounds (102 plugins, disciplined zeros — clean days reported clean); Madara in Wordfence triage. |
| Novel-capability generation | **Lane live; first graduations landed 2026-08-29** | Research lane (`docs/RESEARCH.md`) produced its first graduated techniques same-day: MCP tool-poisoning defenses (hyp-001/hyp-002) — lab-confirmed (`deploy/range-iso/mcp-poison/`, verdict JSON) then pinned into the real client path as `engine/mcpguard.mjs` (description/drift/output screening, quarantine-by-default, audited overrides; `test/mcpclient-poison.test.mjs` 9/9). A weakness found in OUR OWN stack (listing cache abetting rug-pulls) and fixed from the same experiment. The loop works end to end: scout → hypothesize → lab → graduate. Volume of graduated techniques is still 1 class deep — the axis is now *proven*, not yet *productive*. |
| Scale | **Deliberately constrained** | 2 parallel engagements proven (tripcom + bykea, 2026-08-29). Chosen cap: AI usage budget + one operator's HITL bandwidth, not architecture. |
| Knowledge persistence | **Strong** | Write-through campaign persistence, failure ledger, bountyline outcome ledger, KIMI-NOTES cross-session memory, this file. A restart now loses ≤2s of work. |
| Tooling breadth | **Strong for web/AD/cloud-adjacent** | 65 pinned audited tools, 8 C2 transports, AD tiers, detection oracles. No kernel/firmware/radio tiers — out of scope by design, listed so no future AI claims otherwise. |
| Context/memory/cost stack | **Behind the best commercial product** | PentAGI beats us here: chain summarization, dollar cost accounting, semantic memory. Steal-list P1s 1–3 (`docs/competitive-pentagi.md` §5). |

## Verdict (2026-08-29, revised same day after the first graduation)

**Not national level yet — and this file exists to make that sentence precise.**
VARVEL today is national-grade in *governance architecture and operational discipline*
(the axes commercial tools don't even attempt), human-scale-proven at finding real
bugs, and — as of 2026-08-29 evening — *proven but not yet productive* at the axis that
defines the tier: inventing capabilities. `hypotheses.jsonl` now holds its first two
`graduated` lines with lab + production evidence attached (MCP tool-poisoning
defenses, `engine/mcpguard.mjs`). The bridge is built and one crossing is complete;
national level is when this lane produces steadily, on cron, funded by the bounty arm.

## What closes the gap (in order)

1. ~~First graduated research technique (lab-proven novel detection → pinned tool).~~
   **DONE 2026-08-29** — `engine/mcpguard.mjs` from hyp-001/hyp-002. Repeat.
2. Cost/context/memory stack (pentagi steal-list P1s) so 24/7 operation is measurable.
3. Spark → funded always-on compute → the 24/7 research + freshness loops.
4. Stealth measured against an alerted defender (purple-team the own range) — the one
   stealth claim currently resting on design rather than evidence.
