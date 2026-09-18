# VARVEL Research Lane — new-surface discovery & technique invention

**Purpose:** the part of VARVEL that hunts what has no signature yet — emerging attack
surfaces and novel vulnerability *classes*, not just novel instances. Everything else in
VARVEL finds bugs; this lane finds *areas*.

## The hard rule (non-negotiable)

**Novel-technique experiments run ONLY against our own lab** — `targets/` (demo-corp,
Axiom), `deploy/range-iso/`, `vm-lab.mjs`, or self-hosted fixtures we own end to end.
Never a live bounty target, never a third party. A new technique graduates out of the
lab only after it reproduces on demand, and its first live use still crosses the normal
doctrine: lane-classify → `submit-drive.mjs scopecheck` → FILE-or-PARK → Jack's hand
submits. The lab is where we may be loud; engagements are where we stay governed.

## Operating protocol

1. **Hypothesis log** — `docs/research/hypotheses.jsonl` (append-only). One JSON per
   line: `{id, at, direction, hypothesis, labFixture, status: open|testing|confirmed|
   refuted|graduated, evidence}`. Refuted lines stay forever — the failure-ledger rule
   applies to research too; a future agent must never re-test a dead idea unknowingly.
2. **Calibrate on known-knowns** — before trusting a new detector/experiment, prove it
   catches a KNOWN instance of the class in the lab (the honesty contract applied to
   research: a detector that has never caught anything is a hypothesis, not a tool).
3. **Graduation gates** — a confirmed lab result either (a) becomes a pinned tool/test
   in `tools/` + `test/` (audit + 0-fail bar), (b) becomes a bounty hypothesis aimed at
   a scoped program via the normal pipeline, or (c) becomes a writeup. Status flips in
   the log the same day.
4. **Directions doc** — the ranked, web-grounded scouting map:
   `docs/research/directions-2026-08-29.md` (refreshed quarterly or when a direction
   graduates/dies).

## Current top directions (2026-08-29 scouting, full rationale in the directions doc)

1. **MCP / agentic tool-use attack surface** — tool poisoning, cross-server injection,
   IDE auto-execution. VARVEL can self-host the full attacker/server/victim triad
   in-lab (`mcpserve.mjs` is ours). Grindable seam, first result ~2–6 weeks.
2. **HTTP desync on HTTP/3/QUIC** — live advisories + published AI-driven research
   blueprints prove the seam; best payout proximity of the ten.
3. **Passkey/WebAuthn ceremony manipulation** — young spec surface, relying-party
   validation logic systematically under-fuzzed; suits corpus-scale code reading.

## The 24/7 plan (post-spark)

When bounty income funds always-on compute: a recurring research cron (off-peak minute)
cycles the open hypotheses — one direction per round, lab experiments only, results
appended to the log, graduations surfaced to the operator as console cards. Until then:
one scouted directions doc + manual rounds when Jack calls them, exactly like the one
that produced this file.

> Research is the only lane allowed to dream. It still wakes up in the lab.
