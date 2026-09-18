# FUTURE PROJECT SEED — Qwen fine-tune pipeline ("QWEN-PIPELINE")

**Status:** SEED DOCUMENT — goals and framing only, NOT a design. Written 2026-09-01 so
the project can start cold. Owner: Jack. Related: `docs/STATE-OF-VARVEL.md`.

---

## 1. Goals as stated

- Fine-tune **Qwen 3 (27B-class)** on a **DGX Spark** for: cyber / code /
  vulnerability-hunting capability, **and operating varvel** (the H1 bug-bounty
  platform — its tools, doctrine, honesty contract, and workflows).
- Inference target afterwards: **2 concurrent instances, ~30 tok/s each, 262k
  context** — i.e., high-throughput local serving good enough to run varvel's agent
  lanes without frontier-API spend.

Intent: own the model layer the way varvel already owns the harness layer. The
practitioner research (`research/2026-08-31-ai-hunter-practitioner-brief.md`) says the
moat is harness + validation + fresh scope, not model choice — this project is about
making the model *cheap, private, and varvel-native*, not about beating frontier
models on general benchmarks.

## 2. What varvel already produces that is training-relevant

Varvel's honesty discipline means its artifacts are **high-quality labeled security
reasoning data**, not just logs:

- **`data/exports/`** — per-program state/surface/writes exports
  (`<program>-<kind>-YYYY-MM-DD.{json,md}`): structured records of what was tested,
  what was queued, what was exercised, and the honest verdict.
- **Probe matrices** (`.tmp/*matrix.json`, `.tmp/addr-edit-matrix.json`, zomato
  read/write matrices, localizejs oracle runs) — cross-account differentials with
  controls included: exactly the shape of "reasoning with controls" data that's hard
  to synthesize.
- **Honesty-labeled verdicts** — CLEAN / VALIDATED / CLAIMED-UNVALIDATED outcomes,
  oracle verdicts (enforced / violated / inconclusive), kill-fast stops, COVERAGE-
  INCOMPLETE ledgers. Negatives are labeled as negatives — rare and valuable.
- **Submission drafts + outcomes** — `.tmp/*submission*.md`, `.tmp/SUBMISSIONS.md`,
  the gold-standard `.tmp/wordfence-madara-option-overwrite-submission.md`, plus
  rejection/duplicate outcomes (GiveWP rejection, semrush #2666357 DUPLICATE) =
  labeled examples of what does NOT pass triage.
- **Novelty-gate verdicts** — BLOCKED / UNVERIFIABLE / REVIEW-NEEDED / CLEAR with
  named reasons (edge-generated behavior, impact-bar failures, hacktivity candidate
  lists): labeled "is this worth filing?" judgments.
- **Build docs + KIMI-NOTES** — decision-level reasoning trails (why a class is dup
  bait, why a finding was killed, root-cause writeups like the captcha/mail.tm/stall
  incidents): procedural knowledge for the "operating varvel" half of the goal.
- **Research briefs with claim ledgers** — VERIFIED / SELF-REPORTED / UNSOURCED
  labeling is itself a behavior worth teaching.

## 3. Data-curation principles (hard rules, carried over from varvel doctrine)

1. **Keep the honesty labels.** A CLEAN verdict must stay a CLEAN verdict in training
   pairs; the model must learn that reporting clean is a correct, first-class outcome.
2. **NEVER train on fabricated findings.** Any artifact produced before an honesty fix
   (e.g. the localizejs "9 HIGH" scanner-confidence artifacts, pre-soft-404-baseline
   content-discovery claims) goes in ONLY as labeled negative/cautionary examples, or
   not at all.
3. **Controls travel with claims.** A differential without its garbage-path/unauth
   control is an incomplete example — pair them or drop the example.
4. **Scope and authorization context stays attached.** Signed-scope metadata,
   automation-prohibited flags, and the X-HackerOne attestation convention are part of
   the behavior being taught (a model that operates varvel must be fail-closed by
   habit).
5. **Secrets handling:** exports and matrices must be scrubbed of live credentials
   (session cookies, mail.tm tokens, `.tmp/oob-stack.json` authToken, fe-* material)
   before entering any training corpus. Replay bundles already demonstrate the pattern
   (`CRED_<REF>` indirection) — reuse it.
6. **Deduplicate against public writeups** the way novelgate does — internal near-dupes
   and well-known public techniques should be labeled as such, not presented as novel
   reasoning.

## 4. Open questions (resolve when the project starts — do NOT pre-answer now)

- **Quantization vs quality at 262k context.** What quant level keeps long-context
  retrieval/reasoning intact on Spark-class hardware? KV-cache footprint at 262k × 2
  instances is likely the binding constraint, not weights. Needs measurement, not
  guesses.
- **Dual-instance memory budget on DGX Spark.** Unified-memory box: weights + KV for
  two concurrent 27B-class instances at 262k context — does ~30 tok/s each survive,
  or does the second instance force a smaller quant / shorter context? Derive from
  measured KV bytes/token, not spec-sheet math.
- **Eval harness from varvel's own test suites.** varvel's pinned `node:test`
  batteries already encode oracle-discrimination pins (naive scanner flags 3/3, oracle
  sorts correctly; decoys that only a readback clears; honesty fail-closed pins).
  Candidate: turn these into a model eval — can the fine-tuned model operate the tools
  well enough that the suites' acceptance behaviors hold? Which suites transfer
  (idorprobe/race/logicprobe discrimination, novelgate verdict prediction,
  coverage-gate bookkeeping) and which are code-only?
- **Data mixing:** how much general cyber/code data vs varvel-specific operational
  data before the model overfits to varvel's house style and loses breadth?
- **Serving stack choice** for the 2-instance target (and whether the orchestration
  should look like the practitioner pattern: small local model for bulk/sub-agent
  work, frontier API reserved for chaining/verification — the model-routing doctrine
  from the research brief may still apply after the fine-tune).
- **Frontier-access logistics stay relevant meanwhile:** until the local model is
  proven, varvel's lanes still need their current model access; don't plan a cutover
  date before the eval harness exists.

## 5. First three steps when this activates

1. Inventory + scrub pass over `data/exports/`, `.tmp/*matrix*.json`,
   `.tmp/*submission*.md`, novelty sections → a labeled corpus directory (new files
   only; never edit sources).
2. Stand up the smallest eval harness slice (one oracle-discrimination suite → model
   task) so "is the fine-tune working?" has an honest answer from day one.
3. Measure DGX Spark memory/KV reality at 262k before committing to the 2×30 tok/s
   target in either direction.

*Seed ends. This document frames; it does not design.*

---

## Addendum 2026-09-01 — The 24h playbook + scaling thesis (owner-directed context)

### Why week one produced zero findings (honest diagnosis, for the next AI)
1. Wrong targets: mature programs (zomato/semrush/hubspot/meli/frontegg) already swept; we proved doors locked instead of finding open ones.
2. Access barriers killed the two best lanes (semrush captcha, wolt email suppression) — ~15 min of owner time clears both. Push the owner on these EARLY and HARD; they are the throughput bottleneck, not tooling.
3. Deep-dived single targets instead of casting wide. Winners run volume: dozens of programs, cheap validated checks, fresh scope. Paying classes: IDOR/BOLA at API scale, staging/internal missing-auth, JS-bundle secrets (verified by live 200), OAuth/MCP flaws, fresh-CVE version matches. Dup bait: CORS reflection, self-XSS, existence enum, TLS/cookie hygiene.

### The 24h wide-first playbook (committed to the owner 2026-09-01)
Preconditions: owner clears 3 blockers (one semrush captcha solve via captchaassist; wolt signup w/ real mailbox or @wearehackerone.com + magic-link forward; Mullvad relay switch to unblock Cloudflare edge 7844 → restart OOB stack).
Then run continuously, parallel campaigns allowed (ports/session infra supports it):
1. widerecon across full bountyline roster + every fresh H1 scope addition (h1watch) — refreshed repeatedly.
2. cvelane hypotheses → version-disclosed hosts first (fastest validated payout class after JS secrets).
3. jsminer+verify wide across fresh programs — verified secrets = fastest validated payouts.
4. Provision accounts ONLY where cheap (captcha rail + mail.tm; skip phone/corporate-email walls, escalate those to owner).
5. Deep-dive ONLY where signals cluster; kill-fast budgets everywhere.
Promise made to owner: better-than-even odds of ≥1 validated, novel, gate-passing, submittable finding in 24h under these conditions — NOT payout timing (triage latency is out of our control). Deliver an honest scoreboard either way.

### Scaling thesis (owner's vision): $300/mo → reinvest → more hardware → $3k/mo → fund varvel expansion
Recorded as the governing objective. Manager's honest assessment (2026-09-01): hardware is NOT the binding constraint — target access, triage latency (payouts lag findings by weeks-months; plan cash-flow accordingly), and acceptance rate are. Findings scale with fresh surface discovered/day × validation quality, not with GPU count. Validate unit economics on ONE Spark first; scale hardware only after the pipeline demonstrably clears $300/mo. Reference points: top AI-assisted individuals run ~$5k/mo (FireCompass top-3 US), so $3k/mo is achievable-but-not-linear; expect dup/NA rates to dominate early volume (novelty gate + freshness doctrine are the mitigations).
