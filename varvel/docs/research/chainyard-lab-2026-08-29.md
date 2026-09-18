# Chainyard lab — T2 chaining-engine calibration — 2026-08-29

**Fixture:** `targets/chainyard.mjs` (new) — the planted-composition garden specified in
`docs/research/offensive-program-2026-08-29.md` §T2. Five planted lows (reflected
self-XSS, CORS reflect-with-credentials, open redirect, debug RNG-seed leak, predictable
reset token), one composed HIGH (predictable-reset account takeover of admin → vault
canary), one decoy (the CORS primitive — scary header, nil impact: the session cookie
is `SameSite=Strict`, so cross-origin credentialed reads return the anonymous profile).

**Harness:** `deploy/range-iso/chainyard/run.mjs` — boots the target on an ephemeral
loopback port and runs VARVEL's *actual* machinery at it: `guidedWebSearch`
(`engine/webpaths.mjs` → `engine/pathsearch.mjs`) for discovery, `engine/surface.mjs`
for the graph, `engine/chainforge.mjs` for composition, `tools/chainrun.mjs` for
execution. Verdict: `deploy/range-iso/chainyard/last-verdict.json`.

## Verdict

| Question | Result |
|---|---|
| **DETECTION** — does the engine find the lows? | **4/5.** Debug leak found by real pathsearch as `sensitive-hit`; CORS reflection, open redirect, and unescaped reflection observed by direct probes. **Honest miss: L5 (predictable token)** — the token never appears in any response; predictability is not observable from any single request. |
| **COMPOSITION** — does chainforge compose the winning chain? | **No — and worse: it composed ONLY the decoy.** `cors-theft` compiled (2 steps, "confirmed-method"). The winning leak→predict→reset→session→vault chain has no rule that models it. `jwt-forge-chain`, `broken-write`, `exposed-secrets` all reported honest gaps. |
| **DISCRIMINATION** — decoy chained? | **Yes — chainforge picked the decoy.** Caught only at the harness level: executing the compiled decoy via chainrun passes all step expectations, but the impact check shows **zero victim data** (anonymous profile). The hollow-success discriminator exists in the lab harness, **not inside chainrun/chainforge**. |
| **Known-known calibration** — is the winning chain real? | **Reproduced 5/5 steps** via the unmodified `runChain` executor: seed extracted from `/internal/debug`, predicted token `rset-<seed>-admin` accepted, admin session minted, `CY-VAULT-CANARY` read from `/admin/vault`, state reverted. Paired control: a wrong token is refused (403). The target is genuinely exploitable — every gap above is an **engine** gap, not a fixture defect. |

## Diagnosis: where the chain-finding gap lives

The gap is **COMPOSITION, with a DISCRIMINATION hazard** — detection is nearly adequate.

1. **Detection (nearly sufficient).** Pathsearch's outcome table already scores the one
   leak that matters (`sensitive-hit` 0.95). The single detection miss (L5) is
   *intrinsic* to the bug class: no scanner can see a predictable token that never
   appears on the wire. This is exactly the miss-class the chaining engine is supposed
   to absorb — predictability is provable only *in composition* (leak the seed, mint
   the token, try it). T2 does not need a detection build; it needs composition to
   treat "unobservable-but-computable" as a first-class hypothesis.

2. **Composition (the real gap).** `engine/chainforge.mjs` RULES are *vertical*
   templates: each encodes one named methodology end-to-end (leak-JWT-key → forge →
   write). Nothing composes *arbitrary* typed primitives. The winning chain needs a
   horizontal rule: "any leaked high-entropy-looking value (`seed`, `secret`, token
   material) + any endpoint that *consumes* a token of derivable shape = a prediction
   candidate." That is a new rule class — primitives with typed inputs/outputs and a
   compiler that tries type-compatible pairings — not another bespoke rule.

3. **Discrimination (the hazard the decoy exposed).** chainforge compiled the decoy at
   confidence "confirmed-method" and chainrun executed it green — while the chain's
   actual impact is nil. The current executor proves *steps*, not *impact*. The
   validator's paired-control doctrine (`engine/validator.mjs` v2, manhuaus) has no
   counterpart at the chain level. T2 must add an **impact assertion** to chain shape:
   a chain is confirmed only when its terminal step carries attacker-defined proof
   (victim data / canary), not merely a 200.

## What this sizes for the T2 build

- **Build 1 — typed primitives + composition compiler (chainforge v2).** Each primitive
  declares `provides`/`consumes` (e.g. debug-leak `provides: rng-seed`; reset-confirm
  `consumes: token-of-shape rset-<seed>-<user>`). The compiler enumerates
  type-compatible compositions over the surface graph and hands candidates to
  `engine/pathsearch.mjs` as probe descriptors — closing the loop between the two
  modules the program doc paired but the code never connected.
- **Build 2 — chain-level impact oracle (chainrun v2).** Add `impact:` assertions to
  the chain shape (terminal step must contain attacker-chosen marker / victim data) so
  hollow-success chains fail *inside* the executor, the way garbage-controls fail
  findings inside the validator. The decoy chain above is the regression test.
- **Build 3 — the "computable, not observable" detector class.** L5's miss suggests a
  small, high-value detector family: reset/invite/download endpoints whose token shape
  is derivable from any leaked value. Cheap to add once Build 1's typing exists.
- **Not needed:** more discovery. Pathsearch found what mattered with a 16-seed
  wordlist and 40 probes.

## Honesty notes

- The harness *seeded* `/internal/debug` in the wordlist; with the stock
  `ROOT_WORDLIST` (`engine/webpaths.mjs`), `/internal` is present but `debug` is not a
  `COMMON_SUB` segment, so stock discovery would likely miss L4. Real engagements lean
  on wordlist quality; this does not change the composition diagnosis.
- Detection probes for CORS/redirect/reflection were performed by the harness using the
  same observations the relevant tools make, not by invoking every tool wrapper
  end-to-end; the classification of the one search-discovered low (L4) is fully real
  machinery.
- hyp-005 stays **testing**: the engine did NOT compose the chain. The fixture, the
  harness, and a concrete build plan exist — that is the round's output.

## Files

| File | Role |
|---|---|
| `targets/chainyard.mjs` | the garden fixture (loopback-only; `:8973` standalone) |
| `deploy/range-iso/chainyard/run.mjs` | the calibration harness (exports `runLab`, `WINNING_CHAIN`, `DECOY_CHAIN`) |
| `deploy/range-iso/chainyard/last-verdict.json` | this round's empirical verdict |
| `test/chainyard.test.mjs` | 5 pinned tests: loopback boot, per-low observability, end-to-end chain proof with control + revert, decoy impact failure, manual composition walk |

Test runs (2026-08-29): `test/chainyard.test.mjs` **5/5 pass**;
`test/engine.test.mjs` + `test/pathsearch.test.mjs` + `test/chainforge.test.mjs` +
`test/chainforge-campaign.test.mjs` + `test/chainrun.test.mjs` **47/47 pass**.
No live targets touched; loopback only; no new dependencies.

---

## Round 2 (same day, post-authorization): the v2 build — GAP CLOSED

Built per the three-part plan above, then re-ran the same harness against the same
fixture. Verdict: `deploy/range-iso/chainyard/last-verdict.json`.

**What shipped:**

1. **`engine/chaincompose.mjs` — typed-primitive composition compiler.** Primitives
   declare `provides`/`consumes` slots (`leaked-token-material` PROVIDES
   token-material; `predictable-reset-token` CONSUMES token-material + PROVIDES
   auth-as-user, expanded per `engine/tokenshape.mjs` shape hypothesis;
   `protected-data-read` CONSUMES auth-as-user + PROVIDES impact-data). Composition is
   a search over primitive compatibility fed through `engine/pathsearch.mjs` (UCT
   reused; probe = hermetic surface-fit check, classify maps fitness onto the value
   table). `engine/chainforge.mjs` untouched — vertical rules preserved (regression:
   chainforge/chainforge-campaign suites green).
2. **`tools/chainrun.mjs` v2 — chain-level impact assertions.** `chain.impact` asserts
   on a terminal step's response, optionally against a paired control (same request,
   auth headers stripped, must be REFUSED and DIFFER — the manhuaus garbage-control
   doctrine lifted from findings to chains). Steps green + impact failed = `ok:false,
   hollowSuccess:true`, honestly reported. Chains without `impact` behave exactly as
   before (pinned by a regression test).
3. **`engine/tokenshape.mjs` — the computable-not-observable detector, scoped minimal.**
   A 4-entry TOKEN_SHAPES hypothesis library (execution is the oracle that picks the
   shape) + `analyzeSamples()` for endpoints that DO return tokens (constant-stride →
   sequential; epoch-band monotonic → timestamp; otherwise an honest negative).
4. **Validator hookup.** `findingFromChain(run)` turns an impact-proven execution into
   a finding whose evidence cites the oracle vocabulary (chainrun reproduction +
   control comparison); pinned to pass `hasObjectiveOracle` while bare claims still
   fail.

**Round-2 verdict (measured, not claimed):**

| Question | Round 1 | Round 2 |
|---|---|---|
| Detection | 4/5 (L5 invisible) | 4/5 — unchanged, by design (L5 is composition-only) |
| Composition | only the DECOY compiled | **engine composed the winner itself**: `composed:leaked-token-material→predictable-reset-token:prefix-seed-user→protected-data-read`, executed end-to-end, impact proven, canary reached; 3 wrong shape hypotheses failed honestly (403, honest stop) |
| Discrimination | caught only in harness | **decoy now fails INSIDE the executor** — steps green, impact absent, `hollowSuccess:true` |
| Validator | n/a | composed finding passes the objective-oracle ingest gate |

Tests: `chainyard` 6/6, `chaincompose` 7/7, plus chainrun/chainforge/engine/
pathsearch/validator suites — **96/96 green** across the nine relevant files.

**Remaining T2 work:** broaden the primitive library beyond the token-prediction
family (each new primitive = hypothesis-log entry + pinned test); seed-extract regex
fallbacks at execution time (currently first-regex-or-honest-stop); material
extraction from real recon output (bundle paths, published-cred hints) instead of
`material.targetUser` defaults; multi-leak chains (two token-material providers).
