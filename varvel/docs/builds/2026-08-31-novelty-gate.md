# Novelty gate build — 2026-08-31

Born from HackerOne semrush **#2666357, closed DUPLICATE**: we filed CORS
origin-reflection + `Access-Control-Allow-Credentials: true` on
`admin.semrush.net`, but the behavior was emitted by the **Google IAP edge
gate** (`x-goog-iap-generated-response: true`) on unauthenticated 302
responses — no authenticated data was ever read cross-origin, and the program
already knew. This build makes that class of wasted submission structurally
hard. Tests: `test/novelgate.test.mjs` (16).

## Layout

- **`engine/novelcore.mjs`** — the PURE core (zero network, zero fs; pinned by
  a static scan in the test). Weakness classification, the edge-generated
  detector, the per-class impact bar, SimHash internal dedup, the hacktivity
  response reader, the assessment, and the markdown section renderer/parser.
- **`tools/novelgate.mjs`** — the network half + CLI. Hacktivity search over
  H1's public GraphQL (`CompleteHacktivityReportIndex`, unauthenticated),
  internal-corpus collection, and `--annotate` section rewriting.
- **`engine/bountyline.mjs`** — the wiring: `draftReports` runs the offline
  half BEFORE persisting any markdown (a BLOCKED finding is never drafted);
  `queueProgram` REFUSES any report without a novelty section
  (`novelty-gate-missing`) or with a BLOCKED verdict, and carries
  UNVERIFIABLE/REVIEW-NEEDED loudly into the submission checklist.

## Rules

1. **Hacktivity duplicate search** — before a submission is finalized, query
   H1's public disclosed-reports surface twice: program-scoped
   (`handle + hostname + weakness class`) and behavior-signature
   (e.g. `google iap cors reflect`). Candidates (id/title/url/weakness/date)
   are ranked by signature-token overlap; score ≥ 0.3 ⇒ REVIEW-NEEDED and the
   operator must rule out each candidate before the send click.
2. **Edge-generated-behavior detector** — if the tested response's headers
   show edge/gate infrastructure generated it (see signature table below) AND
   the tested status is an unauthenticated challenge (302/401/403), the finding
   is auto-flagged. It survives ONLY with the class impact proof; otherwise
   BLOCKED. Evidence is read from `--status/--headers` or parsed out of the
   draft's own HTTP exchange blocks (`parseHttpEvidence`).
3. **Per-class impact-evidence bar** (`IMPACT_BAR`) — see table below. A
   draft's OWN admission that the proof does not exist
   (`admissionRes` — the semrush draft's "Not included: a post-authentication
   demonstration") hard-fails the bar even if a proof regex coincidentally
   matched.
4. **Internal dedup** — 64-bit SimHash (threshold 14 bits) over
   `.tmp/*submission*.md` / `*report*.md` and `data/exports/*report*`
   (READ-ONLY corpus; `--annotate` REFUSES paths under `data/`/`.data/`).
   A near-duplicate ⇒ REVIEW-NEEDED — re-filing a sibling host is noted,
   never silent.
5. **Fail-closed honesty** — hacktivity unreachable / non-2xx /
   Cloudflare-blocked / unparsable ⇒ named error
   (`hacktivity-unreachable` | `hacktivity-http-error` | `hacktivity-blocked`
   | `hacktivity-bad-response`) and verdict **UNVERIFIABLE**. A failed search
   is NEVER a silent skip and NEVER a fabricated CLEAR. Candidate reports are
   read from the response only — never invented; parse gaps are carried into
   the output.

## Verdicts

`BLOCKED` (hard bar failed — outranks everything) > `UNVERIFIABLE` (search
failed) > `REVIEW-NEEDED` (candidate duplicates, internal near-dupes, or
edge-flagged-with-proof) > `CLEAR`. CLI exit codes: 0 CLEAR, 2 REVIEW-NEEDED,
3 UNVERIFIABLE, 4 BLOCKED. Every rendered section carries the machine marker
`<!-- novelgate:v1 -->`; `queueProgram` keys on it via `parseNoveltySection`.

## Edge-header signature table (`EDGE_SIGNATURES`)

| id | header match | note |
| --- | --- | --- |
| google-iap-generated | `x-goog-iap-generated-response: true` | Google IAP GENERATED this response — the app never saw the request (the semrush case) |
| google-iap | any `x-goog-iap-*` header | the IAP gate speaking, not the app |
| awselb | `server: awselb*` | ELB default error/challenge page |
| cloudfront | `x-cache` or `via` matching `cloudfront` | CloudFront edge cache/error response |
| cloudfront-pop | `x-amz-cf-pop` present | CloudFront PoP-served response |
| akamai | `server: *akamai*` | Akamai edge-generated response |
| fastly | `x-served-by: cache-*` | Fastly edge cache response |
| cloudflare-challenge | `cf-mitigated: challenge` | Cloudflare challenged instead of passing to origin |
| incapsula | `x-cdn` matching `incapsula\|imperva` | Imperva/Incapsula edge response |

Flagged = ≥1 signature AND tested status ∈ {302, 401, 403} (unauthenticated
challenge). Edge headers on a 200 app response are noted, not flagged.

## Per-class impact-evidence bar (`IMPACT_BAR`)

| class | bar | notes |
| --- | --- | --- |
| cors | **authenticated-read** — demonstrated cross-origin READ of authenticated application data; reflected ACAO/ACAC headers alone are configuration, not impact | admission patterns void coincidental proof matches |
| ssrf | **oob-callback** — a correlated out-of-band callback (tools/oob.mjs canary / interactsh); blind-with-no-callback is unproven | |
| idor | **cross-account-with-controls** — ALL of: real victim/ cross-account data + garbage-ID control + unauthenticated control (the validator v2 paired-control doctrine, class-applied) | 2/3 is not enough |
| tls | **never submittable** | scanners emit these for free; every program has seen them all |
| cookie | **ineligible on hackerone by default** | unless chained into demonstrated account impact |
| clickjacking | **ineligible on hackerone by default** | unless a concrete state-changing action on a sensitive page is shown |
| other | no class bar — the validator gate governs | |

## Usage

```
node tools/novelgate.mjs check --program semrush --host admin.semrush.net \
     --weakness cors --draft .tmp/<draft>.md [--status 302 --headers hdrs.json] \
     [--signature "google iap cors reflect"] [--annotate] [--json] [--offline]
```

Egress doctrine: every outbound request rides the ghost chain
(`VARVEL_NOVELGATE_CHAIN`, default `socks5://10.64.0.1:1080`) via
`engine/ghost.mjs` agents and carries `X-HackerOne: varvel` — hackerone.com
queries included. Assumed H1 shape (verified live 2026-08-31): POST
`https://hackerone.com/graphql` with
`search(index: CompleteHacktivityReportIndex, query_string: $q, first: N)` →
`HacktivityDocument` nodes; a live disagreement changes `H1_GRAPHQL`, not the
gate.

## How the semrush case scores

`tools/novelgate.mjs check --program semrush --host admin.semrush.net
--weakness cors --draft <the 2666357 draft> --offline` → **BLOCKED**
(exit 4): class `cors`, edge FLAGGED (`x-goog-iap-generated-response: true`
on a 302), and the impact bar fails on the draft's own admission
("Not included: a post-authentication demonstration…"). Through the pipeline,
`draftReports` refuses the whole draft with `novelty-blocked` and rolls the
program state back honestly (test-pinned).

## Known limitations

- **Undisclosed duplicates are unsearchable.** The gate searches PUBLIC
  disclosed reports only — the semrush duplicate was exactly the kind the
  public surface may not show. The gate REDUCES but CANNOT eliminate
  duplicate risk; a CLEAR verdict is not a promise of novelty. This line is
  embedded in every rendered novelty section.
- The impact bar is regex-based evidence over the draft text — it detects
  *claimed* proof, it cannot verify the proof actually happened (that remains
  the validator's job).
- H1's GraphQL shape is an assumption table (`H1_GRAPHQL`); a schema change
  degrades to UNVERIFIABLE with a named gap, never to a fabricated CLEAR.
- SimHash dedup needs ≥40 tokens per document; shorter drafts skip dedup with
  an honest note.
- `--annotate` rewrites only drafts outside `data/`/`.data/`; bountyline
  reports get their novelty section embedded by `draftReports` itself.
