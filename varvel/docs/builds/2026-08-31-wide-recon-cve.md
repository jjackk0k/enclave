# Wide recon + CVE lane build — 2026-08-31

The doctrine inversion: instead of deep-hunting ONE program at a time, **passively recon
MANY signed/recorded programs and surface the biggest catches** (Tool 1,
`tools/widerecon.mjs`), and give known-vuln opportunities a **dedicated lane** so fresh
KEV/recent CVEs against detected versions are never missed (Tool 2, `tools/cvelane.mjs`).
Honesty contract, stated up front: **no system catches everything** — the goal is
coverage-gated BREADTH with an explicit untested-surface ledger, and a version match is
never called a vulnerability. Tests: `test/widerecon.test.mjs` (11),
`test/cvelane.test.mjs` (16); neighbor suites re-run green (targetscore 9,
coverage-gate 8, novelgate 16, jsminer 9, bountyline 12, campaign-persist 3,
campaign-tools 11, authz-campaign 8, chain-campaign 8, stealth-campaign 8,
logic-campaign 4, chainforge-campaign 3, aisurface 18).

## Layout

- **`tools/widerecon.mjs`** — Tool 1. Policy-aware roster-wide passive sweep: crt.sh +
  Wayback CDX + DoH DNS + TLS cert metadata + a TINY cadence-permitting HTTP fingerprint.
- **`tools/cvelane.mjs`** — Tool 2. KEV + NVD-recent ingestion (cached, polite),
  (software, version) → CVE matching, per-program watchlists, the scored HYPOTHESIS queue.
- **Wiring** — `engine/campaign.mjs` launch option `cveHypotheses`: hypotheses enter the
  coverage gate (`engine/coverage.mjs`) as QUEUED surface with source
  `cvelane-hypothesis`; the campaign may not report DONE-CLEAN while they are undrained.
- Reused, not rebuilt: `tools/targetscore.mjs` (`scoreHost` is the ranking base),
  `engine/ghost.mjs` (chain + agents + `openTunnel`), `engine/bountyline.mjs`
  (`loadRoster`, the automation-policy field), `engine/coverage.mjs` (the gate).

## Tool 1 — widerecon

```
node tools/widerecon.mjs sweep [--programs zomato,semrush,localizejs] [--max-programs 3]
                               [--out data/exports] [--json] [--no-write]
```

Input: the bountyline roster (`data/bountyline/roster.json`) joined to each program's
`<id>-program.json` intake (in-scope domain roots) and `h1sync/<handle>.json` snapshot.
Per program, in order, all GETs, all through the ghost chain
(`VARVEL_WIDERECON_CHAIN`, default `socks5://10.64.0.1:1080`, header
`X-HackerOne: varvel`, fail-closed):

1. **crt.sh** subdomain enum per in-scope root (`?q=%25.<root>&output=json`).
2. **Wayback CDX** per root (`fl=timestamp,original&collapse=urlkey&limit=200`) —
   old/forgotten hostnames and parameterized legacy URLs (IDOR candidates).
3. **DNS resolution** per discovered host — via DoH (`cloudflare-dns.com/dns-query`)
   THROUGH the chain, so no local DNS of targets ever happens. Failure → `UNKNOWN`,
   never guessed.
4. **TLS cert metadata** per live host (subject/issuer/SAN/validity via
   `ghost.openTunnel` + `tls.connect`, `rejectUnauthorized:false` — metadata only).
5. **HTTP tech fingerprint** (cadence-permitting): GET `/` (server / x-powered-by /
   `<meta generator>`, script-count for jsminer-promise) plus the pinned two-file set
   `['/readme.html', '/CHANGELOG.md']` — WP-class hosts get both, others only
   CHANGELOG. This is NOT a crawl.

**Policy behavior (hard, test-pinned):**

- `PROHIBITED_PROGRAMS = ['udemy', 'wordpress', 'matomo']` is a hard pin ON TOP of the
  roster's automation field. Prohibited programs get **zero requests** and appear in
  every report as **SKIPPED-POLICY** with the reason named.
- `human-cadence` programs: concurrency 1, **≥5s** between target-contact requests
  (TLS + fingerprint), ≥1s between third-party intel fetches (crt.sh/wayback/DoH).
- Scope fail-closed: crt.sh/wayback names outside the program's signed roots are
  dropped and counted (`droppedOutOfScope`) — never dialed.

**Ranking signals** (targetscore-style; every bump names its signal and cites evidence):

| signal | pts | source |
| --- | --- | --- |
| (all of `scoreHost`'s: soft-env hostname, auth surface, API density, parameterized, edge-walled −, known-buggy stacks, SPA, …) | shared | `tools/targetscore.mjs` |
| `fresh-subdomain` | +12 | first-seen (crt.sh `not_before` / earliest wayback capture) ≤ 120d |
| `version-disclosed` | +10/tuple, cap +20 | server header / x-powered-by / generator meta / readme / CHANGELOG — feeds cvelane |
| `tls-origin-hint` | +8 | cert subject names an internal/non-prod identity |
| `jsminer-fodder` | +6 | ≥5 script srcs on the front page |
| legacy parameterized wayback URLs | class `idor-candidate` | `?param=` on old captures |

Output: `data/exports/widerecon-<date>.json` + `.md` — ranked catch-list, per-program
notes, the SKIPPED-POLICY list, the `softwareTuples` feedstock for cvelane, and the
untested ledger: verdict **NOTHING-TESTED** — widerecon enumerates, it never tests.

## Tool 2 — cvelane

```
node tools/cvelane.mjs fetch [--refresh]                       # refresh the feed cache only
node tools/cvelane.mjs scan --tuples data/exports/widerecon-<date>.json [--json] [--no-write]
                            [--programs a,b] [--no-watch]      # watchlists auto-load from the roster's h1sync/intake metadata
```

**Feeds + caching (politeness is doctrine):**

| feed | url | key | cache | TTL |
| --- | --- | --- | --- | --- |
| CISA KEV | `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | none | `.tmp/cve-cache/kev.json` | ≥12h (floor, clamped) |
| NVD CVE API 2.0 (recent, last-modified 30d window) | `services.nvd.nist.gov/rest/json/cves/2.0` | none (we don't have one) | `.tmp/cve-cache/nvd-recent.json` | ≥12h |

NVD without a key budgets 5 req/30s: pages sleep **≥6s** apart and the run caps at 3
pages (~600 CVEs); truncation is a NAMED `feeds.errors` entry, never silent. A failed
fetch serves the STALE cache with the error named; no cache + failed fetch = an empty
feed and a named error — CVEs are never fabricated. EPSS is not fetched by default:
`epss` is `null` unless the caller passes an `epssMap` — never fabricated either.

**Matching (pure, test-pinned):** CPE 2.3 criteria from NVD `configurations` +
vendor/product tokens from KEV, bridged to recon banner names through
`SOFTWARE_ALIASES` (`Microsoft-IIS` ↔ `internet_information_server`, …). Version checks:
`exact` (cpe version equal), `in-range` (versionStart/End Including/Excluding),
`out-of-range` (**dropped**), `unknown` (no version observed or no range data — kept,
labelled). KEV carries no ranges: every KEV match is `versionMatch:'unknown'` by
construction. Per-program **watchlists** (`PROGRAM_WATCHLISTS` + stack keywords detected
in h1sync/intake metadata) catch stack-class CVEs without a detected version —
wordpress-stack programs watch core + the plugin/theme description flood; on
automation-prohibited programs these are **watch-only, manual-verification** items and
say so.

**Scoring:** base 20 · KEV +40 · exact +25 / in-range +20 / unknown +5 ·
fresh (≤14d) +10 · EPSS ≥0.5 +10 / ≥0.1 +5 · metadata-inferred (non-pinned) watchlist
stacks −10 weak-evidence · cap 100.

**Output** — `data/exports/cve-hypotheses-<date>.json`: every item is
`{ status:'HYPOTHESIS', routing:'campaign-validator', program, host, software, version,
cve, kev, epss, versionMatch, matchBasis, evidenceOfVersion, validationPlan, note }`.
The label is pinned by test: **a version match ≠ exploitable** — these are validation
work items for the campaign/validator path (captured bytes + differential, then the
novelty gate). They NEVER enter the bountyline draft path.

**Campaign wiring:**

```js
import { toLaunchOptions, loadHypothesesFile } from './tools/cvelane.mjs';
const items = loadHypothesesFile('data/exports/cve-hypotheses-2026-08-31.json');
const launch = toLaunchOptions(items, { targets: ['staging.example.com'] });
// → { targets, tooledRecon:true, targetScore:true, cveHypotheses:[{kind,key,host,cve}] }
new Campaign({ ...launch, engine, scope, runAgent });
```

The constructor queues each `cveHypotheses` entry into the CoverageLedger with source
`cvelane-hypothesis` (logged `cvelane.queue`); a hypothesis whose host is not among the
campaign's targets is fail-closed skipped (logged `cvelane.skip`, counted in
`getState().cvelane = { received, queued, skipped }`). The gate then does its job: an
undrained hypothesis queue means **COVERAGE-INCOMPLETE**, itemized — the coverage-gated
breadth ledger. Hostless watch items can't be queued (no target); `coverageItems()`
returns them in `hostless`, counted.

## Cadence / refresh loop (operator)

1. `node tools/widerecon.mjs sweep` — refreshes the roster sweep (respect each program's
   cadence; run it off-peak; the whole sweep of ~20 programs at human cadence is hours,
   not minutes — that is the point).
2. `node tools/cvelane.mjs scan --tuples data/exports/widerecon-<date>.json` — the
   hypothesis queue (cache makes this cheap; `--refresh` forces a fetch).
3. Pick the top hypotheses → `toLaunchOptions(items, { targets })` → campaign → the
   validator bar decides what is real → the novelty gate decides what is fileable.

## Smoke run (live, 2026-08-31)

Roster-wide sweep of **zomato, semrush, localizejs** at human cadence (≥5s
target-contact pacing from the roster policy; breadth caps reduced to roots 2 / hosts 6 /
fingerprint 2 per program to fit the window — pacing never reduced), plus one cvelane
feed fetch. Exports: `data/exports/widerecon-2026-08-31.{json,md}` and
`cve-hypotheses-2026-08-31.json`.

- **19 intel + 12 target-contact requests**, all through the ghost chain with the
  research header. Per-program results recorded in the export.
- **Surfaced (recon output, tested:false):** legacy parameterized wayback URLs on
  `zomans.com` / `www.zomans.com` — currently NO-A-RECORD forgotten surface;
  `investors.semrush.com` (RESOLVES, nginx, no version disclosed); the localizejs
  staging apex behind Cloudflare (edge-walled, scored DOWN).
- **Feed failures named, nothing fabricated:** crt.sh answered 502/404 from the shared
  ghost exit for every root (its backend rate-limits busy exits — a known crt.sh
  behavior); wayback had two transient socks refusals. Those stages are error entries in
  the report, not silent gaps.
- **cvelane:** KEV 1687 + NVD 600 (page-cap truncation named) ingested and cached.
  Zero host tuples carried a disclosed version in this smoke, so **zero host-targeted
  hypotheses were emitted** (correct — a hypothesis without version evidence would be
  noise); the watchlist lane emitted 55 watch-only HYPOTHESES (pinned wordpress-stack
  KEV items labelled manual-verification-only for the prohibited program;
  metadata-inferred stacks penalized −10 as weak evidence).

## Limitations (stated, not hidden)

- **crt.sh sees only certificate-logged names**; hosts never issued a logged cert are
  invisible. **Wayback sees only what it archived**; absence of a capture is not absence
  of a host. Both gaps are why unknowns stay `UNKNOWN` rather than becoming claims.
- **A disclosed version is not a vulnerability.** cvelane hypotheses carry
  `evidenceOfVersion` + a validation plan precisely so the validator — not the matcher —
  decides. KEV matches are always `versionMatch:'unknown'` (KEV says "exploited against
  SOME version"); NVD CPE data quality varies wildly (plugin CVEs often carry no usable
  CPE — the description-regex watch path exists for that and is labelled weaker).
- The NVD window is capped at 3 pages for politeness; heavy CVE weeks truncate (named in
  `feeds.errors`) — narrow the window or add an NVD API key (we don't have one).
- The fingerprint read-set is deliberately tiny (`/` + ≤2 well-known files); stacks that
  disclose versions only deeper in the tree stay undetected — a named blind spot, traded
  for cadence safety.
- Coverage-gated breadth is still BREADTH: a host ranked low is less interesting, not
  safe; the untested ledger (`NOTHING-TESTED` at recon time, `COVERAGE-INCOMPLETE` until
  drained) is the honest remainder.
