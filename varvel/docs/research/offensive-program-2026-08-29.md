# VARVEL Offensive Research Program — 2026-08-29

**Mission (corrected aim):** the research lane exists to invent **advanced offensive
vulnerability-discovery capability** — ways to find high-severity bugs that modern
tools and most researchers structurally cannot — because that is where bounty profit
lives. The first round produced defensive MCP screens (`engine/mcpguard.mjs`,
`test/mcpclient-poison.test.mjs`); valuable, but not the mission. This program
re-aims the lane at *finding* capability.

**Grounding:** this doc builds on the ranked scouting map in
`docs/research/directions-2026-08-29.md` (all trend URLs live there, retrieved
2026-08-29) and on the research-lane doctrine in `docs/RESEARCH.md` (lab-only rule,
hypothesis log, calibrate-on-known-knowns, graduation gates). Every platform
capability claimed below cites a real file that was read while writing this doc.

**The hard rule, restated (from `docs/RESEARCH.md`):** novel-technique experiments run
ONLY against our own lab — `targets/` (demo-corp, Axiom), `deploy/range-iso/`,
`vm-lab.mjs`, or self-hosted fixtures we own end to end. A technique graduates only
after it reproduces on demand in-lab; its first live use still crosses
lane-classify (`engine/lanes.mjs`) → `tools/submit-drive.mjs scopecheck` →
FILE-or-PARK → Jack's hand submits. Nothing in this program touches a live target.

---

## 1. Why modern tools miss high-severity bugs

Scanners (and, increasingly, AI-augmented scanners) are single-request,
single-context machines. The six miss-classes below are *structural*: the tool's
architecture forbids the observation, not just its payload list. For each: the
mechanism, a historical bounty-example class, and why the payout was high.

### 1.1 Cross-request state reasoning
A scanner fires request N and reads response N. It has no model of what requests
1..N−1 did to server-side state. Bugs that only exist as *state transitions* —
use a coupon twice, replay a password-reset token, call step 3 before step 2 —
are invisible.
- **Historical example class:** race/logic payout stories on payment and
  invite flows — e.g. the limit-overrun / double-redemption class popularized
  by public write-ups on e-commerce and fintech programs (and the
  single-packet technique PortSwigger published for HTTP/2, referenced in the
  directions doc's desync lineage).
- **Why high payout:** the impact is direct money movement or account creation
  with attacker-chosen privileges, and the bug class is rare per-target, so
  programs pay for impact, not effort. No scanner competes with you.

### 1.2 Business-logic invariants
Every app encodes unstated invariants ("a refund can never exceed the charge",
"a user cannot approve their own expense", "a deleted team's webhooks die").
These live in *intent*, not signatures. No payload list contains them.
- **Historical example class:** IDOR/BOLA and price/quantity tampering reports
  are the durable top earners on HackerOne's published top-ten vulnerability
  list (background stats: [HackerOne top-ten](https://www.hackerone.com/lp/top-ten-vulnerabilities));
  the highest-paid instances are *logic* invariants (negative amounts,
  role-crossing approvals), not parameter bugs.
- **Why high payout:** impact maps 1:1 to fraud scenarios the program owner can
  feel; exploitation needs zero sophistication once found; and detection
  requires understanding the business, which no generic tool has.

### 1.3 Chained primitives (two lows → one high)
A self-XSS is informational. A permissive CORS is low. A cookie scoped to
`*.example.com` is a note. Composed: account takeover. Scanners score each
primitive in isolation and report three tickets nobody pays for; the bounty is
in the *composition*, which requires a graph, not a list.
- **Historical example class:** the public record of top bounty write-ups is
  dominated by chains — token theft + subdomain takeover + cookie scope,
  cache deception + auth bypass (the directions doc §anchor cites the
  cache-deception/desync research lineage).
- **Why high payout:** the program pays for the *demonstrated impact* of the
  final chain, not the sum of the primitives. Composition is where a $200
  finding becomes a $5,000 one.

### 1.4 Second-order sinks
Payload enters at endpoint A, is stored, and detonates later at endpoint B —
an admin panel, a webhook consumer, a PDF renderer, an email template, an
async job. The request/response pair a scanner observes contains no signal.
- **Historical example class:** stored-XSS-into-admin-panel and
  blind-XSS-via-support-ticket are classic high-payout reports; SSRF via
  webhook callbacks and PDF-generator renderers are the modern form (the
  tj-actions incident — [GHSA-mrrh-fwg8-r2c3](https://github.com/advisories/ghsa-mrrh-fwg8-r2c3) —
  shows how async CI contexts detonate secrets far from the injection point).
- **Why high payout:** the sink is usually an internal/admin context, so
  impact is privileged-context code execution or internal-network reach —
  and the time/space gap defeats every request-response oracle.

### 1.5 Race windows
TOCTOU between check and use: balance checked then debited, invite validated
then consumed, file validated then served. A sequential tool cannot exist in
two instants at once, and rate-limited scanning widens the gap instead of
closing it.
- **Historical example class:** PortSwigger's "single-packet attack"
  (last-byte sync) made limit-overrun races reliable; the research lineage is
  cited in the directions doc §2. Public write-ups in its wake turned
  previously-theoretical races on quota, transfer, and redemption endpoints
  into repeatable bounties.
- **Why high payout:** same as 1.1 — direct financial/authorization impact,
  near-zero scanner competition, and a reputation premium because most
  hunters can't execute the timing.

### 1.6 Protocol-confusion between layers
Two components parse the same bytes differently: proxy vs backend (desync),
TLS terminator vs app, HTTP/1 vs HTTP/2 vs HTTP/3 translation, JSON parser vs
WAF regex. Each layer is individually correct; the *composition* is the bug.
- **Historical example class:** HTTP request smuggling — the entire desync
  research program (directions doc §2: Akamai's bounty-reported
  CVE-2025-32094 via OPTIONS + line folding,
  [advisory](https://www.akamai.com/blog/security-advisory/cve-2025-32094-http-request-smuggling);
  HAProxy HTTP/3 smuggling CVE-2026-33555). This miss-class has minted more
  named techniques than any other in the last five years.
- **Why high payout:** a desync at a CDN/proxy layer can poison *other users'*
  caches and sessions — impact crosses the user boundary, which is the line
  between medium and critical.

**Summary table — miss-class → why scanners miss it → what unlocks it:**

| Miss-class | Scanner blindness | Unlock (→ §2 edge) |
|---|---|---|
| Cross-request state | no session model | state machine + chain executor (`tools/chainrun.mjs`) |
| Business-logic invariants | no intent model | source/spec reading at corpus scale |
| Chained primitives | per-request scoring | surface graph + path search (`engine/surface.mjs`, `engine/pathsearch.mjs`, `engine/chainforge.mjs`) |
| Second-order sinks | no time/space gap | async beacon/callback instrumentation (`engine/callback.mjs`, `engine/beaconscore.mjs`) |
| Race windows | sequential pacing | dedicated last-byte-sync harness (new: thread T4) |
| Protocol confusion | single-parser view | differential two-stack fixtures (new: thread T1) |

---

## 2. VARVEL's structural edges

Not "we use AI" — the specific machinery, with the file that implements it, and
which miss-classes it unlocks.

### E1 — Corpus-scale source reading (proven, not promised)
The week of 2026-08-27 the hunting engine produced **5 verified WordPress plugin
vulnerabilities, 2 submitted to bounty programs** — provenance recorded in
`engine/lanes.mjs`'s header comment. The pipeline that did it is real code:
`tools/privemap.mjs` (fs-walk a PHP tree → ranked privesc/impact-primitive
report), `tools/reachprove.mjs` (mechanical reachability verdicts over
`engine/reachability.mjs`), and `tools/variantsweep.mjs` (one confirmed
signature → ranked same-shape hit list across an entire local corpus). This is
the discipline the directions doc called "corpus-scale": read *all* the source,
not a sample.
- **Unlocks:** 1.2 (invariants are visible in source), 1.4 (sinks are greppable
  even when unreachable in a scan), and cross-pollinates every other edge.

### E2 — Perfect failure memory
`engine/store.mjs` keeps a cross-session **failure ledger** (`priorFailures`:
held actions, failed exploits, dead-end phases, deduped by phase|approach) so a
new session never re-tries a dead idea. `docs/RESEARCH.md` extends the same
rule to research: refuted hypotheses stay in `docs/research/hypotheses.jsonl`
forever. `engine/pathsearch.mjs` folds cross-session priors directly into the
search value function.
- **Unlocks:** all six — but decisively 1.3 and 1.5, where the search space is
  combinatorial and the win comes from *not* re-exploring pruned branches that
  human hunters re-test every engagement.

### E3 — Surface graph + value-guided path search + chain compiler
`engine/surface.mjs` models the engagement as a graph (17 node types, 20 edge
kinds). `engine/pathsearch.mjs` runs LATS/MCTS over it — real probes, UCT
selection, an outcome-value table (`writable` 0.97 … `not-found` 0.0), pruning,
auto-activation on ≥2 credible paths, and an OPSEC cost term. `engine/graphquery.mjs`
answers NL questions against that graph with provenance to the producing node.
`engine/chainforge.mjs` is the differentiator: a **deterministic exploit-chain
compiler** that turns structured surface data into an executable, evidence-
carrying `chainrun`-shaped plan with per-step confidence and *honest gaps* — a
rule that can't complete says exactly what it's missing instead of
hallucinating. `tools/chainrun.mjs` executes those declarative chains with
expectation checks and evidence capture per step.
- **Unlocks:** 1.3 directly (composition is a graph search + compile), 1.1
  (chains are state-transition sequences).

### E4 — The claimed-vs-real gate (validator as research instrument)
`engine/validator.mjs` enforces proof-vs-belief in code: no confirmed tier
without an objective oracle (`hasObjectiveOracle` ingest downgrade), explicit
reproduction passes, **garbage-control paired reads** (the manhuaus doctrine —
a hollow 200+empty-body burned days once, never again), collision-proof markers
(`vrv` + crypto-random, scrubbed from echoed request URLs), per-class oracles,
and staleness rendering. A detector that caught nothing is a hypothesis, not a
tool — this gate is what makes VARVEL's research output *believable*.
- **Unlocks:** makes every other edge monetizable — bounty programs pay for
  proof, and the validator's paired-control discipline is exactly what survives
  triage.

### E5 — Human-cadence stealth → LONG engagements
`engine/stealth.mjs` enforces quietness *in code*, not in prompts: a shared
emission clock spaces request starts ≥ delay ± jitter as the target sees them,
so concurrency hides latency without multiplying the visible rate; profiles run
from `loud` to `paranoid` (one request in flight, 500–1300 ms gaps).
`engine/footprint.mjs` + `tools/detoracle.mjs` measure detectability instead of
asserting it. `engine/bountyline.mjs` hard-codes the automation gate
(full|human-cadence|prohibited, derived from each program's own policy text,
default prohibited) and maps human-cadence programs to the conservative
campaign cadence.
- **Unlocks:** 1.4 and 1.5 especially — second-order sinks and logic chains
  need engagements measured in *days* of low-and-slow observation, which no
  scanner and few humans can sustain; VARVEL can, quietly, with every request
  still in the Enclave's audit.

### E6 — Self-hosted lab + self-attack calibration loop
`targets/demo-corp.mjs` (breachable with no API key), `targets/northwind.mjs`,
`targets/premium-hard.mjs`, `targets/soc-core.mjs`, `deploy/range-iso/` (ISO VM
range), `vm-lab.mjs`. `engine/twinforge.mjs` records a *defender's* behavior
into a portable profile and synthesizes a loopback-bound twin server that
replays it — with fidelity scoring. `engine/fuzzseed.mjs` already closes the
self-attack loop: its honest first use is fuzzing VARVEL's own wire codecs
(`engine/stegocodec.mjs`, `engine/dnscodec.mjs`, `engine/wsframe.mjs`,
`engine/pipelink.mjs` FrameParser) and pinning crashes as regression tests.
- **Unlocks:** the lab-only rule is a *capability*, not a constraint — we can
  be loud, stateful, and destructive in-lab, which is precisely what technique
  invention requires.

### Edge → miss-class matrix

| Edge | 1.1 state | 1.2 logic | 1.3 chains | 1.4 second-order | 1.5 races | 1.6 protocol |
|---|---|---|---|---|---|---|
| E1 corpus source reading | | ●● | ● | ●● | | ● |
| E2 failure memory | ● | ● | ●● | ● | ●● | ● |
| E3 graph+search+chainforge | ●● | ● | ●● | ● | | ● |
| E4 validator gate | ● | ●● | ●● | ● | ● | ●● |
| E5 human-cadence stealth | ● | ● | ● | ●● | ●● | |
| E6 lab + twinforge | ● | ● | ● | ● | ● | ●● |

(●● = primary unlock, ● = supporting)

---

## 3. The technique-invention program — 8 threads

Ranked by edge × feasibility × payout proximity (honest EV; lottery tickets
marked). Each thread: hypothesis → **lab fixture FIRST** → graduation definition
(pinned tool + test, per `docs/RESEARCH.md` gate 3a) → payout proximity.

---

### T1 — HTTP/3–QUIC desync frontier (directions doc #2)

**Technique hypothesis.** QPACK header compression and H3↔H1/H2 translation
create parser differentials between frontends and origins that no scanner
exercises: compressed-vs-decompressed length accounting (the CVE-2025-64702
asymmetry pattern), header-case/duplicate normalization across protocol
translation, `:pseudo-header` smuggling, and 0-RTT replay semantics. Each is a
desync primitive; primitives compose into cache poisoning and cross-user
hijack.

**Lab fixture FIRST.** `deploy/range-iso/h3-desync/`: a two-stack pair —
an HTTP/3-terminating frontend (self-hosted proxy, e.g. a quic-go or nginx-quic
build) in front of an HTTP/1.1 Node origin (extend `targets/demo-corp.mjs` with
an H3 front container). Build a **differential oracle**: fire candidate request
shapes; log how each layer parsed them (header set, body boundaries, routing
decision); flag any shape the two layers disagree on. Calibrate on a
known-known first: reproduce a documented H2 desync shape against the same
harness before inventing H3 ones (honesty gate, `docs/RESEARCH.md` rule 2).

**Graduation.** Pinned tool `tools/desync.mjs` (differential two-stack prober,
governed, budget-capped, loopback-only by default) + `test/desync.test.mjs`
(proves the oracle flags the known-known and stays silent on benign traffic) +
a chainforge rule that adds "protocol-differential candidate" as an exploit
node prerequisite. Validator gets a `desync` oracle class: paired control =
same shape with a benign header.

**Payout proximity.** ★★★★★ — CDN/proxy/vendor bounties pay top-tier for
smuggling (Akamai's CVE-2025-32094 came in *through* a bounty program).
**Type:** grindable seam. **Timeline:** 4–8 weeks to first differential
finding; a quarter to a smuggling-class result. **Risk:** protocol plumbing
cost is front-loaded and real.

---

### T2 — Chaining engine: automated primitive composition over the surface graph

**Technique hypothesis.** The graph already contains the primitives
(`engine/surface.mjs` nodes: endpoint, finding, cred, tech). `engine/chainforge.mjs`
already compiles methodology-rules into executable chains. The invention is a
**composition search**: treat every low/medium finding as a typed primitive
(leak, redirect, self-xss, cors-permissive, cookie-scope, write-candidate …),
define composition rules (primitive A *enables* primitive B when they share an
origin/token/context node), and run `engine/pathsearch.mjs` over the
*composition space* — two lows → one high, mechanically, with honest gaps when
a middle link is missing.

**Lab fixture FIRST.** Extend `targets/demo-corp.mjs` (or a new
`targets/chainyard.mjs`) with a **planted composition garden**: 6–10 primitives
that are individually informational but compose into 2–3 distinct high-impact
chains (self-XSS + permissive CORS + wildcard cookie → ATO; open redirect +
OAuth flow → token leak; .git exposure → signing key → JWT forge — the key-
material patterns already exist in `engine/chainforge.mjs` `KEY_PATTERNS`).
Success = the engine finds the planted chains *without being told they exist*,
and reports honest gaps on the deliberately-broken chain.

**Graduation.** `engine/chainforge.mjs` gains composition rules (new RULES
entries with needs/build), `engine/pathsearch.mjs` gains a composition-probe
adapter, pinned by `test/chaincompose.test.mjs` (planted chains found; broken
chain reports the exact missing link; nothing fabricated). Validator
integration: each chain step must pass per-step expectation checks via
`tools/chainrun.mjs` evidence capture — a composed chain is only "confirmed"
when the final-step oracle fires under paired control.

**Payout proximity.** ★★★★★ — this is the shortest path from existing code to
money: it converts findings VARVEL already produces (and parks as lows) into
high-impact reports. **Type:** grindable seam. **Timeline:** 3–5 weeks to a
working composition garden + first auto-composed chain. **Why it outranks T1
on feasibility:** every dependency already exists in-repo; the fixture is a
Node target, not a protocol stack.

---

### T3 — Business-logic invariant extraction from source/specs → systematic violation search

**Technique hypothesis.** Invariants are written down — in source conditions,
validation code, OpenAPI constraints, and docs — but never as a testable list.
The technique: (1) run corpus-scale reading (E1: `tools/privemap.mjs`/
`tools/reachprove.mjs` pattern, generalized beyond PHP) to **extract candidate
invariants** ("amount > 0", "owner_id == session.user", "state transitions
forward only") from a target's source or spec; (2) compile each into a
**violation probe** (negative amount, foreign owner id, backward transition);
(3) execute probes as governed, validator-gated requests. This is the miss-
class 1.2 factory.

**Lab fixture FIRST.** `targets/logiclab.mjs` (new): a small commerce/API app
with 8 planted invariant violations of varying subtlety (negative refund, idor
on nested resource, step-skip in a 4-step flow, quantity overflow, self-
approval, currency mixing, replayed redeem, role-crossing invite). Plus a
hand-written "spec" (OpenAPI + README) so extraction has both source and spec
to read. Calibration known-known: the extractor must rediscover at least 6/8
planted invariants before it ever runs anywhere else.

**Graduation.** `tools/invariants.mjs` (source/spec → invariant ledger JSON) +
`test/invariants.test.mjs` (6/8 recall on logiclab; zero fabricated invariants
on a clean control app — precision gate) + a validator oracle class
`logic-violation` (paired control: the same request with a valid value must
NOT violate). Graduated invariants feed `engine/bountyline.mjs` triage as a
new finding class the validator can verify end-to-end.

**Payout proximity.** ★★★★★ — logic bugs are the durable top earners and the
least automated class in the industry. **Type:** grindable seam, and the one
where VARVEL's AI edge (reading + reasoning about intent) is largest relative
to both scanners and humans. **Timeline:** 4–6 weeks to logiclab recall ≥ 6/8;
first real-program logic finding within a quarter.

---

### T4 — Race-condition harness (single-packet / last-byte sync) as a reusable pinned tool

**Technique hypothesis.** Race windows are everywhere but under-hunted because
execution is hard: the miss-class is real, the tooling is scarce. A governed,
loopback-first **last-byte-sync harness** — N requests staged, final byte
released simultaneously — turns theoretical TOCTOU into a measurable oracle:
did the invariant (balance, quota, stock, invite count) hold under concurrency?

**Lab fixture FIRST.** Extend `targets/demo-corp.mjs` (or `targets/logiclab.mjs`)
with **planted race endpoints**: a coupon redeem with a check-then-redeem gap,
a balance debit, a one-time invite. The harness must demonstrate the race
reliably in-lab (≥90% success over 20 trials) before graduation. Note:
`tools/race.mjs` does **not exist** today (verified — no such file); this
thread creates it. HTTP/2 single-packet mode is a v2 extension; v1 is
last-byte sync over parallel connections, which Node can do natively.

**Graduation.** `tools/race.mjs` (governed: scope-checked, budget-capped,
stealth-paced — `engine/stealth.mjs` shared emission clock governs the *lead-up*
requests; the synchronized release is the one deliberate burst, logged as such)
+ `test/race.test.mjs` (planted race caught; non-racy control endpoint
produces zero findings — the honesty gate) + validator oracle class `race`
(control = sequential replay of the identical requests must NOT violate the
invariant; a "violation" that also occurs sequentially is a logic bug, not a
race — the harness must say which).

**Payout proximity.** ★★★★☆ — races pay well (financial endpoints) and the
competition is thin. **Type:** grindable seam. **Timeline:** 2–4 weeks —
cheapest thread to build after T2. **Honesty note:** the *technique* is known
(PortSwigger published it); VARVEL's invention is making it a governed,
self-calibrating, always-available capability — productization, not discovery.

---

### T5 — Auth-flow graph differ across locale/region deployments

**Technique hypothesis.** Multi-locale platforms (the directions doc names
trip.com's 43 locales as the proving ground) deploy *the same auth stack* with
per-locale config drift: different OAuth redirect whitelists, session-cookie
domains, CSP, federated IdP trust, rate limits. The technique: crawl
login/OAuth/session/reset flows per locale into a **flow graph** (nodes =
steps/endpoints, edges = transitions with their security-relevant attributes),
then **diff the graphs pairwise**. A security attribute present in 42 locales
and absent in 1 is a finding candidate no scanner produces, because no scanner
knows the other 42 exist.

**Lab fixture FIRST.** `targets/locale-farm.mjs` (new): one auth stack served
on N loopback ports as N synthetic "locales", with K planted drift bugs
(missing state-check on locale 3, wider redirect whitelist on locale 7, no
rate limit on locale 12, weaker cookie scope on locale 19). Calibration: the
differ must rediscover all K drifts and produce **zero** false drift alarms
when the farm is run un-planted (precision gate).

**Graduation.** `tools/flowdiff.mjs` (flow-graph crawler + pairwise differ;
non-destructive GET/OPTIONS only, same discipline as `engine/webpaths.mjs`) +
`test/flowdiff.test.mjs` (K/K recall, 0 false alarms) + surface integration:
drift findings land as `finding` nodes with the locale pair as provenance
(`engine/graphquery.mjs` can then answer "which locale is weakest").

**Payout proximity.** ★★★★☆ — auth misconfig bugs on large multi-locale
platforms pay consistently, and the differ scales: once built, every multi-
deployment target is a candidate. **Type:** grindable seam. **Timeline:** 3–5
weeks. **Constraint:** live use is *enumeration-heavy but read-only* — still
crosses scopecheck + automation gate (`engine/bountyline.mjs` rule 2) per
program.

---

### T6 — Second-order sink tracer (stored / webhook / async paths)

**Technique hypothesis.** Miss-class 1.4 needs two things scanners lack:
**persistence across time** and **an out-of-band observer**. The technique:
(1) plant collision-proof markers (`engine/validator.mjs`'s `vrv`+random
marker discipline) at every injectable surface; (2) instrument the lab target's
async paths (webhook delivery, email render, PDF job, admin panel) as *sink
observers*; (3) a sweeper revisits sinks on a schedule (E5's long-engagement
cadence) and attributes any detonation to the planting request — closing the
time/space gap mechanically. On real targets the observer role is played by
our own callback infrastructure (`engine/callback.mjs`, `engine/beaconscore.mjs`
already score live flow beacons).

**Lab fixture FIRST.** Extend `targets/demo-corp.mjs` with a planted
second-order garden: a support-ticket field that renders in an admin view, a
webhook URL consumer, a report-PDF renderer, a nightly-batch template.
Calibration: tracer must catch all 4 sink classes and correctly attribute each
detonation to its planting request ID.

**Graduation.** `tools/sinktrace.mjs` (marker planter + scheduled sink sweeper
+ attribution ledger; all sweeps stealth-paced and budgeted) +
`test/sinktrace.test.mjs` (4/4 sink classes caught; attribution correct;
zero false attributions on a clean control) + validator oracle class
`second-order` (detonation must carry the *planting* marker, never a
dictionary word — the manhuaus collision doctrine applied to stored sinks).

**Payout proximity.** ★★★★☆ — blind/stored sinks into admin contexts are
perennial high-sev payouts. **Type:** grindable seam. **Timeline:** 3–4
weeks. Builds directly on T2's garden pattern.

---

### T7 — Corpus variant hunting, generalized beyond WordPress (highest-EV addition #1)

**Technique hypothesis.** The proven loop (E1: privemap → reachprove →
variantsweep over a local WP corpus → 5 verified vulns in a week) is currently
PHP/WordPress-shaped. The invention is not a new bug class but a **repeatable
factory**: same three-stage pipeline, new grammars — npm packages (JS),
PyPI wheels (Python), VS Code extensions (directions doc #9: a confirmed
under-policed corpus — [Wiz: 500+ leaked secrets in extensions](https://www.wiz.io/blog/supply-chain-risk-in-vscode-extension-marketplaces)).
One confirmed signature becomes a corpus-wide sweep in hours.

**Lab fixture FIRST.** No new target needed: the lab *is* the corpus. Download
(legally, read-only) the top-N packages of one new ecosystem into
`data/corpus/<ecosystem>/`; calibrate on a *known CVE* in that ecosystem —
the pipeline must rediscover it from its public signature before hunting new
ones. (Known-known calibration, `docs/RESEARCH.md` rule 2.)

**Graduation.** Grammar packs for `engine/reachability.mjs`/
`engine/variantsweep.mjs` (JS first) + `test/variantsweep-js.test.mjs`
(rediscovers the calibration CVE; honest `skipped[]`/`gaps[]` behavior
preserved per the house contract in `tools/variantsweep.mjs`).

**Payout proximity.** ★★★★☆ — this is the thread with the **most direct
historical revenue proof in the repo** (`engine/lanes.mjs` provenance
comment). **Type:** grindable seam. **Timeline:** 2–3 weeks for the JS
grammar pack. **Honesty:** crowded field in absolute terms; VARVEL's edge is
throughput + the lanes/scopecheck doctrine converting finds into filings
without ban-risk.

---

### T8 — Offensive agent-surface exploitation (highest-EV addition #2 — **lottery ticket**)

**Technique hypothesis.** The MCP round built *defenses* (`engine/mcpguard.mjs`).
The offensive inversion: bounty programs increasingly cover AI features
(agents, copilots, RAG assistants) and the directions doc §1 shows the attack
literature is young. The technique: **indirect prompt injection as a delivery
mechanism for classic impact** — plant instruction-bearing content where an
agentic feature will read it (support ticket, web page, document, tool output),
and demonstrate a *security-relevant* consequence (data exfil to our callback,
cross-tool action the user didn't authorize, session-context leak). This is
miss-class 1.4 (second-order) where the async "sink" is a language model.

**Lab fixture FIRST.** We own the victim: VARVEL itself plus
`tools/mcpserve.mjs` and `deploy/range-iso/mcp-poison/` (the existing
poison fixtures and `llm-round-verdict.json` harness from the defensive round —
reuse the lab, invert the role). Build `targets/agentvictim.mjs`: a small
agentic app (tool-using assistant with a mailbox + a web fetcher) and measure
which injection placements produce which unauthorized actions. The hyp-004
result (0/1 directive compliance at n=1) says current models resist naive
payloads — the research question is *which phrasings/placements/chains work*,
which is exactly the systematic sweep a human won't grind.

**Graduation.** `tools/agentprobe.mjs` (injection-placement battery + action-
delta oracle: did the agent take an action absent from the benign control
run?) + `test/agentprobe.test.mjs` + validator oracle class `agent-injection`
(paired control is mandatory: same content without the instruction must not
trigger the action).

**Payout proximity.** ★★★☆☆ and **variance is huge**: if AI-feature bounty
scope keeps expanding (the directions doc's evidence says it is), this thread
mints a named class; if model resistance improves faster, it produces
writeups, not bounties. **Type: LOTTERY TICKET** — run as a background
thread, never the main lane. **Timeline:** 4–8 weeks to know which world
we're in.

---

## 4. The operating rhythm

### The 24/7 research cron (post-spark)
When bounty income funds always-on compute (the condition named in
`docs/RESEARCH.md` §"The 24/7 plan"), a recurring research cron at a stable
off-peak minute cycles the open threads:

1. **Pick one thread per round** (round-robin weighted by the ranking in §3;
   lottery-ticket T8 gets at most 1 round in 6).
2. **Run one lab experiment** against that thread's fixture — lab only, loud
   allowed, everything logged.
3. **Append results** to `docs/research/hypotheses.jsonl` — including and
   especially refutations (the failure-ledger rule, `docs/RESEARCH.md` rule 1;
   `engine/store.mjs` is the engagement-level analogue).
4. **Surface graduations** to the operator as console cards the same day
   (status flips in the log; pinned tool + test land in `tools/` + `test/`
   under the audit + 0-fail bar).

Until post-spark: manual rounds when the operator calls them — exactly the
pattern that produced hyp-001..hyp-004 and their lab confirmations.

### How graduated techniques feed the bounty pipeline
A graduated technique is, by definition, a pinned tool + test. It enters
revenue through three existing doors, in order:

1. **New validator-verifiable class.** The thread's oracle class is added to
   `engine/validator.mjs` `ORACLES` vocabulary, so findings of the new class
   can reach the *confirmed* tier (the ingest gate, `hasObjectiveOracle`,
   otherwise downgrades them — the gate is what makes the new class credible
   to triage teams).
2. **Bountyline ingestion.** `engine/bountyline.mjs` runs the program state
   machine (imported → scoped → hunted → triaged → reported → queued);
   automation policy is derived from the program's own policy text (default
   prohibited), scope requires a signed engagement scope, and the pipeline
   **never submits** — `queued` is the end of the line; Jack's hand sends.
   Graduated techniques change what `hunted` can find, never who sends.
3. **Scope gate.** Every candidate filing crosses
   `tools/submit-drive.mjs scopecheck` (offline-decidable June-2026 scope
   rules; FILE / PARK / NO-FILE) and `engine/lanes.mjs` lane classification
   (Wordfence/Patchstack rules verified against live programs, classify-never-
   filter). A novel-class finding that no lane accepts goes to direct vendor
   disclosure or a writeup — never forced through a bounty form.

### Honesty gates (non-negotiable, inherited from `docs/RESEARCH.md`)
- **Calibrate on known-knowns** — every new detector first catches a KNOWN
  instance of its class in-lab (T1 reproduces a documented desync; T4
  reproduces its planted race; T7 rediscovers a public CVE). A detector that
  has caught nothing is a hypothesis, not a tool.
- **Paired controls everywhere** — the manhuaus doctrine (`engine/validator.mjs`
  v2): no claim without a control; hollow success = refutation.
- **Refuted is a first-class outcome** — it stays in the log forever; a future
  agent never re-tests a dead idea unknowingly.
- **The auditor watches the research lane too** — `engine/auditor.mjs`'s
  claimed-vs-real delta and stuck-streak re-plan apply to research rounds; a
  thread that goes N rounds with zero anomalies gets an escalating Deep-Think
  (`engine/deepthink.mjs`: ≥2 competing hypotheses with disambiguating probes)
  or is parked honestly.

---

## 5. Sequencing — what runs first and why

| Order | Thread | Why this position |
|---|---|---|
| 1 | **T2 chaining engine** | Highest edge × feasibility product: every dependency exists (`surface.mjs`, `pathsearch.mjs`, `chainforge.mjs`, `chainrun.mjs`); the fixture is a Node target; it monetizes findings VARVEL already parks as lows. First revenue-adjacent result in 3–5 weeks. |
| 2 | **T4 race harness** | Cheapest new capability (2–4 weeks), thin competition, creates `tools/race.mjs` from zero. Its governed-burst pattern also hardens the platform for T1's probes. |
| 3 | **T3 logic invariants** | Largest long-term EV — the least-automated, highest-payout miss-class — but needs T2's garden pattern and validator oracle practice to land cleanly. |
| 4 | **T7 corpus generalization** | The proven-revenue factory; slot it once T1–T3 fixtures exist so grammar-pack work doesn't block invention work. |
| 5 | **T1 HTTP/3 desync** | Highest single-bug payout, but the protocol-stack fixture cost is real; start after T2/T4 prove the differential-oracle pattern on simpler ground. hyp-003 already open. |
| 6 | **T5 auth-flow locale differ** | Solid seam; needs a crawler mature enough to map flows faithfully — reuse `engine/webpaths.mjs` lessons after T2. |
| 7 | **T6 second-order sink tracer** | Depends on T2's garden and long-cadence scheduling; natural fourth-quarter thread. |
| 8 | **T8 agent-surface offense** | **Lottery ticket.** Background thread only (≤1 cron round in 6), reusing the existing `range-iso/mcp-poison` lab. Re-rank after its first 4–8 week verdict. |

**Why T2 first, stated plainly:** the MCP defensive round proved the lab loop
works (hypothesis → fixture → pinned test → graduation, hyp-001/hyp-002). T2
applies that proven loop to the platform's strongest existing assets and the
clearest payout mechanism — primitive composition — with the lowest fixture
cost of any thread. It is the fastest honest path from "research lane" to
"capability nobody else has."

---

## Appendix — hypothesis log additions (2026-08-29)

Appended to `docs/research/hypotheses.jsonl` with status `open` (schema per
`docs/RESEARCH.md`): hyp-005 (T2 composition garden), hyp-006 (T4 race
harness), hyp-007 (T3 invariant extraction). Existing open threads: hyp-003
(HTTP/3 desync), hyp-004 (MCP LLM round, `testing`).

*External trend evidence for all threads: `docs/research/directions-2026-08-29.md`
(every URL retrieved 2026-08-29). Nothing in this program was executed against
a live target.*
