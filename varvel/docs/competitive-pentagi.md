# Competitive analysis — PentAGI vs VARVEL

**Date:** 2026-08-29
**PentAGI source:** shallow clone at `enclave/.tmp/pentagi-src`, HEAD commit
`ea665308baaff015b226f308438a68d929d0f29b` ("fix(deps): upgrade langchaingo …",
dated 2026-08-06). GitHub API on 2026-08-29: **22,165 stars, 2,951 forks**,
repo created 2025-01-06, last push 2026-08-06.
**Method:** static source reading only. PentAGI's docker stack was not run and its
dependencies were not installed. PentAGI paths below are relative to the clone root;
VARVEL paths are relative to `enclave/varvel` (L2 paths relative to `enclave/`).
Negative claims ("pentagi has no X") mean: searched `backend/pkg` and the docs and
found nothing — see §7 for the limits of that.

---

## 1. PentAGI architecture summary

**Shape.** A self-hosted, multi-user web product: Go backend (REST + GraphQL +
Swagger), React/TypeScript frontend (230 `.tsx` files under `frontend/src`),
PostgreSQL + pgvector as the system of record and vector memory, and per-engagement
Docker sandboxes running a Kali image (`vxcontrol/kali-linux` is the default —
`backend/pkg/config/config.go:57`). Optional sidecar stacks ship as separate compose
files: Langfuse analytics (`docker-compose-langfuse.yml`), Graphiti + Neo4j knowledge
graph (`docker-compose-graphiti.yml`), and a full OTel/Grafana/VictoriaMetrics/
Jaeger/Loki observability stack (`docker-compose-observability.yml`, `observability/`).

**Agent orchestration.** A strict delegation hierarchy, not a phase pipeline. A
**primary agent** (orchestrator) decomposes a **Flow** into **Tasks** and
**SubTasks** (ER model in `README.md`; tables in `backend/pkg/database/tasks.sql.go`,
`subtasks.sql.go`) and delegates to specialists *as tool calls* — `coder`,
`pentester`, `maintenance`, `memorist`, `advice` are all registered tool names
(`backend/pkg/tools/registry.go:10-52`). Thirteen agent option types exist
(`backend/pkg/providers/pconfig/config.go:140-170`): primary_agent, assistant,
adviser, generator, refiner, searcher, enricher, coder, installer, pentester,
reflector, plus simple/simple_json. Each agent type can be pinned to a different
model, and the adviser can deliberately run a stronger model than the workers
(`README.md` "Advanced Agent Supervision"). Dynamic plan repair is a first-class,
heavily tested feature: `backend/pkg/providers/subtask_patch.go` (336 lines) with
1,241 lines of tests in `subtask_patch_test.go`.

**Supervision (this is the good part).** Three layers (`README.md`, "Advanced Agent
Supervision"):

- **Reflector (always on):** after 3 consecutive failures to produce a valid tool
  call, a reflector agent is invoked to steer the model back
  (`backend/pkg/providers/performer.go:565` `performReflector`, prompts in
  `backend/pkg/templates/prompts/reflector.tmpl`).
- **Execution monitor (beta, off by default):** an adviser/mentor fires when tool-call
  patterns look stuck — ≥5 identical calls or ≥10 total (configurable) — and injects
  a `<mentor_analysis>` next to the tool result. README claims ~2x result quality on
  Qwen3.5-27B at 2–3x token cost.
- **Planner (beta, off by default):** an adviser in planning mode generates a 3–7
  step plan wrapped in `<task_assignment>` before specialists run
  (`AGENT_PLANNING_STEP_ENABLED`, `task_assignment_wrapper.tmpl`).
- **Hard tool-call caps:** 100 calls for general agents, 20 for limited agents
  (`MAX_GENERAL_AGENT_TOOL_CALLS` / `MAX_LIMITED_AGENT_TOOL_CALLS`, README).

**LLM abstraction.** The broadest part of the product: 10+ first-party providers
(OpenAI, Anthropic, Gemini, Bedrock, Ollama, DeepSeek, GLM, Kimi, Qwen, MiniMax,
custom OpenAI-compatible) plus aggregators (`backend/pkg/providers/` — one package
per provider; 26 example provider YAMLs in `examples/configs/`). Per-model metadata
declares reasoning capability (`budget` / `adaptive` / `adaptive-only`,
`config.go:181-198`) and **price tables including cache-read/cache-write pricing**
(`config.go:100-122`, `CallUsage.UpdateCost`). There are even CLI harnesses for
testing providers/functions/embeddings: `backend/cmd/ctester`, `ftester`, `etester`.

**Cost accounting.** Real and persisted: every message chain accumulates
input/output/cache tokens and computed dollar cost into Postgres
(`backend/pkg/providers/performer.go:898-930` `updateMsgChainUsage` →
`database.UpdateMsgChainUsage` with `UsageCostIn/Out`), and Langfuse gets the same
telemetry for analytics.

**Memory / RAG.** Three tiers: (a) pgvector long-term memory exposed to agents as
tools — `search_in_memory`, `search_guide`/`store_guide`, `search_answer`,
`search_code`/`store_code` (`registry.go:33-40`), with an explicit prompt-level
anonymization protocol for stored guides (`templates/prompts/pentester.tmpl`,
`<anonymization>` block); (b) **chain summarization** — a structured ChainAST
summarizer that keeps the last section intact and QA-pair-summarizes the rest under
byte budgets (`backend/pkg/csum/chain_summary.go`, config table in `README.md`;
design doc `backend/docs/chain_summary.md`); (c) optional Graphiti/Neo4j temporal
knowledge graph fed automatically from agent responses and tool executions
(`performer.go:933-1046` `storeToGraphiti` etc.).

**Tool/execution model.** Agents get: `terminal` (docker exec in the flow's sandbox,
3h hard cap per command, `backend/pkg/tools/terminal.go`), `file`, `browser`
(isolated scraper service), nine web-search backends (`backend/pkg/tools/searchers/`
— DuckDuckGo, Google, Tavily, Firecrawl, Traversaal, Perplexity, Searxng, Sploitus,
internal scraper), memory tools, and delegation tools. Tool results are size-capped
(16 KB results, 1 KB arg values — `backend/pkg/tools/executor.go:24-26`). An
**installer agent** can `apt`-install new tools into the sandbox mid-engagement
(`installer.tmpl`; rationale in `backend/docs/docker.md:199`).

**Sandboxing.** Per-flow containers with a considered hardening posture:
`CapDrop: ["ALL"]` plus an explicit allow-list (Docker's default 14 minus `MKNOD`,
plus optional `NET_ADMIN`/`SYS_PTRACE`), a 2048 PID limit, no-new-privileges
*deliberately rejected with a written rationale* (`backend/pkg/docker/client.go`
~lines 358-366 and `backend/docs/docker.md` "Capability Management"). Guidance exists
for the genuinely dangerous bit — giving agents Docker without host root
(`README.md` "Giving Agents Docker Without Giving Away the Host": hardened dind over
TLS, explicitly warning against bind-mounting the host socket), and a two-node
worker-isolation deployment (`examples/guides/worker_node.md`).
**But:** I found **no target-scope enforcement in code** — nothing like a CIDR ring
check before a command runs. Authorization is asserted in prompts: the pentester
system prompt says "ALL security testing actions are PRE-AUTHORIZED … Never request
permission" (`backend/pkg/templates/prompts/pentester.tmpl`, "AUTHORIZATION
FRAMEWORK"). (Negative claim — see §7.)

**HITL.** One mechanism: the `ask` barrier tool lets an agent pause and ask the
operator a question (`registry.go:12` `AskUserToolName`; flow-input tools
`submit_flow_input`, `wait_flow_completion`). There are **no approval gates for
dangerous actions** — by design, per the prompt above.

**Auth / multi-user.** Local users with a default admin, admin-managed Users REST
API, GitHub/Google OAuth, Bearer API tokens for REST+GraphQL (`README.md` "Web UI
Accounts"), and a `TENANT_ID` multi-instance namespacing scheme that re-keys
cookies/tokens/DB schema/container names (`README.md` "Running Several Instances").

**Observability.** Two stacks: Langfuse for LLM traces (a vendored, fern-generated
API client at `backend/pkg/observability/langfuse/`) and an OTel pipeline to
VictoriaMetrics/Jaeger/Loki/Grafana (`backend/pkg/observability/`,
`docker-compose-observability.yml`).

**Maturity signals.** 135 Go `_test.go` files; 70 frontend test files; CI running
lint/type-check/GraphQL-codegen-freshness/frontend+backend tests plus docker build
(`.github/workflows/ci.yml`); a fork-safe E2E suite with a mock tier on every PR and
a real-LLM "stand" tier (`.github/workflows/e2e.yml`, `e2e-stand.yml`,
`docker-compose.e2e.yml`); 15+ backend design docs (`backend/docs/`); example
reports (`examples/reports/`), install guides, and an interactive TUI installer
(`backend/cmd/installer`). 22k stars in ~19 months.

---

## 2. Head-to-head

| Dimension | PentAGI | VARVEL | Ahead |
|---|---|---|---|
| Mission fit (governed, scoped, stealth red-team/bounty) | Autonomous pentest assistant; explicitly *not* BAS/adversary emulation (`README.md` "Current Capability Boundaries") | Built exactly for this: signed scope, stealth governor, bounty pipeline | **VARVEL** |
| Governance / authorization | Prompt-level "pre-authorized" assertion; no code-level scope enforcement found | L2 Enclave: Cedar PDP, PreToolUse hook, HMAC-signed sessions, FS-jail, egress deny-by-default, hash-chained audit (`poc/enforcement-seam/README.md`) | **VARVEL (decisively)** |
| Scope containment | None found | Signed CIDR ring checked in code (`engine/ipaddr.mjs`, `engine/identity.mjs`); out-of-ring = loud refusal (e.g. lateral spec gate, `docs/AGENT-GUIDE.md:521-523`) | **VARVEL** |
| Proof standard | Findings are whatever the agent writes; no validator found | Validator gate: `confirmed` without an objective oracle is downgraded at ingest; explicit re-run; `refuted` is first-class (`engine/validator.mjs`) | **VARVEL** |
| Honesty/anti-hallucination | Mentor watches tool-call *patterns* (loops), not claims | Claimed-vs-real delta audit + stuck-streak + escalating re-plan (`engine/auditor.mjs`); bounty doctrine encodes platform ban rules in code (`engine/lanes.mjs`, `tools/submit-drive.mjs`) | **VARVEL** |
| Stuck/loop recovery | Reflector after 3 bad tool calls; mentor on repeated calls; planner — intra-agent, tool-call granularity (`performer.go:565`, README) | Auditor at phase granularity; deepthink re-plan (`engine/deepthink.mjs`); wedged-host watchdog `_withBudget` (`engine/campaign.mjs:377-414`) | **PentAGI (slightly — finer granularity)** |
| Agent topology | 13 agent types, delegation-as-tools, dynamic subtask patching (`subtask_patch.go`) | Phase FSM (`engine/campaign.mjs`, 883 lines) + Fireteam parallel specialists (`engine/fireteam.mjs`) + LATS/MCTS path search (`engine/pathsearch.mjs`) | **Tie** (different shapes, both real) |
| LLM provider breadth | 10+ providers + aggregators, per-agent-type model pin, reasoning-mode metadata, price tables (`backend/pkg/providers/`) | Kimi K3 / Claude CLI / mock (`engine/live.mjs`, `engine/claude-cli.mjs`, `engine/brain-provider.mjs`) | **PentAGI (decisively)** |
| Cost accounting | Per-chain token + dollar cost in Postgres + Langfuse (`performer.go:898-930`) | OPSEC/noise budget in "noise points" (`engine/budget.mjs`); **no dollar cost tracking found** | **PentAGI** |
| Memory / RAG | pgvector semantic memory + anonymized guide store + Graphiti knowledge graph | File-backed cross-session store with FAILURE ledger (`engine/store.mjs`); checkpoint/split session resilience (`engine/missions.mjs`); **no vector search** | **PentAGI** |
| Context engineering | Systematic chain summarization with byte budgets (`backend/pkg/csum/`) | Mission checkpoint → summarize → split → resume with refuted-paths seeding (`engine/missions.mjs:1-24`) — coarser, but crash-safe | **PentAGI (slightly)** |
| Tooling | 20+ pro tools in a Kali container + runtime installer agent + 9 web-search backends | ~25 native hardened recon/web tools adversarially audited (`docs/TOOLS.md`), orchestrates external tools; no container toolchain | **PentAGI** (breadth) — but VARVEL's are QA'd harder per tool |
| Offensive tradecraft (C2, persistence, AD, covert channels) | None — out of scope for the product | 8-transport governed C2 with AEAD envelopes (http/dns/icmp/doh/ws/smb/ghc/stg), pivot mesh, SOCKS5, in-memory .NET, persistence + deep persistence, signed-proxy execution, AD roast/lateral/LSASS tiers (`docs/AGENT-GUIDE.md:93-577`) | **VARVEL (decisively)** |
| Stealth engineering | None found | Enforced pacer with shared emission clock (`engine/stealth.mjs`), quantified noise budget (`engine/budget.mjs`), ghost proxy chain (`engine/ghost.mjs`), TLS-inspection classifier with fail-closed/adapt policies (`engine/tlsinspect.mjs`) | **VARVEL (decisively)** |
| Detection measurement | None found | detoracle / edrview / fporacle / floworacle / tradecraft oracles — "measure, never assert" (`docs/AGENT-GUIDE.md:579-615`) | **VARVEL** |
| OPSEC hygiene / cleanup | Not found | Artifact manifests with verified removal; engagement refuses to call itself clean while unverified artifacts persist (`engine/opsec.mjs`, `engine/persist.mjs` doctrine) | **VARVEL** |
| Bug-bounty pipeline | None | Full intake→policy-gate→hunt→triage→redacted-draft→queue (never auto-submits, static-scanned) → outcome ledger (`engine/bountyline.mjs:1-32`) | **VARVEL (decisively)** |
| Sandbox hardening | CapDrop-ALL + allow-list, PID limits, dind-over-TLS guidance, two-node isolation (`backend/docs/docker.md`) | Container story is thinner in-repo (Claude CLI runs host-side, `engine/claude-cli.mjs`); enforcement is hook/egress/FS-jail instead | **PentAGI (sandbox) / VARVEL (policy)** — call it **PentAGI** on container craft |
| UI | Full React product: flows, knowledge, resources, settings, terminal streaming, screenshots (230 components) | Single-file console `app-v3.html` (data-driven, live graph) | **PentAGI (decisively)** |
| API surface | REST + GraphQL + Swagger + Bearer tokens | Single-purpose HTTP API in `server.mjs` | **PentAGI** |
| Multi-user / multi-tenant | Users, OAuth, API tokens, TENANT_ID namespacing | Single-operator model | **PentAGI** |
| Tests | 135 Go + 70 frontend test files (not run here) | 147 pinned test files — **run 2026-08-29: 1261 tests, 1242 pass, 1 env-dependent fail, 18 skipped** (log: `.tmp/varvel-test.log`); adversarial probe-audit QA process (`docs/TOOLS.md`) | **VARVEL (density/rigor)**, PentAGI (CI breadth: e2e w/ real LLM tier) |
| Docs | 15+ backend design docs, guides, 26 provider configs | README + AGENT-GUIDE (800-line operating manual) + 10 topic docs | **Tie** |
| Adoption | 22,165 stars, 2,951 forks, Discord/Telegram | Private | **PentAGI (decisively)** |

---

## 3. Where PentAGI is ahead

1. **LLM provider abstraction.** A registry of 10+ providers with per-agent-type
   model pinning, declarative reasoning-mode capability metadata, and price tables
   with cache pricing (`backend/pkg/providers/pconfig/config.go:140-219`,
   `examples/configs/*.provider.yml` — 26 working examples). VARVEL has two live
   backends plus a mock (`engine/live.mjs`, `engine/claude-cli.mjs`). Nothing in
   VARVEL lets the *auditor* run on a stronger model than the *worker*, which
   PentAGI's adviser pattern does deliberately.
2. **Dollar cost accounting.** Per-call usage → cost computed from per-model price
   metadata and persisted per message chain (`performer.go:898-930`,
   `pconfig/config.go:100-122`). VARVEL's `engine/budget.mjs` counts *noise points*;
   I found no token/dollar tracking.
3. **Semantic memory.** pgvector-backed stores exposed as agent tools with an
   anonymization protocol for what gets stored (`tools/registry.go:33-40`,
   `pentester.tmpl` `<anonymization>`), plus optional Graphiti/Neo4j.
   VARVEL's `engine/store.mjs` is exact-key file storage — a new engagement can't ask
   "what worked last time against something *like* this?".
4. **Context summarization as a system.** The ChainAST summarizer with byte budgets
   and QA-pair strategy (`backend/pkg/csum/chain_summary.go`,
   `backend/docs/chain_summary.md`) is more systematic than VARVEL's
   mission-split/resume (`engine/missions.mjs`), which is crash-resilient but coarse.
5. **Intra-agent loop detection.** The execution monitor catches 5-identical-tool-call
   ruts *inside* a run and injects mentor analysis into the tool result itself
   (`README.md` "Execution Monitoring"). VARVEL's auditor works at phase boundaries
   (`engine/auditor.mjs`), which is later.
6. **Tool-result hygiene.** Hard caps on tool result size (16 KB) and argument length
   (1 KB) at the executor (`backend/pkg/tools/executor.go:24-26`) — a simple,
   effective prompt-injection/context-flooding damper. I did not find an equivalent
   cap in VARVEL's tool path (not verified exhaustively — §7).
7. **Web-search breadth.** Nine pluggable search backends including Sploitus for
   exploit/PoC lookup (`backend/pkg/tools/searchers/`). VARVEL has no general
   web/exploit search tool (its `engine/webpaths.mjs` is content discovery on the
   target itself).
8. **Product surface.** Real multi-user auth, OAuth, API tokens, REST+GraphQL+Swagger,
   tenant namespacing, a 230-component React UI with live terminal and screenshots.
   VARVEL is single-operator with one HTML file (`app-v3.html`). For a platform meant
   to be *used daily by a team*, this gap is real.
9. **Container craft.** The capability allow-list reasoning, the dind-over-TLS
   pattern, the boot-order race warning (`README.md:689-694`), PID limits
   (`backend/pkg/docker/client.go`), and the two-node worker guide are
   production-hardened knowledge VARVEL doesn't have in-repo.
10. **Community/proof-in-the-wild.** 22k stars, example reports from real runs
    (`examples/reports/`), e2e CI tiers including a real-LLM stand
    (`.github/workflows/e2e-stand.yml`). PentAGI has been run by strangers against
    real targets at scale; VARVEL has not.

## 4. Where VARVEL is ahead

1. **Governance, full stop.** PentAGI's authorization model is a paragraph in a
   system prompt (`pentester.tmpl`: "ALL security testing actions are
   PRE-AUTHORIZED … Never request permission"). VARVEL's is a signed scope verified
   by an out-of-model Cedar PDP through a PreToolUse hook with a hash-chained audit
   ledger (`poc/enforcement-seam/README.md`; the injection and forged-token scenarios
   demonstrably fail). For VARVEL's stated mission this is the product; PentAGI
   cannot add it with a feature flag.
2. **Scope containment in code.** CIDR-ring checks in `engine/ipaddr.mjs` consumed by
   the campaign, the lateral-exec spec gate (hostnames refused because they can't be
   scope-verified — `docs/AGENT-GUIDE.md:521-523`), and egress deny-by-default at L2.
   No equivalent found in PentAGI.
3. **The proof standard.** PentAGI reports what the agent claims. VARVEL downgrades
   unbacked `confirmed` claims at ingest, offers one-shot governed reproduction, and
   treats `refuted` as a first-class, report-visible outcome
   (`engine/validator.mjs:1-13`). This is the XBOW/ARTEMIS lesson implemented as a
   rail; PentAGI doesn't have the rail.
4. **Honesty audit.** Claimed-vs-real surface delta with deterministic stuck-streak
   and escalating re-plan (`engine/auditor.mjs`, including a `CLAIM_RE` over verbs
   like "found/confirmed/exploited"). PentAGI's mentor catches *repetition*, not
   *fabrication*.
5. **Offensive depth.** Eight-transport governed C2 with end-to-end AEAD envelopes
   (relay parents provably cannot read forwarded content —
   `test/envelope.test.mjs` per `docs/AGENT-GUIDE.md:112-128`), SMB pivot mesh, SOCKS5
   through the scope seam, GitHub-gist dead-drop and PNG-steganography channels,
   double-gated persistence with verified removal, signed-proxy execution behind
   app-allowlisting, and a full AD tier (kerberoast/ASREP collectors, lateral
   adapters, LSASS-via-comsvcs with mandatory EDR pairing)
   (`docs/AGENT-GUIDE.md:93-577`). PentAGI has nothing in this category and scopes
   itself out of it (`README.md` "Current Capability Boundaries").
6. **Stealth as engineering, not adjectives.** Enforced shared-emission-clock pacer
   (`engine/stealth.mjs:1-11`), quantified noise budgets with HITL escalation
   (`engine/budget.mjs:1-10`), ghost proxy-chain identity with fail-closed pinning
   (`engine/ghost.mjs`), and a TLS-inspection classifier with three explicit policies
   including fail-closed (`docs/AGENT-GUIDE.md:718-767`).
7. **Detection measurement.** The oracle family (detoracle with an EICAR calibration
   gate, edrview, fporacle, floworacle, tradecraft) makes "did they see us?" a
   measured quantity with honest verdict vocabulary
   (`docs/AGENT-GUIDE.md:579-615`). Nothing comparable in PentAGI.
8. **The bounty pipeline.** Policy-text-derived automation gates (silent ⇒
   conservative human-cadence), signed-scope guard, validator-freshness triage,
   redacted drafting, never-auto-submit (pinned by a static scan of the module), and
   a multi-currency outcome ledger that never invents exchange rates
   (`engine/bountyline.mjs:1-32`). Plus the June-2026 account-jeopardy doctrine
   encoded as filing gates (`engine/lanes.mjs`, `tools/submit-drive.mjs scopecheck`).
   PentAGI has no bounty workflow at all.
9. **Cleanup-proof doctrine.** "Persistence that cannot prove its own removal never
   installs"; removals verified by re-read; the platform refuses to call an
   engagement clean while unverified artifacts persist
   (`docs/AGENT-GUIDE.md:324-336`, `engine/opsec.mjs`). PentAGI leaves target hygiene
   to the model.
10. **Test discipline per unit of code.** 1,261 pinned tests including adversarial
    regressions and byte-exact wire-format proofs, re-run for this analysis:
    1242 pass / 1 fail (environment-dependent — see §7) / 18 skipped
    (`.tmp/varvel-test.log`). PentAGI's 135 Go test files are solid for a Go backend
    but thin relative to a much larger surface. VARVEL also documents an adversarial
    probe-audit QA process for its tools (`docs/TOOLS.md`, "QA process").

---

## 5. Steal-list for a future AI (ranked)

`[P1] idea — pentagi evidence — VARVEL integration point — effort`

1. **[P1] Chain/QA summarization with byte budgets** — `backend/pkg/csum/chain_summary.go` + `backend/docs/chain_summary.md` + README config table — new `engine/summarize.mjs`, called from `engine/kimi-runagent.mjs` and `engine/missions.mjs` (split handoff currently ships a `briefSlice`; a real summarizer would preserve far more signal) — **M**
2. **[P1] Dollar cost accounting from per-model price metadata** — `pconfig/config.go:100-122` (`CallUsage.UpdateCost`, cache-aware) + `performer.go:898-930` — extend `engine/budget.mjs` with a parallel `costUsd` ledger fed by `engine/live.mjs`/`engine/brain-provider.mjs` usage returns; surface in `server.mjs` `/api/state` — **S**
3. **[P1] Reflector: auto-steer after N consecutive invalid tool-call generations** — `performer.go:565` `performReflector` + `templates/prompts/reflector.tmpl` — retry path in `engine/kimi-runagent.mjs` (and `engine/claude-cli.mjs` output-parse failures) — **S**
4. **[P1] Intra-agent identical-call loop detection (mentor thresholds: 5 identical / 10 total)** — README "Execution Monitoring" + `performer.go` monitor wiring — `_withBudget` watchdog family in `engine/campaign.mjs:377-414`, or a wrapper in `engine/kimi-runagent.mjs`; complements (does not duplicate) the phase-level auditor — **S**
5. **[P1] Hard caps on tool-result size / argument length before anything enters a prompt** — `backend/pkg/tools/executor.go:24-26` (16 KB / 1 KB) — result ingestion in `engine/kimi-runagent.mjs` and the native-tool `_withBudget` call sites in `engine/campaign.mjs` — **S**
6. **[P2] Semantic (embedding) memory over the store** — pgvector tools `search_guide`/`store_guide` (`tools/registry.go:33-40`) + the anonymization protocol in `pentester.tmpl` — layer over `engine/store.mjs` (keep the FAILURE ledger exact-key; add an embedding index for findings/techniques; adopt the anonymize-before-store rule) — **M-L**
7. **[P2] Adviser-on-a-stronger-model split** — per-agent-type model pinning (`pconfig/config.go:140-170`) + README adviser guidance — generalize `engine/brain-provider.mjs` so `engine/deepthink.mjs`/`engine/auditor.mjs` can pin a heavier model than the worker loop — **M**
8. **[P2] Exploit/PoC web search tool (Sploitus-style) + pluggable search backends** — `backend/pkg/tools/searchers/sploitus.go` (+ 8 siblings) — new `tools/exploitsearch.mjs`, exposed through the governed tool seam and the ghost chain like other egress — **M**
9. **[P2] Sandbox hardening posture for a VARVEL workload container** — `backend/docs/docker.md` "Capability Management" (CapDrop-ALL + allow-list, PID limit, no-new-privileges rationale) + `README.md:673-696` dind-over-TLS — `poc/enforcement-seam/` workload-container spec + `docs/EGRESS.md`; matters the moment VARVEL runs a general shell agent in-container rather than host-side Claude CLI — **M**
10. **[P2] Real-LLM e2e CI tier** — `.github/workflows/e2e-stand.yml` + `docker-compose.e2e.yml` — a scheduled (not per-PR) live run of `test/breach.test.mjs` against the real backend, complementing the hermetic suite and `test/goldenbench.test.mjs` — **M**
11. **[P3] Planner: 3–7-step decomposition wrapped in a task-assignment envelope before specialist fan-out** — `task_assignment_wrapper.tmpl` + `subtasks_generator.tmpl` — `engine/fireteam.mjs` mission briefs / `engine/phases.mjs` per-phase plan step; mainly buys robustness on smaller models — **M**
12. **[P3] Langfuse/OTel trace export for LLM calls** — `backend/pkg/observability/langfuse/` + `docker-compose-observability.yml` — optional sidecar exporter in `engine/kimi-runagent.mjs`; the hash-chained audit stays the ledger of record, Langfuse is the debugging lens — **M**
13. **[P3] Dynamic subtask patching (tested JSON-patch plan repair)** — `backend/pkg/providers/subtask_patch.go` + 1,241-line test — `engine/missions.mjs` (plan revision between checkpoints) — **M**
14. **[P3] Runtime tool-installer agent pattern (apt-in-sandbox)** — `installer.tmpl` + `backend/docs/docker.md:199` — only if/when VARVEL adopts a container toolchain; conflicts with the current native-tools philosophy, so P3 — **M**
15. **[P3] Multi-instance namespacing discipline (TENANT_ID)** — `README.md:698-716` — `engine/settings.mjs`/`engine/statestore.mjs` data-dir keying, if VARVEL ever runs concurrent engagements against shared infra — **S**

## 6. Verdict

For its stated mission — a **governed, scoped, stealth-capable bounty/red-team
platform** — VARVEL is genuinely ahead, and not narrowly: governance, scope
containment, the proof standard, the honesty audit, the stealth/noise machinery, the
C2/AD/persistence tiers, and the bounty pipeline are the mission, and PentAGI has
none of them (its own README scopes it as an autonomous pentest *assistant* and
explicitly disclaims BAS/adversary emulation). PentAGI is ahead as a *product and as
LLM infrastructure*: provider breadth with cost accounting, semantic memory,
systematic context summarization, intra-agent supervision, a real multi-user UI, and
a 22k-star user base that has battle-tested it in the wild. **The single biggest gap
to close is the context/memory/cost stack** (steal-list items 1, 2, 6): PentAGI can
run a cheap small model for hours against a hard target without losing the thread or
the budget plot; VARVEL's current answer (mission split + briefSlice, noise-points
budget) is cruder on exactly the axis — long, expensive, autonomous campaigns — where
its mission demands endurance.

## 7. What I could NOT verify (honest list)

- **PentAGI negative claims are search-bounded, not proof of absence.** "No scope
  enforcement," "no approval gates," "no cleanup verification" come from grepping
  `backend/pkg` (cidr/scope/approval patterns), reading the executor/docker/prompt
  layers, and the docs — not from running the system or auditing all ~10k+ lines of
  `backend/pkg/providers`. A scoped-target feature could exist behind a config I
  didn't open.
- **PentAGI's test suites were not run** (static analysis only, per constraints);
  their 135 Go + 70 frontend test files are counted, not verified green.
- **PentAGI quality claims in its own README** ("2x improvement in result quality"
  from execution monitoring) are vendor claims quoted as such, not reproduced.
- **VARVEL README's "206 tests" line is stale**: the pinned suite is 147 files /
  1,261 tests as run on 2026-08-29 — 1242 pass, **1 fail**, 18 skipped
  (`.tmp/varvel-test.log`). The failure is `test/inlineexec.test.mjs`: its live legs
  skip because `powershell.exe` is unavailable on this host, and teardown then trips
  a Windows libuv assertion (`UV_HANDLE_CLOSING`) — environment-dependent, not a
  logic failure, but it means the suite is **not currently 0-fail on this machine**,
  contradicting AGENTS.md's "0 fail is the bar".
- **L2 Enclave depth.** I read `poc/enforcement-seam/README.md` and confirmed the
  hook/policy/session/ledger files exist; I did not run its demo or audit the Cedar
  policies line-by-line.
- **VARVEL capabilities described in AGENT-GUIDE** (C2 transports, persistence,
  execproxy, AD tier) are documented and have corresponding engine modules and test
  files, but I spot-checked headers and doctrine rather than re-deriving each
  mechanism from source.
- Whether VARVEL has **any** prompt-side tool-result size cap: I searched and found
  none, but did not trace every ingestion path.
