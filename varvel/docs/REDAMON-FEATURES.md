# RedAmon feature inventory → VARVEL build plan

Exhaustive competitive map (RedAmon v6.2.6) so VARVEL matches or beats every feature.
Sourced from RedAmon's README, agentic-system whitepaper, and wiki (Agent-Skills, LATS,
EvoGraph, Fireteam, Adversarial-AI-Recon, AI-Gauntlet, Red-Zone, Surface-Shaper, HackLab).

## Where VARVEL already MATCHES or BEATS (defend + market these)

- **Phase FSM** — VARVEL's 5 phases (recon→validate→exploit→post-ex→report) are *more
  granular* than RedAmon's 3 (info/exploit/post-ex). `validate` + `report` are explicit.
- **OPSEC / operational stealth** — VARVEL has a **deterministic detection-footprint model**,
  an **enforced stealth executor**, and a **quantified noise budget with after-action proof**.
  RedAmon has none of the last three. See the dedicated section below — this is now VARVEL's
  single most defensible advantage, backed by a full competitive deep-dive (2026-08-01).
- **Honesty / anti-loop** — deterministic auditor + stuck counter (extend to tiers+axis to exceed).
- **LATS** — parity (`engine/pathsearch.mjs`), plus two hooks their design lacks: `opsecCost`
  (quieter paths win) and cross-session `prior` boost.
- **Confidence-gated exploitation** — numeric 0–100 + `CONFIRM_AT`; RedAmon doesn't gate on confidence.
- **NL graph query** — `engine/graphquery.mjs`; answers trace to the producing node.
- **Governed Claude-CLI agent** with the enclave hook; **streaming move-cards** in the console.

## Operational stealth — the knockout section (research 2026-08-01)

Full deep-dive of RedAmon's stealth/OPSEC (README, agentic-system whitepaper, CHANGELOG,
wiki ×3, web search; load-bearing quotes re-fetched to confirm). **The finding that decides
the whole category:** RedAmon has *two* execution subsystems with *opposite* stealth
enforcement, and the autonomous one — the part it markets — is the unenforced one.

| RedAmon subsystem | Stealth enforcement |
|---|---|
| **Recon pipeline** (scripted orchestrator: Naabu/httpx/Katana/Nuclei/GVM) | **Code-enforced** but a *static lookup table* — per tool: flip to a quieter flag (Naabu→T2/CONNECT, NSE off), clamp to a constant (GraphQL rate 2/s, concurrency 1), or disable the module (GVM/DAST/cache-poisoning). "AI cannot bypass stealth." |
| **AI agent** (the autonomous LangGraph operator in Kali — nmap/Metasploit/Hydra) | **Prompt-only.** Whitepaper, verbatim: *"Stealth mode is purely prompt-level, there is no separate executor that throttles tools. The LLM is responsible for choosing stealth-appropriate arguments."* A single `--max-rate 200` blows the engagement and nothing catches it. |

RedAmon's gaps (all confirmed): **no footprint model at all** ("footprint" isn't in their
whitepaper); **no jitter / no randomized inter-request delay anywhere** (rates are fixed
constants); **no per-target calibration** (they *name* the `--max-rate 50 vs 200` problem, then
punt it to the LLM); **no stealth budget / no measurement / no after-action proof**; **traffic-
blending near-zero** (no UA rotation, one static `_USER_AGENT` knob); **concurrency undercuts
stealth** (Wave-Runner + Fireteam fire loud concurrent scans with nothing reconciling them
against a stealth goal); their rate limits are **safety/RoE/cost governance, not detection
evasion**. Correct posture they DO hold (and VARVEL matches): **no anti-forensics** — they never
touch target-side logs; VARVEL stays identically clear.

### VARVEL's answer — built + verified (237 tests green)

- ✅ **Enforced stealth executor** (`engine/stealth.mjs`) — profiles `loud|normal|quiet|paranoid`
  set concurrency + inter-request delay + **jitter**, ENFORCED in code inside our native tools
  (`makePacer` wired into `tools/recon.mjs` port sweep + `tools/webscan.mjs` content discovery).
  This is exactly the executor RedAmon's autonomous agent lacks — quietness is a guarantee, not
  a prompt. Timing-floor test proves the pacing is real, not advisory.
- ✅ **Stealth budget** (`engine/budget.mjs`) — RedAmon has NO equivalent. A quantified noise
  ceiling (currency = loudness×count from the footprint model) + a **peak-loudness ceiling**;
  `check()` preflights every activity and flags over-budget/over-ceiling actions to **escalate
  to HITL** rather than fire silently; `status().proof` emits the marketable **"we stayed under
  X noise pts (Y%), peak ≤ Z"** after-action guarantee. Overrides recorded honestly.
- ✅ **Campaign integration** — a profile threads into the native tools (enforced pacing) and the
  budget accrues in lockstep with the OPSEC ledger via the `_noise()` chokepoint; surfaced in
  `/api/state` (`stealth`, `stealthBudget`). `GET/POST /api/stealth` lets the operator pick it.
- **Next (in-bounds, not yet built):** wire the footprint model into the *planner* (rank
  techniques by expected detection cost; queue/refuse over-budget); **P2 target-side detection-
  stack inference** (passively fingerprint WAF/CDN/observed rate-limit thresholds → auto-calibrate
  timing, solving the `50 vs 200` problem RedAmon punts); **defender's-eye after-action report**
  ("here's what a SOC would have seen, and what we stayed under").
- **Boundary-flagged (confirm with Jack before building):** realistic User-Agent / header
  profiles + request-cadence realism ("traffic-blending"). Low-and-slow timing + budget are
  unambiguously in-bounds operational stealth; UA/blending edges toward the evasion line, so it
  waits for a yes. **Hard-out (unchanged):** anti-forensics / log tampering, malware-grade
  evasion (AV/EDR bypass, implants), and NEVER touching the Enclave's own tamper-evident audit.

### Target-aware stealth — BUILT (adaptive calibration RedAmon punts)

`engine/target-profile.mjs` — passively fingerprints the target's defensive stack (WAF/CDN
vendor via headers/cookies/block-pages: Cloudflare/Akamai/Imperva/Sucuri/F5/AWS/Azure/Fastly/
ModSecurity; rate-limit disclosure; bot-challenge; security-header maturity) from ≤2 benign
GETs, then `calibrateStealth()` picks the quietest fitting profile + budget. Wired as the
`'auto'` stealth mode: the campaign fingerprints the target at run start (`_calibrateStealth()`)
and calibrates before recon; surfaced in `/api/state.targetProfile` + the report. This is the
exact `--max-rate 50 vs 200` calibration RedAmon *names in its whitepaper then punts to the LLM*
— VARVEL decides it from measured signals. `GET/POST /api/stealth` lists `auto` first.

### Hardened by dual independent expert review (Fable + Opus, 2026-08-01)

Both models reviewed the stealth code and CONVERGED on the same top findings (high confidence,
no false-flags, boundary respected). Applied: **(a)** honesty fix — the budget proof now requires
BOTH the peak-ceiling AND the cumulative budget to claim "stayed under" (it previously could say
"stayed under 42/40"; both reviewers caught it); **(b)** **shared emission clock** — the pacer now
spaces request *starts* globally, so `concurrency>1` no longer emits the horizontal-scan burst
shape (a provable "≤ N/interval" rate RedAmon can't express); **(c)** one shared pacer threads the
whole engagement (every host + TLS/HTTP/favicon follow-ups + webscan baseline are paced — closed
three un-paced holes); **(d)** fireteam recon now charges the noise budget (was escaping it — the
exact RedAmon gap we mock); **(e)** adaptive back-off on 429/503 (quieter on target push-back);
**(f)** untracked-kind accounting, Infinity-concurrency clamp, integer-floored counts, jitter
floor. **255 tests green.** **Deferred (documented, not a bug):** request-VOLUME fidelity — a
5-path and 5000-path scan currently cost the same per-activity noise; adding a sub-linear volume
term (`loudness × (1+log10(n))`) needs a `BUDGET_PRESETS` retune, so it's a scoped follow-up. The
proof wording now honestly says "activities," not "traffic."

## P0 — build first (category-defining parity; without these we look thin)

> **STATUS (2026-08-01):** ✅ #1 Agent-Skills (`engine/skills.mjs`), ✅ #2 Fireteam-generalized (`specialistsFor`), ✅ #3 Deep-Think (`engine/deepthink.mjs`), ✅ #4 productivity-ladder + axis-lock-in (`auditor.mjs`), ✅ **#5 auto-remediation** (`engine/remediate.mjs` — triage + governed code-fix→PR; `GET /api/triage`, `POST /api/remediate`), ✅ #6 (partial) streaming move-cards. **Also done:** footprint-reducer (always-on deterministic `opsec.reduction` + bounded event-driven AI `engine/footprint-ai.mjs`), Adversarial-AI-Recon (`tools/ai-recon.mjs`). **Remaining:** #7 tool-confirm Modify-args (needs interactive enclave-hook broker), #6 wave/LATS/fireteam UI panels, AI-Gauntlet (boundary), recon-toolchain breadth (build OUR native tools, not industry wrappers). ✅ **Operational stealth suite** (enforced executor + noise budget + `/api/stealth`) — see the dedicated section above. **237 tests green.**

1. **Agent Skills system** — built-in exploitation *playbooks* (CVE/SQLi/XSS/SSRF/RCE/LFI/
   brute/phish/DoS) as prompt-injected guidance keyed by an Intent Router, **+ user-defined
   markdown skills** with startup discovery + per-project toggles. (Playbooks/orchestration,
   not new exploit code — in-bounds.)
2. **Fireteam multi-agent parallelism** — fan-out to N bounded specialist sub-agents (caps,
   wave timeout, per-member HITL approval cards, attributed findings merged back). VARVEL has
   `engine/fireteam.mjs` for recon only — generalize it. Biggest architectural gap.
3. **Deep Think** — structured pre-step forcing ≥2 competing hypotheses + disambiguating probes
   at phase boundaries / unproductive streaks; cooldown + novelty rejection. (We have a lite
   version in the re-plan hint — make it a real node.)
4. **5-tier productivity ladder + axis lock-in** — extend our stuck counter to green→critical
   tiers over 5 signals, and add axis-lock-in (collapse "same dial, different payload" loops).
   Our area to *beat* — make it richer than theirs.
5. **CypherFix-equivalent auto-remediation** — triage agent (dedup/rank findings) → code-fix
   agent (clone repo, code-aware edits, sandboxed tests, **open a GitHub PR**). Closes the loop.
6. **Rich agent-activity console cards** — thinking / tool (streaming output+analysis) / wave /
   LATS tree (node glyphs) / fireteam member panels + inline approvals. *Started* — the chat now
   streams thinking/tool/result cards; extend to wave + LATS + fireteam panels.
7. **Tool-confirmation gate: Allow / Deny / Modify-args** (single + parallel-wave + per-member).
   We have HITL-over-HTTP — add Modify-args.

## P1 — strong differentiators (expected of a serious competitor)

- **Recon breadth** — build OUR OWN native tools (Jack's directive: NOT industry wrappers like
  subfinder/nuclei/ffuf). We have 9 native tools (recon/webscan/dns/tls/http-methods/ai-recon/
  apisurface/crawl/vulncheck); the full roadmap + quality bar lives in `docs/TOOL-PLAN.md` —
  each faster + governed + stealth-aware (they honor the pacer) by construction.
  Quality-over-count: a few excellent native tools beat 40 shell-outs.
  ✅ apisurface (robots/sitemap/OpenAPI/GraphQL/HTML+JS mining) + ✅ crawl (native BFS
  link/form crawler — the Katana/Hakrawler job) + ✅ vulncheck (curated content-verified
  vuln-check engine — the Nuclei slot: exposure probes, header/cookie/CORS audits, body-leak
  patterns; every finding confirmed) — all wired into campaign tooledRecon.
- **Adversarial AI Recon** — AI-infra fingerprinting (ai_* graph tags, ports 11434/6333/7860,
  ~65 SDK packages, MCP handshake). Fresh differentiator; fits Enclave's brand.
- **AI Gauntlet** — LLM red-teaming (garak/PyRIT/Giskard/promptfoo, Attack-Success-Rate,
  zero-egress local judge, OWASP-LLM + MITRE-ATLAS).
- **TrafficMind proxy** — MITM capture + Burp-style table + `proxy_replay`/`proxy_fuzz` tools.
- **Workspace filesystem (24 fs tools) + background jobs (5 tools)** — for long real engagements.
- **Multi-provider backends** — beyond Claude-CLI: OpenAI/OpenRouter/Bedrock/Ollama, dynamic
  model list + reasoning-effort (ties to the Kimi K3 work).
- Also: **MCP plugin system**, **Knowledge-Base RAG** (MITRE/OWASP/KEV), **RoE doc upload →
  auto-config**, **untrusted-output nonce sentinels** (prompt-injection defense), **guidance/
  steering + stop/resume checkpointing**, **3D graph view**, **chat `/skill` reference library**,
  **wave (parallel-tool) execution**, **HackLab-style CTF auto-grader** on the vm-range.

## P2 — defer (niche/heavy/partially covered)

GVM/OpenVAS, WPScan, secret hunters, subdomain-takeover / vhost / web-cache-poison / GraphQL
scanners, Tradecraft Lookup, PTY terminal, 19-preset data tables, 30+ chart Insights dashboard,
500+ param settings engine, multi-tenancy roles, ZIP export/import, hardened single-host deploy.

## Boundary note

RedAmon ships weaponized offensive internals (Metasploit/Hydra drivers, reverse shells, exploit
skills). VARVEL's line holds: **orchestrate** existing authorized tools + build recon/enum/vuln-
check + the reasoning/UI/governance layers; do **not** reimplement exploit payloads, C2/implants,
or evasion. The P0 list is almost entirely reasoning/orchestration/UI (in-bounds); offensive
*breadth* is achieved by driving existing tools under governance, not rebuilding them.

## RedAmon's six marketed pillars (for reference)
Parallel Recon Pipeline · AI Agent Orchestrator · Attack Surface Graph · EvoGraph cross-session
memory · CypherFix remediation · 500+ parameter Project Settings Engine.
