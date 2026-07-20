# Enclave

[![CI](https://github.com/jjackk0k/enclave/actions/workflows/ci.yml/badge.svg)](https://github.com/jjackk0k/enclave/actions/workflows/ci.yml)

**The secure workspace where security teams put AI to work.**

Enclave is a hardened sandbox and professional console where security professionals — red teams, AppSec, IR, SOC, GRC — collaborate with Claude on real, sensitive systems inside per-session isolation, with every action scoped to their role, clearance, and license, and written to an immutable audit trail.

> **Why it exists:** the people who'd benefit most from AI are the ones who legally and practically *can't* paste their work into a public chatbot — breach data, exploits, proprietary source. Enclave gives them the AI leverage **and** the containment.

## 🔗 Live demo

Marketing site + interactive console (GitHub Pages): **https://jjackk0k.github.io/enclave/**

- `index.html` — landing site
- `app.html` — the console (mock SSO → chat + profile + live sandbox panel). Pick a persona, try the **"triage the pcap"** and **"test the guardrails"** prompts.

## Focus areas

Enclave leads with two workloads that share one hardened backend:

| Workload | Best for | Why it fits |
|---|---|---|
| **Secure code review** | AppSec teams, regulated software (fintech / health / defense), pre-release audits | The sensitive asset is *source/IP*; the work is *analysis* — where Claude is already strongest. Near-zero egress. The clean "land" product. |
| **Red team ops** | Offensive-security teams, pentest firms, purple teaming | Active, tooling-driven work needing *scoped authorization*, *strong containment*, and *defensible audit*. The differentiator that proves the isolation moat — the "expand" product. |

## Security model (the important part)

The pretty UI is *just the door*. Real security lives in the backend, in layers, and **authorization is enforced below the model, never by it**:

- A user's clearance/profile **informs** the AI (what to surface, how to phrase) — it **never authorizes** it.
- Every privileged action is checked **server-side** against a signed identity, so no prompt (including prompt injection) can escalate its own permissions.
- Per-session disposable isolation · deny-all egress firewall · hashed, immutable audit ledger.

The full backend design lives in [`docs/security-architecture.md`](docs/security-architecture.md).

## Run locally

No build step — the pages are self-contained (inline CSS/JS). Just open `index.html` in a browser, or serve the folder:

```bash
python -m http.server 8080   # then visit http://localhost:8080
```

## Run the proofs

The backend isn't just a diagram — the core mechanisms run today. From the repo root:

```bash
npm test        # runs every self-checking proof and reports green/red
```

Or run each on its own:

| Proof | What it verifies |
|---|---|
| [`poc/enforcement-seam`](poc/enforcement-seam) | `npm install && npm run demo` — 20 scenarios: clearance **and** qualification enforced by real [Cedar](https://www.cedarpolicy.com/), outside the model, against a signed identity (incl. prompt-injection, confused-deputy, forged-token, and an all-access lead). |
| [`poc/isolation`](poc/isolation) | `npm run demo` — provision → PEP-gated exec → isolated run → teardown → audit, across process / Docker / Firecracker tiers. |
| [`poc/egress-broker`](poc/egress-broker) | `npm run demo` — deny-all egress + the Anthropic key injected *outside* the sandbox (BYO-key that never enters it). |
| [`presets`](presets) | `node scaffold.mjs --list` — scaffold a governed, pre-filled workspace from a preset. |
| [`poc/persona-work`](poc/persona-work) | `npm run demo` — the AI produces a role- and clearance-appropriate deliverable per persona (offline, or `--live` with a key). |
| [`poc/full-stack`](poc/full-stack) | `npm run demo` *(Docker)* — an isolated sandbox with no internet whose only egress is the key-injecting broker: no data leaves, the key never enters. |
| [`poc/tool-forge`](poc/tool-forge) | `npm run demo` *(Docker)* — build a security tool for **Linux and Windows** inside a sealed, no-network container (the tool-dev workload). |

## Run the console (live AI)

```bash
ANTHROPIC_API_KEY=sk-ant-…  npm run console     # then open http://localhost:8977
```

`server.mjs` serves the console on localhost **and** acts as the egress broker for the chat: the browser sends messages with **no key**; the server injects the Anthropic key and calls Claude, so the key never reaches the browser (the same pattern as [`poc/egress-broker`](poc/egress-broker), wired to the real UI). The AI is given the operator's read-only persona context, so it tailors replies to their role and clearance. Without a key set, the console loads in its scripted demo mode.

## Status

Early-stage prototype. The current build demonstrates the **product experience and identity model**. "Micro-VM isolation," "egress firewall," and "immutable ledger" describe the target architecture (see the design doc) — the hardened backend is the next build.

---

© 2026 — all rights reserved. Enclave is an independent concept and is not affiliated with or endorsed by Anthropic. "Claude" and "Claude Code" are products of Anthropic.
