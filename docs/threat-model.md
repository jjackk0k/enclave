# Enclave — Threat Model

> **Status:** Draft v0.1 · 2026-07-20 · for design-partner / security review
> **Method:** asset- and adversary-driven, STRIDE-informed. Every mitigation below maps to a **runnable proof** in this repo (`npm test` runs them all), so no claimed defense is unverified.

## Scope

In scope: the Enclave platform — the console, the per-session sandbox, the identity/authorization/egress/secrets/audit control plane, and the AI (Claude) running inside a session. Out of scope: the security of Anthropic's API itself, the customer's own SSO/IdP internals, physical datacenter security, and (v1) a determined *authorized* malicious operator acting within their granted permissions (an HR/legal control — though the audit trail deters and evidences it).

## Assets

| Asset | Why it matters |
|---|---|
| Customer source code / evidence / engagement data | The sensitive material the operator brings in; primary confidentiality target |
| The Anthropic API key (and any customer secrets) | Theft = billing abuse + a foothold |
| The audit ledger | Integrity of the record auditors and incident responders rely on |
| Cross-tenant isolation | One customer must never reach another |
| Operator identity + clearance/qualification | The basis for every authorization decision |

## Adversaries

- **A1 — Injected/hijacked AI.** The model reads untrusted content (code, a target's HTTP responses, a pcap) and is steered by prompt injection. Treated as *potentially adversarial to its own operator*.
- **A2 — Malicious tool / code in the sandbox.** Offensive tooling or code-under-review tries to escape to the host or another tenant.
- **A3 — External network attacker.** Tries to exfiltrate data or steal the key over the network.
- **A4 — Credential thief.** Captures a token/session and replays it.
- **A5 — Insider with infrastructure access.** Tries to rewrite history in the audit ledger.
- **A6 — Under-privileged operator.** A real, authenticated user attempting actions beyond their clearance/qualification/scope.

## Threats → controls → proof

| # | Threat (STRIDE) | Adversary | Control | Runnable proof |
|---|---|---|---|---|
| T1 | Model talks itself into a privileged action *(Elevation)* | A1, A6 | Authorization decided **outside the model** by a Cedar reference monitor, keyed to the **signed** identity — not model output | [`poc/enforcement-seam`](../poc/enforcement-seam) (prompt-injection scenario denied) |
| T2 | Clearance without the right qualification *(Elevation)* | A6 | Two-axis gate: clearance **and** certification, both required for T2/offensive actions | `poc/enforcement-seam` (L4 red-teamer denied infra; L4 platform eng denied offensive) |
| T3 | Confused deputy across workspaces *(Elevation)* | A6 | Workspace-scoped authz (`resource.workspace == principal.workspace`) | `poc/enforcement-seam` (cross-workspace denied) |
| T4 | Forged / replayed identity *(Spoofing)* | A4 | Signed sessions; **SD-JWT** clearances (key-bound), **DPoP** sender-constrained tokens, **SPIFFE** workload identity | [`poc/identity`](../poc/identity) (forged SVID, replay, wrong-key all rejected) |
| T5 | Data exfiltration *(Information disclosure)* | A1, A3 | Default-deny egress; code-review path has **no NIC** (vsock→proxy); off-allowlist blocked; DLP on the exit | [`poc/egress-broker`](../poc/egress-broker), [`poc/isolation`](../poc/isolation) (ENETUNREACH), [`poc/full-stack`](../poc/full-stack) |
| T6 | API-key / secret theft *(Information disclosure)* | A1, A3 | Key lives in the broker; injected on the outbound hop; **never enters the sandbox or model context**; smuggled keys stripped | `poc/egress-broker`, `poc/full-stack` |
| T7 | Host / cross-tenant escape *(Elevation)* | A2 | Hardware-isolated micro-VM per session + jailer + inner hardened container; ephemeral, destroyed on teardown | `poc/isolation` (container tier: `--network none`, cap-drop, non-root, wiped) |
| T8 | Audit-log tampering *(Tampering, Repudiation)* | A5 | Hash-chained ledger + **Merkle root signed by an external authority**, published off-platform | [`poc/audit-anchor`](../poc/audit-anchor) (tamper + insider-forgery both provably caught) |
| T9 | Tool built here pointed off-scope *(Misuse)* | A6 | Building is gated (cert); **using** the tool stays gated at runtime (offensive cert + signed in-scope target) | `poc/enforcement-seam` + [`tool-shelf.mjs`](../tool-shelf.mjs) gate tiers |

## The load-bearing property

Everything rests on one architectural choice: **the model is least-privileged and the authorization decision lives below it.** The AI is given identity/clearance as *read-only context so it can tailor help* ([`poc/persona-work`](../poc/persona-work)), but a **Policy Enforcement Point intercepts every tool call and defers to a Cedar Policy Decision Point** (in-process or networked, [`poc/enforcement-seam/pdp-server.mjs`](../poc/enforcement-seam/pdp-server.mjs)) that reads the *cryptographically bound* identity. No prompt, however worded, is an input to that decision. This is why T1 (prompt injection) fails closed.

## Residual risks & assumptions

- **Red-team raw-egress path can't be content-inspected** like the code-review path (offensive tools need raw sockets). Compensated by L3/L4 CIDR scope + static egress IP + volumetric caps + full flow logging + short scope leases — *not* equivalent to DLP. This is the highest-residual surface; it's why red team is a later, more-gated tier.
- **micro-VM depends on a hypervisor** (KVM). A hypervisor 0-day is out of scope for v1 (six-figure-bounty class); defense-in-depth (inner container) raises the bar.
- **Authorized-malicious operator** is deterred + evidenced by the anchored audit, not prevented.
- **DoS** is bounded by per-session resource caps (cpu/mem/pids) but not exhaustively addressed in v1.
- The PoCs prove the *mechanisms*; production hardening (WORM storage, TLS-terminating DLP, real SPIRE, HSM-backed keys) is the build on top — see [`security-architecture.md`](security-architecture.md).

## Continuous verification

Every mitigation above is exercised on every push: `node test-all.mjs` runs all eight proofs, and **CI runs them on real Docker** (container isolation + full-stack egress included). A regression that weakened any control would fail the build.
