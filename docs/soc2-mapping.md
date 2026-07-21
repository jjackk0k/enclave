# Enclave — SOC 2 control mapping

> **Status:** Draft v0.1 · 2026-07-20 · for design-partner / auditor conversations
> **Scope:** the **Security** category (Common Criteria, TSC 2017). This maps Enclave's *product* controls to the criteria and points to **evidence that runs** (`npm test`). It is **not** a claim of SOC 2 certification — that requires an audit period, an org-level program, and an auditor's opinion.

## How to read this

SOC 2 is satisfied by a **shared** set of controls. Some criteria are **product-provided** (Enclave enforces them technically), some are **shared**, and many (CC1–CC5 governance, HR, vendor management) are **organizational** — the customer/operator company must run that program regardless of tooling. This table is honest about which is which, so an auditor knows exactly what Enclave contributes.

## Common Criteria → Enclave control → evidence

| Criterion | Requirement (paraphrased) | Enclave control | Ownership | Evidence |
|---|---|---|---|---|
| **CC5.1–CC5.2** | Control activities that mitigate risk | The **PDP/PEP reference monitor** — a deterministic, formally-analyzable Cedar policy decision on every action | Product | [`poc/enforcement-seam`](../poc/enforcement-seam) |
| **CC6.1** | Logical access security; least privilege; encryption | SSO/OIDC identity; **SD-JWT** clearances; **Cedar** authz; TLS/egress encryption; secrets in a broker | Product | [`poc/identity`](../poc/identity), `poc/enforcement-seam`, [`poc/egress-broker`](../poc/egress-broker) |
| **CC6.2** | Users registered & authorized before access | Identity comes from the **signed IdP assertion** — no self-declared clearance | Product | `poc/identity` (SD-JWT/SVID rejected if unsigned) |
| **CC6.3** | Role-based access, least privilege, segregation of duties | Clearance **+ qualification + workspace scope**; HITL approval for high-risk; separation enforced server-side | Product | `poc/enforcement-seam` (20 scenarios incl. cross-workspace, role gates) |
| **CC6.6** | Boundary protection from external threats | Per-session **micro-VM isolation**; **default-deny egress** | Product | [`poc/isolation`](../poc/isolation) (`--network none`), `poc/egress-broker` |
| **CC6.7** | Restrict movement/transmission of information | Code-review path has **no NIC**; DLP on the only exit; API key **never enters the sandbox** | Product | [`poc/full-stack`](../poc/full-stack), `poc/egress-broker` |
| **CC6.8** | Prevent/detect unauthorized software | **Deny-by-default** tool policy; curated, gated tool shelf; PreToolUse interception | Product | `poc/enforcement-seam`, [`tool-shelf.mjs`](../tool-shelf.mjs) |
| **CC7.2** | Monitor for anomalies / security events | Every prompt, tool call, decision, file touch logged; egress flow logging | Product | [`poc/audit-anchor`](../poc/audit-anchor) |
| **CC7.3** | Evaluate security events; produce evidence | **Immutable, externally-anchored** audit ledger; exportable signed evidence bundle | Product | `poc/audit-anchor` (Merkle + signed root) |
| **CC7.4–CC7.5** | Respond to & recover from incidents | Session teardown wipes; ephemeral by design; secret revocation; key kill-switch | Shared | `poc/isolation` (teardown), architecture §8 |
| **CC8.1** | Authorized change management | Policies are versioned (`policy_version` in the ledger); **CI verifies every change** on real Docker | Shared | [CI](../.github/workflows/ci.yml), `poc/enforcement-seam` |
| **CC1–CC4, CC9** | Governance, comms, risk assessment, vendor mgmt | Policies, org structure, risk register, HR screening, vendor reviews | **Organizational** | Customer's program (Enclave supplies audit evidence into it) |

## Two most-tested areas

CC6 (access) and CC7 (monitoring) are where SOC 2 reports most often take exceptions. Enclave front-loads exactly those: access is a **formally-analyzable PDP that provably can't be self-escalated**, and monitoring is an **externally-verifiable immutable ledger**. That's a strong story to walk an auditor through — and it's all running.

## ISO 27001:2022 crosswalk (build once, certify twice)

~70% control overlap. Key Annex A mappings: **A.5.15/A.8.2–A.8.5** (access) ← CC6.1–6.3; **A.8.20/A.8.22/A.8.23** (network/segregation/web-filtering) ← CC6.6–6.7; **A.8.15/A.8.16** (logging/monitoring) ← CC7.2–7.3; **A.8.24** (cryptography) ← CC6.1; **A.8.31** (separation of environments) ← per-session isolation; **A.8.32** (change management) ← CC8.1. Full detail in [`security-architecture.md`](security-architecture.md) §12.

## What the customer org still owns

To actually achieve SOC 2, the operating company needs (beyond Enclave): documented security policies, a risk assessment process, HR/onboarding controls, vendor management, a defined incident-response plan, and a monitoring/on-call program. Enclave's role is to make the **access-control and audit-evidence** parts technically airtight and to emit auditor-ready evidence — not to be the whole program.
