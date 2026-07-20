# Enclave — Project Plan

> **Status:** Draft v0.1 · 2026-07-20 · planning estimate, not a commitment
> All costs and timelines are **rough, assumption-tagged ranges** for an early-stage build, and vary heavily with team geography and scale. Not financial advice.

**Strategy in one line:** land with **secure code review** (lower risk, near-zero egress, broad market), then **expand to red team ops** on the *same* hardened backend.

---

## Milestones

Each phase ends on an **exit criterion**, not a date — dates are targets assuming the team below is in place.

### Phase 0 — Prototype ✅ *(done)*
Product experience + identity model ([the console](../app.html)), the [security architecture](security-architecture.md), and a runnable [enforcement-seam PoC](../poc/enforcement-seam/) proving out-of-model authorization with real Cedar.
**Exit:** ✅ concept validated; the load-bearing security claim proven in code.

### Phase 1 — Code-review MVP + design-partner pilot  *(target ~4–6 months)*
The shippable "land" product. Build:
- **Isolation:** Firecracker microVM per session on a bare-metal/KVM host, jailer, golden-snapshot restore, ephemeral dm-crypt scratch disk, destroy-on-teardown.
- **Egress:** no-NIC + vsock → TLS-terminating egress proxy; allowlist = `api.anthropic.com` + case-ledger only.
- **Enforcement:** productionize the PoC — Cedar **PDP service** + `PreToolUse` **PEP**, deny-by-default **managed** settings.
- **Identity:** OIDC SSO (one IdP to start), short-lived tokens; profile carries role/clearance/license as **read-only** context to the model.
- **Secrets:** Vault; BYO Claude key injected at the egress proxy, never in the sandbox.
- **Audit:** hash-chained ledger → WORM object storage.
- **Product:** the existing console wired to the real backend; basic workspace lifecycle.

**Exit:** 2–3 design-partner security teams running *real* code reviews; isolation boundary survives an external pen-test; SOC 2 Type I readiness.

### Phase 2 — Hardened & certifiable  *(target ~+3–4 months)*
Merkle + external anchoring on the ledger; DLP on egress; SD-JWT clearances; SPIFFE/SPIRE workload identity; DPoP tokens; org-admin console + RBAC; multi-IdP.
**Exit:** SOC 2 Type II window open; ISO 27001 gap assessment done; first *paid* customers.

### Phase 3 — Red-team expansion  *(target ~+3 months)*
Raw scoped egress + Cilium Egress Gateway + static egress IP; signed engagement-scope objects; HITL approval flow; flow logging + anomaly alerting; curated offensive tool shelf.
**Exit:** red-team design partners live on the same substrate.

| Phase | Focus | Target window | Gate to next |
|---|---|---|---|
| 0 | Prototype | — | ✅ done |
| 1 | Code-review MVP | ~months 0–6 | Design partners live + pen-test passed |
| 2 | Harden + certify | ~months 6–10 | SOC 2 Type II open + paid customers |
| 3 | Red-team expand | ~months 10–13 | Red-team partners live |

---

## Rough infra costs

**Assumptions:** single cloud region · pilot scale (≤ ~50 concurrent sessions) · self-hosted OSS where sensible · BYO-key model (customers bring their Anthropic key, so model spend isn't Enclave's line).

| Component | Choice | Rough monthly (pilot) | Notes |
|---|---|---|---|
| **Compute — Firecracker hosts** | 2–3 bare-metal / nested-virt instances (`.metal` or C8i/M8i) | **$1,500–4,000** | The dominant line. KVM requires bare-metal or the newer nested-virt families. microVM density keeps *per-session* cost low. |
| Object storage (WORM audit) | S3 Object Lock (compliance mode) | $50–150 | Cheap at pilot log volume. |
| Secrets | Vault (self-host) or HCP Vault | $150–300 | Small HA cluster. |
| Networking / egress | Cilium (OSS) + gateway/NAT + static IPs | $100–300 | Cilium is free; you pay for gateway nodes + elastic IPs. |
| Identity | Keycloak (self-host) or Auth0/Okta | $50–150 | Keycloak ~1 small instance; hosted IdPs ~free at pilot seats. |
| Observability / logging | Managed or self-host (Grafana/Loki) | $100–300 | |
| CI / registry / backups | — | $100–200 | |
| **Anthropic API** | Pass-through / BYO | **$0 to Enclave** (BYO) | If Enclave fronts model spend later, it's usage-based and re-billed. |
| **Pilot infra total** | | **~$2.5k–8k / month** | Dominated by bare-metal compute; scales with concurrent sessions. |

One-off / annual: SOC 2 tooling + audit ~**$15–50k/yr** (Type I then Type II); a boundary pen-test ~**$10–30k** per engagement.

---

## Phase-1 team

Minimum viable team to ship the code-review MVP:

| Role | Count | What they own | Notes |
|---|---|---|---|
| **Systems / virtualization engineer** | 1 | Firecracker, jailer, snapshot/restore, orchestration, egress fabric | **The critical hire & scarcest skill** — the whole isolation story rides on this. |
| **Backend / platform engineer** | 1 | Cedar PDP/PEP, session broker, Vault, audit pipeline, API | Productionizes the PoC. |
| **Full-stack / product engineer** | 1 | Console, workspace lifecycle, admin | Founder may partly cover this. |
| **Security / compliance lead** | 0.5 | Threat model, SOC 2 program, pen-test coordination | Fractional/advisor early is fine. |
| **Founder (you)** | — | Product, GTM, design-partner relationships | |

**Rough fully-loaded eng burn:** ~3 engineers × ~$150–220k (US senior) ≈ **$0.5–0.7M/yr**, materially lower outside high-cost hubs, plus fractional security. Leaner path: 2 exceptional systems+backend engineers if the founder covers product/frontend.

---

## Critical path, risks & hiring order

- **Critical path = the systems/virtualization hire.** Everything else parallelizes; the isolation layer is the long pole and the hardest to staff.
- **Bare-metal / KVM capacity** has procurement lead time — line it up early.
- **Design partners committed early** are worth more than features: they validate the wedge and supply real code to test the isolation against. Get 1–2 letters of intent before Phase 1 finishes.
- **The red-team raw-egress path** (Phase 3) is the riskiest surface — deliberately sequenced last, after the hardened base and compliance are proven.

**Hire in this order:** (1) systems/virtualization → (2) backend/platform → (3) fractional security/compliance → (4) second product/frontend post-pilot.

---

## Funding context *(informational, not advice)*

Getting to a Phase-1 pilot is a typical **seed-stage** effort: on the order of **~$1–1.5M** covers ~12 months of a 3-engineer team + pilot infra + fractional security + SOC 2 costs. Treat this as a planning benchmark to pressure-test, not a recommendation.
