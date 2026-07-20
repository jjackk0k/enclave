# PoC — the AI makes something befitting the persona

Same task, six operators, six different deliverables. This is the payoff of "clearance **informs** the AI" (the other half of "never **authorizes**"): the Enclave AI tailors *what it produces* to who the operator is — their role, clearance, certifications, and engagement scope — and stays inside their remit.

## Run it

```bash
npm run demo                                   # all six personas, offline
node generate.mjs --persona marcus             # one persona
node generate.mjs --persona dana --task "plan containment for the FS-02 host"
ANTHROPIC_API_KEY=…  node generate.mjs --persona dana --live   # a real Claude call
```

What each persona gets from the *same* prompt:

| Operator | | Deliverable |
|---|---|---|
| Sam Reeve | L1 SOC-Analyst | **Alert Triage Note** — read-only checks, then *escalates* containment/forensics ("needs L3") |
| Dana Okoye | L3 IR-Analyst | **Incident Response Action Plan** — hypothesis, IOCs, containment within her remit |
| Marcus Vale | L4 Red-Team-Lead | **Engagement Recon Plan** — phased, *in-scope only*, exploits gated on approval |
| Priya Nair | L2 GRC-Auditor | **Audit Evidence Request** — controls to test, read-only, no remediation |
| Ravi Shah | L4 Platform-Engineer | **Platform Hardening Plan** — least-privilege infra checklist |
| Alex Chen | L5 Security-Lead | **Executive Security Posture Brief** — cross-domain, nothing beyond remit |

The L1 note ends with, verbatim: *"do not attempt containment or forensic capture — that needs L3."* The AI knows what the operator may do, and writes to it.

## How it works

- The deliverable is generated from the operator's **read-only context** — the exact block built by [`../enforcement-seam/session-context.mjs`](../enforcement-seam/session-context.mjs) (role, clearance, certs, scope, and a policy-derived "you may / beyond your remit" list). That's the *same* context the live model receives, so the offline generator and a live Claude call tailor to identical facts.
- It's driven off the **signed session** and fails closed on a bad one — the AI is never told a clearance that wasn't cryptographically bound.
- **Live path:** with `ANTHROPIC_API_KEY` set and `--live`, the persona context becomes Claude's system prompt and the task is the user turn ([`live.mjs`](live.mjs)). In production that call egresses **through the broker** ([`../egress-broker`](../egress-broker)), which injects the key outside the sandbox — here it's a direct call for the standalone demo.

This closes the loop: the enforcement seam decides what an operator *may do*; this shows the AI *doing work shaped to exactly that*.
