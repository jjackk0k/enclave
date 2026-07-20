// templates.mjs — the offline persona-aware generator. Given who the operator is
// (role, clearance, certs, workspace, engagement scope) it produces a deliverable
// BEFITTING that persona: a junior SOC analyst gets a triage note that escalates
// what's above their clearance; a red-team lead gets an in-scope recon plan; etc.
// This is the deterministic stand-in used when no live model key is set — the same
// persona context also drives the live Claude path (live.mjs).

function header(who, session) {
  return `> **Operator:** ${who.name || session.principal} · ${who.role} · clearance L${who.clearance}` +
    `${who.licenses ? ` · ${who.licenses.join(', ')}` : ''}\n` +
    `> **Workspace:** ${session.workspace} · sealed enclave · egress deny-all · audit on`;
}

function authzSection(caps) {
  return `## Scoped to your authorization\n` +
    `- **You may:** ${caps.permitted.join('; ')}.\n` +
    `- **Beyond your remit (escalate / get approval):** ${caps.escalate.join('; ')}.`;
}

function footer(who) {
  return `---\n*Tailored to a ${who.role} at clearance L${who.clearance}. This deliverable stays within ` +
    `your remit; anything above it is flagged for escalation, and every action you take from here is checked ` +
    `server-side against your signed identity.*`;
}

const ROLE = {
  'SOC-Analyst': (who) => ({
    title: 'Alert Triage Note',
    filename: 'ALERT-TRIAGE-NOTE.md',
    body:
`## Alert
Suspicious interactive logon on a workstation outside business hours (flagged by the SIEM).

## Tier-1 triage (read-only — within your access)
1. Confirm the user/asset and whether the logon time fits their pattern.
2. Check source IP reputation and recent auth history for the account.
3. Look for immediate siblings: repeated failures, new-country logon, MFA prompts.

## Verdict & handoff
- If benign (known travel / expected admin task): close with a ticket note.
- If suspicious: **do not attempt containment or forensic capture — that needs L3.**
  Raise an incident and hand to IR with the timeline you've gathered.`,
  }),

  'IR-Analyst': (who) => ({
    title: 'Incident Response Action Plan',
    filename: 'IR-ACTION-PLAN.md',
    body:
`## Working hypothesis
Hands-on-keyboard intrusion with attempted lateral movement from a compromised workstation.

## Indicators to pin down
| Type | What to confirm |
|------|-----------------|
| Host | patient-zero + any hosts it touched |
| Account | credentials used / possibly stolen |
| Persistence | new services, scheduled tasks, run keys |
| C2 | beacon destination + cadence |

## Containment sequence (within your L3 remit)
1. Network-isolate the affected host (quarantine VLAN).
2. Snapshot memory + disk **before** any change (chain of custody).
3. Disable observed persistence; kill the beacon process.
4. Rotate credentials seen in use; hunt the IOC across the fleet.

Log every step to the case timeline; evidence stays in the enclave.`,
  }),

  'Red-Team-Lead': (who, session) => ({
    title: 'Engagement Recon Plan',
    filename: 'RECON-PLAN.md',
    body:
`## Scope (enforced)
Authorized targets only: **${session.engagementScope || 'per signed Rules of Engagement'}**. Off-scope traffic is dropped by the egress firewall and alerted — stay inside it.

## Phased approach
1. **Passive** — OSINT + DNS/cert enumeration of in-scope ranges. No packets to targets yet.
2. **Active recon** — service/version enumeration across the authorized CIDRs (you hold the offensive cert this requires).
3. **Targeted exploitation** — only against confirmed in-scope services; **each exploit needs the human-in-the-loop approval step**.
4. **Deconfliction** — all traffic egresses from the agreed static source IP; log everything for the blue team's timeline.

## Guardrails
No DoS, no destructive payloads against production without written sign-off. Findings go to the register as you confirm them.`,
  }),

  'GRC-Auditor': (who, session) => ({
    title: 'Audit Evidence Request',
    filename: 'EVIDENCE-REQUEST.md',
    body:
`## Objective
Collect evidence for the control areas below (read-only — no changes to audited systems).

| Control area | Evidence to gather |
|--------------|--------------------|
| Access control | SSO/MFA config, joiner-mover-leaver records, privileged-access list |
| Logging & monitoring | immutable audit-log samples, alerting runbooks |
| Change management | change tickets + approvals for the period |
| Encryption / secrets | key-management policy, secrets-handling standard |

## Method
Request each item with an owner and a date; record it in the evidence register with its source. Flag gaps as findings — do not remediate (that's outside audit's remit).`,
  }),

  'Platform-Engineer': (who) => ({
    title: 'Platform Hardening Plan',
    filename: 'HARDENING-PLAN.md',
    body:
`## Target
Bring the workspace's infrastructure to a least-privilege, deny-by-default baseline.

## Checklist
1. **Network** — default-deny egress; explicit allowlist per service; no public ingress without review.
2. **Identity** — workload identity (no static keys); short-lived, scoped credentials.
3. **Secrets** — none in source or images; broker/Vault-injected at runtime only.
4. **Images** — read-only rootfs, non-root user, dropped capabilities, pinned digests.
5. **IaC review** — diff the Terraform/K8s manifests for privilege escalations before apply.

You hold the platform certification these provisioning actions require; destructive infra changes are logged.`,
  }),

  'Security-Lead': (who) => ({
    title: 'Security Posture Brief (Executive)',
    filename: 'POSTURE-BRIEF.md',
    body:
`## Summary
Cross-domain read of the current posture, with the top priorities for the week.

## By domain
- **Incident response** — open cases, mean-time-to-contain trend, any active intrusions.
- **Offensive** — engagements in flight, high-severity findings awaiting remediation.
- **AppSec** — code-review backlog, exploitable defects shipped vs. fixed.
- **Compliance** — SOC 2 / ISO control gaps and audit readiness.

## Priorities
1. Resource the highest-severity open finding to closure.
2. Confirm every in-flight engagement is inside its signed scope.
3. Clear the credential-rotation and approval queue.

As a lead you can direct any of the above; approvals and privileged actions are still recorded against your identity.`,
  }),

  default: (who) => ({
    title: 'Workspace Briefing',
    filename: 'BRIEFING.md',
    body: `## Getting started\nA short, role-appropriate plan for your workspace. (No specialized template for role "${who.role}" yet.)`,
  }),
};

export function generate({ who, session, caps, task }) {
  const g = (ROLE[who.role] || ROLE.default)(who, session, task);
  const markdown =
`# ${g.title}

${header(who, session)}

${g.body}

${authzSection(caps)}

${footer(who)}
`;
  return { title: g.title, filename: g.filename, markdown };
}
