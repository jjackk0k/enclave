// Preset: Red Team Engagement
export default {
  id: 'red-team',
  title: 'Red Team Engagement',
  workload: 'red-team-ops',
  requires: { clearance: 4, anyCert: ['OSCP', 'OSEP', 'CRTO', 'GPEN', 'GXPN'] },
  egress: { default: 'deny', allow: ['api.anthropic.com', 'case-ledger.internal'], scoped: true },
  // Curated best-in-class shelf (see /tool-shelf.mjs for gate tiers T0/T1/T2).
  tools: ['projectdiscovery (subfinder/httpx/naabu)', 'nmap', 'nuclei', 'burpsuite', 'metasploit', 'sliver', 'netexec', 'impacket', 'bloodhound-ce', 'responder', 'hashcat'],
  params: [
    { key: 'client', prompt: 'Client / target organisation', required: true },
    { key: 'scope',  prompt: 'Authorised target scope — CIDRs, comma-separated', required: true },
    { key: 'lead',   prompt: 'Engagement lead (name)', required: true },
    { key: 'window', prompt: 'Engagement window', default: 'two weeks from kickoff' },
    { key: 'poc',    prompt: 'Client point-of-contact for deconfliction', default: 'TBD' },
  ],
  docs: {
    'RULES-OF-ENGAGEMENT.md':
`# Rules of Engagement — {{name}}

**Client:** {{client}}
**Engagement lead:** {{lead}}
**Window:** {{window}}
**Deconfliction contact:** {{poc}}
**Generated:** {{date}}

## 1. Authorisation
Testing is authorised by {{client}} against the in-scope assets below, for the
stated window only. This document is the operator's authority to act; anything
outside it is prohibited and will be blocked by the platform.

## 2. Scope
- **In scope (authorised targets):** {{scope}}
- **Out of scope:** every address, host, and service not listed above. The Enclave
  egress firewall drops off-scope traffic and alerts — enforced, not advisory.

## 3. Rules
- No denial-of-service or destructive payloads against production without written sign-off.
- Client data encountered is handled under the data-handling rules and never leaves the enclave.
- High-risk / exploit actions require a human approval step (recorded in the ledger).
- All traffic egresses from the pre-agreed static source IP for deconfliction.

## 4. Emergency / stop conditions
If instability or an unexpected system is observed, pause and notify {{poc}} before continuing.

## 5. Sign-off
- Client authoriser: ____________________  Date: __________
- {{lead}} (engagement lead): ____________  Date: __________
`,
    'ENGAGEMENT-SCOPE.json':
`{
  "engagement": "{{name}}",
  "client": "{{client}}",
  "window": "{{window}}",
  "scope": {{scopeJsonArray}},
  "signed": false,
  "_note": "In production the session broker SIGNS this scope; the enforcement seam reads the signed CIDRs to gate offensive actions (see poc/enforcement-seam). Off-scope targets are denied server-side."
}
`,
    'FINDINGS-REGISTER.md':
`# Findings Register — {{client}} ({{name}})

Log each finding as you go. Every entry is also written to the immutable case ledger.

| # | Severity | Title | Asset (in-scope) | Status | Evidence ref |
|---|----------|-------|------------------|--------|--------------|
| 1 |          |       |                  | open   |              |

## Notes
- Severity: Critical / High / Medium / Low / Info.
- "Asset" must be within scope ({{scope}}); off-scope activity should never appear here.
`,
    'README.md':
`# {{name}} — Red Team Engagement

Ready-to-work enclave for **{{client}}**, scaffolded {{date}}.

- **Authority:** see RULES-OF-ENGAGEMENT.md (fill the sign-off lines before kickoff).
- **Scope:** {{scope}} — enforced by the egress firewall + policy engine.
- **Requires:** clearance L4 and an offensive certification (OSCP / OSEP / CRTO / …).
- Start with recon inside scope; log findings in FINDINGS-REGISTER.md.
`,
  },
};
