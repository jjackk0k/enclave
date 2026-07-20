// Preset: GRC / Compliance Audit
export default {
  id: 'grc-audit',
  title: 'GRC / Compliance Audit',
  workload: 'grc-audit',
  requires: { clearance: 2, anyCert: ['CISA', 'CISSP', 'CRISC'] },
  egress: { default: 'deny', allow: ['api.anthropic.com', 'case-ledger.internal'] },
  tools: ['git', 'ripgrep', 'jq'],
  params: [
    { key: 'framework', prompt: 'Framework (SOC 2 / ISO 27001 / …)', default: 'SOC 2' },
    { key: 'period',    prompt: 'Audit period', required: true },
    { key: 'auditor',   prompt: 'Lead auditor (name)', required: true },
    { key: 'scope',     prompt: 'Systems / org units in scope', default: 'org-wide' },
  ],
  docs: {
    'EVIDENCE-REGISTER.md':
`# Evidence Register — {{framework}} ({{period}})

**Lead auditor:** {{auditor}}
**Scope:** {{scope}}
**Generated:** {{date}}

Read-only evidence collection. Nothing is modified; every access is logged.

| Ctrl ref | Control | Evidence collected | Source | Date | Result |
|----------|---------|--------------------|--------|------|--------|
|          |         |                    |        |      |        |
`,
    'CONTROL-MAPPING.md':
`# Control Mapping — {{framework}}

Starter map (aligned with the Enclave architecture's own control story).

| Area | {{framework}} ref | Evidence to gather |
|------|-------------------|--------------------|
| Access control | CC6.1–CC6.3 / A.5.15 | SSO, MFA, least-privilege records |
| Monitoring / logging | CC7.2–CC7.3 / A.8.15 | Immutable audit-log samples |
| Change management | CC8.1 / A.8.32 | Change records + approvals |
| Encryption / secrets | CC6.1 / A.8.24 | Key-management + secrets policy |
`,
    'README.md':
`# {{framework}} Audit — {{period}}

Read-only GRC enclave, opened {{date}} by {{auditor}}. Scope: {{scope}}.

- **Requires:** clearance L2 and an audit certification (CISA / CISSP / CRISC).
- Collect evidence in EVIDENCE-REGISTER.md; map controls in CONTROL-MAPPING.md.
- Read-only workload: no changes to audited systems, everything logged.
`,
  },
};
