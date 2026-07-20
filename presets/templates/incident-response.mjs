// Preset: Incident Response / Forensics
export default {
  id: 'incident-response',
  title: 'Incident Response / Forensics',
  workload: 'incident-response',
  requires: { clearance: 3, anyCert: ['GCIH', 'GCFA', 'GCFE', 'ECIH'] },
  egress: { default: 'deny', allow: ['api.anthropic.com', 'case-ledger.internal'] },
  tools: ['volatility', 'yara', 'sleuthkit', 'zeek', 'chainsaw'],
  params: [
    { key: 'case',     prompt: 'Case ID', required: true },
    { key: 'analyst',  prompt: 'Lead analyst (name)', required: true },
    { key: 'severity', prompt: 'Initial severity (SEV1-4)', default: 'SEV2' },
    { key: 'summary',  prompt: 'One-line incident summary', default: 'under triage' },
  ],
  docs: {
    'INCIDENT-TIMELINE.md':
`# Incident Timeline — {{case}}

**Lead analyst:** {{analyst}}
**Severity:** {{severity}}
**Summary:** {{summary}}
**Opened:** {{date}}

Record events in UTC, newest at the bottom. Every entry is also written to the immutable case ledger.

| Time (UTC) | Source | Observation | Action taken | Analyst |
|------------|--------|-------------|--------------|---------|
|            |        |             |              | {{analyst}} |
`,
    'CASE-NOTES.md':
`# Case Notes — {{case}}

**Working hypothesis:**
-

**Indicators of compromise (IOCs):**
| Type | Value | Source | Confidence |
|------|-------|--------|-----------|
|      |       |        |           |

**Scope of compromise (hosts / accounts / data):**
-

**Containment / eradication steps:**
- [ ] (destructive/containment actions require L3+ and are logged)
`,
    'CHAIN-OF-CUSTODY.md':
`# Chain of Custody — {{case}}

Every evidence item handled during this investigation. Evidence stays inside the
sealed enclave; export is a logged, approved action only.

| Item # | Description | Collected (UTC) | By | Hash (SHA-256) | Handoff |
|--------|-------------|-----------------|----|----------------|---------|
| E-001  |             |                 | {{analyst}} |     |         |
`,
    'README.md':
`# {{case}} — Incident Response

Sealed enclave for case **{{case}}** ({{severity}}), opened {{date}} by {{analyst}}.

- **Requires:** clearance L3 and an IR/forensics certification (GCIH / GCFA / …).
- Log everything in INCIDENT-TIMELINE.md; track evidence in CHAIN-OF-CUSTODY.md.
- Nothing leaves the enclave; containment actions are logged to the case ledger.
`,
  },
};
