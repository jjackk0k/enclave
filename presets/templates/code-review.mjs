// Preset: Secure Code Review
export default {
  id: 'code-review',
  title: 'Secure Code Review',
  workload: 'secure-code-review',
  requires: { clearance: 2, anyCert: null },
  egress: { default: 'deny', allow: ['api.anthropic.com', 'case-ledger.internal'] },
  tools: ['semgrep', 'codeql', 'git', 'ripgrep', 'trivy'],
  params: [
    { key: 'project',  prompt: 'Project / repository under review', required: true },
    { key: 'reviewer', prompt: 'Lead reviewer (name)', required: true },
    { key: 'language', prompt: 'Primary language / stack', default: 'polyglot' },
    { key: 'trigger',  prompt: 'Why now (release / PR / audit)', default: 'scheduled review' },
  ],
  docs: {
    'REVIEW-SCOPE.md':
`# Review Scope — {{project}}

**Lead reviewer:** {{reviewer}}
**Stack:** {{language}}
**Trigger:** {{trigger}}
**Generated:** {{date}}

## In scope
- Source of {{project}} (cloned read-only into this sealed enclave).
- Dependencies and build/config as they affect security.

## Out of scope
- Anything requiring egress: the source never leaves the enclave. The only network
  reachable is the Claude API + case-ledger; there is no other route out.

## Goals
- Find and rank exploitable defects; propose concrete fixes.
- Produce evidence an auditor accepts (findings mapped to code + CWE).
`,
    'THREAT-MODEL.md':
`# Threat Model (starter) — {{project}}

Fill as you learn the system. Keep it short and real.

## Assets
- What is worth stealing / breaking in {{project}}?

## Entry points / trust boundaries
- Where does untrusted input enter? Where do privilege levels change?

## Top risks to check first
- [ ] Injection (SQL / command / template)
- [ ] AuthZ gaps / IDOR / missing access checks
- [ ] Secrets in source or logs
- [ ] Unsafe deserialization
- [ ] Vulnerable / outdated dependencies
`,
    'REVIEW-CHECKLIST.md':
`# Review Checklist — {{project}}

- [ ] Map the entry points and trust boundaries (THREAT-MODEL.md).
- [ ] Grep for dangerous sinks (exec, eval, raw SQL, deserialization).
- [ ] Check authentication and authorization on every privileged path.
- [ ] Scan dependencies for known CVEs.
- [ ] Review secrets handling (none in source, none in logs).
- [ ] Record each finding in FINDINGS.md with file:line + suggested fix.
`,
    'FINDINGS.md':
`# Findings — {{project}} ({{date}})

| # | Severity | Title | file:line | CWE | Fix proposed |
|---|----------|-------|-----------|-----|--------------|
| 1 |          |       |           |     |              |
`,
  },
};
