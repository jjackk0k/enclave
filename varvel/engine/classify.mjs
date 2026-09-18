// VARVEL — finding classifier + remediation mapper (heuristic, orchestration-side).
// Maps a finding to OWASP Top 10 (2021), a MITRE ATT&CK tactic, and a concrete
// remediation. Keyword-based and deterministic; the live agent can override with
// richer analysis, but this guarantees every finding lands in a report with a
// standard mapping and a fix — matching RedAmon's OWASP/MITRE-mapped reporting.

import { riskLevel, sevRank } from './severity.mjs';

const RULES = [
  { re: /admin|unauth|access control|idor|privilege|authz|broken access/i, owasp: 'A01:2021 Broken Access Control', attack: 'TA0001 Initial Access', fix: 'Enforce server-side authorization on every sensitive route; deny by default.' },
  { re: /inject|sqli|\bsql\b|xxe|ssti|command exec|\brce\b|deserial/i, owasp: 'A03:2021 Injection', attack: 'TA0002 Execution', fix: 'Parameterize queries and validate/encode all untrusted input; remove dynamic eval.' },
  { re: /cred|password|secret|token|api key|auth fail|weak.*(pass|cred)/i, owasp: 'A07:2021 Identification & Authentication Failures', attack: 'TA0006 Credential Access', fix: 'Rotate exposed credentials; enforce strong secrets + MFA; remove hardcoded keys.' },
  { re: /crypto|tls|cert|cleartext|plaintext|weak cipher/i, owasp: 'A02:2021 Cryptographic Failures', attack: 'TA0009 Collection', fix: 'Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.' },
  { re: /misconfig|default cred|exposed|open port|directory listing|verbose error/i, owasp: 'A05:2021 Security Misconfiguration', attack: 'TA0007 Discovery', fix: 'Harden configuration; close unused services; remove defaults and verbose errors.' },
  { re: /outdated|old version|vulnerable component|dependency|unpatched/i, owasp: 'A06:2021 Vulnerable & Outdated Components', attack: 'TA0001 Initial Access', fix: 'Patch/upgrade the affected component to a fixed release; track via an SBOM.' },
  { re: /ssrf|server-side request/i, owasp: 'A10:2021 Server-Side Request Forgery', attack: 'TA0007 Discovery', fix: 'Allowlist egress destinations; block access to internal metadata endpoints.' },
];

export function classify(title) {
  for (const r of RULES) if (r.re.test(title || '')) return { owasp: r.owasp, attack: r.attack, fix: r.fix };
  return { owasp: 'A04:2021 Insecure Design', attack: 'TA0043 Reconnaissance', fix: 'Review against secure-design guidance and add a targeted compensating control.' };
}

export function remediation(surface) {
  const findings = (surface.nodes || []).filter((n) => n.type === 'finding');
  return findings
    .map((n) => ({ finding: n.label, ref: n.ref, sev: n.sev, risk: n.risk || riskLevel(n.sev), ...classify(n.label) }))
    .sort((a, b) => sevRank(a.sev) - sevRank(b.sev));
}
