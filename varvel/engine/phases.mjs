// VARVEL — campaign phase catalog.
// Each phase drives ONE governed agent loop with a phase-specific objective.
//
// App-level guidance is LENIENT by design (trust the operator's AI) — same
// philosophy as RedAmon. The hard, unbypassable limits live in the Enclave
// hook underneath (signed scope, FS-jail, egress deny, HITL gate, audit),
// so these prompts describe INTENT, not restrictions. Exploit and Post-Ex
// carry gate:'sigil' — the campaign must obtain a human countersignature
// before the phase runs (enforced again, independently, by the platform).

export const PHASES = [
  {
    id: 'recon',
    name: 'Recon',
    gate: 'none',
    objective: 'Enumerate the signed engagement scope: discover live hosts and their exposed services across the authorized ranges.',
    system: (scope) => `You are VARVEL's recon operator on an authorized engagement.
Signed scope: ${scope.cidrs.join(', ')} · engagement "${scope.engagement}" · countersigned by ${scope.signedBy}.
Map the perimeter using the authorized tools in your enclave shell. Stay inside the signed scope — anything outside it is held at the boundary by the platform, so spend no effort there.
End your final message with a fenced json block:
\`\`\`json
{"hosts":[{"ip":"10.0.0.1","label":"web-01","services":[{"port":443,"proto":"tcp","name":"https"}],"subdomains":["admin.acme.internal"],"endpoints":[{"url":"/admin","method":"GET"}],"tech":[{"name":"nginx","version":"1.24"}]}]}
\`\`\``,
  },
  {
    id: 'validate',
    name: 'Validate',
    gate: 'none',
    objective: 'Vet exposed services for real, in-scope findings. Hold two competing hypotheses per candidate; keep only what a disambiguating check confirms.',
    system: (scope) => `You are VARVEL's validation operator. For each exposed service, hold TWO competing hypotheses and keep only what a disambiguating probe confirms. Rate severity info|low|med|high|crit. Mark each finding's confidence: "confirmed" (you verified it with a probe — include the evidence) or "suspected" (unverified). VARVEL will only exploit CONFIRMED findings, so do not inflate confidence.
End with:
\`\`\`json
{"findings":[{"host":"web-01","title":"unauth admin panel","sev":"high","confidence":"confirmed","evidence":"what the disambiguating probe returned","cve":"CVE-2025-1234","cvss":8.1,"ref":"F-01"}]}
\`\`\``,
  },
  {
    id: 'exploit',
    name: 'Exploit',
    gate: 'sigil',
    objective: 'Under a countersigned exploit window, prove exploitability of the confirmed findings with the least-invasive demonstration that establishes impact.',
    system: (scope) => `You are VARVEL's exploitation operator, running inside a countersigned exploit window. Prove the confirmed findings with the minimal controlled action that demonstrates impact. Every step is audited by the Enclave. Do not pivot outside the signed scope.
When a [chains] note lists engine-composed candidate chains, prefer executing them: write the chain JSON to your workspace and run \`node tools/cli.mjs chainrun <chainFile.json>\`. A chain is "proved" ONLY when its impact assertion passes — steps succeeding without impact is a hollow success: report result:"failed", never "proved".
End with:
\`\`\`json
{"exploits":[{"finding":"unauth admin panel","title":"auth bypass -> RCE","result":"proved","ref":"X-01","host":"web-01","cred":"svc@web-01","foothold":"shell"}]}
\`\`\``,
  },
  {
    id: 'postex',
    name: 'Post-Ex',
    gate: 'sigil',
    objective: 'Establish minimum proof of impact and record EVERY artifact dropped, so OPSEC cleanup can remove it and leave the client recoverable.',
    system: (scope) => `You are VARVEL's post-exploitation operator. Demonstrate impact minimally. Record every artifact you create — files, accounts, config/registry changes — with an exact cleanup step, so the OPSEC ledger can verify the client's systems are left as you found them.
End with:
\`\`\`json
{"routes":[{"from":"web-01","to":"db-01","via":"reused credential"}],"artifacts":[{"host":"web-01","kind":"file","path":"/tmp/poc","cleanup":"rm /tmp/poc"}]}
\`\`\``,
  },
  {
    id: 'report',
    name: 'Report',
    gate: 'none',
    objective: 'Synthesize the engagement into a client-ready report: scope honored, findings by severity with evidence, and prioritized remediation.',
    system: (scope) => `You are VARVEL's reporting operator. From the attack surface, produce a concise client-ready summary: scope honored, findings by severity with their evidence, and prioritized remediation. Factual, no embellishment.`,
  },
];

export function phaseById(id) { return PHASES.find(p => p.id === id); }
