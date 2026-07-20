// demo.mjs — the same task, six operators, six different deliverables. Shows the
// Enclave AI producing work BEFITTING each persona (role + clearance + scope),
// driven by the read-only context it's given. Offline by default; set
// ANTHROPIC_API_KEY and pass --live to any persona via generate.mjs for a live model.

import { produce } from './generate.mjs';

const C = { g: s => `\x1b[32m${s}\x1b[0m`, dim: s => `\x1b[90m${s}\x1b[0m`, b: s => `\x1b[1m${s}\x1b[0m`, y: s => `\x1b[33m${s}\x1b[0m` };
const PERSONAS = ['sam', 'dana', 'marcus', 'priya', 'ravi', 'alex'];

(async () => {
  console.log('\n' + C.b('  ENCLAVE — the AI makes something befitting the persona'));
  console.log(C.dim('  same task ("produce your first deliverable"), decided by who the operator is.\n'));

  let full = null;
  for (const p of PERSONAS) {
    const r = await produce(p);
    if (p === 'sam') full = r; // keep one to print in full below
    console.log(`  ${C.b(r.who.name.padEnd(12))} ${C.dim(('L' + r.who.clearance + ' ' + r.who.role).padEnd(24))} →  ${C.g('“' + r.deliverable.title + '”')}`);
    console.log(`  ${' '.repeat(12)} ${C.dim(`may ${r.caps.permitted.length} action-classes · ${r.caps.escalate.length} beyond remit`)}`);
  }

  console.log('\n' + C.dim('  ── one deliverable in full (the L1 junior — note it escalates what it can\'t do) ──') + '\n');
  console.log(full.deliverable.markdown.split('\n').map(l => '  ' + l).join('\n'));

  console.log('\n' + C.b('  ── how it works ──'));
  console.log('  each deliverable is generated from the operator\'s read-only context (role, clearance, certs,');
  console.log('  scope) — the SAME context the live model receives. A junior gets a triage note that escalates;');
  console.log('  a red-team lead gets an in-scope recon plan; an auditor gets an evidence request.');
  console.log(C.dim('  live model:  ANTHROPIC_API_KEY=…  node generate.mjs --persona marcus --live') + '\n');
})();
