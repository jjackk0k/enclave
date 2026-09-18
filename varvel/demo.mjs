// VARVEL — end-to-end campaign demo (no API key, no real tools).
// Runs the full phase FSM with the mock governed agent so the engine can be
// exercised offline. Swap `runAgent` for the real runGovernedAgent (the
// default) to run a live governed campaign.
//
//   node varvel/demo.mjs
//
import { Campaign } from './engine/campaign.mjs';
import { mockAgent } from './mock-agent.mjs';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dir = dirname(fileURLToPath(import.meta.url));
const scope = { engagement: 'ACME-2231', signedBy: 'M.Vale L4', cidrs: ['10.10.0.0/16'] };

const campaign = new Campaign({
  engine: { model: 'mock' },
  scope,
  runAgent: mockAgent,
  fireteam: true,
  hooks: {
    onPhase: (p) => console.log(`\n> phase: ${p.name}${p.gate === 'sigil' ? '  [HITL gate]' : ''}`),
    approve: async (p) => { console.log(`  . countersignature requested for ${p.name} -> signed (demo)`); return true; },
    onSurface: (cp) => { const c = cp.surface.counts(); console.log(`  surface: ${c.hosts} hosts | ${c.svcs} svc | ${c.findings} findings (${c.crit} crit) | ${c.exploits} exploits | ${c.holds} holds`); },
  },
});

const state = await campaign.run();
const s = state.surface;
const outPath = join(__dir, 'demo-surface.json');
writeFileSync(outPath, JSON.stringify(s, null, 2));
console.log(`\n[done] campaign ${campaign.status} -> surface written: ${outPath}`);
console.log(`       nodes ${s.nodes.length} | edges ${s.edges.length} | holds ${s.holds.length} | phases ${s.phaseLog.length}`);
console.log(`       opsec: ${state.opsec.posture.note}`);
console.log(`       footprint: ${state.opsec.posture.footprint.toolCalls} tool-calls across ${state.opsec.posture.footprint.hostsTouched} hosts | activity events: ${state.activity.length}`);
console.log(`       inherited findings: ${state.inheritedFindings} | budget: ${state.budget.usedSteps}/${state.budget.maxSteps} steps`);
