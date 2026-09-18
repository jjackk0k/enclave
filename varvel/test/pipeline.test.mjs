// VARVEL full-pipeline integration tests — the phase FSM end-to-end, autonomously.
//   node --test varvel/test/pipeline.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Campaign } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';
import { renderReport } from '../engine/report.mjs';

const phasesRun = (c) => c.activity.filter((a) => a.kind === 'phase.start').map((a) => a.data.phase);

test('full pipeline: recon -> validate -> exploit -> postex -> report runs autonomously', async () => {
  const c = new Campaign({
    engine: {}, scope: { engagement: 'PIPE-1', signedBy: 'M.Vale L4', cidrs: ['10.10.0.0/16'] },
    runAgent: mockAgent, hooks: { approve: async () => true },
  });
  const st = await c.run();

  assert.equal(st.status, 'done');
  assert.deepEqual(phasesRun(c), ['recon', 'validate', 'exploit', 'postex', 'report'], 'all five phases ran, in order');

  const cts = st.surface.counts;
  assert.ok(cts.hosts >= 2 && cts.findings >= 2 && cts.crit >= 1 && cts.exploits >= 1, 'surface fully built across phases');

  const md = renderReport(st.surface);
  for (const sec of ['## Findings', '## Governance & scope', '## OPSEC', '## Remediation']) assert.ok(md.includes(sec), 'report has ' + sec);

  assert.ok(st.opsec.artifacts.length >= 1, 'OPSEC ledger populated in post-ex');
  assert.ok(st.activity.some((a) => a.kind === 'campaign.done'), 'campaign completion recorded');
  assert.equal('audit' in st, false, 'no VARVEL audit of record (that is the enclave)');
});

test('pipeline resilience: a throwing phase agent does NOT crash the campaign', async () => {
  const flaky = async (opts) => {
    if (/^Vet/.test(opts.messages[0].content)) throw new Error('LLM 500 during validate');
    return mockAgent(opts);
  };
  const c = new Campaign({
    engine: {}, scope: { engagement: 'PIPE-2', signedBy: 'x', cidrs: ['10.0.0.0/8'] },
    runAgent: flaky, hooks: { approve: async () => true },
  });
  const st = await c.run();

  assert.equal(st.status, 'done', 'campaign still completed despite a failing phase');
  assert.ok(st.activity.some((a) => a.kind === 'phase.error'), 'the phase error was logged, not thrown');
  assert.ok(st.surface.counts.hosts >= 2, 'recon (before the failure) still populated the surface');
  assert.ok(phasesRun(c).includes('report'), 'later phases still ran after the failure');
});

test('pipeline: HITL denial holds exploit + post-ex, campaign still reports', async () => {
  const c = new Campaign({
    engine: {}, scope: { engagement: 'PIPE-3', signedBy: 'x', cidrs: ['10.0.0.0/8'] },
    runAgent: mockAgent, hooks: { approve: async () => false },
  });
  const st = await c.run();
  assert.equal(st.status, 'done');
  assert.equal(st.surface.counts.exploits, 0, 'no exploit without countersignature');
  assert.ok(st.surface.holds.some((h) => h.rule === 'HITL-required'), 'gate holds recorded');
  assert.ok(phasesRun(c).includes('report'), 'still produced a report');
});
