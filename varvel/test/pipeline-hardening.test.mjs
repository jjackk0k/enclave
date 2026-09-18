// VARVEL pipeline-hardening tests — proves the audited autonomy bugs stay fixed.
//   node --test varvel/test/pipeline-hardening.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Campaign, parseJsonBlock } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';
import { priorFindings } from '../engine/store.mjs';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', '.data');
const scope = (e) => ({ engagement: e, signedBy: 'x', cidrs: ['10.0.0.0/8'] });
const jb = (o) => '```json\n' + JSON.stringify(o) + '\n```';
const kinds = (c) => c.activity.map((a) => a.kind);

test('parseJsonBlock: last block wins, unfenced fallback, junk -> null', () => {
  assert.equal(parseJsonBlock('plan ' + jb({ a: 1 }) + ' answer ' + jb({ a: 2 })).a, 2);
  assert.deepEqual(parseJsonBlock('noise {"hosts":[]} tail'), { hosts: [] });
  assert.equal(parseJsonBlock('no json here'), null);
  assert.equal(parseJsonBlock(null), null);
});

test('resilience: a null element in ANY ingest array does not crash the run (BUG-1)', async () => {
  for (const kind of ['hosts', 'services', 'findings', 'exploits', 'routes', 'artifacts']) {
    const bad = kind === 'services' ? { hosts: [{ ip: '10.0.0.1', services: [null] }] } : { [kind]: [null] };
    const agent = async () => ({ text: jb(bad), denials: [], steps: 1 });
    const st = await new Campaign({ engine: {}, scope: scope('BAD-' + kind), runAgent: agent, hooks: { approve: async () => true } }).run();
    assert.equal(st.status, 'done', kind + ': completed');
    assert.ok(kinds({ activity: st.activity }).includes('campaign.done'), kind + ': done logged');
  }
});

test('resilience: wrong-typed denials / negative steps do not crash or unbound budget (BUG-2/7)', async () => {
  const agent = async () => ({ text: 'ok', denials: 5, steps: -1000 });
  const st = await new Campaign({ engine: {}, scope: scope('BADRES'), runAgent: agent, budget: { maxSteps: 3 }, hooks: { approve: async () => true } }).run();
  assert.equal(st.status, 'done');
  assert.ok(st.budget.usedSteps >= 0, 'negative steps clamped');
});

test('HITL: throwing approve -> hold, fail closed (BUG-3)', async () => {
  const st = await new Campaign({ engine: {}, scope: scope('APPTHROW'), runAgent: mockAgent, hooks: { approve: async () => { throw new Error('ui closed'); } } }).run();
  assert.equal(st.status, 'done');
  assert.equal(st.surface.counts.exploits, 0);
  assert.ok(st.surface.holds.some((h) => h.rule === 'HITL-required'));
});

test('HITL: hanging approve -> timeout -> hold, no hang (BUG-4)', async () => {
  // approve that never responds within the gate window (unref'd timer so Node can still exit)
  const st = await new Campaign({ engine: {}, scope: scope('APPHANG'), runAgent: mockAgent, approveTimeoutMs: 120, hooks: { approve: () => new Promise((res) => { const t = setTimeout(() => res(true), 60000); t.unref(); }) } }).run();
  assert.equal(st.status, 'done');
  assert.ok(st.activity.some((a) => a.kind === 'gate.timeout'));
});

test('HITL: truthy non-boolean approve does NOT green-light exploit (BUG-5)', async () => {
  const st = await new Campaign({ engine: {}, scope: scope('APPTRUTHY'), runAgent: mockAgent, hooks: { approve: async () => 'yes-please' } }).run();
  assert.equal(st.surface.counts.exploits, 0, 'only a strict boolean true approves');
});

test('hook isolation: throwing onEvent/onSurface do not crash the campaign (BUG-6)', async () => {
  let n = 0;
  const st = await new Campaign({ engine: {}, scope: scope('HOOK'), runAgent: mockAgent, hooks: { approve: async () => true, onEvent: () => { if (++n === 3) throw new Error('boom'); }, onSurface: () => { throw new Error('boom2'); } } }).run();
  assert.equal(st.status, 'done');
});

test('budget: NaN maxSteps falls back to a finite default (BUG-7)', () => {
  const c = new Campaign({ engine: {}, scope: scope('NANBUD'), runAgent: mockAgent, budget: { maxSteps: NaN } });
  assert.ok(Number.isFinite(c.budget.maxSteps));
});

test('progression gate: empty recon skips exploit/post-ex (BUG-8)', async () => {
  const agent = async (opts) => (opts.messages[0].content.startsWith('Enumerate') ? { text: jb({ hosts: [] }), steps: 1 } : { text: 'nothing', steps: 1 });
  const st = await new Campaign({ engine: {}, scope: scope('EMPTY'), runAgent: agent, hooks: { approve: async () => true } }).run();
  assert.equal(st.surface.counts.findings, 0);
  assert.ok(st.activity.some((a) => a.kind === 'phase.skip' && a.data.phase === 'exploit'), 'exploit skipped');
});

test('cross-session accumulation: findings persist across runs (BUG-10)', async () => {
  rmSync(DATA, { recursive: true, force: true });
  const mk = (ref, title) => async () => ({ text: jb({ findings: [{ host: 'h', title, sev: 'high', ref }] }), steps: 1 });
  await new Campaign({ engine: {}, scope: scope('ACC'), runAgent: mk('A', 'F-ALPHA'), hooks: { approve: async () => true } }).run();
  await new Campaign({ engine: {}, scope: scope('ACC'), runAgent: mk('B', 'F-BETA'), hooks: { approve: async () => true } }).run();
  const prior = priorFindings('ACC');
  assert.ok(prior.some((f) => f.ref === 'A') && prior.some((f) => f.ref === 'B'), 'both sessions accumulated');
});

test('engagement-name collision: sanitized-equal names do NOT share memory (BUG-11)', async () => {
  rmSync(DATA, { recursive: true, force: true });
  const agent = async () => ({ text: jb({ findings: [{ host: 'h', title: 'SECRET', sev: 'high', ref: 'S' }] }), steps: 1 });
  await new Campaign({ engine: {}, scope: scope('ACME/prod'), runAgent: agent, hooks: { approve: async () => true } }).run();
  assert.equal(priorFindings('ACME_prod').length, 0, 'a different engagement must not inherit');
});

test('domain-only tooled recon runs the subdomain scan (BUG-16)', async () => {
  const nx = () => { const e = new Error('nx'); e.code = 'ENOTFOUND'; throw e; };
  const resolver = { resolve4: async (h) => (h.startsWith('www.') ? ['10.0.0.9'] : nx()) };
  const st = await new Campaign({ engine: {}, scope: scope('DOMONLY'), runAgent: mockAgent, tooledRecon: true, targets: [], reconOpts: { domain: 'acme.test', words: ['www', 'nope'], resolver, passive: false }, hooks: { approve: async () => true } }).run();
  assert.ok(st.surface.counts.subdomains >= 1, 'subdomain scan ran despite empty targets');
});

test('getState returns a copy of activity — caller cannot corrupt the feed (BUG-18)', async () => {
  const c = new Campaign({ engine: {}, scope: scope('COPY'), runAgent: mockAgent, hooks: { approve: async () => true } });
  const st = await c.run();
  const n = c.activity.length;
  st.activity.push({ junk: true });
  assert.equal(c.activity.length, n);
});

test('_ingest: PHASE-WRAPPED agent output lands on the surface (the empty-surface bug)', () => {
  // The interactive agent answers like {"success":true,"recon":{"hosts":[…]}} — previously
  // _ingest only read top-level keys, so chat-driven runs showed an empty surface forever.
  const c = new Campaign({ engine: {}, scope: scope('WRAP'), runAgent: mockAgent });
  c._ingest('chat', {
    success: true,
    recon: { hosts: [{ ip: '127.0.0.1', label: 'Axiom', services: [{ port: 8973, proto: 'tcp', name: 'http' }], endpoints: [{ url: '/admin', method: 'GET' }], tech: ['nginx 1.18.0'] }] },
    exploit: { exploits: [{ title: 'forged admin JWT', result: 'proved', ref: 'X-1' }] },
  });
  const s = c.surface.toJSON();
  assert.ok(s.counts.hosts >= 1, 'host landed');
  assert.ok(s.counts.svcs >= 1, 'service landed');
  assert.ok(s.counts.endpoints >= 1, 'endpoint landed');
  assert.ok(s.counts.tech >= 1, 'tech landed');
  assert.ok(s.counts.exploits >= 1, 'exploit landed from the wrapped exploit key');
});
