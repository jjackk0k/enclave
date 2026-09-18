// VARVEL coverage-gate tests — the coverage-completion gate (winner-copyables build,
// Tool 3): the pure ledger (engine/coverage.mjs) + its campaign wiring. Hermetic:
// loopback 127.0.0.1 labs + the mock agent only; no live network.
//   node --test varvel/test/coverage-gate.test.mjs
//
// Pinned: recon-harvested endpoints are QUEUED via the surface.endpoint wrap; lanes
// MARK what they actually exercised (a candidate whose differential never fired stays
// untested); the gate reports NO-SURFACE-QUEUED / DONE-CLEAN / COVERAGE-INCOMPLETE with
// the remaining queue itemized; lane marks against never-queued keys are ORPHANS, kept
// visible; run() computes the verdict and the report renders the ledger.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CoverageLedger, kindOfLabel, COVERAGE_LANES, COVERAGE_CAPS } from '../engine/coverage.mjs';
import { Campaign } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';
import { renderReport } from '../engine/report.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
const scope = (e, extra = {}) => ({ engagement: e, signedBy: 'x', cidrs: ['127.0.0.0/8'], ...extra });

async function withServer(srv, fn) {
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try { return await fn(base); }
  finally { await new Promise((r) => srv.close(r)); }
}

test('the pure core carries NO network/fs (static scan)', () => {
  const src = readFileSync(join(__dir, '..', 'engine', 'coverage.mjs'), 'utf8');
  for (const re of [/node:(http|https|fs|net|child_process)/, /\bfetch\s*\(/, /\bnet\.connect/]) {
    assert.ok(!re.test(src), `coverage.mjs must stay pure — matched ${re}`);
  }
});

test('kindOfLabel classifies param / object-id / plain endpoint', () => {
  assert.equal(kindOfLabel('/api/search?q='), 'param');
  assert.equal(kindOfLabel('/api/orders/{id}'), 'object-id');
  assert.equal(kindOfLabel('/api/me'), 'endpoint');
  assert.ok(COVERAGE_LANES.includes('oracle') && COVERAGE_LANES.includes('manual'));
});

test('ledger: queue dedupes; marks by lane; unknown keys are VISIBLE orphans', () => {
  const L = new CoverageLedger({ now: () => '2026-08-31T12:00:00Z' });
  assert.equal(L.queue({ kind: 'endpoint', key: '/a', host: 'h1', source: 'recon-harvest' }), true);
  assert.equal(L.queue({ kind: 'endpoint', key: '/a' }), false, 'dedupe by kind+key');
  assert.equal(L.queue({ key: '/p?q=' }), true);
  assert.equal(L.queue({ key: '/p?q=' }).kind, undefined); // deduped again
  assert.equal(L.mark('/a', 'oob'), true);
  assert.equal(L.mark('/a', 'oob'), true, 'idempotent per lane');
  assert.equal(L.mark('/a', 'oracle'), true);
  assert.equal(L.mark('/never-queued', 'manual'), false);
  const s = L.status();
  assert.equal(s.queued, 2);
  assert.equal(s.tested, 1);
  assert.equal(s.untested.length, 1);
  assert.equal(s.untested[0].kind, 'param', 'kind inferred from the label shape');
  assert.deepEqual(s.byLane, { oob: 1, oracle: 1 });
  assert.equal(s.orphans.length, 1);
  assert.match(s.orphans[0].note, /kept visible/);
});

test('the gate: NO-SURFACE-QUEUED → COVERAGE-INCOMPLETE (itemized) → DONE-CLEAN', () => {
  const L = new CoverageLedger({});
  assert.equal(L.gate().verdict, 'NO-SURFACE-QUEUED');
  L.queue({ key: '/api/orders/{id}', host: 'app.example.com', source: 'jsminer' });
  L.queue({ key: '/search?q=' });
  const g1 = L.gate();
  assert.equal(g1.verdict, 'COVERAGE-INCOMPLETE');
  assert.equal(g1.remainingTotal, 2);
  assert.deepEqual(g1.remaining.map((i) => i.key), ['/api/orders/{id}', '/search?q=']);
  assert.match(g1.note, /NOT done-clean/);
  L.mark('/api/orders/{id}', 'oracle');
  const g2 = L.gate();
  assert.equal(g2.verdict, 'COVERAGE-INCOMPLETE');
  assert.equal(g2.remainingTotal, 1, 'the exercised item left the remaining queue');
  L.mark('/search?q=', 'oob');
  const g3 = L.gate();
  assert.equal(g3.verdict, 'DONE-CLEAN');
  assert.match(g3.note, /exercise, not safety/);
});

test('ledger overflow past the cap is counted, never silent', () => {
  const L = new CoverageLedger({});
  for (let i = 0; i < COVERAGE_CAPS.maxItems + 3; i++) L.queue({ key: '/p' + i });
  const s = L.status();
  assert.equal(s.queued, COVERAGE_CAPS.maxItems);
  assert.equal(s.overflow, 3);
});

// ——— campaign wiring ———

test('surface.endpoint wrap queues recon harvest; lanes mark; the gate drains', () => withServer(http.createServer((req, res) => {
  if (req.url === '/') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<!doctype html><script src="/app.js"></script>'); }
  if (req.url === '/app.js') { res.writeHead(200, { 'content-type': 'application/javascript' }); return res.end('fetch("/api/orders/1042"); fetch("/api/search?q=x");'); }
  res.writeHead(404); res.end('{}');
}), async (base) => {
  const c = new Campaign({ engine: {}, scope: scope('COV-J1'), runAgent: mockAgent, jsminer: true, stallCheckMs: 0 });
  c.surface.host('127.0.0.1', { label: 'lab' });
  c._reconWebBases.push(base);
  const res = await c.runJsMiner();
  assert.equal(res.ok, true);
  const st = c.coverage.status();
  assert.ok(st.queued >= 1, 'jsminer-harvested endpoints were QUEUED by the endpoint wrap');
  assert.ok(st.untested.some((i) => i.key === '/api/orders/1042'), 'harvested but NOT exercised — on the untested ledger');
  assert.equal(c.coverage.gate().verdict, 'COVERAGE-INCOMPLETE');
  // lanes exercise every queued item
  for (const i of c.coverage.status().untested) assert.equal(c._covMark(i.key, 'oob'), true, `lane mark for ${i.key}`);
  assert.equal(c.coverage.status().untested.length, 0);
  assert.equal(c.coverage.gate().verdict, 'DONE-CLEAN', 'queue drained by lane marks');
  // path-without-query fallback: exercising a bare path covers the queued '?p=' key
  assert.equal(c._covMark('/api/search', 'browseragent'), false, 'never queued — an orphan is refused as a mark');
  c.coverage.queue({ key: '/api/search?q=' });
  assert.equal(c._covMark('/api/search', 'browseragent'), true, 'bare-path mark covers the queued parameterized key');
}));

test('run() computes the completion verdict; getState exposes it; the report renders the ledger', async () => {
  const c = new Campaign({ engine: {}, scope: scope('COV-R1'), runAgent: mockAgent, stallCheckMs: 0 });
  const hid = c.surface.host('127.0.0.1', { label: 'lab' });
  c.surface.endpoint(hid, '/api/orders/{id}', 'GET');
  c.surface.endpoint(hid, '/api/search?q=', 'GET');
  await c.run();
  const st = c.getState();
  assert.equal(st.status, 'done');
  assert.equal(st.completion, 'COVERAGE-INCOMPLETE', 'queued surface no lane touched refuses done-clean');
  assert.ok(st.coverage.queued >= 2, 'our endpoints + whatever the (mock) recon agent ingested are all queued');
  assert.ok(st.coverage.untested.some((i) => i.key === '/api/orders/{id}' && i.host === '127.0.0.1'));
  assert.ok(st.coverage.untested.some((i) => i.key === '/api/search?q='));
  assert.ok(c.activity.some((e) => e.kind === 'coverage.gate' && e.data.verdict === 'COVERAGE-INCOMPLETE'), 'the gate verdict is on the activity record');
  assert.ok(c.surface.phaseLog.some((n) => /COVERAGE-INCOMPLETE/.test(n.summary)), 'the remaining queue is a surface note — named, not silent');

  const md = renderReport(c.surface.toJSON(), { coverage: { ...st.coverage, verdict: st.completion } });
  assert.match(md, /## Coverage — testing-completeness ledger/);
  assert.match(md, /COVERAGE-INCOMPLETE/);
  assert.match(md, /\/api\/orders\/\{id\}/, 'the report itemizes the remaining queue');

  // when lanes drain the queue, the same machinery reports DONE-CLEAN
  for (const i of c.coverage.status().untested) c._covMark(i.key, 'manual', 'operator hand-tested');
  const drained = c.coverage.gate();
  assert.equal(drained.verdict, 'DONE-CLEAN');
  assert.ok((drained.byLane || {}).manual >= 2);
});

test('authz candidates whose differential never fired stay UNTESTED', async () => {
  // lab: /api/items/{id} answers 404 to everyone — refs never harvest, the sweep's
  // candidate degrades inconclusive with ZERO pairs → NOT marked exercised.
  const srv = http.createServer((req, res) => { res.writeHead(404); res.end('{}'); });
  await withServer(srv, async (base) => {
    const c = new Campaign({
      engine: {}, scope: scope('COV-A1'), runAgent: mockAgent, stallCheckMs: 0,
      authz: { base, accounts: [{ label: 'a', cookie: 'sess=a' }, { label: 'b', cookie: 'sess=b' }], templates: [{ path: '/api/items/{id}', methods: ['GET'] }] },
      hooks: { approve: async () => true },
    });
    c.surface.host('127.0.0.1', { label: 'lab' });
    const r = await c.runAuthzSweep();
    assert.equal(r.ok, true);
    assert.equal(r.results[0].read.verdict, 'inconclusive');
    const st = c.coverage.status();
    assert.ok(st.queued >= 1, 'the configured template was queued');
    assert.ok(st.untested.some((i) => i.key === '/api/items/{id}'), 'zero-pair candidate = NOT exercised, honestly on the remaining queue');
  });
});
