// VARVEL authz-campaign wiring test — the two-account authorization oracle as a
// campaign primitive (Build 1), proven on the campaign path against authzlab.
//   node --test varvel/test/authz-campaign.test.mjs
//
// Pinned: scope-gated fail-closed, path-prefix confined, paced + noise-charged,
// proven violations land as CONFIRMED findings with evidence bundles, the gated
// exploit phase auto-runs the sweep, and the results ride the exploit prompt.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Campaign } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';
import { createAuthzlabTarget, TENANT_A, TENANT_B } from '../targets/authzlab.mjs';

const scope = (e, extra = {}) => ({ engagement: e, signedBy: 'x', cidrs: ['127.0.0.0/8'], ...extra });

const AUTHZ = {
  accounts: [
    { label: 'alice', login: { path: '/login', body: `user=${TENANT_A.user}&pass=${TENANT_A.pass}` } },
    { label: 'bob', login: { path: '/login', body: `user=${TENANT_B.user}&pass=${TENANT_B.pass}` } },
  ],
  writes: true, deletes: true,
  templates: [
    { path: '/api/users/{id}', methods: ['GET', 'PATCH'], refs: { a: [TENANT_A.profileId], b: [TENANT_B.profileId] } },
    { path: '/api/safe/documents/{id}', methods: ['GET', 'PATCH'], refs: { a: ['SDOC-A1'], b: ['SDOC-B1'] } },
  ],
};

async function withLab(fn) {
  const srv = createAuthzlabTarget();
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try { return await fn(base); }
  finally {
    await fetch(base + '/lab/revert', { method: 'POST' }).catch(() => {}); // the delete rung destroys an object — restore
    await new Promise((r) => srv.close(r));
  }
}

function seedSurface(c) {
  const hid = c.surface.host('127.0.0.1', { label: 'authzlab' });
  c.surface.endpoint(hid, '/api/documents', 'GET');
  c.surface.endpoint(hid, '/api/me', 'GET');
  return hid;
}

test('runAuthzSweep: harvest → differential → ladder on the campaign path; violations filed CONFIRMED', () => withLab(async (base) => {
  const c = new Campaign({ engine: {}, scope: scope('AUTHZ-C1'), runAgent: mockAgent, authz: AUTHZ });
  assert.ok(c.authz, 'authz config sanitized and kept');
  const hid = seedSurface(c);
  const res = await c.runAuthzSweep({ base });
  assert.equal(res.ok, true);
  assert.equal(res.summary.violations, 2, 'documents + users templates violated; safe family cleared');
  assert.equal(res.summary.accounts.join(','), 'alice,bob');

  // findings landed, confirmed tier, oracle-citing evidence, bundles attached
  const findings = [...c.surface.nodes.values()].filter((n) => n.type === 'finding' && String(n.ref || '').startsWith('authzsweep:'));
  assert.ok(findings.length >= 5, `read+write+delete on documents, read+write+ladder on users (got ${findings.length})`);
  assert.ok(findings.every((f) => f.confidence === 'confirmed'), 'every filed violation is confirmed tier');
  assert.ok(findings.every((f) => /differential oracle \(authzsweep\)/.test(f.evidence)), 'evidence cites the objective oracle');
  const del = findings.find((f) => /delete/.test(f.label));
  assert.ok(del && del.sev === 'crit', 'cross-tenant delete filed at crit');
  const ma = findings.find((f) => /Mass assignment/.test(f.label));
  assert.ok(ma && ma.authz && ma.authz.bundle.pairs.length > 0, 'evidence bundle (raw HTTP pairs) attached to the node');
  assert.ok(ma.authz.bundle.impact.length > 0, 'impact labeled separately from observation');

  // safe family filed NOTHING
  assert.ok(!findings.some((f) => /safe/.test(String(f.ref))), 'enforced control family produced no findings');

  // on the record + exposed to the console
  assert.ok(c.activity.some((e) => e.kind === 'authz.sweep' && e.data.violations === 2), 'authz.sweep logged');
  const st = c.getState();
  assert.ok(st.authzSweep && st.authzSweep.violations === 2, 'summary exposed in getState');
  assert.equal(c.surface.counts().confirmed >= 5, true);
  assert.ok(hid, 'surface host seeded');
}));

test('runAuthzSweep: out-of-scope base refused fail-closed (no requests fired)', () => withLab(async (base) => {
  const c = new Campaign({ engine: {}, scope: scope('AUTHZ-C2'), runAgent: mockAgent, authz: AUTHZ });
  seedSurface(c);
  const res = await c.runAuthzSweep({ base: 'http://10.203.0.9:9' });
  assert.equal(res.ok, false);
  assert.match(res.error, /outside the signed scope/);
  assert.ok(c.activity.some((e) => e.kind === 'authz.refused'), 'refusal logged, never silent');
  const noCfg = new Campaign({ engine: {}, scope: scope('AUTHZ-C3'), runAgent: mockAgent });
  const r2 = await noCfg.runAuthzSweep({ base });
  assert.equal(r2.ok, false);
  assert.match(r2.error, /two provisioned accounts/);
}));

test('runAuthzSweep: path-prefix scope confines harvest + replay, refusals recorded', () => withLab(async (base) => {
  const c = new Campaign({ engine: {}, scope: scope('AUTHZ-C4', { pathPrefixes: ['/api/safe/'] }), runAgent: mockAgent, authz: AUTHZ });
  seedSurface(c);
  const res = await c.runAuthzSweep({ base });
  assert.equal(res.ok, true);
  assert.ok(res.summary.refusals >= 3, 'out-of-prefix replays refused before the wire');
  assert.equal(res.summary.violations, 0, 'only the enforced /api/safe/* family was reachable');
  assert.ok(c.activity.some((e) => e.kind === 'scope.path.refused' && String(e.data.tool || '').startsWith('authzsweep')), 'path refusals on the record');
}));

test('runAuthzSweep: no web base is LOUD, never a silent skip (2026-08-30 live failure)', () => withLab(async (base) => {
  // the exact live launch shape: reconOpts with NO ports/webPorts → _webBases() is []
  const c = new Campaign({ engine: {}, scope: scope('AUTHZ-C6'), runAgent: mockAgent, targets: ['127.0.0.1'], reconOpts: { crawl: { maxPages: 1 } }, authz: AUTHZ });
  seedSurface(c);
  const res = await c.runAuthzSweep();
  assert.equal(res.ok, false);
  assert.match(res.error, /no web base/);
  assert.ok(c.activity.some((e) => e.kind === 'authz.skip' && e.data.reason === 'no-web-base'), 'the skip is on the record — a dormant oracle is never silent');
  void base;
}));

test('runAuthzSweep: cfg.base pins the account-bound host when reconOpts carry no ports', () => withLab(async (base) => {
  const c = new Campaign({ engine: {}, scope: scope('AUTHZ-C7'), runAgent: mockAgent, targets: ['127.0.0.1'], reconOpts: { crawl: { maxPages: 1 } }, authz: { ...AUTHZ, base } });
  assert.equal(c.authz.base, base, 'sanitizeAuthzCfg passes the explicit base through');
  seedSurface(c);
  const res = await c.runAuthzSweep();
  assert.equal(res.ok, true, 'sweep fires via cfg.base despite empty _webBases()');
  assert.equal(res.summary.violations, 2);
}));

test('exploit phase auto-run fires via cfg.base with NO reconOpts ports (live launch-shape regression)', () => withLab(async (base) => {
  const c = new Campaign({
    engine: {}, scope: scope('AUTHZ-C8'), runAgent: async () => ({ text: '{"exploits":[]}', steps: 1 }),
    targets: ['127.0.0.1'], reconOpts: { crawl: { maxPages: 1 } }, // NO ports — the live launch shape that skipped the oracle
    authz: { ...AUTHZ, base }, hooks: { approve: async () => true }, stallCheckMs: 0,
  });
  const hid = seedSurface(c);
  c.surface.finding(hid, { title: 'seed', sev: 'low', ref: 'F-0', confidence: 'confirmed', evidence: 'x' }); // progression gate
  const { PHASES } = await import('../engine/phases.mjs');
  const r = await c.runPhase(PHASES.find((p) => p.id === 'exploit'), '');
  assert.ok(!r.held && !r.skipped, 'exploit phase ran under the approved gate');
  assert.ok(c.authzSweepResult && c.authzSweepResult.ok, 'the sweep auto-ran via cfg.base');
  assert.equal(c.authzSweepResult.summary.violations, 2);
}));

test('exploit phase auto-runs the sweep inside the countersigned window; results ride the prompt', () => withLab(async (base) => {
  let sent = '';
  const agent = async ({ messages }) => { sent = messages[0].content; return { text: '{"exploits":[]}', steps: 1 }; };
  const port = Number(new URL(base).port);
  const c = new Campaign({
    engine: {}, scope: scope('AUTHZ-C5'), runAgent: agent,
    targets: ['127.0.0.1'], reconOpts: { ports: [port] }, // _webBases() → the lab base
    authz: AUTHZ, hooks: { approve: async () => true }, stallCheckMs: 0,
  });
  const hid = seedSurface(c);
  c.surface.finding(hid, { title: 'seed', sev: 'low', ref: 'F-0', confidence: 'confirmed', evidence: 'GET /api/me returned the profile' }); // the progression gate needs a confirmed finding
  const { PHASES } = await import('../engine/phases.mjs');
  const exploit = PHASES.find((p) => p.id === 'exploit');
  const r = await c.runPhase(exploit, '');
  assert.ok(!r.held && !r.skipped, 'exploit phase ran under the approved gate');
  assert.ok(c.authzSweepResult && c.authzSweepResult.ok, 'the sweep auto-ran in the gated phase');
  assert.equal(c.authzSweepResult.summary.violations, 2);
  assert.ok(sent.includes('[authzsweep]'), 'proven violations ride the exploit prompt');
  assert.ok(sent.includes('/api/documents/{id} — idor-delete'), 'worst verdict named per template');
  assert.ok(c.activity.some((e) => e.kind === 'gate.decision' && e.data.phase === 'exploit' && e.data.signed === true), 'the sigil gate signed first');
}));


// ——— bearer-header accounts (2026-08-30: frontegg-style OAuth targets where the
// session is an Authorization: Bearer JWT, not a cookie) ———
test('runAuthzSweep: bearer-header accounts drive the differential; unauth control carries NO header', async () => {
  const { default: http } = await import('node:http');
  const OBJS = { 'OA-1': { tenant: 'A', secret: 'alpha' }, 'OB-1': { tenant: 'B', secret: 'bravo' } };
  const srv = http.createServer((req, res) => {
    const auth = req.headers.authorization || '';
    const tenant = auth === 'Bearer TOK-A' ? 'A' : auth === 'Bearer TOK-B' ? 'B' : null;
    const m = /^\/obj\/([\w-]+)$/.exec(req.url.split('?')[0]);
    if (!m) { res.writeHead(404); return res.end('{}'); }
    if (!tenant) { res.writeHead(401); return res.end('{"error":"authentication required"}'); }
    const o = OBJS[m[1]];
    if (!o) { res.writeHead(404); return res.end('{}'); }
    // planted flaw: authentication checked, ownership never — the oracle must catch it
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(o));
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const c = new Campaign({
      engine: {}, scope: scope('AUTHZ-H1'), runAgent: mockAgent,
      authz: {
        base,
        accounts: [
          { label: 'bearerA', headers: { Authorization: 'Bearer TOK-A' } },
          { label: 'bearerB', headers: { authorization: 'Bearer TOK-B' } }, // case-insensitive name
        ],
        templates: [{ path: '/obj/{id}', methods: ['GET'], refs: { a: ['OA-1'], b: ['OB-1'] } }],
      },
    });
    assert.ok(c.authz, 'header accounts sanitize');
    assert.equal(c.authz.accounts[0].headers.authorization, 'Bearer TOK-A', 'header names lowercased');
    const hid = c.surface.host('127.0.0.1', { label: 'bearerlab' });
    const res = await c.runAuthzSweep();
    assert.equal(res.ok, true);
    assert.equal(res.summary.violations, 1, 'cross-tenant read proven with bearer sessions');
    const r0 = res.results[0];
    assert.equal(r0.read.verdict, 'idor');
    // evidence redaction: no raw token anywhere in the captured pairs
    const blob = JSON.stringify(r0.pairs);
    assert.ok(!blob.includes('TOK-A') && !blob.includes('TOK-B'), 'raw bearer tokens never land in evidence');
    assert.ok(blob.includes('<session:bearerA>') && blob.includes('<session:bearerB>'), 'sessions labeled in evidence');
    void hid;
  } finally { await new Promise((r) => srv.close(r)); }
});
