// VARVEL authzsweep tests — pure classifiers/harvest + the live two-account
// differential against authzlab (Build 1).
//   node --test varvel/test/authzsweep.test.mjs
//
// The Build-1 lesson, pinned: given two provisioned accounts on distinct tenants,
// the sweep harvests object references from BOTH sessions' traffic, cross-replays
// them (authed-other + unauth control), classifies read/write/delete, climbs the
// mass-assignment ladder, and sorts the enforced + decoy shapes honestly. Evidence
// bundles carry raw HTTP pairs with cookies redacted and claims labeled
// observation / inference / impact.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractRefs, templatizePath, harvestExchanges, synthesizeCandidates, classifyWrite, classifyDelete, classifyMassAssign, provisionSession, fetchExchange, authzSweep, sanitizeAuthzCfg, ESCALATION_PARAMS } from '../tools/authzsweep.mjs';
import { createAuthzlabTarget, TENANT_A, TENANT_B } from '../targets/authzlab.mjs';

// ——— pure: harvesting ———

test('extractRefs: id-ish scalar fields from JSON bodies, deduped', () => {
  const refs = extractRefs('{"id":"DOC-A1","tenant":"tenant-a","title":"not a ref","nested":{"document_id":"D-9","order_id":42},"list":[{"uuid":"u-1"}]}');
  const vals = refs.map((r) => r.value);
  assert.ok(vals.includes('DOC-A1') && vals.includes('tenant-a') && vals.includes('D-9') && vals.includes('u-1') && vals.includes('42'));
  assert.ok(!vals.includes('not a ref'), 'non-id keys ignored');
  assert.equal(new Set(vals).size, vals.length, 'deduped');
  assert.deepEqual(extractRefs('not json at all'), []);
});

test('templatizePath: numeric / uuid / prefixed ids fold into {id}', () => {
  assert.deepEqual(templatizePath('/api/orders/1042'), { template: '/api/orders/{id}', value: '1042' });
  assert.deepEqual(templatizePath('/api/orders/ORD-1042'), { template: '/api/orders/{id}', value: 'ORD-1042' });
  assert.deepEqual(templatizePath('/x/550e8400-e29b-41d4-a716-446655440000'), { template: '/x/{id}', value: '550e8400-e29b-41d4-a716-446655440000' });
  assert.equal(templatizePath('/api/orders'), null, 'no id segment, no template');
  assert.equal(templatizePath('/api/me'), null);
});

test('harvestExchanges + synthesizeCandidates: per-session refs, observed + synthesized templates', () => {
  const h = harvestExchanges([
    { session: 'a', method: 'GET', path: '/api/documents', status: 200, resBody: '{"documents":[{"id":"DOC-A1"}]}' },
    { session: 'b', method: 'GET', path: '/api/documents', status: 200, resBody: '{"documents":[{"id":"DOC-B1"}]}' },
    { session: 'a', method: 'GET', path: '/api/bookings/1001', status: 200, resBody: '{"id":1001}' },
  ]);
  assert.equal(h.candidates.length, 1, 'the concrete id path folded into a template');
  assert.equal(h.candidates[0].path, '/api/bookings/{id}');
  assert.deepEqual(h.candidates[0].refs.a, ['1001']);
  const cands = synthesizeCandidates(h, [{ path: '/api/users/{id}', methods: ['GET', 'PATCH'], refs: { a: ['USR-A1'], b: ['USR-B1'] } }]);
  const docs = cands.find((c) => c.path === '/api/documents/{id}');
  assert.ok(docs && docs.synthesized, 'list endpoint + refs → synthesized item template');
  assert.deepEqual(docs.refs.a, ['DOC-A1']);
  assert.deepEqual(docs.refs.b, ['DOC-B1']);
  const users = cands.find((c) => c.path === '/api/users/{id}');
  assert.ok(users && users.configured && users.methods.includes('PATCH'));
  assert.deepEqual(users.refs.a, ['USR-A1'], 'explicit template refs win over the union');
});

// ——— pure: classifiers ———

test('classifyWrite: canary persisted + unauth refused = idor-write; 2xx without effect = enforced', () => {
  const w = classifyWrite({ cross: { status: 200 }, unauth: { status: 401 }, readback: { status: 200, body: '{"title":"CANARY-X"}' }, canary: 'CANARY-X' });
  assert.equal(w.verdict, 'idor-write');
  // the accepted-and-ignored decoy: 200 but no effect
  const d = classifyWrite({ cross: { status: 200 }, unauth: { status: 401 }, readback: { status: 200, body: '{"title":"original"}' }, canary: 'CANARY-X' });
  assert.equal(d.verdict, 'enforced');
  assert.match(d.detail, /accepted-and-ignored/);
  // unauth control also landed it → missing-auth, a distinct verdict
  const u = classifyWrite({ cross: { status: 200 }, unauth: { status: 200 }, readback: { status: 200, body: 'CANARY-X' }, canary: 'CANARY-X' });
  assert.equal(u.verdict, 'unauth-write');
  assert.equal(classifyWrite({ cross: { status: 404 }, unauth: { status: 401 }, readback: null, canary: 'X' }).verdict, 'enforced');
  assert.equal(classifyWrite({ cross: null }).verdict, 'inconclusive');
});

test('classifyDelete: victim-side 404 + refused control = idor-delete', () => {
  assert.equal(classifyDelete({ cross: { status: 200 }, unauth: { status: 401 }, readbackAfter: { status: 404 } }).verdict, 'idor-delete');
  assert.equal(classifyDelete({ cross: { status: 200 }, unauth: { status: 401 }, readbackAfter: { status: 200 } }).verdict, 'inconclusive', 'still readable = unproven');
  assert.equal(classifyDelete({ cross: { status: 403 }, unauth: { status: 401 }, readbackAfter: { status: 200 } }).verdict, 'enforced');
  assert.equal(classifyDelete({ cross: { status: 200 }, unauth: { status: 200 }, readbackAfter: { status: 404 } }).verdict, 'unauth-delete');
});

test('classifyMassAssign: persisted ONLY via the extra param = mass-assignment; ignored = enforced', () => {
  const hit = classifyMassAssign({ before: '{"role":"user"}', controlAfter: '{"role":"user"}', after: '{"role":"admin"}', field: 'role', value: 'admin' });
  assert.equal(hit.verdict, 'mass-assignment');
  // the decoy: 200 either way, readback unchanged
  const decoy = classifyMassAssign({ before: '{"role":"user"}', controlAfter: '{"role":"user"}', after: '{"role":"user"}', field: 'role', value: 'admin' });
  assert.equal(decoy.verdict, 'enforced');
  assert.match(decoy.detail, /200 is not proof/);
  // control ambiguity
  assert.equal(classifyMassAssign({ before: '{"role":"user"}', controlAfter: '{"role":"admin"}', after: '{"role":"admin"}', field: 'role', value: 'admin' }).verdict, 'inconclusive');
  assert.equal(classifyMassAssign({ after: null, field: 'role', value: 'admin' }).verdict, 'inconclusive');
});

test('sanitizeAuthzCfg: needs two provisioned accounts; deletes require writes', () => {
  assert.equal(sanitizeAuthzCfg(null), null);
  assert.equal(sanitizeAuthzCfg({ accounts: [{ cookie: 'x=1' }] }), null, 'one account is not a differential');
  const c = sanitizeAuthzCfg({ accounts: [{ label: 'a', cookie: 'x=1' }, { label: 'b', login: { path: '/login', body: 'u=b' } }], deletes: true });
  assert.ok(c);
  assert.equal(c.deletes, false, 'deletes gated off without writes');
  assert.equal(c.escalate, true);
  assert.equal(c.ladder, ESCALATION_PARAMS);
});

// ——— live: the two-account differential against authzlab ———

async function withLab(fn) {
  const srv = createAuthzlabTarget();
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try { return await fn(base); }
  finally { await new Promise((r) => srv.close(r)); }
}

const ACCOUNTS = [
  { label: 'alice', login: { path: '/login', body: `user=${TENANT_A.user}&pass=${TENANT_A.pass}` } },
  { label: 'bob', login: { path: '/login', body: `user=${TENANT_B.user}&pass=${TENANT_B.pass}` } },
];
const TEMPLATES = [
  { path: '/api/users/{id}', methods: ['GET', 'PATCH'], refs: { a: [TENANT_A.profileId], b: [TENANT_B.profileId] } },
  { path: '/api/safe/documents/{id}', methods: ['GET', 'PATCH', 'DELETE'], refs: { a: ['SDOC-A1'], b: ['SDOC-B1'] } },
  { path: '/api/safe/users/{id}', methods: ['GET', 'PATCH'], refs: { a: [TENANT_A.profileId], b: [TENANT_B.profileId] } },
];

async function revert(base) {
  await fetch(base + '/lab/revert', { method: 'POST' }).catch(() => {});
}

test('authzSweep: harvest → cross-replay → classify → ladder, sorted against authzlab', () => withLab(async (base) => {
  const [sessionA, sessionB] = await Promise.all(ACCOUNTS.map((a) => provisionSession(base, a)));
  assert.ok(sessionA && sessionA.cookie && sessionB && sessionB.cookie, 'both sessions provisioned via login recipes');

  // (a) the harvest pass: both sessions' traffic over the known endpoints
  const exchanges = [];
  for (const p of ['/api/documents', '/api/me']) {
    exchanges.push(await fetchExchange(base, p, { session: 'a', cookie: sessionA.cookie }));
    exchanges.push(await fetchExchange(base, p, { session: 'b', cookie: sessionB.cookie }));
  }
  const harvested = harvestExchanges(exchanges.filter(Boolean));
  const candidates = synthesizeCandidates(harvested, TEMPLATES);
  assert.ok(candidates.some((c) => c.path === '/api/documents/{id}' && c.synthesized), 'documents template synthesized from harvested refs');

  // (b)+(c)+(d) the full sweep with every rung enabled (lab lane)
  const res = await authzSweep(base, { sessionA, sessionB, candidates, writes: true, deletes: true, escalate: true });
  assert.equal(res.ok, true);
  const byTemplate = Object.fromEntries(res.results.map((r) => [r.template, r]));

  // vulnerable documents: read + write + delete all proven cross-tenant
  const docs = byTemplate['/api/documents/{id}'];
  assert.equal(docs.read.verdict, 'idor', 'A1: cross-tenant read confirmed');
  assert.equal(docs.read.crossTenant, true);
  assert.equal(docs.write.verdict, 'idor-write', 'A2: cross-tenant write confirmed by victim-side readback');
  assert.equal(docs.delete.verdict, 'idor-delete', 'A3: cross-tenant delete confirmed by victim-side 404');
  assert.ok(docs.pairs.length >= 6, 'raw HTTP pairs recorded');

  // vulnerable users: cross-tenant profile read + write + the mass-assignment ladder
  const users = byTemplate['/api/users/{id}'];
  assert.equal(users.read.verdict, 'idor', 'A4: cross-tenant profile read');
  assert.equal(users.write.verdict, 'idor-write');
  const role = users.ladder.find((s) => s.param === 'role');
  assert.equal(role.verdict, 'mass-assignment', 'A5: role persists via the extra body param');
  assert.equal(role.reverted, true, 'role reverted to the baseline value');
  const email = users.ladder.find((s) => s.param === 'email');
  assert.equal(email.verdict, 'mass-assignment');

  // the enforced family clears honestly
  const safeDocs = byTemplate['/api/safe/documents/{id}'];
  assert.equal(safeDocs.read.verdict, 'enforced');
  assert.equal(safeDocs.write.verdict, 'enforced');
  const safeUsers = byTemplate['/api/safe/users/{id}'];
  assert.equal(safeUsers.read.verdict, 'enforced');
  const safeRole = safeUsers.ladder.find((s) => s.param === 'role');
  assert.equal(safeRole.verdict, 'enforced', 'the 200-either-way decoy clears on readback');

  // (e) the evidence bundle: labeled claims + redacted raw pairs
  assert.ok(docs.observation.length && docs.inference.length && docs.impact.length, 'observation/inference/impact labeled');
  assert.ok(docs.observation.some((o) => /cross-tenant GET/.test(o)));
  const crossPair = docs.pairs.find((p) => p.label === 'read:cross(A→B)');
  assert.ok(crossPair && crossPair.request.headers.cookie === '<session:alice>', 'cookie redacted in the evidence pair');
  assert.equal(crossPair.response.status, 200);
  assert.ok(docs.pairs.some((p) => p.label === 'write:revert'), 'the revert is on the record');

  // rollup
  assert.equal(res.summary.verdicts['/api/documents/{id}'], 'idor-delete');
  assert.equal(res.summary.verdicts['/api/users/{id}'], 'mass-assignment');
  assert.equal(res.summary.violations, 2, 'two templates with proven violations; the safe family filed nothing');
  assert.ok(res.summary.requests > 20, 'all governed requests counted');

  await revert(base); // the delete rung destroyed DOC-B1 — restore the lab
}));

test('authzSweep: read-only mode never writes (writes/deletes/ladder suppressed)', () => withLab(async (base) => {
  const [sessionA, sessionB] = await Promise.all(ACCOUNTS.map((a) => provisionSession(base, a)));
  const candidates = synthesizeCandidates(harvestExchanges([]), TEMPLATES.slice(0, 1));
  const res = await authzSweep(base, { sessionA, sessionB, candidates, writes: false, deletes: false });
  assert.equal(res.ok, true);
  const users = res.results[0];
  assert.equal(users.read.verdict, 'idor', 'reads still prove the cross-tenant exposure');
  assert.equal(users.write, null);
  assert.equal(users.delete, null);
  assert.equal(users.ladder.length, 0);
  assert.ok(!users.pairs.some((p) => p.write), 'no write pair exists');
}));

test('authzSweep: path-prefix scope confines every request, refusals recorded', () => withLab(async (base) => {
  const [sessionA, sessionB] = await Promise.all(ACCOUNTS.map((a) => provisionSession(base, a)));
  const candidates = synthesizeCandidates(harvestExchanges([]), TEMPLATES.slice(0, 1));
  const res = await authzSweep(base, { sessionA, sessionB, candidates, pathPrefixes: ['/api/safe/'] });
  assert.equal(res.ok, true);
  assert.ok(res.refusals.length >= 3, 'every out-of-prefix request refused before the wire');
  assert.ok(res.refusals.every((r) => r.reason === 'out-of-scope-path'));
  assert.equal(res.results[0].read.verdict, 'inconclusive', 'no claim without responses');
}));

test('authzSweep: never throws on an unreachable base', async () => {
  const res = await authzSweep('http://127.0.0.1:1', {
    sessionA: { label: 'a', cookie: 'x=1' }, sessionB: { label: 'b', cookie: 'y=2' },
    candidates: [{ path: '/api/x/{id}', methods: ['GET'], refs: { a: ['1'], b: ['2'] } }],
    timeout: 250,
  });
  assert.equal(res.ok, true, 'honest inconclusive, not a crash');
  assert.equal(res.results[0].read.verdict, 'inconclusive');
  assert.equal(res.summary.violations, 0);
  const bad = await authzSweep('not-a-url', { sessionA: { label: 'a', cookie: 'x' }, sessionB: { label: 'b', cookie: 'y' }, candidates: [] });
  assert.equal(bad.ok, false);
});
