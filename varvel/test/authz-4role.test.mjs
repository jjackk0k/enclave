// VARVEL authzsweep 4-role tests — the N-account generalization of the two-account
// authorization oracle, plus the victim-object seeding hook (2026-08-30).
//   node --test varvel/test/authz-4role.test.mjs
//
// Pinned: the FULL CROSS PRODUCT of provisioned sessions replays read-only per
// candidate (a vuln visible ONLY to the lowpriv role can no longer hide behind the
// owner/member pair); exactly-two-sessions behavior stays bit-identical (the legacy
// suite passes unchanged — see test/authzsweep.test.mjs); candidates may declare
// per-account-label seeds that provision one object before replay (honest authz.seed
// events); a failed seed degrades the candidate to 'inconclusive' — refs are never
// fabricated.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { authzSweep, sanitizeAuthzCfg, synthesizeCandidates, harvestExchanges } from '../tools/authzsweep.mjs';

// ——— a 3-role lab: owner/member/lowpriv sessions; the planted bug lets LOWPRIV
// read across tenants while owner↔member are blocked ———
function createRoleLab() {
  const DOCS = {
    'DOC-OWN': { id: 'DOC-OWN', owner: 'owner', body: 'owner tenant confidential' },
    'DOC-LOW': { id: 'DOC-LOW', owner: 'lowpriv', body: 'lowpriv tenant records' },
  };
  return http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const m = /^\/api\/doc\/([\w-]+)$/.exec(u.pathname);
    const role = { 'sess=owner': 'owner', 'sess=member': 'member', 'sess=lowpriv': 'lowpriv' }[req.headers.cookie || ''] || null;
    const json = (st, o) => { res.writeHead(st, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (!m) return json(404, { error: 'not found' });
    if (!role) return json(401, { error: 'authentication required' });
    const doc = DOCS[m[1]];
    if (!doc) return json(404, { error: 'not found' });
    if (role === 'lowpriv') return json(200, doc);               // <-- planted bug: lowpriv crosses tenants
    if (doc.owner !== role) return json(403, { error: 'forbidden' }); // owner/member: ownership enforced
    return json(200, doc);
  });
}

async function withServer(srv, fn) {
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try { return await fn(base); }
  finally { await new Promise((r) => srv.close(r)); }
}

const ROLE_SESSIONS = [
  { label: 'owner', cookie: 'sess=owner', role: 'owner' },
  { label: 'member', cookie: 'sess=member', role: 'member' },
  { label: 'lowpriv', cookie: 'sess=lowpriv', role: 'lowpriv' },
];
const ROLE_CANDIDATES = [{ path: '/api/doc/{id}', methods: ['GET'], refs: { a: ['DOC-OWN'], b: [], c: ['DOC-LOW'] } }];

test('sanitizeAuthzCfg: up to 4 accounts with optional role labels; invalid roles drop to null', () => {
  const c = sanitizeAuthzCfg({
    accounts: [
      { label: 'o', cookie: 'a=1', role: 'owner' },
      { label: 'm', cookie: 'a=2', role: 'member' },
      { label: 'l', cookie: 'a=3', role: 'lowpriv' },
      { label: 'x', cookie: 'a=4', role: 'superadmin' }, // not in the vocabulary
      { label: 'overflow', cookie: 'a=5' },              // beyond the 4-account cap
    ],
  });
  assert.ok(c);
  assert.equal(c.accounts.length, 4, 'capped at four accounts');
  assert.deepEqual(c.accounts.map((a) => a.role), ['owner', 'member', 'lowpriv', null], 'roles kept; unknown role → null');
});

test('authzSweep: 3-account cross product catches the vuln visible ONLY to lowpriv', () => withServer(createRoleLab(), async (base) => {
  const res = await authzSweep(base, { sessions: ROLE_SESSIONS, candidates: ROLE_CANDIDATES });
  assert.equal(res.ok, true);
  const r = res.results[0];
  assert.equal(r.read.verdict, 'idor', 'the lowpriv-only cross-read is caught by the cross product');
  assert.equal(r.read.direction, 'C→A', 'the winning direction is lowpriv reading the owner object');
  const dirs = Object.fromEntries(r.read.directions.map((d) => [d.direction, d.verdict]));
  assert.deepEqual(Object.keys(dirs).sort(), ['A→C', 'B→A', 'B→C', 'C→A'], 'every direction with a victim ref ran (unauth control retained per direction)');
  assert.equal(dirs['B→A'], 'enforced', 'member → owner stays blocked');
  assert.equal(dirs['C→A'], 'idor');
  assert.deepEqual(res.summary.accounts, ['owner', 'member', 'lowpriv']);
  assert.equal(res.summary.violations, 1);
}));

test('authzSweep: the SAME lab with only the owner/member pair clears — 2-account behavior unchanged', () => withServer(createRoleLab(), async (base) => {
  const res = await authzSweep(base, {
    sessionA: ROLE_SESSIONS[0], sessionB: ROLE_SESSIONS[1],
    candidates: [{ path: '/api/doc/{id}', methods: ['GET'], refs: { a: ['DOC-OWN'], b: [] } }],
  });
  assert.equal(res.ok, true);
  const r = res.results[0];
  assert.equal(r.read.verdict, 'enforced', 'the lowpriv-only bug is invisible to the pair — honestly enforced');
  assert.deepEqual(r.read.directions.map((d) => d.direction), ['B→A'], 'only the direction with a victim ref ran, exactly like the legacy pair');
  const pairLabels = r.pairs.map((p) => p.label);
  assert.deepEqual(pairLabels, ['read:cross(B→A)', 'read:unauth-control(A)'], 'the exact legacy request sequence');
  assert.equal(res.summary.violations, 0);
}));

// ——— victim-object seeding: POST provisions an object, the id is harvested from
// the response, then the replay proves the cross-tenant read ———
function createSeedLab({ seedStatus = 201 } = {}) {
  let n = 0;
  const items = { 'IT-BETA-1': { id: 'IT-BETA-1', owner: 'beta', title: 'beta records' } };
  return http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x');
    const who = { 'sess=alpha': 'alpha', 'sess=beta': 'beta' }[req.headers.cookie || ''] || null;
    const json = (st, o) => { res.writeHead(st, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (u.pathname === '/api/items' && req.method === 'POST') {
      if (!who) return json(401, { error: 'authentication required' });
      if (seedStatus >= 400) return json(seedStatus, { error: 'provisioning broken' }); // the failure lane
      const id = 'IT-SEEDED-' + (++n);
      items[id] = { id, owner: who, title: 'seeded object' };
      return json(201, items[id]);
    }
    const m = /^\/api\/items\/([\w-]+)$/.exec(u.pathname);
    if (m) {
      if (!who) return json(401, { error: 'authentication required' });
      const it = items[m[1]];
      if (!it) return json(404, { error: 'not found' });
      return json(200, it); // <-- planted bug: any session reads any item
    }
    return json(404, { error: 'not found' });
  });
}

test('authzSweep: victim-object seeding creates refs, then the replay proves idor', () => withServer(createSeedLab(), async (base) => {
  const logs = [];
  const res = await authzSweep(base, {
    sessions: [{ label: 'alpha', cookie: 'sess=alpha' }, { label: 'beta', cookie: 'sess=beta' }],
    candidates: [{
      path: '/api/items/{id}', methods: ['GET'],
      refs: { a: [], b: ['IT-BETA-1'] }, // alpha has NO object — the seed provisions one
      seed: { alpha: { method: 'POST', path: '/api/items', body: '{"title":"seeded"}' } },
    }],
    writes: true, // the seeding hook rides the write rung's enablement
    onLog: (l) => logs.push(l),
  });
  assert.equal(res.ok, true);
  const r = res.results[0];
  assert.equal(r.read.verdict, 'idor', 'the seeded object crosses tenants');
  const seed = logs.find((l) => l.type === 'authz.seed');
  assert.ok(seed && seed.ok === true && seed.account === 'alpha', 'authz.seed logged honestly');
  assert.match(seed.ref, /^IT-SEEDED-/, 'the harvested ref came from the seed response — not fabricated');
  assert.ok(r.pairs.some((p) => p.label === 'seed:alpha'), 'the seed request is in the evidence pairs');
  assert.ok(r.observation.some((o) => /victim-object seeding/.test(o)), 'seeding disclosed in the observation lane');
}));

test('authzSweep: seeding failure degrades the candidate to inconclusive — no crash, no fabricated refs', () => withServer(createSeedLab({ seedStatus: 500 }), async (base) => {
  const logs = [];
  const res = await authzSweep(base, {
    sessions: [{ label: 'alpha', cookie: 'sess=alpha' }, { label: 'beta', cookie: 'sess=beta' }],
    candidates: [{
      path: '/api/items/{id}', methods: ['GET'],
      refs: { a: [], b: ['IT-BETA-1'] },
      seed: { alpha: { method: 'POST', path: '/api/items', body: '{"title":"seeded"}' } },
    }],
    writes: true,
    onLog: (l) => logs.push(l),
  });
  assert.equal(res.ok, true, 'never throws');
  const r = res.results[0];
  assert.equal(r.read.verdict, 'inconclusive');
  assert.match(r.read.detail, /seeding failed/, 'the reason is named');
  assert.match(r.read.detail, /no refs fabricated/);
  assert.equal(r.read.direction, undefined, 'no differential ran on fabricated refs');
  assert.equal(res.summary.violations, 0, 'a failed seed files nothing');
  const seed = logs.find((l) => l.type === 'authz.seed');
  assert.ok(seed && seed.ok === false, 'the failed seed is on the record');
}));

test('authzSweep: writes/deletes/ladder stay on the FIRST pair only under a 3-role matrix', () => withServer(createSeedLab(), async (base) => {
  // three sessions; a write-capable candidate. The PATCH rung must fire as A→B only.
  const res = await authzSweep(base, {
    sessions: [{ label: 'alpha', cookie: 'sess=alpha' }, { label: 'beta', cookie: 'sess=beta' }, { label: 'gamma', cookie: 'sess=gamma' }],
    candidates: [{ path: '/api/items/{id}', methods: ['GET', 'PATCH'], refs: { a: ['IT-BETA-1'], b: ['IT-BETA-1'], c: [] } }],
    writes: true,
  });
  assert.equal(res.ok, true);
  const writePairs = res.results[0].pairs.filter((p) => /^write:|^delete:|^ladder:/.test(p.label));
  assert.ok(writePairs.every((p) => !/gamma|C→/.test(p.label)), 'no write-rung request ever rides the third session');
  assert.ok(writePairs.some((p) => p.label === 'write:cross(A→B)'), 'the write rung fired on the first pair');
}));
