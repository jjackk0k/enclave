// VARVEL idorprobe tests — pure classifier + live differential against chainyard.
//   node --test varvel/test/idorprobe.test.mjs
//
// The decoy lesson, pinned: the scanner-grade heuristic (naiveIdorFlag) flags ALL
// THREE object shapes on chainyard; the differential oracle sorts them into
// idor / enforced / public. The control read is what earns the claim.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { classifyIdor, naiveIdorFlag, idorProbe } from '../tools/idorprobe.mjs';
import { createChainyardTarget } from '../targets/chainyard.mjs';

// ——— pure classifier ———

test('classifyIdor: cross-tenant 200 + refused control + tenant-distinct body = idor', () => {
  const r = classifyIdor({
    own: { status: 200, body: '{"id":1001,"tenant":"alice"}' },
    other: { status: 200, body: '{"id":1002,"tenant":"bob"}' },
    unauth: { status: 401, body: 'unauthorized' },
  });
  assert.equal(r.verdict, 'idor');
});

test('classifyIdor: cross-tenant 404/403 = enforced (indistinguishable from a miss)', () => {
  for (const status of [403, 404]) {
    const r = classifyIdor({
      own: { status: 200, body: '{"id":1001}' },
      other: { status, body: 'not found' },
      unauth: { status: 401, body: 'unauthorized' },
    });
    assert.equal(r.verdict, 'enforced', `status ${status}`);
  }
});

test('classifyIdor: identical unauth body = public (the decoy the control kills)', () => {
  const r = classifyIdor({
    own: { status: 200, body: '{"id":3001}' },
    other: { status: 200, body: '{"id":3002,"title":"studio"}' },
    unauth: { status: 200, body: '{"id":3002,"title":"studio"}' },
  });
  assert.equal(r.verdict, 'public');
  assert.match(r.detail, /public object/);
});

test('classifyIdor: no control read = inconclusive (no claim without a control)', () => {
  const r = classifyIdor({
    own: { status: 200, body: '{"id":1001,"tenant":"alice"}' },
    other: { status: 200, body: '{"id":1002,"tenant":"bob"}' },
    unauth: null,
  });
  assert.equal(r.verdict, 'inconclusive');
  // control refused but body indistinguishable from own → cannot attribute tenancy
  const r2 = classifyIdor({
    own: { status: 200, body: 'same' },
    other: { status: 200, body: 'same' },
    unauth: { status: 403, body: 'forbidden' },
  });
  assert.equal(r2.verdict, 'inconclusive');
  // missing cross-tenant response entirely
  assert.equal(classifyIdor({ own: { status: 200, body: 'x' }, other: null, unauth: null }).verdict, 'inconclusive');
});

test('naiveIdorFlag is the scanner heuristic: any authed 200 flags', () => {
  assert.equal(naiveIdorFlag({ own: { status: 200, body: 'anything' } }), true);
  assert.equal(naiveIdorFlag({ own: { status: 403, body: 'no' } }), false);
  assert.equal(naiveIdorFlag({ own: null }), false);
});

// ——— live differential against the chainyard lab ———

async function withYard(fn) {
  const srv = createChainyardTarget();
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try { return await fn(base); }
  finally { await new Promise((r) => srv.close(r)); }
}

test('idorProbe sorts the three chainyard families; naive flags all three', () => withYard(async (base) => {
  // log in as the published tenant (alice) — same path the composed chain takes
  const login = await new Promise((resolve) => {
    const req = http.request(base + '/login', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' } }, (res) => {
      let b = ''; res.on('data', (d) => { b += d; });
      res.on('end', () => resolve({ status: res.statusCode, cookie: (res.headers['set-cookie'] || [''])[0].split(';')[0] }));
    });
    req.on('error', () => resolve(null));
    req.end('user=alice&pass=tenant-demo-2026');
  });
  assert.ok(login && login.cookie, 'tenant session established');

  const bookings = await idorProbe(base, { pathTemplate: '/api/bookings/{id}', ownId: 1001, otherId: 1002, cookie: login.cookie });
  assert.equal(bookings.verdict, 'idor', 'bookings: no ownership check — the real IDOR');
  assert.equal(bookings.naiveWouldFlag, true);

  const invoices = await idorProbe(base, { pathTemplate: '/api/invoices/{id}', ownId: 2001, otherId: 2002, cookie: login.cookie });
  assert.equal(invoices.verdict, 'enforced', 'invoices: ownership enforced, cross-tenant 404');
  assert.equal(invoices.naiveWouldFlag, true, 'naive heuristic flags the decoy too');

  const listings = await idorProbe(base, { pathTemplate: '/api/listings/{id}', ownId: 3001, otherId: 3002, cookie: login.cookie });
  assert.equal(listings.verdict, 'public', 'listings: identical unauth body — public, not IDOR');
  assert.equal(listings.naiveWouldFlag, true, 'naive heuristic flags the second decoy too');

  // the discrimination proof, compressed: one scanner heuristic, three flags;
  // one differential oracle, three distinct verdicts
  const naiveFlags = [bookings, invoices, listings].map((r) => r.naiveWouldFlag);
  const verdicts = [bookings, invoices, listings].map((r) => r.verdict);
  assert.deepEqual(naiveFlags, [true, true, true]);
  assert.deepEqual(verdicts, ['idor', 'enforced', 'public']);
}));

test('idorProbe never throws (unreachable base → honest inconclusive)', async () => {
  const r = await idorProbe('http://127.0.0.1:1', { pathTemplate: '/api/bookings/{id}', ownId: 1, otherId: 2, cookie: 'x=1', timeout: 300 });
  assert.equal(r.verdict, 'inconclusive');
  assert.equal(r.naiveWouldFlag, false);
});
