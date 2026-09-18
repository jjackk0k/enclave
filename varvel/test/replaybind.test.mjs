// VARVEL replaybind tests — replayable-evidence binding (winner-copyables build,
// Tool 2). Hermetic: injected transports + a loopback 127.0.0.1 lab for the default
// transport. No live network, no ghost chain.
//   node --test varvel/test/replaybind.test.mjs
//
// Pinned: a plan binds every captured pair to assertions (status + marker); session
// cookies are REDACTED-BUT-REFERENCED (the secret NEVER lands in replay.json or
// replay.sh); control legs (unauth/garbage) are first-class legs; matrix captures
// without supplied request paths are skipped and NAMED, routes never invented; a
// replay PASSES only on reproduction, reports FIXED-OR-CHANGED honestly, and SKIPS
// (never guesses) unresolved credentials; the emitted bundle round-trips from disk.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  REPLAY_CAPS, markerFrom, roleOfLabel, planFromPairs, planFromMatrix,
  emitBundle, renderShell, runPlan, defaultTransport, makeCliResolver,
} from '../tools/replaybind.mjs';

const tmp = () => mkdtempSync(join(tmpdir(), 'varvel-rb-'));

// the authzsweep pair shape, as today's zomato work produces it
const PAIRS = [
  { label: 'read:own(A→A)', request: { method: 'GET', path: '/api/addr/101', headers: { cookie: '<session:A>' }, body: null }, response: { status: 200, body: '{"addresses":[{"id":101,"address":"1 YWCA Building"}]}' } },
  { label: 'read:cross(A→B)', request: { method: 'GET', path: '/api/addr/202', headers: { cookie: '<session:A>' }, body: null }, response: { status: 200, body: '{"addresses":[{"id":202,"address":"VICTIM DATA"}]}' } },
  { label: 'read:unauth-control(B)', request: { method: 'GET', path: '/api/addr/202', headers: { cookie: '<none>' }, body: null }, response: { status: 401, body: '{"message":"Unauthorized request! Please refresh the page."}' } },
];

test('markerFrom: JSON message wins; raw run fallback; empty is null', () => {
  assert.equal(markerFrom('{"message":"Unauthorized request! Please refresh the page."}'), 'Unauthorized request! Please refresh the page.');
  assert.equal(markerFrom('{"status":"failed"}'), 'failed');
  assert.equal(markerFrom('  <html>  Oops </html>'), '<html> Oops </html>');
  assert.equal(markerFrom(''), null);
  assert.ok(markerFrom('x'.repeat(400)).length <= REPLAY_CAPS.markerLen);
});

test('roleOfLabel names controls by what they control for', () => {
  assert.equal(roleOfLabel('read:unauth-control(B)'), 'control-unauth');
  assert.equal(roleOfLabel('B_garbage_uid'), 'control-garbage');
  assert.equal(roleOfLabel('seed:lowpriv'), 'seed');
  assert.equal(roleOfLabel('read:cross(A→B)'), 'observation');
});

test('planFromPairs: credentials redacted-but-referenced, controls first-class', () => {
  const r = planFromPairs(PAIRS, { base: 'https://www.zomato.com', program: 'zomato', finding: { title: 'IDOR — /api/addr/{id}', ref: 'authzsweep:/api/addr/{id}#idor', sev: 'high' }, now: '2026-08-31T12:00:00Z' });
  assert.equal(r.ok, true);
  const p = r.plan;
  assert.equal(p.requests.length, 3);
  assert.equal(p.controls, 1);
  assert.equal(p.base, 'https://www.zomato.com');
  // observation legs carry the session reference, never the secret
  assert.deepEqual(p.requests[1].credential, { kind: 'session-cookie', header: 'cookie', ref: 'A' });
  assert.equal(p.requests[1].expect.status, 200);
  assert.equal(p.requests[1].expect.bodyIncludes, null, 'an array-only JSON body has no stable scalar marker — status-only assertion, honest');
  // the unauth control asserts its OWN capture (401 + message)
  assert.equal(p.requests[2].role, 'control-unauth');
  assert.equal(p.requests[2].credential, null);
  assert.equal(p.requests[2].expect.status, 401);
  assert.equal(p.requests[2].expect.bodyIncludes, 'Unauthorized request! Please refresh the page.');
  // nothing in the serialized plan can carry a cookie secret (there was none — the
  // capture was already redacted), and the reference survived intact
  assert.ok(JSON.stringify(p).includes('<session:A>') === false, 'the marker form is converted to a structured reference');
  assert.equal(planFromPairs([], { base: 'https://x' }).error, 'no-pairs');
  assert.equal(planFromPairs(PAIRS, { base: 'not a url' }).error, 'bad-base');
});

test('planFromMatrix formalizes matrix.json captures; missing paths skipped and NAMED', () => {
  const matrix = {
    B_as_A: { http: 200, body: '{"status":"failed","message":"Something went wrong, please try again."}' },
    unauth_as_A: { http: 401, body: '{"message":"Unauthorized request! Please refresh the page."}' },
    mystery_leg: { http: 200, body: '{}' },
  };
  const r = planFromMatrix(matrix, {
    base: 'https://www.zomato.com', program: 'zomato',
    paths: { B_as_A: '/webroutes/cart?uid=447585412', unauth_as_A: '/webroutes/cart?uid=447585412' },
    sessionRefs: { B_as_A: 'b' },
    finding: { title: 'cart uid matrix' },
    now: '2026-08-31T12:00:00Z',
  });
  assert.equal(r.ok, true);
  assert.equal(r.plan.requests.length, 2);
  assert.deepEqual(r.plan.skipped, [{ key: 'mystery_leg', reason: 'no request path supplied for this capture — the matrix stores responses only; routes are never invented' }]);
  assert.equal(r.plan.requests[0].role, 'observation');
  assert.equal(r.plan.requests[0].credential.ref, 'b');
  assert.equal(r.plan.requests[1].role, 'control-unauth');
  assert.equal(r.plan.requests[1].expect.bodyIncludes, 'Unauthorized request! Please refresh the page.');
  assert.equal(planFromMatrix(matrix, { base: 'https://x', paths: {} }).error, 'no-usable-captures');
});

test('emitBundle writes replay.json + replay.sh; secrets never inlined; round-trips', async () => {
  const dir = tmp();
  const { plan } = planFromPairs(PAIRS, { base: 'https://www.zomato.com', program: 'zomato', finding: { title: 'IDOR', ref: 'r1' }, now: '2026-08-31T12:00:00Z' });
  const b = emitBundle(plan, { outDir: join(dir, 'bundle') });
  assert.equal(b.ok, true);
  const sh = readFileSync(join(dir, 'bundle', 'replay.sh'), 'utf8');
  assert.match(sh, /socks5h:\/\/10\.64\.0\.1:1080/, 'the ghost chain is baked in');
  assert.match(sh, /X-HackerOne: varvel/, 'the attestation header is baked in');
  assert.match(sh, /CRED_A=/, 'the credential is a documented var');
  assert.match(sh, /print-cookie/, 'the var documents its broker resolution');
  assert.ok(!sh.includes('0b21b927'), 'no cookie material in the script');
  // round-trip: the plan on disk is the plan that runs
  const disk = JSON.parse(readFileSync(join(dir, 'bundle', 'replay.json'), 'utf8'));
  assert.equal(disk.kind, 'varvel-replay-bundle');
  const r = await runPlan(disk, {
    transport: async ({ url, headers }) => {
      if (url.endsWith('/api/addr/202')) return headers.cookie === 'sess=LIVE' ? { status: 200, body: '{"addresses":[{"id":202,"address":"VICTIM DATA"}]}' } : { status: 401, body: '{"message":"Unauthorized request! Please refresh the page."}' };
      return { status: 200, body: '{"addresses":[{"id":101}]}' };
    },
    resolveCredential: (ref) => (ref === 'A' ? 'sess=LIVE' : null),
  });
  assert.equal(r.verdict, 'REPRODUCED');
  assert.equal(r.summary.reproduced, 3);
});

test('runPlan: fixed-or-changed is honest; unresolved credentials SKIP, never guess', async () => {
  const { plan } = planFromPairs(PAIRS, { base: 'https://www.zomato.com', finding: { title: 'IDOR' } });
  // the target PATCHED the bug: cross read now 403s
  const r = await runPlan(plan, {
    transport: async ({ url, headers }) => {
      if (url.endsWith('/202')) return headers.cookie ? { status: 403, body: '{"message":"Forbidden"}' } : { status: 401, body: '{"message":"Unauthorized request! Please refresh the page."}' };
      return { status: 200, body: '{"addresses":[{"id":101}]}' };
    },
    resolveCredential: () => 'sess=LIVE',
  });
  assert.equal(r.verdict, 'FIXED-OR-CHANGED');
  const cross = r.legs.find((l) => l.label === 'read:cross(A→B)');
  assert.equal(cross.outcome, 'fixed-or-changed');
  assert.ok(cross.assertions.some((a) => a.kind === 'status' && !a.ok));

  // no resolver → the session legs skip, named
  const r2 = await runPlan(plan, { transport: async () => ({ status: 401, body: '{"message":"Unauthorized request! Please refresh the page."}' }) });
  assert.equal(r2.summary.skipped, 2);
  assert.equal(r2.summary.reproduced, 1, 'only the credential-free control leg ran');
  assert.equal(r2.verdict, 'INCOMPLETE', 'partial verification is named, never inflated');
  assert.match(r2.legs[0].reason, /never guessed/);

  // transport failure → leg unverified, not silently failed
  const r3 = await runPlan(plan, { transport: async () => null, resolveCredential: () => 'sess=X' });
  assert.equal(r3.legs[0].outcome, 'transport-failed');
});

test('defaultTransport hits a loopback lab with the attestation header; never throws', async () => {
  const seen = [];
  const srv = http.createServer((req, res) => {
    seen.push({ url: req.url, h1: req.headers['x-hackerone'], cookie: req.headers.cookie || null });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"message":"lab ok"}');
  });
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const base = `http://127.0.0.1:${srv.address().port}`;
    const t = defaultTransport({ timeoutMs: 3000 });
    const res = await t({ method: 'GET', url: base + '/x', headers: { cookie: 'sess=LIVE' } });
    assert.equal(res.status, 200);
    assert.equal(seen[0].h1, 'varvel');
    assert.equal(seen[0].cookie, 'sess=LIVE');
    const dead = await t({ method: 'GET', url: 'http://127.0.0.1:1/none' });
    assert.equal(dead, null);
  } finally { await new Promise((r) => srv.close(r)); }
});

test('makeCliResolver: env wins, then the broker store file', () => {
  const dir = tmp();
  writeFileSync(join(dir, 'zomato-a.json'), JSON.stringify({ v: 1, program: 'zomato', label: 'a', session: { cookies: [{ name: 'PHPSESSID', value: 'FROM-STORE', domain: '.zomato.com' }] } }));
  const old = process.env.VARVEL_SESSIONS_DIR;
  process.env.VARVEL_SESSIONS_DIR = dir;
  try {
    const resolveCred = makeCliResolver({ program: 'zomato' });
    process.env.REPLAY_CRED_X = 'FROM-ENV';
    assert.equal(resolveCred('x'), 'FROM-ENV', 'env override wins');
    assert.equal(resolveCred('a'), 'PHPSESSID=FROM-STORE', 'broker store resolves by program+label');
    assert.equal(resolveCred('zzz'), null, 'unknown refs resolve null — the leg will skip, honestly');
  } finally {
    delete process.env.REPLAY_CRED_X;
    if (old === undefined) delete process.env.VARVEL_SESSIONS_DIR; else process.env.VARVEL_SESSIONS_DIR = old;
  }
});

test('renderShell escapes single quotes in markers/bodies', () => {
  const { plan } = planFromPairs([{ label: 'read:own(A→A)', request: { method: 'POST', path: '/x', headers: {}, body: '{"t":"it\'s"}' }, response: { status: 200, body: "it's alive" } }], { base: 'https://x.example', finding: {} });
  const sh = renderShell(plan);
  assert.match(sh, /it'\\''s/, 'shell-quoted safely');
});
