// VARVEL oob tests — the full loop on 127.0.0.1: server up, the oracle fires at
// a local "vulnerable" endpoint that fetches the canary, poll correlates →
// proven; the negative emits ZERO findings. Plus poll-API auth, the publicBaseUrl
// contract, scope fail-closed, budget honesty. No live network beyond loopback.
//   node --test varvel/test/oob.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { OobServer, oobProbe, hostAllowed, OOB_TEMPLATES } from '../tools/oob.mjs';

async function withServer(opts, fn) {
  const server = new OobServer(opts);
  const { base } = await server.start();
  server.publicBaseUrl = server.publicBaseUrl || base; // lab: the loopback base plays "public"
  try { return await fn(server, base); }
  finally { await server.close(); }
}

// a local "vulnerable" app: /fetch?url= does an outbound fetch (the SSRF sink);
// /nofetch?url= ignores it (the control)
function createVulnApp(counters) {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/fetch') {
      counters.fetch++;
      const target = u.searchParams.get('url');
      try {
        const t = new URL(target);
        http.get({ hostname: t.hostname, port: t.port, path: t.pathname + t.search, timeout: 2000 }, (r) => { r.resume(); }).on('error', () => {});
      } catch { /* unparseable target — the app fails quietly, like real ones */ }
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, note: 'response body carries NO signal — blind by construction' }));
    }
    if (u.pathname === '/nofetch') {
      counters.nofetch++;
      res.writeHead(200);
      return res.end('ok');
    }
    res.writeHead(404); res.end();
  });
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  return srv;
}

test('oobProbe: SSRF loop — canary fired, target calls back, verdict proven', async () => {
  const counters = { fetch: 0, nofetch: 0 };
  const vuln = createVulnApp(counters);
  await new Promise((r) => vuln.listen(0, '127.0.0.1', r));
  const vulnBase = `http://127.0.0.1:${vuln.address().port}`;
  try {
    const logs = [];
    await withServer({ host: '127.0.0.1', port: 0, onLog: (l) => logs.push(l) }, async (server) => {
      const r = await oobProbe(vulnBase, {
        inject: { method: 'GET', path: '/fetch?url={PAYLOAD}' },
        kinds: ['ssrf'], server, deadlineMs: 4000, pollMs: 100, onLog: (l) => logs.push(l),
      });
      assert.equal(r.ok, true, r.error);
      assert.equal(r.findings.length, 1, 'the callback correlated — one proven finding');
      const f = r.findings[0];
      assert.equal(f.verdict, 'proven');
      assert.equal(f.kind, 'ssrf');
      assert.equal(f.callback.canary, f.canary, 'the hit is attributed to THIS probe');
      assert.match(f.request.url, /\/fetch\?url=/);
      assert.ok(f.payload.includes(f.canary), 'the journal shows exactly which payload caused the hit');
      assert.equal(counters.fetch, 1);
      assert.ok(logs.some((l) => l.type === 'oob.hit'), 'the listener logged the callback');
      assert.ok(logs.some((l) => l.type === 'oob.proven'));
    });
  } finally { await new Promise((r) => vuln.close(r)); }
});

test('oobProbe: negative — no callback, verdict unproven, ZERO findings emitted', async () => {
  const counters = { fetch: 0, nofetch: 0 };
  const vuln = createVulnApp(counters);
  await new Promise((r) => vuln.listen(0, '127.0.0.1', r));
  const vulnBase = `http://127.0.0.1:${vuln.address().port}`;
  try {
    await withServer({ host: '127.0.0.1', port: 0 }, async (server) => {
      const r = await oobProbe(vulnBase, {
        inject: { method: 'GET', path: '/nofetch?url={PAYLOAD}' },
        kinds: ['ssrf'], server, deadlineMs: 800, pollMs: 100,
      });
      assert.equal(r.ok, true);
      assert.equal(counters.nofetch, 1, 'the probe WAS fired');
      assert.equal(r.probes.length, 1);
      assert.equal(r.probes[0].verdict, 'unproven', 'honest: fired, no callback');
      assert.equal(r.findings.length, 0, 'no callback, no report — that is the whole point');
    });
  } finally { await new Promise((r) => vuln.close(r)); }
});

test('OobServer: poll API requires the bearer token; correlate is exact-match only', () => withServer({}, async (server, base) => {
  const canary = server.mintCanary('test');
  // fire a callback through the path form
  await fetch(`${base}/c/${canary}/hook?x=1`, { method: 'POST', body: 'hello', headers: { 'content-type': 'text/plain' } });
  // unattributed noise hit — correlates to NOTHING
  await fetch(`${base}/some/random/path`);
  const corr = server.correlate(canary, 0);
  assert.equal(corr.hit, true);
  assert.equal(corr.hits[0].method, 'POST');
  assert.equal(corr.hits[0].body, 'hello');
  assert.equal(corr.hits[0].remoteAddr.includes('127.0.0.1'), true);
  assert.equal(server.correlate('vdeadbeefdeadbeef', 0).hit, false, 'an unknown canary finds nothing');
  // the HTTP poll API: 401 without the token, 200 with it
  const unauth = await fetch(`${base}/_oob/poll?canary=${canary}`);
  assert.equal(unauth.status, 401);
  const auth = await fetch(`${base}/_oob/poll?canary=${canary}`, { headers: { authorization: 'Bearer ' + server.authToken } });
  assert.equal(auth.status, 200);
  const j = await auth.json();
  assert.equal(j.hits.length, 1);
}));

test('OobServer: subdomain-form canary addressing via the Host header', () => withServer({}, async (server, base) => {
  const canary = server.mintCanary('dns-form');
  await new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port: server.port, path: '/x', headers: { host: `${canary}.oob.example` } }, (res) => { res.resume(); res.on('end', resolve); });
    req.end();
  });
  assert.equal(server.correlate(canary, 0).hit, true, 'the <canary>.<oob-host> form attributes by the first label');
}));

test('OobServer.urlFor: publicBaseUrl unset fails with the clear deployment error', () => {
  const bare = new OobServer({});
  assert.throws(() => bare.urlFor('v1234567890abcdef'), /publicBaseUrl unset.*publicly reachable base/s);
});

test('oobProbe: scope fail-closed — outside the signed scope, nothing is dialed', async () => {
  const counters = { fetch: 0, nofetch: 0 };
  const vuln = createVulnApp(counters);
  await new Promise((r) => vuln.listen(0, '127.0.0.1', r));
  try {
    await withServer({}, async (server) => {
      const r = await oobProbe(`http://127.0.0.1:${vuln.address().port}`, {
        inject: { path: '/fetch?url={PAYLOAD}' }, kinds: ['ssrf'], server,
        scope: { hosts: ['acme.io'] },
      });
      assert.equal(r.ok, false);
      assert.match(r.error, /outside the signed scope/);
      assert.equal(counters.fetch, 0, 'the target never saw a request');
      // path-prefix confinement rides the same gate
      const r2 = await oobProbe(`http://127.0.0.1:${vuln.address().port}`, {
        inject: { path: '/fetch?url={PAYLOAD}' }, kinds: ['ssrf'], server,
        pathPrefixes: ['/allowed/'],
      });
      assert.equal(r2.ok, false);
      assert.equal(counters.fetch, 0);
    });
  } finally { await new Promise((r) => vuln.close(r)); }
});

test('oobProbe: budget exhaustion + never throws on unreachable target', () => withServer({}, async (server) => {
  const logs = [];
  const r = await oobProbe('http://127.0.0.1:1', {
    inject: { path: '/fetch?url={PAYLOAD}' }, kinds: ['ssrf'], server,
    timeout: 250, deadlineMs: 300, pollMs: 100, budget: { maxRequests: 1 }, onLog: (l) => logs.push(l),
  });
  assert.equal(r.ok, true, 'unreachable target is an honest unproven, not a crash');
  assert.equal(r.findings.length, 0);
  assert.equal(r.probes[0].response, null);
  const r2 = await oobProbe('not-a-url', { inject: { path: '/x{PAYLOAD}' }, server });
  assert.equal(r2.ok, false);
}));

test('templates: every default template carries the canary marker', () => {
  for (const kind of ['ssrf', 'xxe', 'ssti', 'blind-xss']) {
    assert.ok(Array.isArray(OOB_TEMPLATES[kind]) && OOB_TEMPLATES[kind].length, kind);
    assert.ok(OOB_TEMPLATES[kind].some((t) => t.includes('{CANARY_URL}') || t.includes('{CANARY_HOST}')), kind + ' carries a canary marker');
  }
  assert.equal(hostAllowed('a.acme.io', { hosts: ['acme.io'] }), true);
  assert.equal(hostAllowed('evil.io', { hosts: ['acme.io'] }), false);
});
