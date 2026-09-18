// VARVEL — end-to-end breach test against a live demo target.
//
// Boots the "Acme Robotics" demo site (targets/demo-corp.mjs) on an ephemeral
// localhost port, points VARVEL's own native tools at it, and proves the scanner
// finds every planted exposure a real sloppy deploy would leak. This is the
// difference between unit-testing tools against mocks and demonstrating the
// platform actually *breaches* a realistic target end to end.
//
// Fully hermetic: the target lives and dies inside this process, localhost only.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createDemoTarget } from '../targets/demo-corp.mjs';
import { recon } from '../tools/recon.mjs';
import { webScan, DEFAULT_PATHS } from '../tools/webscan.mjs';
import { analyzeHttp } from '../tools/httpmethods.mjs';

let server, PORT, base;

before(async () => {
  server = createDemoTarget();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  PORT = server.address().port;
  base = `http://127.0.0.1:${PORT}`;
});
after(() => server && server.close());

// Raw node:http helper (deliberately NOT fetch/undici — undici's async handles crash
// libuv on Windows under --test-force-exit).
function httpReq(method, path, body) {
  const data = body != null ? JSON.stringify(body) : null;
  return new Promise((resolve, reject) => {
    const req = http.request(base + path, { method, headers: data ? { 'content-type': 'application/json' } : {} }, (r) => {
      let b = ''; r.on('data', (c) => (b += c)); r.on('end', () => resolve({ status: r.statusCode, body: b }));
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

test('recon fingerprints the demo web service (port + server banner)', async () => {
  const s = await recon(['127.0.0.1'], { ports: [PORT], timeout: 2000, webPorts: new Set([PORT]) });
  assert.equal(s.hosts.length, 1, 'the one live host is discovered');
  const host = s.hosts[0];
  const web = host.services.find((x) => x.name === 'http');
  assert.ok(web, 'the port is identified as an http service');
  assert.equal(web.port, PORT);
  // Server header is authoritative -> nginx is fingerprinted as tech.
  assert.ok(host.tech.some((t) => /nginx/i.test(t.name)), 'nginx server banner is captured');
});

test('webscan recovers the planted exposures (.git / .env / db dump / dir listing / config)', async () => {
  // The demo's robots.txt reveals /backup; a real agent would add it. Here we hand
  // the tool the default wordlist plus the two backup paths for a deterministic run.
  const paths = [...DEFAULT_PATHS, '/backup/', '/backup/db.sql'];
  const r = await webScan(base, { paths, timeout: 2000, concurrency: 8 });

  assert.equal(r.softHost, false, 'the demo is not a catch-all-200 host (no soft-404 noise)');
  const titles = r.findings.map((f) => f.title.toLowerCase());
  const has = (needle) => titles.some((t) => t.includes(needle));

  assert.ok(has('.git'), 'exposed .git repository found');
  assert.ok(has('environment/secrets'), 'exposed .env secrets file found');
  assert.ok(has('database dump'), 'exposed /backup/db.sql database dump found');
  assert.ok(has('backup archive') || has('directory listing'), '/backup/ exposure found (the dedicated backup rule titles it "exposed backup archive", high — richer than the generic directory-listing med)');
  assert.ok(has('config file'), 'exposed config.json found');

  // A crit-severity secret leak must be present (the .env).
  assert.ok(r.findings.some((f) => f.sev === 'crit'), 'at least one critical exposure');
  // The admin portal is discovered as an endpoint (reachable), even if not a "finding".
  assert.ok(r.endpoints.some((e) => e.path === '/admin' && e.status === 200), '/admin portal reachable');
});

test('http analyzer catches the CORS hole on /api and the missing headers on the site', async () => {
  const api = await analyzeHttp(`${base}/api/users`, { timeout: 2000 });
  assert.equal(api.ok, true);
  assert.ok(
    api.findings.some((f) => f.ref === 'CORS-REFLECT' && f.sev === 'high'),
    'CORS reflects arbitrary Origin with credentials on /api',
  );

  const site = await analyzeHttp(`${base}/`, { timeout: 2000 });
  assert.equal(site.ok, true);
  const refs = site.findings.map((f) => f.ref);
  assert.ok(refs.includes('HDR-CSP'), 'missing Content-Security-Policy flagged');
  assert.ok(refs.includes('HDR-XFO'), 'missing X-Frame-Options flagged');
});

test('impact: the broken-access-control write changes site content and reverts cleanly', async () => {
  const h1 = async () => (await httpReq('GET', '/')).body.match(/<h1>([^<]*)<\/h1>/)[1];
  const post = async (banner) => JSON.parse((await httpReq('POST', '/admin/api/banner', { banner })).body);

  assert.equal(await h1(), 'Industrial automation, done right.', 'baseline banner');

  // unauthenticated write — proves modify access (the "change some info" the AI would do)
  const w = await post('BREACHED by VARVEL — authorized test');
  assert.equal(w.ok, true);
  assert.equal(await h1(), 'BREACHED by VARVEL — authorized test', 'homepage reflects the write');
  assert.ok(w.revert && w.revert.body && w.revert.body.banner, 'response carries a revert step (for cleanup)');

  // clean up: restore the original (OPSEC — leave the target clean)
  await post(w.revert.body.banner);
  assert.equal(await h1(), 'Industrial automation, done right.', 'reverted to original');

  // a non-string payload is rejected (400) — the endpoint validates input
  const bad = await httpReq('POST', '/admin/api/banner', { banner: 123 });
  assert.equal(bad.status, 400);
});

test('the full sweep produces a breach dossier (>= 6 corroborated findings)', async () => {
  const paths = [...DEFAULT_PATHS, '/backup/', '/backup/db.sql'];
  const web = await webScan(base, { paths, timeout: 2000 });
  const api = await analyzeHttp(`${base}/api/users`, { timeout: 2000 });
  const site = await analyzeHttp(`${base}/`, { timeout: 2000 });
  const total = web.findings.length + api.findings.length + site.findings.length;
  assert.ok(total >= 6, `expected a corroborated breach dossier, got ${total} findings`);
});
