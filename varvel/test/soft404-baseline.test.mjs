// VARVEL soft-404 baselining tests — the noise-flood killer (Build 1, 2026-08-30).
// Pinned: a local lab server with an SPA fallback (200 + login HTML for ANY unknown
// path) plus ONE real exposed file. The real one must file; every fallback-covered
// sensitive probe must NOT file and must be visibly debunked (soft404.match ledger).
//   node --test varvel/test/soft404-baseline.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { webScan } from '../tools/webscan.mjs';
import { vulnCheck } from '../tools/vulncheck.mjs';
import { simhash64, hamming64, lenBucket, makeBaseline, matchesBaseline } from '../engine/soft404.mjs';

const SPA_SHELL = `<!DOCTYPE html><html><head><title>Acme App — Sign in</title></head>
<body><div id="root"><form action="/login" method="POST">
<input name="email" type="email"/><input name="password" type="password"/>
</form><script src="/static/bundle.js"></script>
<script>fetch('/api/search?q=' + encodeURIComponent(location.hash.slice(1)));</script>
</body></html>`; // ~ the 7.6KB-class login shell every unknown path gets

// Lab server: SPA fallback everywhere, except one REAL exposed .svn/entries.
async function serveLab(realPath = '/.svn/entries', realBody = '12\n\ndir\n4242\n') {
  const hits = [];
  const srv = http.createServer((req, res) => {
    hits.push(req.url);
    if (req.url === realPath) { res.writeHead(200, { 'content-type': 'text/plain' }); res.end(realBody); return; }
    res.writeHead(200, { 'content-type': 'text/html' }); // the soft-404: 200 + login shell for ANY path
    res.end(SPA_SHELL);
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { srv, base: `http://127.0.0.1:${srv.address().port}`, hits };
}

test('simhash64: identical shells are distance 0, different artifacts are far', () => {
  const a = simhash64(SPA_SHELL), b = simhash64(SPA_SHELL + '\n<!-- nonce abc123 -->');
  assert.ok(hamming64(a, b) <= 10, 'near-identical fallback pages stay close');
  const real = simhash64('12\n\ndir\n4242\n');
  assert.ok(hamming64(a, real) > 10, 'a real artifact does NOT resemble the shell');
  assert.equal(lenBucket(7600), lenBucket(7900), 'same magnitude buckets together');
  assert.notEqual(lenBucket(200), lenBucket(7600), 'small artifact buckets apart');
});

test('makeBaseline: 2xx junk answers make a soft baseline; 404 junk does not', () => {
  const soft = makeBaseline([{ status: 200, body: SPA_SHELL }, { status: 200, body: SPA_SHELL }, { status: 200, body: SPA_SHELL }]);
  assert.equal(soft.soft, true);
  const hard = makeBaseline([{ status: 404, body: 'nope' }, { status: 404, body: 'nope' }]);
  assert.equal(hard.soft, false);
  assert.ok(matchesBaseline({ status: 200, body: SPA_SHELL }, soft), 'fallback page matches its own baseline');
  assert.ok(!matchesBaseline({ status: 200, body: '12\n\ndir\n4242\n' }, soft), 'real artifact does not match');
});

test('webscan: SPA fallback debunked, the ONE real .svn/entries still files', async () => {
  const { srv, base } = await serveLab();
  try {
    const res = await webScan(base, {
      paths: ['/.svn/entries', '/actuator/heapdump', '/actuator/env', '/server-status', '/backup.zip', '/.env', '/wp-config.php', '/db.sql'],
      timeout: 700,
    });
    assert.equal(res.softHost, true, 'soft-404 host detected');
    const paths = res.findings.map((f) => f.path);
    assert.deepEqual(paths, ['/.svn/entries'], 'ONLY the real exposure files');
    assert.equal(res.findings[0].soft404Baselined, true, 'survivor marked soft-404 baselined');
    const debunked = (res.soft404.matched || []).map((m) => m.path);
    for (const p of ['/actuator/heapdump', '/actuator/env', '/server-status', '/backup.zip', '/.env'])
      assert.ok(debunked.includes(p), `${p} visibly debunked, not silently dropped`);
    assert.ok(!debunked.includes('/.svn/entries'), 'the real exposure is NOT in the debunk ledger');
  } finally { srv.close(); }
});

test('vulncheck: baseline blocks the fallback flood, content-verified survivor files', async () => {
  // Real heapdump this time: binary HPROF magic, not the HTML shell.
  const { srv, base } = await serveLab('/actuator/heapdump', 'JAVA PROFILE 1.0.2\x00\x01\x02binary-dump');
  try {
    const res = await vulnCheck(base, { timeout: 700, maxProbes: 20 });
    const exp = res.vulnerabilities.filter((v) => !/^(hdr-|cookie-|version-)/.test(v.id)); // exposure-class only
    const ids = exp.map((v) => v.id);
    assert.ok(ids.includes('actuator-heapdump'), 'real heapdump files');
    for (const id of ['svn-entries', 'actuator-env', 'server-status', 'env-file'])
      assert.ok(!ids.includes(id), `${id} NOT filed against the SPA fallback`);
    const debunked = (res.soft404.matched || []).map((m) => m.path);
    for (const p of ['/.svn/entries', '/actuator/env', '/server-status', '/.env'])
      assert.ok(debunked.includes(p), `${p} logged as soft404.match`);
    assert.ok(!debunked.includes('/actuator/heapdump'), 'the real heapdump is not debunked');
    const hd = res.vulnerabilities.find((v) => v.id === 'actuator-heapdump');
    assert.equal(hd.soft404Baselined, true, 'survivor carries the baselined mark');
  } finally { srv.close(); }
});

test('webscan: on a HARD-404 host there is no baseline and real exposures still file', async () => {
  const hits = [];
  const srv = http.createServer((req, res) => {
    hits.push(req.url);
    if (req.url === '/server-status') { res.writeHead(200); res.end('<h1>Apache Server Status</h1>Scoreboard: ____'); return; }
    res.writeHead(404); res.end('not found');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const res = await webScan(base, { paths: ['/server-status', '/.env'], timeout: 700 });
    assert.equal(res.softHost, false, 'no catch-all here');
    assert.ok(res.findings.some((f) => f.path === '/server-status'), 'real server-status files');
    assert.equal(res.findings.some((f) => f.path === '/.env'), false, '404 .env does not file');
  } finally { srv.close(); }
});
