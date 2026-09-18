// VARVEL vulncheck tests — hermetic local servers, safe (localhost only).
//   node --test varvel/test/vulncheck.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { vulnCheck, PROBES, BODY_LEAKS } from '../tools/vulncheck.mjs';
import { makePacer } from '../engine/stealth.mjs';

const vc = (res, id) => res.vulnerabilities.filter((v) => v.id === id);

// Serve { '/path': { status?, headers?, body } } or a plain string body. Tracks hits.
async function serve(routes, rootHeaders = {}) {
  const hits = [];
  const srv = http.createServer((req, res) => {
    hits.push(req.url);
    const r = routes[req.url];
    if (r == null) { res.writeHead(404); res.end('not found'); return; }
    const o = typeof r === 'string' ? { body: r } : r;
    res.writeHead(o.status || 200, { 'content-type': 'text/html', ...rootHeaders, ...(o.headers || {}) });
    res.end(o.body || '');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { srv, base: `http://127.0.0.1:${srv.address().port}`, hits };
}

test('header audit: missing CSP/XFO/XCTO/Referrer-Policy reported; HSTS skipped on http', async () => {
  const { srv, base } = await serve({ '/': '<html>ok</html>' });
  try {
    const res = await vulnCheck(base, { timeout: 700 });
    assert.equal(vc(res, 'hdr-csp').length, 1);
    assert.equal(vc(res, 'hdr-xfo').length, 1);
    assert.equal(vc(res, 'hdr-xcto').length, 1);
    assert.equal(vc(res, 'hdr-hsts').length, 0, 'HSTS only meaningful on https');
    assert.equal(vc(res, 'hdr-csp')[0].confidence, 'confirmed');
    assert.ok(/^VC-\d+$/.test(vc(res, 'hdr-csp')[0].ref));
  } finally { srv.close(); }
});

test('header audit: present headers produce no findings; CSP frame-ancestors satisfies XFO', async () => {
  const { srv, base } = await serve({ '/': '<html>ok</html>' }, {
    'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
  });
  try {
    const res = await vulnCheck(base, { timeout: 700 });
    assert.equal(vc(res, 'hdr-csp').length, 0);
    assert.equal(vc(res, 'hdr-xfo').length, 0, 'frame-ancestors counts');
    assert.equal(vc(res, 'hdr-xcto').length, 0);
  } finally { srv.close(); }
});

test('cookie flags: a bare session cookie is reported with the missing flags named', async () => {
  const { srv, base } = await serve({ '/': { headers: { 'set-cookie': 'sid=abc123; Path=/' }, body: 'ok' } });
  try {
    const res = await vulnCheck(base, { timeout: 700 });
    const f = vc(res, 'cookie-flags');
    assert.equal(f.length, 1);
    assert.ok(/sid/.test(f[0].title));
    assert.ok(/HttpOnly/.test(f[0].title) && /SameSite/.test(f[0].title));
    assert.ok(!/Secure/.test(f[0].title), 'Secure not required on http');
  } finally { srv.close(); }
});

test('exposure probes: real .git/HEAD and .env are confirmed HIGH; catch-all impostors are not', async () => {
  const { srv, base } = await serve({
    '/': 'ok',
    '/.git/HEAD': 'ref: refs/heads/main\n',
    '/.env': 'DB_PASSWORD=hunter2\nAPI_KEY=xyz\n',
    '/.git/config': '<html><body>catch-all page</body></html>', // impostor: right path, wrong content
  });
  try {
    const res = await vulnCheck(base, { timeout: 700 });
    const git = vc(res, 'git-head');
    assert.equal(git.length, 1);
    assert.equal(git[0].sev, 'high');
    assert.ok(/ref: refs/.test(git[0].evidence), 'evidence carried');
    assert.equal(vc(res, 'env-file').length, 1);
    assert.equal(vc(res, 'git-config').length, 0, 'content verification rejects the impostor');
  } finally { srv.close(); }
});

test('CORS: reflected origin WITH credentials is medium; wildcard alone is info; silent is clean', async () => {
  // reflector
  const s1 = http.createServer((req, res) => {
    const h = {};
    if (req.headers.origin) { h['access-control-allow-origin'] = req.headers.origin; h['access-control-allow-credentials'] = 'true'; }
    res.writeHead(200, h); res.end('ok');
  });
  await new Promise((r) => s1.listen(0, '127.0.0.1', r));
  const b1 = `http://127.0.0.1:${s1.address().port}`;
  try {
    const res = await vulnCheck(b1, { timeout: 700 });
    assert.equal(vc(res, 'cors-reflect-cred').length, 1);
    assert.equal(vc(res, 'cors-reflect-cred')[0].sev, 'medium');
  } finally { s1.close(); }

  const { srv, base } = await serve({ '/': { headers: { 'access-control-allow-origin': '*' }, body: 'ok' } });
  try {
    const res = await vulnCheck(base, { timeout: 700 });
    assert.equal(vc(res, 'cors-reflect-cred').length, 0);
    assert.equal(vc(res, 'cors-wildcard').length, 1);
    assert.equal(vc(res, 'cors-wildcard')[0].sev, 'info');
  } finally { srv.close(); }
});

test('body leaks: SQL error is medium, stack trace is low; checked on root AND discovered pages', async () => {
  const { srv, base } = await serve({
    '/': 'ok',
    '/item?id=1': "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near ''",
    '/whoops': 'Traceback (most recent call last):\n  File "app.py", line 4, in <module>',
  });
  try {
    const res = await vulnCheck(base, { timeout: 700, pagePaths: ['/item?id=1', '/whoops'] });
    assert.equal(vc(res, 'sql-mysql').length, 1);
    assert.equal(vc(res, 'sql-mysql')[0].sev, 'medium');
    assert.equal(vc(res, 'sql-mysql')[0].path, '/item?id=1');
    assert.equal(vc(res, 'stack-python').length, 1);
  } finally { srv.close(); }
});

test('version disclosure: advertised server is info; EOL component escalates to medium', async () => {
  const { srv, base } = await serve({ '/': 'ok' }, { server: 'Apache/1.3.42 (Unix)', 'x-powered-by': 'PHP/4.4.9' });
  try {
    const res = await vulnCheck(base, { timeout: 700 });
    assert.equal(vc(res, 'version-disclosure').length, 1);
    assert.equal(vc(res, 'version-disclosure')[0].sev, 'info');
    assert.equal(vc(res, 'version-outdated').length, 1);
    assert.equal(vc(res, 'version-outdated')[0].sev, 'medium');
  } finally { srv.close(); }
});

test('results are severity-sorted (high first) and budget-bounded', async () => {
  const { srv, base, hits } = await serve({
    '/': 'ok',
    '/.git/HEAD': 'ref: refs/heads/main\n',
    '/phpinfo.php': '<title>phpinfo()</title>',
  });
  try {
    const res = await vulnCheck(base, { timeout: 700, maxProbes: 6 });
    assert.ok(hits.length <= 6 + 3, 'request budget honored (+3 soft-404 baseline probes, counted but outside the probe budget), got ' + hits.length);
    const r2 = await vulnCheck(base, { timeout: 700 });
    const sevs = r2.vulnerabilities.map((v) => v.sev);
    const order = ['info', 'low', 'medium', 'high', 'critical'];
    const idx = sevs.map((s) => order.indexOf(s));
    assert.ok(idx.every((v, i) => i === 0 || idx[i - 1] >= v), 'sorted high→info');
    assert.equal(r2.vulnerabilities[0].sev, 'high', 'git exposure first');
  } finally { srv.close(); }
});

test('robustness: bad base throws TypeError; dead server resolves empty', async () => {
  await assert.rejects(() => vulnCheck('nope'), TypeError);
  const res = await vulnCheck('http://127.0.0.1:1', { timeout: 300 });
  assert.equal(res.vulnerabilities.length, 0);
  assert.equal(res.requests > 0, true, 'attempts were made and survived');
});

test('stealth-aware: injected pacer is honored; curated probe count stays small', async () => {
  const { srv, base } = await serve({ '/': 'ok' });
  try {
    const pacer = makePacer('normal');
    let paced = 0;
    const spy = { pace: async () => { paced++; return pacer.pace(); }, penalize: (...a) => pacer.penalize(...a), profile: pacer.profile, requestHeaders: (o) => pacer.requestHeaders(o) };
    const res = await vulnCheck(base, { timeout: 700, pacer: spy });
    assert.ok(paced >= res.requests, 'every request paced');
    assert.equal(res.stealth, 'normal');
    assert.ok(PROBES.length <= 20, 'curated, not a wordlist: ' + PROBES.length + ' probes');
    assert.ok(BODY_LEAKS.length >= 6, 'leak-pattern coverage present');
  } finally { srv.close(); }
});
