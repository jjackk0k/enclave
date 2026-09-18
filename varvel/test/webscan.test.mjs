// VARVEL webscan tests — hermetic local servers, safe (localhost only).
//   node --test varvel/test/webscan.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { webScan, DEFAULT_PATHS } from '../tools/webscan.mjs';

// Start a server from a route map; unknown paths -> `fallback` (default 404).
async function serve(routes, fallback = { status: 404, body: 'not found' }) {
  const hits = [];
  const srv = http.createServer((req, res) => {
    hits.push(req.url);
    const r = routes[req.url] || (typeof fallback === 'function' ? fallback(req) : fallback);
    res.writeHead(r.status, r.headers || {});
    res.end(r.body || '');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { srv, port: srv.address().port, base: `http://127.0.0.1:${srv.address().port}`, hits };
}
const finding = (res, re) => res.findings.find((f) => re.test(f.path));

test('real .git exposure flagged; .gitignore not; breadth covered', async () => {
  const { srv, base } = await serve({
    '/.git/HEAD': { status: 200, body: 'ref: refs/heads/main' },
    '/.git/': { status: 200, body: '<h1>Index of /.git</h1><a href="../">..</a>' },
    '/.git/index': { status: 200, body: 'DIRC\x00\x00' },
    '/.gitignore': { status: 200, body: 'node_modules\n' },
  });
  try {
    const res = await webScan(base, { paths: ['/.git/HEAD', '/.git/', '/.git/index', '/.gitignore'], timeout: 700 });
    assert.ok(finding(res, /\.git\/HEAD/) && finding(res, /\.git\/HEAD/).sev === 'high', '.git/HEAD flagged high');
    assert.ok(finding(res, /\.git\/$/), '.git/ dir flagged');
    assert.equal(finding(res, /gitignore/), undefined, '.gitignore NOT flagged');
  } finally { srv.close(); }
});

test('P0-1 soft-404: catch-all 200 server produces NO phantom crit findings', async () => {
  const { srv, base } = await serve({}, { status: 200, body: '<h1>Page not found</h1>' }); // everything is 200
  try {
    const res = await webScan(base, { paths: ['/.env', '/.aws/credentials', '/.git/HEAD', '/wp-config.php'], timeout: 700 });
    assert.equal(res.softHost, true, 'soft-404 host detected');
    assert.equal(res.findings.length, 0, 'no phantom findings on a catch-all-200 app');
  } finally { srv.close(); }
});

test('P0-2 redirect: 3xx to slash form is NOT flagged as an exposure (but is discovered)', async () => {
  const { srv, base } = await serve({ '/backup': { status: 301, headers: { location: '/backup/' } } });
  try {
    const res = await webScan(base, { paths: ['/backup'], timeout: 700 });
    assert.equal(finding(res, /backup/), undefined, '301 not flagged as a dump');
    assert.ok(res.endpoints.some((e) => e.path === '/backup' && e.status === 301), 'still discovered');
  } finally { srv.close(); }
});

test('P0-3 scope escape: a //other-host path is never requested', async () => {
  const other = await serve({ '/secret': { status: 200, body: 'leak' } });
  const target = await serve({});
  try {
    const res = await webScan(target.base, { paths: [`//127.0.0.1:${other.port}/secret`, '/'], timeout: 700 });
    assert.equal(other.hits.length, 0, 'the other host received ZERO requests');
    assert.ok(!res.endpoints.some((e) => /secret/.test(e.path)), 'off-origin path excluded from results');
  } finally { other.srv.close(); target.srv.close(); }
});

test('P1 broadened classifiers: .hg, .aws/config, actuator subpaths, wp-config, *.sql', async () => {
  const { srv, base } = await serve({
    '/.hg/store/00manifest.i': { status: 200, body: '\x00\x00' },
    '/.aws/config': { status: 200, body: '[profile default]\nregion=us-east-1' },
    '/actuator/heapdump': { status: 200, body: 'JAVA PROFILE 1.0.2\x00\x01\x02hprof-bytes' }, // real heapdumps are binary HPROF — a JSON look-alike no longer passes (soft-404 hardening)
    '/actuator/health': { status: 200, body: '{"status":"UP"}' },
    '/wp-config.php': { status: 200, body: "<?php define('DB_PASSWORD','hunter2');" },
    '/database.sql': { status: 200, body: 'INSERT INTO users VALUES' },
  });
  try {
    const res = await webScan(base, { paths: ['/.hg/store/00manifest.i', '/.aws/config', '/actuator/heapdump', '/actuator/health', '/wp-config.php', '/database.sql'], timeout: 700 });
    assert.ok(finding(res, /\.hg/), '.hg flagged');
    assert.ok(finding(res, /\.aws\/config/), '.aws/config flagged');
    assert.equal(finding(res, /heapdump/).sev, 'high', 'actuator heapdump high');
    assert.equal(finding(res, /health/), undefined, 'actuator/health benign');
    assert.ok(['crit', 'high'].includes(finding(res, /wp-config/).sev), 'wp-config high/crit, not low');
    assert.ok(finding(res, /database\.sql/), 'database.sql flagged');
  } finally { srv.close(); }
});

test('P1-7 discovery: 405 (GET-rejecting endpoint) is discovered', async () => {
  const { srv, base } = await serve({ '/graphql': { status: 405, body: 'method not allowed' } });
  try {
    const res = await webScan(base, { paths: ['/graphql'], timeout: 700 });
    assert.ok(res.endpoints.some((e) => e.path === '/graphql' && e.status === 405));
  } finally { srv.close(); }
});

test('P2 anchored regexes: substring paths do NOT false-positive', async () => {
  const { srv, base } = await serve({
    '/screenshot.envelope.png': { status: 200, body: 'PNG' },
    '/how-to-backup': { status: 200, body: 'blog post' },
    '/backups/index.html': { status: 200, body: 'html' },
    '/debugger-tutorial': { status: 200, body: 'tutorial' },
    '/product-metrics-dashboard': { status: 200, body: 'charts' },
  });
  try {
    const res = await webScan(base, { paths: ['/screenshot.envelope.png', '/how-to-backup', '/backups/index.html', '/debugger-tutorial', '/product-metrics-dashboard'], timeout: 700 });
    assert.equal(res.findings.length, 0, 'no false positives from substring matches');
  } finally { srv.close(); }
});

test('P2-1 dirListing: positive on Apache/Python, negative on benign title', async () => {
  const { srv, base } = await serve({
    '/apache/': { status: 200, body: '<h1>Index of /apache</h1><a href="../">Parent</a>' },
    '/py/': { status: 200, body: '<title>Directory listing for /py</title><a href="x">x</a>' },
    '/blog': { status: 200, body: '<title>Index of Forbidden Books - my blog</title><p>welcome</p>' },
  });
  try {
    const res = await webScan(base, { paths: ['/apache/', '/py/', '/blog'], timeout: 700 });
    assert.ok(finding(res, /apache/) && finding(res, /py/), 'real listings flagged');
    assert.equal(finding(res, /blog/), undefined, 'benign "Index of ..." title NOT flagged');
  } finally { srv.close(); }
});

test('401/403 are discovery endpoints, not findings', async () => {
  const { srv, base } = await serve({ '/admin': { status: 401, body: '' }, '/.env': { status: 403, body: '' } });
  try {
    const res = await webScan(base, { paths: ['/admin', '/.env'], timeout: 700 });
    assert.ok(res.endpoints.some((e) => e.path === '/admin' && e.status === 401));
    assert.equal(res.findings.length, 0, 'protected paths are not exposures');
  } finally { srv.close(); }
});

test('robustness: concurrency<=0 still scans; invalid base throws', async () => {
  const { srv, base } = await serve({ '/admin': { status: 200, body: 'x' } });
  try {
    const res = await webScan(base, { paths: ['/admin', '/nope'], concurrency: 0, timeout: 700 });
    assert.ok(res.endpoints.some((e) => e.path === '/admin'), 'clamped pool still scanned');
  } finally { srv.close(); }
  await assert.rejects(() => webScan('target.com', { paths: ['/'] }), /must be an http/);
  await assert.rejects(() => webScan(undefined, { paths: ['/'] }), /must be an http/);
});

test('DEFAULT_PATHS: substantial and includes key sensitive paths', () => {
  assert.ok(DEFAULT_PATHS.length >= 45);
  assert.ok(DEFAULT_PATHS.includes('/.env') && DEFAULT_PATHS.includes('/.git/HEAD') && DEFAULT_PATHS.includes('/wp-config.php'));
});
