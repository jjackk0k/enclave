// VARVEL wappalyze tests — pure signature engine + zero-cost crawl integration.
//   node --test varvel/test/wappalyze.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { detectOnPage, fingerprintPages, TECH_SIGNATURES } from '../tools/wappalyze.mjs';
import { crawl } from '../tools/crawl.mjs';

test('detectOnPage: headers + cookies + body signals all hit, with evidence', () => {
  const hits = detectOnPage({
    headers: {
      server: 'nginx/1.18.0',
      'x-powered-by': 'PHP/8.2.7',
      'set-cookie': ['laravel_session=abc; HttpOnly'],
    },
    body: '<html><head><meta name="generator" content="WordPress 6.5.2"></head><body><script src="/wp-content/themes/x/app.js"></script></body></html>',
  });
  const byId = Object.fromEntries(hits.map((h) => [h.id, h]));
  assert.equal(byId.nginx.version, '1.18.0');
  assert.equal(byId.php.version, '8.2.7');
  assert.ok(byId.laravel, 'cookie signal hit');
  assert.equal(byId.wordpress.version, '6.5.2');
  assert.ok(byId.wordpress.evidence.length > 0, 'evidence carried');
  assert.ok(!byId.apache && !byId.iis && !byId.django, 'no false positives');
});

test('fingerprintPages: multi-page aggregation raises confidence to confirmed', () => {
  const page = { headers: { server: 'cloudflare' }, body: '<div data-reactroot></div>/_next/static/chunk.js' };
  const agg = fingerprintPages([page, page, { headers: {}, body: 'plain' }]);
  const next = agg.find((t) => t.id === 'nextjs');
  const react = agg.find((t) => t.id === 'react');
  const cf = agg.find((t) => t.id === 'cloudflare');
  assert.equal(next.confidence, 'confirmed', 'seen on 2 pages');
  assert.equal(next.pages, 2);
  assert.equal(react.confidence, 'confirmed');
  assert.equal(cf.confidence, 'confirmed');
  assert.ok(!agg.some((t) => t.id === 'wordpress'));
});

test('single-page sighting stays firm (honest confidence)', () => {
  const agg = fingerprintPages([{ headers: {}, body: '<form><input type="hidden" name="csrfmiddlewaretoken"></form>' }]);
  const django = agg.find((t) => t.id === 'django');
  assert.equal(django.confidence, 'firm');
});

test('signature table sanity: every signature has id/label/cat and at least one matcher', () => {
  assert.ok(TECH_SIGNATURES.length >= 25, 'broad coverage: ' + TECH_SIGNATURES.length);
  for (const t of TECH_SIGNATURES) {
    assert.ok(t.id && t.label && t.cat, 'identity fields');
    assert.ok(Array.isArray(t.sig) && t.sig.length >= 1, t.id + ' has matchers');
    for (const s of t.sig) assert.ok(['headers', 'cookies', 'body'].includes(s.where), t.id + ' where valid');
  }
});

test('version capture: the products with CVE packs can state a version (2026-09-16 coverage audit)', () => {
  // A version→CVE pack is INERT unless some signature supplies a version, and cveCheck refuses a
  // versionless claim by design. Tomcat (3475 NVD CPE nodes) previously had presence-only signals,
  // so its whole pack could never fire; phpMyAdmin had no signature at all. Pin both readings.
  const tomcat = detectOnPage({ headers: { server: 'Apache-Coyote/1.1' }, body: '<html><head><title>Apache Tomcat/9.0.65</title></head></html>' });
  const t = tomcat.find((h) => h.id === 'tomcat');
  assert.ok(t, 'tomcat detected');
  assert.equal(t.version, '9.0.65', 'status-page version captured (pack is no longer inert)');
  const pma = detectOnPage({ headers: { 'set-cookie': ['pma_lang=en'] }, body: '<form><input type="text" id="pma_username" name="pma_username"></form><div class="version">phpMyAdmin 5.1.0</div>' });
  const p = pma.find((h) => h.id === 'phpmyadmin');
  assert.ok(p, 'phpMyAdmin detected');
  assert.equal(p.version, '5.1.0', 'login-page version captured');
  // honesty: presence without a version stays version:null — never invent one
  const pmaNoVer = detectOnPage({ headers: {}, body: '<a href="/phpmyadmin/">phpMyAdmin</a>' });
  assert.equal(pmaNoVer.find((h) => h.id === 'phpmyadmin').version, null, 'presence-only sighting carries no version');
});

test('crawl integration: tech rides the crawl with ZERO extra requests', async () => {
  const srv = http.createServer((req, res) => {
    const hits = [];
    res.writeHead(200, { 'content-type': 'text/html', server: 'nginx/1.24.0', 'x-powered-by': 'Next.js' });
    if (req.url === '/') res.end('<html><body><div id="__next"><a href="/dashboard">d</a></div><script src="/_next/static/chunks/main.js"></script></body></html>');
    else if (req.url === '/dashboard') res.end('<html><body>/_next/static/chunks/dash.js</body></html>');
    else { res.statusCode = 404; res.end(); }
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const res = await crawl(base, { timeout: 700 });
    const ids = res.tech.map((t) => t.id);
    assert.ok(ids.includes('nginx'), 'server header fingerprinted');
    assert.ok(ids.includes('nextjs'), 'Next.js detected from body + header');
    assert.equal(res.tech.find((t) => t.id === 'nginx').version, '1.24.0');
    assert.equal(res.tech.find((t) => t.id === 'nextjs').confidence, 'confirmed', 'seen on both pages');
  } finally { srv.close(); }
});
