// VARVEL crawl tests — hermetic local servers, safe (localhost only).
//   node --test varvel/test/crawl.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { crawl, parsePage, signatureOf } from '../tools/crawl.mjs';
import { makePacer } from '../engine/stealth.mjs';

// Serve a route map { '/path': html }. Tracks every requested URL in `hits`.
async function serve(routes) {
  const hits = [];
  const srv = http.createServer((req, res) => {
    hits.push(req.url);
    const body = routes[req.url];
    if (body == null) { res.writeHead(404); res.end('not found'); return; }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(body);
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { srv, base: `http://127.0.0.1:${srv.address().port}`, hits };
}

const HTML_CT = { 'content-type': 'text/html' };
const ep = (res, re) => res.endpoints.find((e) => re.test(e.path));
const prm = (res, name, where) => res.params.find((p) => p.name === name && (!where || p.where === where));

// A small linked site: / -> /about + /products?page=2 -> /contact (form). Plus traps:
// an external link, a protocol-relative off-host link, a logout link, a CSS asset,
// and a facet path with many query variants.
function site(base) {
  return {
    '/': `<html><body>
      <a href="/about">About</a>
      <a href="/products?page=2&sort=asc">Products</a>
      <a href="https://evil.example.com/steal">off-site</a>
      <a href="//other-host.net/x">proto-relative off-site</a>
      <a href="/account/logout">Log out</a>
      <link rel="stylesheet" href="/static/site.css">
      <a href="mailto:a@b.c">mail</a>
    </body></html>`,
    '/about': `<html><body><a href="/contact">Contact</a><a href="/">home</a></body></html>`,
    '/products?page=2&sort=asc': `<html><body><a href="/products?page=3&sort=asc">next</a></body></html>`,
    '/products?page=3&sort=asc': `<html><body><a href="/products?page=4&sort=asc">next</a></body></html>`,
    '/products?page=4&sort=asc': `<html><body><a href="/products?page=5&sort=asc">next</a></body></html>`,
    '/contact': `<html><body>
      <form action="/api/contact" method="post">
        <input type="text" name="name"><input type="email" name="email"><textarea name="message"></textarea>
      </form>
      <form action="/search" method="get"><input type="search" name="q"></form>
    </body></html>`,
  };
}

test('BFS discovers the linked site: pages visited, endpoints + query params mined', async () => {
  const { srv, base, hits } = await serve(site());
  try {
    const res = await crawl(base, { timeout: 700 });
    assert.ok(res.pages.length >= 4, 'crawled multiple pages, got ' + res.pages.length);
    assert.ok(ep(res, /^\/about$/), '/about discovered');
    assert.ok(ep(res, /^\/products$/), '/products discovered');
    assert.ok(ep(res, /^\/contact$/), '/contact discovered (depth 2)');
    assert.ok(prm(res, 'page', 'query') && prm(res, 'sort', 'query'), 'query params mined from links');
    assert.equal(res.base, base);
    assert.ok(res.requests <= hits.length);
  } finally { srv.close(); }
});

test('same-origin is absolute: external + protocol-relative links are never requested', async () => {
  const { srv, base, hits } = await serve(site());
  try {
    const res = await crawl(base, { timeout: 700 });
    assert.ok(!hits.some((h) => /evil\.example|other-host/.test(h)), 'no off-origin request left the box');
    assert.ok(!res.endpoints.some((e) => /evil|other-host/.test(e.path)), 'no off-origin endpoint recorded');
  } finally { srv.close(); }
});

test('state-changing links (logout) and static assets are never followed', async () => {
  const { srv, base, hits } = await serve(site());
  try {
    const res = await crawl(base, { timeout: 700 });
    assert.ok(!hits.includes('/account/logout'), 'logout never requested');
    assert.ok(!hits.includes('/static/site.css'), 'css asset never requested');
    // ...but the logout path is still RECORDED as surface (it exists and matters)
    assert.ok(ep(res, /^\/account\/logout$/), 'logout path recorded as surface');
  } finally { srv.close(); }
});

test('forms are mapped: action, method, fields → params; endpoints carry the form method', async () => {
  const { srv, base } = await serve(site());
  try {
    const res = await crawl(base, { timeout: 700 });
    const contact = res.forms.find((f) => f.action === '/api/contact');
    assert.ok(contact, 'contact form found');
    assert.equal(contact.method, 'POST');
    assert.deepEqual(contact.fields.sort(), ['email', 'message', 'name']);
    assert.ok(prm(res, 'email', 'form') && prm(res, 'q', 'form'), 'form fields mined as params');
    assert.ok(ep(res, /^\/api\/contact$/).methods.includes('POST'), 'form endpoint carries POST');
    assert.ok(ep(res, /^\/search$/).methods.includes('GET'), 'GET form recorded');
  } finally { srv.close(); }
});

test('facet collapse: query-variant pages are capped per path (page=2..5 → ≤ variantCap fetches)', async () => {
  const { srv, base, hits } = await serve(site());
  try {
    const res = await crawl(base, { timeout: 700, maxVariants: 2 });
    const productFetches = hits.filter((h) => h.startsWith('/products?'));
    assert.ok(productFetches.length <= 2, 'variants capped at 2, got ' + productFetches.length);
    // but the endpoint itself is still discovered
    assert.ok(ep(res, /^\/products$/));
  } finally { srv.close(); }
});

test('depth cap: maxDepth 0 visits only the entry page but still records linked surface', async () => {
  const { srv, base, hits } = await serve(site());
  try {
    const res = await crawl(base, { timeout: 700, maxDepth: 0 });
    assert.equal(res.pages.length, 1, 'only entry page visited');
    assert.ok(!hits.includes('/about'), 'no depth-1 fetch');
    assert.ok(ep(res, /^\/about$/), 'linked surface still recorded');
  } finally { srv.close(); }
});

test('page budget: maxPages bounds total fetches', async () => {
  const { srv, base, hits } = await serve(site());
  try {
    await crawl(base, { timeout: 700, maxPages: 2 });
    const pageHits = hits.filter((h) => !/\.css/.test(h));
    assert.ok(pageHits.length <= 2, 'budget honored, got ' + pageHits.length);
  } finally { srv.close(); }
});

test('cleartext password form over HTTP is flagged (medium)', async () => {
  const { srv, base } = await serve({
    '/': `<html><body><form action="/login" method="post"><input name="user"><input type="password" name="pass"></form></body></html>`,
  });
  try {
    const res = await crawl(base, { timeout: 700 });
    const f = res.findings.find((x) => /cleartext HTTP/i.test(x.title));
    assert.ok(f, 'finding raised');
    assert.equal(f.sev, 'medium');
    assert.equal(f.path, '/login');
    assert.ok(f.ref.startsWith('CRW-'));
  } finally { srv.close(); }
});

test('non-HTML responses are not crawled as pages', async () => {
  const srv = http.createServer((req, res) => {
    if (req.url === '/') { res.writeHead(200, HTML_CT); res.end('<a href="/api/data">d</a>'); return; }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"a":1}');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const res = await crawl(base, { timeout: 700 });
    assert.ok(!res.pages.some((p) => p.path === '/api/data'), 'JSON endpoint not visited as a page');
    assert.ok(ep(res, /^\/api\/data$/), '...but still recorded as surface');
  } finally { srv.close(); }
});

test('unit: parsePage extracts links + forms; signatureOf normalizes param order', () => {
  const { links, forms } = parsePage('<a href="/x">x</a><form action="/y" method="post"><input name="a"></form>');
  assert.ok(links.includes('/x') && links.includes('/y'));
  assert.equal(forms[0].method, 'POST');
  assert.deepEqual(forms[0].fields, ['a']);
  const u1 = new URL('http://h/p?b=2&a=1'), u2 = new URL('http://h/p?a=9&b=8');
  assert.equal(signatureOf(u1), signatureOf(u2), 'param order-insensitive');
  assert.equal(signatureOf(u1), '/p?a&b');
});

test('robustness: bad base throws TypeError; dead server resolves empty, not an exception', async () => {
  await assert.rejects(() => crawl('not-a-url'), TypeError);
  const res = await crawl('http://127.0.0.1:1', { timeout: 300 });
  assert.equal(res.pages.length, 0);
  assert.equal(res.endpoints.length, 0);
});

test('stealth-aware: an injected pacer is honored and reported', async () => {
  const { srv, base } = await serve(site());
  try {
    const pacer = makePacer('normal');
    let paced = 0;
    const spy = { pace: async () => { paced++; return pacer.pace(); }, penalize: (...a) => pacer.penalize(...a), profile: pacer.profile };
    const res = await crawl(base, { timeout: 700, pacer: spy });
    assert.ok(paced >= res.pages.length, 'every fetch paced');
    assert.equal(res.stealth, 'normal');
  } finally { srv.close(); }
});
