// VARVEL apisurface tests — hermetic local servers, safe (localhost only).
//   node --test varvel/test/apisurface.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { apiSurface } from '../tools/apisurface.mjs';
import { makePacer } from '../engine/stealth.mjs';

// Start a server from a route map; unknown paths -> 404. Handles POST bodies.
async function serve(routes, fallback = { status: 404, body: 'not found' }) {
  const hits = [];
  const srv = http.createServer((req, res) => {
    const key = req.method + ' ' + req.url;
    hits.push(key);
    const r = routes[key] || routes[req.url] || (typeof fallback === 'function' ? fallback(req) : fallback);
    res.writeHead(r.status, r.headers || {});
    res.end(r.body || '');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { srv, port: srv.address().port, base: `http://127.0.0.1:${srv.address().port}`, hits };
}

const JSON_CT = { 'content-type': 'application/json' };
const ep = (res, re) => res.endpoints.find((e) => re.test(e.path));
const prm = (res, name) => res.params.find((p) => p.name === name);

const OPENAPI = JSON.stringify({
  openapi: '3.0.1',
  info: { title: 'Widget API', version: '1.0' },
  paths: {
    '/api/widgets': {
      get: { parameters: [{ name: 'limit', in: 'query' }, { name: 'offset', in: 'query' }] },
      post: {},
    },
    '/api/widgets/{id}': {
      parameters: [{ name: 'id', in: 'path' }],
      get: {}, delete: {},
    },
  },
});

const INTROSPECTION_REPLY = JSON.stringify({
  data: {
    __schema: {
      queryType: { name: 'Query' },
      mutationType: { name: 'Mutation' },
      types: [
        { kind: 'OBJECT', name: 'Query', fields: [{ name: 'user', args: [{ name: 'id' }] }, { name: 'search', args: [{ name: 'q' }, { name: 'page' }] }] },
        { kind: 'OBJECT', name: 'Mutation', fields: [{ name: 'login', args: [{ name: 'user' }, { name: 'pass' }] }] },
        { kind: 'OBJECT', name: 'User', fields: [{ name: 'id', args: [] }] },
      ],
    },
  },
});

test('robots.txt + sitemap.xml: volunteered paths are discovered (params too)', async () => {
  // The port is only known after listen(), so build route bodies lazily per-request.
  let base;
  const srv = http.createServer((req, res) => {
    const bodies = {
      '/robots.txt': `User-agent: *\nDisallow: /internal/admin\nAllow: /public/docs\nSitemap: ${base}/sitemap.xml\n`,
      '/sitemap.xml': `<urlset><loc>${base}/about</loc><loc>${base}/products?cat=all</loc></urlset>`,
    };
    const body = bodies[req.url];
    res.writeHead(body ? 200 : 404);
    res.end(body || 'not found');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const res = await apiSurface(base, { timeout: 700 });
    assert.ok(ep(res, /^\/internal\/admin$/), 'robots Disallow path discovered');
    assert.ok(ep(res, /^\/public\/docs$/), 'robots Allow path discovered');
    assert.equal(ep(res, /^\/internal\/admin$/).source, 'robots');
    assert.ok(ep(res, /^\/about$/), 'sitemap loc discovered');
    assert.equal(ep(res, /^\/about$/).source, 'sitemap');
    assert.ok(ep(res, /^\/products$/), 'sitemap loc with query discovered');
    assert.ok(prm(res, 'cat'), 'sitemap query param mined');
  } finally { srv.close(); }
});

test('openapi descriptor: paths, methods, params parsed; honest low-sev finding', async () => {
  const { srv, base } = await serve({
    '/openapi.json': { status: 200, headers: JSON_CT, body: OPENAPI },
  });
  try {
    const res = await apiSurface(base, { timeout: 700 });
    const w = ep(res, /^\/api\/widgets$/);
    assert.ok(w, 'descriptor path discovered');
    assert.deepEqual(w.methods.sort(), ['GET', 'POST'], 'methods from spec');
    assert.equal(w.source, 'descriptor:/openapi.json');
    assert.deepEqual(ep(res, /^\/api\/widgets\/\{id\}$/).methods.sort(), ['DELETE', 'GET']);
    assert.equal(prm(res, 'limit').where, 'query');
    assert.equal(prm(res, 'id').where, 'path');
    assert.equal(res.descriptors.length, 1);
    assert.equal(res.descriptors[0].kind, 'openapi');
    assert.equal(res.descriptors[0].title, 'Widget API');
    assert.equal(res.findings.length, 1, 'one honest finding');
    assert.match(res.findings[0].title, /OpenAPI descriptor exposed unauthenticated/);
    assert.equal(res.findings[0].sev, 'low');
  } finally { srv.close(); }
});

test('graphql introspection: root fields + args mined, schema-exposure finding', async () => {
  const { srv, base } = await serve({
    'POST /graphql': { status: 200, headers: JSON_CT, body: INTROSPECTION_REPLY },
  });
  try {
    const res = await apiSurface(base, { timeout: 700 });
    assert.ok(ep(res, /^\/graphql$/), 'graphql endpoint discovered');
    assert.ok(ep(res, /graphql#user/), 'root query field mapped');
    assert.ok(prm(res, 'q') && prm(res, 'q').where === 'graphql', 'field args mined as params');
    assert.ok(prm(res, 'pass'), 'mutation args mined');
    assert.equal(res.graphql.types, 3);
    assert.equal(res.graphql.fields, 3);
    assert.ok(res.findings.some((f) => /introspection enabled/i.test(f.title)), 'honest introspection finding');
  } finally { srv.close(); }
});

test('HTML + same-origin JS: links, forms, input names, fetch() literals mined', async () => {
  const HTML = `<html><body>
    <a href="/about">About</a>
    <a href="/search?q=term&page=2">Search</a>
    <form action="/login" method="post"><input name="username"><input name="password"></form>
    <script src="/static/app.js"></script>
    <script>fetch('/api/session');</script>
  </body></html>`;
  const JS = `const x = fetch('/api/widgets?limit=10');\nconst y = "/api/health";\nconst z = fetch('https://evil.example.net/api/offsite');`;
  const { srv, base } = await serve({
    '/': { status: 200, body: HTML },
    '/static/app.js': { status: 200, body: JS },
  });
  try {
    const res = await apiSurface(base, { timeout: 700 });
    assert.ok(ep(res, /^\/about$/), 'link mined');
    assert.ok(ep(res, /^\/search$/), 'link with query mined');
    assert.ok(prm(res, 'q') && prm(res, 'page'), 'query param names mined');
    assert.ok(ep(res, /^\/login$/), 'form action mined');
    assert.ok(prm(res, 'username') && prm(res, 'password'), 'form input names mined');
    assert.equal(prm(res, 'username').where, 'form');
    assert.ok(ep(res, /^\/api\/session$/), 'inline fetch() literal mined');
    assert.ok(ep(res, /^\/api\/widgets$/), 'JS fetch() mined');
    assert.ok(ep(res, /^\/api\/health$/), 'JS URL literal mined');
    assert.ok(!ep(res, /offsite/), 'off-origin JS URL never recorded');
  } finally { srv.close(); }
});

test('scope enforcement: a //other-host reference is never requested', async () => {
  const other = await serve({ '/secret': { status: 200, body: 'leak' } });
  const HTML = `<html><body>
    <a href="//127.0.0.1:${other.port}/secret">x</a>
    <script src="//127.0.0.1:${other.port}/evil.js"></script>
    <script>fetch('//127.0.0.1:${other.port}/api/steal');</script>
  </body></html>`;
  const target = await serve({
    '/': { status: 200, body: HTML },
    '/robots.txt': { status: 200, body: `User-agent: *\nDisallow: /local\nSitemap: http://127.0.0.1:${other.port}/sitemap.xml\n` },
  });
  try {
    const res = await apiSurface(target.base, { timeout: 700 });
    assert.equal(other.hits.length, 0, 'the other host received ZERO requests');
    assert.ok(!res.endpoints.some((e) => /secret|steal|evil/.test(e.path)), 'off-origin refs excluded');
    assert.ok(ep(res, /^\/local$/), 'same-origin robots path still discovered');
  } finally { other.srv.close(); target.srv.close(); }
});

test('bare app: no phantom findings, no phantom endpoints', async () => {
  const { srv, base } = await serve({
    '/': { status: 200, body: '<html><body><h1>Welcome</h1></body></html>' },
  });
  try {
    const res = await apiSurface(base, { timeout: 700 });
    assert.equal(res.findings.length, 0, 'no false-positive findings on a bare app');
    assert.equal(res.descriptors.length, 0);
    assert.equal(res.graphql, null);
    assert.ok(res.endpoints.length <= 1, 'only the root at most');
    assert.ok(res.requests <= 40, 'request budget respected');
  } finally { srv.close(); }
});

test('stealth: injected pacer paces requests and is reported', async () => {
  const { srv, base } = await serve({ '/openapi.json': { status: 200, headers: JSON_CT, body: OPENAPI } });
  try {
    let paced = 0;
    const pacer = makePacer('normal');
    const orig = pacer.pace.bind(pacer);
    pacer.pace = async () => { paced++; return orig(); };
    const res = await apiSurface(base, { timeout: 700, pacer });
    assert.equal(res.stealth, 'normal');
    assert.ok(paced > 0, 'requests went through the injected pacer');
    assert.equal(paced, res.requests, 'every request paced exactly once');
    const res2 = await apiSurface(base, { timeout: 700, stealth: 'quiet' });
    assert.equal(res2.stealth, 'quiet', 'stealth profile name works as fallback');
  } finally { srv.close(); }
});

test('robustness: invalid base throws; budget caps total requests', async () => {
  await assert.rejects(() => apiSurface('target.com'), /must be an http/);
  const { srv, base } = await serve({
    '/robots.txt': { status: 200, body: 'User-agent: *\nDisallow: /a\nDisallow: /b\n' },
  });
  try {
    const res = await apiSurface(base, { timeout: 700, maxRequests: 2 });
    assert.ok(res.requests <= 2, 'hard request budget enforced');
  } finally { srv.close(); }
});
