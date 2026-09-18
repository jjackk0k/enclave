// VARVEL parameter/form harvesting tests (Build 2, 2026-08-30).
// Pinned: a local lab SPA shell page with a <form> and inline JS
// fetch('/api/search?q=' + x). Recon (crawl + apisurface) must harvest the form
// fields AND the JS-call query params; applied to a Surface the way engine/campaign.mjs
// does it, the surface must gain ?q= endpoints and BOTH lanes (OOB filter + the
// DOM-XSS reflected-param list) must see targets instead of skipping.
//   node --test varvel/test/param-harvest.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { crawl } from '../tools/crawl.mjs';
import { apiSurface } from '../tools/apisurface.mjs';
import { Surface } from '../engine/surface.mjs';

const SPA = `<!DOCTYPE html><html><head><title>Shop — Sign in</title></head><body>
<div id="root"></div>
<form action="/search" method="GET"><input name="q" type="text"/><input name="sort" type="hidden" value="relevance"/></form>
<script>
  const x = new URLSearchParams(location.search).get('q');
  fetch('/api/search?q=' + x);
  axios.get('/api/v1/items?cat=' + cat + '&q=' + x);
  var xhr = new XMLHttpRequest(); xhr.open('GET', '/api/profile?uid=' + uid);
</script>
<script src="/static/app.js"></script>
</body></html>`;

const APP_JS = `fetch('/api/orders?status=open&page=1'); fetch('/api/coupons?code=' + c);`;

async function serveLab() {
  const srv = http.createServer((req, res) => {
    if (req.url === '/static/app.js') { res.writeHead(200, { 'content-type': 'application/javascript' }); res.end(APP_JS); return; }
    if (req.url === '/' || req.url.startsWith('/?')) { res.writeHead(200, { 'content-type': 'text/html' }); res.end(SPA); return; }
    res.writeHead(404); res.end('not found');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { srv, base: `http://127.0.0.1:${srv.address().port}` };
}

// Mirror of campaign.mjs's harvest application: query params become ?param= endpoint
// nodes and join the reflected-param list; GET-form fields do both.
function applyHarvest(surface, hid, base, { params = [], forms = [] }) {
  const reflected = [];
  const seen = new Set();
  const paramEndpoint = (path, name) => {
    const p = String(path || '/').split('?')[0] || '/';
    const n = String(name || '').trim();
    if (!n || n.length > 64 || !/^[\w.-]+$/.test(n)) return;
    const label = p + '?' + n + '=';
    if (seen.has(label)) return;
    seen.add(label);
    surface.endpoint(hid, label, 'GET');
  };
  for (const p of params) {
    if (!p || p.where !== 'query' || typeof p.name !== 'string') continue;
    try { reflected.push({ base: new URL(p.path || '/', base).href, param: p.name }); } catch { /* skip */ }
    if (p.path) paramEndpoint(p.path, p.name);
  }
  for (const f of forms) {
    if (String(f.method || 'GET').toUpperCase() !== 'GET') continue;
    for (const field of f.fields || f.inputs || []) {
      try { reflected.push({ base: new URL(f.action || f.page || '/', base).href, param: field }); } catch { /* skip */ }
      paramEndpoint(f.action || f.page || '/', field);
    }
  }
  return reflected;
}

// The exact gates the campaign lanes use (engine/campaign.mjs runOobPass / runBrowserPass).
const OOB_FILTER = /(\?[^=]*=)|\{id\}/;

test('crawl: SPA shell yields form fields AND inline-JS query params, tagged with paths', async () => {
  const { srv, base } = await serveLab();
  try {
    const res = await crawl(base, { timeout: 700, maxPages: 5, maxDepth: 1 });
    const qparams = res.params.filter((p) => p.where === 'query');
    const byName = Object.fromEntries(qparams.map((p) => [p.name + '@' + p.path, p]));
    assert.ok(byName['q@/api/search'], 'JS fetch q param harvested with its path');
    assert.ok(byName['cat@/api/v1/items'] && byName['q@/api/v1/items'], 'axios params harvested');
    assert.ok(byName['uid@/api/profile'], 'XHR open() param harvested');
    const form = res.forms.find((f) => f.action === '/search');
    assert.ok(form, 'the GET form was found');
    assert.deepEqual(form.fields, ['q', 'sort']);
  } finally { srv.close(); }
});

test('apisurface: root shell + linked bundle yield path-tagged query params', async () => {
  const { srv, base } = await serveLab();
  try {
    const res = await apiSurface(base, { timeout: 700, maxRequests: 20 });
    const qparams = res.params.filter((p) => p.where === 'query' && p.path);
    const pairs = new Set(qparams.map((p) => p.name + '@' + p.path));
    assert.ok(pairs.has('q@/api/search'), 'inline fetch param harvested');
    assert.ok(pairs.has('status@/api/orders') && pairs.has('page@/api/orders'), 'linked bundle params harvested');
    assert.ok(pairs.has('code@/api/coupons'), 'bundle fetch concat param harvested');
  } finally { srv.close(); }
});

test('surface gains ?q= endpoints and BOTH lanes see targets (the no-parameterized-endpoints killer)', async () => {
  const { srv, base } = await serveLab();
  try {
    const surface = new Surface({ cidrs: ['127.0.0.1/32'], signedBy: 'test', engagement: 'lab' });
    const hid = surface.host('127.0.0.1', { label: 'lab' });
    const cw = await crawl(base, { timeout: 700, maxPages: 5, maxDepth: 1 });
    const api = await apiSurface(base, { timeout: 700, maxRequests: 20 });
    const reflected = [
      ...applyHarvest(surface, hid, base, cw),
      ...applyHarvest(surface, hid, base, api),
    ];
    const paramEndpoints = [...surface.nodes.values()].filter((n) => n.type === 'endpoint' && OOB_FILTER.test(n.label));
    const labels = paramEndpoints.map((n) => n.label);
    assert.ok(labels.includes('/api/search?q='), 'surface gained /api/search?q=');
    assert.ok(labels.includes('/search?q='), 'GET form became the parameterized endpoint /search?q=');
    assert.ok(labels.includes('/api/v1/items?cat=') && labels.includes('/api/v1/items?q='), 'axios endpoint params landed');
    assert.ok(paramEndpoints.length >= 4, 'OOB lane filter sees parameterized endpoints — no more no-parameterized-endpoints skip');
    const rp = reflected.map((r) => r.param + '@' + new URL(r.base).pathname);
    assert.ok(rp.includes('q@/api/search') && rp.includes('q@/search'), 'DOM-XSS canary list fed — no more no-reflected-params skip');
  } finally { srv.close(); }
});
