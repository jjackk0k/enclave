// VARVEL path-prefix scope tests — the agoda-class constraint: a signed scope may
// confine an engagement to URL PATH PREFIXES on a host (H1 agoda-public: ONLY
// https://www.agoda.com/book/). When scope.pathPrefixes is set, EVERY outbound
// request to the scoped host must match a prefix — fail-closed, refusal logged
// (scope.path.refused), never sent.
// Hermetic: loopback two-path fixtures, request-recording servers. No external network.
//   node --test varvel/test/scopepath.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { pathPrefixAllowed, sanitizePathPrefixes } from '../engine/scopepath.mjs';
import { webScan } from '../tools/webscan.mjs';
import { crawl } from '../tools/crawl.mjs';
import { apiSurface } from '../tools/apisurface.mjs';
import { vulnCheck } from '../tools/vulncheck.mjs';
import { runChain } from '../tools/chainrun.mjs';
import { Campaign } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';

// Two-path fixture: an in-prefix page linking to BOTH an in-prefix and an
// out-of-prefix page (+ the root). Every request path is recorded.
function twoPathServer() {
  const seen = [];
  const srv = http.createServer((req, res) => {
    seen.push(req.url);
    const html = (links) => '<html><head><title>t</title></head><body>'
      + links.map((l) => `<a href="${l}">x</a>`).join('') + '</body></html>';
    if (req.url === '/book/') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end(html(['/book/inner', '/other/x', '/', '/book/deep?p=1'])); }
    if (req.url === '/book/inner') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end(html(['/book/'])); }
    if (req.url.startsWith('/book/')) { res.writeHead(200, { 'content-type': 'text/html' }); return res.end(html([])); }
    if (req.url === '/robots.txt') { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('User-agent: *\nDisallow: /other/\n'); }
    res.writeHead(200, { 'content-type': 'text/html' }); return res.end(html([])); // out-of-prefix pages answer 200 — only the GUARD keeps them untouched
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve({ srv, seen, base: `http://127.0.0.1:${srv.address().port}` })));
}

const noAgent = async () => ({ text: '', steps: 0 });

/* ---------- unit: the prefix gate semantics ---------- */

test('pathPrefixAllowed: no prefixes = unconstrained; "/" prefix = unconstrained; otherwise anchored prefix match', () => {
  assert.equal(pathPrefixAllowed('/anything', null), true);
  assert.equal(pathPrefixAllowed('/anything', []), true);
  assert.equal(pathPrefixAllowed('/anything', undefined), true);
  assert.equal(pathPrefixAllowed('/', ['/']), true, 'an explicit "/" prefix allows the root');
  assert.equal(pathPrefixAllowed('/book/', ['/book/']), true);
  assert.equal(pathPrefixAllowed('/book/inner?x=1', ['/book/']), true);
  assert.equal(pathPrefixAllowed('/', ['/book/']), false, 'the ROOT itself is out-of-prefix unless "/" is listed');
  assert.equal(pathPrefixAllowed('/booking', ['/book/']), false, 'prefix is anchored — /booking is not /book/');
  assert.equal(pathPrefixAllowed('/book', ['/book/']), false, 'the bare prefix stem without the trailing slash is outside');
  assert.equal(pathPrefixAllowed('/other/book/', ['/book/']), false);
  assert.deepEqual(sanitizePathPrefixes(['/book/', '']), ['/book/']);
  assert.equal(sanitizePathPrefixes('nope'), null);
  assert.equal(sanitizePathPrefixes(['relative/nolead']), null, 'prefixes must start with /');
});

/* ---------- tool-level confinement ---------- */

test('crawl stays under the prefix: seeds at it, refuses-and-records outside links, never fetches them', async (t) => {
  const { srv, seen, base } = await twoPathServer();
  t.after(() => srv.close());
  const r = await crawl(base, { pathPrefixes: ['/book/'], maxPages: 10, maxDepth: 3, timeout: 900 });
  assert.ok(seen.length > 0, 'the crawl ran');
  assert.ok(seen.every((p) => p.startsWith('/book/')), 'ZERO requests left the prefix, saw: ' + seen.join(', '));
  assert.ok(seen.includes('/book/'), 'seeded at the prefix, not the root');
  assert.ok(r.scopeRefusals.length >= 2, 'out-of-prefix links refused-and-recorded (/other/x, /): ' + JSON.stringify(r.scopeRefusals));
  assert.ok(r.scopeRefusals.some((p) => String(p).startsWith('/other/')), 'the /other/x link was refused');
  assert.ok(r.pages.some((p) => p.path === '/book/inner'), 'in-prefix links still crawled');
});

test('webscan probes only in-prefix paths; baseline junk probes stay under the prefix too', async (t) => {
  const { srv, seen, base } = await twoPathServer();
  t.after(() => srv.close());
  const r = await webScan(base, { paths: ['/', '/.env', '/book/', '/book/admin'], pathPrefixes: ['/book/'], timeout: 900 });
  assert.ok(seen.length > 0, 'the scan ran');
  assert.ok(seen.every((p) => p.startsWith('/book/')), 'ZERO requests left the prefix (incl. baseline), saw: ' + seen.join(', '));
  assert.deepEqual([...r.scopeRefusals].sort(), ['/', '/.env'], 'out-of-prefix paths refused before the wire');
});

test('apisurface: root-level volunteers (robots.txt, sitemap) are refused under a path scope', async (t) => {
  const { srv, seen, base } = await twoPathServer();
  t.after(() => srv.close());
  const r = await apiSurface(base, { pathPrefixes: ['/book/'], timeout: 900 });
  assert.ok(seen.every((p) => p.startsWith('/book/')), 'ZERO requests left the prefix, saw: ' + seen.join(', '));
  assert.ok(r.scopeRefusals.includes('/robots.txt'), 'robots.txt honestly refused: ' + JSON.stringify(r.scopeRefusals));
});

test('vulncheck: header/CORS root audits and exposure probes are refused out-of-prefix; in-prefix page audits still run', async (t) => {
  const { srv, seen, base } = await twoPathServer();
  t.after(() => srv.close());
  const r = await vulnCheck(base, { pathPrefixes: ['/book/'], pagePaths: ['/book/'], timeout: 900 });
  assert.ok(seen.length > 0, 'in-prefix audits ran');
  assert.ok(seen.every((p) => p.startsWith('/book/')), 'ZERO requests left the prefix, saw: ' + seen.join(', '));
  assert.ok(r.scopeRefusals.includes('/'), 'the root audit was refused, not silently relocated');
});

/* ---------- chainrun: per-step path governance ---------- */

test('chainrun refuses an out-of-prefix step before the wire; in-prefix steps still run', async (t) => {
  const { srv, seen, base } = await twoPathServer();
  t.after(() => srv.close());
  const run = await runChain(
    { name: 'pref-test', base, steps: [{ id: 'ok', path: '/book/', expect: { status: 200 } }, { id: 'escape', path: '/other/x', expect: { status: 200 } }] },
    { pathPrefixes: ['/book/'] },
  );
  assert.equal(run.ok, false);
  const okStep = run.steps.find((s) => s.id === 'ok');
  const escStep = run.steps.find((s) => s.id === 'escape');
  assert.equal(okStep.ok, true, 'the in-prefix step ran');
  assert.equal(escStep.ok, false);
  assert.match(escStep.error, /scope\.path|out-of-prefix/i, 'refusal names the path-scope rule');
  assert.ok(!seen.includes('/other/x'), 'the refused request NEVER left');
  // control: without pathPrefixes the same chain fires both steps
  const run2 = await runChain({ name: 'pref-control', base, steps: [{ id: 'a', path: '/book/', expect: { status: 200 } }, { id: 'b', path: '/other/x', expect: { status: 200 } }] });
  assert.equal(run2.ok, true, 'no path constraint → both steps fire');
  assert.ok(seen.includes('/other/x'));
});

/* ---------- campaign level ---------- */

test('campaign validateFinding refuses an out-of-prefix re-read (fail-closed, logged)', async (t) => {
  const { srv, seen, base } = await twoPathServer();
  t.after(() => srv.close());
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-scopepath-val', signedBy: 'x', cidrs: ['127.0.0.0/8'], pathPrefixes: ['/book/'] },
    runAgent: noAgent,
  });
  const hid = c.surface.host('127.0.0.1', { label: 'web' });
  c.surface.service(hid, Number(base.split(':').pop()), 'tcp', 'http');
  c.surface.finding(hid, { title: 'reflected xss', sev: 'high', confidence: 'confirmed', ref: `${base}/other/x?q=1`, evidence: 'GET /other/x?q=1 reflected' });
  const r = await c.validateFinding(0);
  assert.equal(r.state, 'untestable');
  assert.match(String(r.oracle), /out|path prefix|fail-closed/i, 'refusal names the path scope');
  assert.ok(!seen.some((p) => p.startsWith('/other/')), 'the out-of-prefix re-read NEVER fired');
  assert.ok(c.activity.some((e) => e.kind === 'validate.refused' && /path/.test(String(e.data && e.data.reason))), 'validate.refused logged with the path reason');
});

test('campaign runComposedChain wires pathPrefixes into chainrun — out-of-prefix chain steps refused', async (t) => {
  const { srv, seen, base } = await twoPathServer();
  t.after(() => srv.close());
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-scopepath-chain', signedBy: 'x', cidrs: ['127.0.0.0/8'], pathPrefixes: ['/book/'] },
    runAgent: noAgent,
  });
  c.composedChains = { chains: [{ name: 'test-chain', steps: [{ id: 's1', path: '/other/x', expect: { status: 200 } }] }] };
  const r = await c.runComposedChain('test-chain', { base });
  assert.equal(r.ok, false, 'the chain fails honestly');
  assert.match(String((r.run.steps[0] || {}).error), /scope\.path|out-of-prefix/i);
  assert.ok(!seen.some((p) => p.startsWith('/other/')), 'nothing left the prefix');
});

test('campaign threads scope.pathPrefixes into the recon tool options (like the stealth profile)', () => {
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-scopepath-thread', signedBy: 'x', cidrs: ['127.0.0.0/8'], pathPrefixes: ['/book/'] },
    runAgent: noAgent,
  });
  assert.deepEqual(c.reconOpts.web.pathPrefixes, ['/book/']);
  assert.deepEqual(c.reconOpts.crawl.pathPrefixes, ['/book/']);
  assert.deepEqual(c.reconOpts.api.pathPrefixes, ['/book/']);
  assert.deepEqual(c.reconOpts.vuln.pathPrefixes, ['/book/']);
  const d = new Campaign({ engine: {}, scope: { engagement: 'T-scopepath-none', signedBy: 'x', cidrs: ['127.0.0.0/8'] }, runAgent: noAgent });
  assert.equal((d.reconOpts.web || {}).pathPrefixes, undefined, 'no path scope → nothing threaded (backward-compatible)');
  // URL targets normalize to hostnames for the sweep (the path is NOT scope — the
  // path-prefix guard owns that); bare hosts/IPs pass through untouched.
  const e = new Campaign({ engine: {}, scope: { engagement: 'T-scopepath-url', signedBy: 'x', cidrs: ['127.0.0.0/8'] }, runAgent: noAgent, targets: ['https://www.agoda.com/book/', '10.0.0.9'] });
  assert.deepEqual(e.targets, ['www.agoda.com', '10.0.0.9'], 'URL seed → hostname; literals untouched');
});

test('END-TO-END: a prefix-confined tooledRecon campaign never lets a single request leave the prefix', async (t) => {
  const { srv, seen, base } = await twoPathServer();
  t.after(() => srv.close());
  const port = Number(base.split(':').pop());
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-scopepath-e2e', signedBy: 'x', cidrs: ['127.0.0.0/8'], pathPrefixes: ['/book/'] },
    runAgent: mockAgent, targets: ['127.0.0.1'], tooledRecon: true,
    reconOpts: { ports: [port], webPorts: new Set([port]), timeout: 900, preflight: false, web: { paths: ['/', '/.env', '/book/', '/book/admin'] }, crawl: { maxPages: 10 }, vuln: { maxProbes: 5 } },
  });
  await c.tooledRecon();
  assert.ok(seen.length > 0, 'recon actually ran against the fixture');
  assert.ok(seen.every((p) => p.startsWith('/book/')), 'ZERO requests left /book/ across webscan+apisurface+crawl+vulncheck, saw: ' + seen.join(', '));
  const refusals = c.activity.filter((e) => e.kind === 'scope.path.refused');
  assert.ok(refusals.length >= 1, 'refusals are logged on the campaign record');
});
