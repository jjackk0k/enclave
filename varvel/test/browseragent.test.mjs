// VARVEL browseragent tests — the crawl graph builder + scope confinement and
// the DOM-XSS canary verdict logic, all behind a FAKE driver (no real browser —
// the playwright factory is marked manual-smoke). No live network.
//   node --test varvel/test/browseragent.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { crawl, domXssCanary, scopeHostAllowed, BROWSER_CAPS } from '../tools/browseragent.mjs';

// ——— the fake driver: a scripted site behind the driver interface ———
const SITE = {
  'http://target.test/app/': {
    links: ['/app/a', '/app/b', 'http://evil.test/x', 'https://cdn.other.net/s.js', 'mailto:x@y.z', '/admin/panel', '#frag'],
    forms: [{ action: '/app/search', method: 'GET', inputs: ['q'] }],
    xhrs: ['/app/api/me'],
  },
  'http://target.test/app/a': { links: ['/app/b'], forms: [], xhrs: [] },
  'http://target.test/app/b': { links: ['/app/'], forms: [{ action: '/app/login', method: 'POST', inputs: ['user', 'pass'] }], xhrs: ['/app/api/ping'] },
  'http://target.test/app/search': { links: [], forms: [], xhrs: [] },
};

class FakeDriver {
  constructor({ executeParams = [] } = {}) {
    this.visited = [];
    this.executeParams = executeParams; // params whose reflection "executes" (the vulnerable sink)
    this.canary = null;
    this.shots = [];
    this.logs = ['[log] app boot', '[debug] route change'];
  }
  async goto(url) {
    this.visited.push(url);
    const u = new URL(url);
    // DOM-XSS simulation: the sink "executes" the payload only for listed params —
    // the canary script sets window.__varvelCanary, exactly like a real page would
    for (const p of this.executeParams) {
      const v = u.searchParams.get(p);
      const m = v && v.match(/window\.__varvelCanary="(vx[0-9a-f]+)"/);
      if (m) this.canary = m[1];
    }
    const page = SITE[`${u.protocol}//${u.host}${u.pathname}`];
    if (!page) return { ok: false, url, error: '404', links: [], forms: [], xhrs: [] };
    return { ok: true, url, status: 200, ...page };
  }
  async evalJs(expr) { return expr === 'window.__varvelCanary' ? this.canary : null; }
  consoleLogs() { return this.logs.slice(); }
  async screenshot(tag) { this.shots.push(tag); return `/tmp/fake-${tag}.png`; }
  async close() {}
}

// ——— the crawl graph ———

test('crawl: BFS graph, scope-confined — cross-origin links NEVER queued', async () => {
  const driver = new FakeDriver();
  const r = await crawl('http://target.test/app/', { driver, scopeHosts: ['target.test'], pathPrefixes: ['/app/'] });
  assert.equal(r.ok, true, r.error);
  assert.deepEqual(driver.visited.sort(), ['http://target.test/app/', 'http://target.test/app/a', 'http://target.test/app/b'].sort(), 'three in-scope pages, deduped');
  // the confinement ledger
  const refusedUrls = r.refusals.map((x) => x.url);
  assert.ok(refusedUrls.includes('http://evil.test/x'), 'cross-origin recorded as a refusal');
  assert.ok(refusedUrls.includes('https://cdn.other.net/s.js'));
  assert.ok(r.refusals.filter((x) => x.reason === 'cross-origin').length === 2);
  assert.ok(refusedUrls.includes('http://target.test/admin/panel'), 'same-host but out-of-prefix is still refused');
  assert.ok(r.refusals.some((x) => x.reason === 'out-of-scope-path'));
  assert.ok(!driver.visited.some((u) => !u.startsWith('http://target.test/app/')), 'nothing out-of-scope was ever navigated');
  // graph contents
  assert.ok(r.edges.some((e) => e.from === 'http://target.test/app/' && e.to === 'http://target.test/app/a'));
  assert.equal(r.forms.length, 2, 'forms harvested with their page');
  assert.equal(r.forms[1].method, 'POST');
  assert.ok(r.xhrs.some((x) => x.url === '/app/api/me'));
  assert.ok(!r.edges.some((e) => e.to.includes('#')), 'fragments stripped');
});

test('crawl: depth cap + fail-closed start + honest driver failure', async () => {
  const driver = new FakeDriver();
  const shallow = await crawl('http://target.test/app/', { driver, scopeHosts: ['target.test'], maxDepth: 0 });
  assert.deepEqual(shallow.pages.map((p) => p.url), ['http://target.test/app/'], 'depth 0 visits only the start page');
  const outside = await crawl('http://evil.test/', { driver: new FakeDriver(), scopeHosts: ['target.test'] });
  assert.equal(outside.ok, false);
  assert.match(outside.error, /outside the scope allowlist/);
  const noDriver = await crawl('http://target.test/app/', {});
  assert.equal(noDriver.ok, false);
  const bad = await crawl('not-a-url', { driver: new FakeDriver() });
  assert.equal(bad.ok, false);
});

test('crawl: budget exhaustion stops mid-crawl and logs budget.exhausted', async () => {
  const logs = [];
  const driver = new FakeDriver();
  const r = await crawl('http://target.test/app/', { driver, scopeHosts: ['target.test'], budget: { maxRequests: 1 }, onLog: (l) => logs.push(l) });
  assert.equal(r.ok, true);
  assert.equal(driver.visited.length, 1, 'one navigation bought, the rest starved');
  assert.ok(logs.some((l) => l.type === 'budget.exhausted' && l.tool === 'browseragent'));
});

// ——— the DOM-XSS canary oracle ———

test('domXssCanary: execution proves; reflection alone stays unproven with ZERO findings', async () => {
  const driver = new FakeDriver({ executeParams: ['q'] }); // 'q' executes, 'reflected' only reflects
  const r = await domXssCanary('http://target.test/app/search', {
    params: ['q', 'reflected'], driver, scopeHosts: ['target.test'],
  });
  assert.equal(r.ok, true, r.error);
  assert.equal(r.probes.length, 2);
  const hit = r.findings.find((f) => f.param === 'q');
  assert.ok(hit, 'the executing sink produced a finding');
  assert.equal(hit.verdict, 'proven');
  assert.equal(hit.executedBy, 'window.__varvelCanary');
  assert.ok(hit.screenshot && hit.screenshot.includes('domxss-q'), 'screenshot evidence attached');
  assert.ok(hit.console.length >= 1, 'console log evidence attached');
  assert.ok(hit.url.includes(encodeURIComponent(hit.canary)) || hit.url.includes(hit.canary), 'the proven URL carries the canary');
  const miss = r.probes.find((p) => p.param === 'reflected');
  assert.equal(miss.verdict, 'unproven', 'reflection without execution is not a finding');
  assert.equal(r.findings.length, 1, 'the unproven probe emitted NOTHING');
});

test('domXssCanary: marker-callback path proves out-of-band; scope gate refuses', async () => {
  // a sink whose page JS only fetch()es the marker (no window flag readable)
  const driver = new FakeDriver({ executeParams: [] });
  let markerSeen = null;
  const r = await domXssCanary('http://target.test/app/search', {
    params: ['q'], driver, scopeHosts: ['target.test'],
    markerUrl: 'http://127.0.0.1:9/m',
    markerHit: async (id) => { markerSeen = id; return true; }, // the marker correlated
  });
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].executedBy, 'marker-callback');
  assert.ok(markerSeen && markerSeen.startsWith('vx'));
  // scope: refused before any navigation
  const outside = await domXssCanary('http://evil.test/s', { params: ['q'], driver: new FakeDriver(), scopeHosts: ['target.test'] });
  assert.equal(outside.ok, false);
  assert.equal(outside.findings.length, 0);
  const prefix = await domXssCanary('http://target.test/admin/x', { params: ['q'], driver: new FakeDriver(), scopeHosts: ['target.test'], pathPrefixes: ['/app/'] });
  assert.equal(prefix.ok, false);
  assert.match(prefix.error, /path prefixes/);
});

test('scopeHostAllowed: exact + parent-suffix semantics', () => {
  assert.equal(scopeHostAllowed('app.acme.io', ['acme.io']), true);
  assert.equal(scopeHostAllowed('acme.io', ['acme.io']), true);
  assert.equal(scopeHostAllowed('notacme.io', ['acme.io']), false);
  assert.equal(scopeHostAllowed('anything.io', null), true, 'no allowlist = no host constraint (lab default)');
  assert.ok(BROWSER_CAPS.maxPages > 0);
});
