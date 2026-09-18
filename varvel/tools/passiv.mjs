// VARVEL — passive-source reconnaissance aggregator (authorized engagements).
//
// The crt.sh / Wayback / archive slot (GAU + subfinder-passive in RedAmon's pipeline),
// built native. THE ULTIMATE STEALTH TOOL: every byte of this recon comes from PUBLIC
// THIRD-PARTY datasets (certificate-transparency logs, the Wayback Machine's CDX index)
// — the target sees ZERO packets. Noise cost to the engagement: nothing. This is the
// recon you can run on the most defended target without spending a single noise point.
//
// What it produces:
//   subdomains — from CT logs (crt.sh): every name anyone ever got a certificate for
//   endpoints  — from the Wayback CDX index: URLs the archive has seen, incl. paths
//                and query parameters that may be long gone from the live site (the
//                juiciest attack surface is often the forgotten endpoint)
//
// Honest by design: results are labeled by source, nothing is verified against the
// target (that would defeat the purpose), and `targetContact: 0` is a guarantee the
// report can make — every fetch goes to the data providers, never to the scope.
//
// fetchImpl is injectable for hermetic tests.

const DEFAULT_SOURCES = ['crtsh', 'wayback'];
const MAX_ENDPOINTS = 500;          // total endpoint cap across all hosts
const MAX_PER_HOST = 60;            // per-host cap so one noisy app can't flood the graph
const ASSET_RE = /\.(?:png|jpe?g|gif|svg|webp|avif|ico|css|m?js|map|woff2?|ttf|eot|mp[34]|avi|mov|webm)(?:[?#]|$)/i;

// Default fetch adapter (real network — to the DATA PROVIDERS only).
async function defaultFetch(url, timeout) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const r = await fetch(url, { signal: ctrl.signal, headers: { 'user-agent': 'VARVEL-passive-recon' } });
    return { ok: r.ok, status: r.status, text: () => r.text() };
  } finally { clearTimeout(t); }
}

// Parse crt.sh CT-log JSON → subdomains of `domain` (deduped, wildcards stripped,
// strict same-zone enforcement — a malicious CT entry for another zone is dropped).
export function parseCrtSh(text, domain) {
  let rows;
  try { rows = JSON.parse(text); } catch { return []; }
  if (!Array.isArray(rows)) return [];
  const out = new Set();
  const suffix = '.' + domain;
  for (const row of rows) {
    const names = String((row && row.name_value) || '').split('\n');
    for (let n of names) {
      n = n.trim().toLowerCase().replace(/^\*\./, '');
      if (!n || n.includes(' ') || n.includes('_')) continue;
      if (n === domain || n.endsWith(suffix)) out.add(n);
    }
  }
  return [...out].sort();
}

// Parse a Wayback CDX JSON response (fl=original) → per-host endpoints + params.
// Strict same-zone hosts only; static assets skipped; caps enforced.
export function parseWaybackCdx(text, domain, { maxEndpoints = MAX_ENDPOINTS, maxPerHost = MAX_PER_HOST } = {}) {
  let rows;
  try { rows = JSON.parse(text); } catch { return { endpoints: [], params: [] }; }
  if (!Array.isArray(rows)) return { endpoints: [], params: [] };
  const endpoints = [], params = [];
  const seenEp = new Set(), seenPr = new Set(), perHost = new Map();
  const suffix = '.' + domain;
  for (const row of rows) {
    const raw = Array.isArray(row) ? row[0] : row;
    let u;
    try { u = new URL(String(raw)); } catch { continue; }
    if (!/^https?:$/.test(u.protocol)) continue;
    const host = u.hostname.toLowerCase();
    if (!(host === domain || host.endsWith(suffix))) continue;
    if (ASSET_RE.test(u.pathname)) continue;                       // static assets are not surface
    const count = perHost.get(host) || 0;
    if (count >= maxPerHost || endpoints.length >= maxEndpoints) continue;
    const epKey = host + u.pathname;
    if (!seenEp.has(epKey)) {
      seenEp.add(epKey);
      perHost.set(host, count + 1);
      endpoints.push({ host, path: u.pathname, source: 'wayback' });
    }
    for (const [k] of u.searchParams) {
      const prKey = host + ':' + k;
      if (!seenPr.has(prKey)) { seenPr.add(prKey); params.push({ host, name: k, where: 'query', source: 'wayback' }); }
    }
  }
  return { endpoints, params };
}

// Aggregate passive sources for a domain. Zero target contact — guaranteed by
// construction: the ONLY URLs fetched are the providers' own API endpoints.
export async function passiveRecon(domain, { sources = DEFAULT_SOURCES, timeout = 12000, waybackLimit = 2000, fetchImpl = defaultFetch } = {}) {
  domain = String(domain || '').trim().toLowerCase().replace(/^\*\./, '');
  if (!domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) throw new TypeError('passiveRecon: domain must be a registrable domain, got ' + JSON.stringify(domain));

  const wanted = (Array.isArray(sources) && sources.length ? sources : DEFAULT_SOURCES).filter((s) => DEFAULT_SOURCES.includes(s));
  const status = {};
  let subdomains = [], endpoints = [], params = [], requests = 0;

  const jobs = {
    crtsh: async () => {
      const r = await fetchImpl(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, timeout);
      requests++;
      if (!r || !r.ok) throw new Error('crt.sh HTTP ' + (r && r.status));
      subdomains = parseCrtSh(await r.text(), domain).map((name) => ({ name, source: 'crt.sh' }));
    },
    wayback: async () => {
      const r = await fetchImpl(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}/*&output=json&fl=original&collapse=urlkey&limit=${Math.max(1, waybackLimit | 0)}`, timeout);
      requests++;
      if (!r || !r.ok) throw new Error('wayback HTTP ' + (r && r.status));
      const parsed = parseWaybackCdx(await r.text(), domain);
      endpoints = parsed.endpoints;
      params = parsed.params;
    },
  };

  // Sources run concurrently and fail INDEPENDENTLY — one provider down never sinks the run.
  await Promise.allSettled(wanted.map(async (s) => {
    try { await jobs[s](); status[s] = 'ok'; }
    catch (e) { status[s] = 'error: ' + ((e && e.message) || e); }
  }));

  // Endpoints/params on the apex domain itself also imply the apex is a live name.
  const names = new Set(subdomains.map((s) => s.name));
  for (const e of endpoints) if (!names.has(e.host)) { names.add(e.host); subdomains.push({ name: e.host, source: 'wayback' }); }
  subdomains.sort((a, b) => a.name.localeCompare(b.name));

  return {
    domain,
    subdomains,
    endpoints,
    params,
    sources: status,
    requests,          // requests to DATA PROVIDERS
    targetContact: 0,  // guaranteed: the target saw nothing
  };
}
