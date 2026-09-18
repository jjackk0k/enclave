// VARVEL — cvelane: KNOWN-CVE MATCHING (wide-recon + CVE build, Tool 2).
//
// The second lane of the 2026-08-31 doctrine: known-vuln opportunities — especially
// FRESH KEV entries and recent CVEs against DETECTED versions — must never be missed
// while the wide recon sweeps for depth. This tool ingests the free public feeds,
// matches recon-detected (software, version) tuples against them, and emits a scored
// HYPOTHESIS QUEUE.
//
//   node tools/cvelane.mjs scan [--tuples widerecon.json] [--programs zomato,semrush]
//                               [--out data/exports] [--refresh] [--json] [--no-write]
//   node tools/cvelane.mjs fetch   # refresh the feed cache only
//
// FEEDS (free, no key; cached under .tmp/cve-cache/ with a >=12h TTL — politeness floor):
//   * CISA KEV catalog  — https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
//   * NVD CVE API 2.0   — https://services.nvd.nist.gov/rest/json/cves/2.0 (last-modified
//                         window, default 30d). NO API KEY: <=5 req/30s is the public
//                         budget — pages sleep >=6s and the run is capped at 3 pages.
//   EPSS: carried when the caller supplies an epss map ({cve: score}); otherwise null,
//   named 'not fetched' — never fabricated.
//
// THE HONESTY CONTRACT (pinned by test): a version match is NOT exploitability. Every
// output item is status:'HYPOTHESIS' with routing:'campaign-validator' — it names the
// evidence-of-version and a validation plan, and it is NEVER a finding, never enters
// the bountyline draft path. The existing validator/novelty-gate bar (captured bytes +
// differential, then the novelty gate) still decides what is real.
//
// EGRESS: every feed fetch rides the ghost chain (VARVEL_CVELANE_CHAIN, default
// socks5://10.64.0.1:1080) with X-HackerOne: varvel; fail-closed — a failed fetch with
// no cache is a NAMED error and an empty feed, never invented CVEs.
//
// MATCHING: pure functions. CPE 2.3 criteria from NVD configurations + vendor/product
// tokens from KEV, matched through a software-alias table; version ranges
// (versionStartIncluding/…/versionEndExcluding, exact cpe version) checked when the
// tuple's version parses. versionMatch ∈ exact | in-range | unknown | out-of-range;
// out-of-range is dropped, unknown is KEPT and labelled unknown.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ghostGet, PROHIBITED_PROGRAMS, loadIntakes } from './widerecon.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
const VARVEL_ROOT = join(__dir, '..');

export const CVELANE_CAPS = { maxHypotheses: 200, maxNvdPages: 3, nvdResultsPerPage: 200, nvdPageSleepMs: 6500, recentDays: 30, freshDays: 14 };
export const CACHE_TTL_MS = 12 * 3600 * 1000; // >=12h — NVD/KEV are free; keep them that way
export const GHOST_CHAIN = () => process.env.VARVEL_CVELANE_CHAIN || 'socks5://10.64.0.1:1080';
export const FEEDS = {
  kev: { url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' },
  nvd: { url: 'https://services.nvd.nist.gov/rest/json/cves/2.0' },
};
const cacheDir = (dir) => dir || process.env.VARVEL_CVE_CACHE_DIR || join(VARVEL_ROOT, '.tmp', 'cve-cache');

// --- software identity (pure) ----------------------------------------------------------------
// Alias table: a recon banner says "Microsoft-IIS/10.0", a CPE says microsoft:internet_information_server.
export const SOFTWARE_ALIASES = {
  wordpress: ['wordpress', 'wp'],
  php: ['php'], nginx: ['nginx'], apache: ['apache', 'http_server', 'httpd', 'apache_http_server'],
  'microsoft-iis': ['microsoft-iis', 'internet_information_server', 'internet_information_services', 'iis'],
  openssl: ['openssl'], openssh: ['openssh', 'ssh'], tomcat: ['tomcat'], jetty: ['jetty'],
  jquery: ['jquery'], drupal: ['drupal'], joomla: ['joomla'], laravel: ['laravel'],
  django: ['django'], rails: ['rails', 'ruby_on_rails'], express: ['express'],
  strapi: ['strapi'], spring: ['spring', 'spring_framework', 'spring-boot'],
  node: ['node.js', 'nodejs', 'node'], flask: ['flask'], varnish: ['varnish'],
  envoy: ['envoy'], redis: ['redis'], elasticsearch: ['elasticsearch'], grafana: ['grafana'],
  jenkins: ['jenkins'], gitlab: ['gitlab'], confluence: ['confluence'], jira: ['jira'],
  fortinet: ['fortinet', 'fortios', 'fortiproxy'], citrix: ['citrix', 'netscaler'],
  ivanti: ['ivanti'], vmware: ['vmware'], atlassian: ['atlassian'],
};

// aliasTokens(software) → the token set a CPE vendor/product or KEV vendorProject/product
// may carry for this software string.
export function aliasTokens(software) {
  const s = String(software || '').toLowerCase().trim();
  const direct = s.replace(/[^a-z0-9]+/g, '_');
  const set = new Set([s, direct]);
  for (const [canon, aliases] of Object.entries(SOFTWARE_ALIASES)) {
    if (s === canon || aliases.includes(s) || aliases.includes(direct)) {
      set.add(canon);
      for (const a of aliases) { set.add(a); set.add(a.replace(/[^a-z0-9]+/g, '_')); }
    }
  }
  return [...set].filter((t) => t.length >= 2);
}

// --- versions (pure) -------------------------------------------------------------------------
export function parseVersion(v) {
  const m = /^v?(\d+(?:\.\d+){0,3})/.exec(String(v || '').trim());
  if (!m) return null;
  return { parts: m[1].split('.').map((x) => Number(x)), raw: m[1] };
}
export function compareVersions(a, b) {
  const pa = (typeof a === 'string' ? parseVersion(a) : a), pb = (typeof b === 'string' ? parseVersion(b) : b);
  if (!pa || !pb) return null;
  for (let i = 0; i < 4; i++) {
    const x = pa.parts[i] || 0, y = pb.parts[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

// versionSatisfies(version, cpeMatch) → 'exact' | 'in-range' | 'out-of-range' | 'unknown'.
// 'unknown' when the tuple carries no version or the CPE row carries no range/exact data —
// kept, labelled, never upgraded to a claim.
export function versionSatisfies(version, m = {}) {
  if (!version || !parseVersion(version)) return 'unknown';
  if (m.version && parseVersion(m.version) && !['*', '-'].includes(m.version)) {
    return compareVersions(version, m.version) === 0 ? 'exact' : 'out-of-range';
  }
  const hasRange = m.versionStartIncluding || m.versionStartExcluding || m.versionEndIncluding || m.versionEndExcluding;
  if (!hasRange) return 'unknown';
  const c = (v) => compareVersions(version, v);
  if (m.versionStartIncluding && c(m.versionStartIncluding) !== null && c(m.versionStartIncluding) < 0) return 'out-of-range';
  if (m.versionStartExcluding && c(m.versionStartExcluding) !== null && c(m.versionStartExcluding) <= 0) return 'out-of-range';
  if (m.versionEndIncluding && c(m.versionEndIncluding) !== null && c(m.versionEndIncluding) > 0) return 'out-of-range';
  if (m.versionEndExcluding && c(m.versionEndExcluding) !== null && c(m.versionEndExcluding) >= 0) return 'out-of-range';
  return 'in-range';
}

// --- CVE record normalization (pure; tests pin these against recorded samples) ---------------

// cpeFacts('cpe:2.3:a:vendor:product:version:…') → { vendor, product, version } | null
export function cpeFacts(criteria) {
  const m = /^cpe:2\.3:([aho]):([^:]*):([^:]*):([^:]*)/.exec(String(criteria || ''));
  if (!m) return null;
  return { vendor: m[2].toLowerCase(), product: m[3].toLowerCase(), version: m[4] };
}

// softwareMatchesCpe(tokens, {vendor, product}) — any alias token equals or is contained in
// the CPE vendor or product token.
export function softwareMatchesCpe(tokens, cpe) {
  if (!cpe) return false;
  return tokens.some((t) => {
    const tt = t.replace(/[^a-z0-9]+/g, '_');
    return cpe.vendor === tt || cpe.product === tt || cpe.product.includes(tt) || cpe.vendor.includes(tt);
  });
}

// nvdToMatches(nvdCveItem, tokens) → [{ cve, published, description, matchBasis, versionMatch,
// references }] — one per matching vulnerable cpe row; description-token matches (the
// watchlist path) come back versionMatch 'unknown'. Pure.
export function nvdToMatches(item, tokens, { version, descRe } = {}) {
  const cve = item && item.cve;
  if (!cve || !cve.id) return [];
  const desc = ((Array.isArray(cve.descriptions) ? cve.descriptions : []).find((d) => d && d.lang === 'en') || {}).value || '';
  const refs = (Array.isArray(cve.references) ? cve.references : []).map((r) => r && r.url).filter(Boolean).slice(0, 3);
  const out = [];
  const nodes = (Array.isArray(cve.configurations) ? cve.configurations : []).flatMap((c) => (Array.isArray(c.nodes) ? c.nodes : []));
  for (const n of nodes) {
    for (const m of (Array.isArray(n.cpeMatch) ? n.cpeMatch : [])) {
      if (!m || m.vulnerable !== true) continue;
      const cpe = cpeFacts(m.criteria);
      if (!softwareMatchesCpe(tokens, cpe)) continue;
      const vm = versionSatisfies(version, { ...m, version: cpe.version });
      if (vm === 'out-of-range') continue; // a parsed version OUTSIDE the disclosed range is not a hypothesis
      out.push({
        cve: cve.id, published: cve.published || null, description: desc.slice(0, 240),
        matchBasis: `cpe ${m.criteria}`, versionMatch: vm, references: refs,
      });
    }
  }
  if (!out.length && descRe && descRe.test(desc)) {
    out.push({
      cve: cve.id, published: cve.published || null, description: desc.slice(0, 240),
      matchBasis: 'description match (watchlist keyword — no reliable CPE range)', versionMatch: 'unknown', references: refs,
    });
  }
  return out;
}

// kevToMatches(kevEntry, tokens) — KEV carries no version ranges: every match is
// versionMatch 'unknown' (KEV means "exploited in the wild against SOME version"). Pure.
export function kevToMatches(entry, tokens) {
  if (!entry || !entry.cveID) return null;
  const hay = `${entry.vendorProject || ''} ${entry.product || ''}`.toLowerCase().replace(/[^a-z0-9]+/g, '_');
  if (!tokens.some((t) => hay.includes(t.replace(/[^a-z0-9]+/g, '_')))) return null;
  return {
    cve: entry.cveID, published: entry.dateAdded || null, description: String(entry.shortDescription || '').slice(0, 240),
    matchBasis: `kev ${entry.vendorProject}/${entry.product} (${entry.vulnerabilityName || 'no name'})`,
    versionMatch: 'unknown', kev: { dateAdded: entry.dateAdded || null, dueDate: entry.dueDate || null, ransomware: entry.knownRansomwareCampaignUse || 'Unknown' },
    references: [],
  };
}

// --- per-program watchlist (pure) --------------------------------------------------------------
// Pinned watchlists + stack keywords detected in the program's h1sync/intake metadata text.
// WordPress-stack programs watch WP CORE + the plugin/theme CVE flood (descriptions say
// "WordPress plugin"); asset metadata drives it, not guesses.
export const PROGRAM_WATCHLISTS = {
  wordpress: { tokens: ['wordpress'], descRe: /\bwordpress\b/i, note: 'core + plugin/theme CVEs (WP policy covers Core/Gutenberg/WP-CLI/BuddyPress/bbPress/GlotPress)' },
  matomo: { tokens: ['matomo'], descRe: /\bmatomo\b/i, note: 'matomo core' },
  udemy: { tokens: [], descRe: null, note: 'automation-prohibited — watchlist inert, recon never runs' },
};
const STACK_WATCH_RES = [
  [/word\s?press|wp-json/i, 'wordpress'], [/drupal/i, 'drupal'], [/joomla/i, 'joomla'],
  [/laravel/i, 'laravel'], [/php/i, 'php'], [/nginx/i, 'nginx'], [/apache/i, 'apache'],
  [/jenkins/i, 'jenkins'], [/gitlab/i, 'gitlab'], [/grafana/i, 'grafana'],
  [/strapi/i, 'strapi'], [/django/i, 'django'], [/rails/i, 'rails'],
];

export function watchlistFor(programId, metaText) {
  const id = String(programId || '').toLowerCase();
  const pinned = PROGRAM_WATCHLISTS[id] ? [PROGRAM_WATCHLISTS[id]] : [];
  const tokens = new Set(pinned.flatMap((w) => w.tokens));
  let descRes = pinned.map((w) => w.descRe).filter(Boolean);
  const text = String(metaText || '');
  for (const [re, tok] of STACK_WATCH_RES) if (re.test(text)) tokens.add(tok);
  if (tokens.size && !descRes.length && pinned.length === 0) {
    // metadata-derived watch: a conservative description regex over the same tokens
    descRes = [new RegExp([...tokens].map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'i')];
  }
  return { tokens: [...tokens], descRes, pinned: !!PROGRAM_WATCHLISTS[id] };
}

// --- feed cache + fetch -----------------------------------------------------------------------

function readCache(file, ttlMs, nowMs) {
  try {
    if (!existsSync(file)) return null;
    const j = JSON.parse(readFileSync(file, 'utf8'));
    const age = nowMs - Date.parse(j.fetchedAt);
    return { ...j, ageMs: age, fresh: age <= ttlMs };
  } catch { return null; }
}
function writeCache(file, url, data, nowMs) {
  try {
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, JSON.stringify({ fetchedAt: new Date(nowMs).toISOString(), url, data }, null, 2) + '\n');
  } catch { /* cache is an optimization — never fatal */ }
}

// fetchFeeds({ agents, fetchImpl, cacheDir, ttlMs, nowMs, sleepImpl, refresh, recentDays })
// → { kev: {entries, fromCache, stale, fetchedAt}, nvd: same, errors: [] } — never throws.
export async function fetchFeeds(opts = {}) {
  const nowMs = Number.isFinite(Number(opts.nowMs)) ? Number(opts.nowMs) : Date.now();
  const ttl = Math.max(CACHE_TTL_MS, Number(opts.ttlMs) || CACHE_TTL_MS); // the >=12h floor is a FLOOR
  const dir = cacheDir(opts.cacheDir);
  const sleep = typeof opts.sleepImpl === 'function' ? opts.sleepImpl : (ms) => new Promise((r) => setTimeout(r, ms));
  const recentDays = Number.isFinite(Number(opts.recentDays)) ? Number(opts.recentDays) : CVELANE_CAPS.recentDays;
  const errors = [];

  const one = async (name, url, normalize) => {
    const file = join(dir, `${name}.json`);
    const cached = readCache(file, ttl, nowMs);
    if (cached && cached.fresh && !opts.refresh) return { entries: normalize(cached.data), fromCache: true, stale: false, fetchedAt: cached.fetchedAt };
    const r = await ghostGet(url, { agents: opts.agents, fetchImpl: opts.fetchImpl, maxBytes: 24 * 1024 * 1024 }); // feed documents are MB-class — the recon 64KB cap would truncate them
    if (!r.ok || r.status !== 200) {
      const reason = !r.ok ? `${r.error}: ${r.reason}` : `HTTP ${r.status}`;
      errors.push({ feed: name, reason: `${reason} — ${cached ? 'serving the STALE cache (named, not hidden)' : 'NO cache to fall back on; the feed is empty this run, nothing fabricated'}` });
      if (cached) return { entries: normalize(cached.data), fromCache: true, stale: true, fetchedAt: cached.fetchedAt };
      return { entries: [], fromCache: false, stale: false, fetchedAt: null };
    }
    let data;
    try { data = JSON.parse(r.body); } catch {
      errors.push({ feed: name, reason: 'unparsable response — nothing fabricated' });
      return { entries: [], fromCache: false, stale: false, fetchedAt: null };
    }
    writeCache(file, url, data, nowMs);
    return { entries: normalize(data), fromCache: false, stale: false, fetchedAt: new Date(nowMs).toISOString() };
  };

  // KEV: one document, { vulnerabilities: [...] }.
  const kev = await one('kev', FEEDS.kev.url, (d) => (Array.isArray(d && d.vulnerabilities) ? d.vulnerabilities : []));

  // NVD recent: last-modified window, paginated, >=6s between pages (no API key).
  const nvdFile = join(dir, 'nvd-recent.json');
  let nvd;
  {
    const cached = readCache(nvdFile, ttl, nowMs);
    if (cached && cached.fresh && !opts.refresh) {
      nvd = { entries: Array.isArray(cached.data) ? cached.data : [], fromCache: true, stale: false, fetchedAt: cached.fetchedAt };
    } else {
      const end = new Date(nowMs), start = new Date(nowMs - recentDays * 86400000);
      const isoNvd = (d) => d.toISOString().replace(/\.\d{3}Z$/, '.000');
      const items = [];
      let pages = 0, failed = null;
      for (let startIndex = 0; pages < CVELANE_CAPS.maxNvdPages; pages++) {
        if (pages > 0) await sleep(CVELANE_CAPS.nvdPageSleepMs); // public budget: 5 req / 30s without a key
        const url = `${FEEDS.nvd.url}?lastModStartDate=${encodeURIComponent(isoNvd(start))}&lastModEndDate=${encodeURIComponent(isoNvd(end))}&resultsPerPage=${CVELANE_CAPS.nvdResultsPerPage}&startIndex=${startIndex}`;
        const r = await ghostGet(url, { agents: opts.agents, fetchImpl: opts.fetchImpl, timeoutMs: 30000, maxBytes: 24 * 1024 * 1024 });
        if (!r.ok || r.status !== 200) { failed = !r.ok ? `${r.error}: ${r.reason}` : `HTTP ${r.status}`; break; }
        let j;
        try { j = JSON.parse(r.body); } catch { failed = 'unparsable response'; break; }
        const page = Array.isArray(j.vulnerabilities) ? j.vulnerabilities : [];
        items.push(...page);
        startIndex += page.length;
        if (!page.length || startIndex >= (Number(j.totalResults) || 0)) break;
      }
      if (failed && !items.length) {
        errors.push({ feed: 'nvd', reason: `${failed} — ${cached ? 'serving the STALE cache (named, not hidden)' : 'NO cache to fall back on; the feed is empty this run, nothing fabricated'}` });
        nvd = cached ? { entries: Array.isArray(cached.data) ? cached.data : [], fromCache: true, stale: true, fetchedAt: cached.fetchedAt }
          : { entries: [], fromCache: false, stale: false, fetchedAt: null };
      } else {
        if (failed) errors.push({ feed: 'nvd', reason: `pagination stopped: ${failed} — partial window (${items.length} CVEs) kept and named partial` });
        if (pages >= CVELANE_CAPS.maxNvdPages) errors.push({ feed: 'nvd', reason: `page cap ${CVELANE_CAPS.maxNvdPages} hit — the window may be TRUNCATED (named, not hidden); narrow --recent-days for full coverage` });
        writeCache(nvdFile, FEEDS.nvd.url, items, nowMs);
        nvd = { entries: items, fromCache: false, stale: false, fetchedAt: new Date(nowMs).toISOString() };
      }
    }
  }
  return { kev, nvd, errors, windowDays: recentDays };
}

// --- the hypothesis engine (pure over feeds + tuples) ------------------------------------------

// scoreHypothesis({ kev, versionMatch, published, epss, nowMs }) → { score, reasons[] }.
export function scoreHypothesis({ kev, versionMatch, published, epss, nowMs } = {}) {
  let score = 20;
  const reasons = ['base +20 — a CVE record matched a recon-detected software identity'];
  const bump = (s, p, d) => { score += p; reasons.push(`${s} ${p >= 0 ? '+' : ''}${p} — ${d}`); };
  if (kev) bump('kev', 40, 'CISA KEV — exploited in the wild; the "fix-now" list');
  if (versionMatch === 'exact') bump('version', 25, 'the recon-observed version EXACTLY matches the disclosed vulnerable version');
  else if (versionMatch === 'in-range') bump('version', 20, 'the recon-observed version is INSIDE the disclosed vulnerable range');
  else bump('version', 5, 'versionMatch unknown — the feed carries no reliable range or recon saw no version; hypothesis stays, honestly weak');
  const now = Number.isFinite(Number(nowMs)) ? Number(nowMs) : Date.now();
  if (published) {
    const age = (now - Date.parse(published)) / 86400000;
    if (Number.isFinite(age) && age >= 0 && age <= CVELANE_CAPS.freshDays) bump('fresh', 10, `published/added ${Math.round(age)}d ago (<= ${CVELANE_CAPS.freshDays}d) — patch gaps are widest early`);
  }
  if (Number.isFinite(Number(epss))) {
    const e = Number(epss);
    if (e >= 0.5) bump('epss', 10, `EPSS ${e} — top exploitation-probability band`);
    else if (e >= 0.1) bump('epss', 5, `EPSS ${e}`);
  }
  return { score: Math.max(0, Math.min(100, Math.round(score))), reasons };
}

const VALIDATION_PLAN = (h) => [
  `Confirm the running version of ${h.software} on ${h.host} from observable evidence (${h.evidenceOfVersion ? 'already: ' + h.evidenceOfVersion : 'no version evidence yet — get some before ANY test'})`,
  `Read the CVE's references for affected-config prerequisites (a version match is NOT exploitability — modules, flags, and deployment decide)`,
  'Stage a non-destructive differential under the campaign validator (captured bytes + a control) inside the signed scope window — the hypothesis becomes a finding ONLY through that bar, then the novelty gate',
];

// matchTuples(tuples, feeds, { epssMap, nowMs }) — tuples: [{ program, host, software,
// version, evidence }]. Returns the scored, sorted HYPOTHESIS queue. Pure.
export function matchTuples(tuples, feeds, { epssMap, nowMs } = {}) {
  const out = [];
  const seen = new Set();
  for (const t of (Array.isArray(tuples) ? tuples : [])) {
    if (!t || !t.software) continue;
    const tokens = aliasTokens(t.software);
    const matches = [];
    for (const e of (feeds.kev || [])) {
      const m = kevToMatches(e, tokens);
      if (m) matches.push({ ...m, kev: true });
    }
    for (const item of (feeds.nvd || [])) {
      for (const m of nvdToMatches(item, tokens, { version: t.version })) {
        matches.push({ ...m, kev: (feeds.kev || []).some((e) => e.cveID === m.cve) });
      }
    }
    for (const m of matches) {
      const key = `${t.program}|${t.host}|${t.software}|${m.cve}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const epss = epssMap && Number.isFinite(Number(epssMap[m.cve])) ? Number(epssMap[m.cve]) : null;
      const { score, reasons } = scoreHypothesis({ kev: m.kev, versionMatch: m.versionMatch, published: m.published, epss, nowMs });
      out.push({
        status: 'HYPOTHESIS', // THE HONESTY LABEL — never a finding, never a draft
        routing: 'campaign-validator',
        program: t.program || null, host: t.host || null,
        software: t.software, version: t.version || null,
        cve: m.cve, kev: !!m.kev, epss,
        versionMatch: m.versionMatch, matchBasis: m.matchBasis,
        published: m.published, description: m.description || null, references: m.references || [],
        evidenceOfVersion: t.evidence ? `${t.evidence.source}: ${t.evidence.raw}` : null,
        score, reasons,
        validationPlan: VALIDATION_PLAN({ software: t.software, host: t.host, evidenceOfVersion: t.evidence ? `${t.evidence.source}: ${t.evidence.raw}` : null }),
        note: 'a version match is NOT exploitability — this is a validation work item, not a vulnerability',
      });
    }
  }
  out.sort((a, b) => b.score - a.score || String(a.cve).localeCompare(String(b.cve)));
  return out.slice(0, CVELANE_CAPS.maxHypotheses);
}

// watchScan(programs, feeds, { nowMs }) — the watchlist lane: per-program stack keywords
// (h1sync/intake metadata) against the feeds WITHOUT a detected version (host:null,
// versionMatch 'unknown'). For automation-prohibited programs the watchlist is INERT:
// emitted items are labelled watch-only (recon never runs there — the hypothesis exists so
// the operator can MANUALLY check, and it says so).
export function watchScan(programs, feeds, { nowMs } = {}) {
  const out = [];
  for (const p of (Array.isArray(programs) ? programs : [])) {
    const meta = [p.intake && p.intake.policy, p.h1sync && p.h1sync.scopeText, p.h1sync && p.h1sync.policyText].filter(Boolean).join('\n');
    const wl = watchlistFor(p.id, meta);
    if (!wl.tokens.length) continue;
    const prohibited = PROHIBITED_PROGRAMS.includes(String(p.id).toLowerCase());
    const tuples = wl.tokens.map((tok) => ({ program: p.id, host: null, software: tok, version: null, evidence: { source: 'watchlist', raw: `program metadata names this stack (${wl.pinned ? 'pinned' : 'detected'})` } }));
    const items = matchTuples(tuples, { kev: feeds.kev, nvd: [] }, { nowMs }); // KEV only for hostless watch
    for (const item of items.slice(0, 10)) {
      item.watchOnly = true;
      if (!wl.pinned) {
        // metadata-INFERRED stacks are weak evidence (a policy page saying "PHP" is not a
        // host observed running it) — score down and say so, never hide the weakness.
        item.score = Math.max(0, item.score - 10);
        item.reasons.push('weak-evidence -10 — the stack was inferred from program metadata text, not observed on a host');
      }
      if (prohibited) item.note += '; the program is automation-PROHIBITED — manual verification only, VARVEL never probes it';
      out.push(item);
    }
    // NVD watch: description-regex matches (plugin/theme CVE flood) — capped hard.
    for (const item of feeds.nvd || []) {
      for (const re of wl.descRes) {
        for (const m of nvdToMatches(item, wl.tokens, { descRe: re })) {
          const key = `${p.id}|watch|${m.cve}`;
          if (out.some((o) => o.cve === m.cve && o.program === p.id)) break;
          const { score, reasons } = scoreHypothesis({ kev: (feeds.kev || []).some((e) => e.cveID === m.cve), versionMatch: 'unknown', published: m.published, nowMs });
          if (!wl.pinned) { reasons.push('weak-evidence -10 — the stack was inferred from program metadata text, not observed on a host'); }
          out.push({
            status: 'HYPOTHESIS', routing: 'campaign-validator', watchOnly: true,
            program: p.id, host: null, software: wl.tokens[0], version: null,
            cve: m.cve, kev: (feeds.kev || []).some((e) => e.cveID === m.cve), epss: null,
            versionMatch: 'unknown', matchBasis: m.matchBasis, published: m.published,
            description: m.description, references: m.references, evidenceOfVersion: null,
            score: wl.pinned ? score : Math.max(0, score - 10), reasons, validationPlan: VALIDATION_PLAN({ software: wl.tokens[0], host: '<an in-scope host running it>', evidenceOfVersion: null }),
            note: 'watchlist match — no version evidence exists; confirm the stack is even deployed before any test' + (prohibited ? '; the program is automation-PROHIBITED — manual verification only' : ''),
          });
          break;
        }
      }
    }
  }
  const dedup = new Map();
  for (const i of out) if (!dedup.has(`${i.program}|${i.cve}`)) dedup.set(`${i.program}|${i.cve}`, i);
  return [...dedup.values()].sort((a, b) => b.score - a.score).slice(0, CVELANE_CAPS.maxHypotheses);
}

// --- campaign wiring (pure) ---------------------------------------------------------------------

// coverageItems(hypotheses) — CVE HYPOTHESES enter the campaign's coverage gate as QUEUED
// surface with source 'cvelane-hypothesis': the validator must drain (or consciously skip)
// each before the campaign may report DONE-CLEAN. Hostless watch items cannot be queued
// (no target) and are skipped with the count kept.
export function coverageItems(hypotheses) {
  const items = [];
  let hostless = 0;
  for (const h of (Array.isArray(hypotheses) ? hypotheses : [])) {
    if (!h || !h.host) { hostless++; continue; }
    items.push({
      kind: 'endpoint', key: h.path || '/', host: h.host,
      cve: h.cve, source: 'cvelane-hypothesis',
      note: `${h.cve} vs ${h.software}${h.version ? '/' + h.version : ''} (${h.versionMatch}) — HYPOTHESIS; validate via the campaign path, never draft directly`,
    });
  }
  return { items, hostless };
}

// toLaunchOptions(hypotheses, { targets }) — the launch-body shape engine/campaign.mjs
// consumes: hypotheses become campaign TARGETS under tooledRecon + the coverage-gated
// cveHypotheses lane. Hosts outside `targets` are NOT silently added — the caller scopes.
export function toLaunchOptions(hypotheses, { targets } = {}) {
  const ci = coverageItems(hypotheses);
  const hosts = [...new Set(ci.items.map((i) => i.host))];
  const scoped = Array.isArray(targets) && targets.length
    ? ci.items.filter((i) => targets.some((t) => i.host === t || i.host.endsWith('.' + t)))
    : ci.items;
  return {
    targets: Array.isArray(targets) && targets.length ? targets : hosts,
    tooledRecon: true, targetScore: true,
    cveHypotheses: scoped.map((i) => ({ kind: i.kind, key: i.key, host: i.host, cve: i.cve })),
    note: `${scoped.length} CVE HYPOTHESIS item(s) queued for coverage-gated validation (${ci.hostless} hostless watch item(s) cannot be queued)`,
  };
}

// --- scan: feeds + tuples + watchlists → the queue file ---------------------------------------

export async function scan(opts = {}) {
  const nowMs = Number.isFinite(Number(opts.nowMs)) ? Number(opts.nowMs) : Date.now();
  const feeds = await fetchFeeds(opts);
  const tuples = Array.isArray(opts.tuples) ? opts.tuples : [];
  const hypotheses = matchTuples(tuples, { kev: feeds.kev.entries, nvd: feeds.nvd.entries }, { epssMap: opts.epssMap, nowMs });
  const watch = watchScan(opts.programs || [], { kev: feeds.kev.entries, nvd: feeds.nvd.entries }, { nowMs });
  const items = [...hypotheses, ...watch].sort((a, b) => b.score - a.score || String(a.cve).localeCompare(String(b.cve))).slice(0, CVELANE_CAPS.maxHypotheses);
  return {
    tool: 'cvelane',
    label: 'HYPOTHESIS QUEUE — every item routes to the campaign/validator path; NOTHING here is a finding or a draft',
    generatedAt: new Date(nowMs).toISOString(),
    chain: opts.chain || GHOST_CHAIN(),
    feeds: {
      kev: { entries: feeds.kev.entries.length, fetchedAt: feeds.kev.fetchedAt, fromCache: feeds.kev.fromCache, stale: feeds.kev.stale },
      nvd: { entries: feeds.nvd.entries.length, fetchedAt: feeds.nvd.fetchedAt, fromCache: feeds.nvd.fromCache, stale: feeds.nvd.stale, windowDays: feeds.windowDays },
      errors: feeds.errors,
    },
    stats: { tuples: tuples.length, hypotheses: hypotheses.length, watch: watch.length, items: items.length },
    items,
    limitations: [
      'KEV carries no version ranges — every KEV match is versionMatch:unknown (KEV says "exploited against SOME version")',
      'a version match is NOT exploitability: modules/flags/deployment decide; the validator bar (captured bytes + differential) is unchanged',
      'NVD window coverage is capped at 3 pages (~600 CVEs) for politeness; truncation is named in feeds.errors',
      'EPSS is not fetched by default — epss fields are null unless an epssMap is supplied; never fabricated',
      'no system catches everything — CPE data quality and recon version-disclosure are the binding constraints, both carried as UNKNOWN when absent',
    ],
  };
}

// writeQueue(result, { outDir, date }) — data/exports/ only (the standing exception).
export function writeQueue(result, { outDir, date } = {}) {
  const dir = outDir || process.env.VARVEL_CVELANE_OUT || join(VARVEL_ROOT, 'data', 'exports');
  mkdirSync(dir, { recursive: true });
  const d = date || String(result.generatedAt).slice(0, 10);
  const p = join(dir, `cve-hypotheses-${d}.json`);
  writeFileSync(p, JSON.stringify(result, null, 2) + '\n');
  return { jsonPath: p };
}

// loadHypothesesFile(path) → the items array of a written queue (campaign-launch helper).
export function loadHypothesesFile(path) {
  try {
    const j = JSON.parse(readFileSync(String(path), 'utf8'));
    return Array.isArray(j.items) ? j.items : [];
  } catch { return []; }
}

// --- CLI ----------------------------------------------------------------------------------------
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === join(process.argv[1]);
if (isMain) {
  const args = process.argv.slice(2);
  const cmd = args[0] || 'scan';
  const opt = (name) => { const i = args.indexOf('--' + name); return i >= 0 ? args[i + 1] : null; };
  const has = (name) => args.includes('--' + name);
  if (cmd === 'fetch') {
    const feeds = await fetchFeeds({ refresh: has('refresh') });
    console.log(JSON.stringify({ kev: { ...feeds.kev, entries: feeds.kev.entries.length }, nvd: { ...feeds.nvd, entries: feeds.nvd.entries.length }, errors: feeds.errors }, null, 2));
    process.exit(feeds.errors.length && !feeds.kev.entries.length && !feeds.nvd.entries.length ? 3 : 0);
  }
  if (cmd !== 'scan') {
    console.error('usage: node tools/cvelane.mjs scan [--tuples widerecon.json] [--out dir] [--refresh] [--json] [--no-write] | fetch [--refresh]');
    process.exit(64);
  }
  let tuples = [];
  const tf = opt('tuples');
  if (tf) {
    try {
      const j = JSON.parse(readFileSync(tf, 'utf8'));
      tuples = Array.isArray(j.softwareTuples) ? j.softwareTuples : (Array.isArray(j) ? j : []);
    } catch (e) { console.error(`cannot read tuples from ${tf}: ${(e && e.message) || e}`); process.exit(65); }
  }
  // The watchlist lane reads the roster's h1sync/intake metadata (local files) so
  // stack-class CVEs without a detected version still surface — kill with --no-watch.
  let programs = [];
  if (!has('no-watch')) {
    const filter = opt('programs') ? opt('programs').split(',').map((s) => s.toLowerCase()) : null;
    programs = loadIntakes().map((j) => ({ id: j.entry.id, intake: j.intake, h1sync: j.h1sync }))
      .filter((p) => !filter || filter.includes(String(p.id).toLowerCase()));
  }
  const result = await scan({ tuples, programs, refresh: has('refresh') });
  let paths = null;
  if (!has('no-write')) paths = writeQueue(result, { outDir: opt('out') || undefined });
  if (has('json')) console.log(JSON.stringify(result, null, 2));
  else {
    console.log(`${result.label}\n`);
    console.log(`feeds: KEV ${result.feeds.kev.entries}${result.feeds.kev.fromCache ? ' (cache)' : ''}${result.feeds.kev.stale ? ' STALE' : ''} · NVD ${result.feeds.nvd.entries}${result.feeds.nvd.fromCache ? ' (cache)' : ''}${result.feeds.nvd.stale ? ' STALE' : ''}`);
    for (const e of result.feeds.errors) console.log(`feed error [${e.feed}]: ${e.reason}`);
    console.log(`\n${result.items.length} HYPOTHESES (top 20):`);
    for (const h of result.items.slice(0, 20)) {
      console.log(`  ${String(h.score).padStart(3)}  ${h.cve}${h.kev ? ' [KEV]' : ''}  ${h.software}${h.version ? '/' + h.version : ''} @ ${h.host || '(watchlist)'} [${h.program || '?'}] — ${h.versionMatch}`);
    }
    if (paths) console.error(`\nwrote ${paths.jsonPath}`);
  }
}
