// VARVEL — NVD → CVE-pack generator (engine/cvepacks.generated.mjs).
//
// The curated pack (engine/cvepacks.mjs) is hand-reviewed and tiny by design — great
// for the 9 entries a human verified, silent on everything else. This tool expands it
// HONESTLY from primary sources: the official NVD JSON 2.0 yearly feeds plus the CISA
// KEV catalog, emitting engine/cvepacks.generated.mjs in the exact curated shape.
// The engine merges the two (curated always wins per-CVE). The generated file is a
// VERSIONED BUILD ARTIFACT: committed on purpose so findings are reproducible and the
// pack diffs are reviewable. Never hand-edit it — regenerate.
//
// USAGE
//   node tools/cvepack-import.mjs                     # feeds 2016–now, cache-aware
//   node tools/cvepack-import.mjs --years 2019-2024   # explicit window (2002..now)
//   node tools/cvepack-import.mjs --max-per-product 40
//   node tools/cvepack-import.mjs --offline           # cache only; fails if absent
//   node tools/cvepack-import.mjs --refresh           # re-download even if cached
//   Monthly refresh: run with --refresh, review the diff, run npm test, commit.
//   (If a huge year ever OOMs this box: node --max-old-space-size=6144 …)
//
// SOURCES (plain HTTPS, gzip decoded locally, cached raw under data/cvepack-cache/
// with sha256 in manifest.json — re-runs are cheap and the snapshot is reproducible)
//   · https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-<YEAR>.json.gz
//   · https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
// NVD etiquette: strictly sequential downloads, a fixed pause between files, no
// parallelism, no retry storms (a failed feed fails the run loudly — cache survives).
//
// PRODUCT SELECTION — the CPE→wappalyze map below. Rule: a pack is emitted ONLY for
// an id tools/wappalyze.mjs can actually produce (TECH_SIGNATURES). Deliberate drops,
// so nobody "fixes" them later:
//   · openssl, varnish, haproxy, jetty, jboss, weblogic, struts, jenkins — no
//     wappalyze id exists; keying a pack to an id that can never appear is fiction.
//   · node.js (nodejs:node.js, 1133 vulnerable nodes) — the fingerprint vocabulary
//     has `express` (the framework), nothing version-bearing for the node runtime
//     itself; mapping node CVEs onto an express banner would conflate two products.
//   · aspnet — its fingerprinted "version" is a CLR build (4.0.30319), which does not
//     line up with NVD's ASP.NET CPE versions; mapping it would invent ranges.
//   · shopify / cloudflare / akamai / ga / gtm / recaptcha / hcaptcha — SaaS tags,
//     not versioned products a version→CVE pack can speak about honestly.
//   · react / vue — no version capture in the signature table.
//   A pack whose id has no version capture TODAY (tomcat, laravel, django, rails,
//   express, spring, nextjs — same posture as the curated tomcat entries) is inert,
//   never wrong: cveCheck fires only when some fingerprint source supplies a version.
//
// RANGE EXTRACTION — from CPE match nodes of mapped products only:
//   versionStartIncluding/Excluding → gte/gt, versionEndIncluding/Excluding → lte/lt,
//   a bare CPE version (not '*'/'-') → eq. HONESTY RULES (each skip is counted and
//   printed — nothing is silently dropped, and a range is NEVER guessed):
//   · nodes with vulnerable:false are skipped ('not-vulnerable');
//   · nodes under a negated configuration node are skipped ('negated');
//   · a node unbounded on BOTH sides says nothing → skipped ('unbounded');
//   · any bound/eq version that is not strictly dotted-numeric (parseVersion over the
//     WHOLE string — '9.0.0.M1' milestones would silently re-anchor to the release)
//     → skipped ('version-unparseable');
//   · entries that would exceed MAX_RANGES_PER_ENTRY (version-enumeration bombs)
//     → skipped whole ('too-many-ranges'), because dropping ranges silently is worse.
//
// PRIORITY FILTER — keep KEV-flagged always (active exploitation beats any score);
// otherwise CVSS v3.x base ≥ 7.0, falling back to v2 ≥ 7.0 when no v3 metric exists.
// Cap per product (default 60): KEV entries are pinned and never capped out; the
// remaining slots fill newest-first by CVE id so the pack stays reviewable.
// sev bands from the base score: critical ≥ 9, high 7–8.9, medium 4–6.9, low < 4;
// a KEV entry with no CVSS in NVD gets 'high' (the floor of "actively exploited").

import { gunzipSync, createGunzip } from 'node:zlib';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { parseVersion } from '../engine/cvepacks.mjs';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const CACHE_DIR = join(REPO, 'data', 'cvepack-cache');
const OUT_FILE = join(REPO, 'engine', 'cvepacks.generated.mjs');
const NVD_FEED = (y) => `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-${y}.json.gz`;
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

export const DEFAULT_FROM_YEAR = 2016;        // sane recency window; older is archaeology
export const DEFAULT_MAX_PER_PRODUCT = 200;   // reviewability cap (KEV pinned, newest first).
// RAISED 60 → 200 on 2026-09-16 (coverage audit): at 60 the generator was DROPPING 214
// priority-qualifying entries outright — apache 38, php 119, tomcat 32, joomla 25 — i.e. 40%
// of the correlation table was discard-by-cap, and the discarded entries were the OLDEST of
// each product (the ones long-lived, unpatched hosts actually still match). 200 clears the
// cap losses entirely for the 2016-2026 window (widest kept pack is php at 179). Any future
// run that starts dropping becomes visible in the `dropped(cap)` column rather than silent.
export const MAX_RANGES_PER_ENTRY = 32;       // version-enumeration bomb guard
export const MIN_CVSS = 7.0;                  // priority bar (KEV bypasses)
const FETCH_DELAY_MS = 3000;                  // NVD etiquette: one file, pause, next
const FETCH_TIMEOUT_MS = 180_000;

// ——— the curated CPE → wappalyze-id map (see header for the drop list) ———
// cpes: exact 'vendor:product' pairs from the CPE 2.3 URI. Multiple pairs feed one id
// where NVD renamed the vendor/product over time — verified against the 2016–2026
// feeds (node counts in comments): f5 owns nginx since 2019 (f5:nginx_plus is the
// COMMERCIAL product and is deliberately excluded — a bare "nginx/x" banner cannot
// prove Plus); ZEIT is Vercel's old name; NVD spells Joomla with its escaped bang;
// express moved to the OpenJS Foundation vendor; laravel:framework is the framework
// package (laravel:laravel is the app skeleton).
export const CPE_TO_WAPPALYZE = [
  { id: 'apache',    label: 'Apache httpd',      cpes: ['apache:http_server'] },                    // 337 nodes
  { id: 'nginx',     label: 'nginx',             cpes: ['f5:nginx', 'f5:nginx_open_source', 'nginx:nginx'] }, // 45+45 (+0 legacy)
  { id: 'iis',       label: 'Microsoft IIS',     cpes: ['microsoft:internet_information_services'] }, // 1 node — most IIS CVEs file under the Windows OS CPE, honestly thin
  { id: 'php',       label: 'PHP',               cpes: ['php:php'] },                               // 2604 nodes
  { id: 'tomcat',    label: 'Apache Tomcat',     cpes: ['apache:tomcat'] },                         // 3465 nodes
  { id: 'jquery',    label: 'jQuery',            cpes: ['jquery:jquery'] },                         // 6 nodes
  { id: 'wordpress', label: 'WordPress',         cpes: ['wordpress:wordpress'] },                   // 720 nodes — core only, plugins are other products
  { id: 'drupal',    label: 'Drupal',            cpes: ['drupal:drupal'] },                         // 1835 nodes
  { id: 'joomla',    label: 'Joomla',            cpes: ['joomla:joomla\\!'] },                      // 1642 nodes — NVD's escaped "joomla!"
  { id: 'laravel',   label: 'Laravel',           cpes: ['laravel:laravel', 'laravel:framework'] },  // 15+18 nodes
  { id: 'django',    label: 'Django',            cpes: ['djangoproject:django'] },                  // 477 nodes
  { id: 'rails',     label: 'Ruby on Rails',     cpes: ['rubyonrails:rails', 'rubyonrails:ruby_on_rails'] }, // 517+34 nodes
  { id: 'express',   label: 'Express (Node.js)', cpes: ['expressjs:express', 'openjsf:express'] },  // 0+25 nodes
  { id: 'nextjs',    label: 'Next.js',           cpes: ['vercel:next.js', 'zeit:next.js'] },        // 512+21 nodes
  { id: 'spring',    label: 'Spring (Java)',     cpes: ['vmware:spring_framework', 'pivotal_software:spring_framework'] }, // 309+7 — framework only (boot/security are separate products a bare fingerprint can't prove)
  { id: 'angular',   label: 'Angular',           cpes: ['angular:angular'] },                       // 256 nodes — Angular 2+ (AngularJS 1.x is a different product)
  { id: 'phpmyadmin', label: 'phpMyAdmin',       cpes: ['phpmyadmin:phpmyadmin'] },                 // 3732 nodes — the largest mapped family; fingerprint captures the version when the login page states it
];
// DELIBERATE DROPS, RE-VERIFIED 2026-09-16 against the cached 2016-2026 feeds (the coverage
// audit re-scanned every CPE a:vendor:product pair for these products; counts are node tallies):
//   · oracle:http_server (158 nodes) — product IS fingerprintable in principle, but NVD numbers
//     Oracle HTTP Server separately (12.2.x builds). Its code is Apache httpd, yet its version
//     axis is NOT Apache's, so folding it into the `apache` pack would let an OHS-only CVE match
//     a plain `Server: Apache/x.y.z` host. A false positive is worse than a gap: skipped, named.
//   · apache:httpd (0 nodes) — confirms apache:http_server above is the right axis (sanity check).
//   · gunicorn / werkzeug / envoy / traefik / caddy / lighttpd / h2o — no NVD CPE pair under
//     those spellings and no wappalyze signature; nothing to map without inventing a fingerprint.
//   · nodejs:node.js (1139 nodes) — deliberately excluded (see the node.js note above).
//   · shopify / netlify / vercel-dashboard — SaaS tags, not versioned products.
// Lookup table: 'vendor:product' → { id, label } (built once from CPE_TO_WAPPALYZE).
export function cpeLookup(map = CPE_TO_WAPPALYZE) {
  const t = new Map();
  for (const m of map) for (const c of m.cpes) t.set(c, { id: m.id, label: m.label });
  return t;
}

// ——— pure extraction helpers (exported for tests; no I/O below this line) ———

// Strict dotted-numeric gate: the WHOLE trimmed string must be digits+dots and
// parseVersion must agree. Stricter than bare parseVersion on purpose — its prefix
// rule would read '9.0.0.M1' as [9,0,0] and silently re-anchor a milestone range to
// the final release. We never guess a range.
export function isDottedNumericVersion(v) {
  return /^\d+(?:\.\d+)*$/.test(String(v || '').trim()) && parseVersion(v) !== null;
}

// Parse a CPE 2.3 URI → { vendor, product, version } or null when malformed/not 2.3.
// (CPE names in NVD configurations are always the 2.3 URI form.)
export function parseCpeUri(uri) {
  const parts = String(uri || '').split(':');
  if (parts.length < 6 || parts[0] !== 'cpe' || parts[1] !== '2.3') return null;
  return { part: parts[2], vendor: parts[3], product: parts[4], version: parts[5] };
}

// Convert ONE cpeMatch node for an already-mapped product into a pack range.
// Returns { range } or { skip: reason } — never an invented range.
export function rangeFromCpeMatch(match) {
  if (match?.vulnerable !== true) return { skip: 'not-vulnerable' };
  const parsed = parseCpeUri(match.criteria);
  if (!parsed) return { skip: 'bad-cpe' };
  const range = {};
  const bounds = [
    ['versionStartIncluding', 'gte'], ['versionStartExcluding', 'gt'],
    ['versionEndIncluding', 'lte'], ['versionEndExcluding', 'lt'],
  ];
  let hasBound = false;
  for (const [key, clause] of bounds) {
    const v = match[key];
    if (v == null || v === '') continue;
    if (!isDottedNumericVersion(v)) return { skip: 'version-unparseable' };
    range[clause] = v;
    hasBound = true;
  }
  if (!hasBound) {
    // No range markers: a concrete CPE version means "exactly this version".
    const v = parsed.version;
    if (v && v !== '*' && v !== '-') {
      if (!isDottedNumericVersion(v)) return { skip: 'version-unparseable' };
      range.eq = v;
      hasBound = true;
    }
  }
  if (!hasBound) return { skip: 'unbounded' }; // says nothing about versions
  return { range };
}

// Best available CVSS base score for a CVE: v3.1, then v3.0, then v2 (documented
// fallback). Returns { score, source } or null when NVD carries no metric at all.
export function cvssScore(cve) {
  const m = cve?.metrics || {};
  const pick = (arr, path) => {
    const e = Array.isArray(arr) && arr[0];
    const score = e && path(e);
    return typeof score === 'number' && Number.isFinite(score) ? score : null;
  };
  const v31 = pick(m.cvssMetricV31, (e) => e.cvssData?.baseScore);
  if (v31 != null) return { score: v31, source: 'v3.1' };
  const v30 = pick(m.cvssMetricV30, (e) => e.cvssData?.baseScore);
  if (v30 != null) return { score: v30, source: 'v3.0' };
  const v2 = pick(m.cvssMetricV2, (e) => e.cvssData?.baseScore);
  if (v2 != null) return { score: v2, source: 'v2' };
  return null;
}

// Severity vocabulary of the curated pack, banded from a numeric base score.
// kev with no score → 'high': actively exploited is never 'medium', and inventing
// 'critical' would be a guess. Documented in the header.
export function severityFromScore(score, kev) {
  if (score == null) return kev ? 'high' : null;
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

// First sentence of an NVD description, hard-capped (bounded everything). A sentence
// ends at '. ' or end-of-text; a long single sentence truncates at a word boundary
// with an ellipsis. Whitespace is collapsed — descriptions carry stray newlines.
export function firstSentence(text, max = 140) {
  const clean = String(text || '').replace(/\s+/g, ' ').trim();
  if (!clean) return '';
  const end = clean.indexOf('. ');
  const sentence = end === -1 ? clean : clean.slice(0, end + 1);
  if (sentence.length <= max) return sentence;
  const cut = sentence.slice(0, max - 1);
  const sp = cut.lastIndexOf(' ');
  const at = sp > Math.floor(max * 0.5) ? sp : cut.length; // word boundary, else hard cut
  return cut.slice(0, at).trimEnd() + '…';
}

// Walk one NVD feed (parsed JSON 2.0) and collect per-product CVE candidates.
// candidates: Map<techId, Map<cveId, { cve, label, kev, score, scoreSource, desc,
//   ranges: Map<canonicalJson, range>, overflow }>> — ranges dedupe by canonical JSON.
// stats.skips counts every honesty skip by reason (capped per reason defensively).
export function extractFromFeed(feed, { kevSet = new Set(), map = CPE_TO_WAPPALYZE } = {}) {
  const lookup = cpeLookup(map);
  const candidates = new Map();
  const stats = { cvesSeen: 0, nodesMatched: 0, skips: {}, entriesOverflow: 0 };
  const skip = (reason) => { stats.skips[reason] = (stats.skips[reason] || 0) + 1; };
  const walkNode = (node, cve, negated) => {
    if (node?.negate === true) negated = true;
    for (const match of node?.cpeMatch || []) {
      const parsed = parseCpeUri(match?.criteria);
      const target = parsed && lookup.get(`${parsed.vendor}:${parsed.product}`);
      if (!target) continue; // not a mapped product — the overwhelming common case
      stats.nodesMatched++;
      if (negated) { skip('negated'); continue; }
      const { range, skip: reason } = rangeFromCpeMatch(match);
      if (reason) { skip(reason); continue; }
      let perTech = candidates.get(target.id);
      if (!perTech) candidates.set(target.id, (perTech = new Map()));
      let entry = perTech.get(cve.id);
      if (!entry) {
        const scoreInfo = cvssScore(cve);
        entry = {
          cve: cve.id, label: target.label, kev: kevSet.has(cve.id),
          score: scoreInfo ? scoreInfo.score : null, scoreSource: scoreInfo ? scoreInfo.source : null,
          desc: (cve.descriptions || []).find((d) => d.lang === 'en')?.value || '',
          ranges: new Map(), overflow: false,
        };
        perTech.set(cve.id, entry);
      }
      if (entry.ranges.size >= MAX_RANGES_PER_ENTRY) entry.overflow = true;
      else entry.ranges.set(JSON.stringify(range), range);
    }
    for (const child of node?.children || []) walkNode(child, cve, negated);
  };
  for (const vuln of feed?.vulnerabilities || []) {
    const cve = vuln?.cve;
    if (!cve?.id) continue;
    stats.cvesSeen++;
    for (const config of cve.configurations || []) {
      for (const node of config.nodes || []) walkNode(node, cve, false);
    }
  }
  // Enumeration-bomb guard, applied once per entry (not per node): drop the WHOLE
  // entry honestly rather than ship a silently truncated range list.
  for (const [tech, perTech] of candidates) {
    for (const [id, entry] of perTech) {
      if (entry.overflow) { perTech.delete(id); stats.entriesOverflow++; }
    }
    if (!perTech.size) candidates.delete(tech);
  }
  return { candidates, stats };
}

// Apply the priority filter + per-product cap and render final pack entries.
// Returns { packs: { techId: [entry…] }, perProduct: { techId: { kept, pinnedKev,
// droppedPriority, droppedNoDesc, droppedCap } } }. Entry order: newest first.
export function buildPacks(candidates, { maxPerProduct = DEFAULT_MAX_PER_PRODUCT, minCvss = MIN_CVSS } = {}) {
  const packs = {};
  const perProduct = {};
  const newestFirst = (a, b) => cveSortKey(b.cve) - cveSortKey(a.cve) || (a.cve < b.cve ? -1 : 1);
  for (const [tech, perTech] of [...candidates.entries()].sort()) {
    const stats = { kept: 0, pinnedKev: 0, droppedPriority: 0, droppedNoDesc: 0, droppedCap: 0 };
    const eligible = [];
    for (const cand of perTech.values()) {
      const sev = severityFromScore(cand.score, cand.kev);
      const passes = cand.kev || (cand.score != null && cand.score >= minCvss);
      if (!passes || !sev) { stats.droppedPriority++; continue; }
      if (!cand.desc) { stats.droppedNoDesc++; continue; } // no honest note possible
      const kevTail = cand.kev ? ' — CISA KEV (actively exploited)' : '';
      const note = 'NVD: ' + firstSentence(cand.desc, 165 - kevTail.length) + kevTail; // ≤170, suffix never hard-cut
      const title = firstSentence(cand.desc, 88);
      if (!note || !title) { stats.droppedNoDesc++; continue; }
      eligible.push({
        cve: cand.cve, sev, kev: !!cand.kev, title,
        ranges: [...cand.ranges.values()],
        note,
        _kev: !!cand.kev,
      });
    }
    eligible.sort(newestFirst);
    // KEV entries are pinned: the cap can never evict an actively-exploited CVE.
    const pinned = eligible.filter((e) => e._kev);
    const rest = eligible.filter((e) => !e._kev);
    const roomForRest = Math.max(0, maxPerProduct - pinned.length);
    const kept = [...pinned, ...rest.slice(0, roomForRest)].sort(newestFirst);
    stats.droppedCap = Math.max(0, rest.length - roomForRest);
    stats.pinnedKev = pinned.length;
    stats.kept = kept.length;
    if (kept.length) {
      packs[tech] = kept.map(({ _kev, ...entry }) => entry);
      perProduct[tech] = stats;
    }
  }
  return { packs, perProduct };
}

// Numeric sort key for "newest first": year * 1e7 + sequence. Malformed ids sort last.
function cveSortKey(id) {
  const m = /^CVE-(\d{4})-(\d{4,})$/.exec(id || '');
  return m ? Number(m[1]) * 1e7 + Number(m[2]) : -1;
}

// Render engine/cvepacks.generated.mjs: a self-contained data module (no imports) so
// the engine can never fail on a tool dependency. Deterministic: products sorted,
// entries newest-first, fixed key order — same inputs, byte-identical output.
export function renderGeneratedModule(packs, meta = {}) {
  const years = meta.years || [];
  const total = Object.values(packs).reduce((n, arr) => n + arr.length, 0);
  const header = [
    '// VARVEL — GENERATED version→CVE correlation pack (merged by engine/cvepacks.mjs).',
    '//',
    '// /!\\ GENERATED FILE — DO NOT HAND-EDIT. It is a versioned build artifact on',
    '// purpose: the repo pins the exact NVD/KEV snapshot the engine reasons over, so',
    '// findings reproduce and pack changes review as ordinary diffs. Regenerate:',
    '//     node tools/cvepack-import.mjs            (cached feeds; monthly refresh)',
    '//     node tools/cvepack-import.mjs --refresh  (re-download the feeds)',
    '//',
    `// Generated: ${meta.generatedAt || 'unknown'} by tools/cvepack-import.mjs ${(meta.argv || []).join(' ')}`.trimEnd(),
    `// Sources (raw bytes cached under data/cvepack-cache/, sha256 in manifest.json):`,
    `//   · NVD JSON 2.0 yearly feeds ${years.length ? years[0] + '–' + years[years.length - 1] : '—'} (${years.length} files), fetched ${meta.feedsFetchedAt || 'unknown'}`,
    `//   · CISA KEV catalog ${meta.kevVersion || ''} (released ${meta.kevReleased || 'unknown'}), fetched ${meta.kevFetchedAt || 'unknown'}`,
    '//',
    '// Same honesty contract as the curated pack: entries fire ONLY on a fingerprinted',
    '// version, and a version match is confidence firm, never confirmed. Rules enforced',
    '// by the generator (tools/cvepack-import.mjs documents them in full): KEV always',
    '// kept; otherwise CVSS v3 ≥ 7.0 (v2 fallback); ranges come ONLY from NVD CPE match',
    '// nodes — vulnerable:false skipped, negated skipped, unbounded-both-sides skipped,',
    '// non dotted-numeric versions skipped (a range is never guessed); ≤' + (meta.maxPerProduct || DEFAULT_MAX_PER_PRODUCT) + ' entries per',
    '// product, KEV pinned, newest first.',
    `// Entries: ${total} across ${Object.keys(packs).length} products.`,
  ];
  return header.join('\n') + '\n\nexport const GENERATED_CVE_PACKS = ' + JSON.stringify(packs, null, 2) + ';\n';
}

// ——— I/O below this line (fetch/cache/write; tested only via the real run) ———

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

// gunzip in a STREAM, verified by the gunzip CRC over a whole-file decode. Why not
// gunzipSync (measured 2026-09-16, .tmp/gunzip-probe2.mjs + .tmp/gunzip-rate.log): on this
// box the ONE-SHOT sync zlib path throws Z_DATA_ERROR ("incorrect data check" = Adler-32
// mismatch) on ~1 in 6 decodes of the SAME sha256-verified 2026 feed bytes (348MB out), while
// the streaming path decoded the identical bytes cleanly on every run (0 fails / 24 decodes).
// The bytes are provably intact (sha256 == manifest), so the fault is in the sync path under
// this host's memory/AV filtering — not in the data and not in the network.
//
// Recovery doctrine (bounded, honest, never silent): up to DECODE_ATTEMPTS decodes are
// attempted PER PATH; whatever succeeds is validated for shape (vulnerabilities array) and
// only then returned. gunzipSync is preferred on success (CPU-cheap, 110ms for 108MB out);
// streaming is the fallback that measured reliable. If neither path decodes, the error is
// thrown loudly with both causes recorded — nothing is half-parsed, cached or guessed at.
export const DECODE_ATTEMPTS = 2;
export async function gunzipVerified(buf) {
  const errs = [];
  for (let i = 0; i < DECODE_ATTEMPTS; i++) {
    try { return gunzipSync(buf); } catch (e) { errs.push(`sync:${e.code || e.message}`); }
  }
  for (let i = 0; i < DECODE_ATTEMPTS; i++) {
    try {
      const chunks = [];
      await new Promise((resolve, reject) => {
        Readable.from([buf]).pipe(createGunzip())
          .on('data', (c) => chunks.push(c))
          .on('end', resolve).on('error', reject);
      });
      return Buffer.concat(chunks);
    } catch (e) { errs.push(`stream:${e.code || e.message}`); }
  }
  const err = new Error(`gzip decode failed on ${DECODE_ATTEMPTS}x2 attempts (${errs.join(', ')})`);
  err.causes = errs;
  throw err;
}

// Validate+decode a feed's raw bytes BEFORE they are trusted or cached: gunzip when
// the bytes say gzip, tolerate an edge that served identity JSON, and require the
// NVD/KEV shape (a vulnerabilities array). Anything else fails loudly — a corrupt
// feed is never parsed, never cached, never guessed at.
async function decodeFeed(buf, label) {
  let text;
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    try { text = (await gunzipVerified(buf)).toString('utf8'); }
    catch (e) { throw new Error(`${label}: ${e.message} — the cached/raw bytes are not decompressible (a corrupt feed is never parsed)`); }
  }
  else if (String(buf.toString('utf8', 0, 64)).trimStart().startsWith('{')) text = buf.toString('utf8');
  else throw new Error(`${label}: neither gzip nor JSON (first bytes ${buf.subarray(0, 4).toString('hex')})`);
  const feed = JSON.parse(text);
  if (!Array.isArray(feed?.vulnerabilities)) throw new Error(`${label}: parsed but no vulnerabilities array — corrupt feed`);
  return feed;
}

// Fetch one feed into the cache (validated raw bytes), or serve it from cache.
// Sequential by construction — callers await each file before requesting the next.
// Retries are BOUNDED (5 attempts, 5s…20s backoff — resilience, not a hammer): this
// box's VPN path corrupts large mid-stream bytes with the length intact, and only the
// gzip CRC catches it; validation before caching means a poisoned cache can never exist.
async function fetchWithCache(url, file, { offline = false, refresh = false, attempts = 5 } = {}) {
  const dest = join(CACHE_DIR, file);
  if (existsSync(dest) && !refresh) {
    const buf = readFileSync(dest);
    try {
      return { feed: await decodeFeed(buf, file), buf, from: 'cache' };
    } catch (e) {
      if (offline) throw new Error(`--offline: cached ${file} failed validation: ${e.message}`);
      // poisoned cache (a previous truncated run) — fall through and re-download
    }
  }
  if (offline) {
    throw new Error(`--offline: cache miss for ${file} (${dest}) — run online once to seed the cache`);
  }
  let lastErr = null;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      // accept-encoding identity: we want the exact .gz bytes (some CDN edges label
      // the gzip FILE with content-encoding: gzip, which a client would double-decode).
      const res = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS), headers: { 'accept-encoding': 'identity' } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const buf = Buffer.from(await res.arrayBuffer());
      const len = Number(res.headers.get('content-length'));
      if (len && buf.length !== len) throw new Error(`truncated body (${buf.length}/${len} bytes)`);
      const feed = await decodeFeed(buf, file); // validate BEFORE anything touches the cache
      mkdirSync(dirname(dest), { recursive: true });
      writeFileSync(dest, buf);
      return { feed, buf, from: 'network' };
    } catch (e) {
      lastErr = e;
      if (attempt < attempts) await sleep(5000 * attempt);
    }
  }
  throw new Error(`fetch ${url} failed after ${attempts} bounded attempts: ${lastErr.message} — cache intact, re-run to continue`);
}

// Parse --years: '2016-' (2016..now) | '2016-2024' | '2019' (exactly 2019). Bounded
// against reality (NVD starts at 2002; the future hasn't happened yet).
export function parseYearsArg(s, nowYear = new Date().getFullYear()) {
  const m = /^(\d{4})(?:-(\d{4})?)?$/.exec(String(s || '').trim());
  if (!m) throw new Error(`--years must look like 2016- or 2016-2024 (got "${s}")`);
  const from = Number(m[1]);
  const to = m[2] ? Number(m[2]) : (String(s).includes('-') ? nowYear : from);
  if (from < 2002 || to > nowYear || from > to) {
    throw new Error(`--years window ${from}-${to} outside the sane 2002-${nowYear} range`);
  }
  return { from, to };
}

// The full import: fetch feeds → extract → filter/cap → write the generated module.
// Returns { packs, perProduct, skipTotals, meta } for the CLI summary. No git, no
// mutation of anything outside data/cvepack-cache/ and engine/cvepacks.generated.mjs.
export async function runImport({ yearsArg = `${DEFAULT_FROM_YEAR}-`, maxPerProduct = DEFAULT_MAX_PER_PRODUCT, offline = false, refresh = false, outFile = OUT_FILE } = {}) {
  const { from, to } = parseYearsArg(yearsArg);
  const years = [];
  for (let y = from; y <= to; y++) years.push(y);
  const meta = { years, argv: [`--years ${from}-${to === new Date().getFullYear() ? '' : to}`.trim(), `--max-per-product ${maxPerProduct}`], generatedAt: new Date().toISOString(), maxPerProduct };

  // 1) KEV catalog (small; fetched first so kev flags are ready for extraction).
  const kevRaw = await fetchWithCache(KEV_URL, 'known_exploited_vulnerabilities.json', { offline, refresh });
  const kev = kevRaw.feed;
  const kevSet = new Set((kev.vulnerabilities || []).map((v) => v.cveID));
  meta.kevVersion = kev.catalogVersion || null;
  meta.kevReleased = kev.dateReleased || null;
  meta.kevCount = kevSet.size;
  // Provenance continuity: a cache-served file keeps its ORIGINAL fetch timestamp
  // from the previous manifest instead of being restamped — the manifest answers
  // "when were these exact bytes downloaded", not "when did I last read them". For a
  // pre-manifest cache the file's own mtime is the honest arrival time on this box.
  let prevManifest = null;
  try { prevManifest = JSON.parse(readFileSync(join(CACHE_DIR, 'manifest.json'), 'utf8')); } catch { prevManifest = null; }
  const arrivalTime = (file) => {
    try { return statSync(join(CACHE_DIR, file)).mtime.toISOString(); } catch { return 'unknown'; }
  };
  const isDate = (d) => typeof d === 'string' && d.startsWith('2'); // an ISO year, not an 'unknown' placeholder
  const prevFetchedAt = (file) => (isDate(prevManifest?.feeds?.[file]?.fetchedAt) ? prevManifest.feeds[file].fetchedAt : arrivalTime(file));
  meta.kevFetchedAt = kevRaw.from === 'cache' ? (isDate(prevManifest?.kev?.fetchedAt) ? prevManifest.kev.fetchedAt : arrivalTime('known_exploited_vulnerabilities.json')) : meta.generatedAt;
  meta.kevSha = sha256(kevRaw.buf);
  const manifest = { generatedAt: meta.generatedAt, offline, feeds: {}, kev: { url: KEV_URL, sha256: meta.kevSha, bytes: kevRaw.buf.length, from: kevRaw.from, fetchedAt: meta.kevFetchedAt, catalogVersion: meta.kevVersion } };

  // 2) NVD yearly feeds, strictly sequential with a fixed pause between downloads.
  const merged = new Map(); // techId → Map<cveId, cand>
  const skipTotals = {};
  const perProduct = {};
  let feedsFromCache = 0;
  let lastDownload = 0;
  const fetchedAts = [];
  for (const y of years) {
    const file = `nvdcve-2.0-${y}.json.gz`;
    if (!existsSync(join(CACHE_DIR, file)) || refresh) {
      const wait = FETCH_DELAY_MS - (Date.now() - lastDownload);
      if (lastDownload && wait > 0) await sleep(wait); // NVD etiquette, no hammering
      lastDownload = Date.now();
    }
    const { feed, buf, from: src } = await fetchWithCache(NVD_FEED(y), file, { offline, refresh });
    if (src === 'cache') feedsFromCache++;
    const fetchedAt = src === 'network' ? meta.generatedAt : (prevFetchedAt(file) || 'unknown (pre-manifest cache)');
    fetchedAts.push(fetchedAt);
    manifest.feeds[file] = { url: NVD_FEED(y), sha256: sha256(buf), bytes: buf.length, from: src, fetchedAt };
    const { candidates, stats } = extractFromFeed(feed, { kevSet });
    for (const [reason, n] of Object.entries(stats.skips)) skipTotals[reason] = (skipTotals[reason] || 0) + n;
    skipTotals['too-many-ranges'] = (skipTotals['too-many-ranges'] || 0) + stats.entriesOverflow;
    for (const [tech, perTech] of candidates) {
      let dst = merged.get(tech);
      if (!dst) merged.set(tech, (dst = new Map()));
      for (const [id, cand] of perTech) {
        const cur = dst.get(id);
        if (!cur) dst.set(id, cand);
        else for (const [k, r] of cand.ranges) if (cur.ranges.size < MAX_RANGES_PER_ENTRY) cur.ranges.set(k, r);
      }
    }
  }
  const latestFetch = fetchedAts.filter((d) => d.startsWith('2')).sort().pop() || null; // ISO dates start with the year
  meta.feedsFetchedAt = feedsFromCache === years.length
    ? `${latestFetch || 'unknown'} (all from cache)`
    : (feedsFromCache ? `${meta.generatedAt} (${feedsFromCache}/${years.length} cached)` : meta.generatedAt);
  mkdirSync(CACHE_DIR, { recursive: true });
  writeFileSync(join(CACHE_DIR, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');

  // 3) Priority filter + cap, then write the generated module.
  const { packs, perProduct: pp } = buildPacks(merged, { maxPerProduct });
  Object.assign(perProduct, pp);
  const text = renderGeneratedModule(packs, meta);
  mkdirSync(dirname(outFile), { recursive: true });
  writeFileSync(outFile, text);
  return { packs, perProduct, skipTotals, meta, outFile };
}

// ——— CLI ———
function parseCli(argv) {
  const opts = { yearsArg: `${DEFAULT_FROM_YEAR}-`, maxPerProduct: DEFAULT_MAX_PER_PRODUCT, offline: false, refresh: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--years') opts.yearsArg = argv[++i];
    else if (a === '--max-per-product') opts.maxPerProduct = Math.max(1, Number(argv[++i]) || DEFAULT_MAX_PER_PRODUCT);
    else if (a === '--offline') opts.offline = true;
    else if (a === '--refresh') opts.refresh = true;
    else if (a === '--help' || a === '-h') opts.help = true;
    else throw new Error(`unknown flag ${a} (try --help)`);
  }
  if (opts.offline && opts.refresh) throw new Error('--offline and --refresh contradict each other');
  return opts;
}

async function main() {
  const opts = parseCli(process.argv.slice(2));
  if (opts.help) {
    console.log('node tools/cvepack-import.mjs [--years 2016-] [--max-per-product 60] [--offline] [--refresh]\nReads NVD JSON 2.0 feeds + CISA KEV → writes engine/cvepacks.generated.mjs. See the file header.');
    return;
  }
  const { packs, perProduct, skipTotals, meta, outFile } = await runImport(opts);
  const total = Object.values(packs).reduce((n, arr) => n + arr.length, 0);
  console.log(`cvepack-import: NVD ${meta.years[0]}–${meta.years[meta.years.length - 1]} (${meta.years.length} feeds, fetched ${meta.feedsFetchedAt}) + KEV ${meta.kevVersion || ''} (${meta.kevCount} CVEs)`);
  console.log('product           kept  kev-pinned  dropped(priority)  dropped(no-desc)  dropped(cap)');
  let dP = 0, dN = 0, dC = 0;
  for (const [tech, s] of Object.entries(perProduct).sort()) {
    console.log(`${tech.padEnd(16)} ${String(s.kept).padStart(5)} ${String(s.pinnedKev).padStart(11)} ${String(s.droppedPriority).padStart(17)} ${String(s.droppedNoDesc).padStart(17)} ${String(s.droppedCap).padStart(13)}`);
    dP += s.droppedPriority; dN += s.droppedNoDesc; dC += s.droppedCap;
  }
  console.log(`${'TOTAL'.padEnd(16)} ${String(total).padStart(5)} ${''.padStart(11)} ${String(dP).padStart(17)} ${String(dN).padStart(17)} ${String(dC).padStart(13)}`);
  console.log('honesty skips (range-level, counted never silent): ' + (Object.entries(skipTotals).sort().map(([k, v]) => `${k}=${v}`).join(', ') || 'none'));
  console.log(`wrote ${outFile} (${total} entries, ${Object.keys(packs).length} products) — run npm test before committing`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((e) => { console.error('cvepack-import FAILED honestly:', e.message); process.exit(1); });
}
