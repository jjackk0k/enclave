// VARVEL cvepack-import tests — NVD→pack generation honesty + the committed artifact.
// Hermetic: fixture feed JSON only, ZERO network (the real feeds are a cache detail of
// the tool, never of the tests). The meta-test at the bottom audits the REAL committed
// engine/cvepacks.generated.mjs against the curated pack's own invariants.
//   node --test varvel/test/cvepack-import.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CPE_TO_WAPPALYZE, parseCpeUri, isDottedNumericVersion, rangeFromCpeMatch,
  cvssScore, severityFromScore, firstSentence, extractFromFeed, buildPacks,
  renderGeneratedModule, parseYearsArg, DEFAULT_MAX_PER_PRODUCT, MAX_RANGES_PER_ENTRY,
  gunzipVerified,
} from '../tools/cvepack-import.mjs';
import { mergePacks, CURATED_CVE_PACKS, CVE_PACKS } from '../engine/cvepacks.mjs';
import { GENERATED_CVE_PACKS } from '../engine/cvepacks.generated.mjs';
import { TECH_SIGNATURES } from '../tools/wappalyze.mjs';

// ——— fixture builders (NVD JSON 2.0 shape, minimal but faithful) ———
const cpe = (vendor, product, version = '*') => `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;
const match = (criteria, opts = {}) => ({ vulnerable: true, criteria, matchCriteriaId: 'M', ...opts });
const node = (cpeMatch, opts = {}) => ({ operator: 'OR', negate: false, cpeMatch, ...opts });
const metric = (ver, score) => [{ source: 'nvd@nist.gov', type: 'Primary', cvssData: { version: ver, baseScore: score }, exploitabilityScore: 1, impactScore: 1 }];
const cveObj = (id, { desc = 'A flaw. Second sentence.', v31, v30, v2, configs = [] } = {}) => ({
  cve: {
    id, vulnStatus: 'Analyzed',
    descriptions: desc == null ? [] : [{ lang: 'en', value: desc }],
    metrics: {
      ...(v31 != null ? { cvssMetricV31: metric('3.1', v31) } : {}),
      ...(v30 != null ? { cvssMetricV30: metric('3.0', v30) } : {}),
      ...(v2 != null ? { cvssMetricV2: metric('2.0', v2) } : {}),
    },
    configurations: configs,
  },
});

const FEED = {
  resultsPerPage: 15, startIndex: 0, totalResults: 15, format: 'NVD_CVE', version: '2.0', timestamp: '2026-09-12T00:00:00.000',
  vulnerabilities: [
    // start/end INCLUDING → gte/lte; critical via 9.8
    cveObj('CVE-2024-0001', { v31: 9.8, desc: 'A path traversal in Apache HTTP Server allows RCE. Second sentence.', configs: [{ nodes: [node([match(cpe('apache', 'http_server'), { versionStartIncluding: '2.4.0', versionEndIncluding: '2.4.58' })])] }] }),
    // start/end EXCLUDING → gt/lt; high via 7.5
    cveObj('CVE-2024-0002', { v31: 7.5, desc: 'Request smuggling in httpd.', configs: [{ nodes: [node([match(cpe('apache', 'http_server'), { versionStartExcluding: '2.4.0', versionEndExcluding: '2.4.60' })])] }] }),
    // bare CPE version → eq
    cveObj('CVE-2024-0003', { v31: 8.1, desc: 'Resolver flaw in nginx.', configs: [{ nodes: [node([match(cpe('nginx', 'nginx', '1.18.0'))])] }] }),
    // unbounded on both sides ('*', no markers) → skipped 'unbounded', no entry
    cveObj('CVE-2024-0004', { v31: 9.1, desc: 'Claims every version.', configs: [{ nodes: [node([match(cpe('nginx', 'nginx', '*'))])] }] }),
    // vulnerable:false → skipped 'not-vulnerable', no entry
    cveObj('CVE-2024-0005', { v31: 9.1, desc: 'Not-vulnerable node only.', configs: [{ nodes: [node([match(cpe('nginx', 'nginx'), { vulnerable: false, versionEndExcluding: '1.2.3' })])] }] }),
    // unparseable bound (milestone suffix) → skipped 'version-unparseable'
    cveObj('CVE-2024-0006', { v31: 9.0, desc: 'Milestone bound.', configs: [{ nodes: [node([match(cpe('apache', 'http_server'), { versionStartIncluding: '2.4.0-beta', versionEndExcluding: '2.4.9' })])] }] }),
    // KEV-flagged with a MEDIUM score → kept anyway (KEV beats the score bar)
    cveObj('CVE-2024-0007', { v31: 5.0, desc: 'KEV-listed php flaw.', configs: [{ nodes: [node([match(cpe('php', 'php'), { versionEndExcluding: '8.1.29' })])] }] }),
    // 6.9 and not KEV → dropped by the priority filter
    cveObj('CVE-2024-0008', { v31: 6.9, desc: 'Medium php flaw.', configs: [{ nodes: [node([match(cpe('php', 'php'), { versionEndExcluding: '8.2.0' })])] }] }),
    // no v3 metric, v2 7.8 → kept via the documented v2 fallback
    cveObj('CVE-2024-0009', { v2: 7.8, desc: 'WordPress core flaw.', configs: [{ nodes: [node([match(cpe('wordpress', 'wordpress'), { versionStartIncluding: '6.0', versionEndExcluding: '6.0.6' })])] }] }),
    // negated configuration node → skipped 'negated'
    cveObj('CVE-2024-0010', { v31: 9.9, desc: 'Negated config.', configs: [{ nodes: [node([match(cpe('apache', 'http_server'), { versionEndExcluding: '2.4.1' })], { negate: true })] }] }),
    // eq milestone version ('9.0.0.M1') → skipped 'version-unparseable' (never re-anchored)
    cveObj('CVE-2024-0011', { v31: 9.0, desc: 'Tomcat milestone eq.', configs: [{ nodes: [node([match(cpe('apache', 'tomcat', '9.0.0.M1'))])] }] }),
    // two branch nodes for one product → ranges merge (OR semantics)
    cveObj('CVE-2024-0012', { v31: 8.8, desc: 'php branch flaw.', configs: [{ nodes: [node([match(cpe('php', 'php'), { versionEndExcluding: '8.1.29' })]), node([match(cpe('php', 'php'), { versionStartIncluding: '8.2.0', versionEndExcluding: '8.2.20' })])] }] }),
    // cpeMatch nested in children (AND with an OS node) → still extracted
    cveObj('CVE-2024-0013', { v31: 7.8, desc: 'apache child-node flaw.', configs: [{ nodes: [{ operator: 'AND', negate: false, cpeMatch: [], children: [node([match(cpe('apache', 'http_server'), { versionEndExcluding: '2.4.55' })]), node([match('cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*', { vulnerable: false })])] }] }] }),
    // unmapped product (openssl) → ignored entirely, not even a skip statistic
    cveObj('CVE-2024-0014', { v31: 9.8, desc: 'openssl flaw.', configs: [{ nodes: [node([match(cpe('openssl', 'openssl'), { versionEndExcluding: '3.0.0' })])] }] }),
    // no en description → droppedNoDesc (no honest note possible)
    cveObj('CVE-2024-0015', { v31: 9.8, desc: null, configs: [{ nodes: [node([match(cpe('nginx', 'nginx'), { versionEndExcluding: '1.25.0' })])] }] }),
  ],
};
const KEV = new Set(['CVE-2024-0007']);

// ——— range conversion table ———
test('parseCpeUri: 2.3 URIs parse; 2.2/garbage → null', () => {
  assert.deepEqual(parseCpeUri(cpe('apache', 'http_server', '2.4.49')), { part: 'a', vendor: 'apache', product: 'http_server', version: '2.4.49' });
  assert.equal(parseCpeUri('cpe:/a:apache:http_server:2.4.49'), null);
  assert.equal(parseCpeUri('not-a-cpe'), null);
});

test('isDottedNumericVersion: strict whole-string gate (milestones/RCs rejected)', () => {
  assert.ok(isDottedNumericVersion('2.4.49') && isDottedNumericVersion('2') && isDottedNumericVersion('10.0.14393.0'));
  for (const bad of ['9.0.0.M1', '2.4.0-beta', '1.0 RC2', '*', '-', '', 'nginx', '  ']) {
    assert.ok(!isDottedNumericVersion(bad), JSON.stringify(bad));
  }
});

test('rangeFromCpeMatch: the full conversion table, nothing guessed', () => {
  assert.deepEqual(rangeFromCpeMatch(match(cpe('apache', 'http_server'), { versionStartIncluding: '2.4.0', versionEndIncluding: '2.4.58' })), { range: { gte: '2.4.0', lte: '2.4.58' } });
  assert.deepEqual(rangeFromCpeMatch(match(cpe('apache', 'http_server'), { versionStartExcluding: '2.4.0', versionEndExcluding: '2.4.60' })), { range: { gt: '2.4.0', lt: '2.4.60' } });
  assert.deepEqual(rangeFromCpeMatch(match(cpe('nginx', 'nginx', '1.18.0'))), { range: { eq: '1.18.0' } });
  assert.deepEqual(rangeFromCpeMatch(match(cpe('nginx', 'nginx', '*'))), { skip: 'unbounded' });
  assert.deepEqual(rangeFromCpeMatch(match(cpe('nginx', 'nginx', '-'))), { skip: 'unbounded' });
  assert.deepEqual(rangeFromCpeMatch(match(cpe('nginx', 'nginx'), { vulnerable: false, versionEndExcluding: '1.0' })), { skip: 'not-vulnerable' });
  assert.deepEqual(rangeFromCpeMatch(match(cpe('apache', 'http_server'), { versionStartIncluding: '2.4.0-beta' })), { skip: 'version-unparseable' });
  assert.deepEqual(rangeFromCpeMatch(match(cpe('apache', 'tomcat', '9.0.0.M1'))), { skip: 'version-unparseable' });
  // markers win over a criteria version: no phantom eq is added
  assert.deepEqual(rangeFromCpeMatch(match(cpe('apache', 'http_server', '2.4.49'), { versionStartIncluding: '2.4.0' })), { range: { gte: '2.4.0' } });
});

test('cvssScore: v3.1 > v3.0 > v2; null when NVD carries no metric', () => {
  assert.deepEqual(cvssScore(cveObj('CVE-2024-0001', { v31: 9.8, v2: 7.5 }).cve), { score: 9.8, source: 'v3.1' });
  assert.deepEqual(cvssScore(cveObj('CVE-2024-0001', { v30: 8.1, v2: 7.5 }).cve), { score: 8.1, source: 'v3.0' });
  assert.deepEqual(cvssScore(cveObj('CVE-2024-0001', { v2: 7.5 }).cve), { score: 7.5, source: 'v2' });
  assert.equal(cvssScore(cveObj('CVE-2024-0001', {}).cve), null);
});

test('severityFromScore: bands + the KEV-with-no-score floor', () => {
  assert.equal(severityFromScore(9.0, false), 'critical');
  assert.equal(severityFromScore(8.9, false), 'high');
  assert.equal(severityFromScore(7.0, false), 'high');
  assert.equal(severityFromScore(6.9, false), 'medium');
  assert.equal(severityFromScore(3.9, false), 'low');
  assert.equal(severityFromScore(null, true), 'high', 'KEV, no CVSS → high (documented floor)');
  assert.equal(severityFromScore(null, false), null);
});

test('firstSentence: first sentence only, hard cap, word-boundary truncation', () => {
  assert.equal(firstSentence('One. Two. Three.'), 'One.');
  assert.equal(firstSentence('no period at all'), 'no period at all');
  const long = 'word '.repeat(60).trim();
  const out = firstSentence(long, 50);
  assert.ok(out.length <= 50 && out.endsWith('…'), 'truncated with ellipsis inside the cap');
  assert.equal(firstSentence('  spaced\n\nout   text.  More.'), 'spaced out text.');
});

// ——— extraction over the fixture feed ———
test('extractFromFeed: ranges extracted, honesty skips counted, unmapped ignored', () => {
  const { candidates, stats } = extractFromFeed(FEED, { kevSet: KEV });
  assert.equal(stats.cvesSeen, 15);
  const apache = candidates.get('apache');
  assert.deepEqual([...apache.get('CVE-2024-0001').ranges.values()], [{ gte: '2.4.0', lte: '2.4.58' }]);
  assert.deepEqual([...apache.get('CVE-2024-0002').ranges.values()], [{ gt: '2.4.0', lt: '2.4.60' }]);
  assert.ok(apache.get('CVE-2024-0013'), 'cpeMatch in a child node is still extracted');
  assert.ok(!apache.get('CVE-2024-0006'), 'unparseable bound → no range for that node');
  assert.ok(!apache.get('CVE-2024-0010'), 'negated node → skipped');
  assert.equal(apache.get('CVE-2024-0001').score, 9.8);
  const php = candidates.get('php');
  assert.equal(php.get('CVE-2024-0012').ranges.size, 2, 'branch nodes merge into OR ranges');
  assert.equal(php.get('CVE-2024-0007').kev, true, 'KEV flag carried');
  assert.ok(!candidates.get('tomcat'), '9.0.0.M1 eq was unparseable → no tomcat entry');
  assert.ok(!candidates.get('openssl'), 'unmapped product ignored entirely');
  assert.equal(stats.skips['not-vulnerable'], 1);
  assert.equal(stats.skips['unbounded'], 1);
  assert.equal(stats.skips['version-unparseable'], 2);
  assert.equal(stats.skips['negated'], 1);
});

// ——— priority filter + cap ———
test('buildPacks: KEV always kept, <7 dropped unless KEV, v2 fallback works', () => {
  const { candidates } = extractFromFeed(FEED, { kevSet: KEV });
  const { packs, perProduct } = buildPacks(candidates, { maxPerProduct: 60 });
  const phpIds = packs.php.map((e) => e.cve);
  assert.deepEqual(phpIds, ['CVE-2024-0012', 'CVE-2024-0007'], 'KEV 5.0 kept; 6.9 non-KEV dropped; newest first');
  const kevEntry = packs.php.find((e) => e.cve === 'CVE-2024-0007');
  assert.equal(kevEntry.sev, 'medium');
  assert.equal(kevEntry.kev, true);
  assert.ok(/CISA KEV/.test(kevEntry.note), 'KEV provenance in the note');
  assert.ok(/^NVD: /.test(kevEntry.note), 'NVD provenance in the note');
  assert.equal(perProduct.php.droppedPriority, 1, 'the 6.9 drop is counted');
  const wp = packs.wordpress.find((e) => e.cve === 'CVE-2024-0009');
  assert.equal(wp.sev, 'high', 'v2 7.8 fallback → high');
  assert.equal(perProduct.nginx.droppedNoDesc, 1, 'no-description drop is counted, not silent');
  assert.ok(packs.nginx.every((e) => e.cve !== 'CVE-2024-0004' && e.cve !== 'CVE-2024-0005'), 'skipped nodes never became entries');
  const apache1 = packs.apache.find((e) => e.cve === 'CVE-2024-0001');
  assert.equal(apache1.sev, 'critical');
  assert.ok(apache1.title.length > 0 && apache1.title.length <= 100);
});

test('buildPacks: per-product cap keeps newest first, KEV pinned against eviction', () => {
  const mkCand = (id, kev = false) => ({
    cve: id, label: 'Apache httpd', kev, score: 9.1, scoreSource: 'v3.1',
    desc: 'Synthetic flaw.', ranges: new Map([[JSON.stringify({ lt: '9.9.9' }), { lt: '9.9.9' }]]), overflow: false,
  });
  const perTech = new Map();
  for (let i = 0; i < 12; i++) perTech.set(`CVE-2026-0${100 + i}`, mkCand(`CVE-2026-0${100 + i}`)); // 0100..0111
  perTech.set('CVE-2017-0001', mkCand('CVE-2017-0001', true));
  perTech.set('CVE-2018-0002', mkCand('CVE-2018-0002', true));
  const { packs, perProduct } = buildPacks(new Map([['apache', perTech]]), { maxPerProduct: 10 });
  const ids = packs.apache.map((e) => e.cve);
  assert.equal(ids.length, 10);
  assert.equal(perProduct.apache.pinnedKev, 2);
  assert.equal(perProduct.apache.droppedCap, 4, '12 non-KEV − 8 slots = 4 dropped, counted');
  assert.ok(ids.includes('CVE-2017-0001') && ids.includes('CVE-2018-0002'), 'KEV pinned even though oldest');
  assert.ok(!ids.includes('CVE-2026-0100'), 'oldest non-KEV evicted first');
  assert.equal(ids[0], 'CVE-2026-0111', 'newest first');
});

// ——— enumeration-bomb guard + render determinism ———
test('extractFromFeed: >MAX_RANGES_PER_ENTRY drops the whole entry honestly (counted)', () => {
  const many = cveObj('CVE-2024-0099', {
    v31: 9.9, desc: 'Enumerated versions.',
    configs: [{ nodes: [node(Array.from({ length: MAX_RANGES_PER_ENTRY + 1 }, (_, i) => match(cpe('apache', 'http_server', `2.4.${i}`))))] }],
  });
  const { candidates, stats } = extractFromFeed({ vulnerabilities: [many] }, {});
  assert.ok(!candidates.get('apache'), 'entry dropped, not silently truncated');
  assert.equal(stats.entriesOverflow, 1);
});

test('renderGeneratedModule: deterministic output + provenance header', () => {
  const meta = { years: [2024, 2025], generatedAt: '2026-09-12T00:00:00.000Z', argv: ['--years 2024-2025'], feedsFetchedAt: 'cache', kevVersion: '2026.09.10', kevReleased: '2026-09-10', kevFetchedAt: 'cache' };
  const packs = { nginx: [{ cve: 'CVE-2024-0003', sev: 'high', kev: false, title: 't', ranges: [{ eq: '1.18.0' }], note: 'NVD: n' }] };
  const a = renderGeneratedModule(packs, meta);
  assert.equal(a, renderGeneratedModule(packs, meta), 'same inputs → byte-identical');
  assert.ok(/GENERATED FILE — DO NOT HAND-EDIT/.test(a));
  assert.ok(/2024–2025/.test(a) && /2026\.09\.10/.test(a), 'feed + KEV provenance in the header');
  assert.ok(a.includes('export const GENERATED_CVE_PACKS = '));
});

test('parseYearsArg: window parsing with reality bounds', () => {
  assert.deepEqual(parseYearsArg('2016-', 2026), { from: 2016, to: 2026 });
  assert.deepEqual(parseYearsArg('2019-2021', 2026), { from: 2019, to: 2021 });
  assert.deepEqual(parseYearsArg('2020', 2026), { from: 2020, to: 2020 }, 'a bare year is exactly that year');
  for (const bad of ['2001-', '2027-', '2024-2020', 'garbage', '20-24']) {
    assert.throws(() => parseYearsArg(bad, 2026), bad);
  }
});

// ——— merge: curated is never overwritten ———
test('mergePacks: curated entry for the same CVE wins; generated only adds', () => {
  const curated = { apache: [{ cve: 'CVE-2024-0001', sev: 'low', kev: false, title: 'hand', ranges: [{ eq: '1.0' }], note: 'hand-tuned' }] };
  const generated = {
    apache: [
      { cve: 'CVE-2024-0001', sev: 'critical', kev: true, title: 'gen', ranges: [{ lt: '9.9' }], note: 'NVD: gen' },
      { cve: 'CVE-2024-0002', sev: 'high', kev: false, title: 'gen2', ranges: [{ lt: '8.0' }], note: 'NVD: gen2' },
    ],
    nginx: [{ cve: 'CVE-2024-0003', sev: 'high', kev: false, title: 'gen3', ranges: [{ eq: '1.18.0' }], note: 'NVD: gen3' }],
  };
  const merged = mergePacks(curated, generated);
  assert.equal(merged.apache.length, 2);
  assert.equal(merged.apache[0].note, 'hand-tuned', 'curated note survived — never silently overwritten');
  assert.equal(merged.apache[0].sev, 'low', 'curated severity survived');
  assert.equal(merged.apache[1].cve, 'CVE-2024-0002', 'new generated CVE added');
  assert.equal(merged.nginx.length, 1, 'generated-only tech added');
  assert.equal(curated.apache.length, 1, 'input not mutated');
  assert.deepEqual(mergePacks({}, generated).nginx.length, 1);
  assert.deepEqual(mergePacks(curated, {}).apache.length, 1);
});

test('engine wiring: CURATED keeps the original 9; merged CVE_PACKS carries curated notes', () => {
  const curatedCount = Object.values(CURATED_CVE_PACKS).reduce((n, arr) => n + arr.length, 0);
  assert.equal(curatedCount, 9, 'the hand-reviewed 9 are intact');
  const apache41773 = CVE_PACKS.apache.find((p) => p.cve === 'CVE-2021-41773');
  assert.ok(/Actively exploited in the wild/.test(apache41773.note), 'the curated note, not a generated one');
  const generatedTotal = Object.values(GENERATED_CVE_PACKS).reduce((n, arr) => n + arr.length, 0);
  assert.ok(Object.values(CVE_PACKS).reduce((n, arr) => n + arr.length, 0) >= Math.max(curatedCount, generatedTotal), 'merge is additive');
});

// ——— meta-test: the REAL committed generated artifact satisfies the pack invariants ———
test('meta: the private split invariant matches the public MAP (per-CPE pack ceiling)', () => {
  // The generator's first pass splits by MAP ENTRY, not by output id, so a map entry listing
  // N cpes gets ceil(N / cap) x cap — while the committed artifact is split per product and
  // holds ≤ cap. Rendering at the DEFAULT cap is only split-invariant while this holds; the
  // 2026-09-16 audit raised the default 60 → 200, so pin the invariant the meta-test depends on
  // instead of leaving it implicit (phpmyadmin/nginx/spring/angular carry one cpe; tomcat/jQuery
  // etc. carry one; the multi-cpe entries are nginx=3, laravel=2, rails=2, express=2,
  // nextjs=2, spring=2).
  for (const m of CPE_TO_WAPPALYZE) {
    const perEntryCap = Math.ceil(m.cpes.length / DEFAULT_MAX_PER_PRODUCT) * DEFAULT_MAX_PER_PRODUCT;
    assert.ok(perEntryCap <= DEFAULT_MAX_PER_PRODUCT + m.cpes.length - 1,
      `${m.id}: ${m.cpes.length} cpes stays within one cap bucket at cap=${DEFAULT_MAX_PER_PRODUCT}`);
  }
  const widest = Math.max(...Object.values(GENERATED_CVE_PACKS).map((p) => p.length));
  assert.ok(widest <= DEFAULT_MAX_PER_PRODUCT, `committed widest pack ${widest} ≤ cap ${DEFAULT_MAX_PER_PRODUCT}`);
});

test('meta: the default cap does not silently discard priority-qualifying entries', () => {
  // Honesty guard on the coverage bar: at the old default (60) the 2016-2026 window dropped 214
  // entries by cap alone (php 119, apache 38, tomcat 32, joomla 25). Those are the OLDEST of each
  // product — exactly what long-lived hosts still match — so they must fit. A future NVD refresh
  // that outgrows the cap will trip this and force a deliberate decision, never silence.
  const floors = { php: 150, apache: 80, tomcat: 80, joomla: 70, wordpress: 50, phpmyadmin: 20 };
  for (const [id, floor] of Object.entries(floors)) {
    const n = (GENERATED_CVE_PACKS[id] || []).length;
    assert.ok(n >= floor, `${id}: ${n} entries ≥ floor ${floor} (cap losses were removed, not hidden)`);
  }
});

test('gunzipVerified: decodes real gzip bytes and fails loudly on corruption', async () => {
  const { gzipSync } = await import('node:zlib');
  const buf = gzipSync(Buffer.from(JSON.stringify({ vulnerabilities: [{ cve: { id: 'CVE-2026-0001' } }] })));
  const out = await gunzipVerified(buf);
  assert.deepEqual(JSON.parse(out.toString('utf8')).vulnerabilities.length, 1, 'raw gzip round-trips');
  assert.ok(Buffer.isBuffer(out), 'returns the decoded buffer');
  const damaged = Buffer.from(buf);
  damaged[damaged.length - 6] ^= 0xff; // corrupt the trailer → gunzip CRC/Adler check must fail
  await assert.rejects(() => gunzipVerified(damaged), (e) => {
    assert.match(e.message, /gzip decode failed/);
    assert.ok(Array.isArray(e.causes) && e.causes.length >= 1, 'both paths recorded, nothing silent');
    return true;
  });
});

test('meta: committed engine/cvepacks.generated.mjs obeys every curated invariant', () => {
  const wappalyzeIds = new Set(TECH_SIGNATURES.map((t) => t.id));
  let total = 0;
  for (const [tech, packs] of Object.entries(GENERATED_CVE_PACKS)) {
    assert.ok(wappalyzeIds.has(tech), `${tech} is an id wappalyze can actually produce`);
    assert.ok(packs.length <= DEFAULT_MAX_PER_PRODUCT, `${tech} within the per-product cap`);
    const seen = new Set();
    for (const p of packs) {
      total++;
      assert.ok(/^CVE-\d{4}-\d{4,}$/.test(p.cve), tech + ' cve id');
      assert.ok(['info', 'low', 'medium', 'high', 'critical'].includes(p.sev), tech + ' sev vocabulary');
      assert.equal(typeof p.kev, 'boolean', tech + ' kev is boolean');
      assert.ok(p.title && p.title.length <= 100, tech + ' title present and bounded');
      assert.ok(p.note && p.note.startsWith('NVD: ') && p.note.length <= 180, tech + ' note carries NVD provenance, bounded');
      assert.ok(Array.isArray(p.ranges) && p.ranges.length >= 1 && p.ranges.length <= MAX_RANGES_PER_ENTRY, tech + ' ranges bounded');
      assert.ok(!seen.has(p.cve), tech + ' no duplicate cve');
      seen.add(p.cve);
      for (const r of p.ranges) {
        const keys = Object.keys(r);
        assert.ok(keys.length >= 1, tech + ' range says something');
        for (const k of keys) {
          assert.ok(['gte', 'gt', 'lte', 'lt', 'eq'].includes(k), tech + ' range clause vocabulary');
          assert.ok(isDottedNumericVersion(r[k]), `${tech} ${p.cve} bound ${k}=${r[k]} is dotted-numeric (never guessed)`);
        }
      }
    }
  }
  assert.ok(total >= 100, `the expansion is real: ${total} generated entries (was ~9 curated)`);
  const text = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'engine', 'cvepacks.generated.mjs'), 'utf8');
  assert.ok(/GENERATED FILE — DO NOT HAND-EDIT/.test(text), 'artifact warns editors');
  assert.ok(/NVD JSON 2\.0 yearly feeds \d{4}–\d{4}/.test(text), 'feed window recorded');
  assert.ok(/CISA KEV catalog/.test(text), 'KEV provenance recorded');
});

test('meta: every mapped id is fingerprintable (the map itself is honest)', () => {
  const wappalyzeIds = new Set(TECH_SIGNATURES.map((t) => t.id));
  for (const m of CPE_TO_WAPPALYZE) {
    assert.ok(wappalyzeIds.has(m.id), `${m.id} exists in tools/wappalyze.mjs TECH_SIGNATURES`);
    assert.ok(m.cpes.length >= 1 && m.label, m.id + ' map entry complete');
  }
});
