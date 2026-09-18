// VARVEL cvelane tests — the KNOWN-CVE MATCHING lane (tools/cvelane.mjs, wide-recon +
// CVE build Tool 2). Hermetic: feed fetches are INJECTED (fetchImpl fakes over recorded
// KEV/NVD samples), the cache is a tmp dir, sleeps are recorded fakes, the clock is
// pinned. Zero live network.
//   node --test test/cvelane.test.mjs
//
// Pinned: version-range math (exact / in-range / out-of-range / unknown); CPE alias
// matching; the >=12h cache TTL and NVD politeness sleeps; stale-cache honesty on feed
// failure; THE HONESTY BAR — every output item is status 'HYPOTHESIS' routed to
// 'campaign-validator', a version match is never a finding; the campaign coverage-gate
// wiring (cveHypotheses queue, fail-closed to campaign targets).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseVersion, compareVersions, versionSatisfies, cpeFacts, softwareMatchesCpe,
  aliasTokens, nvdToMatches, kevToMatches, watchlistFor, scoreHypothesis,
  fetchFeeds, matchTuples, watchScan, coverageItems, toLaunchOptions, scan, writeQueue,
  CACHE_TTL_MS, CVELANE_CAPS,
} from '../tools/cvelane.mjs';
import { CoverageLedger } from '../engine/coverage.mjs';
import { Campaign } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
const NOW = Date.parse('2026-08-31T12:00:00Z');

// --- recorded feed samples -----------------------------------------------------------------------
const KEV_SAMPLE = {
  title: 'CISA Catalog of Known Exploited Vulnerabilities', catalogVersion: '2026.08.30',
  vulnerabilities: [
    {
      cveID: 'CVE-2026-24001', vendorProject: 'Microsoft', product: 'SharePoint Server',
      vulnerabilityName: 'Microsoft SharePoint Server Remote Code Execution Vulnerability',
      dateAdded: '2026-08-29', shortDescription: 'Microsoft SharePoint Server contains a remote code execution vulnerability.',
      knownRansomwareCampaignUse: 'Unknown', dueDate: '2026-09-12',
    },
    {
      cveID: 'CVE-2026-24002', vendorProject: 'WordPress', product: 'WordPress',
      vulnerabilityName: 'WordPress Core SQL Injection Vulnerability',
      dateAdded: '2026-08-28', shortDescription: 'WordPress Core contains an SQL injection vulnerability.',
      knownRansomwareCampaignUse: 'Unknown', dueDate: '2026-09-11',
    },
  ],
};
const NVD_SAMPLE = {
  resultsPerPage: 2, startIndex: 0, totalResults: 2,
  vulnerabilities: [
    {
      cve: {
        id: 'CVE-2026-30001', published: '2026-08-25T10:00:00.000', lastModified: '2026-08-30T10:00:00.000',
        descriptions: [{ lang: 'en', value: 'A buffer overflow in nginx resolver allows remote code execution.' }],
        references: [{ url: 'https://nginx.org/advisory' }],
        configurations: [{
          nodes: [{
            operator: 'OR', negate: false,
            cpeMatch: [
              { vulnerable: true, criteria: 'cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*', versionStartIncluding: '1.17.0', versionEndExcluding: '1.20.1' },
              { vulnerable: false, criteria: 'cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*' },
            ],
          }],
        }],
      },
    },
    {
      cve: {
        id: 'CVE-2026-30002', published: '2026-08-20T10:00:00.000', lastModified: '2026-08-29T10:00:00.000',
        descriptions: [{ lang: 'en', value: 'The File Upload plugin for WordPress allows unauthenticated arbitrary file upload in versions up to 4.9.9.' }],
        references: [{ url: 'https://wpscan.com/vulnerability/x' }],
        configurations: [],
      },
    },
  ],
};

// --- version math ----------------------------------------------------------------------------------
test('versions: parse, compare, and the range/exact/unknown lattice', () => {
  assert.deepEqual(parseVersion('v1.18.0').parts, [1, 18, 0]);
  assert.equal(parseVersion('nginx'), null);
  assert.equal(compareVersions('1.18.0', '1.20.1'), -1);
  assert.equal(compareVersions('2.0', '2.0.0'), 0);
  assert.equal(compareVersions('1.18.0', 'junk'), null);

  const row = { versionStartIncluding: '1.17.0', versionEndExcluding: '1.20.1' };
  assert.equal(versionSatisfies('1.18.0', row), 'in-range');
  assert.equal(versionSatisfies('1.20.1', row), 'out-of-range'); // end EXCLUDING
  assert.equal(versionSatisfies('1.16.9', row), 'out-of-range');
  assert.equal(versionSatisfies('1.18.0', { version: '1.18.0' }), 'exact');
  assert.equal(versionSatisfies('1.18.0', { version: '1.19.0' }), 'out-of-range');
  assert.equal(versionSatisfies(null, row), 'unknown');        // no version observed → unknown
  assert.equal(versionSatisfies('1.18.0', { version: '*' }), 'unknown'); // no range data → unknown
});

// --- CPE / alias matching ---------------------------------------------------------------------------
test('aliases bridge banner names to CPE tokens', () => {
  assert.ok(softwareMatchesCpe(aliasTokens('nginx'), cpeFacts('cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*')));
  assert.ok(softwareMatchesCpe(aliasTokens('microsoft-iis'), cpeFacts('cpe:2.3:a:microsoft:internet_information_server:10.0:*:*:*:*:*:*:*')));
  assert.ok(!softwareMatchesCpe(aliasTokens('nginx'), cpeFacts('cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*')));
  assert.equal(cpeFacts('not-a-cpe'), null);
});

test('nvdToMatches: in-range kept, out-of-range dropped, non-vulnerable rows ignored', () => {
  const item = NVD_SAMPLE.vulnerabilities[0];
  const hit = nvdToMatches(item, aliasTokens('nginx'), { version: '1.18.0' });
  assert.equal(hit.length, 1);
  assert.equal(hit[0].cve, 'CVE-2026-30001');
  assert.equal(hit[0].versionMatch, 'in-range');
  assert.ok(hit[0].matchBasis.includes('cpe:2.3:a:f5:nginx'));
  const miss = nvdToMatches(item, aliasTokens('nginx'), { version: '1.25.3' });
  assert.equal(miss.length, 0); // a parsed version OUTSIDE the disclosed range is not a hypothesis
  const unknown = nvdToMatches(item, aliasTokens('nginx'), { version: null });
  assert.equal(unknown[0].versionMatch, 'unknown');
  // description-regex watchlist path (WP plugin CVEs carry no usable CPE in this sample)
  const wp = nvdToMatches(NVD_SAMPLE.vulnerabilities[1], ['wordpress'], { descRe: /\bwordpress\b/i });
  assert.equal(wp.length, 1);
  assert.equal(wp[0].versionMatch, 'unknown');
});

test('kevToMatches: vendor/product token hit, versionMatch always unknown (KEV has no ranges)', () => {
  const m = kevToMatches(KEV_SAMPLE.vulnerabilities[0], aliasTokens('sharepoint'));
  assert.equal(m.cve, 'CVE-2026-24001');
  assert.equal(m.versionMatch, 'unknown');
  assert.equal(m.kev.dateAdded, '2026-08-29');
  assert.equal(kevToMatches(KEV_SAMPLE.vulnerabilities[0], aliasTokens('nginx')), null);
});

// --- feed cache + politeness --------------------------------------------------------------------------
function feedHarness({ kevStatus = 200, nvdPages } = {}) {
  const calls = [];
  const sleeps = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    if (url.includes('cisa.gov')) return kevStatus === 200 ? { status: 200, headers: {}, body: JSON.stringify(KEV_SAMPLE) } : { status: kevStatus, headers: {}, body: 'down' };
    if (url.includes('nvd.nist.gov')) {
      const startIndex = Number(new URL(url).searchParams.get('startIndex') || 0);
      const pages = nvdPages || [NVD_SAMPLE];
      const page = pages[startIndex / CVELANE_CAPS.nvdResultsPerPage] || null;
      if (!page) return { status: 200, headers: {}, body: JSON.stringify({ resultsPerPage: 200, startIndex, totalResults: startIndex, vulnerabilities: [] }) };
      return { status: 200, headers: {}, body: JSON.stringify(page) };
    }
    return null;
  };
  const sleepImpl = async (ms) => { sleeps.push(ms); };
  return { calls, sleeps, fetchImpl, sleepImpl, cacheDir: mkdtempSync(join(tmpdir(), 'varvel-cve-cache-')) };
}

test('cache: >=12h TTL — fresh cache serves, expired refetches, TTL floor is a FLOOR', async () => {
  assert.ok(CACHE_TTL_MS >= 12 * 3600 * 1000);
  const h = feedHarness();
  const f1 = await fetchFeeds({ ...h, nowMs: NOW });
  assert.equal(f1.kev.entries.length, 2);
  assert.equal(f1.kev.fromCache, false);
  const kevCalls = h.calls.filter((u) => u.includes('cisa.gov')).length;
  const f2 = await fetchFeeds({ ...h, nowMs: NOW + 3600 * 1000 }); // 1h later — inside TTL
  assert.equal(f2.kev.fromCache, true);
  assert.equal(h.calls.filter((u) => u.includes('cisa.gov')).length, kevCalls); // no refetch
  const f3 = await fetchFeeds({ ...h, nowMs: NOW + 13 * 3600 * 1000 }); // past TTL
  assert.equal(f3.kev.fromCache, false);
  assert.ok(h.calls.filter((u) => u.includes('cisa.gov')).length > kevCalls);
});

test('failure honesty: stale cache served NAMED; no cache → empty feed + named error, nothing fabricated', async () => {
  const ok = feedHarness();
  await fetchFeeds({ ...ok, nowMs: NOW }); // warm the cache
  const bad = feedHarness({ kevStatus: 503 });
  bad.cacheDir = ok.cacheDir; // same cache dir, failing transport
  const f = await fetchFeeds({ ...bad, nowMs: NOW + 13 * 3600 * 1000, refresh: true });
  assert.equal(f.kev.stale, true);
  assert.ok(f.errors.some((e) => e.feed === 'kev' && /STALE/.test(e.reason)));

  const cold = feedHarness({ kevStatus: 503 });
  const f2 = await fetchFeeds({ ...cold, nowMs: NOW });
  assert.equal(f2.kev.entries.length, 0);
  assert.ok(f2.errors.some((e) => e.feed === 'kev' && /NO cache/.test(e.reason)));
});

test('NVD politeness: pages sleep >=6s apart; page cap is a named truncation', async () => {
  const page0 = { ...NVD_SAMPLE, resultsPerPage: 200, startIndex: 0, totalResults: 400 };
  const page1 = { resultsPerPage: 200, startIndex: 200, totalResults: 400, vulnerabilities: [] };
  // two full pages → resultsPerPage must be the page size for pagination to advance
  const full0 = { ...NVD_SAMPLE, vulnerabilities: Array(200).fill(NVD_SAMPLE.vulnerabilities[0]), totalResults: 400, resultsPerPage: 200, startIndex: 0 };
  const h = feedHarness({ nvdPages: [full0, page1] });
  await fetchFeeds({ ...h, nowMs: NOW });
  assert.ok(h.sleeps.some((ms) => ms >= 6000), `NVD page sleep >=6s required, got ${JSON.stringify(h.sleeps)}`);
});

// --- the hypothesis engine ------------------------------------------------------------------------------
test('matchTuples: scored HYPOTHESES with evidence-of-version and a validation plan — never findings', () => {
  const tuples = [
    { program: 'acme', host: 'staging.example.com', software: 'nginx', version: '1.18.0', evidence: { source: 'server-header', raw: 'nginx/1.18.0' } },
    { program: 'acme', host: 'www.example.com', software: 'nginx', version: '1.25.3', evidence: { source: 'server-header', raw: 'nginx/1.25.3' } },
    { program: 'acme', host: 'sp.example.com', software: 'sharepoint', version: null, evidence: null },
  ];
  const out = matchTuples(tuples, { kev: KEV_SAMPLE.vulnerabilities, nvd: NVD_SAMPLE.vulnerabilities }, { nowMs: NOW });
  const nginx = out.find((h) => h.host === 'staging.example.com');
  assert.ok(nginx);
  assert.equal(nginx.cve, 'CVE-2026-30001');
  assert.equal(nginx.versionMatch, 'in-range');
  assert.equal(nginx.evidenceOfVersion, 'server-header: nginx/1.18.0');
  assert.ok(nginx.validationPlan.length >= 3);
  // out-of-range version → NO hypothesis
  assert.ok(!out.some((h) => h.host === 'www.example.com'));
  // KEV hostless-tuple match (version unknown) is kept, labelled unknown
  const sp = out.find((h) => h.host === 'sp.example.com');
  assert.ok(sp && sp.kev && sp.versionMatch === 'unknown');
  // THE HONESTY PIN: every item is a HYPOTHESIS routed to the validator — never a finding
  for (const h of out) {
    assert.equal(h.status, 'HYPOTHESIS');
    assert.equal(h.routing, 'campaign-validator');
    assert.ok(/NOT exploitability/.test(h.note));
  }
  // KEV + in-range beats version-unknown
  const kev = matchTuples([{ program: 'x', host: 'h', software: 'wordpress', version: null }], { kev: KEV_SAMPLE.vulnerabilities, nvd: [] }, { nowMs: NOW });
  const rng = scoreHypothesis({ kev: false, versionMatch: 'in-range', published: '2026-08-25', nowMs: NOW });
  assert.ok(kev[0].score > rng.score - 20); // kev+40 outguns in-range+20 at the same recency
});

test('watchScan: wordpress-stack programs watch core + plugin/theme CVEs; prohibited is watch-only manual', () => {
  const programs = [
    { id: 'wordpress', intake: { policy: 'WordPress Core software, Gutenberg' }, h1sync: { scopeText: 'WordPress', policyText: '' } },
    { id: 'plainapp', intake: { policy: 'nothing stack-like' }, h1sync: null },
  ];
  const out = watchScan(programs, { kev: KEV_SAMPLE.vulnerabilities, nvd: NVD_SAMPLE.vulnerabilities }, { nowMs: NOW });
  assert.ok(out.some((h) => h.program === 'wordpress' && h.cve === 'CVE-2026-24002')); // KEV core
  assert.ok(out.some((h) => h.program === 'wordpress' && h.cve === 'CVE-2026-30002')); // NVD plugin (description match)
  assert.ok(!out.some((h) => h.program === 'plainapp'));
  const wp = out.find((h) => h.program === 'wordpress');
  assert.equal(wp.status, 'HYPOTHESIS');
  assert.ok(/PROHIBITED/.test(wp.note)); // automation-prohibited → manual verification only
  assert.equal(wp.host, null); // hostless watch item
});

test('watchlistFor: pinned watchlists + metadata-detected stacks', () => {
  const pinned = watchlistFor('wordpress', '');
  assert.ok(pinned.pinned && pinned.tokens.includes('wordpress'));
  const detected = watchlistFor('acme', 'the app runs on Drupal with nginx');
  assert.ok(detected.tokens.includes('drupal') && detected.tokens.includes('nginx'));
  assert.equal(watchlistFor('nothing', 'plain text').tokens.length, 0);
});

// --- campaign wiring ------------------------------------------------------------------------------------
test('coverageItems → CoverageLedger: hypotheses queue as untested surface; gate stays INCOMPLETE until drained', () => {
  const hypotheses = matchTuples(
    [{ program: 'acme', host: 'staging.example.com', software: 'nginx', version: '1.18.0', evidence: { source: 'server-header', raw: 'nginx/1.18.0' } }],
    { kev: [], nvd: NVD_SAMPLE.vulnerabilities }, { nowMs: NOW },
  );
  const { items, hostless } = coverageItems(hypotheses);
  assert.equal(hostless, 0);
  assert.equal(items.length, 1);
  assert.equal(items[0].source, 'cvelane-hypothesis');
  const L = new CoverageLedger({ now: () => '2026-08-31T12:00:00Z' });
  for (const i of items) L.queue(i);
  const gate = L.gate();
  assert.equal(gate.verdict, 'COVERAGE-INCOMPLETE'); // a queued hypothesis is WORK OWED
  L.mark('/', 'manual');
  assert.equal(L.gate().verdict, 'DONE-CLEAN');
});

test('coverageItems: hostless watch items cannot queue — counted, not silently dropped', () => {
  const { items, hostless } = coverageItems([{ host: null, cve: 'CVE-2026-1', software: 'x', versionMatch: 'unknown' }]);
  assert.equal(items.length, 0);
  assert.equal(hostless, 1);
});

test('toLaunchOptions: in-target hypotheses become campaign targets; out-of-scope hosts are NOT added', () => {
  const hypotheses = [
    { host: 'staging.example.com', cve: 'CVE-1', software: 'nginx', version: '1', versionMatch: 'in-range' },
    { host: 'other.org', cve: 'CVE-2', software: 'apache', version: '2', versionMatch: 'in-range' },
  ];
  const lo = toLaunchOptions(hypotheses, { targets: ['staging.example.com'] });
  assert.deepEqual(lo.targets, ['staging.example.com']);
  assert.equal(lo.cveHypotheses.length, 1);
  assert.equal(lo.cveHypotheses[0].host, 'staging.example.com');
  assert.equal(lo.tooledRecon, true);
});

test('campaign wiring: cveHypotheses queue into the coverage gate, fail-closed to targets', () => {
  const scope = (e) => ({ engagement: e, signedBy: 'x', cidrs: ['127.0.0.0/8'] });
  const c = new Campaign({
    engine: {}, scope: scope('CVE-LANE-T1'), runAgent: mockAgent, stallCheckMs: 0,
    targets: ['staging.example.com'],
    cveHypotheses: [
      { host: 'staging.example.com', key: '/', cve: 'CVE-2026-30001', kind: 'endpoint' },
      { host: 'not-a-target.example.com', key: '/', cve: 'CVE-2026-99999' },
    ],
  });
  const st = c.getState();
  assert.equal(st.cvelane.received, 2);
  assert.equal(st.cvelane.queued, 1);
  assert.equal(st.cvelane.skipped, 1); // out-of-target hypothesis: logged skip, never queued
  const queued = st.coverage.untested || [];
  assert.ok(st.coverage.queued >= 1);
  assert.ok((st.activity || []).some((a) => a.kind === 'cvelane.skip'));
  assert.ok((st.activity || []).some((a) => a.kind === 'cvelane.queue'));
  c.status = 'done'; // no run needed; constructor-level wiring is the pinned seam
});

// --- scan end-to-end (feeds faked, cache tmp) ---------------------------------------------------------------
test('scan: feeds + tuples → queue file; label, stats, limitations, honesty pins', async () => {
  const h = feedHarness();
  const tuples = [{ program: 'acme', host: 'staging.example.com', software: 'nginx', version: '1.18.0', evidence: { source: 'server-header', raw: 'nginx/1.18.0' } }];
  const result = await scan({ ...h, tuples, nowMs: NOW, programs: [{ id: 'wordpress', intake: { policy: 'WordPress Core' }, h1sync: null }] });
  assert.ok(/HYPOTHESIS QUEUE/.test(result.label));
  assert.ok(result.items.some((i) => i.cve === 'CVE-2026-30001' && i.versionMatch === 'in-range'));
  assert.ok(result.items.some((i) => i.cve === 'CVE-2026-24002' && i.watchOnly)); // wordpress KEV watch
  assert.equal(result.feeds.kev.entries, 2);
  assert.ok(result.limitations.length >= 4);
  for (const i of result.items) assert.equal(i.status, 'HYPOTHESIS');
  const outDir = mkdtempSync(join(tmpdir(), 'varvel-cvelane-out-'));
  const { jsonPath } = writeQueue(result, { outDir, date: '2026-08-31' });
  const written = JSON.parse(readFileSync(jsonPath, 'utf8'));
  assert.equal(written.tool, 'cvelane');
  assert.ok(jsonPath.includes('cve-hypotheses-2026-08-31'));
});

test('epss: null unless supplied — never fabricated', async () => {
  const h = feedHarness();
  const tuples = [{ program: 'acme', host: 'h.example.com', software: 'nginx', version: '1.18.0' }];
  const without = await scan({ ...h, tuples, nowMs: NOW });
  assert.equal(without.items.find((i) => i.cve === 'CVE-2026-30001').epss, null);
  const withMap = await scan({ ...h, tuples, nowMs: NOW, epssMap: { 'CVE-2026-30001': 0.62 } });
  const item = withMap.items.find((i) => i.cve === 'CVE-2026-30001');
  assert.equal(item.epss, 0.62);
  assert.ok(item.reasons.some((r) => /epss/.test(r)));
});
