// VARVEL widerecon tests — the ROSTER-WIDE PASSIVE RECON SWEEP (tools/widerecon.mjs,
// wide-recon + CVE build Tool 1). Hermetic: every transport is INJECTED (fetchImpl /
// resolveImpl / tlsImpl / sleepImpl fakes), the roster+intakes are tmp-dir fixtures.
// Zero live network, zero real sleeps.
//   node --test test/widerecon.test.mjs
//
// Pinned: policy exclusions (prohibited programs get ZERO requests and land as
// SKIPPED-POLICY); human-cadence pacing (concurrency 1, >=5s target-contact);
// scope fail-closed (out-of-scope crt.sh/wayback names dropped, never dialed);
// crt.sh / wayback / version-extraction parsers against recorded samples;
// targetscore-style ranking (staging+fresh+version-disclosed outranks plain www);
// the honesty contract (unknowns stay UNKNOWN; every catch tested:false;
// the report's untested ledger verdict is NOTHING-TESTED).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  probePolicy, rootDomains, inScopeHost, parseCrtSh, parseWaybackCdx, waybackDate,
  extractTech, rankHost, sweep, renderMd, writeExports,
  PROHIBITED_PROGRAMS, WIDERECON_CAPS, FINGERPRINT_FILES,
} from '../tools/widerecon.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
const NOW = Date.parse('2026-08-31T12:00:00Z');

// --- recorded samples -------------------------------------------------------------------------
const CRT_SAMPLE = JSON.stringify([
  { issuer_name: "C=US, O=Let's Encrypt", name_value: 'www.example.com', not_before: '2025-01-04T00:00:00' },
  { issuer_name: "C=US, O=Let's Encrypt", name_value: 'staging.example.com\n*.api.example.com', not_before: '2026-07-20T00:00:00' },
  { issuer_name: "C=US, O=DigiCert", name_value: 'evil-outside.com', not_before: '2026-01-01T00:00:00' },
]);
const WAYBACK_SAMPLE = JSON.stringify([
  ['timestamp', 'original'],
  ['20200101120000', 'http://www.example.com/'],
  ['20190505083000', 'http://staging.example.com/orders/view.php?id=41'],
]);

const STAGING_PAGE = {
  status: 200,
  headers: { server: 'nginx/1.18.0', 'x-powered-by': 'PHP/7.4.3' },
  body: '<html><head><meta name="generator" content="WordPress 6.5.2"></head><body>'
    + '<script src="/a.js"></script><script src="/b.js"></script><script src="/c.js"></script><script src="/d.js"></script><script src="/e.js"></script><script src="/f.js"></script>'
    + '</body></html>',
};
const WWW_PAGE = { status: 200, headers: { server: 'cloudflare' }, body: '<html><body>marketing</body></html>' };
const CHANGELOG = { status: 200, headers: {}, body: '# Changelog\n\n## v2.3.1\n- fixes\n' };
const README_404 = { status: 404, headers: {}, body: 'nope' };

function makeHarness() {
  const calls = [];   // every fetchImpl url — the zero-requests pin reads this
  const sleeps = [];  // every sleepImpl ms — the cadence pin reads this
  const tlsCalls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    if (url.includes('crt.sh')) return { status: 200, headers: {}, body: CRT_SAMPLE };
    if (url.includes('web.archive.org')) return { status: 200, headers: {}, body: WAYBACK_SAMPLE };
    if (url.endsWith('/CHANGELOG.md')) return CHANGELOG;
    if (url.endsWith('/readme.html')) return README_404;
    if (url === 'https://staging.example.com/') return STAGING_PAGE;
    if (url === 'https://www.example.com/') return WWW_PAGE;
    if (url === 'https://api.example.com/') return null; // refused/timeout
    return null;
  };
  const resolveImpl = async (host) => {
    if (host === 'api.example.com') return null;            // UNKNOWN, never guessed
    if (host === 'staging.example.com') return { addresses: ['10.9.9.9'] };
    if (host === 'www.example.com') return { addresses: ['10.1.1.1'] };
    return { addresses: [] };                                // NO-A-RECORD
  };
  const tlsImpl = async (host) => {
    tlsCalls.push(host);
    if (host === 'staging.example.com') return { subject: 'staging.internal.example.com', issuer: 'InternalCA', san: 'DNS:staging.example.com', validFrom: '2026-07-01', validTo: '2027-07-01' };
    return null;
  };
  const sleepImpl = async (ms) => { sleeps.push(ms); };
  return { calls, sleeps, tlsCalls, fetchImpl, resolveImpl, tlsImpl, sleepImpl };
}

// tmp roster: acme (human-cadence, in-scope *.example.com), udemy + wordpress (prohibited)
function makeDataDir() {
  const dir = mkdtempSync(join(tmpdir(), 'varvel-widerecon-'));
  writeFileSync(join(dir, 'roster.json'), JSON.stringify({
    programs: [
      { id: 'acme', handle: 'acme', platform: 'hackerone', state: 'hunted', automation: 'human-cadence' },
      { id: 'udemy', handle: 'udemy', platform: 'hackerone', state: 'imported', automation: 'prohibited' },
      { id: 'wordpress', handle: 'wordpress', platform: 'hackerone', state: 'imported', automation: 'prohibited' },
    ],
  }));
  writeFileSync(join(dir, 'acme-program.json'), JSON.stringify({
    ok: true, platform: 'hackerone', program: { name: 'Acme', handle: 'acme' },
    policy: 'nothing special',
    inScope: { cidrs: [], domains: [{ asset: '*.example.com', note: 'core' }], wildcards: ['*.example.com'], other: ['com.acme.app (Android)'] },
    outOfScope: { cidrs: [], domains: [], wildcards: [], other: [] },
  }));
  return dir;
}

// --- policy -----------------------------------------------------------------------------------
test('policy: hard pin list beats everything; prohibited gets ZERO requests', () => {
  for (const id of ['udemy', 'wordpress', 'matomo']) {
    const p = probePolicy({ id, automation: 'full' }); // even a roster claiming 'full' loses to the pin
    assert.equal(p.policy, 'prohibited');
    assert.equal(p.concurrency, 0);
    assert.equal(p.fingerprint, false);
  }
  assert.ok(PROHIBITED_PROGRAMS.includes('udemy') && PROHIBITED_PROGRAMS.includes('wordpress') && PROHIBITED_PROGRAMS.includes('matomo'));
});

test('policy: human-cadence = concurrency 1, >=5s target delay, >=1s intel delay', () => {
  const p = probePolicy({ id: 'acme', automation: 'human-cadence' });
  assert.equal(p.concurrency, 1);
  assert.ok(p.targetDelayMs >= 5000, `target delay must be >=5s, got ${p.targetDelayMs}`);
  assert.ok(p.intelDelayMs >= 1000);
  assert.equal(p.fingerprint, true);
  const rosterProhibited = probePolicy({ id: 'notpinned', automation: 'prohibited' });
  assert.equal(rosterProhibited.policy, 'prohibited');
});

// --- intake / scope ----------------------------------------------------------------------------
test('rootDomains unwraps wildcards and drops non-domain assets', () => {
  const roots = rootDomains({ inScope: { domains: [{ asset: '*.example.com' }, { asset: 'api.acme.io' }], wildcards: ['*.example.com', '10.0.0.0/8'], other: ['com.acme (Android)'] } });
  assert.ok(roots.includes('example.com'));
  assert.ok(roots.includes('api.acme.io')); // a concrete asset root confines recon to itself — never widened to the apex
  assert.equal(roots.filter((r) => r === 'example.com').length, 1); // deduped
  assert.ok(!roots.some((r) => r.includes('*') || r.includes('/')));
  assert.ok(inScopeHost('staging.example.com', ['example.com']));
  assert.ok(inScopeHost('example.com', ['example.com']));
  assert.ok(!inScopeHost('evil-example.com', ['example.com']));
  assert.ok(!inScopeHost('example.com.evil.com', ['example.com']));
});

// --- parsers (recorded samples) -----------------------------------------------------------------
test('parseCrtSh: multi-line name_value, wildcard unwrap, earliest not_before, garbage → null', () => {
  const names = parseCrtSh(CRT_SAMPLE);
  const byName = new Map(names.map((n) => [n.name, n]));
  assert.ok(byName.has('www.example.com') && byName.has('staging.example.com') && byName.has('api.example.com'));
  assert.equal(byName.get('staging.example.com').firstSeen, '2026-07-20T00:00:00');
  assert.equal(parseCrtSh('<html>error</html>'), null);
  assert.equal(parseCrtSh('{"not":"an array"}'), null);
});

test('parseWaybackCdx: header row skipped, params detected, waybackDate', () => {
  const rows = parseWaybackCdx(WAYBACK_SAMPLE);
  assert.equal(rows.length, 2);
  const legacy = rows.find((r) => r.host === 'staging.example.com');
  assert.equal(legacy.hasParams, true);
  assert.equal(waybackDate(legacy.timestamp), '2019-05-05');
  assert.equal(parseWaybackCdx('blocked!'), null);
});

test('extractTech: server/x-powered-by/generator/readme/CHANGELOG — every tuple cites its evidence', () => {
  const t = extractTech({ headers: STAGING_PAGE.headers, body: STAGING_PAGE.body, path: '/' });
  const sw = Object.fromEntries(t.map((x) => [x.software, x]));
  assert.equal(sw.nginx.version, '1.18.0');
  assert.equal(sw.nginx.evidence.source, 'server-header');
  assert.equal(sw.php.version, '7.4.3');
  assert.equal(sw.wordpress.version, '6.5.2');
  assert.equal(sw.wordpress.evidence.source, 'generator-meta');
  const rm = extractTech({ headers: {}, body: '<h1>WordPress</h1><br/>Version 6.4.1', path: '/readme.html' });
  assert.ok(rm.some((x) => x.software === 'wordpress' && x.version === '6.4.1'));
  const cl = extractTech({ headers: {}, body: CHANGELOG.body, path: '/CHANGELOG.md' });
  assert.ok(cl.some((x) => x.software === 'changelog-version' && x.version === '2.3.1'));
  // a banner without a version is version:null (UNKNOWN), never invented
  const bare = extractTech({ headers: { server: 'nginx' }, body: '', path: '/' });
  assert.equal(bare[0].version, null);
});

// --- ranking -------------------------------------------------------------------------------------
test('rankHost: staging + fresh + version-disclosed outranks a plain edge-walled www', () => {
  const staging = rankHost({
    host: 'staging.example.com', firstSeen: '2026-07-20', nowMs: NOW,
    tech: extractTech({ headers: STAGING_PAGE.headers, body: STAGING_PAGE.body, path: '/' }),
    urls: [{ path: '/orders/view.php?id=41', hasParams: true }],
    scriptCount: 6, cert: { subject: 'staging.internal.example.com' },
  });
  const www = rankHost({ host: 'www.example.com', tech: [{ software: 'edge:cloudflare', version: null }], urls: [], nowMs: NOW });
  assert.ok(staging.score > www.score, `${staging.score} should beat ${www.score}`);
  for (const k of ['soft-env', 'fresh-subdomain', 'version-disclosed', 'tls-origin-hint', 'jsminer-fodder', 'idor-candidate']) {
    assert.ok(staging.kinds.includes(k), `staging should carry kind ${k}`);
  }
  assert.ok(staging.versionTuples.length >= 3); // nginx/1.18.0, PHP/7.4.3, wordpress/6.5.2
  assert.ok(www.kinds.includes('edge-walled'));
  // every reason cites evidence (the targetscore honesty contract holds here too)
  for (const r of staging.reasons) assert.ok(/—/.test(r), `reason must name its evidence: ${r}`);
});

// --- the end-to-end sweep (all transports faked) ---------------------------------------------------
test('sweep: prohibited programs SKIPPED-POLICY with ZERO requests; human-cadence paced; scope fail-closed; unknowns UNKNOWN', async () => {
  const h = makeHarness();
  const dataDir = makeDataDir();
  const report = await sweep({ ...h, dataDir, nowMs: NOW, now: '2026-08-31T12:00:00Z' });

  // prohibited: listed, never probed
  const skipped = report.skippedPolicy.map((s) => s.program).sort();
  assert.deepEqual(skipped, ['udemy', 'wordpress']);
  assert.ok(!h.calls.some((u) => /udemy|wordpress/i.test(u)), 'prohibited programs must see ZERO requests');

  // acme swept at human cadence: intel sleeps >=1s, target-contact sleeps >=5s
  assert.ok(h.sleeps.length > 0);
  assert.ok(Math.min(...h.sleeps) >= 1000, `min sleep ${Math.min(...h.sleeps)} < 1s`);
  assert.ok(h.sleeps.includes(5000), 'human-cadence target-contact delay of 5s must appear');

  // scope fail-closed: evil-outside.com from the crt.sh sample was dropped, never dialed
  const acme = report.programs.find((p) => p.program === 'acme');
  assert.ok(acme.droppedOutOfScope >= 1);
  assert.ok(!h.calls.some((u) => u.includes('evil-outside.com')));
  assert.ok(!h.tlsCalls.some((x) => x.includes('evil-outside.com')));

  // unknowns stay UNKNOWN: api.example.com's resolver returned null
  const api = acme.hosts.find((x) => x.host === 'api.example.com');
  assert.equal(api.resolution, 'UNKNOWN');
  assert.equal(api.fingerprinted, false); // UNKNOWN-resolution hosts are never fingerprinted

  // the catch-list ranks staging first and carries evidence + version tuples
  assert.equal(acme.catches[0].host, 'staging.example.com');
  const st = acme.catches[0];
  assert.ok(st.kinds.includes('fresh-subdomain'));
  assert.ok(st.software.some((s) => s.software === 'nginx' && s.version === '1.18.0' && s.evidence.source === 'server-header'));
  assert.ok(st.legacyParamUrls.some((u) => u.includes('id=41')));
  assert.equal(st.tested, false); // widerecon TESTS NOTHING

  // the softwareTuple feedstock for cvelane exists and carries evidence-of-version
  assert.ok(report.softwareTuples.some((t) => t.program === 'acme' && t.host === 'staging.example.com' && t.software === 'wordpress' && t.version === '6.5.2'));

  // honesty ledger: NOTHING-TESTED, limitations stated
  assert.equal(report.untestedLedger.verdict, 'NOTHING-TESTED');
  assert.ok(report.limitations.length >= 3);

  // md renders the SKIPPED-POLICY section and the ranking table
  const md = renderMd(report);
  assert.ok(md.includes('SKIPPED-POLICY'));
  assert.ok(md.includes('staging.example.com'));

  // exports write ONLY new files under the given exports dir
  const outDir = mkdtempSync(join(tmpdir(), 'varvel-widerecon-out-'));
  const paths = writeExports(report, { outDir, date: '2026-08-31' });
  const written = JSON.parse(readFileSync(paths.jsonPath, 'utf8'));
  assert.equal(written.tool, 'widerecon');
});

test('sweep: a program with no domain roots is NO-DOMAIN-ROOTS (named, not silent)', async () => {
  const h = makeHarness();
  const dir = mkdtempSync(join(tmpdir(), 'varvel-widerecon-noroots-'));
  writeFileSync(join(dir, 'roster.json'), JSON.stringify({ programs: [{ id: 'apponly', handle: 'apponly', automation: 'human-cadence' }] }));
  writeFileSync(join(dir, 'apponly-program.json'), JSON.stringify({ inScope: { domains: [], wildcards: [], other: ['com.app (Android)'] } }));
  const report = await sweep({ ...h, dataDir: dir, nowMs: NOW });
  const p = report.programs.find((x) => x.program === 'apponly');
  assert.equal(p.status, 'NO-DOMAIN-ROOTS');
  assert.equal(h.calls.length, 0); // nothing to enumerate → zero requests
});

test('sweep: feed failures are NAMED errors, never fabricated names', async () => {
  const dir = makeDataDir();
  const report = await sweep({
    dataDir: dir, nowMs: NOW, sleepImpl: async () => {},
    fetchImpl: async () => ({ status: 503, headers: {}, body: 'upstream down' }),
    resolveImpl: async () => null, tlsImpl: async () => null,
  });
  const acme = report.programs.find((p) => p.program === 'acme');
  assert.ok(acme.errors.some((e) => e.stage === 'crt.sh' && /503/.test(e.reason)));
  assert.ok(acme.errors.some((e) => e.stage === 'wayback'));
  // the only hosts are the roots themselves (nothing fabricated from failed feeds)
  assert.deepEqual(acme.hosts.map((x) => x.host), ['example.com']);
  assert.ok(acme.hosts.every((x) => x.resolution === 'UNKNOWN'));
});

test('caps: the active fingerprint read-set stays tiny (no crawl, ever)', () => {
  assert.ok(WIDERECON_CAPS.maxFingerprintHosts <= 8);
  assert.ok(FINGERPRINT_FILES.length <= 2);
  assert.deepEqual(FINGERPRINT_FILES, ['/readme.html', '/CHANGELOG.md']);
});
