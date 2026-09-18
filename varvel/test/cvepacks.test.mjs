// VARVEL cvepacks tests — version math + honesty contract. Hermetic, no I/O.
//   node --test varvel/test/cvepacks.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { parseVersion, compareVersions, inRange, inRanges, cveCheck, CVE_PACKS, CURATED_CVE_PACKS } from '../engine/cvepacks.mjs';
import { GENERATED_CVE_PACKS } from '../engine/cvepacks.generated.mjs';
import { vulnCheck } from '../tools/vulncheck.mjs';

test('cveCheck: the phpMyAdmin coverage expansion activates honestly (2026-09-16 audit)', () => {
  // Added to CPE_TO_WAPPALYZE + TECH_SIGNATURES in the 2026-09-16 coverage audit: 3732 CPE
  // nodes, the largest mapped web-app family after php/tomcat, previously ZERO coverage.
  const out = cveCheck([{ id: 'phpmyadmin', label: 'phpMyAdmin', version: '5.1.0' }]);
  const hit = out.find((c) => c.cve === 'CVE-2020-22452'); // SQLi in CreateAddField.php, 5.0.0 ≤ v < 5.2.0
  assert.ok(hit, 'a real affected version fires');
  assert.equal(hit.sev, 'critical');
  assert.equal(hit.confidence, 'firm', 'version match is firm, never confirmed');
  // and the honest refusal still holds on both sides of the range
  assert.equal(cveCheck([{ id: 'phpmyadmin', label: 'phpMyAdmin', version: '5.2.0' }]).filter((c) => c.cve === 'CVE-2020-22452').length, 0, 'patched version does not fire');
  assert.equal(cveCheck([{ id: 'phpmyadmin', label: 'phpMyAdmin' }]).length, 0, 'no version → no claim, ever');
});

test('correlation breadth: the generated pack covers every mapped product family', () => {
  // "National level" coverage bar, pinned honestly: the committed artifact must keep speaking
  // for every product wappalyze can fingerprint AND actually carry a meaningful table. Counts
  // are floors, not snapshots — a monthly NVD refresh adds entries and must not fail here.
  const mapped = ['apache', 'nginx', 'iis', 'php', 'tomcat', 'jquery', 'wordpress', 'drupal',
    'joomla', 'laravel', 'django', 'rails', 'express', 'nextjs', 'spring', 'angular', 'phpmyadmin'];
  for (const id of mapped) {
    const pack = GENERATED_CVE_PACKS[id];
    assert.ok(Array.isArray(pack) && pack.length >= 1, `${id} carries a generated pack`);
  }
  assert.ok((GENERATED_CVE_PACKS.php || []).length >= 100, 'the thinnest-capped family (php) is no longer cap-limited');
  assert.ok((GENERATED_CVE_PACKS.wordpress || []).length >= 50, 'WP core coverage floor');
  assert.ok((GENERATED_CVE_PACKS.tomcat || []).length >= 80, 'Tomcat coverage floor');
  assert.ok((GENERATED_CVE_PACKS.phpmyadmin || []).length >= 20, 'phpMyAdmin coverage floor');
});

test('correlation honesty: KEV-flagged entries survive the cap and stay flagged', () => {
  let kevTotal = 0;
  for (const [tech, packs] of Object.entries(GENERATED_CVE_PACKS)) {
    for (const p of packs) {
      if (!p.kev) continue;
      kevTotal++;
      assert.ok(Array.isArray(p.ranges) && p.ranges.length >= 1, `${tech} ${p.cve} KEV entry still carries its range`);
    }
  }
  assert.ok(kevTotal >= 30, `actively-exploited coverage is real: ${kevTotal} KEV-flagged entries`);
});

test('parseVersion: dotted prefix only, suffix stripped, garbage → null', () => {
  assert.deepEqual(parseVersion('1.18.0'), [1, 18, 0]);
  assert.deepEqual(parseVersion('8.2.7-1ubuntu1'), [8, 2, 7]);
  assert.deepEqual(parseVersion('2'), [2]);
  assert.equal(parseVersion('nginx'), null);
  assert.equal(parseVersion(''), null);
});

test('compareVersions: numeric, missing components = 0', () => {
  assert.equal(compareVersions('1.18.0', '1.25.4'), -1);
  assert.equal(compareVersions('2.4.49', '2.4.49'), 0);
  assert.equal(compareVersions('8.2', '8.2.1'), -1);
  assert.equal(compareVersions('10.0', '9.9'), 1);
  assert.equal(compareVersions('x', '1.0'), null);
});

test('inRange/inRanges: boundary semantics are exact', () => {
  assert.ok(inRange('2.4.49', { eq: '2.4.49' }));
  assert.ok(!inRange('2.4.50', { eq: '2.4.49' }));
  assert.ok(inRange('1.18.0', { gte: '0.6.18', lte: '1.20.0' }));
  assert.ok(inRange('1.20.0', { gte: '0.6.18', lte: '1.20.0' }), 'lte inclusive');
  assert.ok(!inRange('1.20.1', { gte: '0.6.18', lte: '1.20.0' }));
  assert.ok(inRange('8.2.10', { gte: '8.2.0', lt: '8.2.20' }));
  assert.ok(!inRange('8.2.20', { gte: '8.2.0', lt: '8.2.20' }), 'lt exclusive');
  assert.ok(inRanges('8.1.5', [{ lt: '8.1.29' }, { gte: '8.2.0', lt: '8.2.20' }]), 'OR over branches');
});

test('cveCheck: fires on a real affected version with firm confidence + KEV flag', () => {
  const out = cveCheck([{ id: 'apache', label: 'Apache httpd', version: '2.4.49' }]);
  const hit = out.find((c) => c.cve === 'CVE-2021-41773');
  assert.ok(hit, '41773 fired');
  assert.equal(hit.sev, 'critical');
  assert.equal(hit.kev, true);
  assert.equal(hit.confidence, 'firm', 'version match ≠ proved exploit — honest by contract');
  assert.ok(/2\.4\.49/.test(hit.evidence), 'evidence names the fingerprinted version');
  assert.ok(/verify|backport/i.test(hit.verify), 'verification guidance carried');
});

test('cveCheck: patched version does NOT fire; unknown version NEVER fires', () => {
  assert.equal(cveCheck([{ id: 'apache', label: 'Apache httpd', version: '2.4.49.1' }]).filter((c) => c.cve === 'CVE-2021-41773').length, 0);
  // The CURATED apache entries are all patched at 2.4.56. The merged GENERATED pack
  // honestly DOES fire here — NVD lists 2.4.56 in later affected ranges (e.g.
  // CVE-2024-27316, the 2.4.60 fixes) — that is the expansion working as designed,
  // not a curated regression, so the zero-claim is scoped to the curated entries.
  const curatedApache = new Set(CURATED_CVE_PACKS.apache.map((p) => p.cve));
  assert.equal(cveCheck([{ id: 'apache', label: 'Apache httpd', version: '2.4.56' }]).filter((c) => curatedApache.has(c.cve)).length, 0, 'all CURATED apache packs patched at .56');
  assert.equal(cveCheck([{ id: 'apache', label: 'Apache httpd', version: null }]).length, 0, 'no version → no claim, ever');
  assert.equal(cveCheck([{ id: 'unknown-tech', label: 'X', version: '1.0' }]).length, 0);
});

test('cveCheck: branch ranges (PHP 8.1/8.2/8.3) match the right branches only', () => {
  const fire = (v) => cveCheck([{ id: 'php', label: 'PHP', version: v }]).some((c) => c.cve === 'CVE-2024-4577');
  assert.ok(fire('8.1.28'));
  assert.ok(fire('8.2.19'));
  assert.ok(fire('8.3.7'));
  assert.ok(!fire('8.1.29'));
  assert.ok(!fire('8.2.20'));
  assert.ok(!fire('8.3.8'));
});

test('pack hygiene: every entry has cve/sev/ranges/note; refs unique per tech', () => {
  for (const [tech, packs] of Object.entries(CVE_PACKS)) {
    const seen = new Set();
    for (const p of packs) {
      assert.ok(/^CVE-\d{4}-\d{4,}$/.test(p.cve), tech + ' cve id');
      assert.ok(['info', 'low', 'medium', 'high', 'critical'].includes(p.sev), tech + ' sev');
      assert.ok(Array.isArray(p.ranges) && p.ranges.length, tech + ' ranges');
      assert.ok(p.note && p.title, tech + ' prose');
      assert.ok(!seen.has(p.cve), tech + ' no dup');
      seen.add(p.cve);
    }
  }
});

test('vulnCheck integration: fingerprinted tech fires CVE findings alongside probes', async () => {
  const srv = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html', server: 'Apache/2.4.49 (Unix)' });
    res.end('<html>ok</html>');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const res = await vulnCheck(base, { timeout: 700, tech: [{ id: 'apache', label: 'Apache httpd', version: '2.4.49', confidence: 'confirmed' }] });
    const cve = res.vulnerabilities.find((v) => v.id === 'cve-cve-2021-41773');
    assert.ok(cve, 'CVE finding in the vulncheck result');
    assert.equal(cve.confidence, 'firm');
    assert.ok(/KEV/.test(cve.evidence));
    assert.ok(/^VC-\d+$/.test(cve.ref), 'VC ref assigned');
    assert.equal(res.vulnerabilities[0].sev, 'critical', 'critical sorts first');
  } finally { srv.close(); }
});
