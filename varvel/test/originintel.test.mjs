// VARVEL -- originintel hermetic tests. NO live network: a fixture crt.sh JSON body
// and a scripted resolver stand in for the world. The assertions are the doctrine:
// non-Cloudflare resolvers become candidates with evidence, dead names are honestly
// 'nxdomain', mail infrastructure leaks are named, a throwing resolver degrades one
// host to 'error' without sinking the run, and the scope gate ships in every report.

import test from 'node:test';
import assert from 'node:assert/strict';
import { originIntel, SCOPE_GATE } from '../tools/originintel.mjs';

// Fixture CT answer: two live names (one CF-fronted, one origin), a wildcard entry
// (must split to the apex), a dead name, a name whose lookup explodes, and a
// duplicate across certs (must dedupe).
const CRT_ROWS = [
  { name_value: 'www.example.com\norigin.example.com' },
  { name_value: '*.example.com' },
  { name_value: 'dead.example.com' },
  { name_value: 'flaky.example.com' },
  { name_value: 'www.example.com' },
];

const nxdomain = () => { const e = new Error('queryA ENOTFOUND'); e.code = 'ENOTFOUND'; return e; };
const nodata = () => { const e = new Error('queryAaaa ENODATA'); e.code = 'ENODATA'; return e; };

// Scripted resolver: the whole "internet" these tests see.
//   example.com / www   -> 104.16.5.5 (Cloudflare /13, fronted)
//   origin.example.com  -> 203.0.113.10 (TEST-NET-3, outside CF = origin)
//   mail.example.com    -> 203.0.113.25 (MX + SPF-include host, outside CF)
//   flaky.example.com   -> resolve4 throws a code-less Error (resolver bug)
//   everything else     -> NXDOMAIN on A, ENODATA on AAAA
function scriptedResolver() {
  const A = {
    'example.com': ['104.16.5.5'],
    'www.example.com': ['104.16.5.5'],
    'origin.example.com': ['203.0.113.10'],
    'mail.example.com': ['203.0.113.25'],
  };
  return {
    async resolve4(h) {
      if (h === 'flaky.example.com') throw new Error('scripted resolver explosion');
      if (A[h]) return A[h];
      throw nxdomain();
    },
    async resolve6() { throw nodata(); },
    async resolveMx(h) {
      if (h === 'example.com') return [{ exchange: 'mail.example.com', priority: 10 }];
      throw nxdomain();
    },
    async resolveTxt(h) {
      if (h === 'example.com') return [['v=spf1 include:mail.example.com ip4:203.0.113.30 ~all']];
      throw nxdomain();
    },
  };
}

let seenUrl = null;
const fetcher = async (url) => { seenUrl = url; return JSON.stringify(CRT_ROWS); };

const run = () => originIntel('example.com', { fetcher, resolver: scriptedResolver() });
const byHost = (out, h) => out.hosts.find((x) => x.host === h);
const candidateHosts = (out) => out.candidates.map((c) => c.host);

test('a CT name resolving outside Cloudflare becomes a candidate with sources and signals', async () => {
  const out = await run();
  assert.equal(out.ok, true);
  assert.equal(seenUrl, 'https://crt.sh/?q=%25.example.com&output=json');
  const c = out.candidates.find((x) => x.host === 'origin.example.com');
  assert.ok(c, 'origin.example.com must be a candidate');
  assert.equal(c.state, 'live-non-cf');
  assert.deepEqual(c.ips, ['203.0.113.10']);
  assert.deepEqual(c.sources, ['ct-log']);
  assert.ok(c.signals.some((s) => /outside Cloudflare published ranges/.test(s)), 'verdict signal present');
  assert.ok(c.signals.some((s) => /CT logs/.test(s)), 'source evidence signal present');
  // wildcard split: the apex entered the CT set as 'example.com', never as '*.'
  assert.ok(out.ctNames.includes('example.com'));
  assert.ok(!out.ctNames.some((n) => n.includes('*')));
  // fronted names classify live-cloudflare and are never candidates
  const www = byHost(out, 'www.example.com');
  assert.equal(www.state, 'live-cloudflare');
  assert.ok(!candidateHosts(out).includes('www.example.com'));
  assert.ok(!candidateHosts(out).includes('example.com'));
});

test('NXDOMAIN names are honestly nxdomain, never candidates', async () => {
  const out = await run();
  const dead = byHost(out, 'dead.example.com');
  assert.equal(dead.state, 'nxdomain');
  assert.deepEqual(dead.ips, []);
  assert.ok(dead.signals.some((s) => /NXDOMAIN/.test(s)));
  assert.ok(!candidateHosts(out).includes('dead.example.com'));
});

test('MX/SPF naming non-Cloudflare hosts produces mail-infrastructure candidates', async () => {  const out = await run();
  const mail = out.candidates.find((x) => x.host === 'mail.example.com');
  assert.ok(mail, 'MX host outside CF must be a candidate');
  assert.deepEqual(mail.sources, ['mx', 'spf']);
  assert.deepEqual(mail.ips, ['203.0.113.25']);
  assert.ok(mail.signals.some((s) => /mail-infrastructure/.test(s) && /CloudPiercer/.test(s)), 'in-zone mail leak signal');
  // bare SPF ip4 mechanism: the asserted IP itself is a candidate, labeled as DNS-asserted
  const spfIp = out.candidates.find((x) => x.host === '203.0.113.30');
  assert.ok(spfIp, 'SPF ip4 mechanism outside CF must be a candidate');
  assert.deepEqual(spfIp.sources, ['spf']);
  assert.ok(spfIp.signals.some((s) => /mail-infrastructure/.test(s) && /not resolved by this tool/.test(s)));
});

test('SPF bare ip6 mechanisms are harvested like bare ip4 (CF-ranged and CIDR forms are not)', async () => {
  const resolver = {
    async resolve4(h) { if (A6[h]) return A6[h]; throw nxdomain(); },
    async resolve6() { throw nodata(); },
    async resolveMx() { throw nxdomain(); },
    async resolveTxt(h) {
      if (h === 'example.com') return [['v=spf1 ip6:2001:DB8::25 ip6:2606:4700::1 ip6:2001:db8::/48 ip4:203.0.113.30 ~all']];
      throw nxdomain();
    },
  };
  const A6 = { 'example.com': ['104.16.5.5'], 'www.example.com': ['104.16.5.5'], 'origin.example.com': ['203.0.113.10'] };
  const out = await originIntel('example.com', { fetcher, resolver });
  assert.equal(out.ok, true);
  // the bare ip6 host, canonicalized from the mixed-case zone form, is a candidate
  const v6 = out.candidates.find((x) => x.host === '2001:db8::25');
  assert.ok(v6, 'bare ip6 mechanism outside CF must be a candidate');
  assert.deepEqual(v6.sources, ['spf']);
  assert.ok(v6.signals.some((s) => /ip6 mechanism asserts/.test(s) && /not resolved by this tool/.test(s)));
  // an ip6 inside Cloudflare's published v6 ranges is fronted infrastructure, not an origin
  assert.ok(!out.candidates.some((x) => x.host === '2606:4700::1'), 'CF-ranged ip6 is never a candidate');
  // CIDR-form ip6 is a range assertion, not a host: noted as a gap, never expanded
  assert.ok(!out.candidates.some((x) => /\/48/.test(x.host)), 'CIDR ip6 never becomes a host candidate');
  assert.ok(out.honestGaps && out.honestGaps.some((g) => /CIDR ranges were seen but not expanded/.test(g)), 'the unexpanded CIDR form is honestly noted');
  // v4 regression: the bare ip4 in the same record still lands exactly as before
  assert.ok(out.candidates.some((x) => x.host === '203.0.113.30'), 'bare ip4 harvesting unchanged');
});

test('a resolver throwing on one host degrades that host to error and never sinks the run', async () => {
  const out = await run(); // must resolve, not reject
  assert.equal(out.ok, true);
  const flaky = byHost(out, 'flaky.example.com');
  assert.equal(flaky.state, 'error');
  assert.ok(flaky.signals.some((s) => /resolver error/.test(s) && /NOT clean/.test(s)));
  assert.ok(!candidateHosts(out).includes('flaky.example.com'));
  // the rest of the run survived the explosion
  assert.ok(candidateHosts(out).includes('origin.example.com'));
  assert.ok(candidateHosts(out).includes('mail.example.com'));
});

test('the scope gate and the verification checklist ship in every report', async () => {
  const out = await run();
  assert.equal(out.scopeGate, 'PASSIVE ONLY — no TCP connection to any candidate until it is signed into the engagement scope');
  assert.equal(out.scopeGate, SCOPE_GATE);
  assert.equal(out.verificationChecklist.length, 4);
  const gated = out.verificationChecklist.filter((s) => s.startsWith('AFTER SCOPE SIGNATURE: '));
  assert.equal(gated.length, 3, 'cert/favicon/body-string checks all wait for scope signature');
  assert.ok(out.verificationChecklist.some((s) => /^PASSIVE/.test(s) && /historical A-record/.test(s)), 'historical DNS is the one passive check');
  // standing honest gaps name what v1 does not do
  const gaps = out.honestGaps.join('\n');
  for (const phrase of ['historical A-record databases', 'Censys/Shodan', 'favicon-MMH3', 'subdomain brute force']) {
    assert.ok(gaps.includes(phrase), 'honestGaps names: ' + phrase);
  }
  assert.ok(out.fetchedAt);
});
