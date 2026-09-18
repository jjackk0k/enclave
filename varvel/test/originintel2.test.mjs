// VARVEL -- originintel v2 hermetic tests. NO live network: fixture crt.sh JSON, a
// scripted resolver, a scripted HTTP fetcher, temp-dir range caches, and ONE real
// loopback TLS server pair (the static lab cert, same pattern as doh.test) for the
// default-prober end-to-end. Nothing leaves 127.0.0.1.
//
// The assertions are the v2 doctrine: cross-source candidates aggregate BY IP with
// confidence, historical DNS converges, the favicon fingerprint follows the Shodan
// convention, mmh3 matches the reference algorithm's own known-answer vectors,
// verify REFUSES out-of-scope candidates (printing the exact CIDR to sign), a
// challenge on the candidate vetoes confirmation, and every failed source is an
// honest "unobserved, not absent" gap.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import {
  originDiscover, mmh3, faviconHash, loadCfRanges, dohJsonResolver, parseViewDnsHistory,
} from '../tools/originintel.mjs';
import { DOH_LAB_CERT, DOH_LAB_KEY } from '../engine/doh-labcert.mjs';

const nx = () => { const e = new Error('queryA ENOTFOUND'); e.code = 'ENOTFOUND'; return e; };
const nodata = () => { const e = new Error('queryTxt ENODATA'); e.code = 'ENODATA'; return e; };
const mkdtemp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'varvel-oi2-'));

// A favicon-shaped byte string (fixture only -- not a real .ico, the hash does not care).
const FAVICON = Buffer.from([
  0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x10, 0x10, 0x00, 0x00, 0x01, 0x00,
  0x20, 0x00, 0x68, 0x04, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0xde, 0xad,
  0xbe, 0xef, 0x13, 0x37,
]);

// Fixture CT set: one CF-fronted name, one origin-looking name. (mail.example.com is
// deliberately NOT here -- the MX/SPF sources alone name it, exercising aggregation.)
const CRT_ROWS = [
  { name_value: 'www.example.com\norigin.example.com' },
];

// Fixture viewdns.info iphistory page: one converging IP, one already-Cloudflare IP
// (must be filtered), one history-only IP (low confidence).
const VIEWDNS_HTML = '<html><body><h3>IP History for example.com</h3>'
  + '<table border="1"><tr><th>IP Address</th><th>Owner</th><th>Last seen on this IP</th></tr>'
  + '<tr><td>203.0.113.10</td><td>Example Hosting LLC</td><td>2023-05-01</td></tr>'
  + '<tr><td>104.16.5.5</td><td>Cloudflare Inc</td><td>2024-01-15</td></tr>'
  + '<tr><td>203.0.113.99</td><td>Legacy Host</td><td>2019-11-20</td></tr>'
  + '</table></body></html>';
const VIEWDNS_DRIFT = '<html><body><h1>Welcome to our redesigned site</h1><p>nothing tabular here</p></body></html>';

// The scripted "internet": fetcher routes by URL; resolver answers the example.com zone.
function baseFetcher(url) {
  const u = String(url);
  if (u.startsWith('https://crt.sh/')) return { status: 200, headers: {}, body: JSON.stringify(CRT_ROWS) };
  if (u.startsWith('https://viewdns.info/')) return { status: 200, headers: {}, body: VIEWDNS_HTML };
  if (u === 'https://www.cloudflare.com/ips-v4') return { status: 200, headers: {}, body: '104.16.0.0/13\n172.64.0.0/13\n' };
  if (u === 'https://www.cloudflare.com/ips-v6') return { status: 200, headers: {}, body: '2606:4700::/32\n' };
  if (u === 'https://example.com/favicon.ico') return { status: 200, headers: {}, body: FAVICON };
  throw new Error('unexpected url ' + u);
}

function baseResolver() {
  const A = {
    'example.com': ['104.16.5.5'],          // Cloudflare /13 -- fronted
    'www.example.com': ['104.16.5.5'],      // Cloudflare -- fronted
    'origin.example.com': ['203.0.113.10'], // TEST-NET-3, outside CF -- origin candidate
    'mail.example.com': ['203.0.113.25'],   // MX + SPF-include host, outside CF
  };
  return {
    async resolve4(h) { if (A[h]) return A[h]; throw nx(); },
    async resolve6() { throw nodata(); },
    async resolveMx(h) {
      if (h === 'example.com') return [{ exchange: 'mail.example.com', priority: 10 }];
      throw nx();
    },
    async resolveTxt(h) {
      if (h === 'example.com') return [['v=spf1 include:mail.example.com ip4:203.0.113.30 ~all']];
      throw nodata(); // leaf include target with no TXT: an observed dead branch
    },
  };
}

const base = () => ({ fetcher: baseFetcher, resolver: baseResolver(), cacheDir: mkdtemp(), env: {}, paceMs: 0 });

// ---------- mmh3 / favicon fingerprint ----------

test('mmh3 x86_32 matches the reference known-answer vectors', () => {
  // Anchors derived from Austin Appleby's public-domain reference implementation
  // (smhasher/src/MurmurHash3.cpp): mmh3('') = 0 and mmh3('hello') = 613153351
  // (0x248bfa47) are the widely published vectors; mmh3('foo') = -156908512 is the
  // python-mmh3 package's own documented example (signed 32-bit, the Shodan
  // convention). The seed-1 value is pinned from the SMHasher-validated port below.
  assert.equal(mmh3(''), 0);
  assert.equal(mmh3('hello'), 613153351);
  assert.equal(mmh3('foo'), -156908512);
  assert.equal(mmh3('hello', 1), -1152729939);
  // The strongest KAT: SMHasher's OWN x86_32 VerificationTest, run live -- hash
  // key[0..i] (key[i] = i) with seed 256-i for i = 0..255, concatenate the 256
  // little-endian u32 hashes, hash that 1024-byte array with seed 0. The reference
  // algorithm's printed verification value for MurmurHash3_x86_32 is 0xB0F57EE3.
  const key = Buffer.alloc(256);
  const hashes = Buffer.alloc(256 * 4);
  for (let i = 0; i < 256; i++) {
    key[i] = i;
    hashes.writeUInt32LE(mmh3(key.subarray(0, i), 256 - i) >>> 0, i * 4);
  }
  assert.equal(mmh3(hashes, 0) >>> 0, 0xb0f57ee3, 'SMHasher x86_32 verification value');
});

test('faviconHash follows the Shodan convention (MIME-base64, signed 32-bit)', () => {
  // The Shodan favicon technique: mmh3(base64.encodebytes(favicon)) -- 76-column
  // base64 lines with a trailing newline, signed 32-bit result.
  assert.equal(faviconHash(FAVICON), faviconHash(Buffer.from(FAVICON)));
  assert.notEqual(faviconHash(FAVICON), faviconHash(Buffer.from([1, 2, 3])));
  assert.equal(faviconHash(Buffer.alloc(0)), mmh3(''), 'empty input: python encodebytes(b"") == b""');
  const h = faviconHash(FAVICON);
  assert.ok(Number.isInteger(h) && h >= -2147483648 && h <= 2147483647, 'signed 32-bit');
  // The wrap matters: >57 input bytes produce multi-line base64, hashed verbatim.
  const big = Buffer.alloc(120, 7);
  const wrapped = big.toString('base64').match(/.{1,76}/g).join('\n') + '\n';
  assert.equal(faviconHash(big), mmh3(wrapped));
});

// ---------- parsers / resolvers / range cache ----------

test('parseViewDnsHistory parses the table and reports drift honestly', () => {
  const rows = parseViewDnsHistory(VIEWDNS_HTML);
  assert.deepEqual(rows, [
    { ip: '203.0.113.10', lastSeen: '2023-05-01' },
    { ip: '104.16.5.5', lastSeen: '2024-01-15' },
    { ip: '203.0.113.99', lastSeen: '2019-11-20' },
  ]);
  assert.equal(parseViewDnsHistory(VIEWDNS_DRIFT), null, 'missing markers = parse drift, never silence');
  assert.equal(parseViewDnsHistory(''), null);
});

test('dohJsonResolver maps dns-json answers to node:dns shapes and failure codes', async () => {
  const seen = [];
  const fetcher = async (url) => {
    const u = new URL(String(url));
    seen.push(u);
    const type = u.searchParams.get('type');
    if (type === 'A') return { status: 200, body: { Status: 0, Answer: [{ type: 1, data: '203.0.113.10' }, { type: 5, data: 'ignored.example.com' }] } };
    if (type === 'MX') return { status: 200, body: JSON.stringify({ Status: 0, Answer: [{ type: 15, data: '10 mail.example.com.' }] }) };
    if (type === 'TXT') return { status: 200, body: { Status: 0, Answer: [{ type: 16, data: '"v=spf1 include:x" "second-chunk"' }] } };
    if (type === 'AAAA') return { status: 200, body: { Status: 3 } };
    return { status: 200, body: { Status: 0 } };
  };
  const r = dohJsonResolver({ fetcher, server: 'https://doh.test/dns-query' });
  assert.deepEqual(await r.resolve4('example.com'), ['203.0.113.10']);
  assert.deepEqual(await r.resolveMx('example.com'), [{ priority: 10, exchange: 'mail.example.com' }]);
  assert.deepEqual(await r.resolveTxt('example.com'), [['v=spf1 include:x', 'second-chunk']]);
  assert.equal(seen[0].origin + seen[0].pathname + seen[0].search, 'https://doh.test/dns-query?name=example.com&type=A');
  await assert.rejects(() => r.resolve6('example.com'), (e) => e.code === 'ENOTFOUND');
  const empty = dohJsonResolver({ fetcher: async () => ({ status: 200, body: { Status: 0, Answer: [] } }), server: 'https://doh.test/' });
  await assert.rejects(() => empty.resolve4('example.com'), (e) => e.code === 'ENODATA');
});

test('loadCfRanges: live fetch validates + writes the cache; a fresh cache serves later calls', async () => {
  const dir = mkdtemp();
  let fetches = 0;
  const fetchText = async (u) => { fetches++; return u.endsWith('ips-v4') ? '104.16.0.0/13\n172.64.0.0/13\n' : '2606:4700::/32\n'; };
  const a = await loadCfRanges({ fetchText, cacheDir: dir });
  assert.equal(a.source, 'live');
  assert.deepEqual(a.v4, ['104.16.0.0/13', '172.64.0.0/13']);
  assert.deepEqual(a.v6, ['2606:4700::/32']);
  assert.equal(fetches, 2);
  assert.ok(fs.existsSync(path.join(dir, 'cf-ranges.json')), 'workspace cache file written');
  const b = await loadCfRanges({ fetchText: async () => { throw new Error('must not be called'); }, cacheDir: dir });
  assert.equal(b.source, 'cache');
  assert.deepEqual(b.v4, a.v4);
  // stale cache + failed live fetch -> cache-stale with an honest note
  const stale = JSON.parse(fs.readFileSync(path.join(dir, 'cf-ranges.json'), 'utf8'));
  stale.fetchedAt = new Date(Date.now() - 30 * 86400000).toISOString();
  fs.writeFileSync(path.join(dir, 'cf-ranges.json'), JSON.stringify(stale));
  const c = await loadCfRanges({ fetchText: async () => { throw new Error('offline'); }, cacheDir: dir });
  assert.equal(c.source, 'cache-stale');
  assert.ok(/stale cache/.test(c.note));
});

test('loadCfRanges: no cache + failed fetch falls back to the dated hardcoded list', async () => {
  const r = await loadCfRanges({ fetchText: async () => { throw new Error('offline'); }, cacheDir: mkdtemp() });
  assert.equal(r.source, 'fallback');
  assert.equal(r.ok, false);
  assert.ok(/dated hardcoded list of 2026-08-05/.test(r.gap), 'the fallback names its own date');
  assert.ok(r.v4.length >= 10 && r.v6.length >= 5, 'the dated pin is usable');
});

// ---------- originDiscover: passive aggregation ----------

test('originDiscover passive: candidates aggregate BY IP with sources, confidence, evidence', async () => {
  const out = await originDiscover('example.com', base());
  assert.equal(out.ok, true);
  assert.equal(out.mode, 'passive');
  assert.equal(out.candidates.length, 4);
  const [c1, c2, c3, c4] = out.candidates;
  // historical + live convergence on the same IP = high
  assert.equal(c1.ip, '203.0.113.10');
  assert.deepEqual(c1.sources, ['ct-log', 'history-viewdns']);
  assert.equal(c1.confidence, 'high');
  assert.ok(c1.evidence.some((e) => /crt\.sh/.test(e) && /outside Cloudflare/.test(e)));
  assert.ok(c1.evidence.some((e) => /last seen 2023-05-01/.test(e)));
  // two independent mail sources = high
  assert.equal(c2.ip, '203.0.113.25');
  assert.deepEqual(c2.sources, ['mx', 'spf']);
  assert.equal(c2.confidence, 'high');
  assert.ok(c2.evidence.some((e) => /CloudPiercer/.test(e)));
  // single live DNS assertion = medium
  assert.equal(c3.ip, '203.0.113.30');
  assert.deepEqual(c3.sources, ['spf-ip4']);
  assert.equal(c3.confidence, 'medium');
  // history-only = low (stale leads age badly)
  assert.equal(c4.ip, '203.0.113.99');
  assert.deepEqual(c4.sources, ['history-viewdns']);
  assert.equal(c4.confidence, 'low');
  // the Cloudflare historical IP was filtered; the fronted names never candidated
  assert.ok(!out.candidates.some((c) => c.ip === '104.16.5.5'));
  // per-source states + the SecurityTrails disabled-with-note state
  assert.equal(out.sources['ct-log'], 'ok');
  assert.equal(out.sources.mx, 'ok');
  assert.equal(out.sources.spf, 'ok');
  assert.equal(out.sources['history-viewdns'], 'ok');
  assert.equal(out.sources['history-securitytrails'], 'disabled');
  assert.equal(out.sources.favicon, 'ok');
  assert.equal(out.sources['cf-ranges'], 'live');
  assert.ok(out.gaps.some((g) => /SECURITYTRAILS_API_KEY is not set/.test(g)));
  assert.ok(out.gaps.some((g) => /unobserved, not absent/.test(g)));
  // apex favicon fingerprint observed; recommendedScope lists the exact host routes
  assert.equal(out.apexFavicon.hash, faviconHash(FAVICON));
  assert.deepEqual(out.recommendedScope, ['203.0.113.10/32', '203.0.113.25/32', '203.0.113.30/32', '203.0.113.99/32']);
  assert.deepEqual(out.verified, [], 'passive mode never probes');
  assert.deepEqual(out.refusals, []);
  assert.equal(out.scopeGate.startsWith('PASSIVE ONLY'), true);
});

test('originDiscover: SPF bare ip6 assertions candidate like ip4; CF-ranged and private v6 never do', async () => {
  const resolver = baseResolver();
  resolver.resolveTxt = async (h) => {
    if (h === 'example.com') return [['v=spf1 include:mail.example.com ip4:203.0.113.30 ip6:2001:DB8::25 ip6:2606:4700::1 ip6:fd00::9 ~all']];
    throw nodata();
  };
  const out = await originDiscover('example.com', { ...base(), resolver });
  assert.equal(out.ok, true);
  // bare ip6, canonicalized from the mixed-case zone form, candidates exactly like ip4
  const v6 = out.candidates.find((c) => c.ip === '2001:db8::25');
  assert.ok(v6, 'bare ip6 mechanism outside CF must candidate');
  assert.deepEqual(v6.sources, ['spf-ip6']);
  assert.equal(v6.confidence, 'medium', 'single DNS-asserted source = medium, like ip4');
  assert.ok(v6.evidence.some((e) => /bare ip6 mechanism/.test(e) && /not resolved by this tool/.test(e)));
  // inside Cloudflare's live v6 range: fronted, filtered
  assert.ok(!out.candidates.some((c) => c.ip === '2606:4700::1'), 'CF-ranged ip6 is never a candidate');
  // ULA: a DNS anomaly, noted, NEVER a candidate (a hostile zone must not aim us at a lab)
  assert.ok(!out.candidates.some((c) => c.ip === 'fd00::9'), 'private v6 never candidates');
  assert.ok(out.notes.some((n) => /asserts a private\/range address \(fd00::9\)/.test(n)), 'the anomaly is named');
  // v4 regression: the same record's bare ip4 still lands exactly as before
  assert.ok(out.candidates.some((c) => c.ip === '203.0.113.30' && c.sources.includes('spf-ip4')));
  assert.ok(out.recommendedScope.includes('2001:db8::25/128'), 'the v6 candidate scopes as a /128 host route');
});

test('originDiscover: every failed source is an honest gap -- unobserved, not absent', async () => {
  let crtCalls = 0;
  const out = await originDiscover('example.com', {
    fetcher: async (url) => { if (String(url).startsWith('https://crt.sh/')) crtCalls++; throw new Error('network down'); },
    resolver: {
      async resolve4() { throw nx(); },
      async resolve6() { throw nodata(); },
      async resolveMx() { throw nx(); },
      async resolveTxt() { throw nx(); },
    },
    cacheDir: mkdtemp(), env: {}, paceMs: 0,
  });
  assert.equal(out.ok, true, 'never throws, never a hard failure');
  assert.deepEqual(out.candidates, []);
  assert.equal(crtCalls, 2, 'crt.sh gets exactly one retry');
  const g = out.gaps.join('\n');
  assert.ok(/crt\.sh fetch failed after one retry/.test(g));
  assert.ok(/MX lookup for example\.com failed/.test(g));
  assert.ok(/TXT lookup for example\.com failed/.test(g));
  assert.ok(/viewdns\.info IP-history fetch failed/.test(g));
  assert.ok(/SecurityTrails A-history NOT queried/.test(g));
  assert.ok(/apex favicon fetch failed/.test(g));
  assert.ok(/dated hardcoded list of 2026-08-05/.test(g));
  assert.ok(/unobserved, not absent/.test(g));
  assert.equal(out.sources['cf-ranges'], 'fallback');
  assert.equal(out.sources['ct-log'], 'failed');
});

// ---------- originDiscover: verify mode (governance) ----------

test('verify REFUSES out-of-scope candidates with the exact CIDR -- and never probes them', async () => {
  const calls = [];
  const prober = async (ip) => {
    calls.push(ip);
    return { ok: true, status: 200, headers: {}, body: Buffer.from('<html><title>example.com home</title></html>'), favicon: FAVICON, faviconStatus: 200, cert: null };
  };
  const out = await originDiscover('example.com', {
    ...base(), mode: 'verify', scope: ['203.0.113.0/24'],
    candidates: ['203.0.113.10', '198.51.100.10', '2001:db8::10'], prober,
  });
  assert.equal(out.ok, true);
  assert.deepEqual(calls, ['203.0.113.10'], 'ONLY the in-scope candidate was probed');
  assert.equal(out.verified.length, 1);
  assert.equal(out.verified[0].confirmed, true, 'title marker + favicon match confirm');
  const refIps = out.refusals.map((r) => r.ip).sort();
  assert.deepEqual(refIps, ['198.51.100.10', '2001:db8::10']);
  assert.equal(out.refusals.find((r) => r.ip === '198.51.100.10').recommendedCidr, '198.51.100.10/32');
  assert.equal(out.refusals.find((r) => r.ip === '2001:db8::10').recommendedCidr, '2001:db8::10/128');
  assert.ok(/not inside the signed engagement scope/.test(out.refusals[0].reason));
  // the refusals feed recommendedScope; the already-covered candidates do not
  assert.deepEqual(out.recommendedScope, ['198.51.100.10/32', '2001:db8::10/128']);
});

test('verify without a signed scope refuses wholesale -- zero probes', async () => {
  const calls = [];
  const out = await originDiscover('example.com', {
    ...base(), mode: 'verify', candidates: ['203.0.113.10'],
    prober: async (ip) => { calls.push(ip); return { ok: false, error: 'must not run' }; },
  });
  assert.equal(calls.length, 0, 'never probed without scope');
  assert.equal(out.verified.length, 0);
  assert.equal(out.refusals.length, 1);
  assert.ok(/no signed engagement scope was provided/.test(out.refusals[0].reason));
  assert.equal(out.refusals[0].recommendedCidr, '203.0.113.10/32');
  assert.ok(out.gaps.some((g) => /NO signed scope/.test(g)));
  assert.ok(out.recommendedScope.includes('203.0.113.10/32'));
});

test('a CF challenge on the candidate VETOES confirmation even with a favicon match', async () => {
  const prober = async () => ({
    ok: true,
    status: 403,
    headers: { server: 'cloudflare', 'cf-mitigated': 'challenge', 'cf-ray': 'a1b2c3-AMS' },
    body: Buffer.from('<html><title>Just a moment...</title><p>challenge-platform</p></html>'),
    favicon: FAVICON, faviconStatus: 200, cert: null,
  });
  const out = await originDiscover('example.com', {
    ...base(), mode: 'verify', scope: ['203.0.113.0/24'], candidates: ['203.0.113.10'], prober,
  });
  assert.equal(out.verified.length, 1);
  const v = out.verified[0];
  assert.equal(v.detection.present, true);
  assert.equal(v.detection.kind, 'managed-js');
  assert.equal(v.confirmed, false, 'challenge response is never a confirmed origin');
  assert.ok(v.evidence.some((e) => /challenge evidence on the candidate/.test(e)));
  assert.ok(v.evidence.some((e) => /favicon mmh3 .* MATCHES/.test(e)), 'the matching signal is still reported');
});

test('a failed probe is an honest unobserved state, never a negative finding', async () => {
  const out = await originDiscover('example.com', {
    ...base(), mode: 'verify', scope: ['203.0.113.0/24'], candidates: ['203.0.113.10'],
    prober: async () => ({ ok: false, error: 'read timeout' }),
  });
  assert.equal(out.verified.length, 1);
  assert.equal(out.verified[0].confirmed, false);
  assert.equal(out.verified[0].error, 'read timeout');
  assert.ok(out.verified[0].evidence.some((e) => /unobserved, not absent/.test(e)));
});

test('verify with the REAL default prober over loopback TLS: favicon + cert CN + title confirm', async () => {
  // A real TLS server pair stand-in: the static lab cert (CN=varvel-doh-lab.local,
  // same fixture pattern as doh.test) serves the apex-shaped page + favicon; the
  // DEFAULT prober dials it with SNI/Host pinned to the domain. Loopback only.
  const seenHosts = [];
  const server = https.createServer({ cert: DOH_LAB_CERT, key: DOH_LAB_KEY }, (req, res) => {
    seenHosts.push(req.headers.host);
    if (req.url === '/favicon.ico') {
      res.writeHead(200, { 'content-type': 'image/x-icon' });
      res.end(FAVICON);
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html><head><title>varvel-doh-lab.local status page</title></head><body>ok</body></html>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const labFetcher = async (url) => {
    const u = String(url);
    if (u.startsWith('https://crt.sh/')) return { status: 200, headers: {}, body: JSON.stringify([{ name_value: 'varvel-doh-lab.local' }]) };
    if (u.startsWith('https://viewdns.info/')) return { status: 200, headers: {}, body: VIEWDNS_DRIFT };
    if (u === 'https://www.cloudflare.com/ips-v4') return { status: 200, headers: {}, body: '104.16.0.0/13\n' };
    if (u === 'https://www.cloudflare.com/ips-v6') return { status: 200, headers: {}, body: '2606:4700::/32\n' };
    if (u === 'https://varvel-doh-lab.local/favicon.ico') return { status: 200, headers: {}, body: FAVICON };
    throw new Error('unexpected url ' + u);
  };
  const labResolver = {
    async resolve4(h) { if (h === 'varvel-doh-lab.local') return ['104.16.5.5']; throw nx(); },
    async resolve6() { throw nodata(); },
    async resolveMx() { throw nx(); },
    async resolveTxt() { throw nodata(); },
  };
  try {
    const out = await originDiscover('varvel-doh-lab.local', {
      fetcher: labFetcher, resolver: labResolver, cacheDir: mkdtemp(), env: {}, paceMs: 0,
      mode: 'verify', scope: ['127.0.0.0/8'], candidates: ['127.0.0.1'], verifyPort: port,
    });
    assert.equal(out.ok, true);
    assert.deepEqual(out.candidates, [], 'the CF-fronted apex is not a candidate');
    assert.equal(out.refusals.length, 0, 'loopback is inside the signed scope');
    assert.equal(out.verified.length, 1);
    const v = out.verified[0];
    assert.equal(v.ip, '127.0.0.1');
    assert.equal(v.confirmed, true);
    assert.equal(v.detection.present, false);
    assert.equal(v.faviconHash, faviconHash(FAVICON), 'real favicon bytes hashed identically on both sides');
    assert.equal(v.cert.cn, 'varvel-doh-lab.local');
    assert.ok(v.evidence.some((e) => /favicon mmh3 .* MATCHES/.test(e)));
    assert.ok(v.evidence.some((e) => /names varvel-doh-lab\.local or \*\.varvel-doh-lab\.local/.test(e)));
    assert.ok(v.evidence.some((e) => /page markers \(title\)/.test(e)));
    assert.ok(seenHosts.length >= 2 && seenHosts.every((h) => h === 'varvel-doh-lab.local'),
      'Host header pinned to the domain on every candidate request');
  } finally {
    server.close();
    if (server.closeAllConnections) server.closeAllConnections();
  }
});
