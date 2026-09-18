// fporacle.test.mjs -- hermetic: exact-string JA4/JA4S/JA4H against hand-crafted hello
// buffers (expected values derived from the official spec, shown inline), real-loopback
// JA4 capture + JA4S probe, the findings matrix for the agent's WebClient wire shape,
// fail-closed garbage handling, and the channel's passive observer integration.
//   node --test varvel/test/fporacle.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import https from 'node:https';
import tls from 'node:tls';
import { parseClientHello, ja4, parseServerHello, ja4s, ja4h, httpShape, fingerprintFindings, hash12, isGrease } from '../engine/fingerprint.mjs';
import { buildProbeClientHello, probeJa4s, captureJa4, createHttpObserver, assessHttp } from '../tools/fporacle.mjs';
import { CallbackChannel } from '../engine/callback.mjs';

const SCOPE = { cidrs: ['127.0.0.0/8'] };
const hmac = (t, m) => crypto.createHmac('sha256', t).update(m).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Self-signed fixture for the in-test https server (throwaway test cert, CN=fporacle-test.local).
const KEY = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC8HOlgNyGMKGuE
3bDZh+EC4jBWX94v323/RR62kKeXTdW+9YeAwcPJj1RVObcyksYnS9Xv7++wzIqo
08ST+Kjge3JENCDLK2ydofPSk+LaUFeVjw2UXy8w75I2RrAKX5CP5bM/HmeQa8V/
Dc+A+CcBQXLb+XKTRLRtpGMmCAxU6n7/6+JqEHOOGLlFOyQUwIJ6T5PfWgNjHFrI
K+Fup4onZGL8e0RZpcV0R7LPoJAjxlfEKVBcg7fdTzoUxamrfGKXGmgxGqcgZkIL
ESoaZ6oqkV4CYVrY1NiPtAmr2/wjfBbHiMvpD90fkkiXXn7XelIvmB7C0AM7pv5x
6PjC+R3lAgMBAAECggEAA9sWhYcGbwMHwSoczTirH2NXg6MPa4J0P2lBSeiz0WF3
t3mnlLdkC1D0H5MWnY4YoFw+Pwl3VkkQW97gsU/FgQ8cC9MttjxmS4zdnJFfcwN2
ksrjMl6zxEME3OFHYSRi/YVtzntnEAoa0DyOO6HahXy78qUC+OB4T6RboT9E/Bs8
B3b/RGOYyedWP/aqgmidHYO/sbZxAEJkFQ4mUMvM2fV1Pmnx1oDdQfWmAMD8+yrj
4K9r8rrNaAi475Yfdd/wan9tJ0nSilyAoPAH3a77WjFu2155bjISNE7ZyRig2Kik
MPX+cYkMpXUD3ViMgfZrBWPn9ZeNJaSmqHbHw1kIQQKBgQDtrPLvWauErwvV0Pqd
fshQit+edx5JE0gC1qbI/zJvWCBqTkI++FHgjHfsMgLkAJ8EsztQB9biuhg30Pqw
tzeOCLALR3ybvs0mbzXGF7qynWCCT+ZGJo3rjIoXRex5kaCFoqSEDFxD0mhK7+/4
wqjo+in7ysl1Srxd0k6pmFj6eQKBgQDKnbwU2TfcaufC77HC+4UuWoAeCa80Zcwl
vQFXJLtNSxPYb1ysXJ7FPaZdmRt/5S3b2YsqOju8E7DKDRZ+OiHWQHBGCPBnVA8z
OCBZ5rDVyYQAQs6Gh68nw0/qiAhLkTFqeHQVpCKaebHu+Y1skw2yrbG4+un0fpzR
MnMCJsojzQKBgBoJBveXIAXB0w8R/FICUFkaTVKjg8rHdOzyrIR6CAFQawSaHAGf
3AA4Au75r31gYAr4wzeKFEzzy7FZkAyJlWlWpEooA4tgBEMAjahscwQb3zWHIRdw
I724wGu6OiQ7ApWA8nqQjA7V3pzO2b+rOyuCM9UkKptRm36/ieRkDuMpAoGAEYuF
HN0ObETJmuS8pOC40KG/lFpMVKI4AlCSjCQ/H9tPdZ93C+ndScEj5dj7O6DxzqbQ
2TA/ufKOjYCCoR2Rjob38eiWQKxTwKCslHxYdbrEdm1Siu226h+MjQeIiFqjR8/0
ZWdYI75D/SiY6Xz2Y7GMwTLhDW3lUGwo71fCi0UCgYAiuotAs68zS9LtPTOqhTWG
u8wPKLHKbTEwTAyWqsqyjv8ay6AdB3pYqULv8mQlE7DTM/J8kr0qq6tS228hHCDn
B+XAQYa6aUw1E6KnXebIbWibVYO7LksYfj+L4PglsAd2lhnzLiwO1/+XxyjKmea5
wZw5G8R0Lx3WmfNlLLw0+w==
-----END PRIVATE KEY-----`;
const CERT = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIULKruBcS0fNvS6eJf8JYDdgWbhlswDQYJKoZIhvcNAQEL
BQAwHjEcMBoGA1UEAwwTZnBvcmFjbGUtdGVzdC5sb2NhbDAeFw0yNjA4MDQyMTI5
NTRaFw0zNjA4MDEyMTI5NTRaMB4xHDAaBgNVBAMME2Zwb3JhY2xlLXRlc3QubG9j
YWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8HOlgNyGMKGuE3bDZ
h+EC4jBWX94v323/RR62kKeXTdW+9YeAwcPJj1RVObcyksYnS9Xv7++wzIqo08ST
+Kjge3JENCDLK2ydofPSk+LaUFeVjw2UXy8w75I2RrAKX5CP5bM/HmeQa8V/Dc+A
+CcBQXLb+XKTRLRtpGMmCAxU6n7/6+JqEHOOGLlFOyQUwIJ6T5PfWgNjHFrIK+Fu
p4onZGL8e0RZpcV0R7LPoJAjxlfEKVBcg7fdTzoUxamrfGKXGmgxGqcgZkILESoa
Z6oqkV4CYVrY1NiPtAmr2/wjfBbHiMvpD90fkkiXXn7XelIvmB7C0AM7pv5x6PjC
+R3lAgMBAAGjUzBRMB0GA1UdDgQWBBSoksDAnMnHqMmCixrxBXT7uZQq+DAfBgNV
HSMEGDAWgBSoksDAnMnHqMmCixrxBXT7uZQq+DAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4IBAQAiUaWWRGWmRxqX1RhGyIbGRPJ9HPSOtY8Onfgx3uMn
DorrJO9np6L0IF1eBEfSyi7FyaMNlO2gUIJ3RFRsUM9KQLfJLTvzhj/YCOUAV60N
Q/DLcW04dvDCUN/pWvrERRIuaUk2ZTN4uHZt4WKK9Z4Bvl0tugiDkzlAemhaGef4
MbCjSltW4slX6RXo8GHPgmJEqPiYl1ACbswuNHzDklR7wPzaIe4ovvIWvP7B5g4X
VUOaq9h00WZ8grtt2tXkk6J/3r8GspUEhP0U4jCpjJCGdC72Ey5VDbW+VzhojNHf
O24GhVh3GC0V66Ve5ignQBP+JDRHpU+ZRfT8U4TnOe0I
-----END CERTIFICATE-----`;

// --- hand-crafted wire fixtures ---
const u16 = (...vs) => Buffer.from(vs.flatMap((v) => [(v >> 8) & 0xff, v & 0xff]));
const extRec = (type, data) => Buffer.concat([u16(type, data.length), data]);
const hsRec = (type, body) => {
  const hs = Buffer.concat([Buffer.from([type]), Buffer.from([(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff]), body]);
  return Buffer.concat([Buffer.from([22, 3, 1]), u16(hs.length), hs]);
};

// ClientHello: ciphers [1301 c02f 002f + GREASE 0a0a]; extensions [GREASE 1a1a, SNI
// example.com, ALPN h2+http/1.1, supported_versions 0304+0303, sigalgs 0403 0804 + GREASE].
function clientHelloBuf() {
  const sni = Buffer.from('example.com');
  const exts = Buffer.concat([
    extRec(0x1a1a, Buffer.alloc(0)),
    extRec(0x0000, Buffer.concat([u16(3 + sni.length), Buffer.from([0]), u16(sni.length), sni])),
    extRec(0x0010, Buffer.concat([u16(12), Buffer.from([2]), Buffer.from('h2', 'latin1'), Buffer.from([8]), Buffer.from('http/1.1', 'latin1')])),
    extRec(0x002b, Buffer.concat([Buffer.from([4]), u16(0x0304, 0x0303)])),
    extRec(0x000d, Buffer.concat([u16(6), u16(0x0403, 0x0804, 0x0a0a)])),
  ]);
  const ciphers = u16(0x1301, 0xc02f, 0x002f, 0x0a0a);
  const body = Buffer.concat([u16(0x0303), Buffer.alloc(32, 0x11), Buffer.from([0]), u16(ciphers.length), ciphers, Buffer.from([1, 0]), u16(exts.length), exts]);
  return hsRec(1, body);
}

// ServerHello (TLS1.2 shape): cipher c02f, extensions [SNI ack, ALPN h2, renegotiation_info].
function serverHelloBuf() {
  const exts = Buffer.concat([
    extRec(0x0000, Buffer.alloc(0)),
    extRec(0x0010, Buffer.concat([u16(3), Buffer.from([2]), Buffer.from('h2', 'latin1')])),
    extRec(0xff01, Buffer.from([0])),
  ]);
  const body = Buffer.concat([u16(0x0303), Buffer.alloc(32, 0x22), Buffer.from([0]), u16(0xc02f), Buffer.from([0]), u16(exts.length), exts]);
  return hsRec(2, body);
}

// The agent's real check-in wire shape (.NET System.Net.WebClient, established facts):
// GET /c with x-agent, x-seq, x-auth in add order; Host and nothing else browser-ish.
const AGENT_GET = { method: 'GET', httpVersion: '1.1', headers: [['Host', '127.0.0.1:8971'], ['x-agent', 'a1b2c3'], ['x-seq', '7'], ['x-auth', 'ff00ff']] };
// POST /r adds x-task and Expect: 100-continue.
const AGENT_POST = { method: 'POST', httpVersion: '1.1', headers: [['Host', '127.0.0.1:8971'], ['x-agent', 'a1b2c3'], ['x-seq', '8'], ['x-auth', 'ff00ff'], ['x-task', 't-1'], ['Expect', '100-continue']] };
const BROWSER_GET = { method: 'GET', httpVersion: '1.1', headers: [['Host', 'example.com'], ['User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'], ['Accept', 'text/html'], ['Accept-Language', 'en-US,en;q=0.9'], ['Referer', 'https://example.com/'], ['Cookie', 'b=2; a=1']] };

test('parseClientHello + ja4: exact spec string, GREASE filtered, derivation shown', () => {
  const parsed = parseClientHello(clientHelloBuf());
  assert.ok(parsed);
  assert.equal(parsed.version, 0x0304);            // true version from supported_versions
  assert.equal(parsed.sni, 'example.com');
  assert.deepEqual(parsed.alpn, ['h2', 'http/1.1']);
  // Derivation (JA4.md): version '13'; SNI ext present -> 'd'; ciphers post-GREASE = 3
  // (002f,1301,c02f sorted -> 54093f43ad55); exts post-GREASE = 4 counting SNI+ALPN;
  // hash list EXCLUDES 0000+0010 -> 000d,002b + '_' + sigalgs as presented (0403,0804)
  // -> ef5f37ab036a; first ALPN h2 -> 'h2'.
  assert.equal(ja4(parsed), 't13d0304h2_54093f43ad55_ef5f37ab036a');
  assert.equal(hash12('002f,1301,c02f'), '54093f43ad55'); // the b-section derivation, pinned
  assert.equal(hash12('000d,002b_0403,0804'), 'ef5f37ab036a');
});

test('ja4: the official JA4.md worked example reproduces exactly', () => {
  // The spec's own example vectors (JA4.md "Example" + rust tls.rs test):
  assert.equal(ja4({
    version: 0x0304,
    ciphers: [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
    extensions: [0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015],
    sni: 'example.com', alpn: ['h2'],
    sigalgs: [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
  }), 't13d1516h2_8daaf6152771_e5627efa2ab1');
});

test('parseServerHello + ja4s: exact spec string, derivation shown', () => {
  const parsed = parseServerHello(serverHelloBuf());
  assert.ok(parsed);
  assert.equal(parsed.version, 0x0303);
  assert.equal(parsed.cipher, 0xc02f);
  assert.equal(parsed.alpn, 'h2');
  // Derivation (rust ServerStats / python to_ja4s -- no JA4S.md exists): 't' + '12' +
  // ext count 03 + alpn 'h2' + '_' + cipher 'c02f' + '_' + hash12(exts in PRESENTED
  // order '0000,0010,ff01' = 79f4a30b0773).
  assert.equal(ja4s(parsed), 't1203h2_c02f_79f4a30b0773');
});

test('ja4s: the rust reference test vector reproduces exactly', () => {
  assert.equal(ja4s({ version: 0x0303, cipher: 0xc030, extensions: [0x0005, 0x0017, 0xff01, 0x0000], alpn: null }), 't120400_c030_4e8089b08790');
});

test('ja4h: exact strings for the agent wire shape and a browser shape', () => {
  // Agent (WebClient facts): ge + 11 + n(cookie) + n(referer) + 04 headers (Host,x-agent,
  // x-seq,x-auth; none excluded) + 0000 (no Accept-Language) _ hash12(header names as
  // sent) _ 000000000000 _ 000000000000 (no cookies -> zero sections, per the CSV rows).
  assert.equal(ja4h(AGENT_GET), 'ge11nn040000_da0705ce3d77_000000000000_000000000000');
  // Browser: c(cookie) r(referer), 04 counted (Cookie+Referer excluded from the count
  // and the b-list), lang en-US->'enus'; cookie names sorted 'a,b'; pairs sorted 'a=1,b=2'.
  assert.equal(ja4h(BROWSER_GET), 'ge11cr04enus_8ddaef5d77af_1eb7c54d5283_06beefe2b477');
});

test('findings: fire for the agent shape, never for a real browser shape', () => {
  const agentFindings = fingerprintFindings({ shape: httpShape(AGENT_GET.headers) });
  assert.deepEqual(agentFindings.map((f) => f.ref), ['FP-HTTP-MINIMAL', 'FP-XHEADERS']);
  assert.equal(agentFindings[0].sev, 'high');
  assert.equal(agentFindings[1].sev, 'med');
  // POST /r adds Expect: 100-continue (the .NET signature).
  const postRefs = fingerprintFindings({ shape: httpShape(AGENT_POST.headers) }).map((f) => f.ref);
  assert.ok(postRefs.includes('FP-EXPECT'));
  // Claiming a browser UA over the agent shape: mismatch + missing language join in.
  const claimed = fingerprintFindings({ shape: httpShape(AGENT_GET.headers), claimedUA: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120' }).map((f) => f.ref);
  assert.deepEqual(claimed, ['FP-HTTP-MINIMAL', 'FP-UA-MISMATCH', 'FP-XHEADERS', 'FP-LANG']);
  // A real browser shape with its own UA: nothing fires. (This is a measurement, NOT a
  // stealth verdict -- the honest absence of mismatch flags, not "undetectable".)
  assert.deepEqual(fingerprintFindings({ shape: httpShape(BROWSER_GET.headers), claimedUA: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120' }), []);
});

test('assessHttp: one-shot composition over the agent shape', () => {
  const r = assessHttp({ method: 'GET', httpVersion: '1.1', url: '/c', rawHeaders: AGENT_GET.headers.flat(), socket: { remoteAddress: '127.0.0.1' } });
  assert.equal(r.ja4h, 'ge11nn040000_da0705ce3d77_000000000000_000000000000');
  assert.equal(r.shape.count, 4);
  assert.equal(r.shape.hasUA, false);
  assert.deepEqual(r.shape.customXHeaders, ['x-agent', 'x-seq', 'x-auth']);
  assert.deepEqual(r.findings.map((f) => f.ref), ['FP-HTTP-MINIMAL', 'FP-XHEADERS']);
});

test('fail-closed: garbage in, null out -- never a guess, never a throw', () => {
  for (const junk of [null, undefined, '', Buffer.alloc(0), Buffer.from([1, 2, 3]), Buffer.from([22, 3, 1, 0, 2, 9, 9]), Buffer.from([23, 3, 3, 0, 1, 0])]) {
    assert.equal(parseClientHello(junk), null);
    assert.equal(parseServerHello(junk), null);
  }
  assert.equal(parseClientHello(serverHelloBuf()), null);  // right framing, wrong hello type
  assert.equal(parseServerHello(clientHelloBuf()), null);
  assert.equal(ja4(null), null);
  assert.equal(ja4s(null), null);
  assert.equal(ja4h(), null);
  assert.equal(ja4h({ headers: 'not-an-array' }), null);
  assert.ok(isGrease(0x0a0a) && isGrease(0xfafa) && !isGrease(0x1301) && !isGrease(0x0a0b));
  const r = assessHttp(null);                              // garbage req: no throw, honest empty
  assert.equal(r.shape.count, 0);
  assert.deepEqual(r.findings, []);
});

test('buildProbeClientHello: the probe parses back through our own ClientHello parser', () => {
  const parsed = parseClientHello(buildProbeClientHello('x.test'));
  assert.ok(parsed, 'probe hello must be well-formed on the wire');
  assert.equal(parsed.version, 0x0304);
  assert.equal(parsed.sni, 'x.test');
  assert.deepEqual(parsed.alpn, ['h2', 'http/1.1']);
  assert.equal(parsed.ciphers.length, 15);
  assert.equal(parsed.extensions.length, 12);
});

test('captureJa4: real node tls client on loopback, stable across runs', async () => {
  const connect = (port) => {
    const s = tls.connect({ host: '127.0.0.1', port, servername: 'fp-capture.test', rejectUnauthorized: false, ALPNProtocols: ['h2', 'http/1.1'] });
    s.on('error', () => {}); // the capture server hangs up after one record -- expected
  };
  const r1 = await captureJa4({ connect });
  assert.equal(r1.ok, true);
  assert.match(r1.ja4, /^t1[23]d\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/);
  assert.equal(r1.parsed.sni, 'fp-capture.test');
  const r2 = await captureJa4({ connect });
  assert.equal(r2.ok, true);
  assert.equal(r2.ja4, r1.ja4, 'same client, same hello bytes -> same JA4 (measurement stability)');
  const bad = await captureJa4({ connect: () => {}, timeout: 200 });
  assert.equal(bad.ok, false); // no client arrives -> honest failure, never a hang
});

test('probeJa4s: live ServerHello from an in-test https server; honest failure when refused', async () => {
  const srv = https.createServer({ key: KEY, cert: CERT }, (req, res) => res.end('ok'));
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const r = await probeJa4s('127.0.0.1', srv.address().port, { servername: 'fporacle-test.local' });
    assert.equal(r.ok, true);
    assert.match(r.ja4s, /^t1[23]\d{2}(00|h1|h2)_[0-9a-f]{4}_[0-9a-f]{12}$/);
    assert.match(r.cipher, /^[0-9a-f]{4}$/);
    // Cross-check against the PUBLISHED table: Node/OpenSSL TLS1.3 with cipher 1302 and
    // 2 extensions is exactly FoxIO's SoftEther-server row (t130200_1302_a56c5b993250).
    if (r.version === '0304' && r.cipher === '1302') assert.equal(r.ja4s, 't130200_1302_a56c5b993250');
    const refused = await probeJa4s('127.0.0.1', 9, {});
    assert.equal(refused.ok, false);
    const notTls = await probeJa4s('127.0.0.1', srv.address().port, {}); // https server, but probe is fine; a plain-HTTP peer would fail parse -- covered by garbage tests
    assert.equal(notTls.ok, true);
  } finally { srv.close(); }
});

test('observer: bounded ring, distinct count, never throws on garbage reqs', () => {
  const ob = createHttpObserver({ ringSize: 3 });
  const req = (seq) => ({ method: 'GET', httpVersion: '1.1', url: '/c?x=1', rawHeaders: ['Host', 'h', 'x-agent', 'a', 'x-seq', String(seq), 'x-auth', 'z'], socket: { remoteAddress: '127.0.0.1' } });
  for (let i = 1; i <= 5; i++) ob.observe(req(i));
  const st = ob.status();
  assert.equal(st.observations.length, 3, 'ring is bounded');
  assert.equal(st.distinctJa4h, 1, 'same client shape -> one distinct JA4H');
  assert.equal(st.observations[0].route, '/c', 'route is split on ?');
  assert.equal(st.observations[0].remoteIp, '127.0.0.1');
  assert.ok(st.observations[0].ja4h.startsWith('ge11'));
  ob.observe(null); ob.observe({}); ob.observe({ rawHeaders: 'junk' }); // garbage: no throw
  assert.equal(ob.status().observations.length <= 3, true);
});

test('channel integration: _handle observes check-ins passively, responses unchanged', async () => {
  const ch = new CallbackChannel({ scope: SCOPE });
  const { port } = await ch.arm(0);
  try {
    const { agentId, token } = ch.registerAgent({});
    const r = await fetch(`http://127.0.0.1:${port}/c`, { headers: { 'x-agent': agentId, 'x-seq': '1', 'x-auth': hmac(token, agentId + ':1:pull') } });
    assert.equal(r.status, 204, 'idle check-in behavior unchanged by the observer');
    const st = ch.fpStatus();
    assert.equal(st.observations.length, 1);
    assert.equal(st.observations[0].route, '/c');
    assert.match(st.observations[0].ja4h, /^ge1[01]/);
    assert.ok(st.observations[0].shapeSummary.count >= 3);
    assert.equal(st.distinctJa4h, 1);
  } finally { await ch.disarm(); }
});

test('teardown grace (win32)', async () => { await sleep(500); });
