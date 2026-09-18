// selfview.test.mjs -- gap#8: the defender-view infrastructure pre-flight.
// Pins: the pure classifier's rule set (lab-cert CN leak, self-signed, public-CA CT
// likelihood, banner/body markers, clean -> info only, dedupe + severity order), the
// JARM prober's spec shape (10 crafted hellos parse as real ClientHellos, digest
// construction incl. the reference's 'None' quirk), live JARM SELF-CONSISTENCY against
// an in-test https server, the never-throw live paths, and the /api/preflight route.
//
// JARM VALIDATION, stated honestly: no published Salesforce reference VECTOR is pinned
// here (none exists for a Node test server). Instead, on 2026-08-05 this implementation
// was cross-validated against the REFERENCE IMPLEMENTATION itself -- the actual
// salesforce/jarm jarm.py (BSD 3-Clause, stdlib-only harness) run live against the same
// in-test Node https server: identical per-probe raw outcomes AND identical 62-char
// hashes for two server shapes:
//   TLS1.3-capable server: 29d29d00000000000042d42d0000000ad80867a4eb26b8ad9d5050746fcd40
//   TLS1.2-only server:    29d29d00000000000029d29d29d29d0e0678690791de4eef3e3181f3af256e
// (Those exact hashes depend on the host's Node/OpenSSL build, so the hermetic tests
// below assert SELF-CONSISTENCY and difference-by-config, not the literal strings.)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { viewFindings, jarmProbes, readJarmResponse, jarmDigest, ctLogClass } from '../engine/selfview.mjs';
import { parseClientHello, isGrease } from '../engine/fingerprint.mjs';
import { DOH_LAB_CERT, DOH_LAB_KEY } from '../engine/doh-labcert.mjs';
import { scanSelf, report, runJarm } from '../tools/preflight.mjs';

const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const refs = (f) => f.map((x) => x.ref);
const find = (f, ref) => f.find((x) => x.ref === ref);

function listen(server) {
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));
}
function close(server) {
  return new Promise((r) => {
    const t = setTimeout(r, 2000);
    try { server.closeAllConnections && server.closeAllConnections(); } catch {}
    server.close(() => { clearTimeout(t); r(); });
  });
}

// The lab-cert observation fixture: exactly what analyzeTls reports for our own DoH lab
// cert (CN=varvel-doh-lab.local). PV-CERT-CN-LEAK firing on it is the point of the rule.
const LAB_CERT_OBS = { selfSigned: true, cn: 'varvel-doh-lab.local', san: 'DNS:varvel-doh-lab.local', issuer: 'varvel-doh-lab.local', validTo: 'Aug  1 23:20:13 2036 GMT' };

// ---------- classifier ----------
test('classifier: the lab-cert CN fixture fires PV-CERT-CN-LEAK + PV-CERT-SELFSIGNED, no PV-CTLOG', () => {
  const f = viewFindings({ tls: [{ port: 4453, ja4s: 'x', cert: LAB_CERT_OBS, tlsFindings: [] }], http: [], egress: null, ctLog: 'not-indexed' });
  const leak = find(f, 'PV-CERT-CN-LEAK');
  assert.ok(leak, 'CN=varvel-doh-lab.local MUST leak the toolset');
  assert.equal(leak.sev, 'high');
  assert.match(leak.title, /varvel/);
  assert.match(leak.title, /:4453/);
  assert.equal(find(f, 'PV-CERT-SELFSIGNED').sev, 'med');
  assert.equal(find(f, 'PV-CTLOG'), undefined, 'self-signed -> not indexed -> no CT finding');
  // severity-ordered: high before med before info
  const rank = { crit: 0, high: 1, med: 2, low: 3, info: 4 };
  for (let i = 1; i < f.length; i++) assert.ok(rank[f[i - 1].sev] <= rank[f[i].sev], 'severity ordered');
});

test('classifier: a public-CA issuer fires PV-CTLOG; an unclassified issuer stays honest', () => {
  const pub = viewFindings({ tls: [{ port: 443, ja4s: 'x', cert: { selfSigned: false, cn: 'example.com', san: 'DNS:example.com', issuer: "Let's Encrypt R3", validTo: 'x' }, tlsFindings: [] }], http: [], egress: null, ctLog: 'likely-indexed' });
  assert.deepEqual(refs(pub), ['PV-CTLOG'], 'only the CT finding on a standard port with a clean cert');
  assert.match(find(pub, 'PV-CTLOG').title, /Let's Encrypt/);
  const priv = viewFindings({ tls: [{ port: 443, ja4s: 'x', cert: { selfSigned: false, cn: 'example.com', san: '', issuer: 'Example Internal CA', validTo: 'x' }, tlsFindings: [] }], http: [], egress: null, ctLog: 'unknown' });
  assert.equal(find(priv, 'PV-CTLOG'), undefined, 'unknown indexing is never claimed');
});

test('classifier: a banner or body marker naming the toolset fires PV-BANNER-TOOL (high)', () => {
  const byHeader = viewFindings({ tls: [], http: [{ port: 8971, status: 200, serverHeader: 'VARVEL', headers: ['server'], bodyMarkers: [] }], egress: null, ctLog: 'unknown' });
  assert.equal(find(byHeader, 'PV-BANNER-TOOL').sev, 'high');
  const byBody = viewFindings({ tls: [], http: [{ port: 8971, status: 200, serverHeader: null, headers: [], bodyMarkers: ['enclave'] }], egress: null, ctLog: 'unknown' });
  assert.ok(find(byBody, 'PV-BANNER-TOOL'), 'body markers alone fire it');
  const clean = viewFindings({ tls: [], http: [{ port: 80, status: 200, serverHeader: 'nginx', headers: ['server'], bodyMarkers: [] }], egress: null, ctLog: 'unknown' });
  assert.equal(find(clean, 'PV-BANNER-TOOL'), undefined);
});

test('classifier: clean observations produce info-only findings, and the egress note is always paired', () => {
  const f = viewFindings({
    tls: [{ port: 443, ja4s: 't13d1512h2_1301_abcdef012345', cert: { selfSigned: false, cn: 'cdn.example.com', san: 'DNS:cdn.example.com', issuer: 'DigiCert TLS RSA SHA256 2020 CA1', validTo: 'x' }, tlsFindings: [] }],
    http: [{ port: 80, status: 200, serverHeader: 'nginx', headers: ['server', 'date'], bodyMarkers: [] }],
    egress: { ip: '203.0.113.7', org: 'AS64500 Example ISP', asn: 'AS64500' },
    ctLog: 'unknown',
  });
  assert.ok(f.length >= 1, 'the egress observation still reports');
  for (const x of f) assert.equal(x.sev, 'info', 'clean obs -> info only, got ' + x.ref);
  const eg = find(f, 'PV-EGRESS-CLASS');
  assert.match(eg.title, /203\.0\.113\.7/);
  assert.match(eg.title, /AS64500 Example ISP/);
  assert.match(eg.title, /paid proxy\/VPN classification feeds are NOT covered/);
});

test('classifier: dedupe across ports (one finding per ref, all ports in evidence)', () => {
  const f = viewFindings({
    tls: [
      { port: 4453, ja4s: 'x', cert: LAB_CERT_OBS, tlsFindings: [] },
      { port: 8443, ja4s: 'y', cert: LAB_CERT_OBS, tlsFindings: [] },
    ],
    http: [], egress: null, ctLog: 'not-indexed',
  });
  assert.equal(f.filter((x) => x.ref === 'PV-CERT-SELFSIGNED').length, 1);
  assert.equal(f.filter((x) => x.ref === 'PV-CERT-CN-LEAK').length, 1);
  assert.match(find(f, 'PV-CERT-SELFSIGNED').title, /:4453/);
  assert.match(find(f, 'PV-CERT-SELFSIGNED').title, /:8443/);
});

test('classifier: the JA4S Node shape fires PV-JA4S-STACK; a fuller extension set does not', () => {
  const nodeShape = viewFindings({ tls: [{ port: 443, ja4s: 't130200_1302_a56c5b993250', cert: { selfSigned: false, cn: 'a.b', san: '', issuer: 'X', validTo: 'x' }, tlsFindings: [] }], http: [], egress: null, ctLog: 'unknown' });
  assert.ok(find(nodeShape, 'PV-JA4S-STACK'));
  const stockShape = viewFindings({ tls: [{ port: 443, ja4s: 't13d1512h2_1301_abcdef012345', cert: { selfSigned: false, cn: 'a.b', san: '', issuer: 'X', validTo: 'x' }, tlsFindings: [] }], http: [], egress: null, ctLog: 'unknown' });
  assert.equal(find(stockShape, 'PV-JA4S-STACK'), undefined, '21 extensions is a configured-server shape');
});

test('classifier: TCP-open-but-silent ports still feed PV-PORT-OPEN (a SYN scan sees them)', () => {
  const f = viewFindings({ tls: [], http: [], egress: null, ctLog: 'unknown', openPorts: [4453, 49561] });
  assert.ok(find(f, 'PV-PORT-OPEN'), 'open-but-silent ports are still scan-visible exposure');
  assert.match(find(f, 'PV-PORT-OPEN').title, /:4453/);
  assert.match(find(f, 'PV-PORT-OPEN').title, /:49561/);
});

test('ctLogClass: self-signed -> not-indexed; public CA -> likely-indexed; else unknown', () => {
  assert.equal(ctLogClass({ selfSigned: true, issuer: 'anything' }), 'not-indexed');
  assert.equal(ctLogClass({ selfSigned: false, issuer: "Let's Encrypt R3" }), 'likely-indexed');
  assert.equal(ctLogClass({ selfSigned: false, issuer: 'CN=Example Internal CA' }), 'unknown');
  assert.equal(ctLogClass(null), 'unknown');
});

// ---------- JARM: probe shape ----------
test('jarmProbes: the 10 crafted hellos parse as real ClientHellos with the spec shape', () => {
  const probes = jarmProbes('example.test');
  assert.equal(probes.length, 10);
  const parsed = probes.map((p) => parseClientHello(p.packet));
  assert.ok(parsed.every(Boolean), 'every probe parses via engine/fingerprint parseClientHello');
  // tls1.2-forward: legacy+supported versions top out at 1.2, 69 ciphers, SNI carried
  assert.equal(parsed[0].version, 0x0303);
  assert.equal(parsed[0].ciphers.length, 69);
  assert.equal(parsed[0].sni, 'example.test');
  // tls1.3-forward: supported_versions reaches 1.3
  assert.equal(parsed[6].version, 0x0304);
  // tls1.1-middle-out: no supported_versions ext, legacy 1.1
  assert.equal(parsed[5].version, 0x0302);
  assert.ok(!parsed[5].extensions.includes(0x002b));
  // tls1.3-invalid: the NO1.3 list carries no TLS1.3 suites
  assert.equal(parsed[8].ciphers.length, 64);
  assert.ok(!parsed[8].ciphers.some((c) => c >= 0x1301 && c <= 0x1305));
  // tls1.2-middle-out: GREASE rides cipher position 0 (69+1)
  assert.equal(parsed[4].ciphers.length, 70);
  assert.ok(isGrease(parsed[4].ciphers[0]));
  // top-half keeps the middle cipher first, then the reversed top half (35 total)
  assert.equal(parsed[2].ciphers.length, 35);
  assert.equal(parsed[2].ciphers[0], 0xc012);
  // ALPN order follows the extension munge: probe 1 REVERSE ('hq' first), probe 2 FORWARD ('http/0.9' first)
  assert.equal(parsed[0].alpn[0], 'hq');
  assert.equal(parsed[1].alpn[0], 'http/0.9');
  assert.equal(jarmProbes('').length, 0, 'no host -> no probes (fail-closed)');
});

// ---------- JARM: digest construction ----------
test('jarmDigest: all-empty is 62 zeros; construction pins the fuzzy table + the None quirk', () => {
  assert.equal(jarmDigest(Array(10).fill('|||')), '0'.repeat(62));
  // c02f is index 41 (0x29) in the fuzzy table; version 0303 -> 'd'
  const d = jarmDigest(['c02f|0303|h2|0010-002b', ...Array(9).fill('|||')]);
  assert.equal(d.length, 62);
  assert.equal(d.slice(0, 30), '29d' + '000'.repeat(9));
  assert.equal(d.slice(30), sha256('h20010-002b').slice(0, 32));
  // the reference's str(None) quirk: an absent ALPN hashes as the literal text 'None'
  const n = jarmDigest(['1302|0303|None|002b-0033', ...Array(9).fill('|||')]);
  assert.equal(n.slice(0, 3), '42d'); // 1302 is index 66 (0x42)
  assert.equal(n.slice(30), sha256('None002b-0033').slice(0, 32));
  // short input pads with empty outcomes; version 0304 -> 'e'
  const v = jarmDigest(['1301|0304|h2|0010']);
  assert.equal(v.slice(0, 3), '41e'); // 1301 is index 65 (0x41)
});

test('readJarmResponse: null, garbage, alerts, and plaintext all resolve to the empty outcome', () => {
  assert.equal(readJarmResponse(null), '|||');
  assert.equal(readJarmResponse(Buffer.from('GARBAGE-BYTES')), '|||');
  assert.equal(readJarmResponse(Buffer.from([21, 3, 3, 0, 2, 2, 40])), '|||'); // alert
  assert.equal(readJarmResponse(Buffer.from('HTTP/1.1 200 OK\r\n\r\n')), '|||');
});

// ---------- JARM: live self-consistency (cross-validated per the header note) ----------
test('JARM live: the same server fingerprints identically twice; different TLS opts differ', async () => {
  const srv = https.createServer({ key: DOH_LAB_KEY, cert: DOH_LAB_CERT }, (q, s) => s.end('{}'));
  const port = await listen(srv);
  const a = await runJarm('127.0.0.1', port);
  const b = await runJarm('127.0.0.1', port);
  assert.equal(a.ok, true);
  assert.match(a.hash, /^[0-9a-f]{62}$/);
  assert.notEqual(a.hash, '0'.repeat(62), 'a live TLS server answers some crafted hellos');
  assert.ok(a.answered > 0);
  assert.equal(a.hash, b.hash, 'identical server -> identical 62-char hash, run over run');

  const srv12 = https.createServer({ key: DOH_LAB_KEY, cert: DOH_LAB_CERT, maxVersion: 'TLSv1.2' }, (q, s) => s.end('{}'));
  const port12 = await listen(srv12);
  const c = await runJarm('127.0.0.1', port12);
  assert.equal(c.ok, true);
  assert.notEqual(c.hash, a.hash, 'a TLS1.2-only server is a different fingerprint than the 1.3-capable one');
  await close(srv);
  await close(srv12);
});

// ---------- preflight live paths: never throw ----------
test('scanSelf: dead ports, garbage talkers, and bad input never throw -- gaps are reported', async () => {
  const dead = await scanSelf({ host: '127.0.0.1', ports: [1], timeout: 800 });
  assert.equal(dead.ok, true);
  assert.equal(dead.tls.length, 0);
  assert.equal(dead.http.length, 0);
  assert.ok(dead.gaps.some((g) => /port 1: no response -- closed or filtered/.test(g)), 'the dead port is honestly closed/filtered');
  assert.equal(dead.openPorts.length, 0, 'a refused port is NOT scan-visible as open');

  const garbageSrv = net.createServer((s) => { s.on('error', () => {}); s.end('GARBAGE-BYTES-NOT-TLS-NOT-HTTP'); });
  const gport = await listen(garbageSrv);
  const g = await scanSelf({ host: '127.0.0.1', ports: [gport], timeout: 800 });
  assert.equal(g.ok, true);
  assert.equal(g.tls.length, 0);
  assert.equal(g.http.length, 0);
  assert.ok(g.openPorts.includes(gport), 'a garbage talker is still TCP-open -- a SYN scan sees it');
  assert.ok(g.gaps.some((x) => x.includes('port ' + gport + ': TCP-open but answered neither TLS nor HTTP')), 'honest gap, not a crash');
  const gj = await runJarm('127.0.0.1', gport, { timeout: 800 });
  assert.equal(gj.ok, true);
  assert.equal(gj.hash, '0'.repeat(62), 'garbage answers no crafted hello');
  await close(garbageSrv);

  const bad = await scanSelf({});
  assert.equal(bad.ok, false);
  const badRep = await report({ host: '127.0.0.1', ports: [] });
  assert.equal(badRep.ok, false);
});

test('report: full pipeline over in-test TLS + HTTP listeners -- findings, jarm map, honestGaps', async () => {
  const tlsSrv = https.createServer({ key: DOH_LAB_KEY, cert: DOH_LAB_CERT }, (q, s) => s.end('{}'));
  const tport = await listen(tlsSrv);
  const httpSrv = http.createServer((q, s) => { s.setHeader('content-type', 'text/html'); s.end('<title>VARVEL test page</title>'); });
  const hport = await listen(httpSrv);
  const rep = await report({ host: '127.0.0.1', ports: [tport, hport, 1], timeout: 1500 });
  assert.equal(rep.ok, true);
  const fr = refs(rep.findings);
  // the lab cert on the wire MUST leak: CN=varvel-doh-lab.local + self-signed + Node shape
  assert.ok(fr.includes('PV-CERT-CN-LEAK'), 'live lab cert leaks the toolset: ' + fr);
  assert.ok(fr.includes('PV-CERT-SELFSIGNED'));
  assert.ok(fr.includes('PV-JA4S-STACK'));
  assert.ok(fr.includes('PV-BANNER-TOOL'), 'the test page names the toolset');
  assert.ok(fr.includes('PV-PORT-OPEN'), 'ephemeral test ports are non-standard');
  assert.match(rep.jarm[tport], /^[0-9a-f]{62}$/);
  assert.equal(rep.observations.tls[0].cert.cn, 'varvel-doh-lab.local');
  assert.equal(rep.observations.ctLog, 'not-indexed', 'self-signed lab cert is not CT-indexed');
  assert.ok(rep.honestGaps.some((g) => /port 1:/.test(g)));
  assert.ok(rep.honestGaps.some((g) => /paid proxy\/VPN classification feeds are NOT covered/.test(g)));
  assert.ok(rep.honestGaps.some((g) => /crt\.sh was NOT queried/.test(g)));
  await close(tlsSrv);
  await close(httpSrv);
});

// ---------- the route ----------
test('GET /api/preflight: findings array + reportHash over a real spawned server', async () => {
  const serverFile = join(dirname(fileURLToPath(import.meta.url)), '..', 'server.mjs');
  const port = 39211;
  const proc = spawn(process.execPath, [serverFile], {
    env: { ...process.env, VARVEL_PORT: String(port), VARVEL_DEMO_PORT: '39212', VARVEL_HARD_PORT: '39213' },
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  try {
    await new Promise((resolve, reject) => {
      const to = setTimeout(() => reject(new Error('server.mjs did not report listening within 25s')), 25000);
      let buf = '';
      proc.stdout.on('data', (d) => {
        buf += d;
        if (buf.includes('VARVEL service on')) { clearTimeout(to); resolve(); }
      });
      proc.on('exit', () => reject(new Error('server.mjs exited before listening: ' + buf.slice(0, 200))));
    });
    const r = await fetch(`http://127.0.0.1:${port}/api/preflight`);
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.equal(body.ok, true);
    assert.ok(Array.isArray(body.findings), 'findings array present');
    assert.match(body.reportHash, /^[0-9a-f]{64}$/, 'the audit binding rides a sha256 of the report JSON');
    assert.ok(refs(body.findings).includes('PV-BANNER-TOOL'), 'the live console HTML names the toolset -- honestly reported');
    assert.ok(refs(body.findings).includes('PV-PORT-OPEN'));
    assert.ok(Array.isArray(body.honestGaps) && body.honestGaps.length >= 2, 'the standing caveats are always present');
    assert.ok(body.observations.http.some((h) => h.port === port && h.status === 200), 'the API port was observed over HTTP');
  } finally { proc.kill(); }
});

// Teardown grace: on win32, --test-force-exit can fire while sockets are still closing
// (libuv UV_HANDLE_CLOSING assert). Same guard as agentsig/transportfail/dnstransport.
test('teardown grace for socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});
