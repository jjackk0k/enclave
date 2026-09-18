// ghost.test.mjs — hermetic tests for engine/ghost.mjs (Ghost Mode).
// All proxies/echoes are local mocks; nothing leaves the loopback interface.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { parseChain, isPrivateDest, openTunnel, scrubHeaders, Ghost, probeSocks5, detectTor, resolveGhostChain } from '../engine/ghost.mjs';

const KEY = `-----BEGIN PRIVATE KEY-----
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQCf0YT5WQPSqj8I
I1Me+t+DwUAbf+alsXscLayZ7chzu+RpYAMjEXScJx7oLQvQQewrVXLs0aoLgkUx
gzlXfy4JoxuUR4AvFoYziUNk74ERYwkruu9/BUCTUOw8rKS7saHMCeoiAyfl9NHG
Un7FYkeDqTOxY4i1DYZAqO19p9pMbrAV2nXMCYl0hbA6iI/Z1qAYIGzSHqhUd96A
ncm8NvLtl10Nx1f7AvAgQbwh62349A69pFPak7iOn0ZuTs03q4f8RlXSzCb5d/Df
v4ZQdvzxc/ciZuuMwoJx1c43fH7MVNsFGBFjd+3WNs7a6/7neMOIER+OXd7u4irL
IgGFeKsVAgMBAAECggEAE573gl1pWL3KC0e69ry6IETjh/zF5mXJxYXeAO/ugjb5
Le65s956wIkVBFAzeRf+1Lsi5uw+wjb2I8QGkDVvA4Pg6O12UVGknEMn4QZ+hBHy
mEnVCXUtnmh6+GABwYFnadN1yUM17MeH0Z9jLPyJ5yIo1Ihxyjik2N9keN7YsDVc
/JB64AOHzo2Wah6w+LjB83gAN7JM/OHeh+qtiizlY5muVKLv5LMrEa2ANQ37PjIZ
qFSi0zk5eenlEJIWURPEfF/LzkTDm1GeNosCS1c2tBV/dqbqKaW+KoGT7g8DXE8t
w8MLd2wrTWvlx3ogOzWS0a3+570kZENJ0xFbfWvVKQKBgQDQc05RruLrwxwc7QPG
yU/M1fE5AnA6atKd06b2w159QNTW/wMttqOG9GYZ4krNWLrUfvIdv294X2Cgt3xi
RiwmXiDp/mFcJj5B9HS+iplxt8xq83L56ZEyLr9h/7E7mFImwIL5DPUBEdp5jXTV
cS1mQ1awMv0Di1If3/DzjU58AwKBgQDERkuBtDSOvIEGjbC4yvuzHbk8F+O7ossi
M6ObpZkoV/cWbvDRw3rYL5gfJQW7iZc4Qi/JziSL78IFRxuBTjW0+VMrHJ+tGvcz
ViiVC5/A9GoHHqaJ9apZ/XrjGRekVJL12EBb5wk7v/7RBvY/oL6a04+XM0mQEKhZ
HRtWbIJtBwKBgQCrL5aJFGO9FH1479ijHt5PLP+uPudlwiZ3gMLkciueF2jzq3ez
ygLfqMRUy3d8zjqYmixB694ib8mOE0Gt/0zwsWq8X7EbGTkVtylM9cvwDO5ugsHQ
pVUdbjCzzWWCuKP2uTCWUWK/3yaZnmbthsWu7uw5RZZtm7P1A1cA3PIwewJ/PJF0
u5HgpiuFpYAUCPKauatyfhjhLgYOqX9F/cIcgVaj6UhTCGhKgGwvhWznV/gdsj66
gIwcuxJBzV8kHcMEz9Qg1iz/GWw43J6550SvB9xk282Zlvk4mIygX3Re11dCApu5
QKMLNmUJPXfohboVF7IxnXc2PD7ntJhG12Sk2wKBgGElUongjcHF+s3xogqQg+km
k38JL5ZMranaCmF+0he2x2wCcRO7XSxuQxDJmB6m13swOZVdOplFp9EijfabUyoe
fIAX1CKvg6L4V7YclHlyPUdKjgR61vWk/l1WUVwF9qQySxCtmD5bhGj3R7nOeY/q
5xZuEy2I3nWFJEznEd6w
-----END PRIVATE KEY-----`;
const CERT = `-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIUEVzWn1EwcnfZke7EBG3LGanhnvAwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQZ2hvc3QtdGVzdC5sb2NhbDAeFw0yNjA4MDMyMzI1Mjla
Fw0zNjA3MzEyMzI1MjlaMBsxGTAXBgNVBAMMEGdob3N0LXRlc3QubG9jYWwwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCf0YT5WQPSqj8II1Me+t+DwUAb
f+alsXscLayZ7chzu+RpYAMjEXScJx7oLQvQQewrVXLs0aoLgkUxgzlXfy4JoxuU
R4AvFoYziUNk74ERYwkruu9/BUCTUOw8rKS7saHMCeoiAyfl9NHGUn7FYkeDqTOx
Y4i1DYZAqO19p9pMbrAV2nXMCYl0hbA6iI/Z1qAYIGzSHqhUd96Ancm8NvLtl10N
x1f7AvAgQbwh62349A69pFPak7iOn0ZuTs03q4f8RlXSzCb5d/Dfv4ZQdvzxc/ci
ZuuMwoJx1c43fH7MVNsFGBFjd+3WNs7a6/7neMOIER+OXd7u4irLIgGFeKsVAgMB
AAGjUzBRMB0GA1UdDgQWBBTCwv2Qz4g3QdOv1ZlsbJeGHK8VNTAfBgNVHSMEGDAW
gBTCwv2Qz4g3QdOv1ZlsbJeGHK8VNTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQAorSibpD2Cif2YDNz1bRKdDmWVRyGUN3g7cpELvYH07j8AwcRb
YGapB0Jh/WQie9NzdUYKfP4Fd961fQ0MGpcxliLH+gnyXiRuXevVFdLgvIFG5xvq
i63O6+DTMkdZ90SZ/Zdufz8pte3C60a3hjhP9DqsJElYyMtw1UZ/mmPizfUBvpeM
/QBhCkxFSlo1lmYFFqvqOb8UuYdLWJ0f9JDvwDGYfpSSGV5TbyvyigWwuK75BLCy
P/fbD6R5yfzbOIDkaNcywKcAGPRWGwtDAXO82YbU48T9wtbe4EZ6K4fsj6K03LcE
cb2MelRQeixRMCHCuGUWbLvB2UEaDAHTs7yk
-----END CERTIFICATE-----`;

// ---------- mocks ----------
function listen(server) {
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));
}
// server.close() waits for keep-alive agent sockets forever — force them down first.
function close(server) {
  return new Promise((r) => {
    const t = setTimeout(r, 2000);
    try { server.closeAllConnections && server.closeAllConnections(); } catch {}
    server.close(() => { clearTimeout(t); r(); });
  });
}

// HTTP proxy mock: answers absolute-URI requests itself; CONNECTs tunnels for 'CONNECT'.
function mockHttpProxy({ onRequest, onConnect } = {}) {
  const srv = net.createServer((sock) => {
    let head = '';
    sock.on('data', function onData(d) {
      head += d.toString('latin1');
      const end = head.indexOf('\r\n\r\n');
      if (end < 0) return;
      const first = head.split('\r\n')[0];
      const m = /^CONNECT ([^ ]+) HTTP/.exec(first);
      if (m) {
        sock.off('data', onData);
        const [host, port] = m[1].split(':');
        if (onConnect) onConnect(host, Number(port));
        const up = net.connect({ host: '127.0.0.1', port: Number(m[1].split(':')[1]) }, () => {
          sock.write('HTTP/1.1 200 OK\r\n\r\n');
          sock.pipe(up); up.pipe(sock);
        });
        up.on('error', () => sock.destroy());
      } else {
        if (onRequest) onRequest(first, head);
        sock.end('HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nx-mock: proxied\r\n\r\n{"ip":"203.0.113.7"}');
      }
    });
  });
  return srv;
}

function mockSocks5({ onConnect } = {}) {
  return net.createServer((sock) => {
    let stage = 0, buf = Buffer.alloc(0);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 2 + buf[1]) {
        sock.write(Buffer.from([0x05, 0x00])); stage = 1; buf = Buffer.alloc(0);
      } else if (stage === 1 && buf.length >= 5) {
        const hlen = buf[4];
        const host = buf.subarray(5, 5 + hlen).toString();
        const port = buf.readUInt16BE(5 + hlen);
        if (onConnect) onConnect(host, port);
        const up = net.connect({ host: '127.0.0.1', port }, () => {
          sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          sock.pipe(up); up.pipe(sock);
        });
        up.on('error', () => sock.destroy());
        stage = 2;
      }
    });
  });
}

function httpGet(url, agent) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request({ hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname, agent, rejectUnauthorized: false, timeout: 8000 }, (res) => {
      let b = '';
      res.on('data', (d) => (b += d));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.end();
  });
}

// ---------- tests ----------
test('parseChain: http/socks5/auth/defaults + rejects bad input', () => {
  const c = parseChain('http://user:pw@proxy1.local:8080, socks5://proxy2.local');
  assert.equal(c.length, 2);
  assert.deepEqual(c[0], { scheme: 'http', host: 'proxy1.local', port: 8080, user: 'user', pass: 'pw' });
  assert.deepEqual(c[1], { scheme: 'socks5', host: 'proxy2.local', port: 1080, user: '', pass: '' });
  assert.deepEqual(parseChain(''), []);
  assert.throws(() => parseChain('ftp://x:21'), /scheme/);
  assert.throws(() => parseChain('not-a-url'), /not a URL/);
});

test('isPrivateDest: RFC1918/loopback/link-local + v6 ULA/link-local private; public names public', () => {
  for (const h of ['10.0.0.5', '192.168.50.130', '127.0.0.1', '172.16.0.9', '172.31.255.1', '169.254.1.1', 'localhost', '::1', 'printer.local',
    'fd00::1', 'fc00::9', 'fe80::1', '[fd00::1]', '::ffff:192.168.1.5']) assert.equal(isPrivateDest(h), true, h);
  for (const h of ['8.8.8.8', '172.32.0.1', 'example.com', '203.0.113.7', '2001:4860:4860::8888', '2001:db8::1']) assert.equal(isPrivateDest(h), false, h);
});

test('http egress rides the proxy as absolute-URI with NO local DNS of the target', async () => {
  let seen = null;
  const proxy = mockHttpProxy({ onRequest: (first) => { seen = first; } });
  const pport = await listen(proxy);
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: `http://127.0.0.1:${pport}` });
  // 'ghost-echo.test' cannot resolve anywhere — if a local DNS lookup were attempted, this fails.
  const res = await httpGet('http://ghost-echo.test/', ghost.agents().httpAgent);
  assert.equal(res.status, 200);
  assert.match(seen, /^GET http:\/\/ghost-echo\.test\/ HTTP/); // absolute-form: the PROXY resolves it
  assert.equal(JSON.parse(res.body).ip, '203.0.113.7');
  await close(proxy);
});

test('https egress: CONNECT tunnel carries the hostname (remote DNS), TLS works end-to-end', async () => {
  let connectedTo = null;
  const proxy = mockHttpProxy({ onConnect: (host, port) => { connectedTo = { host, port }; } });
  const pport = await listen(proxy);
  const echo = https.createServer({ key: KEY, cert: CERT }, (req, res) => { res.setHeader('content-type', 'application/json'); res.end('{"ok":true}'); });
  const eport = await listen(echo);
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: `http://127.0.0.1:${pport}` });
  // The mock tunnels any CONNECT port to 127.0.0.1:<same port> — run the echo on that port shape.
  const res = await httpGet(`https://ghost-secure.test:${eport}/`, ghost.agents().httpsAgent);
  assert.equal(res.status, 200);
  assert.deepEqual(connectedTo, { host: 'ghost-secure.test', port: eport }); // proxy got the NAME, not an IP
  await close(echo); await close(proxy);
});

test('two-hop chain: proxy1 receives CONNECT to proxy2, proxy2 receives CONNECT to target', async () => {
  const seen1 = [], seen2 = [];
  const p1 = mockHttpProxy({ onConnect: (h, p) => seen1.push(`${h}:${p}`) });
  const p2 = mockHttpProxy({ onConnect: (h, p) => seen2.push(`${h}:${p}`) });
  const p1port = await listen(p1);
  const echo = https.createServer({ key: KEY, cert: CERT }, (req, res) => res.end('{}'));
  const eport = await listen(echo);
  // chain: p1 -> p2 -> target. p2's address inside the tunnel is resolved via... p1 tunnels by
  // port to 127.0.0.1 — so name p2 as 127.0.0.1 with its real port.
  const p2port = await listen(p2);
  const chain = [{ scheme: 'http', host: '127.0.0.1', port: p1port, user: '', pass: '' }, { scheme: 'http', host: '127.0.0.1', port: p2port, user: '', pass: '' }];
  const sock = await openTunnel(chain, 'ghost-target.test', eport, 10000);
  sock.destroy();
  assert.deepEqual(seen1, [`127.0.0.1:${p2port}`]);
  assert.deepEqual(seen2, [`ghost-target.test:${eport}`]);
  await close(echo); await close(p1); await close(p2);
});

test('openTunnel: v6 literal targets are BRACKETED in the CONNECT authority form', async () => {
  let head = '';
  const proxy = net.createServer((sock) => {
    sock.on('data', (d) => {
      if (!head.includes('\r\n\r\n')) {
        head += d.toString('latin1');
        if (head.includes('\r\n\r\n')) sock.write('HTTP/1.1 200 OK\r\n\r\n');
      }
    });
  });
  const pport = await listen(proxy);
  const s = await openTunnel([{ scheme: 'http', host: '127.0.0.1', port: pport, user: '', pass: '' }], '2001:db8::9', 443);
  s.destroy();
  assert.ok(head.startsWith('CONNECT [2001:db8::9]:443 HTTP/1.1\r\nHost: [2001:db8::9]:443\r\n'),
    'a bare "CONNECT 2001:db8::9:443" is unparseable to a conforming proxy — got ' + JSON.stringify(head.slice(0, 60)));
  await close(proxy);
});

test('openTunnel: socks5 carries a v6 literal as ATYP 0x04 raw bytes (never as a resolvable NAME)', async () => {
  let req = null, stage = 0, buf = Buffer.alloc(0);
  const proxy = net.createServer((sock) => {
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 2 + buf[1]) { sock.write(Buffer.from([0x05, 0x00])); stage = 1; buf = Buffer.alloc(0); }
      else if (stage === 1 && buf.length >= 22) { req = buf.subarray(0, 22); stage = 2; sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); }
    });
  });
  const pport = await listen(proxy);
  const s = await openTunnel([{ scheme: 'socks5', host: '127.0.0.1', port: pport, user: '', pass: '' }], '2001:DB8::25', 80);
  s.destroy();
  assert.equal(req[3], 0x04, 'v6 literal on the wire as ATYP 0x04');
  assert.deepEqual([...req.subarray(4, 20)], [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x25], 'the 16 raw address bytes');
  assert.equal(req.readUInt16BE(20), 80);
  await close(proxy);
});

test('openTunnel: socks5 keeps the historical DOMAIN form for v4 literals (zero v4 wire change)', async () => {
  let req = null, stage = 0, buf = Buffer.alloc(0);
  const proxy = net.createServer((sock) => {
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 2 + buf[1]) { sock.write(Buffer.from([0x05, 0x00])); stage = 1; buf = Buffer.alloc(0); }
      else if (stage === 1 && buf.length >= 5 && buf.length >= 5 + buf[4] + 2) { req = buf; stage = 2; sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); }
    });
  });
  const pport = await listen(proxy);
  const s = await openTunnel([{ scheme: 'socks5', host: '127.0.0.1', port: pport, user: '', pass: '' }], '10.10.0.5', 445);
  s.destroy();
  assert.equal(req[3], 0x03, 'v4 literal still DOMAIN form');
  assert.equal(req.subarray(5, 5 + req[4]).toString(), '10.10.0.5');
  await close(proxy);
});

test('http egress to a v6 literal rides the proxy as a BRACKETED absolute-URI', async () => {
  let seen = null;
  const proxy = mockHttpProxy({ onRequest: (first) => { seen = first; } });
  const pport = await listen(proxy);
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: `http://127.0.0.1:${pport}` });
  const res = await httpGet('http://[2001:db8::9]/', ghost.agents().httpAgent);
  assert.equal(res.status, 200);
  assert.match(seen, /^GET http:\/\/\[2001:db8::9\]\/ HTTP/, 'a bare http://2001:db8::9/ is not a URL — got ' + seen);
  await close(proxy);
});

test('GUARANTEE: required mode classifies v6 destinations — public v6 refused unverified, ULA/link-local/::1 direct', async () => {
  const ghost = new Ghost();
  ghost.configure({ mode: 'required', chain: 'http://127.0.0.1:1' }); // dead hop
  await assert.rejects(() => ghost.assertEgress('http://[2001:db8::9]/'), (e) => e.ghostRefused === true && /REFUSED/.test(e.message));
  await assert.rejects(() => ghost.assertEgress('http://[2001:4860:4860::8888]/'), (e) => e.ghostRefused === true);
  await assert.rejects(() => ghost.assertEgress('2001:db8::9'), (e) => e.ghostRefused === true, 'bare v6 dest refused too');
  // private v6 destinations are always allowed direct (range traffic never leaves the lab)
  assert.equal(await ghost.assertEgress('http://[fd00::5]/'), true, 'ULA = the range');
  assert.equal(await ghost.assertEgress('http://[::1]:8080/'), true, 'v6 loopback');
  assert.equal(await ghost.assertEgress('fe80::1'), true, 'link-local');
  assert.equal(await ghost.assertEgress('http://[::ffff:192.168.1.5]/'), true, 'a MAPPED private v4 is private — the classic bypass reads as the lab, not as public');
});

test('socks5 egress: handshake + CONNECT carry the hostname (remote DNS)', async () => {
  let connectedTo = null;
  const proxy = mockSocks5({ onConnect: (h, p) => { connectedTo = { host: h, port: p }; } });
  const pport = await listen(proxy);
  const echo = https.createServer({ key: KEY, cert: CERT }, (req, res) => res.end('{"s":1}'));
  const eport = await listen(echo);
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: `socks5://127.0.0.1:${pport}` });
  const res = await httpGet(`https://ghost-socks.test:${eport}/`, ghost.agents().httpsAgent);
  assert.equal(res.status, 200);
  assert.deepEqual(connectedTo, { host: 'ghost-socks.test', port: eport });
  await close(echo); await close(proxy);
});

test('GUARANTEE: required mode refuses PUBLIC egress when unverified — and never touches a socket', async () => {
  const ghost = new Ghost();
  ghost.configure({ mode: 'required', chain: 'http://127.0.0.1:1' }); // dead hop
  await assert.rejects(() => ghost.assertEgress('https://example.com/'), (e) => e.ghostRefused === true && /REFUSED/.test(e.message));
  // private destinations are always allowed (range traffic never leaves the lab)
  assert.equal(await ghost.assertEgress('http://192.168.50.130/'), true);
  assert.equal(await ghost.assertEgress('http://10.0.0.4/'), true);
});

test('verify(): ok when exit IP differs from operator IP; fails honestly when identical', async () => {
  // Echo distinguishes direct (origin-form path) from proxied (absolute-form) requests.
  const echo = http.createServer((req, res) => {
    const viaProxy = /^https?:\/\//.test(req.url);
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ ip: viaProxy ? '203.0.113.7' : '198.51.100.3' }));
  });
  const eport = await listen(echo);
  let proxyHit = false;
  const proxy = mockHttpProxy({ onRequest: () => { proxyHit = true; } });
  const pport = await listen(proxy);

  const ghost = new Ghost();
  ghost.configure({ mode: 'required', chain: `http://127.0.0.1:${pport}`, checkUrl: `http://127.0.0.1:${eport}/` });
  const v = await ghost.verify();
  assert.equal(proxyHit, true);
  assert.equal(v.ok, true);
  assert.equal(v.exitIp, '203.0.113.7');
  assert.equal(ghost.verifiedOk(), true);
  assert.equal(await ghost.assertEgress('https://example.com/'), true); // gate opens after verification

  const ghost2 = new Ghost();
  ghost2.configure({ mode: 'on', chain: `http://127.0.0.1:${pport}`, checkUrl: `http://127.0.0.1:${eport}/same` });
  // force identical IPs: bypass the proxy difference by checking direct-vs-direct shape
  ghost2._ipOf = async (url, agents) => (agents ? '198.51.100.3' : '198.51.100.3');
  const v2 = await ghost2.verify();
  assert.equal(v2.ok, false);
  assert.match(v2.error, /NOT hidden/);
  await close(proxy); await close(echo);
});

test('verify(): chain death is reported, and required mode stays closed', async () => {
  const echo = http.createServer((req, res) => res.end('{"ip":"198.51.100.3"}'));
  const eport = await listen(echo);
  const ghost = new Ghost();
  ghost.configure({ mode: 'required', chain: 'http://127.0.0.1:1', checkUrl: `http://127.0.0.1:${eport}/` });
  const v = await ghost.verify();
  assert.equal(v.ok, false);
  assert.match(v.error, /did not reach/);
  await assert.rejects(() => ghost.assertEgress('https://example.com/'), (e) => e.ghostRefused === true);
  await close(echo);
});

test('scrubHeaders: strips tool markers, forces persona UA, keeps content headers', () => {
  const out = scrubHeaders({ 'user-agent': 'VARVEL-webscan', 'x-varvel-run': 'abc', 'x-powered-by': 'VARVEL', accept: 'text/html', 'content-type': 'application/json' });
  assert.equal(out['x-varvel-run'], undefined);
  assert.equal(out['x-powered-by'], undefined);
  assert.match(out['user-agent'], /^Mozilla\/5\.0/);
  assert.equal(out.accept, 'text/html');
  assert.equal(out['content-type'], 'application/json');
});

test('status(): never records proxy credentials, masks the operator baseline IP', () => {
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: 'http://user:secret@proxy.local:8080' });
  ghost._verified = { ok: true, baselineIp: '198.51.100.3', exitIp: '203.0.113.7', at: 'now' };
  const s = ghost.status();
  assert.deepEqual(s.chain, ['http://proxy.local:8080']);
  assert.equal(JSON.stringify(s).includes('secret'), false);
  assert.equal(s.verified.baselineIp, '198.51.x.x');
  assert.equal(s.verified.exitIp, '203.0.113.7');
});

test('private destinations DIAL DIRECT even when armed — the proxy sees nothing', async () => {
  let proxySaw = 0;
  const proxy = mockHttpProxy({ onRequest: () => proxySaw++, onConnect: () => proxySaw++ });
  const pport = await listen(proxy);
  const range = http.createServer((req, res) => res.end('range-ok'));
  const rport = await listen(range);
  const ghost = new Ghost();
  ghost.configure({ mode: 'required', chain: `http://127.0.0.1:${pport}` });
  const r = await httpGet(`http://127.0.0.1:${rport}/x`, ghost.agents().httpAgent);
  assert.equal(r.status, 200);
  assert.equal(r.body, 'range-ok', 'served by the lab, not the proxy');
  assert.equal(proxySaw, 0, 'proxy never saw the private request');
  await close(range); await close(proxy);
});

test('https agent: private destination is direct TLS (proxy sees nothing)', async () => {
  let proxySaw = 0;
  const proxy = mockHttpProxy({ onConnect: () => proxySaw++ });
  const pport = await listen(proxy);
  const tlsSrv = https.createServer({ key: KEY, cert: CERT }, (req, res) => res.end('tls-range-ok'));
  const tport = await listen(tlsSrv);
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: `http://127.0.0.1:${pport}` });
  const r = await httpGet(`https://127.0.0.1:${tport}/`, ghost.agents().httpsAgent);
  assert.equal(r.status, 200);
  assert.equal(r.body, 'tls-range-ok');
  assert.equal(proxySaw, 0, 'proxy never saw the private TLS request');
  await close(tlsSrv); await close(proxy);
});

test('connect(): private dials direct; public rides the chain', async () => {
  const saw = [];
  const proxy = mockHttpProxy({ onConnect: (h, p) => saw.push(`${h}:${p}`) });
  const pport = await listen(proxy);
  const echo = net.createServer((s) => s.end('ok'));
  const eport = await listen(echo);
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: `http://127.0.0.1:${pport}` });
  const direct = await ghost.connect({ host: '127.0.0.1', port: eport });
  direct.destroy();
  assert.deepEqual(saw, [], 'proxy untouched by private connect');
  const tunneled = await ghost.connect({ host: 'example.com', port: eport });
  tunneled.destroy();
  assert.deepEqual(saw, [`example.com:${eport}`], 'public host CONNECTed through the chain');
  await close(echo); await close(proxy);
});

// ---------- Tor auto-detect (the free chain) ----------
function mockSocks5Greet({ refuse = false, garbage = false } = {}) {
  return net.createServer((s) => {
    s.on('data', () => {
      if (garbage) { s.end('not-a-socks-reply'); return; }
      s.end(Buffer.from([0x05, refuse ? 0xff : 0x00]));
    });
    s.on('error', () => {});
  });
}

test('detectTor: SOCKS5 greeting answered -> ok with the answering port + chain', async () => {
  const srv = mockSocks5Greet();
  const port = await listen(srv);
  const t = await detectTor({ ports: [port] });
  assert.equal(t.ok, true);
  assert.equal(t.port, port);
  assert.equal(t.chain, `socks5://127.0.0.1:${port}`);
  await close(srv);
});

test('detectTor: nothing listening / garbage answer -> ok:false, never throws', async () => {
  const dead = await detectTor({ ports: [1], timeout: 400 }); // port 1: refused
  assert.equal(dead.ok, false);
  const garbageSrv = mockSocks5Greet({ garbage: true });
  const gport = await listen(garbageSrv);
  const g = await detectTor({ ports: [gport], timeout: 400 });
  assert.equal(g.ok, false);
  const refuseSrv = mockSocks5Greet({ refuse: true });
  const rport = await listen(refuseSrv);
  const r = await detectTor({ ports: [rport], timeout: 400 });
  assert.equal(r.ok, false);
  await close(garbageSrv); await close(refuseSrv);
});

test('resolveGhostChain: configured chain wins and detection is never consulted', async () => {
  const r = await resolveGhostChain({ mode: 'on', chain: 'socks5://127.0.0.1:9050', detect: async () => { throw new Error('detect must not run'); } });
  assert.equal(r.source, 'configured');
  assert.equal(r.hops.length, 1);
  assert.equal(r.hops[0].port, 9050);
});

test('resolveGhostChain: empty chain falls back to detected Tor; off needs nothing', async () => {
  const r = await resolveGhostChain({ mode: 'required', chain: '', detect: async () => ({ ok: true, port: 9050, chain: 'socks5://127.0.0.1:9050' }) });
  assert.equal(r.source, 'tor');
  assert.equal(r.hops.length, 1);
  assert.equal(r.hops[0].scheme, 'socks5');
  const off = await resolveGhostChain({ mode: 'off', chain: '', detect: async () => { throw new Error('detect must not run'); } });
  assert.deepEqual(off, { hops: [], source: 'off' });
});

test('resolveGhostChain: empty chain and no Tor -> honest error naming the free path', async () => {
  await assert.rejects(
    () => resolveGhostChain({ mode: 'on', chain: ' ', detect: async () => ({ ok: false, reason: 'no listener' }) }),
    /no local Tor detected.*Free path: install Tor/,
  );
});

test('Ghost.refreshTor caches and status() carries the tor field', async () => {
  const ghost = new Ghost();
  const t1 = await ghost.refreshTor({ force: true });
  assert.equal(typeof t1.detected, 'boolean');
  assert.ok(ghost.status().tor, 'status exposes tor state');
  const t2 = await ghost.refreshTor(); // cached — same object identity
  assert.equal(t2, t1);
});

// ---------- national-adversary tier (2026-09-01): per-hop health, ghost shaper,
// rotation set, and the correlation-resistance self-report. All loopback mocks.
import { normalizeExitSet } from '../engine/egresscheck.mjs';

test('probeHops: a healthy socks5 hop answers its greeting — ok:true, latency recorded, status() carries it', async () => {
  const proxy = mockSocks5();
  const pport = await listen(proxy);
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: `socks5://127.0.0.1:${pport}` });
  const h = await ghost.probeHops({ force: true });
  assert.equal(h.ok, true);
  assert.equal(h.hops.length, 1);
  assert.equal(h.hops[0].hop, `socks5://127.0.0.1:${pport}`);
  assert.equal(h.hops[0].ok, true);
  assert.equal(typeof h.hops[0].latencyMs, 'number');
  assert.equal(ghost.status().hopHealth.ok, true, 'status() exposes the probe result');
  await close(proxy);
});

test('probeHops: hop 2 is probed THROUGH hop 1 (the path so far, not a direct dial)', async () => {
  const p1 = mockSocks5(); // tunnels by port to 127.0.0.1:<port> — the lab stand-in for a relay
  const p2 = mockSocks5();
  const p1port = await listen(p1);
  const p2port = await listen(p2);
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: `socks5://127.0.0.1:${p1port},socks5://127.0.0.1:${p2port}` });
  const h = await ghost.probeHops({ force: true });
  assert.equal(h.ok, true, 'both hops healthy through the chain');
  assert.equal(h.hops.length, 2);
  assert.equal(h.hops[1].ok, true, 'hop 2 answered its greeting THROUGH hop 1');
  await close(p1); await close(p2);
});

test('probeHops: a dead hop fails honestly and downstream hops are UNPROBED (ok:null), never guessed', async () => {
  const p2 = mockSocks5();
  const p2port = await listen(p2);
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: `socks5://127.0.0.1:1,socks5://127.0.0.1:${p2port}` }); // port 1 = refused
  const h = await ghost.probeHops({ force: true, timeout: 1500 });
  assert.equal(h.ok, false);
  assert.equal(h.hops[0].ok, false);
  assert.ok(h.hops[0].error, 'the failure is named');
  assert.equal(h.hops[1].ok, null, 'downstream of a dead hop is unmeasurable — marked, not probed direct');
  assert.match(h.hops[1].error, /unprobed/);
  await close(p2);
});

test('probeHops: cached 15s like refreshTor (status polls must not re-probe every render)', async () => {
  const proxy = mockSocks5();
  const pport = await listen(proxy);
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: `socks5://127.0.0.1:${pport}` });
  const h1 = await ghost.probeHops({ force: true });
  const h2 = await ghost.probeHops();
  assert.equal(h2, h1, 'cached — same object identity');
  await close(proxy);
});

test('shaper: configure accepts {minDelayMs,jitterMs,padTo}; status reports it; garbage is LOUD', () => {
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: 'http://127.0.0.1:1', shaper: { minDelayMs: 100, jitterMs: 50, padTo: 'mtu' } });
  assert.deepEqual(ghost.status().shaper, { minDelayMs: 100, jitterMs: 50, padTo: 'mtu' });
  assert.throws(() => ghost.setShaper({ minDelayMs: 1, padTo: 'constant-rate' }), /padTo/); // app layer cannot do constant-rate — refused, named
  assert.throws(() => ghost.setShaper({ minDelayMs: -5 }), /minDelayMs/);
  ghost.setShaper(null);
  assert.equal(ghost.status().shaper, null);
});

test('shaper: VARVEL_GHOST_SHAPER env is the operator channel; invalid JSON is LOUD, never silently dropped', () => {
  process.env.VARVEL_GHOST_SHAPER = '{"minDelayMs":250,"padTo":"mtu"}';
  try {
    const ghost = new Ghost();
    ghost.configure({ mode: 'on', chain: 'http://127.0.0.1:1' });
    assert.equal(ghost.shaper.minDelayMs, 250);
    assert.equal(ghost.shaper.padTo, 'mtu');
  } finally { delete process.env.VARVEL_GHOST_SHAPER; }
  process.env.VARVEL_GHOST_SHAPER = 'not-json';
  try {
    const ghost = new Ghost();
    assert.throws(() => ghost.configure({ mode: 'on', chain: 'http://127.0.0.1:1' }), /VARVEL_GHOST_SHAPER/);
  } finally { delete process.env.VARVEL_GHOST_SHAPER; }
});

test('normalizeExitSet: canonicalizes (v6 forms collapse), drops unparseable entries LOUDLY', () => {
  const r = normalizeExitSet('203.0.113.7, 2001:DB8::9, not-an-ip');
  assert.deepEqual(r.list, ['203.0.113.7', '2001:db8::9']);
  assert.deepEqual(r.dropped, ['not-an-ip']);
  assert.deepEqual(normalizeExitSet(null), { list: [], dropped: [] });
  assert.deepEqual(normalizeExitSet(['::ffff:203.0.113.7']).list, ['203.0.113.7'], 'mapped v4 collapses');
});

test('setExitSet: stores the canonical rotation set; all-garbage input refuses LOUDLY (an empty set matches nothing)', () => {
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: 'http://127.0.0.1:1' });
  ghost.setExitSet(['203.0.113.7', 'bogus']);
  assert.deepEqual(ghost.status().exitSet, ['203.0.113.7']);
  assert.deepEqual(ghost.status().exitSetDropped, ['bogus'], 'dropped entries stay visible');
  assert.throws(() => ghost.setExitSet(['bogus', 'also-bogus']), /no parseable IP/);
  ghost.setExitSet(null);
  assert.equal(ghost.status().exitSet, null);
});

test('substatus(): ghost OFF grades the chain FAIL — direct egress exposes the operator', () => {
  const ghost = new Ghost();
  const s = ghost.substatus();
  assert.equal(s.overall, 'fail');
  assert.equal(s.checks.find((c) => c.id === 'mode').grade, 'fail');
});

test('substatus(): armed single-hop unverified — honest WARN overall, UNVERIFIED where unmeasured, never asserted', () => {
  const ghost = new Ghost();
  ghost.configure({ mode: 'required', chain: 'http://127.0.0.1:1' }); // dead hop, never dialed here
  const s = ghost.substatus();
  assert.equal(s.overall, 'warn');
  const byId = Object.fromEntries(s.checks.map((c) => [c.id, c]));
  assert.equal(byId.mode.grade, 'pass', 'required = fail-closed posture');
  assert.equal(byId.verified.grade, 'unverified', 'never measured — said, not assumed');
  assert.equal(byId.hops.grade, 'warn');
  assert.match(byId.hops.detail, /single-hop/i);
  assert.equal(byId.dns.grade, 'pass', 'DNS-at-last-proxy is code-level, test-pinned');
  assert.equal(byId.exitClass.grade, 'unverified');
  assert.equal(byId.stability.grade, 'unverified');
  assert.equal(byId.tlsFingerprint.grade, 'unverified');
  assert.equal(byId.ipv6.grade, 'unverified');
  assert.equal(byId.shaping.grade, 'warn', 'no shaper armed');
  assert.equal(byId.coverTraffic.grade, 'warn', 'no app-layer cover traffic — admitted');
  assert.equal(byId.flowCorrelation.grade, 'warn');
  assert.match(byId.flowCorrelation.detail, /low/i);
});

test('substatus(): verified + pinned + set-matched + shaped grades those axes PASS; the baseline IP stays MASKED', () => {
  const ghost = new Ghost();
  ghost.configure({ mode: 'required', chain: 'http://127.0.0.1:1', shaper: { minDelayMs: 900, jitterMs: 400 } });
  ghost._verified = { ok: true, baselineIp: '198.51.100.3', exitIp: '203.0.113.7', at: 't' };
  ghost._lastExitCheck = {
    ok: true, verdict: 'stable', distinct: ['203.0.113.7'],
    expectExit: '203.0.113.7', pinMatch: true, expectExitSet: ['203.0.113.7', '198.51.100.9'], setMatch: true,
    egress: { ok: true, class: 'vpn', org: 'AS1234 Mullvad VPN AB', heuristic: true },
    warnings: [], at: 't',
  };
  const s = ghost.substatus();
  const byId = Object.fromEntries(s.checks.map((c) => [c.id, c]));
  assert.equal(byId.verified.grade, 'pass');
  assert.equal(byId.pin.grade, 'pass');
  assert.equal(byId.stability.grade, 'pass');
  assert.equal(byId.exitClass.grade, 'warn', 'a known-VPN ASN is attributable to the PROVIDER — said plainly');
  assert.equal(byId.shaping.grade, 'pass');
  assert.match(byId.shaping.detail, /constant-rate/i, 'the app-layer ceiling is stated even on PASS');
  assert.equal(JSON.stringify(s).includes('198.51.100.3'), false, 'operator baseline never leaks into the report');
  assert.ok(s.residual && s.residual.length > 40, 'a plain-language residual-risk statement rides along');
});
