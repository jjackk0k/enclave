// VARVEL recon tool tests — hermetic (own local servers), safe (localhost only).
//   node --test varvel/test/recon.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import { recon, scanHost, ipInScope, mmh3_32, identifyService } from '../tools/recon.mjs';

test('ipInScope: utility CIDR membership (NOT enforced by the tool)', () => {
  assert.equal(ipInScope('10.10.2.18', ['10.10.0.0/16']), true);
  assert.equal(ipInScope('10.11.2.18', ['10.10.0.0/16']), false);
  assert.equal(ipInScope('8.8.8.8', ['0.0.0.0/0']), true);
  assert.equal(ipInScope('192.168.1.5', ['192.168.1.0/24']), true);
  assert.equal(ipInScope('192.168.2.5', ['192.168.1.0/24']), false);
  assert.equal(ipInScope('fd00::5', ['fd00::/8']), true, 'v6 ring membership');
  assert.equal(ipInScope('fd00:0:0:1::5', ['fd00::/64']), false, 'v6 ring exclusion');
  assert.equal(ipInScope('10.0.0.5', ['::/0']), false, 'family-strict: all-v6 is not match-all');
});

test('mmh3_32: empty input is 0, deterministic, signed 32-bit', () => {
  assert.equal(mmh3_32(Buffer.from('')), 0, 'MurmurHash3 of empty (seed 0) is 0');
  assert.equal(mmh3_32(Buffer.from('varvel')), mmh3_32(Buffer.from('varvel')), 'deterministic');
  const h = mmh3_32(Buffer.from('some-favicon-bytes'));
  assert.ok(Number.isInteger(h) && h >= -2147483648 && h <= 2147483647, 'signed 32-bit');
});

test('recon: lenient — scans given targets and fingerprints HTTP + security headers + favicon', async () => {
  const favicon = Buffer.from('\x00\x00\x01\x00\x01\x00\x10\x10VARVELICON', 'latin1');
  const srv = http.createServer((req, res) => {
    if (req.url === '/favicon.ico') { res.writeHead(200, { 'content-type': 'image/x-icon' }); return res.end(favicon); }
    res.writeHead(200, { server: 'VARVEL-test/1.0', 'content-security-policy': "default-src 'self'", 'x-powered-by': 'Node' });
    res.end('<html><head><title>Target Web</title></head><body>ok</body></html>');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  try {
    // no scope passed at all -> still scans (lenient, like RedAmon). webPorts override so the ephemeral port gets HTTP-fingerprinted.
    const res = await recon(['127.0.0.1'], { ports: [port], timeout: 800, webPorts: new Set([port]) });
    assert.equal(res.scanned, 1);
    const host = res.hosts.find((h) => h.ip === '127.0.0.1');
    assert.ok(host, 'target scanned');
    const svc = host.services.find((s) => s.port === port);
    assert.ok(svc && svc.http, 'HTTP fingerprint captured');
    assert.equal(svc.http.server, 'VARVEL-test/1.0');
    assert.equal(svc.http.title, 'Target Web');
    assert.equal(svc.http.security.csp, true, 'CSP header detected');
    assert.equal(svc.http.security.hsts, false, 'HSTS absence detected');
    assert.equal(typeof svc.faviconHash, 'number', 'Shodan-compatible favicon hash computed');
  } finally {
    srv.close();
  }
});

test('scanHost: closed port produces no false positive', async () => {
  const res = await scanHost('127.0.0.1', { ports: [1], timeout: 500 });
  assert.equal(res.services.length, 0);
});

test('identifyService: banner version detection (nmap -sV lite)', () => {
  const ssh = identifyService(22, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1');
  assert.equal(ssh.name, 'ssh');
  assert.equal(ssh.product, 'OpenSSH');
  assert.ok(/^8\.9/.test(ssh.version), 'ssh software version parsed');
  const ftp = identifyService(21, '220 (vsFTPd 3.0.3)');
  assert.equal(ftp.name, 'ftp');
  assert.ok(/3\.0\.3/.test(ftp.version || ''), 'ftp version parsed');
  assert.equal(identifyService(6379, '+PONG').name, 'redis');
  assert.equal(identifyService(80, 'HTTP/1.1 200 OK').name, 'http');
  assert.equal(identifyService(22, null).name, 'ssh', 'falls back to port map when no banner');
  assert.equal(identifyService(65000, 'random noise').name, 'unknown');
  assert.equal(identifyService(110, '-ERR temporarily unavailable').name, 'pop3', 'POP3 -ERR is not misread as redis');
  const redis = identifyService(6379, 'redis_version:7.0.5');
  assert.equal(redis.name, 'redis'); assert.equal(redis.version, '7.0.5', 'redis version captured, not dropped');
  const httpId = identifyService(80, 'HTTP/1.1 200 OK');
  assert.equal(httpId.name, 'http');
  assert.equal(httpId.product, undefined); assert.equal(httpId.version, undefined, 'protocol version is not the software version');
});

test('mmh3_32: known-answer vectors (proves Shodan-compatibility)', () => {
  assert.equal(mmh3_32(Buffer.from('')), 0);
  assert.equal(mmh3_32(Buffer.from('foo')), -156908512, 'matches python mmh3.hash("foo")');
  assert.equal(mmh3_32(Buffer.from('0')), -764297089);
  assert.equal(mmh3_32(Buffer.from('01')), 1642882560);
  assert.equal(mmh3_32(Buffer.from('012')), -328401012);
  assert.equal(mmh3_32(Buffer.from('0123')), -736521056);
  assert.equal(mmh3_32(Buffer.from('01234')), 433070448);
});

test('ipInScope: rejects malformed input (out-of-range octet, bad mask, leading zero)', () => {
  assert.equal(ipInScope('192.168.1.300', ['192.168.2.0/24']), false, 'out-of-range octet not coerced into a neighbouring subnet');
  assert.equal(ipInScope('999.999.999.999', ['0.0.0.0/0']), false);
  assert.equal(ipInScope('8.8.8.8', ['10.0.0.0/']), false, 'trailing-slash mask is NOT match-all');
  assert.equal(ipInScope('1.2.3.4', ['1.2.3.4/abc']), false, 'non-numeric mask rejected');
  assert.equal(ipInScope('1.2.3.4', ['1.2.3.4/33']), false);
  assert.equal(ipInScope('010.0.0.1', ['10.0.0.0/8']), false, 'leading-zero octet rejected (octal ambiguity)');
  assert.equal(ipInScope('10.0.0.5', ['10.0.0.0/8']), true, 'valid membership still works');
});

test('scanHost: connect-then-RST port is reported OPEN (latch on connect)', async () => {
  const srv = net.createServer((s) => { try { s.resetAndDestroy(); } catch { s.destroy(); } });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const p = srv.address().port;
  try {
    const res = await scanHost('127.0.0.1', { ports: [p], timeout: 900, webPorts: new Set() });
    assert.ok(res.services.some((s) => s.port === p), 'connect-then-RST still reported open');
  } finally { srv.close(); }
});

test('scanHost: silent-open port detected even at timeout<200ms', async () => {
  const conns = [];
  const srv = net.createServer((s) => { conns.push(s); }); // accept, stay silent
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const p = srv.address().port;
  try {
    const res = await scanHost('127.0.0.1', { ports: [p], timeout: 150, webPorts: new Set() });
    assert.ok(res.services.some((s) => s.port === p), 'silent open port found at low timeout');
  } finally { conns.forEach((s) => { try { s.destroy(); } catch {} }); srv.close(); }
});

test('scanHost: favicon hashed after following a same-host redirect', async () => {
  const icon = Buffer.from('\x00\x00\x01\x00 favicon via redirect payload', 'latin1');
  const srv = http.createServer((req, res) => {
    if (req.url === '/') { res.writeHead(200); return res.end('<html></html>'); }
    if (req.url === '/favicon.ico') { res.writeHead(301, { location: '/real.ico' }); return res.end(); }
    if (req.url === '/real.ico') { res.writeHead(200); return res.end(icon); }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const p = srv.address().port;
  try {
    const res = await scanHost('127.0.0.1', { ports: [p], webPorts: new Set([p]), timeout: 800 });
    const svc = res.services.find((s) => s.port === p);
    assert.equal(typeof svc.faviconHash, 'number', 'favicon hashed after 301');
  } finally { srv.close(); }
});

test('scanHost: favicon via <link rel="icon"> fallback when /favicon.ico is missing', async () => {
  const icon = Buffer.from('\x00\x00\x01\x00 link-rel favicon payload', 'latin1');
  const srv = http.createServer((req, res) => {
    if (req.url === '/') { res.writeHead(200); return res.end('<head><link rel="icon" href="/logo.ico"></head>'); }
    if (req.url === '/logo.ico') { res.writeHead(200); return res.end(icon); }
    res.writeHead(404); res.end(); // /favicon.ico -> 404
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const p = srv.address().port;
  try {
    const res = await scanHost('127.0.0.1', { ports: [p], webPorts: new Set([p]), timeout: 800 });
    const svc = res.services.find((s) => s.port === p);
    assert.equal(typeof svc.faviconHash, 'number', 'favicon hashed via <link rel=icon> fallback');
  } finally { srv.close(); }
});
