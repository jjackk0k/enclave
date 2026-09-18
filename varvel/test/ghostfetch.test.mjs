// VARVEL ghostfetch tests — the ghost-chain transport (tools/ghostfetch.mjs).
// Hermetic: a mock SOCKS5 server + a mock HTTP target, both on 127.0.0.1 — zero
// external network. The doctrines under test: chain resolution precedence,
// the SOCKS5 handshake (ATYP=domain = remote DNS by construction), REP-code
// translation, FAIL-CLOSED on a dead proxy, the whole-operation deadline (the
// headers-then-silence stall), the local carve-out, and the strict HTTP reader.
//   node --test test/ghostfetch.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { createServer } from 'node:http';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dir = dirname(fileURLToPath(import.meta.url));
const gf = await import('../tools/ghostfetch.mjs');

// A mock SOCKS5 server: answers the greeting, records the CONNECT target, then
// either refuses with a REP code or bridges to a handler (data callback).
function mockSocks5({ onConnect, refuseWith } = {}) {
  const conns = { count: 0, lastDest: null };
  const srv = net.createServer((sock) => {
    sock.once('data', (greet) => {
      if (greet[0] !== 0x05) { sock.destroy(); return; }
      sock.write(Buffer.from([0x05, 0x00]));
      sock.once('data', (req) => {
        conns.count += 1;
        // parse ATYP=domain CONNECT
        const atyp = req[3];
        let dest = null;
        if (atyp === 0x03) {
          const len = req[4];
          dest = req.subarray(5, 5 + len).toString('utf8');
          conns.lastDest = { host: dest, atyp: 'domain', port: req.readUInt16BE(5 + len) };
        } else {
          conns.lastDest = { atyp };
        }
        if (refuseWith !== undefined) {
          sock.end(Buffer.from([0x05, refuseWith, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          return;
        }
        sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        if (onConnect) onConnect(sock, conns.lastDest);
      });
    });
  });
  return new Promise((resolve) => {
    srv.listen(0, '127.0.0.1', () => resolve({ srv, conns, port: srv.address().port }));
  });
}

// --- chain resolution ---------------------------------------------------------

test('resolveGhostChain: env override wins; then VARVEL_ENGAGEMENT bucket; then first armed; none -> null', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'varvel-ghost-'));
  const file = join(tmp, 'settings.json');
  writeFileSync(file, JSON.stringify({
    alpha: { 'ghost.mode': 'required', 'ghost.chain': 'socks5://10.0.0.1:1080' },
    beta: { 'ghost.mode': 'on', 'ghost.chain': 'socks5://10.0.0.2:1080' },
    plain: { 'recon.maxPages': 5 },
  }));
  assert.equal(gf.resolveGhostChain({ env: {}, settingsFile: file }).chain, 'socks5://10.0.0.1:1080', 'first armed bucket');
  assert.equal(gf.resolveGhostChain({ env: { VARVEL_ENGAGEMENT: 'beta' }, settingsFile: file }).chain, 'socks5://10.0.0.2:1080', 'named engagement wins over first-armed');
  const envWins = gf.resolveGhostChain({ env: { VARVEL_GHOST_CHAIN: 'socks5://1.2.3.4:9999', VARVEL_ENGAGEMENT: 'beta' }, settingsFile: file });
  assert.equal(envWins.chain, 'socks5://1.2.3.4:9999');
  assert.equal(envWins.source, 'env VARVEL_GHOST_CHAIN');
  assert.equal(gf.resolveGhostChain({ env: {}, settingsFile: join(tmp, 'absent.json') }), null);
});

test('parseProxy: socks5 only — anything else is refused loudly', () => {
  assert.deepEqual(gf.parseProxy('socks5://10.64.0.1:1080'), { scheme: 'socks5', host: '10.64.0.1', port: 1080 });
  assert.equal(gf.parseProxy('socks5://10.64.0.1').port, 1080);
  assert.throws(() => gf.parseProxy('http://10.0.0.1:8080'), /not supported/);
  assert.throws(() => gf.parseProxy('socks5://'), /no host|Invalid URL/);
});

// --- the SOCKS5 handshake + proxy fetch -----------------------------------------

test('ghostFetch rides the chain: greeting, ATYP=domain CONNECT (remote DNS), full HTTP exchange', async () => {
  const http = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': '16' });
    res.end('{"proxied":true}');
  });
  await new Promise((r) => http.listen(0, '127.0.0.1', r));
  const targetPort = http.address().port;
  const { srv, conns } = await mockSocks5({
    onConnect: (sock, dest) => {
      const up = net.connect({ host: '127.0.0.1', port: targetPort });
      sock.pipe(up).pipe(sock);
    },
  });
  try {
    const fetchVia = gf.ghostFetch(`socks5://127.0.0.1:${srv.address().port}`);
    const res = await fetchVia(`http://target.example:${targetPort}/v1/x`, { headers: { authorization: 'x' } });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { proxied: true });
    assert.equal(conns.count, 1);
    assert.equal(conns.lastDest.atyp, 'domain', 'the destination NAME went to the proxy — remote DNS by construction');
    assert.equal(conns.lastDest.host, 'target.example', 'the proxy resolved the name, not us');
  } finally {
    srv.close(); http.close();
  }
});

test('chunked transfer encoding is read strictly', async () => {
  const { srv } = await mockSocks5({
    onConnect: (sock) => {
      sock.on('data', () => {});
      sock.write('HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n');
      sock.write('5\r\n{"a":\r\n');   // chunk 1: 5 bytes '{"a":'
      sock.write('3\r\n 1}\r\n');     // chunk 2: 3 bytes ' 1}'
      sock.write('0\r\n\r\n');         // terminator
    },
  });
  try {
    const res = await gf.ghostFetch(`socks5://127.0.0.1:${srv.address().port}`)('http://t.example/x', {});
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { a: 1 });
  } finally { srv.close(); }
});

test('FAIL CLOSED: a dead proxy is ghost-chain-down, never a direct fall-back', async () => {
  const fetchVia = gf.ghostFetch('socks5://127.0.0.1:9', { timeoutMs: 2000 }); // port 9: nothing listens
  await assert.rejects(() => fetchVia('http://never.example/', {}), (e) => {
    assert.equal(e.code, 'ghost-chain-down');
    assert.match(e.message, /FAIL CLOSED/);
    return true;
  });
});

test('proxy REP refusal is translated, never bare', async () => {
  const { srv } = await mockSocks5({ refuseWith: 0x04 });
  try {
    await assert.rejects(
      () => gf.socks5Connect({ proxy: { host: '127.0.0.1', port: srv.address().port }, destHost: 'gone.example', destPort: 443 }),
      (e) => {
        assert.equal(e.code, 'ghost-connect-refused');
        assert.match(e.message, /host unreachable/);
        return true;
      });
  } finally { srv.close(); }
});

test('the whole-operation deadline kills a headers-then-silence stall (the 2026-09-09 wedge)', async () => {
  const { srv } = await mockSocks5({
    onConnect: (sock) => {
      sock.on('data', () => {});
      sock.write('HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n'); // headers, then silence forever
    },
  });
  try {
    const t0 = Date.now();
    await assert.rejects(
      () => gf.ghostFetch(`socks5://127.0.0.1:${srv.address().port}`, { timeoutMs: 400 })('http://stall.example/', {}),
      (e) => { assert.equal(e.code, 'ghost-timeout'); return true; });
    assert.ok(Date.now() - t0 < 3000, 'the stall died at the deadline, not parked');
  } finally { srv.close(); }
});

test('local targets bypass the chain (rule: local stays local) — the proxy sees NOTHING', async () => {
  const { srv, conns } = await mockSocks5({});
  const http = createServer((req, res) => res.end('{"local":true}'));
  await new Promise((r) => http.listen(0, '127.0.0.1', r));
  try {
    const res = await gf.ghostFetch(`socks5://127.0.0.1:${srv.address().port}`)(`http://127.0.0.1:${http.address().port}/x`, {});
    assert.deepEqual(await res.json(), { local: true });
    assert.equal(conns.count, 0, 'no local request ever touched the proxy');
  } finally { srv.close(); http.close(); }
});

test('ghostPreflight: ok through a live mock proxy; named failure through a dead one', async () => {
  const { srv } = await mockSocks5({});
  try {
    const ok = await gf.ghostPreflight(`socks5://127.0.0.1:${srv.address().port}`, { host: 'api.hackerone.com', port: 443 });
    assert.equal(ok.ok, true);
    assert.match(ok.detail, /remote DNS/);
  } finally { srv.close(); }
  const dead = await gf.ghostPreflight('socks5://127.0.0.1:9', { timeoutMs: 1500 });
  assert.equal(dead.ok, false);
  assert.equal(dead.error, 'ghost-chain-down');
});

test("regression 2026-09-10: a deadline kill + repeated socket errors NEVER crash the process", async () => {
  // The first live hunt died at 23:14 on an unhandled TLSSocket 'error' event
  // (code 'ghost-timeout'): destroy(err) manufactured an event that outlived its
  // listeners. The fix: destroy() takes no error arg + every transport carries a
  // durable error sink from birth to death. Proven here on BOTH layers:
  let uncaught = null;
  const onUncaught = (e) => { uncaught = e; };
  process.once('uncaughtException', onUncaught);
  try {
    // (a) mid-body stall → named rejection, then the event loop settles, alive
    const { srv } = await mockSocks5({
      onConnect: (sock) => {
        sock.on('data', () => {});
        sock.write('HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n{"partial":'); // then silence
      },
    });
    try {
      await assert.rejects(
        () => gf.ghostFetch(`socks5://127.0.0.1:${srv.address().port}`, { timeoutMs: 300 })('http://stallbody.example/', {}),
        (e) => { assert.equal(e.code, 'ghost-timeout'); return true; });
    } finally { srv.close(); }
    // (b) the double-error drill: two error events on one live chain socket — the
    // first consumes any once-listeners, the second must meet the durable sink
    const { srv: srv2 } = await mockSocks5({});
    try {
      const sock = await gf.socks5Connect({ proxy: { host: '127.0.0.1', port: srv2.address().port }, destHost: 'drill.example', destPort: 443 });
      sock.emit('error', new Error('drill-1'));
      sock.emit('error', new Error('drill-2'));
      try { sock.destroy(); } catch { /* gone */ }
    } finally { srv2.close(); }
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r)); // let anything async surface
    assert.equal(uncaught, null, 'no error event may ever reach uncaughtException');
  } finally {
    process.off('uncaughtException', onUncaught);
  }
});

// --- the read-only method extension (the poc-forge's probe path) -----------------------------

test('the read-only extension: POST rides the chain with a bounded body, framing owned by the transport', async () => {
  let seen = null;
  const http = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      seen = { method: req.method, path: req.url, cl: req.headers['content-length'], body, ua: req.headers['user-agent'], host: req.headers.host };
      res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '2' });
      res.end('ok');
    });
  });
  await new Promise((r) => http.listen(0, '127.0.0.1', r));
  const targetPort = http.address().port;
  const { srv } = await mockSocks5({
    onConnect: (sock) => {
      const up = net.connect({ host: '127.0.0.1', port: targetPort });
      sock.pipe(up).pipe(sock);
    },
  });
  try {
    const fetchVia = gf.ghostFetch(`socks5://127.0.0.1:${srv.address().port}`);
    const res = await fetchVia(`http://target.example:${targetPort}/submit?a=1`, {
      method: 'POST', body: 'marker=VARVEL-POC-INERT-x',
      headers: { 'user-agent': 'VARVEL-pocforge', 'content-length': '9999', connection: 'keep-alive', host: 'spoofed.example' },
    });
    assert.equal(res.status, 200);
    assert.equal(seen.method, 'POST');
    assert.equal(seen.path, '/submit?a=1');
    assert.equal(seen.body, 'marker=VARVEL-POC-INERT-x', 'the body bytes arrive intact');
    assert.equal(seen.cl, String(Buffer.byteLength('marker=VARVEL-POC-INERT-x')), 'content-length is the transport\'s, never the caller\'s');
    assert.equal(seen.ua, 'VARVEL-pocforge');
    assert.equal(seen.host, `target.example:${targetPort}`, 'a caller-supplied Host is dropped — the transport owns the framing');
  } finally {
    srv.close(); http.close();
  }
});

test('the read-only extension: HEAD returns headers with an EMPTY body even when content-length is present', async () => {
  const http = createServer((req, res) => {
    // node strips the body for HEAD automatically; content-length still describes the hypothetical GET
    res.writeHead(200, { server: 'nginx/1.18.0', 'content-length': '1234' });
    res.end('this never reaches a HEAD client');
  });
  await new Promise((r) => http.listen(0, '127.0.0.1', r));
  const targetPort = http.address().port;
  const { srv } = await mockSocks5({
    onConnect: (sock) => {
      const up = net.connect({ host: '127.0.0.1', port: targetPort });
      sock.pipe(up).pipe(sock);
    },
  });
  try {
    const fetchVia = gf.ghostFetch(`socks5://127.0.0.1:${srv.address().port}`, { timeoutMs: 3000 });
    const res = await fetchVia(`http://target.example:${targetPort}/`, { method: 'HEAD' });
    assert.equal(res.status, 200);
    assert.equal(res.headers.server, 'nginx/1.18.0', 'the banner header is the observable marker');
    assert.equal(await res.text(), '', 'a HEAD body is empty BY DEFINITION — never read as bytes');
  } finally {
    srv.close(); http.close();
  }
});

test('the read-only extension: anything beyond GET/HEAD/POST is refused BEFORE a byte leaves', async () => {
  const { srv, conns } = await mockSocks5({});
  try {
    const fetchVia = gf.ghostFetch(`socks5://127.0.0.1:${srv.address().port}`);
    await assert.rejects(() => fetchVia('http://t.example/', { method: 'PUT' }), (e) => {
      assert.equal(e.code, 'ghost-method-refused');
      return true;
    });
    await assert.rejects(() => fetchVia('http://t.example/', { method: 'DELETE' }), (e) => e.code === 'ghost-method-refused');
    await assert.rejects(() => fetchVia('http://t.example/', { body: 'x' }), (e) => {
      assert.equal(e.code, 'ghost-method-refused');
      assert.match(e.message, /POST only/);
      return true;
    });
    assert.equal(conns.count, 0, 'refusals happen before the proxy is even dialed');
  } finally { srv.close(); }
});
