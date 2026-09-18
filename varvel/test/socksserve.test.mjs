// socksserve.test.mjs — the governed SOCKS5 pivot (gap #4b, stage 3). Hermetic: loopback
// echo servers + loopback SOCKS clients, the REAL relay path. The allow-check seam is
// exercised as the engagement scope ring (inAnyCidr) exactly the way the agent wires it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { SocksServer, SocksError, parseGreeting, parseRequest, parseAuth, buildReply, REP } from '../engine/socksserve.mjs';
import { inAnyCidr, isLoopback, parseIp } from '../engine/ipaddr.mjs';

const tick = (ms = 15) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, timeoutMs = 2000) {
  const start = Date.now();
  while (!fn()) {
    if (Date.now() - start > timeoutMs) return false;
    await new Promise((r) => setTimeout(r, 15));
  }
  return true;
}

// A loopback echo server: whatever the pivoted client sends comes back.
async function echoServer() {
  const srv = net.createServer((s) => s.on('data', (d) => s.write(d)));
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { srv, port: srv.address().port };
}

// Minimal RFC 1928/1929 client over a raw socket (zero deps — the test speaks the wire).
function socksClient(port, { auth } = {}) {
  const sock = net.connect(port, '127.0.0.1');
  sock.on('error', () => {});
  const steps = [];
  let buf = Buffer.alloc(0);
  const waitBytes = (n, timeoutMs = 2500) => new Promise((resolve, reject) => {
    const t0 = Date.now();
    const poll = () => {
      if (buf.length >= n) { const out = buf.subarray(0, n); buf = buf.subarray(n); return resolve(out); }
      if (Date.now() - t0 > timeoutMs) return reject(new Error('timeout waiting for ' + n + ' bytes (have ' + buf.length + ')'));
      setTimeout(poll, 8);
    };
    poll();
  });
  sock.on('data', (d) => { buf = Buffer.concat([buf, d]); });
  const ready = new Promise((resolve, reject) => { sock.once('connect', resolve); sock.once('error', reject); });
  return {
    ready,
    sock,
    // greeting with the given method list; returns the server's method pick (or 0xFF)
    async greet(methods = [0x00, 0x02]) {
      sock.write(Buffer.from([0x05, methods.length, ...methods]));
      const r = await waitBytes(2);
      return r[1];
    },
    async auth(user, pass) {
      const u = Buffer.from(user, 'latin1'), p = Buffer.from(pass, 'latin1');
      sock.write(Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([p.length]), p]));
      const r = await waitBytes(2);
      return r[1]; // 0 = ok
    },
    // CONNECT: atyp 'ipv4' (host = 'a.b.c.d'), 'domain', or 'ipv6' (host = any v6 text form).
    async connect(host, portNum, atyp = 'ipv4') {
      let addr;
      if (atyp === 'ipv4') addr = Buffer.from([0x01, ...host.split('.').map(Number)]);
      else if (atyp === 'ipv6') {
        // build the 16 wire bytes; the mapped form is spelled out because the platform
        // parser deliberately collapses '::ffff:a.b.c.d' to fam 4 (no groups kept)
        const mm = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(host);
        let g;
        if (mm) { const o = mm[1].split('.').map(Number); g = [0, 0, 0, 0, 0, 0xffff, (o[0] << 8) | o[1], (o[2] << 8) | o[3]]; }
        else g = parseIp(host).groups;
        addr = Buffer.concat([Buffer.from([0x04]), Buffer.from(g.flatMap((x) => [x >> 8, x & 0xff]))]);
      }
      else { const h = Buffer.from(host, 'latin1'); addr = Buffer.concat([Buffer.from([0x03, h.length]), h]); }
      const p = Buffer.alloc(2); p.writeUInt16BE(portNum, 0);
      sock.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), addr, p]));
      return waitBytes(10); // VER REP RSV ATYP BND(4+2)
    },
    async send(data) { sock.write(Buffer.isBuffer(data) ? data : Buffer.from(data)); return waitBytes(Buffer.isBuffer(data) ? data.length : Buffer.byteLength(data)); },
    close: () => { try { sock.destroy(); } catch {} },
    isClosed: () => sock.destroyed,
  };
}

const ringAllow = (cidrs) => ({ host, addressType }) => {
  if (isLoopback(host)) return true;
  if (addressType !== 'ipv4' && addressType !== 'ipv6') return { ok: false, reason: 'domains are not in the ring' };
  return inAnyCidr(host, cidrs) ? true : { ok: false, reason: host + ' outside the ring' };
};

// ---------------- pure wire helpers ----------------
test('socks wire: greeting/request/auth parsers + reply builder shapes', () => {
  assert.deepEqual(parseGreeting(Buffer.from([0x05, 0x02, 0x00, 0x02])).methods, [0, 2]);
  assert.equal(parseGreeting(Buffer.from([0x05, 0x02])), null, 'incomplete greeting waits');
  assert.throws(() => parseGreeting(Buffer.from([0x04, 0x01, 0x00])), SocksError); // SOCKS4 refused
  assert.throws(() => parseGreeting(Buffer.from([0x05, 0x00])), SocksError);       // no methods

  const req = Buffer.from([0x05, 0x01, 0x00, 0x01, 10, 0, 0, 5, 0x1a, 0xe1]);
  const p = parseRequest(req);
  assert.deepEqual({ host: p.host, port: p.port, addressType: p.addressType }, { host: '10.0.0.5', port: 6881, addressType: 'ipv4' });
  const dom = Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, 9]), Buffer.from('tenet-web'), Buffer.from([0x00, 0x50])]);
  assert.deepEqual({ host: parseRequest(dom).host, port: parseRequest(dom).port }, { host: 'tenet-web', port: 80 });
  assert.equal(parseRequest(req.subarray(0, 5)), null, 'incomplete request waits');
  assert.throws(() => parseRequest(Buffer.from([0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0, 80])), (e) => e.rep === REP.COMMAND_NOT_SUPPORTED); // BIND
  assert.throws(() => parseRequest(Buffer.from([0x05, 0x01, 0x00, 0x09])), (e) => e.rep === REP.ADDRESS_TYPE_NOT_SUPPORTED);           // unknown atyp

  // ATYP 0x04 (IPv6): 16 raw bytes -> canonical text via the shared engine/ipaddr parser.
  assert.equal(parseRequest(Buffer.from([0x05, 0x01, 0x00, 0x04])), null, 'incomplete v6 request waits for the rest');
  const v6 = Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x04]),
    Buffer.from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x25]), Buffer.from([0x00, 0x50])]);
  assert.deepEqual({ host: parseRequest(v6).host, port: parseRequest(v6).port, addressType: parseRequest(v6).addressType },
    { host: '2001:db8::25', port: 80, addressType: 'ipv6' }, 'v6 wire form parses to the canonical literal');
  const mapped = Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x04]),
    Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 5]), Buffer.from([0x1a, 0xe1])]);
  const mp = parseRequest(mapped);
  assert.equal(mp.host, '10.0.0.5', 'v4-mapped v6 on the wire IS the v4 destination');
  assert.equal(mp.addressType, 'ipv4', 'mapped collapses: the v4 ring governs it');

  const a = parseAuth(Buffer.concat([Buffer.from([0x01, 3]), Buffer.from('bob'), Buffer.from([4]), Buffer.from('pass')]));
  assert.equal(a.user, 'bob');
  assert.equal(a.pass, 'pass');
  assert.deepEqual([...buildReply(REP.SUCCEEDED)], [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
});

// ---------------- governed server over loopback ----------------
test('socks e2e: no-auth CONNECT (IPv4 form) relays bytes to a loopback echo server', async () => {
  const { srv: echo, port: echoPort } = await echoServer();
  const events = [];
  const socks = new SocksServer({ allow: ringAllow(['127.0.0.0/8']), onEvent: (t, o) => events.push({ type: t, ...o }) });
  await socks.listen(0, '127.0.0.1');
  try {
    const c = socksClient(socks.port);
    await c.ready;
    assert.equal(await c.greet([0x00]), 0x00, 'no-auth method selected');
    const rep = await c.connect('127.0.0.1', echoPort);
    assert.equal(rep[1], REP.SUCCEEDED, 'CONNECT granted by the seam');
    assert.deepEqual([...rep.subarray(2)], [...buildReply(0).subarray(2)], 'standard 0.0.0.0:0 bound shape');
    const echoed = await c.send('through-the-pivot');
    assert.equal(echoed.toString(), 'through-the-pivot', 'bytes relayed both ways');
    assert.ok(events.some((e) => e.type === 'socks.associated' && e.host === '127.0.0.1' && e.port === echoPort));
    c.close();
    assert.ok(await waitFor(() => events.some((e) => e.type === 'socks.closed')), 'association teardown audited');
    const closed = events.find((e) => e.type === 'socks.closed');
    assert.equal(closed.bytesUp, Buffer.byteLength('through-the-pivot'));
    assert.equal(closed.bytesDown, Buffer.byteLength('through-the-pivot'));
  } finally { await socks.close(); echo.close(); }
});

test('socks e2e: IPv6 form is governed by the SAME ring — in-ring relays, out-of-ring refused with NO dial', async () => {
  const { srv: echo, port: echoPort } = await echoServer();
  const events = [];
  let dials = 0;
  const socks = new SocksServer({
    allow: ringAllow(['fd00::/8']),
    // injected dialer: the ring decision is what is under test; the relay dial itself
    // goes to the loopback echo (no real v6 route needed in a hermetic test).
    connectImpl: async (host, port) => { dials++; return net.connect(echoPort, '127.0.0.1'); },
    onEvent: (t, o) => events.push({ type: t, ...o }),
  });
  await socks.listen(0, '127.0.0.1');
  try {
    const c = socksClient(socks.port);
    await c.ready;
    assert.equal(await c.greet([0x00]), 0x00);
    // in-ring v6 (mixed-case compressed form on the wire — canonicalized before the seam)
    const rep = await c.connect('FD00::A:0:1', echoPort, 'ipv6');
    assert.equal(rep[1], REP.SUCCEEDED, 'in-ring v6 CONNECT granted');
    assert.ok(events.some((e) => e.type === 'socks.associated' && e.host === 'fd00::a:0:1' && e.addressType === 'ipv6'), 'seam + audit see the canonical form');
    const echoed = await c.send('v6-through-the-pivot');
    assert.equal(echoed.toString(), 'v6-through-the-pivot');
    c.close();
    // out-of-ring v6: refused by ruleset, never dialed
    const c2 = socksClient(socks.port);
    await c2.ready;
    assert.equal(await c2.greet([0x00]), 0x00);
    const rep2 = await c2.connect('2001:db8::9', 443, 'ipv6');
    assert.equal(rep2[1], REP.NOT_ALLOWED, 'out-of-ring v6 refused');
    await tick(120);
    assert.equal(dials, 1, 'only the allowed v6 destination was ever dialed');
    assert.ok(events.some((e) => e.type === 'socks.refused' && e.host === '2001:db8::9' && /outside the ring/.test(e.reason)));
    c2.close();
  } finally { await socks.close(); echo.close(); }
});

test('socks e2e: v4-mapped v6 wire form is governed by the V4 ring (the classic bypass, closed)', async () => {
  const { srv: echo, port: echoPort } = await echoServer();
  const events = [];
  let dials = 0;
  const socks = new SocksServer({
    allow: ringAllow(['10.10.0.0/16']),
    connectImpl: async (host, port) => { dials++; return net.connect(echoPort, '127.0.0.1'); },
    onEvent: (t, o) => events.push({ type: t, ...o }),
  });
  await socks.listen(0, '127.0.0.1');
  try {
    const c = socksClient(socks.port);
    await c.ready;
    assert.equal(await c.greet([0x00]), 0x00);
    const rep = await c.connect('::ffff:10.10.0.5', echoPort, 'ipv6'); // mapped form of an in-ring v4
    assert.equal(rep[1], REP.SUCCEEDED, 'mapped in-ring v4 allowed via the v4 ring');
    assert.ok(events.some((e) => e.type === 'socks.associated' && e.host === '10.10.0.5' && e.addressType === 'ipv4'));
    c.close();
    const c2 = socksClient(socks.port);
    await c2.ready;
    assert.equal(await c2.greet([0x00]), 0x00);
    const rep2 = await c2.connect('::ffff:192.168.44.9', 445, 'ipv6'); // mapped form of an OUT-of-ring v4
    assert.equal(rep2[1], REP.NOT_ALLOWED, 'a mapped out-of-ring v4 must NOT read as an ungoverned v6 destination');
    await tick(120);
    assert.equal(dials, 1, 'the mapped bypass was never dialed');
    c2.close();
  } finally { await socks.close(); echo.close(); }
});

test('socks e2e: DOMAIN form (localhost) connects; the seam saw the domain string', async () => {
  const { srv: echo, port: echoPort } = await echoServer();
  const seen = [];
  const socks = new SocksServer({
    allow: (d) => { seen.push(d); return d.addressType === 'domain' && d.host === 'localhost'; },
    onEvent: () => {},
  });
  await socks.listen(0, '127.0.0.1');
  try {
    const c = socksClient(socks.port);
    await c.ready;
    assert.equal(await c.greet([0x00]), 0x00);
    const rep = await c.connect('localhost', echoPort, 'domain');
    assert.equal(rep[1], REP.SUCCEEDED, 'domain-form CONNECT works');
    assert.equal(seen[0].host, 'localhost', 'the seam decided on the domain string');
    assert.equal(seen[0].addressType, 'domain');
    const echoed = await c.send('domain-pivot');
    assert.equal(echoed.toString(), 'domain-pivot');
    c.close();
  } finally { await socks.close(); echo.close(); }
});

test('socks governance: out-of-scope destination refused 0x02 with NO dial attempted; default-refuse when unset', async () => {
  const events = [];
  let dials = 0;
  const socks = new SocksServer({
    allow: ringAllow(['10.10.0.0/16']),
    connectImpl: async (host, port) => { dials++; return net.connect(port, host); },
    onEvent: (t, o) => events.push({ type: t, ...o }),
  });
  await socks.listen(0, '127.0.0.1');
  try {
    const c = socksClient(socks.port);
    await c.ready;
    assert.equal(await c.greet([0x00]), 0x00);
    const rep = await c.connect('192.168.44.9', 445); // outside the signed ring
    assert.equal(rep[1], REP.NOT_ALLOWED, 'refused with the RFC ruleset code');
    await tick(120);
    assert.equal(dials, 0, 'a refused destination is NEVER dialed');
    assert.ok(events.some((e) => e.type === 'socks.refused' && e.host === '192.168.44.9' && /outside the ring/.test(e.reason)));

    // no allow callback at all => default-refuse EVERYTHING (an ungoverned relay refused)
    const bare = new SocksServer({ onEvent: (t, o) => events.push({ type: t, ...o }) });
    await bare.listen(0, '127.0.0.1');
    const c2 = socksClient(bare.port);
    await c2.ready;
    assert.equal(await c2.greet([0x00]), 0x00);
    const rep2 = await c2.connect('127.0.0.1', 80);
    assert.equal(rep2[1], REP.NOT_ALLOWED, 'default-refuse: even loopback is refused ungoverned');
    assert.ok(events.some((e) => e.type === 'socks.refused' && /no allow-check/.test(e.reason)));
    c2.close();
    await bare.close();
    c.close();
  } finally { await socks.close(); }
});

test('socks auth: RFC 1929 user/pass required + verified; wrong pass fails; method-not-offered gets 0xFF', async () => {
  const events = [];
  const { srv: echo, port: echoPort } = await echoServer();
  const socks = new SocksServer({ auth: { user: 'operator', pass: 's3cret' }, allow: ringAllow(['127.0.0.0/8']), onEvent: (t, o) => events.push({ type: t, ...o }) });
  await socks.listen(0, '127.0.0.1');
  try {
    // client that only offers no-auth -> 0xFF + close
    const c0 = socksClient(socks.port);
    await c0.ready;
    assert.equal(await c0.greet([0x00]), 0xff, 'no acceptable method');
    c0.close();
    // wrong password -> auth failure + close
    const c1 = socksClient(socks.port);
    await c1.ready;
    assert.equal(await c1.greet([0x02]), 0x02);
    assert.equal(await c1.auth('operator', 'wrong'), 0x01, 'bad credentials refused');
    assert.ok(await waitFor(() => events.some((e) => e.type === 'socks.auth-failed')));
    c1.close();
    // right credentials -> full association
    const c2 = socksClient(socks.port);
    await c2.ready;
    assert.equal(await c2.greet([0x00, 0x02]), 0x02, 'user/pass method selected');
    assert.equal(await c2.auth('operator', 's3cret'), 0x00);
    const rep = await c2.connect('127.0.0.1', echoPort);
    assert.equal(rep[1], REP.SUCCEEDED);
    const echoed = await c2.send('authenticated-pivot');
    assert.equal(echoed.toString(), 'authenticated-pivot');
    c2.close();
  } finally { await socks.close(); echo.close(); }
});

test('socks robustness: malformed greeting, unsupported command (0x07), unreachable target (0x05), pipelined bytes', async () => {
  const { srv: echo, port: echoPort } = await echoServer();
  const events = [];
  const socks = new SocksServer({ allow: ringAllow(['127.0.0.0/8']), onEvent: (t, o) => events.push({ type: t, ...o }) });
  await socks.listen(0, '127.0.0.1');
  try {
    // SOCKS4 garbage -> closed, audited, server alive
    const bad = net.connect(socks.port, '127.0.0.1', () => bad.write(Buffer.from([0x04, 0x01, 0x00, 0x50, 1, 2, 3, 4, 0])));
    bad.on('error', () => {});
    await waitFor(() => bad.destroyed, 1500);
    assert.ok(await waitFor(() => events.some((e) => e.type === 'socks.malformed')));

    // BIND (0x02) -> command-not-supported reply 0x07
    const c1 = socksClient(socks.port);
    await c1.ready;
    assert.equal(await c1.greet([0x00]), 0x00);
    c1.sock.write(Buffer.from([0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80]));
    const rep1 = await new Promise((resolve) => { let b = Buffer.alloc(0); const h = (d) => { b = Buffer.concat([b, d]); if (b.length >= 10) { c1.sock.off('data', h); resolve(b); } }; c1.sock.on('data', h); });
    assert.equal(rep1[1], REP.COMMAND_NOT_SUPPORTED);
    assert.ok(events.some((e) => e.type === 'socks.unsupported'));
    c1.close();

    // connect to a closed loopback port -> 0x05 connection refused (governed dial failed)
    const c2 = socksClient(socks.port);
    await c2.ready;
    assert.equal(await c2.greet([0x00]), 0x00);
    const rep2 = await c2.connect('127.0.0.1', 1);
    assert.equal(rep2[1], REP.CONNECTION_REFUSED);
    assert.ok(events.some((e) => e.type === 'socks.unreachable'));
    c2.close();

    // pipelined greeting+request in ONE segment works (real clients do this)
    const c3 = socksClient(socks.port);
    await c3.ready;
    const p = Buffer.alloc(2); p.writeUInt16BE(echoPort, 0);
    c3.sock.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), Buffer.from([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1]), p]));
    const got = await new Promise((resolve) => { let b = Buffer.alloc(0); const h = (d) => { b = Buffer.concat([b, d]); if (b.length >= 12) { c3.sock.off('data', h); resolve(b); } }; c3.sock.on('data', h); });
    assert.equal(got[1], 0x00, 'method pick');
    assert.equal(got[3], REP.SUCCEEDED, 'coalesced request parsed after the greeting');
    c3.close();

    // and the server is still healthy for a normal association after all that
    const c4 = socksClient(socks.port);
    await c4.ready;
    assert.equal(await c4.greet([0x00]), 0x00);
    assert.equal((await c4.connect('127.0.0.1', echoPort))[1], REP.SUCCEEDED);
    assert.equal((await c4.send('still-alive')).toString(), 'still-alive');
    c4.close();
  } finally { await socks.close(); echo.close(); }
});

test('socks server status: honest view of governance + counters', async () => {
  const ungov = new SocksServer();
  await ungov.listen(0, '127.0.0.1');
  const s0 = ungov.status();
  assert.equal(s0.governed, false, 'an ungoverned server SAYS so');
  await ungov.close();
  const socks = new SocksServer({ allow: () => false, auth: { user: 'u', pass: 'p' } });
  await socks.listen(0, '127.0.0.1');
  const s = socks.status();
  assert.equal(s.listening, true);
  assert.equal(s.governed, true);
  assert.equal(s.auth, true);
  assert.ok(s.port > 0);
  await socks.close();
});

// Teardown grace (win32 libuv assert guard), same house pattern.
test('teardown grace for socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});
