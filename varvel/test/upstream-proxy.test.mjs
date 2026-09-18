// upstream-proxy.test.mjs — listener upstream proxy chaining (operator directive).
// Config flow (constructor option > env VARVEL_UPSTREAM_PROXY > 'channel.upstreamProxy'
// setting), parse strictness, FAIL-CLOSED behavior, and the ghc mailbox leg actually
// riding http:// + socks5h:// chains. Hermetic: loopback only — mock proxies and a mock
// SaaS mailbox, no external network, no raw sockets.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { CallbackChannel, parseUpstreamProxy, UpstreamProxyError } from '../engine/callback.mjs';
import { Ghc2Api } from '../engine/ghc2.mjs';
import { SocksServer } from '../engine/socksserve.mjs';
import { DOH_LAB_CERT, DOH_LAB_KEY } from '../engine/doh-labcert.mjs';

const SCOPE = { engagement: 'test', signedBy: 'test', cidrs: ['127.0.0.0/8'] };

// A temp settings store so the 'channel.upstreamProxy' SETTINGS leg is real (the
// registry lazy-loads this file; set BEFORE the first channel construction below).
const settingsDir = mkdtempSync(join(tmpdir(), 'varvel-uproxy-settings-'));
process.env.VARVEL_SETTINGS_FILE = join(settingsDir, 'settings.json');
writeFileSync(process.env.VARVEL_SETTINGS_FILE, JSON.stringify({
  uproxy: { 'channel.upstreamProxy': 'socks5h://127.0.0.1:11080' },
}));

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

// Mock SaaS mailbox (the GitHub-gist shape Ghc2Api speaks): GET lists comments,
// POST creates one. Counts hits — the fail-closed proof is that this stays at ZERO.
function mockMailbox({ tls: useTls } = {}) {
  const hits = [];
  const handler = (req, res) => {
    hits.push({ method: req.method, url: req.url });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(req.method === 'POST' ? '{"id":42}' : '[]');
  };
  const srv = useTls ? https.createServer({ key: DOH_LAB_KEY, cert: DOH_LAB_CERT }, handler) : http.createServer(handler);
  return { srv, hits };
}

// Mock HTTP forward proxy: CONNECT <authority> -> tunnel to 127.0.0.1:<port>; records it.
function mockConnectProxy({ onConnect } = {}) {
  return net.createServer((sock) => {
    let head = '';
    sock.on('data', function onData(d) {
      head += d.toString('latin1');
      const end = head.indexOf('\r\n\r\n');
      if (end < 0) return;
      const m = /^CONNECT ([^ ]+) HTTP/.exec(head.split('\r\n')[0]);
      if (!m) { sock.destroy(); return; }
      sock.off('data', onData);
      const authority = m[1];
      const port = Number(authority.split(':').pop());
      if (onConnect) onConnect(authority, port);
      const up = net.connect({ host: '127.0.0.1', port }, () => {
        sock.write('HTTP/1.1 200 OK\r\n\r\n' + head.slice(end + 4));
        sock.pipe(up); up.pipe(sock);
      });
      up.on('error', () => sock.destroy());
    });
  });
}

const savedEnv = process.env.VARVEL_UPSTREAM_PROXY;
function setEnv(v) { if (v == null) delete process.env.VARVEL_UPSTREAM_PROXY; else process.env.VARVEL_UPSTREAM_PROXY = v; }
function ch(extra = {}, scope = SCOPE) {
  const events = [];
  const c = new CallbackChannel({ scope, onEvent: (t, o) => events.push({ type: t, ...o }), ...extra });
  return { c, events };
}

test('parseUpstreamProxy: http:// + socks5h:// forms, defaults, v6, creds; empty is null', () => {
  assert.equal(parseUpstreamProxy(null), null);
  assert.equal(parseUpstreamProxy(''), null);
  assert.equal(parseUpstreamProxy('   '), null);
  assert.deepEqual(parseUpstreamProxy('http://127.0.0.1:8080'), { scheme: 'http', host: '127.0.0.1', port: 8080, user: '', pass: '' });
  assert.deepEqual(parseUpstreamProxy('http://proxy.local'), { scheme: 'http', host: 'proxy.local', port: 80, user: '', pass: '' });
  assert.deepEqual(parseUpstreamProxy('socks5h://127.0.0.1'), { scheme: 'socks5', host: '127.0.0.1', port: 1080, user: '', pass: '' });
  assert.deepEqual(parseUpstreamProxy('socks5h://user:p%40ss@[::1]:1090'), { scheme: 'socks5', host: '::1', port: 1090, user: 'user', pass: 'p@ss' });
});

test('parseUpstreamProxy: malformed/unsupported is a NAMED error (fail-closed)', () => {
  for (const bad of ['socks5://127.0.0.1:1080', 'ftp://127.0.0.1:21', 'not-a-url', 'http://']) {
    assert.throws(() => parseUpstreamProxy(bad), (e) => {
      assert.equal(e.name, 'UpstreamProxyError', bad);
      assert.equal(e.code, 'UPSTREAM_PROXY', bad);
      assert.ok(e instanceof UpstreamProxyError);
      return true;
    }, bad);
  }
  assert.throws(() => parseUpstreamProxy('socks5://x'), /socks5h ONLY/, 'plain socks5:// names the local-DNS leak it would be');
});

test('config precedence: constructor option > env > settings; unconfigured is byte-identical', () => {
  try {
    setEnv('socks5h://127.0.0.1:20001');
    // option beats env
    const a = ch({ upstreamProxy: 'http://127.0.0.1:18080' });
    assert.equal(a.c.upstreamProxy.scheme, 'http');
    assert.equal(a.c.upstreamProxySource, 'option');
    // env beats settings (settings has socks5h://127.0.0.1:11080 for engagement 'uproxy')
    const b = ch({}, { ...SCOPE, engagement: 'uproxy' });
    assert.equal(b.c.upstreamProxy.port, 20001);
    assert.equal(b.c.upstreamProxySource, 'env');
    setEnv(null);
    // settings honored when neither option nor env is set
    const c = ch({}, { ...SCOPE, engagement: 'uproxy' });
    assert.deepEqual(c.c.upstreamProxy, { scheme: 'socks5', host: '127.0.0.1', port: 11080, user: '', pass: '' });
    assert.equal(c.c.upstreamProxySource, 'settings');
    // unconfigured: no proxy state at all
    const d = ch({}, { ...SCOPE, engagement: 'plain' });
    assert.equal(d.c.upstreamProxy, null);
    assert.equal(d.c.upstreamProxySource, null);
  } finally { setEnv(savedEnv); }
});

test('config fail-closed at construction: a malformed proxy REFUSES to arm a listener', () => {
  assert.throws(() => ch({ upstreamProxy: 'socks5://127.0.0.1:1080' }), (e) => e.name === 'UpstreamProxyError' && e.code === 'UPSTREAM_PROXY');
  try {
    setEnv('garbage-proxy');
    assert.throws(() => ch(), (e) => e.code === 'UPSTREAM_PROXY');
  } finally { setEnv(savedEnv); }
});

test('no proxy configured: the mailbox leg rides DIRECT and the client is untouched', async () => {
  const { srv, hits } = mockMailbox();
  const mport = await listen(srv);
  const { c } = ch();
  try {
    const api = new Ghc2Api({ token: 'github_pat_TEST', gistId: 'deadbeefgist', apiBase: 'http://127.0.0.1:' + mport });
    c.attachGhc({ client: api, intervalSec: 0 });
    assert.equal(api.agents, null, 'no agents threaded — byte-identical to before the directive');
    assert.equal(c.ghcStatus().upstreamProxy, null);
    const r = await c.ghcPollNow();
    assert.equal(r.ok, true);
    assert.equal(hits.length, 1);
    assert.match(hits[0].url, /^\/gists\/deadbeefgist\/comments/);
  } finally { c.detachGhc(); await close(srv); }
});

test('http:// upstream proxy: the mailbox poll transits the CONNECT tunnel (creds never rendered)', async () => {
  const { srv, hits } = mockMailbox();
  const mport = await listen(srv);
  const seen = [];
  const proxy = mockConnectProxy({ onConnect: (authority, port) => seen.push({ authority, port }) });
  const pport = await listen(proxy);
  const { c, events } = ch({ upstreamProxy: 'http://user:secretpass@127.0.0.1:' + pport });
  try {
    const api = new Ghc2Api({ token: 'github_pat_TEST', gistId: 'deadbeefgist', apiBase: 'http://127.0.0.1:' + mport });
    c.attachGhc({ client: api, intervalSec: 0 });
    assert.ok(api.agents && api.agents.httpAgent, 'proxy agents threaded into the client');
    const st = c.ghcStatus().upstreamProxy;
    assert.deepEqual(st, { applied: true, scheme: 'http', host: '127.0.0.1', port: pport, source: 'option' });
    const r = await c.ghcPollNow();
    assert.equal(r.ok, true);
    assert.deepEqual(seen, [{ authority: '127.0.0.1:' + mport, port: mport }], 'the proxy got the CONNECT, not a direct dial');
    assert.equal(hits.length, 1, 'the request completed through the tunnel');
    assert.match(hits[0].url, /^\/gists\//, 'origin-form request line on the tunneled connection');
    assert.ok(events.some((e) => e.type === 'channel.upstream-proxy' && e.applied === true && e.leg === 'ghc-mailbox'));
    // Proxy CREDENTIALS never render — not in status, not in the audit stream.
    const rendered = JSON.stringify(events) + JSON.stringify(c.ghcStatus());
    assert.ok(!rendered.includes('secretpass'), 'proxy credentials never leave the dialer');
  } finally { c.detachGhc(); await close(proxy); await close(srv); }
});

test('https mailbox through the http:// proxy: TLS rides the tunnel end-to-end', async () => {
  const { srv, hits } = mockMailbox({ tls: true });
  const mport = await listen(srv);
  const proxy = mockConnectProxy({});
  const pport = await listen(proxy);
  const { c } = ch({ upstreamProxy: 'http://127.0.0.1:' + pport });
  try {
    const api = new Ghc2Api({ token: 'github_pat_TEST', gistId: 'deadbeefgist', apiBase: 'https://127.0.0.1:' + mport });
    c.attachGhc({ client: api, intervalSec: 0 });
    const r = await c.ghcPollNow();
    assert.equal(r.ok, true);
    assert.equal(hits.length, 1, 'TLS terminated at the mailbox — through the CONNECT tunnel');
  } finally { c.detachGhc(); await close(proxy); await close(srv); }
});

test('socks5h:// upstream proxy: the mailbox poll rides the SOCKS5 handshake (repo SocksServer)', async () => {
  const { srv, hits } = mockMailbox();
  const mport = await listen(srv);
  const decisions = [];
  const socks = new SocksServer({ allow: (d) => { decisions.push(d); return true; } });
  const sport = (await socks.listen(0, '127.0.0.1')).port;
  const { c } = ch({ upstreamProxy: 'socks5h://127.0.0.1:' + sport });
  try {
    const api = new Ghc2Api({ token: 'github_pat_TEST', gistId: 'deadbeefgist', apiBase: 'http://127.0.0.1:' + mport });
    c.attachGhc({ client: api, intervalSec: 0 });
    const r = await c.ghcPollNow();
    assert.equal(r.ok, true);
    assert.equal(decisions.length, 1);
    assert.equal(decisions[0].host, '127.0.0.1');
    assert.equal(decisions[0].port, mport);
    assert.equal(hits.length, 1, 'the governed socks server relayed the poll');
  } finally { c.detachGhc(); await socks.close(); await close(srv); }
});

test('FAIL-CLOSED: a configured-but-unreachable proxy fails the leg — NOTHING goes direct', async () => {
  const { srv, hits } = mockMailbox();
  const mport = await listen(srv);
  // A guaranteed-closed loopback port (open, learn, close).
  const probe = net.createServer(); const deadPort = await listen(probe); await close(probe);
  const { c, events } = ch({ upstreamProxy: 'http://127.0.0.1:' + deadPort });
  try {
    const api = new Ghc2Api({ token: 'github_pat_TEST', gistId: 'deadbeefgist', apiBase: 'http://127.0.0.1:' + mport });
    c.attachGhc({ client: api, intervalSec: 0 });
    const r = await c.ghcPollNow();
    assert.equal(r.ok, false, 'the leg failed...');
    assert.equal(hits.length, 0, '...and the mailbox saw NOTHING — no silent direct-connect, no leak');
    const err = events.find((e) => e.type === 'ghc.error');
    assert.ok(err, 'the failure is loud in the audit stream');
    assert.match(String(err.error), /upstream proxy http:\/\/127\.0\.0\.1:\d+ cannot carry/, 'the NAMED error');
    assert.match(String(err.error), /fail-closed: no direct fallback/);
  } finally { c.detachGhc(); await close(srv); }
});

test('FAIL-CLOSED at attach: a proxy is configured but the client has no agents seam', () => {
  const { c } = ch({ upstreamProxy: 'http://127.0.0.1:18080' });
  const foreign = { listComments: async () => ({ ok: true, comments: [] }), createComment: async () => ({ ok: true, id: 1 }) };
  assert.throws(() => c.attachGhc({ client: foreign, intervalSec: 0 }), (e) => {
    assert.equal(e.name, 'UpstreamProxyError');
    assert.equal(e.code, 'UPSTREAM_PROXY');
    assert.match(e.message, /attach REFUSED/);
    return true;
  });
  assert.equal(c.ghc, null, 'refused before any state changed — nothing attached');
});

// Settings-file hygiene (the registry cached our temp store for this process).
test('settings temp store cleanup', () => {
  rmSync(settingsDir, { recursive: true, force: true });
  delete process.env.VARVEL_SETTINGS_FILE;
  if (savedEnv == null) delete process.env.VARVEL_UPSTREAM_PROXY; else process.env.VARVEL_UPSTREAM_PROXY = savedEnv;
  assert.ok(true);
});
