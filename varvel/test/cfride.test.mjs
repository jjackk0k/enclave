// cfride.test.mjs -- hermetic pins for the clearance RIDE's egress parity (the
// 2026-08-10 live-proven gap: the default fetcher exited DIRECT, so chain-minted
// IP-bound clearance was looked up under the chain's id and then burned at the edge).
// The chain-ridden path is proven over a LOCAL mock SOCKS5 proxy + LOCAL origin (the
// ghost.test.mjs harness pattern): the public target name never resolves locally, so a
// successful ride PROVES the request rode the chain (DNS-by-last-proxy). Nothing leaves
// loopback, ever. The gate refusal paths are pinned with an injected spy fetcher (the
// same seam the pre-fix tests used) and never touch a socket.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ride } from '../tools/cfride.mjs';
import { Ghost, chainEgressId } from '../engine/ghost.mjs';
import { vaultKey, writeVault } from '../tools/clearance/broker.mjs';

const FAKE_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const PUBLIC_HOST = 'zone-one.example'; // unresolvable locally: direct egress would fail DNS
const CLEAN_PAGE = '<html><head><title>Zone One</title></head><body><main>' + 'served page, no challenge here '.repeat(8) + '</main></body></html>';
const CF_CHALLENGE_BODY = '<html><title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script></html>';

function listen(server) {
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));
}
// server.close() waits for keep-alive agent sockets forever -- force them down first.
function close(server) {
  return new Promise((r) => {
    const t = setTimeout(r, 2000);
    try { server.closeAllConnections && server.closeAllConnections(); } catch {}
    server.close(() => { clearTimeout(t); r(); });
  });
}

// SOCKS5 mock (the ghost.test.mjs pattern): completes the handshake, records the CONNECT
// target, then tunnels by CONNECT PORT to 127.0.0.1 -- the public NAME travels to the
// proxy (remote-DNS doctrine) and the loopback origin answers through the tunnel.
function mockSocks5(state) {
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
        state.connects.push({ host, port });
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

// The loopback origin: records the identity headers of every hit, serves a clean page.
function mockOrigin(state) {
  return http.createServer((req, res) => {
    state.hits.push({ url: req.url, ua: req.headers['user-agent'], cookie: req.headers.cookie || '' });
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(CLEAN_PAGE);
  });
}

function tmpVault() {
  return join(tmpdir(), 'cfride-vault-' + process.pid + '-' + Math.random().toString(36).slice(2) + '.json');
}

// A vault holding ONE valid entry for zone under egressId (the mint-side keying).
function vaultWith(zone, egressId, cookieValue) {
  const vaultPath = tmpVault();
  const now = Date.now();
  const entries = {};
  entries[vaultKey(zone, egressId, FAKE_UA)] = {
    cookies: [{ name: 'cf_clearance', value: cookieValue, domain: zone.split(':')[0], path: '/' }],
    ua: FAKE_UA,
    mintedAt: new Date(now - 60000).toISOString(),
    expiresAt: new Date(now + 45 * 60000).toISOString(),
    engine: 'patchright (stealth Playwright + real Chrome)',
  };
  assert.equal(writeVault(entries, { vaultPath }).ok, true);
  return vaultPath;
}

// --- (a) the default fetcher rides the armed ghost chain ------------------------------

test('chain-keyed ride: the DEFAULT fetcher exits the ghost chain with the vault UA+cookie (DNS by the proxy)', async (t) => {
  const socksState = { connects: [] };
  const originState = { hits: [] };
  const socks = mockSocks5(socksState);
  const origin = mockOrigin(originState);
  const pport = await listen(socks);
  const oport = await listen(origin);
  t.after(async () => { await close(origin); await close(socks); });

  const chain = 'socks5://127.0.0.1:' + pport;
  const egressId = chainEgressId(chain);
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain });
  const url = 'http://' + PUBLIC_HOST + ':' + oport + '/';
  const vaultPath = vaultWith(PUBLIC_HOST + ':' + oport, egressId, 'chain-minted');

  const r = await ride(url, { tool: 'raw', egressId, ghost, vaultPath });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.proof.status, 200);
  assert.equal(r.proof.detection.present, false);
  assert.match(r.ride.transport, /ghost chain \(1 hop/);
  // the chain was ridden: the proxy got a CONNECT carrying the PUBLIC NAME (remote DNS --
  // a direct dial would have failed DNS on zone-one.example)
  assert.deepEqual(socksState.connects, [{ host: PUBLIC_HOST, port: oport }]);
  // and the origin saw the vault's EXACT identity
  assert.equal(originState.hits.length, 1);
  assert.equal(originState.hits[0].ua, FAKE_UA);
  assert.equal(originState.hits[0].cookie, 'cf_clearance=chain-minted');
});

test('chain-keyed ride: the crawl sweep rides the SAME chain agents as the proof (vault identity on every hit)', async (t) => {
  const socksState = { connects: [] };
  const originState = { hits: [] };
  const socks = mockSocks5(socksState);
  const origin = mockOrigin(originState);
  const pport = await listen(socks);
  const oport = await listen(origin);
  t.after(async () => { await close(origin); await close(socks); });

  const chain = 'socks5://127.0.0.1:' + pport;
  const egressId = chainEgressId(chain);
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain });
  const url = 'http://' + PUBLIC_HOST + ':' + oport + '/';
  const vaultPath = vaultWith(PUBLIC_HOST + ':' + oport, egressId, 'chain-minted');

  const r = await ride(url, { tool: 'crawl', maxPages: 1, egressId, ghost, vaultPath });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.tool, 'crawl');
  assert.match(r.ride.transport, /ghost chain/);
  assert.ok(socksState.connects.length >= 2, 'proof + crawl page both rode the chain (got ' + socksState.connects.length + ')');
  for (const cn of socksState.connects) assert.deepEqual(cn, { host: PUBLIC_HOST, port: oport });
  assert.ok(originState.hits.length >= 2);
  for (const h of originState.hits) {
    assert.equal(h.ua, FAKE_UA, 'every swept request carries the vault UA');
    assert.equal(h.cookie, 'cf_clearance=chain-minted', 'every swept request carries the vault cookie');
  }
});

test('ghost REQUIRED + verified chain: the ride exits the chain (the verify gate is satisfied)', async (t) => {
  const socksState = { connects: [] };
  const originState = { hits: [] };
  const socks = mockSocks5(socksState);
  const origin = mockOrigin(originState);
  const pport = await listen(socks);
  const oport = await listen(origin);
  t.after(async () => { await close(origin); await close(socks); });

  const chain = 'socks5://127.0.0.1:' + pport;
  const egressId = chainEgressId(chain);
  const ghost = new Ghost();
  ghost.configure({ mode: 'required', chain });
  // preset a satisfied verification (verify() itself is pinned in ghost.test.mjs)
  ghost._verified = { ok: true, baselineIp: '198.51.100.3', exitIp: '203.0.113.7', at: new Date().toISOString() };
  const url = 'http://' + PUBLIC_HOST + ':' + oport + '/';
  const vaultPath = vaultWith(PUBLIC_HOST + ':' + oport, egressId, 'chain-minted');

  const r = await ride(url, { tool: 'raw', egressId, ghost, vaultPath });
  assert.equal(r.ok, true, r.reason);
  assert.deepEqual(socksState.connects, [{ host: PUBLIC_HOST, port: oport }]);
  assert.equal(originState.hits.length, 1);
});

// --- (b) fail-closed postures ----------------------------------------------------------

test('fail-closed: ghost REQUIRED + no chain + public target refuses BEFORE any request (both entry kinds)', async () => {
  const fetcherCalls = [];
  const spyFetcher = async (u) => { fetcherCalls.push(u); return { status: 200, headers: {}, body: CLEAN_PAGE }; };
  // direct-keyed entry: required mode forbids operator-IP egress to public targets
  let vaultPath = vaultWith(PUBLIC_HOST, 'direct', 'op-direct');
  let r = await ride('http://' + PUBLIC_HOST + '/', { tool: 'raw', egressId: 'direct', ghost: new Ghost(), ghostMode: 'required', vaultPath, fetcher: spyFetcher });
  assert.equal(r.ok, false);
  assert.match(r.reason, /REQUIRED/);
  assert.match(r.reason, /fail-closed/);
  // chain-keyed entry: the chain it binds to is not armed
  vaultPath = vaultWith(PUBLIC_HOST, 'socks5://10.64.0.1:1080', 'chain-minted');
  r = await ride('http://' + PUBLIC_HOST + '/', { tool: 'raw', egressId: 'socks5://10.64.0.1:1080', ghost: new Ghost(), ghostMode: 'required', vaultPath, fetcher: spyFetcher });
  assert.equal(r.ok, false);
  assert.match(r.reason, /not armed with a chain/);
  assert.match(r.reason, /fail-closed/);
  assert.equal(fetcherCalls.length, 0, 'not a single fetch attempted');
});

test('fail-closed: entry bound to chain A with ghost armed with chain B -- a different exit IP burns the cookie', async () => {
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: 'socks5://127.0.0.1:9050' });
  const vaultPath = vaultWith(PUBLIC_HOST, 'socks5://10.64.0.1:1080', 'chain-minted');
  const r = await ride('http://' + PUBLIC_HOST + '/', {
    tool: 'raw', egressId: 'socks5://10.64.0.1:1080', ghost, vaultPath,
    fetcher: async () => { throw new Error('must not fetch'); },
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /different exit IP/);
  assert.match(r.reason, /fail-closed/);
});

// --- (c) private/range doctrine ---------------------------------------------------------

test('private/range destination rides DIRECT per ghost doctrine -- even a chain-keyed entry never leaves the lab', async (t) => {
  const socksState = { connects: [] };
  const originState = { hits: [] };
  const socks = mockSocks5(socksState);
  const origin = mockOrigin(originState);
  const pport = await listen(socks);
  const oport = await listen(origin);
  t.after(async () => { await close(origin); await close(socks); });

  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: 'socks5://127.0.0.1:' + pport });
  const url = 'http://127.0.0.1:' + oport + '/';
  // entry keyed to a DIFFERENT (unarmed) chain id: private doctrine trumps the binding
  const vaultPath = vaultWith('127.0.0.1:' + oport, 'socks5://10.64.0.1:1080', 'chain-minted');

  const r = await ride(url, { tool: 'raw', egressId: 'socks5://10.64.0.1:1080', ghost, vaultPath });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.proof.status, 200);
  assert.match(r.ride.transport, /private\/range/);
  assert.equal(socksState.connects.length, 0, 'the chain was NEVER dialed for a lab target');
  assert.equal(originState.hits.length, 1);
  assert.equal(originState.hits[0].ua, FAKE_UA);
});

// --- (e) direct-keyed entries keep direct transport -------------------------------------

test('direct-keyed entry keeps DIRECT transport (ghost off AND ghost on+chain), public target', async () => {
  const fetcherCalls = [];
  const spyFetcher = async (u) => { fetcherCalls.push(u); return { status: 200, headers: {}, body: CLEAN_PAGE }; };
  const url = 'http://' + PUBLIC_HOST + '/';
  const vaultPath = vaultWith(PUBLIC_HOST, 'direct', 'op-direct');
  // ghost off: no identity mandate; the direct-bound cookie rides direct
  let r = await ride(url, { tool: 'raw', egressId: 'direct', ghost: new Ghost(), vaultPath, fetcher: spyFetcher });
  assert.equal(r.ok, true, r.reason);
  assert.match(r.ride.transport, /^direct/);
  // ghost on + armed chain: best-effort mode still honors the entry's binding (the
  // transport matches the VAULT, not the armed chain) -- the dead hop proves it is
  // never dialed
  const armed = new Ghost();
  armed.configure({ mode: 'on', chain: 'socks5://127.0.0.1:1' });
  r = await ride(url, { tool: 'raw', egressId: 'direct', ghost: armed, vaultPath, fetcher: spyFetcher });
  assert.equal(r.ok, true, r.reason);
  assert.match(r.ride.transport, /best-effort/);
  assert.equal(fetcherCalls.length, 2);
});

// --- the pre-existing honesty contract, re-pinned against the new gate ------------------

test('honesty gate: a challenged proof reports clearance-failure with evidence (never a fake ride)', async () => {
  const vaultPath = vaultWith(PUBLIC_HOST, 'direct', 'op-direct');
  const r = await ride('http://' + PUBLIC_HOST + '/', {
    tool: 'crawl', egressId: 'direct', ghost: new Ghost(), vaultPath,
    fetcher: async () => ({ status: 403, headers: { 'cf-mitigated': 'challenge' }, body: CF_CHALLENGE_BODY }),
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /CHALLENGED/);
  assert.equal(r.proof.status, 403);
});

test('honesty: no clearance / bad URL are ok:false, never throw, and never touch the transport gate', async () => {
  const r1 = await ride('http://' + PUBLIC_HOST + '/', { egressId: 'direct', ghost: new Ghost(), vaultPath: tmpVault() });
  assert.equal(r1.ok, false);
  assert.match(r1.reason, /no valid clearance/);
  const r2 = await ride('not-a-url', { ghost: new Ghost(), vaultPath: tmpVault() });
  assert.equal(r2.ok, false);
  assert.match(r2.reason, /no valid clearance/);
});

// --- --full-body: the uncapped evidence pull -------------------------------------
// The default stays capped at 64KB (a challenge page is small); --full-body returns
// the UNCAPPED body while the challenge gate keeps classifying the calibrated window.

test('full-body: default raw stays capped at 64KB; --full-body returns the UNCAPPED body', async (t) => {
  const BIG = '<html><head><title>Big Page</title></head><body><main>' + 'evidence line, no challenge here '.repeat(8000) + '</main></body></html>';
  assert.ok(BIG.length > 65536 * 2, 'the fixture is well past the cap (' + BIG.length + ' bytes)');
  const origin = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(BIG);
  });
  const oport = await listen(origin);
  t.after(async () => { await close(origin); });

  const zone = '127.0.0.1:' + oport; // private/range: direct per ghost doctrine
  const vaultPath = vaultWith(zone, 'direct', 'op-direct');
  const url = 'http://' + zone + '/big';

  const capped = await ride(url, { tool: 'raw', egressId: 'direct', ghost: new Ghost(), vaultPath });
  assert.equal(capped.ok, true, capped.reason);
  assert.equal(capped.result.status, 200);
  assert.equal(capped.result.body.length, 65536, 'default behavior is unchanged: the body caps at BODY_CAP');
  assert.equal(capped.result.bodyCapped, undefined, 'no full-body annotations by default');

  const full = await ride(url, { tool: 'raw', egressId: 'direct', ghost: new Ghost(), vaultPath, fullBody: true });
  assert.equal(full.ok, true, full.reason);
  assert.equal(full.result.body.length, BIG.length, 'the UNCAPPED body rides for evidence pulls');
  assert.equal(full.result.bodyCapped, false);
  assert.equal(full.result.bodyBytes, BIG.length);
  assert.equal(full.proof.detection.present, false, 'the gate still classifies the calibrated window (no false challenge)');
});
