// sessride.test.mjs -- hermetic pins for the governed session ride (vault clearance +
// authenticated cookie jar in ONE request path). The cfride.test.mjs harness pattern:
// a LOCAL mock SOCKS5 proxy + LOCAL origin prove the chain-ridden path (the public
// target name never resolves locally, so a successful ride PROVES the request rode the
// chain); the gate refusal paths are pinned with an injected spy fetcher and never
// touch a socket. Nothing leaves loopback, ever.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { readFileSync, writeFileSync } from 'node:fs';
import { sessRide, mergeCookies, readJar, authEvidence } from '../tools/sessride.mjs';
import { Ghost, chainEgressId } from '../engine/ghost.mjs';
import { vaultKey, writeVault } from '../tools/clearance/broker.mjs';

const FAKE_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const PUBLIC_HOST = 'zone-one.example'; // unresolvable locally: direct egress would fail DNS
const SCOPE_LOCAL = '127.0.0.0/8';
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

// SOCKS5 mock (the cfride/ghost.test.mjs pattern): completes the handshake, records the
// CONNECT target, then tunnels by CONNECT PORT to 127.0.0.1 -- the public NAME travels
// to the proxy (remote-DNS doctrine) and the loopback origin answers through the tunnel.
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
// opts.setCookie: one set-cookie line emitted on every response.
function mockOrigin(state, { setCookie } = {}) {
  return http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      state.hits.push({ method: req.method, url: req.url, host: req.headers.host, ua: req.headers['user-agent'], cookie: req.headers.cookie || '', contentType: req.headers['content-type'] || '', body });
      const headers = { 'content-type': 'text/html' };
      if (setCookie) headers['set-cookie'] = [setCookie];
      res.writeHead(200, headers);
      res.end(CLEAN_PAGE);
    });
  });
}

function tmpFile(prefix) {
  return join(tmpdir(), prefix + process.pid + '-' + Math.random().toString(36).slice(2) + '.json');
}

// A vault holding ONE valid entry for zone under egressId (the mint-side keying).
function vaultWith(zone, egressId, cookieValue) {
  const vaultPath = tmpFile('sessride-vault-');
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

// --- merge order (the DEFINED contract) -------------------------------------

test('merge: jar lays the base in file order, vault clearance OVERLAYS name collisions', () => {
  const m = mergeCookies({
    jar: [['wordpress_logged_in_abc', 'user|token'], ['cf_clearance', 'STALE-JAR-COPY'], ['_gid', 'ga']],
    clearance: [{ name: 'cf_clearance', value: 'VAULT-FRESH' }],
  });
  assert.equal(m.explicit, false);
  // order: jar order preserved; the vault value wins the cf_clearance collision
  assert.equal(m.header, 'wordpress_logged_in_abc=user|token; cf_clearance=VAULT-FRESH; _gid=ga');
  assert.deepEqual(m.sent, ['wordpress_logged_in_abc', 'cf_clearance', '_gid']);
  assert.deepEqual(m.fromJar, ['wordpress_logged_in_abc', 'cf_clearance', '_gid']);
  assert.deepEqual(m.fromClearance, ['cf_clearance']);
});

test('merge: an explicit Cookie header REPLACES the merge entirely (and says so)', () => {
  const m = mergeCookies({
    jar: [['wordpress_logged_in_abc', 'user|token']],
    clearance: [{ name: 'cf_clearance', value: 'VAULT-FRESH' }],
    explicitCookie: 'session=operator-literal; cf_clearance=operator-value',
  });
  assert.equal(m.explicit, true);
  assert.equal(m.header, 'session=operator-literal; cf_clearance=operator-value');
  assert.deepEqual(m.sent, ['session', 'cf_clearance']);
});

// --- the jar file contract ----------------------------------------------------

test('readJar: a missing file is an empty jar WITH A NOTE (the first-run signin case)', () => {
  const missing = readJar(tmpFile('sessride-jar-'));
  assert.equal(missing.ok, true);
  assert.deepEqual(missing.entries, []);
  assert.match(missing.note, /EMPTY jar/);
});

test('readJar: corrupt JSON, non-array, and malformed pairs are plain refusals', () => {
  const p1 = tmpFile('sessride-jar-');
  writeFileSync(p1, '{not json');
  assert.match(readJar(p1).error, /not valid JSON/);
  const p2 = tmpFile('sessride-jar-');
  writeFileSync(p2, '{"a":1}');
  assert.match(readJar(p2).error, /array of \[name, value\] pairs/);
  const p3 = tmpFile('sessride-jar-');
  writeFileSync(p3, '[["ok","v"],["broken"]]');
  assert.match(readJar(p3).error, /malformed/);
  const p4 = tmpFile('sessride-jar-');
  writeFileSync(p4, '[["wordpress_logged_in_x","u|t"],["n",42]]');
  const good = readJar(p4);
  assert.equal(good.ok, true);
  assert.deepEqual(good.entries, [['wordpress_logged_in_x', 'u|t'], ['n', '42']], 'values coerce to strings');
});

// --- the governed ride over loopback -------------------------------------------

test('ride: jar + clearance ride the SAME request (vault UA pinned); set-cookie persists to the jar, never the vault value', async (t) => {
  const originState = { hits: [] };
  const origin = mockOrigin(originState, { setCookie: 'wp_last=rotated-1; Path=/; HttpOnly' });
  const oport = await listen(origin);
  t.after(async () => { await close(origin); });

  const zone = '127.0.0.1:' + oport;
  const vaultPath = vaultWith(zone, 'direct', 'vault-clearance-val');
  const jarPath = tmpFile('sessride-jar-');
  writeFileSync(jarPath, JSON.stringify([['wordpress_logged_in_abc', 'user|token'], ['cf_clearance', 'STALE-JAR-COPY']]));

  const r = await sessRide('http://' + zone + '/user-settings/', { scope: SCOPE_LOCAL, ghost: new Ghost(), vaultPath, jarPath });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.status, 200);
  assert.equal(originState.hits.length, 1);
  const hit = originState.hits[0];
  assert.equal(hit.ua, FAKE_UA, 'the vault EXACT UA rides');
  // the merge on the wire: jar base + VAULT clearance value (not the stale jar copy)
  assert.equal(hit.cookie, 'wordpress_logged_in_abc=user|token; cf_clearance=vault-clearance-val');
  // the report names what was sent, per source, names only
  assert.deepEqual(r.cookies.sent, ['wordpress_logged_in_abc', 'cf_clearance']);
  assert.deepEqual(r.cookies.fromClearance, ['cf_clearance']);
  assert.equal(r.cookies.explicitHeader, false);
  // set-cookie persisted to the JAR FILE; the vault's clearance value never lands in it
  assert.deepEqual(r.setCookies, ['wp_last']);
  assert.match(r.headers['set-cookie'][0], /^wp_last=<redacted/, 'set-cookie values are redacted in the report');
  const onDisk = JSON.parse(readFileSync(jarPath, 'utf8'));
  assert.equal(onDisk.find((p) => p[0] === 'wp_last')[1], 'rotated-1', 'server-set cookie persisted');
  assert.equal(onDisk.find((p) => p[0] === 'cf_clearance')[1], 'STALE-JAR-COPY', 'the vault clearance value is NEVER written into the jar');
});

test('ride: POST carries body + content-type through the same governed path', async (t) => {
  const originState = { hits: [] };
  const origin = mockOrigin(originState);
  const oport = await listen(origin);
  t.after(async () => { await close(origin); });

  const zone = '127.0.0.1:' + oport;
  const vaultPath = vaultWith(zone, 'direct', 'vault-clearance-val');
  const r = await sessRide('http://' + zone + '/wp-admin/admin-ajax.php', {
    scope: SCOPE_LOCAL, ghost: new Ghost(), vaultPath,
    jar: [['wordpress_logged_in_abc', 'user|token']],
    method: 'POST', body: 'action=wp_manga_signin&login=u', contentType: 'application/x-www-form-urlencoded',
  });
  assert.equal(r.ok, true, r.reason);
  assert.equal(originState.hits[0].method, 'POST');
  assert.equal(originState.hits[0].body, 'action=wp_manga_signin&login=u');
  assert.equal(originState.hits[0].contentType, 'application/x-www-form-urlencoded');
  assert.match(originState.hits[0].cookie, /wordpress_logged_in_abc=user\|token/);
});

// --- governance: signed scope (fail-closed, BEFORE any request) -----------------

test('scope: no scope / out-of-scope are refused BEFORE any request; the refusal prints the signed CIDRs', async () => {
  const fetcherCalls = [];
  const spyFetcher = async (u) => { fetcherCalls.push(u); return { status: 200, headers: {}, body: CLEAN_PAGE }; };
  const vaultPath = vaultWith(PUBLIC_HOST, 'direct', 'op-direct');
  // no scope at all
  let r = await sessRide('http://' + PUBLIC_HOST + '/', { ghost: new Ghost(), vaultPath, jar: [['a', 'b']], fetcher: spyFetcher });
  assert.equal(r.ok, false);
  assert.match(r.reason, /no signed engagement scope/);
  assert.match(r.reason, /fail-closed/);
  // scope present, host resolves outside it (injected resolver -- hermetic)
  r = await sessRide('http://' + PUBLIC_HOST + '/', {
    scope: '10.0.0.0/8', ghost: new Ghost(), vaultPath, jar: [['a', 'b']], fetcher: spyFetcher,
    resolve: async () => ['203.0.113.10'],
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /outside the signed engagement scope/);
  assert.match(r.reason, /10\.0\.0\.0\/8/, 'the refusal prints the signed scope');
  assert.equal(fetcherCalls.length, 0, 'not a single fetch attempted');
});

// --- governance: ghost egress parity (the cfride wiring) -------------------------

test('fail-closed: ghost REQUIRED + public target refuses BEFORE any request (direct- and chain-keyed entries)', async () => {
  const fetcherCalls = [];
  const spyFetcher = async (u) => { fetcherCalls.push(u); return { status: 200, headers: {}, body: CLEAN_PAGE }; };
  // direct-keyed entry: required mode forbids operator-IP egress to public targets
  let vaultPath = vaultWith(PUBLIC_HOST, 'direct', 'op-direct');
  let r = await sessRide('http://' + PUBLIC_HOST + '/', { scope: '203.0.113.0/24', resolve: async () => ['203.0.113.10'], ghost: new Ghost(), ghostMode: 'required', vaultPath, jar: [['a', 'b']], fetcher: spyFetcher });
  assert.equal(r.ok, false);
  assert.match(r.reason, /REQUIRED/);
  assert.match(r.reason, /fail-closed/);
  // chain-keyed entry: the chain it binds to is not armed
  vaultPath = vaultWith(PUBLIC_HOST, 'socks5://10.64.0.1:1080', 'chain-minted');
  r = await sessRide('http://' + PUBLIC_HOST + '/', { scope: '203.0.113.0/24', resolve: async () => ['203.0.113.10'], egressId: 'socks5://10.64.0.1:1080', ghost: new Ghost(), ghostMode: 'required', vaultPath, jar: [['a', 'b']], fetcher: spyFetcher });
  assert.equal(r.ok, false);
  assert.match(r.reason, /not armed with a chain/);
  assert.match(r.reason, /fail-closed/);
  assert.equal(fetcherCalls.length, 0, 'not a single fetch attempted');
});

test('chain-keyed ride: the session rides the ghost chain with BOTH identities (DNS by the proxy)', async (t) => {
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
  const zone = PUBLIC_HOST + ':' + oport;
  const vaultPath = vaultWith(zone, egressId, 'chain-minted');

  const r = await sessRide('http://' + zone + '/user-settings/', {
    scope: '203.0.113.0/24', resolve: async () => ['203.0.113.10'], // the scope gate, hermetic
    ghost, vaultPath, jar: [['wordpress_logged_in_abc', 'user|token']],
  });
  assert.equal(r.ok, true, r.reason);
  // the chain was ridden: the proxy got a CONNECT carrying the PUBLIC NAME
  assert.deepEqual(socksState.connects, [{ host: PUBLIC_HOST, port: oport }]);
  // and the origin saw BOTH identities at the vault's exact UA
  assert.equal(originState.hits.length, 1);
  assert.equal(originState.hits[0].ua, FAKE_UA);
  assert.equal(originState.hits[0].cookie, 'wordpress_logged_in_abc=user|token; cf_clearance=chain-minted');
  assert.match(r.ride.transport, /ghost chain/);
});

// --- honesty: challenged / transport failure / jar required ----------------------

test('honesty gate: a challenged response is ok:false WITH the evidence (never a claimed action)', async () => {
  const vaultPath = vaultWith('127.0.0.1', 'direct', 'op-direct');
  const r = await sessRide('http://127.0.0.1/', {
    scope: SCOPE_LOCAL, ghost: new Ghost(), vaultPath, jar: [['a', 'b']],
    fetcher: async () => ({ status: 403, headers: { 'cf-mitigated': 'challenge' }, body: CF_CHALLENGE_BODY }),
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /CHALLENGED/);
  assert.equal(r.proof.status, 403);
});

test('honesty: a transport failure is plain data (ok:false), never a claimed action', async () => {
  const vaultPath = vaultWith('127.0.0.1', 'direct', 'op-direct');
  const r = await sessRide('http://127.0.0.1/', {
    scope: SCOPE_LOCAL, ghost: new Ghost(), vaultPath, jar: [['a', 'b']],
    fetcher: async () => ({ status: 0, error: 'ghost chain unavailable -- public egress refused' }),
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /transport failure/);
  assert.match(r.reason, /nothing can be claimed/);
});

test('honesty: no jar is a plain refusal (the tool rides BOTH identities, by definition)', async () => {
  const vaultPath = vaultWith('127.0.0.1', 'direct', 'op-direct');
  const r = await sessRide('http://127.0.0.1/', { scope: SCOPE_LOCAL, ghost: new Ghost(), vaultPath });
  assert.equal(r.ok, false);
  assert.match(r.reason, /no session jar supplied/);
  const bad = tmpFile('sessride-jar-');
  writeFileSync(bad, '{oops');
  const r2 = await sessRide('http://127.0.0.1/', { scope: SCOPE_LOCAL, ghost: new Ghost(), vaultPath, jarPath: bad });
  assert.equal(r2.ok, false);
  assert.match(r2.reason, /not valid JSON/);
});

// --- redirect governance: scope re-check per hop, session never leaves its host -----

test('redirects: a same-host relative redirect is followed (host header exact -- the manhuaus.comc regression pin)', async (t) => {
  const state = { hits: [] };
  const origin = http.createServer((req, res) => {
    state.hits.push({ url: req.url, host: req.headers.host, cookie: req.headers.cookie || '' });
    if (req.url === '/jump') {
      res.writeHead(302, { location: '/next' });
      return res.end();
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(CLEAN_PAGE);
  });
  const oport = await listen(origin);
  t.after(async () => { await close(origin); });

  const zone = '127.0.0.1:' + oport;
  const vaultPath = vaultWith(zone, 'direct', 'vault-clearance-val');
  const r = await sessRide('http://' + zone + '/jump', { scope: SCOPE_LOCAL, ghost: new Ghost(), vaultPath, jar: [['a', 'b']] });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.redirectHops, 1);
  assert.match(r.finalUrl, /\/next$/);
  assert.deepEqual(state.hits.map((h) => h.url), ['/jump', '/next']);
  for (const h of state.hits) {
    assert.equal(h.host, zone, 'the Host header is EXACTLY the parsed URL host -- never a concatenation');
    assert.match(h.cookie, /cf_clearance=vault-clearance-val/, 'the session rides every same-host hop');
  }
});

test('redirects: a cross-host Location is reported as data, NEVER followed with the session (credential-leak guard)', async (t) => {
  const otherState = { hits: [] };
  const other = mockOrigin(otherState);
  const otherPort = await listen(other);
  const origin = http.createServer((req, res) => {
    res.writeHead(302, { location: 'http://127.0.0.1:' + otherPort + '/stolen' });
    res.end();
  });
  const oport = await listen(origin);
  t.after(async () => { await close(origin); await close(other); });

  const zone = '127.0.0.1:' + oport;
  const vaultPath = vaultWith(zone, 'direct', 'vault-clearance-val');
  const r = await sessRide('http://' + zone + '/jump', { scope: SCOPE_LOCAL, ghost: new Ghost(), vaultPath, jar: [['a', 'b']] });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.status, 302);
  assert.ok(r.redirectRefused, 'the cross-host refusal is reported');
  assert.match(r.redirectRefused.reason, /never leaves its host/);
  assert.equal(otherState.hits.length, 0, 'the session NEVER touched the other host');
});

// --- authcheck: evidence, never proof ---------------------------------------------

test('authEvidence: verdicts come from observable markers only (a hollow 200 is UNVERIFIABLE, never authenticated)', () => {
  // authenticated chrome
  const auth = authEvidence({ status: 200, body: '<html><body><div id="wpadminbar" class="wp-admin-bar"></div><a href="https://x/wp-login.php?action=logout">Log Out</a></body></html>' });
  assert.equal(auth.verdict, 'looks-authenticated');
  assert.ok(auth.evidenceFor.length >= 2);
  assert.match(auth.caveat, /never proof/);
  // anonymous: redirected to the login form
  const anon = authEvidence({ status: 200, finalUrl: 'https://x/wp-login.php?redirect_to=%2F', body: '<form id="loginform"><input name="log"><input name="pwd"></form>' });
  assert.equal(anon.verdict, 'looks-anonymous');
  assert.ok(anon.evidenceAgainst.length >= 2);
  // THE CALIBRATION PIN: a bare 200 with no markers asserts NOTHING
  const hollow = authEvidence({ status: 200, body: '<html><body>generic cached page</body></html>' });
  assert.equal(hollow.verdict, 'unverifiable');
  // both sides firing is reported as conflict, never resolved silently
  const both = authEvidence({ status: 200, body: '<div id="wpadminbar"></div><form id="loginform"><input name="log"><input name="pwd"></form>' });
  assert.equal(both.verdict, 'conflicting-evidence');
});

test('authcheck mode: the verdict rides the governed result as EVIDENCE (not proof)', async () => {
  const vaultPath = vaultWith('127.0.0.1', 'direct', 'op-direct');
  const r = await sessRide('http://127.0.0.1/user-settings/', {
    scope: SCOPE_LOCAL, ghost: new Ghost(), vaultPath, jar: [['wordpress_logged_in_abc', 'user|token']], mode: 'authcheck',
    fetcher: async () => ({ status: 200, headers: {}, body: '<html><body><div id="wpadminbar"></div><a href="/wp-login.php?action=logout">Log Out</a>account settings here</body></html>' }),
  });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.authState.verdict, 'looks-authenticated');
  assert.match(r.authState.caveat, /EVIDENCE, never proof/);
});
