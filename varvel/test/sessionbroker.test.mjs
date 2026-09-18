// VARVEL sessionbroker tests — the real-browser session broker (winner-copyables
// build, Tool 1). Hermetic: injected probe/transport/relogin fakes + one loopback
// 127.0.0.1 lab for the default probe. No live network, no ghost chain, no browser.
//   node --test varvel/test/sessionbroker.test.mjs
//
// Pinned: a session is 'live' ONLY on an expected canary status; transport failure is
// 'unknown' (NEVER dead, never alive); a dead canary triggers refresh then relogin in
// that order; refresh-only entries recover without a browser; a script relogin fires
// ONLY under allowSpawn; secrets are masked in listSessions; migration harvests canary
// endpoints from the captured XHR journals (never invents routes).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  SESSION_CAPS, registerSession, loadSession, listSessions, cookieHeaderFor,
  handleFor, defaultProbe, canaryVerdict, checkSession, refreshSession,
  reloginSession, getLiveSession, migrateLegacySessions,
} from '../tools/sessionbroker.mjs';

const NOW = '2026-08-31T12:00:00.000Z';
const LATER = '2026-09-01T12:00:00.000Z';
const tmp = () => mkdtempSync(join(tmpdir(), 'varvel-sb-'));

const entry = (over = {}) => ({
  program: 'demo', label: 'a',
  session: { cookies: [{ name: 'sess', value: 'SECRET-COOKIE-VALUE', domain: '.example.com' }] },
  canary: { method: 'GET', url: 'https://app.example.com/api/me', auth: 'cookie', expectStatus: [200], denyStatus: [401, 403], harvestedFrom: 'test' },
  ...over,
});

const probeReturns = (res) => async () => res;

test('registerSession validates shape and persists; secrets on disk, masked in list', () => {
  const dir = tmp();
  assert.equal(registerSession(null, { dir }).error, 'bad-entry');
  assert.equal(registerSession({ program: '!!', label: 'a', session: { cookies: [{ name: 'x', value: 'y' }] }, canary: { url: 'https://x' } }, { dir }).error, 'bad-slug');
  assert.equal(registerSession({ program: 'demo', label: 'a', session: {}, canary: { url: 'https://x' } }, { dir }).error, 'no-credentials');
  assert.equal(registerSession({ program: 'demo', label: 'a', session: { cookies: [{ name: 'x', value: 'y' }] } }, { dir }).error, 'no-canary');

  const r = registerSession(entry(), { dir, now: NOW });
  assert.equal(r.ok, true);
  assert.equal(registerSession(entry(), { dir, now: NOW }).error, 'already-registered', 'a silent overwrite is refused');
  assert.equal(registerSession(entry(), { dir, now: NOW, replace: true }).ok, true);

  const loaded = loadSession('demo', 'a', { dir });
  assert.equal(loaded.session.cookies[0].value, 'SECRET-COOKIE-VALUE', 'the store holds the real credential');
  assert.equal(loaded.health.state, 'never-checked');
  assert.equal(loadSession('demo', 'zzz', { dir }), null);

  const list = listSessions({ dir });
  assert.equal(list.sessions.length, 1);
  assert.equal(list.sessions[0].cookies[0].value, '<stored:19 chars>', 'list masks the secret');
  assert.ok(!JSON.stringify(list).includes('SECRET-COOKIE-VALUE'), 'no secret anywhere in the listing');
});

test('cookieHeaderFor follows the browser domain rule; handleFor is the authzsweep shape', () => {
  const e = entry();
  assert.equal(cookieHeaderFor(e, 'https://app.example.com/x'), 'sess=SECRET-COOKIE-VALUE');
  assert.equal(cookieHeaderFor(e, 'https://example.com/x'), 'sess=SECRET-COOKIE-VALUE', 'leading-dot parent matches the bare host');
  assert.equal(cookieHeaderFor(e, 'https://other.org/x'), null, 'foreign host gets nothing');
  const h = handleFor(e);
  assert.deepEqual(Object.keys(h).sort(), ['cookie', 'headers', 'label', 'program', 'sessionLabel'].sort());
  assert.equal(h.label, 'demo-a');
  assert.equal(h.cookie, 'sess=SECRET-COOKIE-VALUE');
});

test('canaryVerdict: alive only on expected status; transport failure is unknown, never dead', () => {
  const e = entry();
  assert.equal(canaryVerdict(e, { status: 200, body: '{"me":1}' }).state, 'alive');
  assert.equal(canaryVerdict(e, { status: 401, body: '' }).state, 'dead');
  assert.equal(canaryVerdict(e, { status: 403, body: '' }).state, 'dead');
  assert.equal(canaryVerdict(e, null).state, 'unknown');
  assert.equal(canaryVerdict(e, { status: 500, body: '' }).state, 'unknown', 'a 5xx is neither alive nor dead');
  const e2 = entry({ canary: { url: 'https://app.example.com/api/me', expectStatus: [200], denyStatus: [401], denyBodyRe: 'please log in' } });
  assert.equal(canaryVerdict(e2, { status: 200, body: 'Welcome, please log in to continue' }).state, 'dead', 'a 200 login page is DEAD, not alive');
});

test('checkSession journals health; getLiveSession hands a live handle on a green canary', async () => {
  const dir = tmp();
  registerSession(entry(), { dir, now: NOW });
  const r = await getLiveSession('demo', 'a', { dir, probe: probeReturns({ status: 200, body: '{"me":true}' }), now: NOW });
  assert.equal(r.ok, true);
  assert.equal(r.state, 'live');
  assert.equal(r.session.cookie, 'sess=SECRET-COOKIE-VALUE');
  assert.equal(r.checks.length, 1);
  assert.equal(r.checks[0].step, 'canary');
  const reloaded = loadSession('demo', 'a', { dir });
  assert.equal(reloaded.health.state, 'alive');
  assert.equal(reloaded.health.history.length, 1, 'the verdict is journaled on disk');
});

test('unknown canary (transport failure) is NEVER handed out as live', async () => {
  const dir = tmp();
  registerSession(entry(), { dir, now: NOW });
  const r = await getLiveSession('demo', 'a', { dir, probe: probeReturns(null), now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'canary-unverifiable');
  assert.equal(r.session, undefined, 'no unverified session handle');
  assert.equal(loadSession('demo', 'a', { dir }).health.state, 'unknown');
});

test('dead canary → refresh recipe → re-canary: refresh-only recovery, no browser', async () => {
  const dir = tmp();
  const e = entry({
    refresh: { url: 'https://id.example.com/token/refresh', method: 'POST', useCookies: true, tokenPath: 'accessToken', ttlSeconds: 86400 },
  });
  e.canary.auth = 'bearer';
  e.session.headers = { authorization: 'Bearer OLD-TOKEN' };
  registerSession(e, { dir, now: NOW });
  const seen = { refreshCalls: 0, canaryAuth: [] };
  const transport = async ({ url }) => {
    seen.refreshCalls++;
    assert.equal(url, 'https://id.example.com/token/refresh');
    return { status: 200, headers: { 'set-cookie': ['fe_refresh_x=ROTATED; Domain=.example.com; Path=/'] }, json: { accessToken: 'NEW-TOKEN', expiresIn: 86400 } };
  };
  const probe = async ({ headers }) => {
    seen.canaryAuth.push(headers && headers.authorization);
    return seen.canaryAuth.length === 1 ? { status: 401, body: '' } : { status: 200, body: '{"me":true}' };
  };
  const r = await getLiveSession('demo', 'a', { dir, probe, transport, now: NOW });
  assert.equal(r.ok, true);
  assert.equal(r.state, 'refreshed');
  assert.equal(seen.refreshCalls, 1);
  assert.deepEqual(seen.canaryAuth, ['Bearer OLD-TOKEN', 'Bearer NEW-TOKEN'], 'the canary re-ran with the refreshed bearer');
  assert.equal(r.session.headers.authorization, 'Bearer NEW-TOKEN');
  const saved = loadSession('demo', 'a', { dir });
  assert.equal(saved.session.cookies.find((c) => c.name === 'fe_refresh_x').value, 'ROTATED', 'a rotated refresh cookie is merged, never dropped');
  assert.ok(Date.parse(saved.expiresAt) > Date.parse(NOW), 'expiry extended');
});

test('expired metadata refreshes BEFORE the canary spends a request', async () => {
  const dir = tmp();
  const e = entry({
    expiresAt: '2026-08-31T00:00:00.000Z', // already expired at NOW
    refresh: { url: 'https://id.example.com/token/refresh', tokenPath: 'accessToken' },
  });
  registerSession(e, { dir, now: NOW });
  const order = [];
  const transport = async () => { order.push('refresh'); return { status: 200, headers: {}, json: { accessToken: 'T2' } }; };
  const probe = async () => { order.push('canary'); return { status: 200, body: '{}' }; };
  const r = await getLiveSession('demo', 'a', { dir, probe, transport, now: NOW });
  assert.equal(r.ok, true);
  assert.deepEqual(order, ['refresh', 'canary']);
});

test('refresh refused → injected relogin → re-canary: full recovery ladder', async () => {
  const dir = tmp();
  const e = entry({
    refresh: { url: 'https://id.example.com/token/refresh', tokenPath: 'accessToken' },
    relogin: { kind: 'manual', note: 'browser recipe pending' },
  });
  registerSession(e, { dir, now: NOW });
  const transport = async () => ({ status: 401, headers: {}, json: null, body: 'expired refresh' });
  let canaryCalls = 0;
  const probe = async () => ({ status: ++canaryCalls === 1 ? 401 : 200, body: '{}' });
  const relogin = async () => ({ session: { cookies: [{ name: 'sess', value: 'FRESH-COOKIE', domain: '.example.com' }] } });
  const r = await getLiveSession('demo', 'a', { dir, probe, transport, relogin, now: NOW });
  assert.equal(r.ok, true);
  assert.equal(r.state, 'reauthed');
  assert.equal(r.session.cookie, 'sess=FRESH-COOKIE');
  assert.deepEqual(r.checks.map((c) => c.step), ['canary', 'refresh:dead-canary', 'relogin', 'canary:post-relogin']);
});

test('dead + no working recovery = honest session-dead with the recipe named', async () => {
  const dir = tmp();
  const e = entry({ relogin: { kind: 'script', command: 'node .tmp/zom-signup.mjs a', resultPath: '.tmp/zom-signup-a-result.json' } });
  registerSession(e, { dir, now: NOW });
  const r = await getLiveSession('demo', 'a', { dir, probe: probeReturns({ status: 401, body: '' }), now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'session-dead');
  assert.match(r.reason, /DEAD/);
  assert.equal(r.relogin.command, 'node .tmp/zom-signup.mjs a', 'the recovery recipe is named for the operator');
  assert.equal(loadSession('demo', 'a', { dir }).health.state, 'dead');
});

test('script relogin fires ONLY under allowSpawn; spawn+resultPath refresh the store', async () => {
  const dir = tmp();
  const e = entry({ relogin: { kind: 'script', command: 'node fake-login.mjs a', resultPath: '.tmp/fake-result.json' } });
  registerSession(e, { dir, now: NOW });
  const r1 = await reloginSession(loadSession('demo', 'a', { dir }), { now: NOW });
  assert.equal(r1.error, 'relogin-not-armed', 'a headed browser login is never fired silently from a library call');

  const tmpRoot = tmp();
  mkdirSync(join(tmpRoot, '.tmp'), { recursive: true });
  writeFileSync(join(tmpRoot, '.tmp', 'fake-result.json'), JSON.stringify({ cookies: [{ name: 'sess', value: 'SPAWNED', domain: '.example.com' }] }));
  // spawn fake: the REPO-relative resultPath won't exist under the real repo — inject
  // a relogin fn for the read-back leg instead (script execution itself is the operator's).
  const r2 = await reloginSession(loadSession('demo', 'a', { dir }), {
    allowSpawn: true, now: NOW,
    spawn: async (cmd, args) => { assert.equal(cmd, 'node'); assert.deepEqual(args, ['fake-login.mjs', 'a']); return true; },
  });
  assert.equal(r2.ok, false); // resultPath unreadable under the real repo — honest failure
  assert.equal(r2.error, 'relogin-no-session');
});

test('migration harvests canaries from the captured journals — never invented routes', () => {
  const dir = tmp();
  const tmpRoot = tmp();
  writeFileSync(join(tmpRoot, 'zom-harvest-a.json'), JSON.stringify({
    email: 'varvel-zom-a@example.com',
    cookies: [{ name: 'PHPSESSID', value: 'ZM-A', domain: '.zomato.com' }, { name: 'csrf', value: 'C-A', domain: '.zomato.com' }],
    xhr: [
      { method: 'GET', url: 'https://www.zomato.com/webroutes/auth/init', status: 200 },
      { method: 'GET', url: 'https://www.zomato.com/php/get_user_notifications.php?action=get-unread-notification-count&user_id=447585412', status: 200 },
    ],
  }));
  writeFileSync(join(tmpRoot, 'zom-signup-b-result.json'), JSON.stringify({
    email: 'varvel-zom-b@example.com',
    cookies: [{ name: 'PHPSESSID', value: 'ZM-B', domain: '.zomato.com' }],
  }));
  // b has NO harvest journal — honestly skipped, not given an invented canary
  writeFileSync(join(tmpRoot, 'fe-login-a-result.json'), JSON.stringify({
    email: 'varvel-fe-a@example.com',
    cookies: [{ name: 'fe_refresh_abc', value: 'FR-A', domain: '.frontegg-prod.au.frontegg.com' }, { name: '_ga', value: 'G', domain: '.frontegg.com' }],
  }));
  const r = migrateLegacySessions({ tmp: tmpRoot, dir, now: NOW });
  assert.equal(r.ok, true);
  assert.deepEqual(r.registered.map((s) => `${s.program}-${s.label}`), ['zomato-a', 'frontegg-a']);
  assert.equal(r.skipped.length, 2, 'zomato-b (no journal) and frontegg-b (no file) are honestly skipped');
  assert.ok(r.skipped.some((s) => /no authenticated XHR/.test(s.reason)));

  const z = loadSession('zomato', 'a', { dir });
  assert.match(z.canary.url, /user_id=447585412/, 'the canary is the harvested authenticated endpoint, user id included');
  assert.equal(z.canary.denyBodyRe, 'Unauthorized request');
  assert.equal(z.relogin.command, 'node .tmp/zom-signup.mjs a');
  assert.equal(z.health.state, 'never-checked', 'migration performs NO network — health is honestly unchecked');

  const f = loadSession('frontegg', 'a', { dir });
  assert.equal(f.refresh.url, 'https://frontegg-prod.au.frontegg.com/frontegg/identity/resources/auth/v1/user/token/refresh');
  assert.equal(f.refresh.ttlSeconds, 86400);
  assert.equal(f.canary.auth, 'bearer');
  assert.ok(!f.session.cookies.some((c) => c.name === '_ga'), 'analytics cookies stay out of the managed session');
});

test('defaultProbe against a loopback lab: cookie rides, status/body return, never throws', async () => {
  const srv = http.createServer((req, res) => {
    if (req.headers.cookie === 'sess=LAB') { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"me":true}'); }
    else { res.writeHead(401); res.end('{}'); }
  });
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const base = `http://127.0.0.1:${srv.address().port}`;
    const probe = defaultProbe({ timeoutMs: 3000 });
    const ok = await probe({ method: 'GET', url: base + '/api/me', cookie: 'sess=LAB' });
    assert.equal(ok.status, 200);
    assert.match(ok.body, /"me":true/);
    const no = await probe({ method: 'GET', url: base + '/api/me' });
    assert.equal(no.status, 401);
    const dead = await probe({ method: 'GET', url: 'http://127.0.0.1:1/none' });
    assert.equal(dead, null, 'transport failure resolves null, never throws');
  } finally { await new Promise((r) => srv.close(r)); }
});

test('caps exist and are sane', () => {
  assert.ok(SESSION_CAPS.maxCookies >= 16);
  assert.ok(SESSION_CAPS.canaryTimeoutMs >= 5000);
});

// ——— campaign wiring (the broker→authz seam): authz accounts may name a
// sessionRef 'program:label' instead of a literal cookie; runAuthzSweep resolves a
// LIVE session through the broker before provisioning. Hermetic: getLiveSessionImpl
// fake, loopback cookie lab. Pinned: the broker-supplied cookie reaches the wire;
// a dead session fails the sweep CLOSED with authz.session-dead on the record. ———

function cookieLab() {
  const OBJS = { 'CA-1': { tenant: 'A', secret: 'alpha' }, 'CB-1': { tenant: 'B', secret: 'bravo' } };
  const seen = [];
  const srv = http.createServer((req, res) => {
    const cookie = req.headers.cookie || '';
    seen.push(cookie);
    const tenant = cookie === 'sess=a' ? 'A' : cookie === 'sess=b' ? 'B' : null;
    const m = /^\/obj\/([\w-]+)$/.exec(req.url.split('?')[0]);
    if (!m) { res.writeHead(404); return res.end('{}'); }
    if (!tenant) { res.writeHead(401); return res.end('{"error":"authentication required"}'); }
    const o = OBJS[m[1]];
    if (!o) { res.writeHead(404); return res.end('{}'); }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(o));
  });
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  return { srv, seen };
}

test('campaign wiring: sessionRef account is resolved through the broker; its cookie drives the sweep', async () => {
  const { Campaign } = await import('../engine/campaign.mjs');
  const { mockAgent } = await import('../mock-agent.mjs');
  const { srv, seen } = cookieLab();
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const c = new Campaign({
      engine: {}, scope: { engagement: 'SB-W1', signedBy: 'x', cidrs: ['127.0.0.0/8'] }, runAgent: mockAgent,
      authz: {
        base,
        accounts: [
          { label: 'a', sessionRef: 'demo:a' },        // broker-managed: NO literal cookie in config
          { label: 'b', cookie: 'sess=b' },
        ],
        templates: [{ path: '/obj/{id}', methods: ['GET'], refs: { a: ['CA-1'], b: ['CB-1'] } }],
      },
      sessionBroker: {
        getLiveSessionImpl: async (prog, lbl) => {
          assert.equal(prog, 'demo');
          assert.equal(lbl, 'a');
          return { ok: true, state: 'live', session: { label: 'demo-a', cookie: 'sess=a', headers: null, refreshedAt: NOW } };
        },
      },
    });
    assert.equal(c.authz.accounts[0].sessionRef, 'demo:a', 'sanitizeAuthzCfg passes sessionRef through');
    c.surface.host('127.0.0.1', { label: 'cookielab' });
    const res = await c.runAuthzSweep();
    assert.equal(res.ok, true, 'sweep ran on the broker-resolved session');
    assert.equal(res.summary.violations, 1, 'cross-tenant read proven with the broker cookie');
    assert.ok(seen.includes('sess=a'), 'the broker-supplied cookie reached the wire');
    assert.ok(c.activity.some((e) => e.kind === 'authz.session' && e.data.sessionRef === 'demo:a' && e.data.state === 'live'), 'authz.session logged with the live state');
  } finally { await new Promise((r) => srv.close(r)); }
});

test('campaign wiring: a dead broker session fails the sweep CLOSED and is named on the record', async () => {
  const { Campaign } = await import('../engine/campaign.mjs');
  const { mockAgent } = await import('../mock-agent.mjs');
  const { srv, seen } = cookieLab();
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const c = new Campaign({
      engine: {}, scope: { engagement: 'SB-W2', signedBy: 'x', cidrs: ['127.0.0.0/8'] }, runAgent: mockAgent,
      authz: {
        base,
        accounts: [
          { label: 'a', sessionRef: 'demo:a' },
          { label: 'b', cookie: 'sess=b' },
        ],
        templates: [{ path: '/obj/{id}', methods: ['GET'], refs: { a: ['CA-1'], b: ['CB-1'] } }],
      },
      sessionBroker: {
        getLiveSessionImpl: async () => ({ ok: false, error: 'session-dead', reason: 'canary 401 and refresh refused' }),
      },
    });
    c.surface.host('127.0.0.1', { label: 'cookielab' });
    const res = await c.runAuthzSweep();
    assert.equal(res.ok, false, 'the sweep refuses to run on a dead session (fail-closed)');
    assert.match(res.error, /dead/);
    assert.match(res.error, /demo:a/, 'the dead sessionRef is named in the error');
    assert.ok(c.activity.some((e) => e.kind === 'authz.session-dead' && e.data.sessionRef === 'demo:a' && /refresh refused/.test(e.data.reason)), 'authz.session-dead on the activity record with the broker reason');
    assert.ok(seen.every((ck) => ck !== 'sess=a'), 'no stale credential ever reached the wire');
  } finally { await new Promise((r) => srv.close(r)); }
});
