// VARVEL — chainyard: the planted-COMPOSITION garden (research thread T2).
//
// An AUTHORIZED, self-contained practice target (localhost only) for calibrating the
// chaining engine. Unlike demo-corp — which plants standalone exposures — chainyard
// plants a set of individually-LOW weaknesses where NO single one is filable, plus
// ONE composed HIGH reachable only by chaining a specific subset of the lows, plus
// ONE DECOY low that looks chainable but isn't. The chain is the finding.
//
// Planted lows (each benign/informational in isolation):
//   L1 /search?q=          reflected self-XSS — unescaped reflection, but the page is
//                          only ever rendered to the searcher (self-XSS: informational)
//   L2 /api/me             CORS reflects any Origin WITH credentials — BUT the session
//                          cookie is SameSite=Strict, so a cross-origin credentialed
//                          read carries no cookie and gets the ANONYMOUS profile.
//                          THE DECOY: the header is scary, the impact is nil.
//   L3 /goto?next=         open redirect (302 anywhere) — a real low, but it composes
//                          into nothing here (the winning chain is server-side).
//   L4 /internal/debug     info-leak: server RNG seed + uptime (sensitive-hit pattern)
//   L5 /reset/request      predictable reset token: rset-<seed>-<user>. The token is
//                          NOT returned in the response (emailed, in fiction) — weak
//                          entropy is invisible until L4's seed is known.
//
// The composed HIGH (account takeover of admin, server-side):
//   L4 leak seed  →  predict L5 token  →  POST /reset/confirm  →  admin session  →
//   GET /admin/vault (contains CY_VAULT_CANARY)  →  POST /lab/revert (hygiene)
//
// Run:  node varvel/targets/chainyard.mjs     # standalone on :8973 (or CHAINYARD_PORT)
//   import { createChainyardTarget } from '../targets/chainyard.mjs'   # tests/lab

import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';

export const VAULT_CANARY = 'CY-VAULT-CANARY-7f3d9a2b';
export const BOB_BOOKING_CANARY = 'BOB-BOOKING-CANARY-b7e2f1';
export const BOB_INVOICE_CANARY = 'BOB-INVOICE-CANARY-44aa90';
export const RACE_CANARY = 'RACE-CANARY-5d2c8e';   // marks every race-fixture state mutation (readback evidence)
export const GIFT_CANARY = 'GIFT-CANARY-90f1ab';   // the SAFE control's single effect
export const ADMIN_USER = 'admin';
const ADMIN_PASS = 'garden-demo-2026'; // published in /docs, like Axiom's sandbox creds
const TENANT_USER = 'alice';
const TENANT_PASS = 'tenant-demo-2026'; // published in /docs — the low-priv identity the IDOR chain rides

const page = (title, body) => `<!doctype html><html><head><title>${title} · Chainyard</title>
<style>body{font:15px/1.6 system-ui;margin:0;color:#1b2430}header{background:#233043;color:#fff;padding:16px 36px}
nav a{color:#cfe3ff;margin-right:16px;text-decoration:none}main{max-width:780px;margin:0 auto;padding:28px 22px}
code{background:#f0f3f7;padding:1px 5px;border-radius:4px}footer{color:#68788a;padding:20px 36px;border-top:1px solid #e3e9f0}</style></head>
<body><header><b>CHAINYARD</b> &nbsp;<nav><a href="/">Home</a><a href="/search">Search</a><a href="/account">Account</a><a href="/docs">Docs</a></nav></header>
<main>${body}</main><footer>© Chainyard Ltd · internal tools demo</footer></body></html>`;

const readBody = (req, cap = 4096) => new Promise((resolve) => {
  let b = ''; req.on('data', (c) => { b += c; if (b.length > cap) req.destroy(); });
  req.on('end', () => resolve(b));
});

export function createChainyardTarget() {
  // Per-instance state. The seed is random per boot — but LEAKED by /internal/debug,
  // which is what makes L5's predictable token computable (the composition point).
  const state = {
    seed: randomBytes(4).toString('hex'),      // leaked by L4; drives L5 tokens
    bootedAt: Date.now(),
    users: {
      [ADMIN_USER]: { pass: ADMIN_PASS, role: 'admin', email: 'admin@chainyard.example' },
      [TENANT_USER]: { pass: TENANT_PASS, role: 'tenant', email: 'alice@chainyard.example' },
      bob: { pass: 'bob-never-logs-in', role: 'tenant', email: 'bob@chainyard.example' }, // the OTHER tenant — the IDOR victim
    },
    resetTokens: new Map(),                    // user -> token (as "emailed", never in responses)
    sessions: new Map(),                       // sid -> user
    // Tenant object stores — the ownership-confusion garden (bykea-class API shape:
    // numeric sequential ids behind an identity boundary).
    bookings: {
      1001: { id: 1001, tenant: 'alice', title: 'Depot pickup', notes: 'ALICE-BOOKING-CANARY-11c0ff' },
      1002: { id: 1002, tenant: 'bob', title: 'Harbor delivery', notes: BOB_BOOKING_CANARY },
    },
    invoices: {
      2001: { id: 2001, tenant: 'alice', amount: 1400 },
      2002: { id: 2002, tenant: 'bob', amount: 2750, memo: BOB_INVOICE_CANARY },
    },
    listings: {
      3001: { id: 3001, title: 'Warehouse slot A', price: 90 },
      3002: { id: 3002, title: 'Warehouse slot B', price: 120 },
    },
    // The race garden (T4) — check-then-act TOCTOU shapes with a PLANTED async window
    // between check and act (in fiction: an audit-log write). Last-byte-synced bursts
    // land inside the window; sequential replay does not. R4 is the SAFE control.
    coupons: { WELCOME10: { code: 'WELCOME10', value: 10, redeemedBy: null } }, // R1 single-use, shared across tenants
    redemptions: [],                       // every successful R1 redeem appends {code,user,marker}
    wallets: { alice: 100, bob: 100 },     // R2 balances
    ledger: [],                            // every R2 transfer appends {from,to,amount,balanceAfter,marker}
    giveaway: { limit: 1, entries: [] },   // R3 one entry per tenant
    gifts: {},                             // R4 SAFE control: code -> { claimedBy, marker } (locked + idempotent)
  };
  const RACE_WINDOW_MS = 90; // the planted check/act gap — wide enough for a synced loopback burst
  const raceTick = () => new Promise((r) => setTimeout(r, RACE_WINDOW_MS));
  // Per-key promise mutex — the CORRECT pattern R4 uses (the defense is serialization,
  // not timing: R4 keeps the same async window as the vulnerable endpoints).
  const giftLocks = new Map();
  const withGiftLock = (key, fn) => {
    const prev = giftLocks.get(key) || Promise.resolve();
    const next = prev.then(fn, fn);
    giftLocks.set(key, next.catch(() => {}));
    return next;
  };
  const resetRaceFixtures = () => {
    state.coupons.WELCOME10.redeemedBy = null;
    state.redemptions.length = 0;
    state.wallets.alice = 100; state.wallets.bob = 100;
    state.ledger.length = 0;
    state.giveaway.entries.length = 0;
    for (const k of Object.keys(state.gifts)) delete state.gifts[k];
  };
  const tokenFor = (user) => `rset-${state.seed}-${user}`; // L5: predictable once seed leaks

  const json = (res, status, obj, extraHeaders = {}) => {
    res.writeHead(status, { 'content-type': 'application/json', ...extraHeaders });
    res.end(JSON.stringify(obj));
  };

  return http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://localhost');
    const path = u.pathname;

    // --- L2 (DECOY): CORS reflect-with-credentials on the identity endpoint -------
    if (path === '/api/me') {
      const h = {};
      const origin = req.headers.origin;
      if (origin) { h['access-control-allow-origin'] = origin; h['access-control-allow-credentials'] = 'true'; }
      if (req.method === 'OPTIONS') { res.writeHead(204, { ...h, 'access-control-allow-methods': 'GET', allow: 'GET' }); return res.end(); }
      // The session cookie is SameSite=Strict (see /login) — a cross-site credentialed
      // fetch does NOT carry it, so the "scary" CORS header only ever serves this:
      const sid = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith('cy_sess='));
      const sess = sid && state.sessions.get(sid.slice(8));
      if (!sess) return json(res, 200, { user: 'anonymous', role: 'none', note: 'no first-party session' }, h);
      const usr = state.users[sess.user];
      return json(res, 200, { user: sess.user, role: usr.role, email: usr.email }, h);
    }

    // --- the composed HIGH: predictable reset → session → vault -------------------
    // Framework-realistic method surface: GET on the POST-only reset endpoints gets a
    // 405 + Allow (what a real router emits — and what webProber turns into an
    // OPTIONS-revealed write-candidate during discovery).
    if ((path === '/reset/request' || path === '/reset/confirm') && req.method !== 'POST') {
      res.writeHead(req.method === 'OPTIONS' ? 204 : 405, { 'content-type': 'application/json', allow: 'POST' });
      return res.end(req.method === 'OPTIONS' ? undefined : '{"error":"method not allowed"}');
    }
    if (path === '/reset/request' && req.method === 'POST') {
      const b = JSON.parse((await readBody(req)) || '{}');
      const user = state.users[b.user] ? b.user : null;
      if (user) state.resetTokens.set(user, tokenFor(user)); // "emailed" — never returned
      return json(res, 200, { ok: true, delivery: 'email' }); // same shape either way (no user enum)
    }
    if (path === '/reset/confirm' && req.method === 'POST') {
      const b = JSON.parse((await readBody(req)) || '{}');
      const expected = state.resetTokens.get(b.user);
      if (!expected || b.token !== expected || typeof b.password !== 'string' || !b.password) {
        return json(res, 403, { error: 'invalid reset token' });
      }
      state.users[b.user].pass = b.password;
      const sid = 'sess_' + randomBytes(6).toString('hex');
      state.sessions.set(sid, { user: b.user });
      // Realistic: a completed reset logs you in — the session rides Set-Cookie (so a
      // composed chain can carry it forward generically, no app-specific cookie name).
      res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': `cy_sess=${sid}; Path=/; SameSite=Strict; HttpOnly` });
      return res.end(JSON.stringify({ ok: true, session: sid, revert: { method: 'POST', path: '/lab/revert' } }));
    }
    if (path === '/admin/vault') {
      const sid = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith('cy_sess='));
      const sess = sid && state.sessions.get(sid.slice(8));
      if (!sess || state.users[sess.user].role !== 'admin') return json(res, 403, { error: 'admin session required' });
      return json(res, 200, { owner: sess.user, vault: VAULT_CANARY, note: 'crown-jewel store' });
    }

    // --- lab hygiene: restore planted state (the chain's net change becomes zero) --
    // Body {"scope":"race"} resets ONLY the race fixtures (between race attempts — the
    // caller's session must survive); anything else is a full revert (and also resets
    // the race fixtures, since a full restore covers them).
    if (path === '/lab/revert' && req.method === 'POST') {
      let scoped = null;
      try { scoped = JSON.parse((await readBody(req)) || '{}').scope || null; } catch { scoped = null; }
      if (scoped === 'race') { resetRaceFixtures(); return json(res, 200, { ok: true, reverted: true, scope: 'race' }); }
      state.users[ADMIN_USER].pass = ADMIN_PASS;
      state.sessions.clear();
      state.resetTokens.clear();
      resetRaceFixtures();
      return json(res, 200, { ok: true, reverted: true });
    }

    // --- the IDOR / ownership-confusion garden ------------------------------------
    const sessUser = () => {
      const sid = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith('cy_sess='));
      const sess = sid && state.sessions.get(sid.slice(8));
      return sess ? sess.user : null;
    };

    // L7 (low): the activity feed LEAKS enumerable object ids + their owning tenants —
    // informational alone (no object content), but it PROVIDES the enumerable-id source
    // the ownership-confusion primitive consumes. First booking/invoice entries are the
    // OTHER tenant's (recent activity is global — realistic).
    if (path === '/api/feed') {
      return json(res, 200, { recent: [
        { type: 'booking', id: 1002, tenant: 'bob' },
        { type: 'booking', id: 1001, tenant: 'alice' },
        { type: 'invoice', id: 2002, tenant: 'bob' },
        { type: 'invoice', id: 2001, tenant: 'alice' },
      ] });
    }

    // L8 (the REAL ownership confusion): /api/bookings/<id> checks AUTHENTICATION but
    // never OWNERSHIP — any tenant reads any booking (missing per-object check).
    let m = /^\/api\/bookings\/(\d+)$/.exec(path);
    if (m) {
      const me = sessUser();
      if (!me) return json(res, 401, { error: 'authentication required' });
      const b = state.bookings[m[1]];
      if (!b) return json(res, 404, { error: 'not found' });
      return json(res, 200, b); // <-- the planted bug: no b.tenant === me check
    }

    // L9 (DECOY — ownership ENFORCED): /api/invoices/<id> has the same enumerable-id
    // shape, so a naive scanner flags it — but cross-tenant reads get a 404
    // indistinguishable from a miss. The differential oracle kills it.
    m = /^\/api\/invoices\/(\d+)$/.exec(path);
    if (m) {
      const me = sessUser();
      if (!me) return json(res, 401, { error: 'authentication required' });
      const inv = state.invoices[m[1]];
      if (!inv || inv.tenant !== me) return json(res, 404, { error: 'not found' });
      return json(res, 200, inv);
    }

    // L10 (DECOY — PUBLIC object): /api/listings/<id> returns the SAME body to anyone,
    // authed or not. Enumerable ids + 200-for-everyone LOOKS like an IDOR to naive
    // tools; the unauth control (identical body) proves it is a public object.
    m = /^\/api\/listings\/(\d+)$/.exec(path);
    if (m) {
      const l = state.listings[m[1]];
      if (!l) return json(res, 404, { error: 'not found' });
      return json(res, 200, l);
    }

    // --- the race garden (T4): TOCTOU between CHECK and ACT -------------------------
    // R1/R2/R3 are the bounty-paying shapes (single-use redeem, balance debit,
    // per-tenant limit); R4 is the SAFE control — properly locked AND idempotent,
    // so naive parallelism flags it (all-200s) while the state readback clears it.

    // R1 (REAL): single-use coupon — check "redeemed?" … await … record. No re-check.
    if (path === '/api/coupons/redeem' && req.method === 'POST') {
      const me = sessUser();
      if (!me) return json(res, 401, { error: 'authentication required' });
      const b = JSON.parse((await readBody(req)) || '{}');
      const c = state.coupons[b.code];
      if (!c) return json(res, 404, { error: 'no such coupon' });
      if (c.redeemedBy) return json(res, 409, { error: 'already redeemed' });      // CHECK
      await raceTick();                                                            // <-- planted TOCTOU window
      c.redeemedBy = me;                                                           // ACT (vulnerable: no re-check)
      state.redemptions.push({ code: c.code, user: me, at: Date.now(), marker: RACE_CANARY });
      return json(res, 200, { ok: true, code: c.code, credited: c.value, marker: RACE_CANARY });
    }
    // R1 readback: redemption COUNT for the coupon (the duplicated-effect oracle)
    m = /^\/api\/coupons\/([A-Z0-9-]+)$/.exec(path);
    if (m && req.method === 'GET') {
      const me = sessUser();
      if (!me) return json(res, 401, { error: 'authentication required' });
      const c = state.coupons[m[1]];
      if (!c) return json(res, 404, { error: 'no such coupon' });
      const rs = state.redemptions.filter((r) => r.code === c.code);
      return json(res, 200, { marker: rs[0] ? RACE_CANARY : null, code: c.code, redemptions: rs.length, redeemedBy: rs.map((r) => r.user) });
    }

    // R2 (REAL): balance transfer — check "sufficient?" … await … debit. No re-check.
    if (path === '/api/wallet/transfer' && req.method === 'POST') {
      const me = sessUser();
      if (!me) return json(res, 401, { error: 'authentication required' });
      const b = JSON.parse((await readBody(req)) || '{}');
      const amt = Number(b.amount);
      if (!(amt > 0) || !state.users[b.to]) return json(res, 400, { error: 'bad transfer' });
      if (state.wallets[me] < amt) return json(res, 422, { error: 'insufficient funds' }); // CHECK
      await raceTick();                                                                    // <-- window
      state.wallets[me] -= amt;                                                            // ACT (no re-check)
      state.wallets[b.to] += amt;
      state.ledger.push({ from: me, to: b.to, amount: amt, balanceAfter: state.wallets[me], marker: RACE_CANARY });
      return json(res, 200, { ok: true, balance: state.wallets[me], marker: RACE_CANARY });
    }
    // R2 readback: own balance + debit count (overdraw = balance < 0)
    if (path === '/api/wallet' && req.method === 'GET') {
      const me = sessUser();
      if (!me) return json(res, 401, { error: 'authentication required' });
      const debits = state.ledger.filter((l) => l.from === me).length;
      return json(res, 200, { marker: debits ? RACE_CANARY : null, user: me, balance: state.wallets[me], debits });
    }

    // R3 (REAL): giveaway entry — per-tenant limit CHECK … await … append.
    if (path === '/api/giveaway/enter' && req.method === 'POST') {
      const me = sessUser();
      if (!me) return json(res, 401, { error: 'authentication required' });
      const mine = state.giveaway.entries.filter((e) => e.user === me).length;
      if (mine >= state.giveaway.limit) return json(res, 429, { error: 'entry limit reached' }); // CHECK
      await raceTick();                                                                        // <-- window
      state.giveaway.entries.push({ user: me, at: Date.now(), marker: RACE_CANARY });          // ACT
      return json(res, 200, { ok: true, entries: mine + 1, marker: RACE_CANARY });
    }
    // R3 readback
    if (path === '/api/giveaway' && req.method === 'GET') {
      const me = sessUser();
      if (!me) return json(res, 401, { error: 'authentication required' });
      const yours = state.giveaway.entries.filter((e) => e.user === me).length;
      return json(res, 200, { marker: yours ? RACE_CANARY : null, limit: state.giveaway.limit, yourEntries: yours });
    }

    // R4 (SAFE CONTROL): claim-once gift — per-key MUTEX serializes claimants and the
    // replay response is idempotent-200. Concurrent burst: N×200 (naive flags it), but
    // the state readback shows exactly ONE claim. The sequential control agrees.
    if (path === '/api/gift/claim' && req.method === 'POST') {
      const me = sessUser();
      if (!me) return json(res, 401, { error: 'authentication required' });
      const b = JSON.parse((await readBody(req)) || '{}');
      if (!b.code) return json(res, 400, { error: 'code required' });
      const out = await withGiftLock('gift:' + b.code, async () => {
        const existing = state.gifts[b.code];
        if (existing) {
          if (existing.claimedBy === me) return { status: 200, body: { ok: true, code: b.code, already: true, note: 'idempotent replay — still one gift' } };
          return { status: 409, body: { error: 'claimed by another user' } };
        }
        await raceTick(); // same async work as R1–R3 — the LOCK, not the timing, is the defense
        state.gifts[b.code] = { claimedBy: me, marker: GIFT_CANARY };
        return { status: 200, body: { ok: true, code: b.code, claimed: true } };
      });
      return json(res, out.status, out.body);
    }
    // R4 readback: claim COUNT for the gift code
    m = /^\/api\/gifts\/([A-Z0-9-]+)$/.exec(path);
    if (m && req.method === 'GET') {
      const me = sessUser();
      if (!me) return json(res, 401, { error: 'authentication required' });
      const g = state.gifts[m[1]];
      return json(res, 200, { marker: g ? GIFT_CANARY : null, code: m[1], claims: g ? 1 : 0, claimedBy: g ? g.claimedBy : null });
    }

    // --- ordinary app surface ------------------------------------------------------
    if (path === '/login' && req.method === 'POST') {
      const b = new URLSearchParams(await readBody(req));
      const usr = state.users[b.get('user')];
      if (!usr || usr.pass !== b.get('pass')) return json(res, 403, { error: 'bad credentials' });
      const sid = 'sess_' + randomBytes(6).toString('hex');
      state.sessions.set(sid, { user: b.get('user') });
      res.writeHead(302, {
        location: '/account',
        // SameSite=Strict is load-bearing: it is why L2's reflected CORS is a DECOY.
        'set-cookie': `cy_sess=${sid}; Path=/; SameSite=Strict; HttpOnly`,
      });
      return res.end();
    }
    if (path === '/search') {
      const q = u.searchParams.get('q') || '';
      // L1: reflected unescaped — but the results page is only ever shown to the
      // searcher themselves (self-XSS; informational alone).
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end(page('Search', `<h1>Search</h1><form><input name=q value="${q}"><button>Go</button></form><p>Results for <b>${q}</b>: none. <i>(your searches are private to your browser)</i></p>`));
    }
    if (path === '/goto') {
      // L3: open redirect — a genuine low, composing into nothing on this target.
      const next = u.searchParams.get('next') || '/';
      res.writeHead(302, { location: next });
      return res.end();
    }
    if (path === '/internal/debug') {
      // L4: the leak that makes L5 computable. ENV-style KEY=VALUE shape (what
      // classifyResponse scores as a sensitive-hit).
      res.writeHead(200, { 'content-type': 'text/plain' });
      return res.end(`RNG_SEED=${state.seed}\nUPTIME_MS=${Date.now() - state.bootedAt}\nBUILD=cy-1.4.2\n`);
    }
    if (path === '/docs') {
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end(page('Docs', `<h1>Developer docs</h1><p>Demo sign-in: <code>${ADMIN_USER} / ${ADMIN_PASS}</code>. Tenant demo account: <code>${TENANT_USER} / ${TENANT_PASS}</code>. Reset flow: <code>POST /reset/request {"user":…}</code> emails a token; <code>POST /reset/confirm {"user","token","password"}</code> consumes it. Object APIs: <code>/api/bookings/&lt;id&gt;</code>, <code>/api/invoices/&lt;id&gt;</code>, <code>/api/listings/&lt;id&gt;</code>; recent activity at <code>/api/feed</code>.</p><p>Demo coupon: <code>WELCOME10</code> (single-use; <code>POST /api/coupons/redeem {"code":…}</code>). Wallet: <code>POST /api/wallet/transfer {"to","amount"}</code> — try a transfer to <code>bob</code>; balance at <code>GET /api/wallet</code>. Giveaway: <code>POST /api/giveaway/enter</code> (one entry per tenant). Demo gift: <code>GIFT-2026</code> via <code>POST /api/gift/claim {"code":…}</code> (claim once).</p>`));
    }
    if (path === '/account') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end(page('Account', '<h1>Account</h1><p>Sign in via POST /login.</p>')); }
    if (path === '/' || path === '') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end(page('Home', '<h1>Chainyard internal tools</h1><p>Search, account, and password reset.</p>')); }

    res.writeHead(404, { 'content-type': 'text/html' });
    res.end(page('Not found', '<h1>404</h1>'));
  });
}

// standalone (robust across Windows file:// vs file:/// normalization)
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.CHAINYARD_PORT || 8973);
  createChainyardTarget().listen(port, '127.0.0.1', () => console.log(`Chainyard composition garden on http://127.0.0.1:${port}`));
}
