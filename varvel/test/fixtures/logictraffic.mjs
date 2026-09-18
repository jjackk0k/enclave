// VARVEL — logiclab traffic recorder (test fixture / evidence generator).
//
// Boots logiclab in-process and drives NORMAL-USAGE journeys (what recon + a crawl of
// the app as the published tenant would actually observe): unauth probes, wallet
// payments, order lifecycles (one to confirmed, one to delivered, one cancelled),
// bookings, coupon applications (incl. a refused repeat), referrals — on BOTH the
// vulnerable /api/* surface and the enforced /api/safe/* mirror. Every request and
// response is recorded as an observation: { seq, session, method, path, status, req,
// res } — the shape engine/logicdiscover.mjs consumes.
//
// Deliberately NEVER touches /openapi.json: the whole point of T3b is discovery with
// NO spec. /lab/revert is lab hygiene, not app traffic — not recorded.

import http from 'node:http';
import { createLogiclabTarget, TENANT_USER, TENANT_PASS } from '../../targets/logiclab.mjs';

function fire(base, { session = 'alice', method = 'GET', path, body = null, cookie = null }) {
  return new Promise((resolve) => {
    const u = new URL(path, base);
    const headers = {};
    if (cookie) headers.cookie = cookie;
    let payload = null;
    if (body != null) {
      if (typeof body === 'string') { payload = body; } else { payload = JSON.stringify(body); headers['content-type'] = 'application/json'; }
    }
    const r = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers, timeout: 3000 }, (res) => {
      let b = ''; res.on('data', (d) => { b += d; });
      res.on('end', () => {
        let parsed = null;
        try { const j = JSON.parse(b); if (j && typeof j === 'object' && !Array.isArray(j)) parsed = j; } catch {}
        resolve({ status: res.statusCode, headers: res.headers, raw: b, parsed });
      });
    });
    r.on('error', () => resolve(null));
    r.on('timeout', () => { r.destroy(); resolve(null); });
    if (payload != null) r.write(payload);
    r.end();
  });
}

// Record the full observation set. Returns { observations, close } — close() shuts the
// lab down. Deterministic journey order; seq is monotonic.
export async function recordLogicTraffic() {
  const srv = createLogiclabTarget();
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const observations = [];
  let seq = 0;
  const rec = async (session, method, path, body = null, cookie = null) => {
    const r = await fire(base, { session, method, path, body, cookie });
    observations.push({
      seq: seq++, session, method, path,
      status: r ? r.status : 0,
      req: body && typeof body === 'object' ? body : null,
      res: r ? r.parsed : null,
    });
    return r;
  };

  // recon finds the docs page publishing the demo tenant, then logs in
  await rec('anon', 'GET', '/docs');
  const login = await rec('anon', 'POST', '/login', null);
  // /login takes a form — refire properly and capture the session cookie
  const loginRes = await fire(base, { session: 'anon', method: 'POST', path: '/login', body: new URLSearchParams({ user: TENANT_USER, pass: TENANT_PASS }).toString() });
  observations.push({ seq: seq++, session: 'anon', method: 'POST', path: '/login', status: loginRes ? loginRes.status : 0, req: null, res: null });
  void login;
  const cookie = loginRes && loginRes.status === 302 ? String(loginRes.headers['set-cookie']).split(';')[0] : null;
  if (!cookie) throw new Error('logiclab login failed — cannot record authenticated traffic');

  // unauth probes: the write surface demands a session (this is recon's 401 pass)
  await rec('anon', 'POST', '/api/payments', { amount: 1 });
  await rec('anon', 'POST', '/api/orders', { itemId: 'ITEM1', qty: 1, price: 25 });
  await rec('anon', 'PATCH', '/api/rides/RIDE1/status', { status: 'accepted' });
  await rec('anon', 'PATCH', '/api/safe/rides/RIDE1/status', { status: 'accepted' });

  for (const P of ['', '/safe']) {
    const A = `/api${P}`; // the safe mirror lives at /api/safe/*
    // wallet / payments
    await rec('alice', 'GET', `${A}/wallet`, null, cookie);
    await rec('alice', 'POST', `${A}/payments`, { amount: 10 }, cookie);
    await rec('alice', 'GET', `${A}/wallet`, null, cookie);
    await rec('alice', 'POST', `${A}/payments`, { amount: 5 }, cookie);
    await rec('alice', 'GET', `${A}/wallet`, null, cookie);

    // order journey 1: create → pay → confirm (the checkout flow, legitimately ordered)
    const o1 = await rec('alice', 'POST', `${A}/orders`, { itemId: 'ITEM1', qty: 1, price: 25 }, cookie);
    const id1 = o1.parsed.id;
    await rec('alice', 'GET', `${A}/orders/${id1}`, null, cookie);
    await rec('alice', 'POST', `${A}/orders/${id1}/pay`, {}, cookie);
    await rec('alice', 'GET', `${A}/orders/${id1}`, null, cookie);
    await rec('alice', 'POST', `${A}/checkout/confirm`, { orderId: id1 }, cookie);
    await rec('alice', 'GET', `${A}/orders/${id1}`, null, cookie);

    // order journey 2: create → pay → ship → deliver (the full forward lifecycle)
    const o2 = await rec('alice', 'POST', `${A}/orders`, { itemId: 'ITEM2', qty: 1, price: 40 }, cookie);
    const id2 = o2.parsed.id;
    await rec('alice', 'GET', `${A}/orders/${id2}`, null, cookie);
    await rec('alice', 'POST', `${A}/orders/${id2}/pay`, {}, cookie);
    await rec('alice', 'GET', `${A}/orders/${id2}`, null, cookie);
    await rec('alice', 'POST', `${A}/orders/${id2}/ship`, {}, cookie);
    await rec('alice', 'GET', `${A}/orders/${id2}`, null, cookie);
    await rec('alice', 'POST', `${A}/orders/${id2}/deliver`, {}, cookie);
    await rec('alice', 'GET', `${A}/orders/${id2}`, null, cookie);

    // order journey 3: create → cancel (cancel observed ONLY from pending)
    const o3 = await rec('alice', 'POST', `${A}/orders`, { itemId: 'ITEM1', qty: 1, price: 25 }, cookie);
    const id3 = o3.parsed.id;
    await rec('alice', 'GET', `${A}/orders/${id3}`, null, cookie);
    await rec('alice', 'POST', `${A}/orders/${id3}/cancel`, {}, cookie);
    await rec('alice', 'GET', `${A}/orders/${id3}`, null, cookie);

    // bookings: the ride resource shows a constant capacity; bookedSeats accumulates
    await rec('alice', 'GET', `${A}/rides/RIDE1`, null, cookie);
    await rec('alice', 'POST', `${A}/bookings`, { rideId: 'RIDE1', seats: 2 }, cookie);
    await rec('alice', 'GET', `${A}/rides/RIDE1`, null, cookie);
    await rec('alice', 'POST', `${A}/bookings`, { rideId: 'RIDE1', seats: 1 }, cookie);
    await rec('alice', 'GET', `${A}/rides/RIDE1`, null, cookie);

    // coupons: one code per order is the observed norm; a same-code repeat is refused
    const o4 = await rec('alice', 'POST', `${A}/orders`, { itemId: 'ITEM1', qty: 1, price: 25 }, cookie);
    const id4 = o4.parsed.id;
    await rec('alice', 'GET', `${A}/orders/${id4}`, null, cookie);
    await rec('alice', 'POST', `${A}/coupons/apply`, { orderId: id4, code: 'SAVE10' }, cookie);
    await rec('alice', 'GET', `${A}/orders/${id4}`, null, cookie);
    await rec('alice', 'POST', `${A}/coupons/apply`, { orderId: id4, code: 'SAVE10' }, cookie); // repeat → refused
    const o5 = await rec('alice', 'POST', `${A}/orders`, { itemId: 'ITEM2', qty: 1, price: 40 }, cookie);
    const id5 = o5.parsed.id;
    await rec('alice', 'POST', `${A}/coupons/apply`, { orderId: id5, code: 'SAVE20' }, cookie);
    await rec('alice', 'GET', `${A}/orders/${id5}`, null, cookie);

    // referrals: the caller's identity carries their own code; redeeming ANOTHER's is normal
    await rec('alice', 'GET', '/api/me', null, cookie);
    await rec('alice', 'POST', `${A}/referrals`, { code: 'REF-BOB' }, cookie);
    await rec('alice', 'GET', `${A}/referrals`, null, cookie);
  }

  return { observations, base, close: () => new Promise((r) => srv.close(r)) };
}
