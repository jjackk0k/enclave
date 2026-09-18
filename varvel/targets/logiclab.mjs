// VARVEL — logiclab: the planted BUSINESS-LOGIC invariant garden (research thread T3).
//
// An AUTHORIZED, self-contained practice target (localhost only) for calibrating the
// invariant extractor. Where chainyard plants composition lows, logiclab plants eight
// business-logic INVARIANT VIOLATIONS (e-commerce/booking-flavored — the
// bykea/tripcom-class surface), a fully ENFORCED clean control surface mirroring them
// under /api/safe/*, and an OpenAPI description (/openapi.json) whose vendor
// extensions document the INTENDED invariants. The extractor reads the spec; the
// prover checks the server against it.
//
// Planted violations (each individually invisible to single-request scanners):
//   V1 POST /api/payments          negative amount CREDITS the wallet (no min check)
//   V2 POST /api/orders            client-supplied price trusted (server-authoritative
//                                  field accepted; charged total reflects the tamper)
//   V3 POST /api/bookings          seats beyond ride capacity accepted (no max check)
//   V4 POST /api/checkout/confirm  step-skip: confirms an UNPAID order (flow-order)
//   V5 POST /api/coupons/apply     coupon stacking beyond the 1-per-order limit
//   V6 PATCH /api/rides/<id>/status  role-confusion: a passenger drives the ride
//                                  state machine (driver-only transition)
//   V7 POST /api/orders/<id>/cancel  backward transition: cancels a DELIVERED order
//                                  (and still refunds)
//   V8 POST /api/referrals         self-referral: own code accepted, bonus credited
//
// The clean control surface /api/safe/* enforces every one of these. /api/safe/orders
// is the DECOY: it ACCEPTS the client price field (200, looks violated to a
// status-code tool) but IGNORES it server-side — the readback shows the catalog
// price. Only a readback oracle clears it.
//
// Run:  node varvel/targets/logiclab.mjs     # standalone on :8974 (or LOGICLAB_PORT)
//   import { createLogiclabTarget } from '../targets/logiclab.mjs'   # tests/lab

import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';

export const LOGIC_CANARY = 'LOGIC-CANARY-3e9b77';
export const TENANT_USER = 'alice';
export const TENANT_PASS = 'shop-demo-2026'; // published in /docs — the low-priv identity the chains ride

const readBody = (req, cap = 4096) => new Promise((resolve) => {
  let b = ''; req.on('data', (c) => { b += c; if (b.length > cap) req.destroy(); });
  req.on('end', () => resolve(b));
});

// The OpenAPI description the extractor consumes. Vendor extensions document INTENT:
//   x-invariant       per-operation: kind, param, control request, setup, readback recipe
//   x-flows           named multi-step flows (ordered operationIds)
//   x-state-machines  named machines: transitions with allowed from-states
// Schema constraints (minimum/maximum/enum) are READ FROM THE SCHEMA — that is the
// "extracted from OpenAPI" claim; x-invariant supplies only what OpenAPI cannot say
// (how to observe state, what a valid control request looks like).
function buildSpec() {
  const jsonBody = (properties, required) => ({
    content: { 'application/json': { schema: { type: 'object', properties, required: required || Object.keys(properties) } } },
  });
  return {
    openapi: '3.0.3',
    info: { title: 'Logiclab travel shop API', version: '1.0.0' },
    'x-flows': { checkout: ['createOrder', 'payOrder', 'confirmCheckout'] },
    'x-state-machines': {
      order: {
        states: ['pending', 'paid', 'shipped', 'delivered', 'confirmed', 'cancelled'],
        transitions: [
          { name: 'pay', from: ['pending'], to: 'paid' },
          { name: 'ship', from: ['paid'], to: 'shipped' },
          { name: 'deliver', from: ['shipped'], to: 'delivered' },
          { name: 'cancel', from: ['pending', 'paid'], to: 'cancelled' },
        ],
      },
      ride: {
        states: ['open', 'accepted', 'started', 'completed', 'cancelled'],
        transitions: [
          { name: 'setStatus', role: 'driver', from: ['open', 'accepted', 'started'], to: ['accepted', 'started', 'completed'] },
        ],
      },
    },
    paths: {
      '/api/payments': {
        post: {
          operationId: 'createPayment',
          summary: 'Debit the wallet to pay for goods',
          requestBody: jsonBody({ amount: { type: 'number', minimum: 1, description: 'amount to debit; must be positive' } }),
          'x-invariant': {
            kind: 'bounds-min', param: 'amount',
            control: { body: { amount: 10 } },
            readback: { method: 'GET', path: '/api/wallet', effect: '"balance":(-?\\d+)', model: 'subtract-param' },
          },
        },
      },
      '/api/orders': {
        post: {
          operationId: 'createOrder',
          summary: 'Create an order; price is server-computed from the catalog',
          requestBody: jsonBody({
            itemId: { type: 'string', enum: ['ITEM1', 'ITEM2'] },
            qty: { type: 'integer', minimum: 1, maximum: 10 },
            price: { type: 'number', 'x-server-authoritative': true, description: 'ignored client hint; catalog price is authoritative' },
          }),
          'x-invariant': {
            kind: 'server-authoritative', param: 'price',
            control: { body: { itemId: 'ITEM1', qty: 2, price: 25 } },
            readback: { method: 'GET', path: '/api/orders/{{orderId}}', effect: '"unitPrice":([\\d.]+)', model: 'set-param', saveFromViolation: { var: 'orderId', regex: '"id":"([\\w-]+)"' } },
          },
        },
      },
      '/api/bookings': {
        post: {
          operationId: 'createBooking',
          summary: 'Book seats on a ride',
          requestBody: jsonBody({
            rideId: { type: 'string', enum: ['RIDE1'] },
            seats: { type: 'integer', minimum: 1, maximum: 4, description: 'ride capacity is 4' },
          }),
          'x-invariant': {
            kind: 'bounds-max', param: 'seats',
            control: { body: { rideId: 'RIDE1', seats: 2 } },
            readback: { method: 'GET', path: '/api/rides/RIDE1', effect: '"bookedSeats":(\\d+)', model: 'add-param' },
          },
        },
      },
      '/api/checkout/confirm': {
        post: {
          operationId: 'confirmCheckout',
          summary: 'Confirm an order — final step of the checkout flow',
          requestBody: jsonBody({ orderId: { type: 'string' } }),
          'x-invariant': {
            kind: 'flow-order', flow: 'checkout',
            setup: [{ method: 'POST', path: '/api/orders', body: { itemId: 'ITEM1', qty: 1, price: 25 }, save: { orderId: '"id":"([\\w-]+)"' } }],
            controlSteps: [{ method: 'POST', path: '/api/orders/{{orderId}}/pay', body: {} }],
            control: { body: { orderId: '{{orderId}}' } },
            readback: { method: 'GET', path: '/api/orders/{{orderId}}', fields: { status: '"status":"(\\w+)"', payment: '"paymentStatus":"(\\w+)"' }, expect: { status: 'confirmed', payment: 'unpaid' } },
          },
        },
      },
      '/api/coupons/apply': {
        post: {
          operationId: 'applyCoupon',
          summary: 'Apply ONE coupon to an order',
          requestBody: jsonBody({ orderId: { type: 'string' }, code: { type: 'string', enum: ['SAVE10', 'SAVE20'] } }),
          'x-limit': 1,
          'x-invariant': {
            kind: 'usage-limit', param: 'code', limit: 1,
            setup: [{ method: 'POST', path: '/api/orders', body: { itemId: 'ITEM2', qty: 1, price: 40 }, save: { orderId: '"id":"([\\w-]+)"' } }],
            control: { body: { orderId: '{{orderId}}', code: 'SAVE10' } },
            readback: { method: 'GET', path: '/api/orders/{{orderId}}', effect: '"couponCount":(\\d+)', model: 'count-exceeds' },
          },
        },
      },
      '/api/rides/{id}/status': {
        patch: {
          operationId: 'setRideStatus',
          summary: 'Advance the ride state machine — DRIVER only',
          'x-role': 'driver',
          requestBody: jsonBody({ status: { type: 'string', enum: ['accepted', 'started', 'completed'] } }),
          'x-invariant': {
            kind: 'role-gate', param: 'status', role: 'driver',
            concretePath: '/api/rides/RIDE1/status',
            control: { unauth: true }, // the same request without a session must be refused
            readback: { method: 'GET', path: '/api/rides/RIDE1', fields: { status: '"status":"(\\w+)"' }, expect: { status: '{{v}}' } },
          },
        },
      },
      '/api/orders/{id}/cancel': {
        post: {
          operationId: 'cancelOrder',
          summary: 'Cancel a pending or paid order',
          'x-state-machine': { machine: 'order', transition: 'cancel' },
          'x-invariant': {
            kind: 'state-machine', machine: 'order', transition: 'cancel',
            setup: [
              { method: 'POST', path: '/api/orders', body: { itemId: 'ITEM2', qty: 1, price: 40 }, save: { orderId: '"id":"([\\w-]+)"' } },
              { method: 'POST', path: '/api/orders/{{orderId}}/pay', body: {} },
              { method: 'POST', path: '/api/orders/{{orderId}}/ship', body: {} },
              { method: 'POST', path: '/api/orders/{{orderId}}/deliver', body: {} },
            ],
            controlSetup: [{ method: 'POST', path: '/api/orders', body: { itemId: 'ITEM1', qty: 1, price: 25 }, save: { cid: '"id":"([\\w-]+)"' } }],
            control: { method: 'POST', path: '/api/orders/{{cid}}/cancel', body: {} },
            violationPath: '/api/orders/{{orderId}}/cancel',
            readback: { method: 'GET', path: '/api/orders/{{orderId}}', fields: { status: '"status":"(\\w+)"' }, expect: { status: 'cancelled' } },
          },
        },
      },
      '/api/referrals': {
        post: {
          operationId: 'createReferral',
          summary: 'Redeem a referral code — referrer and referee must differ',
          'x-distinct-actors': true,
          requestBody: jsonBody({ code: { type: 'string', enum: ['REF-ALICE', 'REF-BOB'] } }),
          'x-invariant': {
            kind: 'actor-separation', param: 'code',
            selfFrom: { method: 'GET', path: '/api/me', field: '"refCode":"([\\w-]+)"' },
            control: { body: { code: 'REF-BOB' } },
            readback: { method: 'GET', path: '/api/referrals', effect: '"uses":(\\d+)', model: 'count-exceeds', limit: 1 },
          },
        },
      },

      // ——— the clean control surface: identical intent, enforced server-side ———
      '/api/safe/payments': {
        post: {
          operationId: 'createSafePayment',
          requestBody: jsonBody({ amount: { type: 'number', minimum: 1 } }),
          'x-invariant': {
            kind: 'bounds-min', param: 'amount',
            control: { body: { amount: 10 } },
            readback: { method: 'GET', path: '/api/safe/wallet', effect: '"balance":(-?\\d+)', model: 'subtract-param' },
          },
        },
      },
      '/api/safe/orders': {
        post: {
          operationId: 'createSafeOrder',
          summary: 'DECOY: accepts the price field (200) but IGNORES it — catalog price is charged',
          requestBody: jsonBody({
            itemId: { type: 'string', enum: ['ITEM1', 'ITEM2'] },
            qty: { type: 'integer', minimum: 1, maximum: 10 },
            price: { type: 'number', 'x-server-authoritative': true },
          }),
          'x-invariant': {
            kind: 'server-authoritative', param: 'price',
            control: { body: { itemId: 'ITEM1', qty: 2, price: 25 } },
            readback: { method: 'GET', path: '/api/safe/orders/{{orderId}}', effect: '"unitPrice":([\\d.]+)', model: 'set-param', saveFromViolation: { var: 'orderId', regex: '"id":"([\\w-]+)"' } },
          },
        },
      },
      '/api/safe/bookings': {
        post: {
          operationId: 'createSafeBooking',
          requestBody: jsonBody({ rideId: { type: 'string', enum: ['RIDE1'] }, seats: { type: 'integer', minimum: 1, maximum: 4 } }),
          'x-invariant': {
            kind: 'bounds-max', param: 'seats',
            control: { body: { rideId: 'RIDE1', seats: 2 } },
            readback: { method: 'GET', path: '/api/safe/rides/RIDE1', effect: '"bookedSeats":(\\d+)', model: 'add-param' },
          },
        },
      },
      '/api/safe/checkout/confirm': {
        post: {
          operationId: 'confirmSafeCheckout',
          requestBody: jsonBody({ orderId: { type: 'string' } }),
          'x-invariant': {
            kind: 'flow-order', flow: 'checkout',
            setup: [{ method: 'POST', path: '/api/safe/orders', body: { itemId: 'ITEM1', qty: 1, price: 25 }, save: { orderId: '"id":"([\\w-]+)"' } }],
            controlSteps: [{ method: 'POST', path: '/api/safe/orders/{{orderId}}/pay', body: {} }],
            control: { body: { orderId: '{{orderId}}' } },
            readback: { method: 'GET', path: '/api/safe/orders/{{orderId}}', fields: { status: '"status":"(\\w+)"', payment: '"paymentStatus":"(\\w+)"' }, expect: { status: 'confirmed', payment: 'unpaid' } },
          },
        },
      },
      '/api/safe/coupons/apply': {
        post: {
          operationId: 'applySafeCoupon',
          requestBody: jsonBody({ orderId: { type: 'string' }, code: { type: 'string', enum: ['SAVE10', 'SAVE20'] } }),
          'x-limit': 1,
          'x-invariant': {
            kind: 'usage-limit', param: 'code', limit: 1,
            setup: [{ method: 'POST', path: '/api/safe/orders', body: { itemId: 'ITEM2', qty: 1, price: 40 }, save: { orderId: '"id":"([\\w-]+)"' } }],
            control: { body: { orderId: '{{orderId}}', code: 'SAVE10' } },
            readback: { method: 'GET', path: '/api/safe/orders/{{orderId}}', effect: '"couponCount":(\\d+)', model: 'count-exceeds' },
          },
        },
      },
      '/api/safe/rides/{id}/status': {
        patch: {
          operationId: 'setSafeRideStatus',
          'x-role': 'driver',
          requestBody: jsonBody({ status: { type: 'string', enum: ['accepted', 'started', 'completed'] } }),
          'x-invariant': {
            kind: 'role-gate', param: 'status', role: 'driver',
            concretePath: '/api/safe/rides/RIDE1/status',
            control: { unauth: true },
            readback: { method: 'GET', path: '/api/safe/rides/RIDE1', fields: { status: '"status":"(\\w+)"' }, expect: { status: '{{v}}' } },
          },
        },
      },
      '/api/safe/orders/{id}/cancel': {
        post: {
          operationId: 'cancelSafeOrder',
          'x-state-machine': { machine: 'order', transition: 'cancel' },
          'x-invariant': {
            kind: 'state-machine', machine: 'order', transition: 'cancel',
            setup: [
              { method: 'POST', path: '/api/safe/orders', body: { itemId: 'ITEM2', qty: 1, price: 40 }, save: { orderId: '"id":"([\\w-]+)"' } },
              { method: 'POST', path: '/api/safe/orders/{{orderId}}/pay', body: {} },
              { method: 'POST', path: '/api/safe/orders/{{orderId}}/ship', body: {} },
              { method: 'POST', path: '/api/safe/orders/{{orderId}}/deliver', body: {} },
            ],
            controlSetup: [{ method: 'POST', path: '/api/safe/orders', body: { itemId: 'ITEM1', qty: 1, price: 25 }, save: { cid: '"id":"([\\w-]+)"' } }],
            control: { method: 'POST', path: '/api/safe/orders/{{cid}}/cancel', body: {} },
            violationPath: '/api/safe/orders/{{orderId}}/cancel',
            readback: { method: 'GET', path: '/api/safe/orders/{{orderId}}', fields: { status: '"status":"(\\w+)"' }, expect: { status: 'cancelled' } },
          },
        },
      },
      '/api/safe/referrals': {
        post: {
          operationId: 'createSafeReferral',
          'x-distinct-actors': true,
          requestBody: jsonBody({ code: { type: 'string', enum: ['REF-ALICE', 'REF-BOB'] } }),
          'x-invariant': {
            kind: 'actor-separation', param: 'code',
            selfFrom: { method: 'GET', path: '/api/me', field: '"refCode":"([\\w-]+)"' },
            control: { body: { code: 'REF-BOB' } },
            readback: { method: 'GET', path: '/api/safe/referrals', effect: '"uses":(\\d+)', model: 'count-exceeds', limit: 1 },
          },
        },
      },
    },
  };
}

function freshState() {
  return {
    users: {
      [TENANT_USER]: { pass: TENANT_PASS, role: 'passenger', email: 'alice@logiclab.example', refCode: 'REF-ALICE' },
      bob: { pass: 'bob-never-logs-in', role: 'passenger', email: 'bob@logiclab.example', refCode: 'REF-BOB' },
      dave: { pass: 'dave-drives', role: 'driver', email: 'dave@logiclab.example', refCode: 'REF-DAVE' },
    },
    catalog: { ITEM1: { id: 'ITEM1', name: 'City ride voucher', price: 25 }, ITEM2: { id: 'ITEM2', name: 'Harbor tour seat', price: 40 } },
    wallet: { alice: 100, bob: 100 },          // vulnerable-surface wallet
    safeWallet: { alice: 100, bob: 100 },      // control-surface wallet
    rides: { RIDE1: { id: 'RIDE1', driver: 'dave', seats: 4, bookedSeats: 0, status: 'open' } },
    safeRides: { RIDE1: { id: 'RIDE1', driver: 'dave', seats: 4, bookedSeats: 0, status: 'open' } },
    orders: new Map(), orderSeq: 1000,
    safeOrders: new Map(), safeOrderSeq: 5000,
    coupons: { SAVE10: { code: 'SAVE10', off: 10 }, SAVE20: { code: 'SAVE20', off: 20 } },
    referralUses: [],                          // { code, by, marker }
    safeReferralUses: [],
  };
}

export function createLogiclabTarget() {
  let state = freshState();
  const sessions = new Map(); // sid -> user (survives /lab/revert: fixture resets must not kill the probing session)
  const SPEC = buildSpec();

  const json = (res, status, obj, extraHeaders = {}) => {
    res.writeHead(status, { 'content-type': 'application/json', ...extraHeaders });
    res.end(JSON.stringify(obj));
  };

  return http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://localhost');
    const path = u.pathname;
    const sessUser = () => {
      const sid = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith('ll_sess='));
      const sess = sid && sessions.get(sid.slice(8));
      return sess || null;
    };
    const me = sessUser;
    const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : Number(v));

    // --- lab hygiene: restore planted state (sessions survive on purpose) ----------
    if (path === '/lab/revert' && req.method === 'POST') {
      state = freshState();
      return json(res, 200, { ok: true, reverted: true });
    }

    // --- identity / docs / spec ------------------------------------------------------
    if (path === '/login' && req.method === 'POST') {
      const b = new URLSearchParams(await readBody(req));
      const usr = state.users[b.get('user')];
      if (!usr || usr.pass !== b.get('pass')) return json(res, 403, { error: 'bad credentials' });
      const sid = 'sess_' + randomBytes(6).toString('hex');
      sessions.set(sid, b.get('user'));
      res.writeHead(302, { location: '/account', 'set-cookie': `ll_sess=${sid}; Path=/; SameSite=Strict; HttpOnly` });
      return res.end();
    }
    if (path === '/docs') {
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end(`<!doctype html><title>Docs · Logiclab</title><h1>Developer docs</h1><p>Tenant demo account: <code>${TENANT_USER} / ${TENANT_PASS}</code>. The API is described by <code>GET /openapi.json</code> (OpenAPI 3, with the intended invariants annotated). Shop endpoints under <code>/api/*</code>; the hardened mirror under <code>/api/safe/*</code>.</p>`);
    }
    if (path === '/openapi.json') return json(res, 200, SPEC);
    if (path === '/api/me') {
      const user = me();
      if (!user) return json(res, 401, { error: 'authentication required' });
      const usr = state.users[user];
      return json(res, 200, { user, role: usr.role, email: usr.email, refCode: usr.refCode });
    }

    // === vulnerable surface =========================================================

    // V1: negative-amount payment CREDITS the wallet (no minimum check)
    if (path === '/api/payments' && req.method === 'POST') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const b = JSON.parse((await readBody(req)) || '{}');
      const amt = num(b.amount);
      if (!Number.isFinite(amt)) return json(res, 400, { error: 'amount required' });
      state.wallet[user] -= amt; // <-- the planted bug: amount may be negative
      return json(res, 200, { ok: true, balance: state.wallet[user], marker: LOGIC_CANARY });
    }
    if (path === '/api/wallet') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      return json(res, 200, { user, balance: state.wallet[user] });
    }

    // order lifecycle (vuln surface) — create TRUSTS the client price (V2)
    if (path === '/api/orders' && req.method === 'POST') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const b = JSON.parse((await readBody(req)) || '{}');
      const item = state.catalog[b.itemId];
      if (!item) return json(res, 404, { error: 'no such item' });
      const qty = num(b.qty) || 1;
      const unitPrice = num(b.price); // <-- planted bug: client price is authoritative
      if (!Number.isFinite(unitPrice)) return json(res, 400, { error: 'price required' });
      const id = 'ORD-' + (++state.orderSeq);
      state.orders.set(id, { id, user, itemId: item.id, qty, unitPrice, total: +(unitPrice * qty).toFixed(2), status: 'pending', paymentStatus: 'unpaid', coupons: [], couponCount: 0, marker: LOGIC_CANARY });
      return json(res, 200, { ok: true, id });
    }
    let m = /^\/api\/orders\/([\w-]+)(?:\/(pay|ship|deliver|cancel))?$/.exec(path);
    if (m && !path.startsWith('/api/safe/')) {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const o = state.orders.get(m[1]);
      if (!o) return json(res, 404, { error: 'not found' });
      const action = m[2] || (req.method === 'GET' ? 'read' : null);
      if (action === 'read') return json(res, 200, o);
      if (req.method !== 'POST') return json(res, 405, { error: 'method not allowed' });
      if (action === 'pay') { // the flow's middle step
        if (o.status !== 'pending') return json(res, 409, { error: 'not payable from ' + o.status });
        o.status = 'paid'; o.paymentStatus = 'paid';
        return json(res, 200, { ok: true, id: o.id });
      }
      if (action === 'ship') {
        if (o.status !== 'paid') return json(res, 409, { error: 'not shippable from ' + o.status });
        o.status = 'shipped'; return json(res, 200, { ok: true, id: o.id });
      }
      if (action === 'deliver') {
        if (o.status !== 'shipped') return json(res, 409, { error: 'not deliverable from ' + o.status });
        o.status = 'delivered'; return json(res, 200, { ok: true, id: o.id });
      }
      if (action === 'cancel') { // V7: NO from-state check — delivered orders cancel (and refund)
        if (o.status === 'cancelled') return json(res, 409, { error: 'already cancelled' });
        if (o.paymentStatus === 'paid') state.wallet[user] += o.total; // refund even after delivery
        o.status = 'cancelled';
        return json(res, 200, { ok: true, id: o.id, refunded: o.total, marker: LOGIC_CANARY });
      }
    }

    // V3: booking beyond ride capacity (no max check)
    if (path === '/api/bookings' && req.method === 'POST') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const b = JSON.parse((await readBody(req)) || '{}');
      const ride = state.rides[b.rideId];
      if (!ride) return json(res, 404, { error: 'no such ride' });
      const seats = num(b.seats);
      if (!Number.isInteger(seats) || seats < 1) return json(res, 400, { error: 'seats must be a positive integer' });
      ride.bookedSeats += seats; // <-- planted bug: capacity never consulted
      return json(res, 200, { ok: true, rideId: ride.id, bookedSeats: ride.bookedSeats, marker: LOGIC_CANARY });
    }
    if (path === '/api/rides/RIDE1' && req.method === 'GET') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      return json(res, 200, state.rides.RIDE1);
    }

    // V6: passenger drives the ride state machine (no role check)
    m = /^\/api\/rides\/([\w-]+)\/status$/.exec(path);
    if (m && req.method === 'PATCH') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const ride = state.rides[m[1]];
      if (!ride) return json(res, 404, { error: 'not found' });
      const b = JSON.parse((await readBody(req)) || '{}');
      ride.status = String(b.status || ride.status); // <-- planted bug: no driver-role check
      return json(res, 200, { ok: true, id: ride.id, status: ride.status, marker: LOGIC_CANARY });
    }

    // V4: confirm WITHOUT the payment step (flow-order not enforced)
    if (path === '/api/checkout/confirm' && req.method === 'POST') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const b = JSON.parse((await readBody(req)) || '{}');
      const o = state.orders.get(b.orderId);
      if (!o) return json(res, 404, { error: 'not found' });
      if (o.status === 'cancelled') return json(res, 409, { error: 'cancelled' });
      o.status = 'confirmed'; // <-- planted bug: paymentStatus never consulted
      return json(res, 200, { ok: true, id: o.id, status: o.status, marker: LOGIC_CANARY });
    }

    // V5: coupon stacking beyond the documented 1-per-order limit
    if (path === '/api/coupons/apply' && req.method === 'POST') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const b = JSON.parse((await readBody(req)) || '{}');
      const o = state.orders.get(b.orderId);
      const c = state.coupons[b.code];
      if (!o || !c) return json(res, 404, { error: 'not found' });
      if (o.coupons.includes(c.code)) return json(res, 409, { error: 'already applied' });
      o.coupons.push(c.code); o.couponCount++; o.total = Math.max(0, +(o.total - c.off).toFixed(2)); // <-- planted bug: no count limit
      return json(res, 200, { ok: true, id: o.id, coupons: o.coupons, total: o.total, marker: LOGIC_CANARY });
    }

    // V8: self-referral accepted (no distinct-actor check)
    if (path === '/api/referrals' && req.method === 'POST') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const b = JSON.parse((await readBody(req)) || '{}');
      const owner = Object.keys(state.users).find((k) => state.users[k].refCode === b.code);
      if (!owner) return json(res, 404, { error: 'no such code' });
      state.referralUses.push({ code: b.code, by: user, self: owner === user, marker: LOGIC_CANARY }); // <-- planted bug: self allowed (and repeatable)
      state.wallet[user] += 10;
      return json(res, 200, { ok: true, bonus: 10, marker: LOGIC_CANARY });
    }
    if (path === '/api/referrals' && req.method === 'GET') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      return json(res, 200, { uses: state.referralUses.filter((r) => r.by === user).length, selfUse: state.referralUses.some((r) => r.by === user && r.self) });
    }

    // === clean control surface: same intent, every invariant ENFORCED ===============

    if (path === '/api/safe/payments' && req.method === 'POST') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const b = JSON.parse((await readBody(req)) || '{}');
      const amt = num(b.amount);
      if (!Number.isFinite(amt) || amt < 1) return json(res, 422, { error: 'invalid amount' }); // enforced
      state.safeWallet[user] -= amt;
      return json(res, 200, { ok: true, balance: state.safeWallet[user] });
    }
    if (path === '/api/safe/wallet') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      return json(res, 200, { user, balance: state.safeWallet[user] });
    }

    // DECOY: accepts the client price field (200 — looks violated) but IGNORES it.
    if (path === '/api/safe/orders' && req.method === 'POST') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const b = JSON.parse((await readBody(req)) || '{}');
      const item = state.catalog[b.itemId];
      if (!item) return json(res, 404, { error: 'no such item' });
      const qty = num(b.qty) || 1;
      const unitPrice = item.price; // catalog price is authoritative — the client field is dropped
      const id = 'SAFE-' + (++state.safeOrderSeq);
      state.safeOrders.set(id, { id, user, itemId: item.id, qty, unitPrice, total: +(unitPrice * qty).toFixed(2), status: 'pending', paymentStatus: 'unpaid', coupons: [], couponCount: 0 });
      return json(res, 200, { ok: true, id }); // note: 200 either way — status cannot see the enforcement
    }
    m = /^\/api\/safe\/orders\/([\w-]+)(?:\/(pay|ship|deliver|cancel))?$/.exec(path);
    if (m) {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const o = state.safeOrders.get(m[1]);
      if (!o) return json(res, 404, { error: 'not found' });
      const action = m[2] || (req.method === 'GET' ? 'read' : null);
      if (action === 'read') return json(res, 200, o);
      if (req.method !== 'POST') return json(res, 405, { error: 'method not allowed' });
      if (action === 'pay') {
        if (o.status !== 'pending') return json(res, 409, { error: 'not payable from ' + o.status });
        o.status = 'paid'; o.paymentStatus = 'paid';
        return json(res, 200, { ok: true, id: o.id });
      }
      if (action === 'ship') {
        if (o.status !== 'paid') return json(res, 409, { error: 'not shippable from ' + o.status });
        o.status = 'shipped'; return json(res, 200, { ok: true, id: o.id });
      }
      if (action === 'deliver') {
        if (o.status !== 'shipped') return json(res, 409, { error: 'not deliverable from ' + o.status });
        o.status = 'delivered'; return json(res, 200, { ok: true, id: o.id });
      }
      if (action === 'cancel') { // enforced: cancel only from pending/paid
        if (!['pending', 'paid'].includes(o.status)) return json(res, 409, { error: 'cannot cancel from ' + o.status });
        o.status = 'cancelled';
        return json(res, 200, { ok: true, id: o.id });
      }
    }

    if (path === '/api/safe/bookings' && req.method === 'POST') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const b = JSON.parse((await readBody(req)) || '{}');
      const ride = state.safeRides[b.rideId];
      if (!ride) return json(res, 404, { error: 'no such ride' });
      const seats = num(b.seats);
      if (!Number.isInteger(seats) || seats < 1 || ride.bookedSeats + seats > ride.seats) {
        return json(res, 422, { error: 'invalid seat count' }); // enforced
      }
      ride.bookedSeats += seats;
      return json(res, 200, { ok: true, rideId: ride.id, bookedSeats: ride.bookedSeats });
    }
    if (path === '/api/safe/rides/RIDE1' && req.method === 'GET') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      return json(res, 200, state.safeRides.RIDE1);
    }

    m = /^\/api\/safe\/rides\/([\w-]+)\/status$/.exec(path);
    if (m && req.method === 'PATCH') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const ride = state.safeRides[m[1]];
      if (!ride) return json(res, 404, { error: 'not found' });
      if (user !== ride.driver) return json(res, 403, { error: 'driver only' }); // enforced (role)
      const b = JSON.parse((await readBody(req)) || '{}');
      ride.status = String(b.status || ride.status);
      return json(res, 200, { ok: true, id: ride.id, status: ride.status });
    }

    if (path === '/api/safe/checkout/confirm' && req.method === 'POST') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const b = JSON.parse((await readBody(req)) || '{}');
      const o = state.safeOrders.get(b.orderId);
      if (!o) return json(res, 404, { error: 'not found' });
      if (o.paymentStatus !== 'paid') return json(res, 409, { error: 'payment step required' }); // enforced (flow)
      o.status = 'confirmed';
      return json(res, 200, { ok: true, id: o.id, status: o.status });
    }

    if (path === '/api/safe/coupons/apply' && req.method === 'POST') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const b = JSON.parse((await readBody(req)) || '{}');
      const o = state.safeOrders.get(b.orderId);
      const c = state.coupons[b.code];
      if (!o || !c) return json(res, 404, { error: 'not found' });
      if (o.couponCount >= 1) return json(res, 409, { error: 'coupon limit reached' }); // enforced (limit)
      o.coupons.push(c.code); o.couponCount++; o.total = Math.max(0, +(o.total - c.off).toFixed(2));
      return json(res, 200, { ok: true, id: o.id, coupons: o.coupons, total: o.total });
    }

    if (path === '/api/safe/referrals' && req.method === 'POST') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      const b = JSON.parse((await readBody(req)) || '{}');
      const owner = Object.keys(state.users).find((k) => state.users[k].refCode === b.code);
      if (!owner) return json(res, 404, { error: 'no such code' });
      if (owner === user) return json(res, 422, { error: 'cannot refer yourself' }); // enforced (distinct actors)
      if (state.safeReferralUses.some((r) => r.by === user)) return json(res, 409, { error: 'already used a code' });
      state.safeReferralUses.push({ code: b.code, by: user });
      state.safeWallet[user] += 10;
      return json(res, 200, { ok: true, bonus: 10 });
    }
    if (path === '/api/safe/referrals' && req.method === 'GET') {
      const user = me(); if (!user) return json(res, 401, { error: 'authentication required' });
      return json(res, 200, { uses: state.safeReferralUses.filter((r) => r.by === user).length, selfUse: false });
    }

    if (path === '/' || path === '') {
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end('<!doctype html><title>Logiclab</title><h1>Logiclab travel shop</h1><p>Docs at /docs; spec at /openapi.json.</p>');
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end('{"error":"not found"}');
  });
}

// standalone (robust across Windows file:// vs file:/// normalization)
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.LOGICLAB_PORT || 8974);
  createLogiclabTarget().listen(port, '127.0.0.1', () => console.log(`Logiclab invariant garden on http://127.0.0.1:${port}`));
}
