// VARVEL — logicdiscover: business-logic invariant discovery from OBSERVED TRAFFIC (T3b).
//
// The annotation-free half of hyp-007. engine/logicinvariants.mjs reads intent from an
// OpenAPI spec's x-invariant/x-flows/x-state-machines annotations; real targets hand us
// no such spec. This module derives the SAME executable candidate shape (consumed
// unchanged by tools/logicprobe.mjs and the chainrun invariant step) from HTTP
// observations alone — the shapes recon already collects: endpoints, request/response
// JSON bodies, status codes, ordering.
//
// Input:  observations: [{ seq, session, method, path, status, req, res }] — req/res are
//         parsed JSON bodies (or null). Ordered; seq monotonic.
// Output: { candidates, dropped, stats } — candidates are extractInvariants-shaped
//         ({ id, kind, method, path, param, derived, setup, controlSteps, controlSetup,
//         control, violation, readback, selfFrom }) plus source:'traffic-discovery' and
//         an evidence trail naming the observations that motivated the candidate.
//
// Derivation rules (each documented, each honest — no control/readback ⇒ DROP):
//   1. server-authoritative — a money-named numeric request field (price|amount|…)
//      on a creation endpoint (response carries `id`, and a GET on <tpl>/{{id}} was
//      observed) ⇒ tamper to 0.01, read back the resource's money field (set-param).
//   2. bounds-min — a numeric request field whose every observed call moves a shared
//      numeric state field DOWN by exactly its value (debit semantics), never observed
//      ≤ 0 ⇒ probe −10×max-observed, readback subtract-param.
//   3. bounds-max — same but the state field accumulates UP by the value AND the
//      readback resource carries a constant same-named/capacity-vocab field ≥ the max
//      observed accumulation ⇒ probe capacity+1, readback add-param.
//   4. flow-order — a terminal POST referencing an entity id that was ALWAYS observed
//      after intermediate action(s) on that entity ⇒ skip the intermediates; expect
//      = fields the terminal step changed (post value) + fields the skipped step
//      changed (their pre-step value) — "B's effect present AND the skipped step's
//      effect absent", derived from the ordered field timeline.
//   5. usage-limit — a string request field with ≥2 distinct observed values where a
//      per-entity repeat of the SAME value was observed refused (4xx), and the entity
//      readback carries a count field ⇒ apply the second value; count-exceeds with
//      limit = max observed count.
//   6. role-gate — a mutating endpoint observed refusing unauth (401/403), never
//      observed succeeding, whose final path segment names a string field on the
//      parent resource ⇒ drive it to the first unobserved canonical terminal state;
//      the prover's own unauth re-fire is the control.
//   7. state-machine — a destructive-named action (cancel|close|refund|…) observed
//      succeeding ONLY from early states, while some entity was observed reaching a
//      later state ⇒ replay the observed journey to the late state, invoke the action,
//      expect the observed post-action state.
//   8. actor-separation — a string request field whose observed values share a token
//      shape (common prefix ≥3 ending in -/_:. ) with a field on the caller's identity
//      resource (GET exposing role/email) ⇒ redeem the caller's OWN value (resolved at
//      runtime via selfFrom), readback count-exceeds on the same-path GET.
//
// Verdict discipline is the prover's (tools/logicprobe.mjs): every candidate here
// carries its own control + readback recipe derived from the same observations, or it
// is DROPPED with the reason — inconclusive is never a claim. Pure, zero-dep, no network.

const TERMINAL_VOCAB = ['completed', 'cancelled', 'delivered', 'closed', 'approved', 'refunded'];
const DESTRUCTIVE_ACTIONS = ['cancel', 'close', 'refund', 'void', 'delete', 'abort', 'archive'];
const MONEY_REQUEST = ['price', 'amount', 'total', 'cost', 'fee', 'fare'];
const MONEY_READBACK = ['unitPrice', 'price', 'amount', 'total', 'cost', 'fee', 'fare'];
const CAPACITY_FIELDS = ['seats', 'capacity', 'limit', 'max', 'quota', 'stock'];
const ID_FIELD = (f) => f === 'id' || /Id$/.test(f);

const isObj = (v) => v != null && typeof v === 'object' && !Array.isArray(v);
const numFields = (o) => (isObj(o) ? Object.keys(o).filter((k) => typeof o[k] === 'number' && Number.isFinite(o[k])) : []);
const strFields = (o) => (isObj(o) ? Object.keys(o).filter((k) => typeof o[k] === 'string') : []);
const numRe = (f) => `"${f}":(-?[\\d.]+)`;
const strRe = (f) => `"${f}":"([\\w-]+)"`;
const commonPrefix = (a, b) => { const s = String(a), t = String(b); let i = 0; while (i < s.length && i < t.length && s[i] === t[i]) i++; return s.slice(0, i); };

export function discoverInvariants(observations) {
  const obs = (Array.isArray(observations) ? observations : []).map((o, i) => ({
    seq: Number.isFinite(o && o.seq) ? o.seq : i,
    session: (o && o.session) || 'anon',
    method: String((o && o.method) || 'GET').toUpperCase(),
    path: String((o && o.path) || ''),
    status: Number.isFinite(o && o.status) ? o.status : 0,
    req: isObj(o && o.req) ? o.req : null,
    res: isObj(o && o.res) ? o.res : null,
  }));
  const candidates = [];
  const dropped = [];
  const drop = (rule, target, reason) => dropped.push({ rule, target: String(target), reason });

  // ——— entity registration: creation responses carry a string `id`; later paths
  // referencing that value are templated to {{id}}. Only the canonical `id` field
  // registers (a `rideId` field is a reference, not a creation). ———
  const idValues = new Set();
  for (const o of obs) if (o.res && typeof o.res.id === 'string' && o.res.id.length >= 2) idValues.add(o.res.id);
  const templatize = (path) => String(path).split('/').map((s) => (idValues.has(s) ? '{{id}}' : s)).join('/');

  const byTpl = new Map(); // 'METHOD template' -> [obs]
  for (const o of obs) {
    const k = o.method + ' ' + templatize(o.path);
    if (!byTpl.has(k)) byTpl.set(k, []);
    byTpl.get(k).push(o);
  }
  const gets = (tpl) => byTpl.get('GET ' + tpl) || [];
  const posts = [...byTpl.entries()].filter(([k]) => k.startsWith('POST ')).map(([, v]) => v);
  const isCreation = (list, tpl) => list.some((o) => o.status < 300 && o.res && typeof o.res.id === 'string') && gets(tpl + '/{{id}}').length > 0;

  const createObsFor = (idv) => obs.find((o) => o.method === 'POST' && o.status < 300 && o.res && o.res.id === idv);
  const timeline = (idv) => obs
    .filter((o) => o.path.includes(idv) || (o.req && Object.values(o.req).includes(idv)))
    .sort((a, b) => a.seq - b.seq);
  const entityGetTpl = (idv) => {
    const g = obs.find((o) => o.method === 'GET' && o.status < 300 && o.path.includes(idv));
    return g ? templatize(g.path) : null;
  };

  // identity resource: a GET exposing role/email (the caller's self-description)
  let identity = null;
  for (const [k, list] of byTpl) {
    if (!k.startsWith('GET ')) continue;
    const o = list.find((x) => x.status < 300 && x.res && (typeof x.res.role === 'string' || typeof x.res.email === 'string'));
    if (o) { identity = { tpl: templatize(o.path), res: o.res }; break; }
  }

  const push = (c) => candidates.push({
    specPath: null, param: null, setup: [], controlSteps: [], controlSetup: [], control: {},
    violation: null, readback: null, selfFrom: null,
    source: 'traffic-discovery', ...c,
  });

  // ——— 1. server-authoritative (creation endpoint, money-named client field) ———
  for (const list of posts) {
    const tpl = templatize(list[0].path);
    if (!isCreation(list, tpl)) continue;
    const first = list.find((o) => o.req && o.status < 300);
    if (!first) continue;
    const rbFields = numFields(gets(tpl + '/{{id}}')[0].res);
    for (const f of numFields(first.req)) {
      if (!MONEY_REQUEST.includes(f)) continue;
      const g = MONEY_READBACK.find((x) => rbFields.includes(x));
      if (!g) { drop('server-authoritative', `${tpl}#${f}`, `money-named request field "${f}" but the linked readback ${tpl}/{{id}} exposes no money field — no readback oracle derivable`); continue; }
      push({
        id: `traffic:POST ${tpl}#${f}`, kind: 'server-authoritative', method: 'POST', path: tpl, param: f,
        derived: { values: [0.01], basis: `traffic: "${f}" is a money-named client field on a creation endpoint; tamper to 0.01 and read back the server's "${g}"` },
        control: { body: first.req },
        violation: { method: 'POST', path: tpl, body: { ...first.req, [f]: 0.01 } },
        readback: { method: 'GET', path: tpl + '/{{id}}', effect: numRe(g), model: 'set-param', saveFromViolation: { var: 'id', regex: strRe('id') } },
        evidence: { observedAt: first.seq, readbackPath: tpl + '/{{id}}', readbackField: g },
      });
    }
  }

  // ——— 2/3. bounds-min (debit sign) / bounds-max (observed capacity) ———
  for (const list of posts) {
    const tpl = templatize(list[0].path);
    if (isCreation(list, tpl)) continue;
    const withReq = list.filter((o) => o.req && o.status < 300);
    if (!withReq.length) continue;
    const reqNums = numFields(withReq[0].req).filter((f) => withReq.every((o) => typeof o.req[f] === 'number'));
    for (const f of reqNums) {
      const effFields = numFields((withReq.find((o) => o.res) || {}).res);
      if (!effFields.length) { drop('bounds', `${tpl}#${f}`, 'endpoint responses expose no numeric state field — no readback oracle derivable'); continue; }
      let emitted = false;
      for (const e of effFields) {
        const gEntry = [...byTpl.entries()].find(([k, l]) => k.startsWith('GET ') && l.some((o) => o.res && typeof o.res[e] === 'number'));
        if (!gEntry) { drop('bounds', `${tpl}#${f}`, `effect field "${e}" never observed on any GET — no readback oracle derivable`); continue; }
        const gTpl = gEntry[0].slice(4);
        // The readback must be a CONCRETE observed path (the prover has no {{id}}
        // binding for shared-state resources); prefer the GET whose path carries an
        // entity id that the control request body references.
        const concreteRb = (reqBody) => {
          const g = gEntry[1].find((o) => Object.values(reqBody || {}).some((v) => typeof v === 'string' && o.path.split('/').includes(v)));
          return g ? g.path : gTpl;
        };
        const pairs = [];
        for (const o of withReq) {
          if (!o.res || typeof o.res[e] !== 'number') continue;
          const prev = obs.filter((x) => x.seq < o.seq && x.res && typeof x.res[e] === 'number').pop();
          if (prev) pairs.push({ v: o.req[f], d: o.res[e] - prev.res[e] });
        }
        if (!pairs.length) { drop('bounds', `${tpl}#${f}`, `no before/after "${e}" observations bracket a call — correlation underivable`); continue; }
        const subtract = pairs.every((p) => p.v > 0 && Math.abs(p.d + p.v) < 1e-9);
        const add = pairs.every((p) => p.v > 0 && Math.abs(p.d - p.v) < 1e-9);
        if (subtract) {
          const maxV = Math.max(...pairs.map((p) => p.v));
          const ctrl = withReq.find((o) => o.req[f] === maxV) || withReq[0];
          push({
            id: `traffic:POST ${tpl}#${f}`, kind: 'bounds-min', method: 'POST', path: tpl, param: f,
            derived: { values: [-10 * maxV], basis: `traffic: "${e}" drops by exactly "${f}" on ${pairs.length} observed call(s) (debit semantics) and ${f} was never observed ≤ 0 → probe ${-10 * maxV}` },
            control: { body: ctrl.req },
            violation: { method: 'POST', path: tpl, body: { ...ctrl.req, [f]: -10 * maxV } },
            readback: { method: 'GET', path: concreteRb(ctrl.req), effect: numRe(e), model: 'subtract-param' },
            evidence: { correlations: pairs, effect: e, readbackPath: concreteRb(ctrl.req) },
          });
          emitted = true; break;
        }
        if (add) {
          const resSnaps = gEntry[1].map((o) => o.res).filter((r) => r && typeof r[e] === 'number');
          const eMax = Math.max(...obs.map((x) => (x.res && typeof x.res[e] === 'number' ? x.res[e] : 0)));
          const cap = numFields(resSnaps[0] || {}).find((c) =>
            (c === f || CAPACITY_FIELDS.includes(c)) &&
            resSnaps.every((r) => r[c] === resSnaps[0][c]) &&
            resSnaps[0][c] >= eMax);
          if (cap == null) { drop('bounds-max', `${tpl}#${f}`, `"${e}" accumulates by "${f}" but no constant capacity field observed on ${gTpl} — cannot motivate an overrun value`); continue; }
          const capVal = resSnaps[0][cap];
          const ctrl = withReq.slice().sort((a, b) => a.req[f] - b.req[f])[0];
          push({
            id: `traffic:POST ${tpl}#${f}`, kind: 'bounds-max', method: 'POST', path: tpl, param: f,
            derived: { values: [capVal + 1], basis: `traffic: "${e}" grows by exactly "${f}" and the resource's constant "${cap}" = ${capVal} caps every observed accumulation → probe ${capVal + 1}` },
            control: { body: ctrl.req },
            violation: { method: 'POST', path: tpl, body: { ...ctrl.req, [f]: capVal + 1 } },
            readback: { method: 'GET', path: concreteRb(ctrl.req), effect: numRe(e), model: 'add-param' },
            evidence: { correlations: pairs, effect: e, capacityField: cap, capacity: capVal, readbackPath: concreteRb(ctrl.req) },
          });
          emitted = true; break;
        }
        drop('bounds', `${tpl}#${f}`, `effect "${e}" deltas ${JSON.stringify(pairs)} correlate neither negatively nor positively with "${f}" — honestly unmotivated`);
      }
      void emitted;
    }
  }

  // ——— 4. flow-order (terminal call always preceded by intermediates) ———
  for (const list of posts) {
    const tpl = templatize(list[0].path);
    if (isCreation(list, tpl)) continue;
    const o = list.find((x) => x.req && x.status < 300 && Object.values(x.req).some((v) => typeof v === 'string' && idValues.has(v)));
    if (!o) continue;
    const [refKey, idv] = Object.entries(o.req).find(([, v]) => typeof v === 'string' && idValues.has(v));
    const tl = timeline(idv);
    const create = createObsFor(idv);
    if (!create) continue;
    const intermediates = tl.filter((x) => x.seq > create.seq && x.seq < o.seq && x.method === 'POST' && x.path.includes(idv));
    if (!intermediates.length) { drop('flow-order', tpl, `no intermediate step observed between creation and the terminal call for ${idv} — no flow to skip`); continue; }
    const getsTl = tl.filter((x) => x.method === 'GET' && x.status < 300);
    const atCreate = getsTl.find((x) => x.seq > create.seq && x.seq < intermediates[0].seq);
    const before = getsTl.filter((x) => x.seq < o.seq).pop();
    const after = getsTl.find((x) => x.seq > o.seq);
    if (!atCreate || !before || !after) { drop('flow-order', tpl, 'insufficient readback observations around the terminal call — no expect oracle derivable'); continue; }
    // expect: fields the terminal step changed → post value; fields an intermediate
    // changed → the PRE-step (creation-time) value. Id-like/volatile fields excluded.
    const fields = {};
    const expect = {};
    for (const f of strFields(after.res)) {
      if (ID_FIELD(f)) continue;
      if (![atCreate, before, after].every((s) => typeof s.res[f] === 'string')) continue;
      fields[f] = strRe(f);
      expect[f] = before.res[f] !== after.res[f] ? after.res[f] : atCreate.res[f];
    }
    if (!Object.keys(fields).length) { drop('flow-order', tpl, 'no stable string state fields across the entity timeline — no readback oracle derivable'); continue; }
    if (!Object.keys(fields).some((f) => before.res[f] !== after.res[f])) { drop('flow-order', tpl, 'the terminal call changed no observed state field — nothing to assert'); continue; }
    push({
      id: `traffic:POST ${tpl}`, kind: 'flow-order', method: 'POST', path: tpl,
      derived: { values: [null], basis: `traffic: ${tpl} was only ever observed AFTER ${intermediates.map((i) => i.path.split('/').pop()).join(',')} on the same entity → invoke it on a fresh entity with the intermediate(s) skipped` },
      setup: [{ method: create.method, path: templatize(create.path), body: create.req, save: { id: strRe('id') } }],
      controlSteps: intermediates.map((i) => ({ method: i.method, path: templatize(i.path), body: i.req || {} })),
      control: { body: { ...o.req, [refKey]: '{{id}}' } },
      violation: { method: 'POST', path: tpl, body: { ...o.req, [refKey]: '{{id}}' } },
      readback: { method: 'GET', path: templatize(after.path), fields, expect },
      evidence: { entity: idv, intermediates: intermediates.map((i) => templatize(i.path)) },
    });
  }

  // ——— 5. usage-limit (per-entity repeat refused; second distinct value) ———
  for (const list of posts) {
    const tpl = templatize(list[0].path);
    if (isCreation(list, tpl)) continue;
    const all = list.filter((o) => o.req);
    const refs = all.map((o) => ({ o, ref: Object.entries(o.req).find(([, v]) => typeof v === 'string' && idValues.has(v)) })).filter((x) => x.ref);
    if (!refs.length) continue;
    const strFs = strFields(refs[0].o.req).filter((f) => !idValues.has(refs[0].o.req[f]));
    for (const f of strFs) {
      const values = [...new Set(refs.filter((x) => x.o.status < 300).map((x) => x.o.req[f]).filter((v) => typeof v === 'string'))];
      if (values.length < 2) continue;
      const seen = new Set();
      const refusal = refs.some((x) => {
        const k = x.ref[1] + '|' + x.o.req[f];
        const refused = seen.has(k) && x.o.status >= 400;
        if (x.o.status < 300) seen.add(k);
        return refused;
      });
      if (!refusal) { drop('usage-limit', `${tpl}#${f}`, 'no observed per-entity repeat refusal — cannot motivate a one-per-entity limit'); continue; }
      const idv = refs[0].ref[1];
      const gTpl = entityGetTpl(idv);
      const countField = gTpl && gets(gTpl).length
        ? numFields(gets(gTpl)[0].res).find((c) => /count/i.test(c))
        : null;
      if (!countField) { drop('usage-limit', `${tpl}#${f}`, 'no per-entity count field observed — no readback oracle derivable'); continue; }
      const create = createObsFor(idv);
      if (!create) { drop('usage-limit', `${tpl}#${f}`, 'the referenced entity\'s creation call was never observed — no setup derivable'); continue; }
      const controlVal = refs.find((x) => x.o.status < 300).o.req[f];
      const other = values.find((v) => v !== controlVal);
      const limit = Math.max(0, ...obs.map((x) => (x.res && typeof x.res[countField] === 'number' ? x.res[countField] : 0)));
      push({
        id: `traffic:POST ${tpl}#${f}`, kind: 'usage-limit', method: 'POST', path: tpl, param: f,
        derived: { values: [other], basis: `traffic: "${f}" observed with ${values.length} distinct values, a same-value repeat on one entity was refused (${refs.find((x) => x.o.status >= 400) ? refs.find((x) => x.o.status >= 400).o.status : '4xx'}), and "${countField}" never exceeded ${limit} → apply a second distinct value to one entity`, limit },
        setup: [{ method: create.method, path: templatize(create.path), body: create.req, save: { id: strRe('id') } }],
        control: { body: { ...refs[0].o.req, [refs[0].ref[0]]: '{{id}}' } },
        violation: { method: 'POST', path: tpl, body: { ...refs[0].o.req, [refs[0].ref[0]]: '{{id}}', [f]: other } },
        readback: { method: 'GET', path: gTpl, effect: numRe(countField), model: 'count-exceeds', limit },
        evidence: { values, controlVal, countField, limit },
      });
    }
  }

  // ——— 6. role-gate (unauth-refused mutator of a resource state field) ———
  const mutRefusals = obs.filter((o) => ['POST', 'PATCH', 'PUT'].includes(o.method) && (o.status === 401 || o.status === 403));
  const roleSeen = new Set();
  for (const o of mutRefusals) {
    const m = /^(.*)\/(\w+)$/.exec(o.path);
    if (!m) continue;
    const [, parent, action] = m;
    const gTpl = templatize(parent);
    const gList = gets(gTpl).filter((x) => x.status < 300 && x.res);
    if (!gList.length) continue;
    if (!strFields(gList[0].res).includes(action)) continue; // the action must name a resource string field
    const key = o.method + ' ' + o.path;
    if (roleSeen.has(key)) continue;
    if (obs.some((x) => x.method === o.method && templatize(x.path) === templatize(o.path) && x.status > 0 && x.status < 300)) continue; // observed succeeding → usable, not a gate
    roleSeen.add(key);
    const seenVals = new Set(gList.map((x) => x.res[action]).filter((v) => typeof v === 'string'));
    const probe = TERMINAL_VOCAB.find((v) => !seenVals.has(v));
    if (!probe) { drop('role-gate', o.path, 'every canonical terminal state already observed — nothing to drive to'); continue; }
    push({
      id: `traffic:${o.method} ${o.path}#${action}`, kind: 'role-gate', method: o.method, path: o.path, param: action,
      derived: { values: [probe], basis: `traffic: ${o.method} ${o.path} refused unauthenticated (${o.status}), was never observed succeeding for this session, and drives the resource's "${action}" field (observed: ${[...seenVals].join('/') || 'none'}) → the low-priv session drives it to the unobserved terminal "${probe}"` },
      control: { unauth: true }, // the prover re-fires the request without a session; refusal = control
      violation: { method: o.method, path: o.path, body: { [action]: probe } },
      readback: { method: 'GET', path: parent, fields: { [action]: strRe(action) }, expect: { [action]: '{{v}}' } },
      evidence: { refusalStatus: o.status, observedValues: [...seenVals] },
    });
  }

  // ——— 7. state-machine (destructive action from a state it never succeeded from) ———
  const families = new Map(); // entity GET template -> [id values]
  for (const idv of idValues) {
    const g = entityGetTpl(idv);
    if (!g) continue;
    if (!families.has(g)) families.set(g, []);
    families.get(g).push(idv);
  }
  for (const [gTpl, ids] of families) {
    const gList = gets(gTpl).filter((x) => x.status < 300 && x.res);
    if (!gList.length) continue;
    const statusField = strFields(gList[0].res).find((f) => f === 'status' || f === 'state');
    if (!statusField) continue;
    const actions = new Map(); // action -> { from:Set, to:Set, sample }
    for (const idv of ids) {
      const tl = timeline(idv);
      for (const x of tl) {
        if (x.method !== 'POST' || x.status >= 300 || !x.path.includes(idv)) continue;
        const am = /^\/(\w+)$/.exec(x.path.split(idv)[1] || '');
        if (!am) continue;
        const prevGet = tl.filter((g) => g.method === 'GET' && g.seq < x.seq && g.res).pop();
        const nextGet = tl.find((g) => g.method === 'GET' && g.seq > x.seq && g.res);
        if (!prevGet || !nextGet) continue;
        if (!actions.has(am[1])) actions.set(am[1], { from: new Set(), to: new Set(), sample: x });
        actions.get(am[1]).from.add(prevGet.res[statusField]);
        actions.get(am[1]).to.add(nextGet.res[statusField]);
      }
    }
    for (const [a, info] of actions) {
      if (!DESTRUCTIVE_ACTIONS.includes(a)) continue;
      const toState = [...info.to][0];
      if (!toState) continue;
      for (const idv of ids) {
        const tl = timeline(idv);
        const gts = tl.filter((g) => g.method === 'GET' && g.res);
        if (!gts.length) continue;
        // The probe state is the entity's FINAL observed state — provided it is neither
        // an observed-legal from-state nor the action's own to-state (cancelling an
        // already-cancelled entity is an idempotency question, not a transition
        // violation), AND the entity's own journey demonstrably reaches it: the last
        // entity-path action's next GET shows that state.
        const final = gts[gts.length - 1].res[statusField];
        if (!final || info.from.has(final) || info.to.has(final)) continue;
        const create = createObsFor(idv);
        if (!create) continue;
        const drivers = tl.filter((x) => x.method === 'POST' && x.status < 300 && x.path.includes(idv) && x.seq > create.seq);
        const lastDriver = drivers[drivers.length - 1] || null;
        const reachGet = lastDriver ? gts.find((g) => g.seq > lastDriver.seq) : gts.find((g) => g.seq > create.seq);
        if (!reachGet || reachGet.res[statusField] !== final) continue; // journey doesn't reach the final state via observed steps — can't build the setup
        if (!gts.some((g) => info.from.has(g.res[statusField]))) continue; // never passed through an observed-legal from-state — no contrast
        push({
          id: `traffic:POST ${gTpl.replace('{{id}}', '×')}/${a}`, kind: 'state-machine', method: info.sample.method, path: templatize(info.sample.path),
          derived: { values: [null], basis: `traffic: "${a}" only ever succeeded from ${JSON.stringify([...info.from])} but an entity's observed journey ends at "${final}" → drive a fresh entity there and invoke ${a}`, toState, preState: final },
          setup: [
            { method: create.method, path: templatize(create.path), body: create.req, save: { id: strRe('id') } },
            ...drivers.map((d) => ({ method: d.method, path: templatize(d.path), body: d.req || {} })),
          ],
          controlSetup: [{ method: create.method, path: templatize(create.path), body: create.req, save: { cid: strRe('id') } }],
          control: { method: info.sample.method, path: templatize(info.sample.path).replace('{{id}}', '{{cid}}'), body: info.sample.req || {} },
          violation: { method: info.sample.method, path: templatize(info.sample.path), body: info.sample.req || {} },
          readback: { method: 'GET', path: gTpl, fields: { [statusField]: strRe(statusField) }, expect: { [statusField]: toState } },
          evidence: { action: a, allowedFrom: [...info.from], probedFrom: final, toState },
        });
        break; // one candidate per action per family
      }
    }
  }

  // ——— 8. actor-separation (redeem the caller's OWN operand) ———
  if (identity) {
    for (const list of posts) {
      const tpl = templatize(list[0].path);
      if (isCreation(list, tpl)) continue;
      const withReq = list.filter((o) => o.req && o.status < 300);
      if (!withReq.length) continue;
      const gList = gets(tpl).filter((x) => x.status < 300 && x.res);
      if (!gList.length) continue; // no same-path readback → no oracle
      const countField = numFields(gList[0].res)[0];
      if (!countField) continue;
      for (const f of strFields(withReq[0].req)) {
        const vals = [...new Set(withReq.map((o) => o.req[f]).filter((v) => typeof v === 'string'))];
        if (!vals.length) continue;
        const match = strFields(identity.res)
          .map((g) => ({ g, v: identity.res[g] }))
          .find(({ v }) => vals.some((x) => { const p = commonPrefix(x, v); return p.length >= 3 && /[-_:.]$/.test(p); }));
        if (!match) continue;
        const limit = Math.max(0, ...gList.map((x) => (typeof x.res[countField] === 'number' ? x.res[countField] : 0)));
        push({
          id: `traffic:POST ${tpl}#${f}`, kind: 'actor-separation', method: 'POST', path: tpl, param: f,
          derived: { values: ['{{self}}'], basis: `traffic: "${f}" values share a token shape with the caller's own "${match.g}" (common prefix "${commonPrefix(vals[0], match.v)}") → redeem the caller's OWN value (resolved at runtime)`, limit },
          selfFrom: { method: 'GET', path: identity.tpl, field: strRe(match.g) },
          control: { body: withReq[0].req },
          violation: { method: 'POST', path: tpl, body: { ...withReq[0].req, [f]: '{{self}}' } },
          readback: { method: 'GET', path: tpl, effect: numRe(countField), model: 'count-exceeds', limit },
          evidence: { values: vals, identityField: match.g, countField, limit },
        });
        break; // one actor-separation candidate per endpoint
      }
    }
  }

  return {
    candidates,
    dropped,
    stats: {
      observations: obs.length,
      templates: byTpl.size,
      entities: idValues.size,
      identity: identity ? identity.tpl : null,
      candidates: candidates.length,
      dropped: dropped.length,
    },
  };
}
