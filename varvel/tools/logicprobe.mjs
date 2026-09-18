// VARVEL — logicprobe: the business-logic invariant PROVER (T3).
//
// Executes one extracted invariant candidate (engine/logicinvariants.mjs) against a
// target, to the platform's proof standard:
//
//   CONTROL first  — a spec-valid request must succeed (proves the endpoint is
//                    usable by us and establishes the baseline state). No working
//                    control = NO CLAIM (inconclusive), mirroring the race doctrine.
//   VIOLATION      — the request the spec says must be rejected/ignored, with the
//                    extractor-derived value.
//   READBACK       — the effect is read from STATE (balance, seat count, order
//                    status+coupon count, referral count), never inferred from the
//                    violation response's status code.
//
// Verdict vocabulary (classifyLogic is pure):
//   violated    — control succeeded AND violation accepted AND readback shows the
//                 ATTACKER-CHOSEN effect (tampered price materialized, balance moved
//                 by the negative amount, terminal state reached without the middle
//                 step, count beyond the limit, own code credited)
//   enforced    — violation refused (4xx), OR accepted-but-ineffective (the DECOY
//                 shape: 200 yet the readback shows the server-side value)
//   inconclusive— control failed, readback unreadable, or effect ambiguous
//
// naiveLogicFlag() is the status-code heuristic (violation request returned 2xx) —
// exported so tests can show it claims the enforced decoy while the oracle clears it.
//
// ⚠ These probes are WRITE-PRONE (they create orders, move balances, drive state
// machines). They run only in the HITL-gated exploit phase, never in recon/validate.
// runLogicProbe NEVER throws.

import http from 'node:http';

function req(base, { method = 'GET', path, headers = {}, body = null, timeout = 3000 }) {
  return new Promise((resolve) => {
    const u = new URL(path, base);
    if (u.origin !== new URL(base).origin) { resolve(null); return; } // same-origin governance
    const h = { 'user-agent': 'VARVEL-logicprobe', ...headers };
    if (body != null && !h['content-type']) h['content-type'] = 'application/json';
    const r = http.request({ hostname: u.hostname, port: u.port || 80, path: u.pathname + u.search, method, timeout, headers: h }, (res) => {
      let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    r.on('error', () => resolve(null)); r.on('timeout', () => { r.destroy(); resolve(null); });
    if (body != null) r.write(typeof body === 'string' ? body : JSON.stringify(body));
    r.end();
  });
}

const render = (s, vars) => typeof s === 'string'
  ? s.replace(/\{\{(\w+)\}\}/g, (m, k) => (vars[k] ?? m))
  : s;
const renderDeep = (v, vars) => typeof v === 'string' ? render(v, vars)
  : Array.isArray(v) ? v.map((x) => renderDeep(x, vars))
  : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, renderDeep(x, vars)]))
  : v;

const grab = (body, regex) => {
  try { const m = new RegExp(regex).exec(body || ''); return m ? (m[1] ?? m[0]) : null; } catch { return null; }
};

// ——— the pure classifier ———
export function naiveLogicFlag({ violationStatus }) {
  return violationStatus != null && violationStatus >= 200 && violationStatus < 300;
}

export function classifyLogic({ controlOk, violationStatus, effectMatch }) {
  const refused = violationStatus != null && violationStatus >= 400 && violationStatus < 500;
  const accepted = naiveLogicFlag({ violationStatus });
  if (!controlOk) return { verdict: 'inconclusive', detail: 'control request failed — the endpoint is unusable by this session; no claim without a working control' };
  if (refused) return { verdict: 'enforced', detail: `violating request refused (${violationStatus}) — the invariant holds` };
  if (accepted && effectMatch === 'attacker') return { verdict: 'violated', detail: 'violation accepted AND the state readback shows the attacker-chosen effect' };
  if (accepted && (effectMatch === 'server' || effectMatch === 'unchanged')) return { verdict: 'enforced', detail: 'violation request accepted (2xx) but the readback shows the SERVER-side value — accepted-but-ineffective, not a violation' };
  if (!accepted) return { verdict: 'inconclusive', detail: `violation request returned ${violationStatus}` };
  return { verdict: 'inconclusive', detail: 'state readback unreadable or ambiguous — no claim without the readback' };
}

// Effect comparison per readback model. Returns 'attacker' | 'server' | 'unchanged' | null.
function matchNumeric(model, base, after, v, limit) {
  if (after == null) return null;
  const num = (x) => (x == null ? null : Number(x));
  const b = num(base), a = num(after), val = num(v);
  switch (model) {
    case 'set-param':
      if (val == null) return null;
      return Math.abs(a - val) < 1e-9 ? 'attacker' : 'server';
    case 'add-param':
      if (b == null || val == null) return null;
      if (Math.abs(a - (b + val)) < 1e-9) return 'attacker';
      if (Math.abs(a - b) < 1e-9) return 'unchanged';
      return null;
    case 'subtract-param':
      if (b == null || val == null) return null;
      if (Math.abs(a - (b - val)) < 1e-9) return 'attacker';
      if (Math.abs(a - b) < 1e-9) return 'unchanged';
      return null;
    case 'count-exceeds': {
      const lim = limit ?? num(base);
      if (b == null) return a > lim ? 'attacker' : 'unchanged';
      return a > b && b >= lim ? 'attacker' : (a === b ? 'unchanged' : null);
    }
    default:
      return null;
  }
}

function matchFields(readback, body, vars) {
  const got = {};
  for (const [name, regex] of Object.entries(readback.fields || {})) got[name] = grab(body, regex);
  if (Object.values(got).some((v) => v == null)) return { match: null, got };
  const expect = renderDeep(readback.expect || {}, vars);
  const all = Object.entries(expect).every(([k, v]) => got[k] === v);
  return { match: all ? 'attacker' : 'server', got, expect };
}

// ——— the governed prober ———
// runLogicProbe(base, candidate, { headers, resetPath, timeout })
export async function runLogicProbe(base, candidate, { headers = {}, resetPath = null, timeout = 3000 } = {}) {
  try {
    if (!candidate || !candidate.kind) return { verdict: 'inconclusive', detail: 'no candidate', naiveWouldFlag: false, requests: 0 };
    let requests = 0;
    const vars = {};
    const fire = async (spec) => {
      const r = await req(base, {
        method: spec.method || 'POST',
        path: render(spec.path, vars),
        headers: spec.unauth ? {} : headers,
        body: spec.body != null ? renderDeep(spec.body, vars) : null,
        timeout,
      });
      requests++;
      return r;
    };
    const runSteps = async (steps) => {
      for (const s of steps || []) {
        const r = await fire(s);
        if (!r || r.status >= 400) return { ok: false, status: r ? r.status : null, step: s.path };
        for (const [varName, regex] of Object.entries(s.save || {})) {
          const v = grab(r.body, regex);
          if (v == null) return { ok: false, status: r.status, step: s.path, error: 'save failed for ' + varName };
          vars[varName] = v;
        }
      }
      return { ok: true };
    };
    const readback = async (rb) => {
      if (!rb) return null;
      const r = await fire({ method: rb.method || 'GET', path: rb.path });
      return r ? r.body : null;
    };
    if (resetPath) { await fire({ method: 'POST', path: resetPath, body: {} }); }

    const xi = candidate;
    const v = xi.derived && xi.derived.values ? xi.derived.values[0] : null;
    vars.v = v; // for expect templates like {{v}}
    let controlOk = false;
    let violationStatus = null;
    let effectMatch = null;
    let baseVal = null, afterVal = null, fieldsGot = null;
    let rbBody = null;

    if (xi.kind === 'role-gate') {
      // control: the SAME request without a session must be refused
      const cr = await fire({ method: xi.method, path: xi.path, body: { [xi.param]: v }, unauth: true });
      controlOk = !!cr && [401, 403].includes(cr.status);
      const vr = await fire({ method: xi.method, path: xi.path, body: { [xi.param]: v } });
      violationStatus = vr ? vr.status : null;
      rbBody = await readback(xi.readback);
      const fm = xi.readback && xi.readback.fields ? matchFields(xi.readback, rbBody, vars) : { match: null };
      effectMatch = fm.match; fieldsGot = fm.got;
    } else if (xi.kind === 'flow-order') {
      // control: full legitimate flow (setup + middle steps + terminal) must succeed
      const cSetup = await runSteps(xi.setup);
      const cMid = cSetup.ok ? await runSteps(xi.controlSteps) : cSetup;
      const cReq = cMid.ok ? await fire({ method: xi.method, path: xi.path, body: xi.control.body }) : null;
      controlOk = !!(cSetup.ok && cMid.ok && cReq && cReq.status >= 200 && cReq.status < 300);
      // violation: FRESH entity (re-run setup), then the terminal step WITHOUT the middle
      const vSetup = await runSteps(xi.setup);
      if (vSetup.ok) {
        const vr = await fire({ method: xi.method, path: xi.path, body: xi.control.body });
        violationStatus = vr ? vr.status : null;
        rbBody = await readback(xi.readback);
        const fm = matchFields(xi.readback, rbBody, vars);
        effectMatch = fm.match; fieldsGot = fm.got;
      }
    } else if (xi.kind === 'state-machine') {
      // control: the transition from an ALLOWED from-state must work
      const cSetup = await runSteps(xi.controlSetup);
      const cReq = cSetup.ok ? await fire({ ...(xi.control.path ? { method: xi.control.method || xi.method, path: xi.control.path } : { method: xi.method, path: xi.path }), body: xi.control.body || {} }) : null;
      controlOk = !!(cSetup.ok && cReq && cReq.status >= 200 && cReq.status < 300);
      // violation: drive the entity past the allowed from-states, then invoke the transition
      const vSetup = await runSteps(xi.setup);
      if (vSetup.ok) {
        const vr = await fire({ method: xi.violation.method, path: xi.violation.path, body: xi.violation.body });
        violationStatus = vr ? vr.status : null;
        rbBody = await readback(xi.readback);
        const fm = matchFields(xi.readback, rbBody, vars);
        effectMatch = fm.match; fieldsGot = fm.got;
      }
    } else if (xi.kind === 'actor-separation') {
      // resolve the caller's OWN operand at runtime
      const selfR = await fire({ method: xi.selfFrom.method || 'GET', path: xi.selfFrom.path });
      const selfVal = selfR ? grab(selfR.body, xi.selfFrom.field) : null;
      if (selfVal == null) return { verdict: 'inconclusive', kind: xi.kind, operation: xi.id, detail: 'could not resolve own operand via selfFrom', naiveWouldFlag: false, requests };
      vars.self = selfVal;
      const cr = await fire({ method: xi.method, path: xi.path, body: xi.control.body });
      controlOk = !!cr && cr.status >= 200 && cr.status < 300;
      const cb = await readback(xi.readback);
      baseVal = cb != null && xi.readback.effect ? grab(cb, xi.readback.effect) : null;
      const vr = await fire({ method: xi.method, path: xi.path, body: { ...renderDeep(xi.control.body || {}, vars), [xi.param]: selfVal } });
      violationStatus = vr ? vr.status : null;
      rbBody = await readback(xi.readback);
      afterVal = rbBody != null && xi.readback.effect ? grab(rbBody, xi.readback.effect) : null;
      effectMatch = matchNumeric('count-exceeds', baseVal, afterVal, null, xi.readback.limit);
    } else {
      // bounds-min / bounds-max / server-authoritative / usage-limit
      const s = await runSteps(xi.setup);
      const cr = s.ok ? await fire({ method: xi.method, path: xi.path, body: xi.control.body }) : null;
      controlOk = !!(s.ok && cr && cr.status >= 200 && cr.status < 300);
      if (xi.readback && xi.readback.effect) {
        const cb = await readback(xi.readback);
        baseVal = cb != null ? grab(cb, xi.readback.effect) : null;
      }
      const vr = controlOk ? await fire({ method: xi.method, path: xi.path, body: xi.violation.body }) : null;
      violationStatus = vr ? vr.status : null;
      if (vr && xi.readback && xi.readback.saveFromViolation) {
        const sv = grab(vr.body, xi.readback.saveFromViolation.regex);
        if (sv != null) vars[xi.readback.saveFromViolation.var] = sv;
      }
      rbBody = await readback(xi.readback);
      if (xi.readback && xi.readback.fields) {
        const fm = matchFields(xi.readback, rbBody, vars);
        effectMatch = fm.match; fieldsGot = fm.got;
      } else if (xi.readback && xi.readback.effect) {
        afterVal = rbBody != null ? grab(rbBody, xi.readback.effect) : null;
        effectMatch = matchNumeric(xi.readback.model, baseVal, afterVal, v, xi.readback.limit ?? (xi.derived && xi.derived.limit));
      }
    }

    const cls = classifyLogic({ controlOk, violationStatus, effectMatch });
    return {
      verdict: cls.verdict, detail: cls.detail + ' | ' + (xi.derived ? xi.derived.basis : ''),
      kind: xi.kind, operation: xi.id,
      controlOk, violationStatus, effectMatch,
      base: baseVal, after: afterVal, fields: fieldsGot,
      naiveWouldFlag: naiveLogicFlag({ violationStatus }),
      readbackBody: rbBody ? String(rbBody).slice(0, 400) : null,
      requests,
    };
  } catch (e) {
    return { verdict: 'inconclusive', detail: 'probe error: ' + String((e && e.message) || e), naiveWouldFlag: false, requests: 0 };
  }
}
