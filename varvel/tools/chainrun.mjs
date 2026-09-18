// VARVEL — governed exploit-chain executor (shelf→native port #2).
//
// Origin: the k2.7 breach run's run_exploit.py — an ad-hoc script that replayed the
// Axiom chain. This is the reviewed native version: a DECLARATIVE chain runner. A chain
// is a JSON document of steps; the executor walks them in order, threads extracted
// values forward, checks each expectation, and captures EVIDENCE at every step — so an
// exploit chain becomes a repeatable, auditable fixture instead of a throwaway script.
//
// Chain shape:
//   { name, base,
//     steps: [
//       { id, method?, path, headers?, body?, form?,                     // request
//         extract?: { varName: { json?: 'a.b[0]', regex?: 're(group)' } }, // capture forward
//         expect?: { status?: [200] | 200, contains?: 'str', notContains?: 'str' },   // assertions
//         note?: 'what this step proves' }
//       { id, jwt: { claims, key, var? } }                                // compute: mint HS256, no request
//       { id, race: { method, path, headers?, body?, times, attempts, intended,     // TOCTOU probe:
//                     resetPath?, readback: { path, effect } },            //   burst vs sequential
//         expect?: { contains } }                                          //   control + state readback
//       { id, invariant: { kind, path, method?, specPath?, headers?, resetPath? }, // logic probe:
//         expect?: { contains } }                                          //   spec-extracted invariant
//                                                                          //   + control + readback
//     ] }
//   impact?: { step?, contains?, notContains?, control?: {stripHeaders, refuseStatus, mustDiffer} }
//     — chain-level impact assertion (v2). Steps passing proves requests, not impact;
//     a chain that passes all steps but fails impact is FAILED with hollowSuccess: true.
// Templates: '{{var}}' in path/headers/body/form values resolve from extracted vars
// (plus {{base}}). Every step records { id, status, ok, evidence, ms } and the run
// returns { ok, steps, vars (redacted-see-below), evidenceHonest } — a step that fails
// its expectation is marked and the run STOPS (honest: a chain that didn't complete
// never claims completion).
//
// Governance: same-origin enforced against the declared `base` (a template can never
// exfiltrate extracted values elsewhere — extraction output goes ONLY to later steps
// on the same origin), request budget capped, stealth-pacer honored, secrets in vars
// are redacted from the RETURNED run object (they exist for threading, not for display).

import http from 'node:http';
import https from 'node:https';
import { makePacer, asPacer } from '../engine/stealth.mjs';
import { pathPrefixAllowed, sanitizePathPrefixes } from '../engine/scopepath.mjs';
import { signHs256 } from './jwtforge.mjs';
import { raceProbe } from './race.mjs';
import { extractInvariants, findCandidate } from '../engine/logicinvariants.mjs';
import { runLogicProbe } from './logicprobe.mjs';

const BODY_CAP = 192 * 1024;
const DEFAULT_MAX_STEPS = 24;
const REDACT = (v) => (typeof v === 'string' && v.length > 24 ? v.slice(0, 6) + '…[' + v.length + ' chars]' : v);

function raw(u, { method = 'GET', headers = {}, body = null, timeout = 1500 } = {}) {
  return new Promise((resolve) => {
    const lib = u.protocol === 'https:' ? https : http;
    let text = '', settled = false;
    const done = (v) => { if (settled) return; settled = true; clearTimeout(deadline); resolve(v); };
    const req = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method, timeout, rejectUnauthorized: false, headers,
    }, (r) => {
      r.on('data', (d) => {
        if (settled) return;
        if (text.length < BODY_CAP) text += d.toString('utf8', 0, Math.max(0, BODY_CAP - text.length));
        if (text.length >= BODY_CAP) { done({ status: r.statusCode, headers: r.headers, body: text }); try { req.destroy(); } catch {} }
      });
      r.on('end', () => done({ status: r.statusCode, headers: r.headers, body: text }));
    });
    const deadline = setTimeout(() => { try { req.destroy(); } catch {} done(null); }, Math.max(timeout * 3, 3000));
    req.on('timeout', () => { try { req.destroy(); } catch {} done(null); });
    req.on('error', () => done(null));
    if (body != null) req.write(body);
    req.end();
  });
}

const render = (s, vars) => String(s ?? '').replace(/\{\{(\w+)\}\}/g, (m, k) => (k === 'base' ? vars.__base : (vars[k] ?? m)));

// json: 'a.b[0].c' dotted path; regex: 're' (first capture group or whole match);
// header: response header name (+ regex) for cookie-style captures.
function extractValue(body, headers, spec) {
  if (spec.header != null) {
    const raw = ([]).concat((headers || {})[String(spec.header).toLowerCase()] || []).join('; ');
    if (!raw) return null;
    if (spec.regex == null) return raw;
    try { const m = new RegExp(spec.regex).exec(raw); return m ? (m[1] ?? m[0]) : null; } catch { return null; }
  }
  if (spec.json != null) {
    try {
      let v = JSON.parse(body);
      for (const part of String(spec.json).split('.')) {
        const m = /^(\w+)(?:\[(\d+)\])?$/.exec(part);
        if (!m) return null;
        v = v[m[1]];
        if (m[2] != null) v = Array.isArray(v) ? v[Number(m[2])] : undefined;
        if (v == null) return null;
      }
      return typeof v === 'object' ? JSON.stringify(v) : String(v);
    } catch { return null; }
  }
  if (spec.regex != null) {
    try {
      const m = new RegExp(spec.regex).exec(body);
      return m ? (m[1] ?? m[0]) : null;
    } catch { return null; }
  }
  return null;
}

export async function runChain(chain, { timeout = 2000, maxSteps = DEFAULT_MAX_STEPS, stealth, pacer, pathPrefixes = null } = {}) {
  if (!chain || typeof chain !== 'object') throw new TypeError('runChain: a chain object is required');
  let origin;
  try { const u = new URL(chain.base); if (!/^https?:$/.test(u.protocol)) throw new Error('proto'); origin = u.origin; }
  catch { throw new TypeError('runChain: chain.base must be an http(s) URL, got ' + JSON.stringify(chain.base)); }

  pacer = asPacer(pacer) || (stealth ? makePacer(stealth) : null);
  // Path-prefix scope (fail-closed, 2026-08-31): when the signed scope carries
  // pathPrefixes, every step URL must match a prefix — same layer as the
  // off-origin governance check below. Refusal stops the chain honestly.
  const px = sanitizePathPrefixes(pathPrefixes);
  const pathGate = (u, id) => {
    if (!px) return null;
    if (px.includes('/')) return null;
    if (pathPrefixAllowed(u.pathname, px)) return null;
    return { id, ok: false, error: `out-of-prefix path blocked (scope.path): ${u.pathname} not under ${px.join(', ')}` };
  };
  const budget = Math.max(1, Math.floor(maxSteps) || DEFAULT_MAX_STEPS);
  const vars = { __base: origin };
  const steps = [];
  const stepBodies = new Map(); // id -> capped body (for the impact assertion)
  const stepRequests = new Map(); // id -> rendered request (for the impact control re-fire)
  let used = 0;

  for (const step of (chain.steps || []).slice(0, budget)) {
    const t0 = Date.now();
    // Compute step: mint an HS256 JWT from a previously-extracted key (the Axiom chain's
    // forge). No request is made; claims render from vars.
    if (step.jwt) {
      const claims = {};
      for (const [k, v] of Object.entries(step.jwt.claims || {})) claims[k] = typeof v === 'string' ? render(v, vars) : v;
      try {
        vars[step.jwt.var || 'jwt'] = signHs256(claims, render(step.jwt.key || '', vars));
        steps.push({ id: step.id || 'jwt', ok: true, compute: 'signHs256', evidence: 'HS256 JWT minted from recovered key (value redacted)', ms: Date.now() - t0 });
      } catch (e) {
        steps.push({ id: step.id || 'jwt', ok: false, error: 'jwt mint failed: ' + ((e && e.message) || e), ms: Date.now() - t0 });
        break;
      }
      continue;
    }
    // Race step: fire a governed TOCTOU probe (tools/race.mjs) — last-byte-sync burst
    // vs sequential-replay control, verdict from STATE READBACK. The step's "body" is
    // the probe summary JSON, so expect/extract/impact assertions work unchanged.
    // A race step has no single HTTP status (status:null); assert on the verdict.
    // WRITE-PRONE by nature — composed race chains belong to the HITL-gated exploit
    // phase only, and runComposedChain's scope gate applies before this ever fires.
    if (step.race) {
      const spec = step.race;
      const rPath = render(spec.path || '/', vars);
      let ru;
      try { ru = new URL(rPath, origin); } catch { ru = null; }
      if (!ru || ru.origin !== origin) {
        steps.push({ id: step.id || 'race', ok: false, error: 'off-origin race template blocked (governance)', ms: Date.now() - t0 });
        break;
      }
      const rpg = pathGate(ru, step.id || 'race');
      if (rpg) { rpg.ms = Date.now() - t0; steps.push(rpg); break; }
      const rr = await raceProbe(origin, {
        request: {
          method: spec.method || 'POST',
          path: ru.pathname + ru.search,
          headers: Object.fromEntries(Object.entries(spec.headers || {}).map(([k, v]) => [String(k).toLowerCase(), render(v, vars)])),
          body: spec.body != null ? render(spec.body, vars) : null,
        },
        concurrency: spec.times, attempts: spec.attempts, intended: spec.intended,
        resetPath: spec.resetPath, resetBody: spec.resetBody,
        readback: spec.readback ? { path: render(spec.readback.path, vars), effect: spec.readback.effect } : null,
        pacer, timeout,
      });
      used += rr.requests || 0;
      const body = JSON.stringify({
        verdict: rr.verdict, rate: rr.rate,
        readback: rr.readbackBody ? String(rr.readbackBody).slice(0, 240) : null, // state proof rides up front (evidence-capped)
        sequential: rr.sequential, concurrent: rr.concurrent,
        naiveWouldFlag: rr.naiveWouldFlag, flaky: rr.flaky === true, attempts: rr.attempts, concurrency: rr.concurrency,
        detail: rr.detail,
      });
      const rec = { id: step.id || 'race', method: spec.method || 'POST', path: ru.pathname + ru.search, status: null, ok: true, ms: Date.now() - t0,
        race: { verdict: rr.verdict, rate: rr.rate, seqEffect: rr.sequential && rr.sequential.effect, parEffect: rr.concurrent && rr.concurrent.effect } };
      const exp = step.expect || {};
      if (exp.status != null) { rec.ok = false; rec.error = 'race steps carry no single HTTP status — assert on the verdict body (contains)'; }
      if (rec.ok && exp.contains != null && !body.includes(render(exp.contains, vars))) { rec.ok = false; rec.error = 'race verdict body missing ' + JSON.stringify(String(render(exp.contains, vars)).slice(0, 40)); }
      if (rec.ok && exp.notContains != null && body.includes(render(exp.notContains, vars))) { rec.ok = false; rec.error = 'race verdict body must NOT contain ' + JSON.stringify(String(render(exp.notContains, vars)).slice(0, 40)); }
      rec.evidence = body.replace(/\s+/g, ' ').slice(0, 140);
      steps.push(rec);
      stepBodies.set(rec.id, body);
      if (!rec.ok) break;
      for (const [name, espec] of Object.entries(step.extract || {})) {
        const v = extractValue(body, {}, espec || {});
        if (v != null) vars[name] = v;
        else { rec.ok = false; rec.error = 'extract failed for var ' + name; steps[steps.length - 1] = rec; }
      }
      if (!rec.ok) break;
      continue;
    }
    // Invariant step: fetch the API spec, extract the candidate invariant for the
    // observed route, and PROVE it (tools/logicprobe.mjs — control request, violation
    // request, state readback). The step "body" is the probe summary JSON, so
    // expect/extract/impact work unchanged. No single HTTP status (status:null).
    // WRITE-PRONE (creates orders, moves balances) — HITL-gated exploit phase only.
    if (step.invariant) {
      const ispec = step.invariant;
      const iHeaders = Object.fromEntries(Object.entries(ispec.headers || {}).map(([k, v]) => [String(k).toLowerCase(), render(v, vars)]));
      let candidate = null, extractNote = '';
      if (ispec.candidate && ispec.candidate.kind) {
        // Inline candidate (e.g. traffic-discovered via engine/logicdiscover.mjs):
        // no spec fetch at all — probe paths stay same-origin inside logicprobe.
        candidate = ispec.candidate;
        extractNote = 'inline candidate (' + (candidate.source || 'provided') + ')';
      } else {
      const sp = render(ispec.specPath || '/openapi.json', vars);
      let su;
      try { su = new URL(sp, origin); } catch { su = null; }
      if (!su || su.origin !== origin) {
        steps.push({ id: step.id || 'invariant', ok: false, error: 'off-origin spec template blocked (governance)', ms: Date.now() - t0 });
        break;
      }
      const spg = su ? pathGate(su, step.id || 'invariant') : null;
      if (spg) { spg.ms = Date.now() - t0; steps.push(spg); break; }
      used++;
      if (pacer) await pacer.pace();
      const specRes = await raw(su, { headers: iHeaders, timeout });
      if (!specRes || specRes.status !== 200) {
        extractNote = 'spec fetch failed (' + (specRes ? specRes.status : 'no response') + ')';
      } else {
        try {
          const ex = extractInvariants(JSON.parse(specRes.body));
          candidate = findCandidate(ex.candidates, { kind: ispec.kind, path: render(ispec.path || '/', vars) });
          if (!candidate) extractNote = `no candidate invariant extracted for kind=${ispec.kind} path=${ispec.path} (${ex.candidates.length} candidates, ${ex.dropped.length} dropped)`;
        } catch (e) { extractNote = 'spec parse failed: ' + ((e && e.message) || e); }
      }
      }
      let body, rec;
      if (!candidate) {
        rec = { id: step.id || 'invariant', method: ispec.method || 'POST', path: render(ispec.path || '/', vars), status: null, ok: false, error: extractNote, ms: Date.now() - t0 };
        rec.evidence = extractNote.slice(0, 140);
        steps.push(rec);
        stepBodies.set(rec.id, JSON.stringify({ verdict: 'inconclusive', detail: extractNote }));
        break; // honest stop: no extracted invariant, no probe
      }
      // Path-prefix scope: every path the prover would fire (setup/control/violation/
      // readback/selfFrom) must sit under the prefix — checked BEFORE any probe request.
      if (px && !px.includes('/')) {
        const probePaths = [
          ...(candidate.setup || []), ...(candidate.controlSteps || []), ...(candidate.controlSetup || []),
          candidate.violation, candidate.readback, candidate.selfFrom,
        ].filter(Boolean).map((s) => String(s.path || '').replace(/\{\{[^}]+\}\}/g, 'x'));
        const badPath = probePaths.find((p) => !pathPrefixAllowed(p.split('?')[0], px));
        if (badPath) {
          rec = { id: step.id || 'invariant', method: ispec.method || 'POST', path: render(ispec.path || '/', vars), status: null, ok: false, error: `out-of-prefix path blocked (scope.path): ${badPath} not under ${px.join(', ')}`, ms: Date.now() - t0 };
          rec.evidence = rec.error.slice(0, 140);
          steps.push(rec);
          stepBodies.set(rec.id, JSON.stringify({ verdict: 'inconclusive', detail: rec.error }));
          break;
        }
      }
      const pr = await runLogicProbe(origin, candidate, { headers: iHeaders, resetPath: ispec.resetPath, timeout });
      used += pr.requests || 0;
      body = JSON.stringify({
        verdict: pr.verdict, kind: pr.kind, operation: pr.operation,
        controlOk: pr.controlOk, violationStatus: pr.violationStatus, effectMatch: pr.effectMatch,
        base: pr.base ?? null, after: pr.after ?? null, fields: pr.fields || null,
        naiveWouldFlag: pr.naiveWouldFlag,
        readback: pr.readbackBody || null, detail: pr.detail,
      });
      rec = { id: step.id || 'invariant', method: ispec.method || 'POST', path: render(ispec.path || '/', vars), status: null, ok: true, ms: Date.now() - t0,
        invariant: { verdict: pr.verdict, kind: pr.kind, operation: pr.operation } };
      const iexp = step.expect || {};
      if (iexp.status != null) { rec.ok = false; rec.error = 'invariant steps carry no single HTTP status — assert on the verdict body (contains)'; }
      if (rec.ok && iexp.contains != null && !body.includes(render(iexp.contains, vars))) { rec.ok = false; rec.error = 'invariant verdict body missing ' + JSON.stringify(String(render(iexp.contains, vars)).slice(0, 40)); }
      if (rec.ok && iexp.notContains != null && body.includes(render(iexp.notContains, vars))) { rec.ok = false; rec.error = 'invariant verdict body must NOT contain ' + JSON.stringify(String(render(iexp.notContains, vars)).slice(0, 40)); }
      rec.evidence = body.replace(/\s+/g, ' ').slice(0, 140);
      steps.push(rec);
      stepBodies.set(rec.id, body);
      if (!rec.ok) break;
      for (const [name, espec] of Object.entries(step.extract || {})) {
        const v2 = extractValue(body, {}, espec || {});
        if (v2 != null) vars[name] = v2;
        else { rec.ok = false; rec.error = 'extract failed for var ' + name; steps[steps.length - 1] = rec; }
      }
      if (!rec.ok) break;
      continue;
    }
    const method = (step.method || (step.body != null || step.form != null ? 'POST' : 'GET')).toUpperCase();
    const path = render(step.path || '/', vars);
    let u;
    try { u = new URL(path, origin); } catch { u = null; }
    if (!u || u.origin !== origin) {
      steps.push({ id: step.id || '?', ok: false, error: 'off-origin template blocked (governance)', ms: Date.now() - t0 });
      break; // governance: extraction can never be sent off-origin
    }
    const pg = pathGate(u, step.id || '?');
    if (pg) { pg.ms = Date.now() - t0; steps.push(pg); break; } // path-scope: refused before the wire

    const headers = { 'user-agent': 'VARVEL-chainrun' };
    for (const [k, v] of Object.entries(step.headers || {})) headers[k.toLowerCase()] = render(v, vars);
    let body = null;
    if (step.form) { body = new URLSearchParams(Object.entries(step.form).map(([k, v]) => [k, render(v, vars)])).toString(); headers['content-type'] = 'application/x-www-form-urlencoded'; }
    else if (step.body != null) { body = typeof step.body === 'string' ? render(step.body, vars) : JSON.stringify(step.body); if (!headers['content-type']) headers['content-type'] = 'application/json'; }

    used++;
    if (pacer) await pacer.pace();
    const r = await raw(u, { method, headers, body, timeout });
    if (pacer && r && (r.status === 429 || r.status === 503)) pacer.penalize(2, 0);

    const rec = { id: step.id || '?', method, path: u.pathname + u.search, status: r ? r.status : null, ok: true, ms: Date.now() - t0 };
    if (!r) { rec.ok = false; rec.error = 'no response'; steps.push(rec); break; }

    // Expectations (honest assertions)
    const exp = step.expect || {};
    const statuses = exp.status == null ? null : [].concat(exp.status);
    if (statuses && !statuses.includes(r.status)) { rec.ok = false; rec.error = `expected status ${statuses.join('/')}, got ${r.status}`; }
    if (rec.ok && exp.contains != null && !r.body.includes(render(exp.contains, vars))) { rec.ok = false; rec.error = 'expected body to contain ' + JSON.stringify(String(exp.contains).slice(0, 40)); }
    if (rec.ok && exp.notContains != null && r.body.includes(render(exp.notContains, vars))) { rec.ok = false; rec.error = 'body must NOT contain ' + JSON.stringify(String(exp.notContains).slice(0, 40)); }

    // Evidence: the matched proof, capped — never the whole page
    rec.evidence = (r.body || '').replace(/\s+/g, ' ').slice(0, 140);
    steps.push(rec);
    stepBodies.set(rec.id, (r.body || '').slice(0, 8192));
    stepRequests.set(rec.id, { method, path: u.pathname + u.search, headers: { ...headers }, body });
    if (!rec.ok) break; // honest stop: a failed link breaks the chain

    // Extraction feeds later steps (same-origin only, enforced above)
    for (const [name, spec] of Object.entries(step.extract || {})) {
      const v = extractValue(r.body, r.headers, spec || {});
      if (v != null) vars[name] = v;
      else { rec.ok = false; rec.error = 'extract failed for var ' + name; steps[steps.length - 1] = rec; }
    }
    if (!rec.ok) break;
  }

  const stepsOk = steps.length > 0 && steps.every((s) => s.ok);

  // ——— chain-level IMPACT assertion (v2: the hollow-success killer) ———
  // Passing every step proves the requests succeeded; it does NOT prove impact.
  // chain.impact asserts something about a terminal step's RESPONSE — optionally
  // against a paired CONTROL (the same request re-fired with auth headers stripped,
  // the manhuaus garbage-control doctrine lifted from findings to chains):
  //   impact: { step?: <id>          // default: last executed step
  //             contains?: str|str[], notContains?: str|str[],   // {{var}} rendered
  //             control?: { stripHeaders: ['cookie'], refuseStatus: [401,403], mustDiffer: true } }
  // A chain whose steps all pass but whose impact assertion fails is FAILED, with
  // hollowSuccess: true — reported, never silently green.
  let impact = null;
  if (chain.impact && stepsOk) {
    const imp = chain.impact;
    const targetId = imp.step || steps[steps.length - 1].id;
    const body = stepBodies.get(targetId);
    const failures = [];
    if (body == null) failures.push(`impact step '${targetId}' was never executed`);
    else {
      for (const c of [].concat(imp.contains || [])) if (!body.includes(render(c, vars))) failures.push('impact body missing ' + JSON.stringify(String(render(c, vars)).slice(0, 40)));
      for (const c of [].concat(imp.notContains || [])) if (body.includes(render(c, vars))) failures.push('impact body must NOT contain ' + JSON.stringify(String(render(c, vars)).slice(0, 40)));
    }
    if (imp.control && stepRequests.has(targetId)) {
      const spec = stepRequests.get(targetId);
      const strip = new Set([].concat(imp.control.stripHeaders || []).map((h) => String(h).toLowerCase()));
      const cHeaders = Object.fromEntries(Object.entries(spec.headers).filter(([k]) => !strip.has(k)));
      used++;
      if (pacer) await pacer.pace();
      const cr = await raw(new URL(spec.path, origin), { method: spec.method, headers: cHeaders, body: spec.body, timeout });
      if (!cr) failures.push('impact control request got no response — control unreadable, impact unproven');
      else {
        if (imp.control.refuseStatus && !imp.control.refuseStatus.includes(cr.status)) {
          failures.push(`control (without ${[...strip].join('/')}) was not refused: got ${cr.status}, expected ${imp.control.refuseStatus.join('/')}`);
        }
        if (imp.control.mustDiffer && body != null && cr.body === body) {
          failures.push('control response is IDENTICAL to the authed response — the chain proves nothing (hollow success)');
        }
      }
    }
    impact = { asserted: true, step: targetId, ok: failures.length === 0, detail: failures.length ? failures.join('; ') : 'impact proven (assertions held' + (imp.control ? ', control behaved' : '') + ')' };
  } else if (chain.impact) {
    impact = { asserted: true, ok: false, detail: 'chain steps did not complete — impact assertion not reached' };
  }

  const ok = stepsOk && (!impact || impact.ok);
  const hollowSuccess = stepsOk && impact && !impact.ok;
  // Vars thread forward but don't leak in full into the returned object (a forged token
  // is redacted in the run record; the evidence strings carry the proof instead).
  const redactedVars = Object.fromEntries(Object.entries(vars).filter(([k]) => k !== '__base').map(([k, v]) => [k, REDACT(v)]));
  return {
    chain: chain.name || 'chain', base: origin, ok,
    stepsCompleted: steps.filter((s) => s.ok).length, stepsTotal: (chain.steps || []).length,
    steps, vars: redactedVars, requests: used, stealth: pacer ? pacer.profile.label : null,
    ...(impact ? { impact } : {}),
    ...(hollowSuccess ? { hollowSuccess: true } : {}),
  };
}
