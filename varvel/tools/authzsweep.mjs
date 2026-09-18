// VARVEL — authzsweep: the TWO-ACCOUNT AUTHORIZATION oracle, productized (Build 1).
//
// The lab differential (tools/idorprobe.mjs) grown into the pipeline primitive the
// crit-class analysis (docs/research/crit-class-analysis-2026-08-30.md §5 Build 1)
// specifies. Given a target with TWO provisioned accounts on distinct tenants:
//
//   (a) HARVEST  — extractRefs/templatizePath/harvestExchanges pull every object
//       reference (id, uuid, *_id, tenant, document…) out of both sessions' traffic
//       and fold concrete observed paths into {id} templates;
//   (b) CROSS-REPLAY — every harvested reference is replayed as the OTHER session
//       AND unauthenticated (the control that earns the claim);
//   (c) CLASSIFY — read (classifyIdor, reused), write (classifyWrite: cross write
//       + VICTIM-SIDE readback + unauth control), delete (classifyDelete: cross
//       delete + readback-404), each direction labeled cross-tenant;
//   (d) ESCALATION LADDER — write-capable candidates get the mass-assignment ladder
//       (role/email/isAdmin/password) fired at the caller's OWN object, proven only
//       by a before/control/after READBACK triple (a 200 that ignores the field is
//       the decoy — status cannot see enforcement);
//   (e) EVIDENCE — every result carries a report-ready bundle: raw HTTP request/
//       response pairs (cookies redacted) + claims labeled observation vs inference
//       vs impact, per the winning-report shape (§4 of the analysis).
//
// ⚠ SAFETY: reads run anywhere; writes/deletes/ladder are WRITE-PRONE and gated
// behind explicit opts (writes/deletes) — the campaign wires them to the
// HITL-countersigned exploit window only. Every state-changing success is followed
// by a best-effort REVERT, and the revert is recorded on the pair list.
//
// House contract: extractRefs/templatizePath/harvestExchanges/classify* are PURE;
// authzSweep touches the network but NEVER throws. No dependencies beyond stdlib.

import http from 'node:http';
import https from 'node:https';
import { randomBytes } from 'node:crypto';
import { classifyIdor } from './idorprobe.mjs';
import { pathPrefixAllowed } from '../engine/scopepath.mjs';

export const AUTHZ_CAPS = { maxRefs: 40, maxCandidates: 12, maxEndpoints: 24, maxLadder: 4, bodySnippet: 600 };

// Object-reference keys the harvester recognizes (id, uuid, tenant_id, document_id,
// profileId, owner_id…). Values must be short scalars — long blobs are not references.
export const REF_KEY_RE = /^(id|uuid|guid|tenant|tenant_?id|doc(ument)?_?id|owner_?id|user_?id|profile_?id|account_?id|order_?id|booking_?id|invoice_?id|.*_id|.*Id|.*Uuid)$/i;

// The mass-assignment escalation ladder (spec §2.1: add password/role/email params).
// revert: false marks params whose original value is unknowable from a readback
// (password) — the sweep says so honestly instead of pretending a restore happened.
export const ESCALATION_PARAMS = [
  { key: 'role', value: 'admin', revert: true },
  { key: 'email', value: 'varvel-authz-probe@example.invalid', revert: true },
  { key: 'isAdmin', value: true, revert: true },
  { key: 'password', value: 'Varvel-authz-probe-1!', revert: false },
];

const clamp = (n, lo, hi) => Math.max(lo, Math.min(hi, n));
const isRefValue = (v) => (typeof v === 'string' && v.length > 0 && v.length <= 128) || (typeof v === 'number' && Number.isFinite(v));

// ——— (a) HARVEST — pure ———

// extractRefs(text) → [{ key, value }] — id-ish scalar fields from a JSON (or
// JSON-ish) body. Deduped, capped. Never throws.
export function extractRefs(text) {
  const out = [];
  const seen = new Set();
  const push = (key, value) => {
    if (out.length >= AUTHZ_CAPS.maxRefs) return;
    if (!REF_KEY_RE.test(String(key)) || !isRefValue(value)) return;
    const k = String(key) + '=' + String(value);
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ key: String(key), value: String(value) });
  };
  const s = String(text || '');
  try {
    const walk = (node, depth) => {
      if (depth > 6 || node == null) return;
      if (Array.isArray(node)) { for (const v of node.slice(0, 50)) walk(v, depth + 1); return; }
      if (typeof node === 'object') { for (const [k, v] of Object.entries(node)) { if (isRefValue(v)) push(k, v); else walk(v, depth + 1); } }
    };
    walk(JSON.parse(s), 0);
  } catch {
    // Regex fallback for non-JSON bodies: "key": "value" / "key": 123 pairs.
    const re = /"([A-Za-z_][\w-]*)"\s*:\s*"?([A-Za-z0-9][\w.@-]{0,127})"?\s*[,}]/g;
    let m; while ((m = re.exec(s)) && out.length < AUTHZ_CAPS.maxRefs) push(m[1], m[2]);
  }
  return out;
}

// templatizePath('/api/orders/ORD-1042') → { template: '/api/orders/{id}', value: 'ORD-1042' }.
// Numeric (≥2 digits), UUID, and PREFIX-1234-style segments count as object ids.
// Returns null when no segment looks like a reference.
export function templatizePath(pathname) {
  const segs = String(pathname || '').split('/');
  let value = null;
  const out = segs.map((seg) => {
    if (value !== null || !seg) return seg;
    if (/^\d{2,}$/.test(seg) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg) || /^[A-Za-z]{2,6}-\d[\w-]*$/.test(seg) || /^[A-Z]{2,8}-[A-Z0-9][\w-]{2,}$/.test(seg)) {
      value = seg; return '{id}';
    }
    return seg;
  });
  return value === null ? null : { template: out.join('/'), value };
}

// harvestExchanges(exchanges) — exchanges are observed traffic records:
//   { session: 'a'|'b', method, path, status, reqBody, resBody }
// → { candidates: [{ path, methods, refs: { a: [], b: [] }, body, observed }],
//     endpointRefs: { '/api/x': { a: [...], b: [...] } } }
// Concrete id-bearing paths fold into {id} templates; every body ref is attributed
// to its source endpoint so synthesizeCandidates can pair refs with path shapes.
export function harvestExchanges(exchanges) {
  const candMap = new Map();   // template -> candidate
  const endpointRefs = {};     // source endpoint path -> refs per session
  for (const ex of exchanges || []) {
    if (!ex || typeof ex.path !== 'string') continue;
    // Session letters a..d (4-role generalization 2026-08-30); unknown sessions fold to 'a'.
    const side = /^[a-d]$/.test(String(ex.session)) ? String(ex.session) : 'a';
    const method = String(ex.method || 'GET').toUpperCase();
    const ep = ex.path.split('?')[0];
    const refs = [...extractRefs(ex.resBody), ...extractRefs(ex.reqBody)];
    if (refs.length) {
      const er = (endpointRefs[ep] = endpointRefs[ep] || { a: [], b: [] });
      const erSide = (er[side] = er[side] || []);
      for (const r of refs) if (!erSide.some((x) => x.value === r.value)) erSide.push(r);
    }
    const t = templatizePath(ep);
    if (!t) continue;
    const key = t.template;
    const c = candMap.get(key) || { path: key, methods: [], refs: { a: [], b: [] }, body: null, observed: true };
    if (!c.methods.includes(method)) c.methods.push(method);
    const cSide = (c.refs[side] = c.refs[side] || []);
    if (!cSide.includes(t.value)) cSide.push(t.value);
    if (method !== 'GET' && ex.reqBody && !c.body) c.body = String(ex.reqBody).slice(0, 2048);
    candMap.set(key, c);
  }
  return { candidates: [...candMap.values()].slice(0, AUTHZ_CAPS.maxCandidates), endpointRefs };
}

// synthesizeCandidates(harvested, templates) — merge observed candidates with
// (i) SYNTHESIZED templates: a list endpoint whose traffic carried refs gets the
// classic REST item shape `<endpoint>/{id}` (marked synthesized — an inference, and
// labeled as such in the evidence), and (ii) operator/api-surface TEMPLATES
// ([{ path: '/api/users/{id}', methods: ['GET','PATCH'], body? }]) which receive the
// union of all harvested refs per session. Capped; deduped by path.
export function synthesizeCandidates(harvested, templates) {
  const map = new Map();
  const cloneRefs = (r) => { const out = {}; for (const [k, v] of Object.entries(r || {})) out[k] = [...v]; return out; };
  for (const c of (harvested && harvested.candidates) || []) map.set(c.path, { ...c, refs: cloneRefs(c.refs) });
  const erValues = Object.values((harvested && harvested.endpointRefs) || {});
  // the union of session letters actually observed (a/b always; c/d when a 4-role
  // matrix rides) — 2-account inputs produce the bit-identical a/b shape
  const sides = [...new Set(['a', 'b', ...erValues.flatMap((r) => Object.keys(r || {}))])];
  const allRefs = {};
  for (const refs of erValues) {
    for (const side of sides) for (const r of (refs && refs[side]) || []) {
      const ar = (allRefs[side] = allRefs[side] || []);
      if (!ar.includes(r.value)) ar.push(r.value);
    }
  }
  for (const [ep, refs] of Object.entries((harvested && harvested.endpointRefs) || {})) {
    if (templatizePath(ep)) continue; // already a concrete candidate
    if (!sides.some((s) => ((refs || {})[s] || []).length)) continue;
    const path = ep.replace(/\/$/, '') + '/{id}';
    if (map.has(path)) continue;
    const srefs = {};
    for (const side of sides) srefs[side] = (((refs || {})[side]) || []).map((r) => r.value);
    map.set(path, { path, methods: ['GET'], refs: srefs, body: null, synthesized: true });
  }
  for (const t of templates || []) {
    if (!t || typeof t.path !== 'string' || !t.path.includes('{id}')) continue;
    const existing = map.get(t.path);
    const tSides = [...new Set([...sides, ...Object.keys(t.refs || {})])];
    const refs = {};
    for (const side of tSides) refs[side] = (t.refs && t.refs[side]) || allRefs[side] || [];
    if (existing) {
      for (const mth of t.methods || []) if (!existing.methods.includes(mth)) existing.methods.push(mth);
      for (const side of Object.keys(refs)) for (const v of refs[side]) {
        const ev = (existing.refs[side] = existing.refs[side] || []);
        if (!ev.includes(v)) ev.push(v);
      }
      if (t.body && !existing.body) existing.body = typeof t.body === 'string' ? t.body : JSON.stringify(t.body);
      existing.configured = true;
    } else {
      map.set(t.path, {
        path: t.path,
        methods: (Array.isArray(t.methods) && t.methods.length ? t.methods : ['GET']).map((m) => String(m).toUpperCase()),
        refs, body: t.body ? (typeof t.body === 'string' ? t.body : JSON.stringify(t.body)) : null,
        writeField: t.writeField, seed: t.seed && typeof t.seed === 'object' ? t.seed : undefined, configured: true,
      });
    }
  }
  return [...map.values()].slice(0, AUTHZ_CAPS.maxCandidates);
}

// ——— (c) CLASSIFY — pure ———

// classifyWrite: a cross-tenant WRITE is proven by its EFFECT, never its status.
//   idor-write   — cross write 2xx AND victim-side readback carries the canary AND
//                  the unauth control write was refused
//   unauth-write — the UNAUTH control also landed the canary (worse: no auth at all —
//                  reported as its own verdict, never silently folded into IDOR)
//   enforced     — cross write refused, OR 2xx but the readback shows NO effect
//                  (accepted-and-ignored: status cannot see enforcement)
//   inconclusive — anything else, said honestly
export function classifyWrite({ cross, unauth, readback, canary } = {}) {
  if (!cross || cross.status == null) return { verdict: 'inconclusive', detail: 'cross-tenant write produced no response — no claim without a response' };
  const wrote = readback && readback.status === 200 && canary && String(readback.body || '').includes(canary);
  const unauthRefused = unauth && [401, 403].includes(unauth.status);
  if ([401, 403, 404].includes(cross.status)) return { verdict: 'enforced', detail: `cross-tenant write refused (${cross.status}) — ownership check holds` };
  if (cross.status >= 200 && cross.status < 300) {
    if (unauth && unauth.status >= 200 && unauth.status < 300 && wrote) {
      return { verdict: 'unauth-write', detail: 'the UNAUTHENTICATED control write also persisted the canary — this is missing authentication, a distinct (worse) verdict' };
    }
    if (wrote && unauthRefused) return { verdict: 'idor-write', detail: 'cross-tenant write persisted (victim-side readback carries the canary) while the unauth control was refused — ownership confusion on WRITE confirmed' };
    if (!wrote) return { verdict: 'enforced', detail: `cross-tenant write returned ${cross.status} but the victim-side readback shows NO effect — accepted-and-ignored; status is not proof` };
    return { verdict: 'inconclusive', detail: 'write effect unproven — unauth control missing or not refused' };
  }
  return { verdict: 'inconclusive', detail: `cross-tenant write returned ${cross.status}` };
}

// classifyDelete: cross-tenant DELETE proven by the object being GONE on the
// victim-side readback, with the unauth control refused.
export function classifyDelete({ cross, unauth, readbackAfter } = {}) {
  if (!cross || cross.status == null) return { verdict: 'inconclusive', detail: 'cross-tenant delete produced no response' };
  const unauthRefused = unauth && [401, 403].includes(unauth.status);
  if ([401, 403, 404].includes(cross.status)) return { verdict: 'enforced', detail: `cross-tenant delete refused (${cross.status}) — ownership check holds` };
  if (cross.status >= 200 && cross.status < 300) {
    if (unauth && unauth.status >= 200 && unauth.status < 300) return { verdict: 'unauth-delete', detail: 'the UNAUTHENTICATED control delete also succeeded — missing authentication, not IDOR' };
    if (!readbackAfter || readbackAfter.status == null) return { verdict: 'inconclusive', detail: 'delete claimed but no victim-side readback — effect unproven' };
    if (readbackAfter.status === 404 && unauthRefused) return { verdict: 'idor-delete', detail: 'cross-tenant delete removed the object (victim-side readback 404) while the unauth control was refused — ownership confusion on DELETE confirmed' };
    if (readbackAfter.status === 200) return { verdict: 'inconclusive', detail: 'delete returned 2xx but the object is still readable — effect not proven' };
    return { verdict: 'inconclusive', detail: `readback after delete returned ${readbackAfter.status}` };
  }
  return { verdict: 'inconclusive', detail: `cross-tenant delete returned ${cross.status}` };
}

const fieldValue = (body, field) => {
  try { const o = JSON.parse(String(body || '')); return o && o[field] !== undefined ? o[field] : undefined; } catch { return undefined; }
};
const looseEq = (a, b) => a !== undefined && String(a) === String(b);

// classifyMassAssign: the escalation-ladder oracle. A privilege field counts as
// assigned ONLY when it persists in the AFTER readback, was NOT set by the CONTROL
// write (same request minus the extra param), and did not already hold the value.
//   mass-assignment — field persisted via the extra param only
//   enforced        — the server ignored the extra field (the /api/safe decoy: 200
//                     either way; only the readback can tell)
//   inconclusive    — control/before ambiguity, no readback
export function classifyMassAssign({ before, controlAfter, after, field, value } = {}) {
  if (after == null) return { verdict: 'inconclusive', detail: 'no readback after the escalation write — no claim without a readback' };
  const vAfter = fieldValue(after, field);
  if (!looseEq(vAfter, value)) return { verdict: 'enforced', detail: `readback shows ${field} unchanged/absent — the server ignored the extra field (200 is not proof)` };
  if (looseEq(fieldValue(controlAfter, field), value)) return { verdict: 'inconclusive', detail: `${field} reached the probe value under the CONTROL write too — cannot attribute it to the extra parameter` };
  if (looseEq(fieldValue(before, field), value)) return { verdict: 'inconclusive', detail: `${field} already held the probe value before the write` };
  return { verdict: 'mass-assignment', detail: `${field}=${JSON.stringify(value)} persisted ONLY via the extra body parameter (before/control readbacks clean) — mass assignment confirmed` };
}

// ——— transport (never throws) ———

function fire(base, { method = 'GET', path, cookie = null, body = null, timeout = 3000, extraHeaders = null, authHeaders = null, agents = null } = {}) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(path, base); } catch { return resolve(null); }
    const lib = u.protocol === 'https:' ? https : http;
    const headers = { 'user-agent': 'VARVEL-authzsweep', ...(extraHeaders || {}), ...(authHeaders || {}) };
    if (cookie) headers.cookie = cookie;
    if (body != null) headers['content-type'] = 'application/json';
    const req = lib.request({ hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search, method, timeout, headers, agent: agents ? agents[u.protocol === 'https:' ? 'https' : 'http'] : undefined }, (res) => {
      let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    req.on('error', () => resolve(null)); req.on('timeout', () => { req.destroy(); resolve(null); });
    if (body != null) req.write(body);
    req.end();
  });
}

// provisionSession(base, account) — resolve an account ({ label, cookie } or
// { label, headers } (bearer/api-key auth) or { label, login: { path, body } }) to
// { label, cookie, headers }. Null on failure (honest).
export async function provisionSession(base, account, { timeout = 3000, extraHeaders = null } = {}) {
  if (!account || typeof account !== 'object') return null;
  if (account.cookie || account.headers) {
    return {
      label: account.label || 'account',
      cookie: account.cookie ? String(account.cookie) : null,
      headers: account.headers && typeof account.headers === 'object' ? { ...account.headers } : null,
    };
  }
  if (!account.login || !account.login.path) return null;
  const r = await fire(base, { method: account.login.method || 'POST', path: account.login.path, body: account.login.body != null ? String(account.login.body) : null, timeout, extraHeaders });
  if (!r || !r.status || r.status >= 400) return null;
  const setCookie = r.headers && r.headers['set-cookie'];
  const cookie = (Array.isArray(setCookie) ? setCookie[0] : setCookie || '').split(';')[0];
  return cookie ? { label: account.label || 'account', cookie, headers: null } : null;
}

// fetchExchange — one governed GET for the harvest pass; returns the exchange
// record harvestExchanges consumes (or null on refusal/failure).
export async function fetchExchange(base, path, { session = 'a', cookie = null, authHeaders = null, timeout = 3000, pacer = null, extraHeaders = null, pathPrefixes = null, agents = null } = {}) {
  const pathname = String(path || '').split('?')[0];
  if (pathPrefixes && !pathPrefixAllowed(pathname, pathPrefixes)) return null;
  if (pacer && typeof pacer.pace === 'function') await pacer.pace();
  const r = await fire(base, { method: 'GET', path, cookie, timeout, extraHeaders, authHeaders, agents });
  if (!r) return null;
  return { session, method: 'GET', path: pathname, status: r.status, resBody: String(r.body || '').slice(0, 8192) };
}

// sanitizeAuthzCfg — the campaign constructor's config seam. Needs ≥2 provisioned
// accounts (cookie, headers (bearer/api-key), or login each); deletes require writes. Never throws.
const sanitizeHeaders = (h) => {
  if (!h || typeof h !== 'object' || Array.isArray(h)) return null;
  const out = {};
  for (const [k, v] of Object.entries(h).slice(0, 6)) {
    if (!/^[a-z0-9-]+$/i.test(k) || typeof v !== 'string' || !v || v.length > 2048) continue;
    out[k.toLowerCase()] = v;
  }
  return Object.keys(out).length ? out : null;
};
export function sanitizeAuthzCfg(x) {
  if (!x || typeof x !== 'object' || !Array.isArray(x.accounts)) return null;
  const accounts = x.accounts
    .map((a) => (a && typeof a === 'object' ? { ...a, headers: sanitizeHeaders(a.headers) } : a))
    .filter((a) => a && typeof a === 'object' && (a.cookie || a.headers || (a.login && a.login.path) || typeof a.sessionRef === 'string'))
    .slice(0, 4)
    .map((a) => ({
      label: String(a.label || 'account'), cookie: a.cookie ? String(a.cookie) : null, headers: a.headers || null,
      login: a.login ? { path: String(a.login.path), body: a.login.body != null ? String(a.login.body) : null, method: a.login.method } : null,
      // 4-role matrix (2026-08-30): an OPTIONAL role label ('owner'|'member'|'lowpriv') —
      // informational for the evidence trail; the differential itself is role-agnostic.
      role: ['owner', 'member', 'lowpriv'].includes(a.role) ? a.role : null,
      // Broker-managed session reference 'program:label' — the campaign resolves a live
      // cookie through the session broker before provisioning (script relogin allowed
      // only when the campaign's broker config enables allowSpawn).
      sessionRef: typeof a.sessionRef === 'string' ? a.sessionRef : null,
    }));
  if (accounts.length < 2) return null;
  const writes = !!x.writes;
  return {
    accounts, writes,
    // base: operator-pinned sweep base (the account-bound host). Survives launches whose
    // reconOpts carry no web ports, where recon-derived _webBases() would be empty.
    base: typeof x.base === 'string' && /^https?:\/\//i.test(x.base) ? x.base : null,
    deletes: writes && !!x.deletes, // deletes are the most destructive rung — they require the write rung too
    escalate: x.escalate !== false,
    ladder: Array.isArray(x.ladder) ? x.ladder.filter((p) => p && typeof p.key === 'string').slice(0, AUTHZ_CAPS.maxLadder) : ESCALATION_PARAMS,
    templates: Array.isArray(x.templates) ? x.templates.filter((t) => t && typeof t.path === 'string' && t.path.includes('{id}')).slice(0, AUTHZ_CAPS.maxCandidates) : [],
    maxEndpoints: clamp(Math.floor(Number(x.maxEndpoints)) || AUTHZ_CAPS.maxEndpoints, 1, 100),
  };
}

// ——— the governed sweep ———
// authzSweep(base, { sessions | sessionA+sessionB, candidates, writes, deletes,
//   escalate, ladder, timeout, pacer, extraHeaders, pathPrefixes, agents, onRequest, onLog })
//
// 4-ROLE GENERALIZATION (2026-08-30): `sessions` takes up to FOUR provisioned
// sessions (owner/member/lowpriv/…). The READ differential runs the FULL CROSS
// PRODUCT — every provisioned session replays every other session's harvested
// reference (A→B, A→C, B→A, B→C, C→A, C→B…) with the unauth control retained per
// direction — and the WORST verdict per template wins (a vuln visible only to the
// lowpriv role can no longer hide behind the owner/member pair). Writes, deletes,
// and the escalation ladder stay EXACTLY as-is on the FIRST pair only (sessions[0]
// vs sessions[1]) — writes stay conservative. Given exactly two sessions the request
// sequence and verdicts are bit-identical to the two-account oracle.
//
// VICTIM-OBJECT SEEDING: a candidate may declare `seed` PER ACCOUNT LABEL
// ({ '<label>': { method, path, body } }). When that account's refs are empty and
// the write rung is enabled, the sweep provisions ONE object through that account
// before replay (honest authz.seed log events via onLog). A failed seed degrades the
// candidate to 'inconclusive' with the reason — refs are NEVER fabricated.
//
// Returns { ok, summary, results, refusals } — NEVER throws. summary.verdicts maps
// template → worst verdict; every result carries its report-ready evidence bundle.
export async function authzSweep(base, { sessions = null, sessionA = null, sessionB = null, candidates = [], writes = false, deletes = false, escalate = true, ladder = ESCALATION_PARAMS, timeout = 3000, pacer = null, extraHeaders = null, pathPrefixes = null, agents = null, onRequest = null, onLog = null } = {}) {
  const refusals = [];
  const results = [];
  let requestCount = 0;
  try {
    new URL(base); // validate
  } catch { return { ok: false, error: 'unparseable base URL', summary: { candidates: 0, violations: 0, requests: 0, verdicts: {} }, results, refusals }; }
  const sessList = (Array.isArray(sessions) && sessions.length ? sessions : [sessionA, sessionB]).filter(Boolean).slice(0, 4);
  if (sessList.length < 2) return { ok: false, error: 'two sessions required', summary: { candidates: 0, violations: 0, requests: 0, verdicts: {} }, results, refusals };
  sessionA = sessList[0]; // the write/delete/ladder differential pair — ALWAYS the first two
  sessionB = sessList[1];
  const letter = (i) => String.fromCharCode(97 + i); // refs key: a, b, c, d
  const LABEL = (i) => String.fromCharCode(65 + i);  // evidence label: A, B, C, D
  const logTo = (obj) => { if (typeof onLog === 'function') { try { onLog(obj); } catch { /* observer never breaks the sweep */ } } };

  const pace = async () => { if (pacer && typeof pacer.pace === 'function') await pacer.pace(); };
  const redact = (cookie) => {
    for (const s of sessList) if (s.cookie && cookie === s.cookie) return `<session:${s.label}>`;
    return cookie ? '<redacted>' : '<none>';
  };
  // auth headers are credentials too — redact them to the owning session's label in evidence
  const redactHdrs = (ah) => {
    if (!ah) return null;
    const out = {};
    for (const [k, v] of Object.entries(ah)) {
      let owner = null;
      for (const s of sessList) if (s.headers && s.headers[k] === v) { owner = s.label; break; }
      out[k] = owner ? `<session:${owner}>` : '<redacted>';
    }
    return out;
  };
  const send = async (label, { method = 'GET', path, cookie = null, authHeaders = null, body = null, write = false, seed = false }) => {
    const pathname = String(path).split('?')[0];
    if (pathPrefixes && !pathPrefixAllowed(pathname, pathPrefixes)) { refusals.push({ path: pathname, reason: 'out-of-scope-path' }); return null; }
    await pace();
    const r = await fire(base, { method, path, cookie, authHeaders, body, timeout, extraHeaders, agents });
    requestCount++;
    if (onRequest) { try { onRequest({ label, method, path: pathname, write, ...(seed ? { seed: true } : {}) }); } catch { /* observer never breaks the sweep */ } }
    // The raw HTTP pair, report-ready (cookie + auth headers redacted, bodies snipped).
    pairBuf.push({
      label,
      request: { method, path: pathname, headers: { cookie: redact(cookie), ...(redactHdrs(authHeaders) || {}), ...(body != null ? { 'content-type': 'application/json' } : {}) }, body: body != null ? String(body).slice(0, AUTHZ_CAPS.bodySnippet) : null },
      response: r ? { status: r.status, body: String(r.body || '').slice(0, AUTHZ_CAPS.bodySnippet) } : null,
    });
    return r;
  };
  let pairBuf = [];

  for (const cand of candidates.slice(0, AUTHZ_CAPS.maxCandidates)) {
    pairBuf = [];
    const observation = [], inference = [], impact = [];
    const out = { template: cand.path, synthesized: !!cand.synthesized, configured: !!cand.configured, read: null, write: null, delete: null, ladder: [], pairs: null, observation, inference, impact };
    const at = (id) => cand.path.replace('{id}', encodeURIComponent(String(id)));
    const refsOf = (i) => (cand.refs && Array.isArray(cand.refs[letter(i)])) ? cand.refs[letter(i)] : [];

    // ——— victim-object SEEDING: empty refs + a declared seed + writes enabled ⇒
    // provision ONE object through that account before replay. Honest either way. ———
    if (cand.seed && typeof cand.seed === 'object' && writes) {
      let seedError = null;
      for (let i = 0; i < sessList.length; i++) {
        if (refsOf(i).length) continue;
        const spec = cand.seed[sessList[i].label];
        if (!spec || typeof spec.path !== 'string') continue;
        const r = await send(`seed:${sessList[i].label}`, { method: spec.method || 'POST', path: spec.path, body: spec.body != null ? String(spec.body) : null, cookie: sessList[i].cookie, authHeaders: sessList[i].headers, write: true, seed: true });
        if (r && r.status >= 200 && r.status < 300) {
          const found = extractRefs(r.body);
          if (found.length) {
            (cand.refs[letter(i)] = cand.refs[letter(i)] || []).push(found[0].value);
            logTo({ type: 'authz.seed', account: sessList[i].label, path: spec.path, ok: true, status: r.status, ref: found[0].value });
            observation.push(`victim-object seeding: provisioned one object as ${sessList[i].label} (${spec.method || 'POST'} ${spec.path} → ${r.status}, ref ${found[0].value})`);
            continue;
          }
          seedError = `${sessList[i].label}: seed returned ${r.status} but no object reference in the response body`;
        } else {
          seedError = `${sessList[i].label}: seed ${spec.method || 'POST'} ${spec.path} ${r ? 'returned ' + r.status : 'produced no response'}`;
        }
        logTo({ type: 'authz.seed', account: sessList[i].label, path: spec.path, ok: false, status: r ? r.status : null, reason: seedError });
      }
      if (seedError) {
        out.read = { verdict: 'inconclusive', detail: `victim-object seeding failed (${seedError}) — degraded honestly; no refs fabricated`, seeded: false };
        out.pairs = pairBuf;
        results.push(out);
        continue;
      }
    }

    const ownId = refsOf(0)[0];   // session A's own object
    const otherId = refsOf(1)[0]; // session B's object — the cross target for A
    if (!sessList.some((_, i) => refsOf(i).length)) { out.read = { verdict: 'inconclusive', detail: 'no object references harvested for this template' }; out.pairs = pairBuf; results.push(out); continue; }

    // ——— (b)+(c) READ differential: the FULL CROSS PRODUCT of provisioned sessions,
    // every direction with its own unauth control. Worst verdict per template wins. ———
    const dirs = [];
    for (let i = 0; i < sessList.length; i++) {
      for (let j = 0; j < sessList.length; j++) {
        if (i === j || !refsOf(j).length) continue;
        const victimId = refsOf(j)[0];
        const caller = sessList[i];
        const own = refsOf(i).length ? await send(`read:own(${LABEL(i)}→${LABEL(i)})`, { path: at(refsOf(i)[0]), cookie: caller.cookie, authHeaders: caller.headers }) : null;
        const cross = await send(`read:cross(${LABEL(i)}→${LABEL(j)})`, { path: at(victimId), cookie: caller.cookie, authHeaders: caller.headers });
        const unauth = await send(`read:unauth-control(${LABEL(j)})`, { path: at(victimId), cookie: null });
        dirs.push({ dir: `${LABEL(i)}→${LABEL(j)}`, callerLabel: caller.label, victimId, result: classifyIdor({ own, other: cross, unauth }) });
      }
    }
    const worst = dirs.find((d) => d.result.verdict === 'idor') || dirs.find((d) => d.result.verdict === 'public') || dirs[0] || { dir: null, callerLabel: sessionA.label, victimId: otherId || ownId, result: { verdict: 'inconclusive', detail: 'no references' } };
    out.read = { verdict: worst.result.verdict, detail: worst.result.detail, direction: worst.dir, directions: dirs.map((d) => ({ direction: d.dir, verdict: d.result.verdict })), crossTenant: true };
    if (out.read.verdict === 'idor') {
      observation.push(`cross-tenant GET ${at(worst.victimId)} as ${worst.callerLabel} returned 200 with content distinct from the caller's own object`);
      observation.push('the unauthenticated control read of the same object was refused (401/403)');
      inference.push('an authentication check exists but the per-object OWNERSHIP check is missing (differential control isolates exactly that)');
      impact.push(`any authenticated user can read every object under ${cand.path} — cross-tenant data exposure (scale: enumerable via the harvested reference space)`);
    } else if (out.read.verdict === 'public') {
      observation.push('the unauth control returned the IDENTICAL body — public object, not an ownership confusion');
    } else if (out.read.verdict === 'enforced') {
      observation.push(`cross-tenant read refused — ownership enforced (${out.read.detail})`);
    } else {
      observation.push(`read differential inconclusive: ${out.read.detail}`);
    }

    // ——— (c) WRITE rung: only when explicitly enabled, and only where a read proved
    // cross-tenant exposure OR the candidate declares a write method. Canary field,
    // victim-side readback, unauth control, best-effort revert. ———
    const writeMethod = (cand.methods || []).find((m) => ['PATCH', 'PUT', 'POST'].includes(m)) || 'PATCH';
    const wantsWrite = writes && (out.read.verdict === 'idor' || (cand.methods || []).some((m) => ['PATCH', 'PUT', 'POST'].includes(m)));
    if (wantsWrite && otherId) {
      const field = cand.writeField || 'title';
      const canary = 'VARVEL-AUTHZ-CANARY-' + randomBytes(4).toString('hex');
      const prior = await send('write:baseline(A reads B)', { path: at(otherId), cookie: sessionA.cookie, authHeaders: sessionA.headers });
      const priorValue = prior ? fieldValue(prior.body, field) : undefined;
      const unauthW = await send('write:unauth-control', { method: writeMethod, path: at(otherId), body: JSON.stringify({ [field]: canary }), write: true });
      const crossW = await send('write:cross(A→B)', { method: writeMethod, path: at(otherId), cookie: sessionA.cookie, authHeaders: sessionA.headers, body: JSON.stringify({ [field]: canary }), write: true });
      const readback = await send('write:victim-readback(B)', { path: at(otherId), cookie: sessionB.cookie, authHeaders: sessionB.headers });
      out.write = classifyWrite({ cross: crossW, unauth: unauthW, readback, canary });
      if (out.write.verdict === 'idor-write') {
        observation.push(`cross-tenant ${writeMethod} as ${sessionA.label} persisted the canary onto ${sessionB.label}'s object (victim-side readback)`);
        inference.push('the missing ownership check extends from read to WRITE — the object is attacker-modifiable');
        impact.push(`any authenticated user can MODIFY every object under ${cand.path} — integrity loss across tenants, not just disclosure`);
        if (priorValue !== undefined) {
          await send('write:revert', { method: writeMethod, path: at(otherId), cookie: sessionA.cookie, authHeaders: sessionA.headers, body: JSON.stringify({ [field]: priorValue }), write: true });
          observation.push(`reverted the canary write back to the victim's original ${field} value (best effort, on the record)`);
        } else {
          observation.push('revert SKIPPED honestly: the original field value was not recoverable from the baseline read');
        }
      } else {
        observation.push(`write rung: ${out.write.detail}`);
      }
    }

    // ——— (c) DELETE rung: the most destructive — explicit opt-in only ———
    if (deletes && otherId && (out.read.verdict === 'idor' || (cand.methods || []).includes('DELETE'))) {
      const unauthD = await send('delete:unauth-control', { method: 'DELETE', path: at(otherId), write: true });
      const crossD = await send('delete:cross(A→B)', { method: 'DELETE', path: at(otherId), cookie: sessionA.cookie, authHeaders: sessionA.headers, write: true });
      const readbackAfter = await send('delete:victim-readback(B)', { path: at(otherId), cookie: sessionB.cookie, authHeaders: sessionB.headers });
      out.delete = classifyDelete({ cross: crossD, unauth: unauthD, readbackAfter });
      observation.push(`delete rung: ${out.delete.detail}`);
      if (out.delete.verdict === 'idor-delete') {
        inference.push('the missing ownership check extends to DELETE — attacker can destroy victim objects');
        impact.push(`any authenticated user can DELETE every object under ${cand.path} — availability/integrity loss; the lab state was restored via /lab/revert after proof`);
        observation.push('NOTE: the victim object was deleted as proof — restore target state (lab revert) after the run');
      }
    }

    // ——— (d) ESCALATION LADDER: mass assignment against the caller's OWN object
    // (safe by construction). Control write (no extra param) BEFORE the violation
    // write, readback triple, best-effort revert for revertable params. ———
    const ladderWanted = escalate && writes && (out.write || (cand.methods || []).some((m) => ['PATCH', 'PUT'].includes(m)));
    if (ladderWanted && ownId) {
      for (const param of (ladder || []).slice(0, AUTHZ_CAPS.maxLadder)) {
        const before = await send(`ladder:before(${param.key})`, { path: at(ownId), cookie: sessionA.cookie, authHeaders: sessionA.headers });
        const plainBody = cand.body || '{}';
        await send(`ladder:control-write(${param.key})`, { method: writeMethod, path: at(ownId), cookie: sessionA.cookie, authHeaders: sessionA.headers, body: plainBody, write: true });
        const controlAfter = await send(`ladder:control-readback(${param.key})`, { path: at(ownId), cookie: sessionA.cookie, authHeaders: sessionA.headers });
        const violBody = (() => { try { return JSON.stringify({ ...JSON.parse(plainBody), [param.key]: param.value }); } catch { return JSON.stringify({ [param.key]: param.value }); } })();
        await send(`ladder:violation-write(${param.key}=${JSON.stringify(param.value)})`, { method: writeMethod, path: at(ownId), cookie: sessionA.cookie, authHeaders: sessionA.headers, body: violBody, write: true });
        const after = await send(`ladder:after(${param.key})`, { path: at(ownId), cookie: sessionA.cookie, authHeaders: sessionA.headers });
        const v = classifyMassAssign({ before: before && before.body, controlAfter: controlAfter && controlAfter.body, after: after && after.body, field: param.key, value: param.value });
        const step = { param: param.key, value: param.value, verdict: v.verdict, detail: v.detail };
        if (v.verdict === 'mass-assignment') {
          const beforeVal = before ? fieldValue(before.body, param.key) : undefined;
          if (param.revert !== false && beforeVal !== undefined) {
            await send(`ladder:revert(${param.key})`, { method: writeMethod, path: at(ownId), cookie: sessionA.cookie, authHeaders: sessionA.headers, body: JSON.stringify({ [param.key]: beforeVal }), write: true });
            step.reverted = true;
          } else {
            step.reverted = false;
            step.revertNote = param.revert === false
              ? `param "${param.key}" is not revertable from a readback (original value unknowable) — SAID HONESTLY; restore own account state after the run`
              : 'no baseline value to restore to — revert skipped honestly';
          }
          observation.push(`the extra body parameter ${param.key}=${JSON.stringify(param.value)} PERSISTED on the caller's own object (before/control readbacks clean)`);
          inference.push(`${param.key} is mass-assignable — the update handler binds unlisted fields; combined with the cross-tenant write rung this is the IDOR→privilege-escalation/ATO ladder`);
          impact.push(`privilege-field mass assignment (${param.key}) turns the object-write flaw into account-level compromise (role change / email hijack / password reset semantics)`);
        }
        out.ladder.push(step);
      }
    }

    out.pairs = pairBuf;
    results.push(out);
  }

  // ——— (e) the summary + verdict rollup ———
  const VERDICT_SEV = { 'idor-delete': 5, 'unauth-delete': 5, 'unauth-write': 4, 'mass-assignment': 4, 'idor-write': 3, idor: 2, public: 1, enforced: 0, inconclusive: -1 };
  const verdicts = {};
  let violations = 0;
  for (const r of results) {
    const ladderHit = r.ladder.find((s) => s.verdict === 'mass-assignment');
    const all = [r.read && r.read.verdict, r.write && r.write.verdict, r.delete && r.delete.verdict, ladderHit && 'mass-assignment'].filter(Boolean);
    const best = all.sort((x, y) => (VERDICT_SEV[y] || 0) - (VERDICT_SEV[x] || 0))[0] || 'inconclusive';
    verdicts[r.template] = best;
    if (['idor', 'idor-write', 'idor-delete', 'mass-assignment', 'unauth-write', 'unauth-delete'].includes(best)) violations++;
  }
  return {
    ok: true,
    summary: {
      candidates: results.length, violations, requests: requestCount, refusals: refusals.length,
      verdicts,
      accounts: sessList.map((s) => s.label),
      sessions: sessList.map((s) => ({ label: s.label, role: s.role || null })),
      modes: { reads: true, writes: !!writes, deletes: !!deletes, escalate: !!escalate && !!writes },
    },
    results, refusals,
  };
}
