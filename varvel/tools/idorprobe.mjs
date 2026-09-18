// VARVEL — idorprobe: the ownership-confusion DIFFERENTIAL oracle (T2 IDOR family).
//
// The IDOR test done to the platform's proof standard: three governed reads —
//   own    : the caller's OWN object, authenticated      (baseline)
//   other  : ANOTHER tenant's object, authenticated      (the claim)
//   unauth : ANOTHER tenant's object, NO credentials     (the control)
// and a PURE classifier over the trio. A status-code-only claim is never made:
//
//   idor      — other=200 AND unauth refused (401/403) AND other's body differs from
//               own (a DIFFERENT object's content crossed the boundary)
//   enforced  — other=403/404 (ownership check holds; indistinguishable from a miss)
//   public    — other=200 but the UNAUTH control returns the IDENTICAL body (a public
//               object: enumerable + 200-for-everyone LOOKS like an IDOR to naive
//               tools; the control is what kills it)
//   inconclusive — anything else, said honestly (no claim without a control)
//
// naiveIdorFlag() is the scanner-grade heuristic (object ref + enumerable id + authed
// 200) — exported so tests can demonstrate that it flags ALL THREE shapes while the
// differential oracle sorts them. That contrast is the decoy's lesson.
//
// House contract: classifyIdor is pure; idorProbe touches the network but NEVER throws.

import http from 'node:http';
import https from 'node:https';

export function naiveIdorFlag({ own }) {
  // What a scanner sees: an authenticated object read succeeded on an enumerable id.
  return !!(own && own.status === 200);
}

export function classifyIdor({ own, other, unauth }) {
  if (!other || other.status == null) return { verdict: 'inconclusive', detail: 'cross-tenant read produced no response — no claim without a response' };
  if (other.status === 403 || other.status === 404) {
    return { verdict: 'enforced', detail: `cross-tenant read refused (${other.status}) — ownership check holds` };
  }
  if (other.status === 401) return { verdict: 'enforced', detail: 'cross-tenant read requires different auth (401)' };
  if (other.status === 200) {
    if (unauth && unauth.status === 200 && unauth.body === other.body) {
      return { verdict: 'public', detail: 'unauth control returned the IDENTICAL body — public object, not an ownership confusion' };
    }
    if (!unauth || unauth.status == null) return { verdict: 'inconclusive', detail: 'no control read — the claim stays unproven' };
    if ([401, 403].includes(unauth.status) && own && own.status === 200 && own.body !== other.body) {
      return { verdict: 'idor', detail: 'cross-tenant 200 with tenant-distinct content while the unauth control was refused — ownership confusion confirmed' };
    }
    if ([401, 403].includes(unauth.status)) {
      return { verdict: 'inconclusive', detail: 'control refused, but cross-tenant body matches own (or no own baseline) — cannot attribute tenancy' };
    }
    return { verdict: 'inconclusive', detail: `control returned ${unauth.status} (not refused, not identical) — partial exposure, reproduce manually` };
  }
  return { verdict: 'inconclusive', detail: `cross-tenant read returned ${other.status}` };
}

function get(u, { cookie, timeout = 2500 } = {}) {
  return new Promise((resolve) => {
    const lib = u.protocol === 'https:' ? https : http;
    const headers = { 'user-agent': 'VARVEL-idorprobe' };
    if (cookie) headers.cookie = cookie;
    const req = lib.request({ hostname: u.hostname, port: u.port || 80, path: u.pathname + u.search, method: 'GET', timeout, headers }, (res) => {
      let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => resolve({ status: res.statusCode, body: b }));
    });
    req.on('error', () => resolve(null)); req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

/**
 * @param base   http(s) base URL (loopback/lab in the research lane)
 * @param pathTemplate  e.g. '/api/bookings/{id}'
 * @param ownId  the caller's own object id    @param otherId  another tenant's id
 * @param cookie the caller's session cookie (optional — without it, only public detection is possible)
 */
export async function idorProbe(base, { pathTemplate, ownId, otherId, cookie, timeout } = {}) {
  try {
    const at = (id) => new URL(String(pathTemplate).replace('{id}', String(id)), base);
    const requests = [];
    const fire = async (u, c, label) => { const r = await get(u, { cookie: c, timeout }); requests.push({ label, path: u.pathname, status: r ? r.status : null }); return r; };
    const own = cookie ? await fire(at(ownId), cookie, 'own') : null;
    const other = await fire(at(otherId), cookie, 'other');
    const unauth = await fire(at(otherId), null, 'unauth-control');
    const result = classifyIdor({ own, other, unauth });
    return { ...result, naiveWouldFlag: naiveIdorFlag({ own: own || other }), requests };
  } catch (e) {
    return { verdict: 'inconclusive', detail: 'probe error: ' + String((e && e.message) || e), naiveWouldFlag: false, requests: [] };
  }
}
