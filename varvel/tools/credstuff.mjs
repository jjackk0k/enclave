// VARVEL — credential-stuffing analyzer (authorized engagements, HITL-locked).
//
// RedAmon hands this to Hydra with 50+ protocols. VARVEL's native answer is deliberately
// narrower and MORE governed: web-form credential testing as an ANALYZER, not a cannon.
//
// HARD GOVERNANCE (by construction, not by prompt):
//   · HITL-LOCKED: refuses to run without `authorized: true` — the caller (the campaign's
//     countersigned exploit phase, or the operator directly) must explicitly unlock it.
//   · BUDGET-GATED: hard attempt cap (default 10, absolute max 25) — stuffing is the
//     loudest auth pattern there is ('auth-attempt', loudness 4), so the count is a
//     mandate, not a suggestion.
//   · LOCKOUT-AWARE: the first sign of lockout/rate-limiting (429, "locked", "too many",
//     escalating response times is NOT used — signals only) STOPS the run immediately.
//     Locking out real users is how pentests become incidents.
//   · STEALTH-PACED: every attempt goes through the shared pacer.
//   · HONEST: a success is only claimed on a real differential (redirect/session-cookie/
//     success-marker vs the established failure baseline). Passwords are NEVER echoed
//     back in results — masked to first 2 chars + length.

import http from 'node:http';
import https from 'node:https';
import { makePacer, asPacer } from '../engine/stealth.mjs';

const ABSOLUTE_MAX = 25;
const LOCKOUT_RE = /locked|lockout|too many (attempts|requests)|try again later|temporarily blocked|captcha/i;
const mask = (p) => String(p).slice(0, 2) + '…[' + String(p).length + ' chars]';

function post(u, { form, timeout = 2500, hdrs, agents } = {}) {
  return new Promise((resolve) => {
    const lib = u.protocol === 'https:' ? https : http;
    const body = new URLSearchParams(form).toString();
    let settled = false, text = '';
    const done = (v) => { if (settled) return; settled = true; clearTimeout(deadline); resolve(v); };
    const req = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method: 'POST', timeout, rejectUnauthorized: false,
      agent: agents ? (u.protocol === 'https:' ? agents.httpsAgent : agents.httpAgent) : undefined,
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'content-length': Buffer.byteLength(body), ...(hdrs || { 'user-agent': 'VARVEL-credstuff' }) },
    }, (r) => {
      r.on('data', (d) => { if (text.length < 32768) text += d.toString('utf8', 0, 32768 - text.length); });
      r.on('end', () => done({ status: r.statusCode, headers: r.headers, body: text }));
    });
    const deadline = setTimeout(() => { try { req.destroy(); } catch {} done(null); }, Math.max(timeout * 3, 6000));
    req.on('timeout', () => { try { req.destroy(); } catch {} done(null); });
    req.on('error', () => done(null));
    req.write(body);
    req.end();
  });
}

// loginUrl: the form action. usernames/passwords: candidate lists (tested nested,
// usernames outer). fields: { user: 'email', pass: 'password' } form field names.
// success: custom markers { statusIn: [302], location: /dashboard/, cookie: /session=|token=/i, bodyMatch: /welcome/i }
// failure baseline is established from the FIRST failure, then successes are diffs from it.
export async function credStuff(loginUrl, { usernames = [], passwords = [], fields = { user: 'email', pass: 'password' }, authorized = false, maxAttempts = 10, success = {}, stealth, pacer, timeout = 2500, agents = null } = {}) {
  if (!authorized) {
    return { refused: true, reason: 'HITL-locked: credential testing requires explicit authorization (the countersigned exploit phase or the operator). Pass { authorized: true } after sign-off.', attempts: 0, successes: [] };
  }
  let origin;
  try { origin = new URL(loginUrl).origin; } catch { throw new TypeError('credStuff: loginUrl must be an http(s) URL'); }
  const cap = Math.min(Math.max(1, Math.floor(maxAttempts) || 10), ABSOLUTE_MAX);
  if (!usernames.length || !passwords.length) throw new TypeError('credStuff: usernames and passwords are required');

  pacer = asPacer(pacer) || (stealth ? makePacer(stealth) : null);
  const results = [];
  let attempts = 0, stopped = null;
  let failureBaseline = null;

  outer:
  for (const user of usernames) {
    for (const pass of passwords) {
      if (attempts >= cap) { stopped = 'attempt budget reached (' + cap + ') — by design, stuffing stays bounded'; break outer; }
      attempts++;
      if (pacer) await pacer.pace();
      const r = await post(new URL(loginUrl), { form: { [fields.user]: user, [fields.pass]: pass }, timeout, hdrs: pacer && pacer.requestHeaders ? pacer.requestHeaders({ accept: 'text/html,*/*' }) : undefined, agents });
      if (pacer && r && (r.status === 429 || r.status === 503)) pacer.penalize(3, 0); // credential push-back is serious: triple back-off
      if (!r) continue;

      // LOCKOUT TRIPWIRE — stop before we become an incident.
      if (r.status === 429 || LOCKOUT_RE.test(r.body)) {
        stopped = 'LOCKOUT/rate-limit signal detected (HTTP ' + r.status + ') — stopped immediately to avoid account lockouts';
        break outer;
      }

      const cookies = ([]).concat(r.headers['set-cookie'] || []).join('; ');
      const isSuccess =
        (success.statusIn ? success.statusIn.includes(r.status) : [302, 303].includes(r.status))
        || (success.location && (r.headers.location || '').includes(success.location))
        || (success.cookie && success.cookie.test(cookies))
        || (success.bodyMatch && success.bodyMatch.test(r.body))
        || (!success.statusIn && !success.location && !success.cookie && !success.bodyMatch
            && failureBaseline
            && (r.status !== failureBaseline.status || cookies !== failureBaseline.cookies)
            && ((r.status >= 300 && r.status < 400) || (cookies && r.status === 200)));

      if (!failureBaseline && !isSuccess) failureBaseline = { status: r.status, cookies };
      if (isSuccess) {
        results.push({ username: user, passwordMasked: mask(pass), evidence: 'HTTP ' + r.status + (r.headers.location ? ' → ' + r.headers.location : '') + (cookies ? ' · session cookie issued' : ''), confidence: 'firm' });
      }
    }
  }

  return {
    loginUrl: origin + new URL(loginUrl).pathname,
    authorized: true,
    attempts,
    cap,
    stopped,
    successes: results,
    honest: results.length === 0 ? 'no valid credentials found within the authorized budget' : null,
    stealth: pacer ? pacer.profile.label : null,
  };
}
