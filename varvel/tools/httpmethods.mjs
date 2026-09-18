// VARVEL — HTTP methods + CORS + header misconfiguration checker (authorized).
//
// Enumerates allowed methods (OPTIONS/Allow), flags dangerous ones (PUT/DELETE/
// TRACE/CONNECT/PATCH), detects CORS misconfigurations (wildcard-with-credentials
// and arbitrary-origin reflection, robust to trivial origin normalization), and
// notes missing security headers. Read-only probes (OPTIONS + benign GETs).
//
// Correctness hardening (audited): header findings are only emitted for a host we
// actually reached (an unreachable host never "fabricates" missing-header findings);
// HSTS is only expected over https (meaningless over plain http); method names are
// trimmed + case-normalized; reflection is matched after trivial normalization.
//
// `httpFindings` is a pure, deterministic classifier; `analyzeHttp` does the live work.

import http from 'node:http';
import https from 'node:https';

const DANGEROUS = ['PUT', 'DELETE', 'CONNECT', 'PATCH'];
const normOrigin = (o) => String(o || '').trim().replace(/\/$/, '').toLowerCase();

export function httpFindings({ methods = [], cors = {}, headers = null } = {}) {
  const f = [];
  const add = (sev, title, ref) => f.push({ sev, title, ref });
  const up = (Array.isArray(methods) ? methods : []).map((m) => String(m).trim().toUpperCase()).filter(Boolean);

  if (up.includes('TRACE')) add('med', 'HTTP TRACE enabled (Cross-Site Tracing risk)', 'HTTP-TRACE');
  const dangerous = [...new Set(up.filter((m) => DANGEROUS.includes(m)))];
  if (dangerous.length) add('high', 'dangerous HTTP methods allowed: ' + dangerous.join(', '), 'HTTP-METHODS');

  if (cors.reflects && cors.credentials) add('high', 'CORS reflects arbitrary Origin with credentials', 'CORS-REFLECT');
  else if (cors.acao === '*' && cors.credentials) add('high', 'CORS allows any origin (*) with credentials', 'CORS-WILD-CRED');
  else if (cors.reflects) add('med', 'CORS reflects arbitrary Origin', 'CORS-REFLECT-NC');
  else if (cors.acao === '*') add('low', 'CORS allows any origin (Access-Control-Allow-Origin: *)', 'CORS-WILD');

  // Only emit header findings when we actually have header data (a reached host).
  if (headers && typeof headers === 'object') {
    if (headers.hsts === false) add('info', 'missing Strict-Transport-Security header', 'HDR-HSTS');
    if (headers.csp === false) add('low', 'missing Content-Security-Policy header', 'HDR-CSP');
    if (headers.xfo === false) add('low', 'missing X-Frame-Options header (clickjacking)', 'HDR-XFO');
  }
  return f;
}

function request(base, { method = 'GET', headers = {}, timeout = 1500 } = {}) {
  return new Promise((resolve) => {
    let u; try { u = new URL(base); } catch { return resolve(null); }
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request({ hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: (u.pathname || '/') + (u.search || ''), method, timeout, rejectUnauthorized: false, headers: { 'user-agent': 'VARVEL-http', ...headers } }, (r) => {
      r.resume(); // headers only
      resolve({ status: r.statusCode, headers: r.headers });
    });
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
    req.end();
  });
}

export async function analyzeHttp(base, { timeout = 1500 } = {}) {
  let scheme = 'http:'; try { scheme = new URL(base).protocol; } catch { return { ok: false, error: 'bad url', base }; }
  const opt = await request(base, { method: 'OPTIONS', timeout });
  const get = await request(base, { method: 'GET', timeout });
  const probeOrigin = 'https://varvel-cors-probe.example';
  const corsResp = await request(base, { method: 'GET', headers: { origin: probeOrigin }, timeout });

  if (!get && !opt && !corsResp) return { ok: false, error: 'unreachable', base };

  const methods = [...new Set(((opt && opt.headers.allow) || '').split(',').map((m) => m.trim().toUpperCase()).filter(Boolean))];
  const ch = (corsResp && corsResp.headers) || {};
  const acao = ch['access-control-allow-origin'];
  const cors = {
    acao,
    credentials: ch['access-control-allow-credentials'] === 'true',
    reflects: !!acao && acao !== '*' && normOrigin(acao) === normOrigin(probeOrigin),
  };

  // header findings only if we reached the host; HSTS only meaningful over https
  const gh = (get && get.headers) || null;
  const headers = gh ? { hsts: scheme === 'https:' ? !!gh['strict-transport-security'] : true, csp: !!gh['content-security-policy'], xfo: !!gh['x-frame-options'] } : null;

  return { ok: true, base, reachable: !!gh, methods, cors, headers, findings: httpFindings({ methods, cors, headers }) };
}
