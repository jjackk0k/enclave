// engine/challenge.mjs — PURE challenge-taxonomy detection (Cloudflare-first, WAF-generic).
//
// Why: 2026-08-05 mission 1 (manhuaus) — every web tool saw "403" and only the operator's
// reading of cf-mitigated told us it was a MANAGED CHALLENGE, not a block. The taxonomy is
// the difference between "target defended, back off" and "path is open". Research basis:
// cf-mitigated header, challenge-platform markers, Turnstile iframe, error-1020 block page,
// legacy rate-limit engine, and Cloudflare's AI Labyrinth honeypot (2025) — see KIMI-NOTES.
//
// HONESTY CONTRACT: detection is EVIDENCE classification, never a bypass claim and never a
// vendor verdict. Every verdict carries the exact signals that fired. A 'none' means "no
// challenge evidence observed in THIS response" — not "the zone is unprotected".

export const CHALLENGE_KINDS = [
  'block-1020',        // hard WAF block page ("error code: 1020") — rule fired, no challenge offered
  'rate-limit',        // 429 / retry-after pressure
  'turnstile',         // interactive Turnstile widget present
  'captcha',           // interactive CAPTCHA challenge
  'managed-js',        // managed/JS challenge ("Just a moment…", challenge-platform)
  'labyrinth-suspect', // AI Labyrinth honeypot markers — NEVER follow; report
  'none',
];

const hdr = (headers, name) => {
  if (!headers) return '';
  if (typeof headers.get === 'function') return headers.get(name) || '';
  const want = name.toLowerCase();
  for (const k of Object.keys(headers)) if (k.toLowerCase() === want) return String(headers[k] || '');
  return '';
};

/**
 * Classify ONE response's challenge posture.
 * @param {{status?:number, headers?:object, body?:string}} r
 * @returns {{present:boolean, kind:string, signals:string[], cf:{server:boolean, ray:string|null, mitigated:string|null}}}
 */
export function detectChallenge({ status = 0, headers = {}, body = '' } = {}) {
  const server = hdr(headers, 'server');
  const cfServer = /cloudflare/i.test(server);
  const ray = hdr(headers, 'cf-ray') || null;
  const mitigated = hdr(headers, 'cf-mitigated') || null;
  const retryAfter = hdr(headers, 'retry-after') || null;
  const b = String(body || '');
  const signals = [];
  let kind = 'none';

  // --- interactive + block kinds (highest precedence) ---
  if (/error code:\s*1020|Attention Required!\s*\|\s*Cloudflare/i.test(b)) {
    kind = 'block-1020';
    signals.push('Cloudflare 1020 block page — a firewall rule FIRED on this request (no challenge offered)');
  } else if (status === 429 || /cf-ratelimit|rate.?limit/i.test(hdr(headers, 'cf-chl-bypass') + ' ' + b.slice(0, 400))) {
    kind = 'rate-limit';
    signals.push(`rate-limit pressure (status ${status}${retryAfter ? ', retry-after ' + retryAfter : ''})`);
    if (retryAfter) signals.push('retry-after: ' + retryAfter);
  } else if (/challenges\.cloudflare\.com\/turnstile|cf-turnstile/i.test(b)) {
    kind = 'turnstile';
    signals.push('Turnstile widget markers — an INTERACTIVE proof-of-work/environment challenge is embedded');
  } else if (/cf_captcha|captcha-delivery|g-recaptcha|hcaptcha/i.test(b)) {
    kind = 'captcha';
    signals.push('CAPTCHA markers — an interactive human challenge is embedded');
  } else if (/cdn-cgi\/labyrinth|\blabyrinth\b/i.test(b) || /cdn-cgi\/labyrinth/i.test(hdr(headers, 'link') + ' ' + hdr(headers, 'cf-labyrinth'))) {
    kind = 'labyrinth-suspect';
    signals.push('AI Labyrinth markers — a honeypot that feeds bots generated mazes; do NOT follow links from this body');
  } else if (/cf-chl-|challenge-platform|cf_chl_|Just a moment\.\.\.|Checking your browser|Verify you are human/i.test(b) || (mitigated && /challenge/i.test(mitigated))) {
    kind = 'managed-js';
    if (mitigated && /challenge/i.test(mitigated)) signals.push(`cf-mitigated: ${mitigated}`);
    if (/challenge-platform|cf-chl-|cf_chl_/i.test(b)) signals.push('challenge-platform script markers — the JS bundle must execute to mint cf_clearance');
    if (/Just a moment\.\.\.|Checking your browser|Verify you are human/i.test(b)) signals.push('interstitial body text ("Just a moment…")');
  }

  if (kind !== 'none') {
    if (cfServer) signals.unshift('server: cloudflare');
    if (ray) signals.push('cf-ray: ' + ray);
    if (status === 503 && kind === 'managed-js') signals.push('status 503 — legacy JS-challenge shape (older managed form)');
    else if (status) signals.push(`status ${status}`);
  } else {
    if (cfServer) signals.push('server: cloudflare — no challenge evidence in THIS response (not proof the zone is unprotected)');
    else signals.push('no Cloudflare markers and no challenge evidence observed');
  }

  return { present: kind !== 'none', kind, signals, cf: { server: cfServer, ray, mitigated } };
}

/**
 * Summarize a surface map (cfmap): which paths are challenged vs openly served.
 * @param {Array<{path:string, status:number, detection:object}>} probes
 */
export function summarizeSurface(probes = []) {
  const out = { total: probes.length, challenged: 0, open: [], blocked: [], rateLimited: [], labyrinth: [], errors: [], note: '' };
  for (const p of probes) {
    const d = p.detection || {};
    if (d.kind === 'labyrinth-suspect') { out.labyrinth.push(p.path); continue; }
    if (d.kind === 'block-1020') { out.blocked.push(p.path); continue; }
    if (d.kind === 'rate-limit') { out.rateLimited.push(p.path); continue; }
    if (d.present) { out.challenged++; continue; }
    if (p.status >= 200 && p.status < 400) out.open.push({ path: p.path, status: p.status });
    else out.errors.push({ path: p.path, status: p.status });
  }
  out.note = out.open.length
    ? `${out.open.length} path(s) served WITHOUT challenge — reportable posture finding (per-path rule carve-outs are common); an open path is surface, not a bypass`
    : (out.challenged === out.total && out.total > 0 ? 'uniform challenge posture across probed paths' : 'no unchallenged surface observed in this probe set');
  return out;
}
