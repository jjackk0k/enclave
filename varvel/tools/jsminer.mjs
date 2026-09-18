// VARVEL — jsminer: JS / SOURCEMAP MINING, zero-dep (hunting-tools build, Tool 2).
//
// katana/gau are NOT installed and we never shell out — given a base URL this
// miner does it in-process: fetch the HTML (ghost-riding, paced), collect script
// srcs, fetch each JS (scope-confined), and extract
//
//   (a) ENDPOINTS — endpoint-like strings ('/api/…', absolute URLs); concrete
//       id-bearing paths fold into {id} templates (authzsweep's templatizePath)
//       and are emitted as CANDIDATES in the exact shape synthesizeCandidates()
//       consumes: { path with {id}, methods, refs: { a: [], b: [] } };
//   (b) SECRETS — the trufflehog/gitleaks regex set: AWS AKIA, Google AIza,
//       GitHub ghp_/github_pat_, Slack xox*, Stripe sk_live, SendGrid, Twilio,
//       JWTs, private-key blocks, and generic high-entropy assignments
//       (Shannon-gated, placeholder-denylisted);
//   (c) SOURCEMAPS — '//# sourceMappingURL=' → fetch the .map → mine every
//       sourcesContent entry AGAIN (webpack-buried routes + keys surface here).
//
// THE ORACLE: a secret only graduates to 'verified' by LIVE USE — verifySecret()
// is OPT-IN, does exactly ONE governed request (the AWS STS GetCallerIdentity
// differential: SignatureDoesNotMatch = the key ID is KNOWN to AWS → verified;
// InvalidClientTokenId = unknown → stays a candidate; Google AIza gets the
// key-invalid differential). mine() NEVER verifies unless verify:true is passed —
// extraction without invocation is the default, and the tests pin that no
// verification request fires uninvited.
//
// GOVERNANCE: every fetch accepts agents { http, https } (ghost chain
// socks5://10.64.0.1:1080, wired by the campaign), awaits pacer.pace() before
// every request, honors pathPrefixes confinement, and FAILS CLOSED when `scope`
// is present and the target host is outside it — a refusal is returned, nothing
// is dialed. Budget {maxRequests, maxMs} stops the run honestly
// ('budget.exhausted' via onLog). Never throws.
//
// CAPS: JSMINER_CAPS.
//
// usage:
//   import { mine, verifySecret } from './tools/jsminer.mjs';
//   const r = await mine('https://target.example/', { agents, pacer, scope, budget, onLog });
//   // r.candidates feeds synthesizeCandidates(harvested, r.candidates) in authzsweep
//   const v = await verifySecret(r.secrets[0], { agents, pacer }); // OPT-IN, one request

import http from 'node:http';
import https from 'node:https';
import { pathPrefixAllowed } from '../engine/scopepath.mjs';
import { templatizePath } from './authzsweep.mjs';

export const JSMINER_CAPS = { maxScripts: 24, maxMaps: 8, maxJsBytes: 1048576, maxEndpoints: 200, maxSecrets: 40, maxCandidates: 24, maxVerify: 4, bodySnippet: 400 };

const logTo = (onLog, obj) => { if (typeof onLog === 'function') { try { onLog(obj); } catch { /* observer never breaks the miner */ } } };

function makeBudget(budget, onLog) {
  const b = { maxRequests: Number.isFinite(budget && budget.maxRequests) ? budget.maxRequests : Infinity, maxMs: Number.isFinite(budget && budget.maxMs) ? budget.maxMs : Infinity, used: 0, t0: Date.now() };
  return {
    spend(what) {
      const elapsed = Date.now() - b.t0;
      if (b.used >= b.maxRequests || elapsed >= b.maxMs) {
        logTo(onLog, { type: 'budget.exhausted', tool: 'jsminer', what, used: b.used, maxRequests: b.maxRequests, elapsedMs: elapsed, maxMs: b.maxMs });
        return false;
      }
      b.used += 1;
      return true;
    },
    state: () => ({ used: b.used, maxRequests: b.maxRequests, elapsedMs: Date.now() - b.t0, maxMs: b.maxMs }),
  };
}

// hostAllowed(host, scope) — fail-closed when a signed scope is present and the
// host is outside it. scope.hosts entries match exactly or as a parent suffix.
export function hostAllowed(host, scope) {
  if (!scope || !Array.isArray(scope.hosts) || !scope.hosts.length) return true; // no scope constraint (lab default)
  const h = String(host || '').toLowerCase();
  return scope.hosts.some((s) => { const x = String(s).toLowerCase(); return h === x || h.endsWith('.' + x); });
}

// ——— transport (never throws) — the authzsweep fire() shape ———
function fire(url, { method = 'GET', timeout = 8000, agents = null, extraHeaders = null } = {}) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve(null); }
    const lib = u.protocol === 'https:' ? https : http;
    // extraHeaders: program-required attestation headers (e.g. HackerOne's
    // X-HackerOne) — merged over the tool UA's sibling headers, never replacing it.
    const hdrs = { 'user-agent': 'VARVEL-jsminer' };
    if (extraHeaders && typeof extraHeaders === 'object') for (const [k, v] of Object.entries(extraHeaders)) { const lk = String(k).toLowerCase(); if (lk !== 'user-agent') hdrs[lk] = String(v); }
    const req = lib.request({ hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search, method, timeout, headers: hdrs, agent: agents ? agents[u.protocol === 'https:' ? 'https' : 'http'] : undefined }, (res) => {
      let b = ''; res.on('data', (d) => { if (b.length < JSMINER_CAPS.maxJsBytes) b += d; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    req.on('error', () => resolve(null)); req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

// ——— (a) ENDPOINTS — pure ———
const SKIP_ASSET_RE = /\.(css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|avif)(\?|#|$)/i;
// extractEndpoints(text) → { paths: ['/api/…'], urls: ['https://…'] } — quoted
// path strings with a letter, minus static assets; absolute http(s) URLs.
export function extractEndpoints(text) {
  const paths = [], urls = [];
  const seenP = new Set(), seenU = new Set();
  const s = String(text || '');
  let m;
  const rePath = /["'`](\/(?:[A-Za-z0-9_\-.~{}]|\{[a-z]+\})[A-Za-z0-9_\-.\/~{}]{1,120})["'`]/g;
  while ((m = rePath.exec(s)) && paths.length < JSMINER_CAPS.maxEndpoints) {
    const p = m[1];
    if (!/[A-Za-z]/.test(p)) continue;                 // '/' or '/123' is not an endpoint
    if (p.startsWith('//')) continue;                  // protocol-relative — handled as URL
    if (SKIP_ASSET_RE.test(p)) continue;
    if (seenP.has(p)) continue;
    seenP.add(p); paths.push(p);
  }
  const reUrl = /\bhttps?:\/\/[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)+(?::\d{1,5})?(?:\/[^\s"'`<>)]*)?/g;
  while ((m = reUrl.exec(s)) && urls.length < JSMINER_CAPS.maxEndpoints) {
    const u = m[0].replace(/[.,;:]+$/, '');
    if (SKIP_ASSET_RE.test(u)) continue;
    if (/\.(example|invalid|test)(\.|\/|:|$)/.test(u)) continue; // doc placeholder TLDs are not surface
    if (seenU.has(u)) continue;
    seenU.add(u); urls.push(u);
  }
  return { paths, urls };
}

// ——— (b) SECRETS — the trufflehog/gitleaks regex set, ported — pure ———
export const SECRET_RULES = [
  { type: 'aws-access-key-id', re: /\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g },
  { type: 'google-api-key', re: /\bAIza[0-9A-Za-z_\-]{35}\b/g },
  { type: 'gcp-oauth-client', re: /\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b/g },
  { type: 'github-token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}_[A-Za-z0-9_]{40,}\b/g },
  { type: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { type: 'stripe-live-key', re: /\b[sr]k_live_[0-9A-Za-z]{16,}\b/g },
  { type: 'sendgrid-api-key', re: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/g },
  { type: 'twilio-account-sid', re: /\bAC[0-9a-f]{32}\b/g },
  { type: 'jwt', re: /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b/g },
  { type: 'private-key-block', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g },
];
const GENERIC_ASSIGN_RE = /["']?(?:api[_-]?key|api[_-]?secret|access[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|private[_-]?token|app[_-]?secret)["']?\s*[:=]\s*["'`]([A-Za-z0-9\/+_\-=.]{16,128})["'`]/gi;
const PLACEHOLDER_RE = /your|example|placeholder|change|xxxx|<|>|\.\.\.|process\.env|dummy|sample/i;

// shannon(s) — bits/char; the gitleaks generic rule gates on entropy, and so do
// we (3.5): 'aaaaaaaaaaaaaaaa' is not a secret no matter what it is named.
export function shannon(s) {
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  let h = 0;
  for (const n of Object.values(freq)) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

// extractSecrets(text) → [{ type, value, redacted, entropy?, status: 'candidate' }]
// Status is ALWAYS 'candidate' here — graduation to 'verified' is verifySecret's
// job, live and opt-in. Deduped, capped. Never throws.
export function extractSecrets(text) {
  const out = [];
  const seen = new Set();
  const s = String(text || '');
  const push = (type, value, extra = {}) => {
    if (out.length >= JSMINER_CAPS.maxSecrets) return;
    const k = type + '=' + value;
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ type, value, redacted: value.length > 10 ? value.slice(0, 6) + '…' + value.slice(-2) : value.slice(0, 3) + '…', status: 'candidate', ...extra });
  };
  for (const rule of SECRET_RULES) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(s))) push(rule.type, m[0]);
  }
  GENERIC_ASSIGN_RE.lastIndex = 0;
  let m;
  while ((m = GENERIC_ASSIGN_RE.exec(s))) {
    const v = m[1];
    if (PLACEHOLDER_RE.test(v)) continue;
    const h = shannon(v);
    if (h < 3.5) continue; // low-entropy decoy — a real key mixes its alphabet
    push('generic-high-entropy', v, { entropy: Number(h.toFixed(2)) });
  }
  return out;
}

// endpointsToCandidates(paths) — fold concrete id-bearing paths into the
// {id}-templated candidate shape synthesizeCandidates() consumes as `templates`
// ({ path, methods, refs: { a, b } }). Plain paths stay in `endpoints` — the
// authzsweep oracle needs the {id} shape to run a differential. Pure.
export function endpointsToCandidates(paths) {
  const out = [];
  const seen = new Set();
  for (const p of paths || []) {
    const t = templatizePath(String(p).split('?')[0]);
    if (!t || seen.has(t.template)) continue;
    seen.add(t.template);
    out.push({ path: t.template, methods: ['GET'], refs: { a: [], b: [] }, observedValue: t.value, source: 'jsminer' });
    if (out.length >= JSMINER_CAPS.maxCandidates) break;
  }
  return out;
}

// ——— the governed mine ———
// mine(baseUrl, { agents, pacer, scope, pathPrefixes, budget, onLog, timeout,
//   verify, verifyEndpoints }) → { ok, base, scripts, sourcemaps, endpoints,
//   secrets, candidates, refusals, budget, verification } — NEVER throws.
// verify defaults FALSE: secrets are extracted, never invoked, unless the
// operator asks (the tests pin that no verification request fires uninvited).
export async function mine(baseUrl, { agents = null, pacer = null, scope = null, pathPrefixes = null, budget = null, onLog = null, timeout = 8000, verify = false, verifyEndpoints = null, extraHeaders = null } = {}) {
  const refusals = [];
  const bd = makeBudget(budget, onLog);
  let u;
  try { u = new URL(baseUrl); } catch { return { ok: false, error: 'unparseable base URL', base: String(baseUrl), scripts: [], sourcemaps: [], endpoints: { paths: [], urls: [] }, secrets: [], candidates: [], refusals, budget: bd.state(), verification: { attempted: false } }; }
  // FAIL-CLOSED: outside a signed scope, the refusal is the whole result
  if (!hostAllowed(u.hostname, scope)) {
    refusals.push({ url: baseUrl, reason: 'out-of-scope-host' });
    logTo(onLog, { type: 'jsminer.refused', url: baseUrl, reason: 'out-of-scope-host' });
    return { ok: false, error: 'target host outside the signed scope — refused before the wire', base: baseUrl, scripts: [], sourcemaps: [], endpoints: { paths: [], urls: [] }, secrets: [], candidates: [], refusals, budget: bd.state(), verification: { attempted: false } };
  }
  const pace = async () => { if (pacer && typeof pacer.pace === 'function') await pacer.pace(); };
  const get = async (url, what) => {
    if (!bd.spend(what)) return null;
    await pace();
    return fire(url, { timeout, agents, extraHeaders });
  };

  const scripts = [], sourcemaps = [], refusalsOut = refusals;
  const allPaths = new Set(), allUrls = new Set();
  const secrets = [];
  const seenSecrets = new Set();
  const absorb = (text, origin) => {
    const eps = extractEndpoints(text);
    for (const p of eps.paths) allPaths.add(p);
    for (const x of eps.urls) allUrls.add(x);
    for (const sec of extractSecrets(text)) {
      const k = sec.type + '=' + sec.value;
      if (seenSecrets.has(k) || secrets.length >= JSMINER_CAPS.maxSecrets) continue;
      seenSecrets.add(k);
      secrets.push({ ...sec, foundIn: origin });
    }
  };

  // ——— pass 0: the HTML page ———
  const page = await get(baseUrl, 'html');
  if (!page || page.status == null) return { ok: false, error: 'base page unreachable', base: baseUrl, scripts, sourcemaps, endpoints: { paths: [], urls: [] }, secrets, candidates: [], refusals: refusalsOut, budget: bd.state(), verification: { attempted: false } };
  absorb(page.body, baseUrl);

  // ——— pass 1: script srcs, scope-confined ———
  const srcRe = /<script[^>]*\ssrc=["']([^"']+)["']/gi;
  let m;
  const srcs = [];
  while ((m = srcRe.exec(page.body)) && srcs.length < JSMINER_CAPS.maxScripts * 2) {
    let su;
    try { su = new URL(m[1], baseUrl); } catch { continue; }
    if (!/^https?:$/.test(su.protocol)) continue;
    srcs.push(su.href);
  }
  for (const src of srcs.slice(0, JSMINER_CAPS.maxScripts)) {
    const su = new URL(src);
    // same-host scripts always ride; cross-host scripts ONLY when the signed
    // scope names the host — otherwise the refusal is recorded, nothing dialed
    if (su.hostname !== u.hostname && !(scope && hostAllowed(su.hostname, scope))) {
      refusalsOut.push({ url: src, reason: 'out-of-scope-host' });
      continue;
    }
    if (pathPrefixes && !pathPrefixAllowed(su.pathname, pathPrefixes)) {
      refusalsOut.push({ url: src, reason: 'out-of-scope-path' });
      continue;
    }
    const r = await get(src, 'js:' + su.pathname);
    if (!r || r.status !== 200) { scripts.push({ url: src, status: r ? r.status : null, mined: false }); continue; }
    scripts.push({ url: src, status: r.status, bytes: r.body.length, mined: true });
    absorb(r.body, src);

    // ——— pass 2: sourcemap → sourcesContent → mine AGAIN ———
    const sm = r.body.match(/\/\/[#@]\s*sourceMappingURL=\s*(\S+)/);
    if (sm && sourcemaps.length < JSMINER_CAPS.maxMaps) {
      let mu;
      try { mu = new URL(sm[1], src); } catch { mu = null; }
      if (mu && (mu.hostname === u.hostname || (scope && hostAllowed(mu.hostname, scope))) && (!pathPrefixes || pathPrefixAllowed(mu.pathname, pathPrefixes))) {
        const mr = await get(mu.href, 'map:' + mu.pathname);
        if (mr && mr.status === 200) {
          let map = null;
          try { map = JSON.parse(mr.body); } catch { /* a non-JSON map is not a map */ }
          if (map && Array.isArray(map.sourcesContent)) {
            let minedSrcs = 0;
            for (let i = 0; i < map.sourcesContent.length; i++) {
              if (typeof map.sourcesContent[i] !== 'string') continue;
              absorb(map.sourcesContent[i], mu.href + '#' + ((map.sources && map.sources[i]) || i));
              minedSrcs++;
            }
            sourcemaps.push({ url: mu.href, sources: minedSrcs, mined: true });
          } else {
            sourcemaps.push({ url: mu.href, sources: 0, mined: false, note: 'no sourcesContent — nothing to reconstruct' });
          }
        }
      } else if (mu) {
        refusalsOut.push({ url: mu.href, reason: 'out-of-scope' });
      }
    }
  }

  const candidates = endpointsToCandidates([...allPaths]);

  // ——— THE ORACLE, OPT-IN: verify secrets by live use ———
  const verification = { attempted: false, results: [] };
  if (verify === true) {
    verification.attempted = true;
    for (const sec of secrets.slice(0, JSMINER_CAPS.maxVerify)) {
      const v = await verifySecret(sec, { agents, pacer, budget: bd, timeout, endpoints: verifyEndpoints, onLog });
      verification.results.push(v);
      if (v.verified) sec.status = 'verified';
    }
  }

  logTo(onLog, { type: 'jsminer.mined', base: baseUrl, scripts: scripts.length, sourcemaps: sourcemaps.length, endpoints: allPaths.size + allUrls.size, secrets: secrets.length, candidates: candidates.length, verified: secrets.filter((s) => s.status === 'verified').length });
  return {
    ok: true, base: baseUrl, scripts, sourcemaps,
    endpoints: { paths: [...allPaths].slice(0, JSMINER_CAPS.maxEndpoints), urls: [...allUrls].slice(0, JSMINER_CAPS.maxEndpoints) },
    secrets, candidates, refusals: refusalsOut, budget: bd.state(), verification,
  };
}

// ——— the secret oracle — exactly ONE governed request, opt-in only ———
// verifySecret(secret, { agents, pacer, budget, timeout, endpoints, onLog })
//   aws-access-key-id : STS GetCallerIdentity UNSIGNED-shape differential — a
//     forged signature on a REAL key id earns 'SignatureDoesNotMatch' (the key
//     EXISTS: verified); an unknown key id earns 'InvalidClientTokenId' (stays a
//     candidate). One request, no valid signature ever sent.
//   google-api-key    : the geocode key differential — 200/'REQUEST_DENIED' for
//     a live-but-restricted key vs explicit key-invalid for a dead one.
//   anything else     : { verified: false, reason: 'no verifier for this type' }
// `endpoints` overrides the public verifier URLs — tests point them at a local
// mock. Never throws; NEVER called by mine() unless verify:true.
export async function verifySecret(secret, { agents = null, pacer = null, budget = null, timeout = 8000, endpoints = null, onLog = null } = {}) {
  if (!secret || typeof secret.value !== 'string') return { verified: false, reason: 'no secret given' };
  const ep = endpoints || {};
  const bd = budget && typeof budget.spend === 'function' ? budget : makeBudget(budget, onLog);
  if (!bd.spend('verify:' + secret.type)) return { type: secret.type, verified: false, reason: 'budget exhausted — verification not attempted' };
  if (pacer && typeof pacer.pace === 'function') await pacer.pace();

  if (secret.type === 'aws-access-key-id') {
    const base = (ep.aws || 'https://sts.amazonaws.com').replace(/\/$/, '');
    // the UNSIGNED differential: real key id + garbage signature → SignatureDoesNotMatch
    const q = `?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256`
      + `&X-Amz-Credential=${encodeURIComponent(secret.value + '/20260101/us-east-1/sts/aws4_request')}`
      + `&X-Amz-Date=20260101T000000Z&X-Amz-SignedHeaders=host&X-Amz-Signature=${'0'.repeat(64)}`;
    const r = await fire(base + '/' + q, { timeout, agents });
    if (!r) return { type: secret.type, verified: false, reason: 'verifier unreachable — no claim without a response' };
    const body = String(r.body || '');
    if (/SignatureDoesNotMatch/.test(body)) return { type: secret.type, verified: true, detail: 'STS answered SignatureDoesNotMatch to a forged signature — the key ID is KNOWN to AWS (a dead key earns InvalidClientTokenId)', redacted: secret.redacted };
    if (/InvalidClientTokenId/.test(body)) return { type: secret.type, verified: false, detail: 'STS answered InvalidClientTokenId — AWS does not know this key ID', redacted: secret.redacted };
    return { type: secret.type, verified: false, reason: `verifier answered ${r.status} without a recognizable differential`, redacted: secret.redacted };
  }
  if (secret.type === 'google-api-key') {
    const base = (ep.google || 'https://maps.googleapis.com/maps/api/geocode/json').replace(/\/$/, '');
    const r = await fire(`${base}?address=varvel-probe&key=${encodeURIComponent(secret.value)}`, { timeout, agents });
    if (!r) return { type: secret.type, verified: false, reason: 'verifier unreachable — no claim without a response' };
    const body = String(r.body || '');
    if (/keyInvalid|API key not valid/i.test(body)) return { type: secret.type, verified: false, detail: 'Google rejected the key as invalid', redacted: secret.redacted };
    return { type: secret.type, verified: true, detail: `Google answered ${r.status} WITHOUT a key-invalid error — the key is live (REQUEST_DENIED means live-but-restricted, still billable)`, redacted: secret.redacted };
  }
  return { type: secret.type, verified: false, reason: `no verifier for type '${secret.type}' — stays a candidate (honest)`, redacted: secret.redacted };
}
