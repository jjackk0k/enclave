// VARVEL — targetscore: per-host EXPECTED-YIELD scoring (the target ROI layer).
//
// Stop grinding hardened edge-walled estates indiscriminately: score every
// in-scope host for expected yield from data recon ALREADY gathered (surface
// nodes, tech nodes, response-behavior samples) so the campaign spends its
// per-host tool budgets on soft, high-value surface FIRST. Pure function over
// the attack-surface graph — NO I/O, NO LLM call, fully deterministic: the
// same surface always produces the same scores.
//
// THE HONESTY CONTRACT: every point bump emits a reason that NAMES its signal
// and cites the observed evidence behind it ("api-density +12 — 9 endpoint(s)
// harvested on the host"). A reason with no observed signal does not exist;
// the tests pin that absent signals produce no reasons. Scores REORDER —
// they never skip an in-scope host, never hide one, and change no refusal
// rule. A Cloudflare/Akamai static edge scores DOWN, not out.
//
// OUTPUT: per host { host, hid?, score 0-100, reasons[], classes[] } — classes
// are routing hints for downstream lanes ('idor-candidate', 'ai-surface',
// 'api-heavy', 'soft-env', 'spa', 'edge-walled'). scoreSurface() also returns
// `ordered` (host labels, score-descending) and `scores` (label/ip → score)
// so the campaign can order per-host tool budgets without re-walking nodes.
//
// CAPS: TARGETSCORE_CAPS.
//
// usage:
//   import { scoreHost, scoreSurface, preScoreTargets } from './tools/targetscore.mjs';
//   const s = scoreSurface(campaign.surface);            // live Surface or its toJSON()
//   const pre = preScoreTargets(targets, priorSurface);  // sweep-order pre-pass

export const TARGETSCORE_CAPS = { maxReasons: 24, maxHosts: 500, maxClasses: 8 };

// ——— the signal tables — every regex here is a signal recon actually records ———
// Non-prod hostname keywords: staging/dev/admin surface carries weaker auth,
// self-signup, and debug defaults far more often than the marketing edge.
const SOFT_HOST_RE = /(?:^|[.\-])(admin|staging|stage|dev|internal|test|sandbox|uat|qa|beta)(?:[.\-]|$)/i;
const API_HOST_RE = /(?:^|[.\-])(api|graphql|gateway|ws)(?:[.\-]|$)/i;
// Login/auth forms as endpoint paths recon harvested (crawl/webscan/apisurface).
const AUTH_EP_RE = /\/(login|signin|sign-in|signon|auth|oauth|sso|session|token)(\/|\?|$)/i;
// Parameterized endpoints land on the surface as '/path?param=' or '{id}' templates.
const PARAM_EP_RE = /(\?[^=]*=)|\{id\}/;
// CDN/WAF edge vendors — fingerprinted via tech nodes (headers/TLS/stack) by recon.
const CDN_EDGE_RE = /cloudflare|akamai|cloudfront|fastly|incapsula|imperva|sucuri|stackpath|edgecast/i;
const SPA_RE = /react|vue\.?js|angular|svelte|next\.?js|nuxt|ember/i;
// AI/LLM surface hints: endpoint shapes + stack fingerprints (the +210% YoY class).
const AI_EP_RE = /\/(\.well-known\/ai-plugin\.json|mcp|sse|chat|completions?|copilot|llm|ai)(\/|\?|$)/i;
const AI_TECH_RE = /openai|anthropic|langchain|llamaindex|copilot|\bllm\b|\bmcp\b/i;
const WS_RE = /\b(wss?|websocket|socket\.io)\b/i;
const GRAPHQL_RE = /graphql/i;
// Historically bug-dense stacks score UP — payout data concentrates where these run.
const KNOWN_BUGGY = [
  [/word\s?press|wp-json|wp-content/i, 14, 'wordpress'],
  [/drupal/i, 14, 'drupal'],
  [/joomla/i, 12, 'joomla'],
  [/strapi/i, 10, 'strapi'],
  [/laravel/i, 10, 'laravel'],
  [/php|phpmyadmin/i, 8, 'php'],
  [/django/i, 6, 'django'],
  [/rails|ruby on rails/i, 6, 'rails'],
  [/spring|tomcat/i, 6, 'spring'],
  [/express|node\.?js/i, 4, 'express'],
  [/flask/i, 4, 'flask'],
  [/asp\.?net|\biis\b/i, 4, 'aspnet'],
];
const STACK_CAP = 20; // stack bumps total at most this — one signal family can't dominate

// scoreHost(ctx) — ctx: { host, ip, endpoints[], tech[], services[], subdomains[],
// debunks } — all strings/labels as recon recorded them. Never throws; a bare
// live host scores the base 30 (in-scope and alive is always worth SOMETHING).
export function scoreHost(ctx = {}) {
  const host = String(ctx.host || ctx.ip || '');
  const endpoints = (Array.isArray(ctx.endpoints) ? ctx.endpoints : []).map(String);
  const tech = (Array.isArray(ctx.tech) ? ctx.tech : []).map(String);
  const services = (Array.isArray(ctx.services) ? ctx.services : []).map(String);
  const names = [host, ...(Array.isArray(ctx.subdomains) ? ctx.subdomains : []).map(String)].filter(Boolean);
  const debunks = Number.isFinite(Number(ctx.debunks)) ? Number(ctx.debunks) : 0;
  let score = 30;
  const reasons = [];
  const classes = [];
  const bump = (signal, points, detail, cls) => {
    if (reasons.length >= TARGETSCORE_CAPS.maxReasons) return;
    score += points;
    reasons.push(`${signal} ${points >= 0 ? '+' : ''}${points} — ${detail}`);
    if (cls && classes.length < TARGETSCORE_CAPS.maxClasses && !classes.includes(cls)) classes.push(cls);
  };

  // 1. hostname keywords — observable before a single packet (pre-pass uses just these).
  const softName = names.find((n) => SOFT_HOST_RE.test(n));
  if (softName) bump('hostname:soft-env', 18, `hostname "${softName}" carries a non-prod keyword (admin|staging|dev|internal|test|sandbox) — weaker auth / self-signup / debug defaults are the norm there`, 'soft-env');
  const apiName = names.find((n) => API_HOST_RE.test(n));
  if (apiName) bump('hostname:api-role', 10, `hostname "${apiName}" declares an API/gateway role — programmatic surface, not marketing pages`);

  // 2. login/auth surface — the entry point of the highest-paying class (access control).
  const authEps = endpoints.filter((e) => AUTH_EP_RE.test(e));
  if (authEps.length) bump('auth-surface', 12, `login/auth surface observed: ${authEps.slice(0, 3).join(', ')}${authEps.length > 3 ? ` (+${authEps.length - 3} more)` : ''} — an authenticated app behind it means object-level authorization to test`);

  // 3. API surface density — endpoints per host, as harvested.
  const n = endpoints.length;
  if (n >= 12) bump('api-density', 16, `${n} endpoints harvested on the host — dense programmatic surface`, 'api-heavy');
  else if (n >= 6) bump('api-density', 12, `${n} endpoints harvested on the host`, 'api-heavy');
  else if (n >= 3) bump('api-density', 8, `${n} endpoints harvested on the host`);
  else if (n >= 1) bump('api-density', 3, `${n} endpoint(s) harvested on the host`);

  // 4. parameterized endpoints — id-bearing paths + query params are IDOR/BOLA fodder.
  const paramEps = endpoints.filter((e) => PARAM_EP_RE.test(e));
  if (paramEps.length) {
    bump('parameterized', Math.min(15, 5 * paramEps.length), `${paramEps.length} parameterized endpoint(s) (?param= or {id} template): ${paramEps.slice(0, 3).join(', ')}`, paramEps.length && authEps.length ? 'idor-candidate' : null);
    if (paramEps.length && authEps.length) bump('idor-shape', 6, `parameterized object endpoints AND a login surface — the exact two-account differential shape (idor-candidate)`);
  }

  // 5. WAF/edge — a fingerprinted CDN/WAF in front of THIN surface scores DOWN:
  //    generic probing dies at the edge; there is nothing behind it to authorize.
  const edgeTech = tech.filter((t) => CDN_EDGE_RE.test(t));
  if (edgeTech.length) {
    bump('edge-walled', -20, `edge vendor fingerprinted: ${edgeTech.slice(0, 3).join(', ')} — hardened perimeter; generic probing is burned budget here`, 'edge-walled');
    if (n <= 2) bump('edge-static', -10, `only ${n} endpoint(s) visible behind the edge — static content, nothing to authorize or inject`);
  } else if (services.some((s) => /^https?:/i.test(s))) {
    // 6. non-CDN origin — a live web service with NO edge fingerprint answers from the origin.
    bump('non-cdn-origin', 8, `live web service with no CDN/WAF vendor fingerprinted — responses come from the origin, probes reach the application`);
  }
  const tlsHint = tech.find((t) => /^TLS:/i.test(t) && SOFT_HOST_RE.test(t));
  if (tlsHint) bump('tls-origin-hint', 4, `TLS subject "${tlsHint.replace(/^TLS:/i, '')}" names a non-prod/origin identity — the certificate leaks the backend's real name`);

  // 7. known-buggy stacks — capped as a family.
  let stackPts = 0;
  for (const [re, pts, name] of KNOWN_BUGGY) {
    if (stackPts >= STACK_CAP) break;
    const hit = tech.find((t) => re.test(t));
    if (hit) { bump(`stack:${name}`, pts, `stack "${hit}" — a historically bug-dense stack scores UP`); stackPts += pts; }
  }

  // 8. SPA — the attack surface lives in client JS (jsminer fodder), not the HTML shell.
  const spa = tech.find((t) => SPA_RE.test(t));
  if (spa) bump('spa', 4, `SPA framework "${spa}" — client-rendered app; the real routes/keys live in the JS bundles`, 'spa');

  // 9. response behavioral diversity — a host whose soft-404 SPA fallback was
  //    actually SAMPLED (debunk ledger entries exist) is behaviorally mapped.
  if (debunks > 0) bump('behavior:soft-404', 3, `soft-404 SPA-fallback behavior observed (${debunks} debunked catch-all response(s)) — response behavior was sampled, not assumed`);

  // 10. GraphQL / AI / WebSocket hints — the fast-growing paid classes.
  const gql = endpoints.find((e) => GRAPHQL_RE.test(e)) || tech.find((t) => GRAPHQL_RE.test(t));
  if (gql) bump('graphql', 8, `GraphQL surface observed: "${gql}" — one schema drives BOLA tests across every query/mutation`, 'api-heavy');
  const aiEp = endpoints.find((e) => AI_EP_RE.test(e));
  const aiTech = tech.find((t) => AI_TECH_RE.test(t));
  if (aiEp || aiTech) bump('ai-surface', 12, `AI/LLM surface hint: ${aiEp ? `endpoint "${aiEp}"` : ''}${aiEp && aiTech ? ' + ' : ''}${aiTech ? `stack "${aiTech}"` : ''} — the fastest-growing paid class (H1: AI-in-scope +210% YoY, prompt injection +540%)`, 'ai-surface');
  const ws = endpoints.find((e) => WS_RE.test(e)) || tech.find((t) => WS_RE.test(t)) || services.find((s) => WS_RE.test(s));
  if (ws) bump('websocket', 4, `WebSocket/realtime hint: "${ws}" — a second, less-audited message channel beside HTTP`);

  score = Math.max(0, Math.min(100, Math.round(score)));
  return { host, score, reasons, classes };
}

// scoreSurface(surface) — group the graph's endpoint/tech/service/subdomain nodes
// per host and score each. Accepts a live Surface (nodes Map) or its toJSON()
// (nodes array). Returns { hosts (score-desc), ordered, scores } — deterministic.
export function scoreSurface(surface) {
  const nodes = surface && surface.nodes instanceof Map
    ? [...surface.nodes.values()]
    : (surface && Array.isArray(surface.nodes) ? surface.nodes : []);
  const edges = (surface && Array.isArray(surface.edges)) ? surface.edges : [];
  const debunked = (surface && Array.isArray(surface.debunked)) ? surface.debunked : [];
  const byId = new Map(nodes.map((n) => [n && n.id, n]));
  const childrenOf = (hid, kind) => edges.filter((e) => e && e.kind === kind && e.from === hid).map((e) => byId.get(e.to)).filter(Boolean);
  const out = [];
  for (const h of nodes.filter((x) => x && x.type === 'host').slice(0, TARGETSCORE_CAPS.maxHosts)) {
    const subdomains = nodes
      .filter((x) => x && x.type === 'subdomain' && edges.some((e) => e && e.kind === 'resolves' && e.from === x.id && e.to === h.id))
      .map((x) => x.label);
    const s = scoreHost({
      host: h.label || h.ip, ip: h.ip,
      endpoints: childrenOf(h.id, 'exposes').map((x) => x.label),
      tech: childrenOf(h.id, 'runs').map((x) => x.label),
      services: nodes.filter((x) => x && x.type === 'service' && x.host === h.id).map((x) => x.label),
      subdomains,
      debunks: debunked.filter((d) => d && (d.host === h.label || d.host === h.ip)).length,
    });
    out.push({ ...s, hid: h.id, keys: [h.label, h.ip].filter((k) => k != null && k !== '').map((k) => String(k).toLowerCase()) });
  }
  out.sort((a, b) => b.score - a.score || String(a.host).localeCompare(String(b.host))); // deterministic tiebreak
  const scores = {};
  for (const s of out) for (const k of s.keys) scores[k] = s.score;
  return { hosts: out.map(({ keys, ...rest }) => rest), ordered: out.map((s) => s.host), scores };
}

// preScoreTargets(targets, priorSurface) — the PRE-SWEEP ordering pass: score from
// what is known before recon runs (hostname keywords, plus a fresh inherited
// surface's detail when carryForward seeded one). Returns score-descending rows
// { target, score, reasons, classes }; the campaign sweeps in THIS order.
export function preScoreTargets(targets, priorSurface) {
  const prior = priorSurface && Array.isArray(priorSurface.nodes) ? scoreSurface(priorSurface) : null;
  const rows = (Array.isArray(targets) ? targets : []).map((t) => {
    const target = String(t);
    const base = scoreHost({ host: target });
    // A fresh prior surface knows this host's real stack/endpoints — its score is
    // richer than hostname-only and every reason in it cites observed data.
    const k = target.toLowerCase();
    const ph = prior && prior.hosts.find((h) => String(h.host || '').toLowerCase() === k);
    if (ph && ph.score > base.score) return { target, score: ph.score, reasons: ph.reasons.map((r) => 'inherited: ' + r), classes: ph.classes };
    return { target, score: base.score, reasons: base.reasons, classes: base.classes };
  });
  rows.sort((a, b) => b.score - a.score || a.target.localeCompare(b.target));
  return rows;
}
