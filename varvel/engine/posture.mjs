// VARVEL — posture scorecard: how hard is this target, measured against real sites.
//
// Jack's ask: "give me a benchmark so I know how good Axiom is security-wise" — and a
// way to test new tools against a known-hard reference ON THE FLY. This scores any
// target's defensive posture 0–100 from the signals target-profile already measures
// (headers / WAF persona / rate-limit disclosure), then renders it SIDE-BY-SIDE with
// real-world references measured live on 2026-07-30 (stripe.com, github.com,
// cloudflare.com) and with our own practice targets. No vibes: every point lists the
// signal it came from, and the benchmark values are recorded observations with a date.
//
// Uses: grade a practice target honestly ("is Axiom really Stripe-class?"), benchmark a
// new native tool against references of known hardness, and track posture regressions
// when we harden a target.

import { fingerprintDefenses } from './target-profile.mjs';

// Signals, weighted to 100. Each: id, points, and how the fingerprint proves it.
export const SIGNALS = [
  { id: 'csp',        points: 15, has: (fp) => fp.securityHeaders.includes('csp'), label: 'Content-Security-Policy' },
  { id: 'hsts',       points: 10, has: (fp) => fp.securityHeaders.includes('hsts'), label: 'HSTS' },
  { id: 'xfo',        points: 8,  has: (fp) => fp.securityHeaders.includes('xfo'), label: 'Clickjacking protection (XFO/frame-ancestors)' },
  { id: 'xcto',       points: 5,  has: (fp) => fp.securityHeaders.includes('xcto'), label: 'X-Content-Type-Options' },
  { id: 'waf',        points: 25, has: (fp) => (fp.defenses || []).some((d) => /waf/.test(d.kind)), label: 'WAF persona (vendor fingerprint)' },
  { id: 'cdn',        points: 5,  has: (fp) => (fp.defenses || []).some((d) => /cdn/.test(d.kind)), label: 'Edge/CDN fronting' },
  { id: 'ratelimit',  points: 20, has: (fp) => !!fp.rateLimit, label: 'Rate limiting (disclosed or observed 429)' },
  { id: 'challenge',  points: 12, has: (fp) => !!fp.challenge, label: 'Bot challenge / mitigation page' },
];

// Score a fingerprint ({ defenses, rateLimit, challenge, securityHeaders }) →
// { score, grade, breakdown }. Grade bands are honest: Axiom-class ≈ 70+.
export function scorePosture(fp) {
  const breakdown = SIGNALS.map((s) => ({ signal: s.id, label: s.label, points: s.points, got: s.has(fp) }));
  const score = breakdown.reduce((a, b) => a + (b.got ? b.points : 0), 0);
  const grade = score >= 80 ? 'A (enterprise edge)' : score >= 60 ? 'B (hardened)' : score >= 40 ? 'C (defended)' : score >= 20 ? 'D (basic)' : 'F (exposed)';
  return { score, grade, breakdown };
}

// Reference postures MEASURED LIVE on 2026-07-30 (headers pulled from the real sites).
// Honest snapshots — real sites evolve; re-measure before quoting these elsewhere.
export const BENCHMARKS = {
  'stripe.com': {
    class: 'fintech enterprise edge', measured: '2026-07-30',
    fingerprint: {
      defenses: [],
      rateLimit: { throttled: false, note: 'documented API limits' },
      challenge: null,
      securityHeaders: ['csp', 'hsts', 'xfo', 'xcto'],
    },
    notes: 'CSP strong, HSTS 2yr+preload, XFO SAMEORIGIN (weaker than DENY), legacy referrer-policy. Rate limits documented rather than header-disclosed on the marketing site.',
  },
  'github.com': {
    class: 'developer platform edge', measured: '2026-07-30',
    fingerprint: {
      defenses: [],
      rateLimit: { throttled: false, note: 'documented API limits' },
      challenge: null,
      securityHeaders: ['csp', 'hsts', 'xfo', 'xcto'],
    },
    notes: "Strictest CSP of the set (default-src 'none'), XFO DENY, 1yr HSTS+preload.",
  },
  'cloudflare.com': {
    class: 'edge vendor (WAF persona model)', measured: '2026-07-30',
    fingerprint: {
      defenses: [{ id: 'cloudflare', vendor: 'Cloudflare', kind: 'waf-cdn', monitoring: 'high', signals: ['header:server', 'header:cf-ray'] }],
      rateLimit: { throttled: false, note: 'Cloudflare rate limiting available' },
      challenge: null,
      securityHeaders: ['csp', 'hsts', 'xfo', 'xcto'],
    },
    notes: 'The behavior model for Axiom Shield (cf-ray ≈ x-axiom-shield-ref).',
  },
  'axiom (practice target)': {
    class: 'hardened practice target', measured: '2026-07-30',
    fingerprint: {
      defenses: [{ id: 'axiom-shield', vendor: 'Axiom Shield (custom edge WAF)', kind: 'waf', monitoring: 'high', signals: ['header:x-axiom-shield'] }],
      rateLimit: { limit: 120, throttled: false, note: '120/min global + 6/min login, 429+Retry-After' },
      challenge: null,
      securityHeaders: ['csp', 'hsts', 'xfo', 'xcto'],
    },
    notes: 'Our hardened practice target — Stripe-class headers + active Shield. Depth is one ruleset, not a security org.',
  },
};

// Grade one fingerprint against one or all benchmarks.
export function comparePosture(fp, benchmark = null) {
  const mine = scorePosture(fp);
  const refs = benchmark && BENCHMARKS[benchmark] ? { [benchmark]: BENCHMARKS[benchmark] } : BENCHMARKS;
  const against = Object.entries(refs).map(([name, b]) => {
    const s = scorePosture(b.fingerprint);
    return { name, class: b.class, measured: b.measured, score: s.score, grade: s.grade, delta: mine.score - s.score, notes: b.notes };
  }).sort((a, b) => b.score - a.score);
  return { mine, against };
}

// One-shot: fingerprint a live base (response fields injected by the caller for
// hermetic tests) and grade it against the benchmarks.
export function postureReport({ status, headers, body } = {}, benchmark = null) {
  const fp = fingerprintDefenses({ status, headers, body });
  return { fingerprint: fp, ...comparePosture(fp, benchmark) };
}
