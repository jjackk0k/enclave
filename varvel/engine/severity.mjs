// VARVEL — severity: the platform's ONE vocabulary + triage roll-up.
//
// Findings across tools historically spoke two dialects — short ('crit', 'med') and
// long ('critical', 'medium') — and the surface's unknown→'med' coercion silently
// DOWNGRADED long-form criticals (a KEV 'critical' landed in reports as MEDIUM).
// One normalizer, used everywhere a finding enters the model; the triage roll-up
// (riskLevel) is derived by rule, never stored by hand.
//
// Canonical scale (most-severe first): crit > high > med > low > info.
export const SEVS = ['crit', 'high', 'med', 'low', 'info'];

const ALIAS = {
  crit: 'crit', critical: 'crit', fatal: 'crit',
  high: 'high', severe: 'high',
  med: 'med', medium: 'med', moderate: 'med',
  low: 'low', minor: 'low', warning: 'low',
  info: 'info', informational: 'info', note: 'info', none: 'info',
};

// Any reasonable spelling -> canonical. Unknown/missing -> 'med' (the historical
// surface coercion, kept deliberately: a finding of unstated weight triages as
// medium — under-stating risk to 'info' is the failure we refuse).
export function normSev(x) {
  return ALIAS[String(x ?? '').trim().toLowerCase()] || 'med';
}

// Sort rank: most-severe first. Always 0..4 (input is normalized first).
export function sevRank(sev) {
  return SEVS.indexOf(normSev(sev));
}

// Triage roll-up for reporting: every finding carries an explicit risk level an
// exec can act on — 'high' needs action now, 'medium' needs a plan, 'info' is posture.
export function riskLevel(sev) {
  const r = sevRank(sev);
  return r <= 1 ? 'high' : r <= 3 ? 'medium' : 'info';
}

// Score-band risk roll-up for RANKED hunting findings (privemap candidates,
// reachprove rescore results) — the `riskLevel` field stamped where severity is
// computed. EXACT MAPPING:
//   score >= 50 → 'high' | 10–49.99 → 'medium' | < 10 → 'info'
// (the same numeric cut-offs the miners use for sev crit/high, med/low, info, so
// the band always agrees with riskLevel(sev)); contributor+ reach —
// contributor/author/editor/admin/admin-gated/shop-manager/server — steps the band
// DOWN one level (high→medium, medium→info, info stays): mid-level-auth findings
// triage one rung less urgent. unauth/subscriber/shortcode/unknown reach never
// adjusts (house doctrine: never penalize what cannot be proven).
const MID_PRIV_REACH = new Set(['contributor', 'author', 'editor', 'admin', 'admin-gated', 'shop-manager', 'server']);
export function riskLevelForScore(score, reach) {
  const s = Number(score);
  const band = Number.isFinite(s) && s >= 50 ? 'high' : Number.isFinite(s) && s >= 10 ? 'medium' : 'info';
  if (!MID_PRIV_REACH.has(String(reach ?? '').trim().toLowerCase())) return band;
  return band === 'high' ? 'medium' : 'info';
}
