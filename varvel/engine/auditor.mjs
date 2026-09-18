// VARVEL — productivity / honesty auditor.
//
// The autonomy differentiator: after every discovery phase, cross-check what the
// agent CLAIMED against the REAL attack-surface delta. An agent that says "found an
// admin panel / recovered creds / enumerated hosts" but changed nothing is flagged
// as dishonest-or-stalled and its progress is downgraded — the trait RedAmon is
// proud of, done here as deterministic, governed verification (no trust required).
//
// Pure functions, fully unit-tested. Orchestration only.

const COUNTED = ['hosts', 'subdomains', 'svcs', 'endpoints', 'tech', 'cves', 'findings', 'exploits', 'creds', 'footholds', 'routes'];
const CLAIM_RE = /\b(found|discover(?:ed)?|identif(?:ied|y)|confirm(?:ed)?|prov(?:ed|e)|exploit(?:ed)?|obtain(?:ed)?|recover(?:ed)?|enumerat(?:ed|e)|compromis(?:ed|e)|escalat(?:ed|e)|pivot(?:ed)?)\b/i;

// Compare two surface.counts() snapshots + the agent's claim text.
export function assessProgress(before = {}, after = {}, claimText = '') {
  const delta = {};
  let realDelta = 0;
  for (const k of COUNTED) {
    const d = (after[k] || 0) - (before[k] || 0);
    if (d) delta[k] = d;
    if (d > 0) realDelta += d;
  }
  const claimedProgress = CLAIM_RE.test(String(claimText || ''));
  // Claiming progress with zero real surface growth = dishonest/hallucinated.
  const honest = !claimedProgress || realDelta > 0;
  const verdict = realDelta > 0 ? 'productive' : (claimedProgress ? 'dishonest-or-stalled' : 'no-progress');
  return { realDelta, delta, claimedProgress, honest, verdict };
}

// A re-plan hint appended to a retried phase objective when it produced no progress.
// `tier` escalates: tier 1 = change approach; tier ≥2 = Deep-Think — force competing
// hypotheses before acting (VARVEL's answer to RedAmon's Deep Think / hypothesis step).
export function replanHint(phase, denials = 0, tier = 1) {
  const why = denials > 0 ? ` and ${denials} action(s) were held by the platform` : '';
  if (tier >= 2) {
    return `\n[re-plan · deep-think] The previous ${phase} attempt still produced NO new results${why}. Stop repeating the failing approach. First emit at least TWO competing hypotheses for why nothing surfaced (wrong target set? wrong technique? the path is gated? there is genuinely nothing here?), then pursue only the single strongest one with a concretely different action. If the honest answer is "nothing more here", say so plainly — never fabricate findings.`;
  }
  return `\n[re-plan] The previous ${phase} attempt produced NO new results${why}. Change approach: try a different technique/target within scope; do not repeat what already failed. If there is genuinely nothing, say so plainly — do not fabricate findings.`;
}

// Roll a list of per-phase assessments into a campaign-level productivity summary.
// `stuckStreak` is the longest run of consecutive non-growth phases — a DETERMINISTIC,
// LLM-independent "stuck" signal (RedAmon's most reliable one), computed from the real
// surface delta, not the agent's self-report.
export function productivity(assessments = []) {
  const s = { phases: assessments.length, productive: 0, noProgress: 0, dishonest: 0, totalDelta: 0 };
  let run = 0, maxRun = 0;
  for (const a of assessments) {
    s.totalDelta += a.realDelta || 0;
    if (a.verdict === 'productive') { s.productive++; run = 0; }
    else { if (a.verdict === 'dishonest-or-stalled') s.dishonest++; else s.noProgress++; run += 1; if (run > maxRun) maxRun = run; }
  }
  s.stuckStreak = maxRun;
  s.honestyRate = assessments.length ? Number(((assessments.length - s.dishonest) / assessments.length).toFixed(3)) : 1;
  // 5-tier productivity ladder (green→critical), rolled up from the deterministic
  // stuck streak + unproductive + dishonest signals. Additive only: every field
  // above is preserved, so consumers that ignore `tier` are unaffected.
  s.tier = productivityTier({ stuck: s.stuckStreak, unproductiveRecent: s.noProgress, dishonest: s.dishonest }).tier;
  return s;
}

// ── 5-tier productivity ladder ───────────────────────────────────────────────
// RedAmon escalates a single "stuck" counter; VARVEL grades the campaign on a
// deterministic green→critical ladder computed from independent signals — the
// real stuck streak, recent unproductive phases, tool-axis repetition, and
// dishonest claims — and pairs each rung with a concrete GOVERNING action. The
// top rung authorises the platform to REJECT the next expensive repeat rather
// than merely nag. Higher tiers always claim the boundary (score 4 = orange,
// 7 = red, 9 = critical), so escalation is monotonic and never ambiguous.
export function productivityTier({ stuck = 0, unproductiveRecent = 0, axisRepeat = 0, dishonest = 0 } = {}) {
  const n = (v) => { const x = Number(v); return Number.isFinite(x) && x > 0 ? x : 0; };
  const score = Number((n(stuck) * 2 + n(unproductiveRecent) + n(axisRepeat) * 1.5 + n(dishonest) * 2).toFixed(2));
  let tier, action;
  if (score < 3)      { tier = 'green';    action = ''; }
  else if (score < 4) { tier = 'yellow';   action = 'hint'; }                    // soft hint
  else if (score < 7) { tier = 'orange';   action = 'deep-think'; }              // force competing hypotheses
  else if (score < 9) { tier = 'red';      action = 'demand-new-hypothesis'; }   // new hypothesis class required
  else                { tier = 'critical'; action = 'reject-next-repeat'; }       // next expensive repeat is rejected
  return { tier, score, action };
}

// Coarse "axis" fingerprint of one tool-call step. The AXIS is everything held
// constant while a brute/fuzz loop spins a single dial: the tool, the target URL
// (scheme://host/path — query/fragment dropped), and the request SHAPE with every
// key=value collapsed to key=* (the value IS the dial). Two steps that differ only
// in a payload/wordlist token map to the SAME axis; a different path, host, tool,
// or param-shape maps to a DIFFERENT one. Pure and total — never throws.
function axisKey(step) {
  const s = step || {};
  const tool = String(s.name || '').trim();
  const detail = String(s.detail || '');
  const url = detail.match(/[a-z][\w+.-]*:\/\/[^\s'"]+/i);          // scheme://host/path...
  const target = url ? url[0].split(/[?#]/)[0] : '';                 // stable dimension — NOT wildcarded
  const shape = detail
    .replace(/[a-z][\w+.-]*:\/\/[^\s'"]+/ig, '')                     // pull the URL out (kept as target)
    .replace(/([\w.\-]+)=[^\s&'"]*/g, '$1=*')                        // key=value -> key=* (wildcard the dial)
    .replace(/\s+/g, ' ')
    .trim();
  return [tool, target, shape].filter(Boolean).join(' ');
}

// Detect axis lock-in: the agent hammering the SAME tool+target+shape while only
// varying one parameter (classic brute-force / fuzz / password-spray loop). If the
// most common axis key across the last `window` steps recurs >= `threshold` times,
// it's locked and the caller should push the agent to change a DIFFERENT dial.
// Conservative by design — it favours "not locked" when unsure (varied targets keep
// distinct literal keys), so the critical-tier rejection never fires on genuine
// exploration. Robust to empty / short / malformed input; never throws.
export function axisLockIn(steps, { window = 8, threshold = 3 } = {}) {
  if (!Array.isArray(steps) || steps.length === 0) return { locked: false };
  const w = Math.max(1, Number(window) || 8);
  const th = Math.max(1, Number(threshold) || 3);
  const counts = new Map();
  let top = '', topN = 0;
  for (const step of steps.slice(-w)) {
    const key = axisKey(step);
    if (!key) continue;
    const c = (counts.get(key) || 0) + 1;
    counts.set(key, c);
    if (c > topN) { topN = c; top = key; }
  }
  if (top && topN >= th) {
    return { locked: true, axis: top, count: topN, note: `Repeating ${top} — change a DIFFERENT parameter, not the same dial.` };
  }
  return { locked: false };
}
