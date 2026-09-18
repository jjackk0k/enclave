// VARVEL — footprint reducer / OPSEC advisor.
//
// Watches an engagement's detection footprint (footprint.mjs via opsec.mjs) and turns it
// into a concrete, prioritized plan to LOWER the detection-risk number: for each loud
// activity it names the quieter *legitimate* alternative already recorded in that
// activity's footprint profile (rate-limit, narrow scope, prefer passive sources, spread
// over time), and projects what the risk would drop to if those moves were applied.
//
// BOUNDARY — read before extending. This is tradecraft TRANSPARENCY for authorized
// testing. Its only goal is to reduce NEEDLESS noise on the client's systems — professional
// courtesy so a scoped test doesn't pointlessly flood the client's SIEM. It does NOT, and
// must not, implement or recommend evasion / anti-forensics / detection-bypass: every
// "quieter" move here is a legitimate scoping choice already vetted in footprint.mjs, the
// estimated reduction is always a fraction well below 1 (authorized activity stays visible,
// never made invisible), and on a signed engagement everything remains logged and
// attributable in the Enclave's tamper-evident audit ledger. It adds NO new techniques —
// it only re-reads the existing deterministic footprint model.
//
// Pure functions, no I/O, no runtime deps. Never throws: bad/empty input returns a safe
// "nothing to reduce" result.

// Same risk thresholds footprint.mjs uses, applied to a 0–5 loudness score.
const RISK = (n) =>
  n >= 4.5 ? 'critical' : n >= 3.5 ? 'high' : n >= 2.5 ? 'elevated' : n >= 1.5 ? 'moderate' : 'low';

const round1 = (n) => Math.round(n * 10) / 10;

// A "loud" activity is one a log reviewer would notice (loudness >= 3, per footprint.mjs's
// own loudness scale). Below that an activity already sits in the traffic noise floor.
const LOUD = 3;

// Rough fraction of THIS activity's noise the quieter, in-scope approach saves. Higher for
// louder activities — they carry the most needless-noise headroom to trim by rate-limiting,
// narrowing scope to what the objective needs, or preferring passive sources. Deliberately
// bounded well below 1: the quieter path reduces needless noise, it never claims to make
// authorized activity invisible (that would be evasion — out of scope for this module).
function estReductionFor(loudness) {
  if (loudness >= 5) return 0.5;
  if (loudness >= 4) return 0.4;
  if (loudness >= LOUD) return 0.3;
  return 0; // quiet activities are already as low as they get
}

// Re-score a set of { loudness, count } items with footprint.mjs's exact weighting:
// the peak loudness leads (0.55) and the count-weighted mean modulates it (0.45), capped
// at 5 and rounded to one decimal — identical to scoreFootprint so the numbers line up.
function weightedScore(items) {
  const list = (Array.isArray(items) ? items : []).filter((e) => e && e.count > 0);
  if (!list.length) return 0;
  const total = list.reduce((s, e) => s + e.count, 0);
  const mean = list.reduce((s, e) => s + e.loudness * e.count, 0) / total;
  const peak = Math.max(...list.map((e) => e.loudness));
  return round1(Math.min(5, peak * 0.55 + mean * 0.45));
}

// Accept either a full opsec.toJSON(), a posture() object, or a raw scoreFootprint() result,
// and pull out the scored detection picture. Returns null when there's nothing scorable.
function resolveDetection(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  if (input.posture && input.posture.detection) return input.posture.detection; // opsec.toJSON()
  if (input.detection) return input.detection; //                                  posture()
  if ('loudest' in input || 'weighted' in input || 'risk' in input) return input; // scoreFootprint()
  return null;
}

// Suggested target detection level for context. A quiet, professional engagement aims for
// the noise floor; from a loud posture, 'moderate' is the realistic first target, then 'low'.
export function targetLevel(risk) {
  const r = String(risk || '').toLowerCase();
  return r === 'critical' || r === 'high' ? 'moderate' : 'low';
}

function noneResult(target) {
  return {
    target: target || null,
    currentRisk: 'none',
    currentScore: 0,
    projectedRisk: 'none',
    projectedScore: 0,
    reducible: 0,
    targetLevel: targetLevel('none'),
    plan: [],
    summary: 'No noisy activity yet.',
  };
}

// Given opsec.toJSON() (or its .posture.detection), produce a footprint-reduction plan.
export function footprintAdvisor(opsecJSON, { target } = {}) {
  try {
    const det = resolveDetection(opsecJSON);
    const loudest = det && Array.isArray(det.loudest) ? det.loudest : [];
    if (!det || !loudest.length || !det.events) return noneResult(target);

    // Full activity set (loudest[] already carries every distinct activity + its count).
    const base = loudest.map((a) => ({
      loudness: Number(a.loudness) || 0,
      count: Math.max(1, Number(a.count) || 1),
    }));
    const currentScore = typeof det.weighted === 'number' ? det.weighted : weightedScore(base);
    const currentRisk = det.risk || RISK(currentScore);

    // One plan item per loud activity, loudest first (loudest[] is already so ordered):
    // why it's loud (its first defender-visible signal) + the quieter in-scope alternative
    // straight from the footprint profile + a rough fraction of its noise that saves.
    const plan = loudest
      .filter((a) => (Number(a.loudness) || 0) >= LOUD)
      .map((a) => {
        const loudness = Number(a.loudness) || 0;
        const estReduction = estReductionFor(loudness);
        return {
          id: a.id,
          activity: a.label || a.id,
          category: a.category || null,
          loudness,
          currentCount: Math.max(1, Number(a.count) || 1),
          issue: (Array.isArray(a.signals) && a.signals[0]) || 'Leaves an observable trace in the client’s logs.',
          quieter: a.quieter || 'Rate-limit, narrow scope to what the objective needs, and prefer passive sources.',
          estReduction,
          estReductionPct: Math.round(estReduction * 100),
        };
      });

    // Project the score as if every loud activity had its needless-noise fraction trimmed.
    // Reductions only ever lower loudness, so projectedScore <= currentScore, always.
    const projected = base.map((e) => ({
      loudness: e.loudness >= LOUD ? e.loudness * (1 - estReductionFor(e.loudness)) : e.loudness,
      count: e.count,
    }));
    const projectedScore = weightedScore(projected);
    const projectedRisk = RISK(projectedScore);
    const reducible = round1(currentScore - projectedScore);

    const summary = plan.length
      ? `Detection risk is ${String(currentRisk).toUpperCase()}. ` +
        `${plan.length} lower-noise adjustment(s)${plan[0] ? ` — starting with ${plan[0].activity}` : ''} ` +
        `project it down to ${String(projectedRisk).toUpperCase()} (−${reducible.toFixed(1)}/5 loudness) by ` +
        `rate-limiting, narrowing scope, and preferring passive sources — all in-scope, all still logged.`
      : `Detection footprint is already ${String(currentRisk).toUpperCase()} — no loud activity to reduce.`;

    return {
      target: target || null,
      currentRisk,
      currentScore,
      projectedRisk: plan.length ? projectedRisk : currentRisk,
      projectedScore: plan.length ? projectedScore : currentScore,
      reducible: plan.length ? reducible : 0,
      targetLevel: targetLevel(currentRisk),
      plan,
      summary,
    };
  } catch {
    return noneResult(target);
  }
}

// Compact operator-facing text block: current risk, the top 3 reduction moves (loudest
// first) with their quieter alternative + estimated saving, and the projected risk if
// applied. Returns '' when there is nothing to reduce.
export function reductionBriefing(advice) {
  if (!advice || !Array.isArray(advice.plan) || !advice.plan.length) return '';
  const L = [];
  const tgt = advice.target ? ` · ${advice.target}` : '';
  L.push(
    `OPSEC footprint reducer${tgt} — current detection risk: ${String(advice.currentRisk).toUpperCase()} ` +
      `(${advice.currentScore}/5), target for a quiet engagement: ${advice.targetLevel || targetLevel(advice.currentRisk)}.`,
  );
  L.push('Top lower-noise moves (loudest first) — trim needless noise on the client; all in-scope, all logged:');
  advice.plan.slice(0, 3).forEach((p, i) => {
    L.push(`  ${i + 1}. [${p.loudness}/5] ${p.activity}${p.currentCount > 1 ? ` ×${p.currentCount}` : ''} — ~${p.estReductionPct}% quieter`);
    L.push(`     loud because: ${p.issue}`);
    L.push(`     quieter, in-scope: ${p.quieter}`);
  });
  L.push(
    `Projected if applied: ${String(advice.projectedRisk).toUpperCase()} (${advice.projectedScore}/5) — ` +
      `down ${advice.reducible}/5. Every action stays logged and attributable in the audit ledger.`,
  );
  return L.join('\n');
}
