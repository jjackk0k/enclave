// VARVEL — shapegrade: the ORACLE-GRADED SELF-MEASUREMENT loop for the shaping pack.
//
// Why it exists: applying a malleable profile is a CLAIM ("this wire now looks like a
// CDN asset fetch"). A claim you never measure is worse than no disguise — it breeds
// operator confidence on faith. This module closes the loop: it takes the profile the
// channel APPLIED and grades it against what the platform's own oracles OBSERVED —
//   · JA4H: the fporacle passive ring (tools/fporacle createHttpObserver) vs the
//     profile's expectedJa4h (engine/malleable — the exact wire header order builder).
//   · cadence: beaconscore over the channel's observed check-in ring (the measured
//     flow) vs the profile cadence's own pre-flight score (scoreProfileShape — what
//     the cadence model says it WILL look like).
//   · burst pattern: histogram concentration / tightness, claimed vs measured.
//
// THE HONESTY CONTRACT (same doctrine as engine/beaconscore, tools/detoracle): this
// REPORTS claimed-vs-measured. It NEVER asserts undetectability, and a 'match' is only
// ever "the wire measured as the profile claimed on these features" — a string
// comparison and a feature comparison, not a vendor verdict. Divergence is the LOUD
// case: a disguise that does not measure as claimed is reported in `divergent`, never
// smoothed over. Insufficient evidence is 'insufficient-data', never guessed.
//
// Pure logic, no I/O: observations/flow/preFlight are passed in (the tools/ shell or
// the channel gathers them). `now` injectable.

import { shapeProfile, expectedJa4h, SHAPE_PROFILES } from './malleable.mjs';
import { ja4h } from './fingerprint.mjs';
import { scoreProfileShape } from './beaconscore.mjs';

// Grade one applied shape against observed evidence.
//   shape:      name or object — what the channel applied (required)
//   observations: fporacle ring entries [{ route, ja4h, agent?, at }] (may be [])
//   flow:       a scoreFlow() result over the agent's observed check-in ring (or null)
//   preFlight:  optional injected scoreProfileShape result (tests inject determinism)
// Returns the graded report. Never throws; unknown shape names grade as an error object.
export function gradeShape({ shape, observations = [], flow = null, preFlight = null, rand } = {}) {
  const s = shapeProfile(shape);
  if (!s) return { ok: false, error: "unknown shape profile '" + String(shape) + "' -- known: " + Object.keys(SHAPE_PROFILES).join(', ') };

  const NOTE = 'claimed-vs-measured grading over the platform\'s own oracles (fporacle JA4H ring + beaconscore flow features).'
    + ' A match means the wire measured as the profile CLAIMED on these features -- it is never a claim of undetectability;'
    + ' vendor detector weights are secret. TLS-layer JA4 is outside this stack\'s control (no native TLS): the http layer is all this grades.';

  // 'plain' makes no claim by definition — report the measured shape raw, grade nothing.
  if (!s.http || !s.cadence) {
    return {
      ok: true, profile: s.name || 'plain', label: s.label, verdict: 'no-claim',
      claimed: null,
      measured: measureJa4h(observations, null),
      flow: flow || null,
      checks: [], divergent: [],
      note: "'plain' is today's unshaped wire: there is no template to grade against, so the measured facts are reported raw. " + NOTE,
    };
  }

  // --- claimed ---
  const claimJa4hPull = expectedJa4h(s, { method: 'GET', ja4hFn: ja4h });
  const claimJa4hPush = expectedJa4h(s, { method: 'POST', ja4hFn: ja4h });
  const claimFlight = preFlight || scoreProfileShape(
    { label: s.label, intervalMs: s.cadence.intervalMs, jitterMs: s.cadence.jitterMs || 0, jitterPct: s.cadence.jitterPct || 0, burst: s.cadence.burst },
    { rand },
  );

  // --- measured JA4H: ring entries on THIS shape's routes (attribution note below) ---
  const routes = new Set([...s.http.pullPaths, ...s.http.pushPaths]);
  const measured = measureJa4h(observations, routes);

  const checks = [];
  const divergent = [];

  // check 1: pull JA4H exact match (the fingerprint is over header NAMES/order/count —
  // an exact string match is the honest bar; anything less is a divergence to explain)
  if (measured.samples === 0) {
    checks.push({ dim: 'ja4h-pull', claimed: claimJa4hPull, measured: null, verdict: 'no-evidence', detail: 'the fporacle ring holds no requests on this shape\'s routes yet' });
  } else {
    const m = measured.dominant;
    if (m === claimJa4hPull) {
      checks.push({ dim: 'ja4h-pull', claimed: claimJa4hPull, measured: m, verdict: 'match', detail: 'measured JA4H equals the claimed fingerprint on ' + measured.perJa4h[m] + ' observed request(s)' });
    } else {
      const d = 'JA4H DIVERGENCE: claimed ' + claimJa4hPull + ' but the wire measured ' + m + ' (' + measured.perJa4h[m] + ' samples, ' + measured.distinct + ' distinct) -- the disguise does not measure as claimed';
      checks.push({ dim: 'ja4h-pull', claimed: claimJa4hPull, measured: m, verdict: 'divergent', detail: d });
      divergent.push(d);
    }
    if (measured.distinct > 1) {
      const d = 'JA4H INSTABILITY: ' + measured.distinct + ' distinct fingerprints observed on the shape\'s routes -- a stable disguise produces exactly one';
      checks.push({ dim: 'ja4h-stability', claimed: '1 distinct', measured: String(measured.distinct), verdict: 'divergent', detail: d });
      divergent.push(d);
    }
  }

  // check 2: cadence band, claimed (pre-flight score of the cadence model) vs measured
  // (the live flow ring). Band-level comparison: exact numbers move sample to sample,
  // a BAND flip is the honest signal.
  if (!flow || flow.band === 'insufficient-data') {
    checks.push({ dim: 'cadence', claimed: claimFlight.band, measured: flow ? 'insufficient-data' : null, verdict: 'no-evidence', detail: 'fewer than 12 observed check-ins -- no honest cadence grade yet (fail-closed)' });
  } else {
    const sameBand = flow.band === claimFlight.band;
    const d = sameBand
      ? 'measured cadence band ' + flow.band + ' (score ' + flow.score + ') matches the cadence model\'s pre-flight ' + claimFlight.band + ' (score ' + claimFlight.score + ')'
      : 'CADENCE DIVERGENCE: the cadence model pre-flighted ' + claimFlight.band + ' (score ' + claimFlight.score + ') but the live wire measures ' + flow.band + ' (score ' + flow.score + ') -- trust the measured number';
    checks.push({ dim: 'cadence', claimed: { band: claimFlight.band, score: claimFlight.score }, measured: { band: flow.band, score: flow.score, features: flow.features }, verdict: sameBand ? 'match' : 'divergent', detail: d });
    if (!sameBand) divergent.push(d);
  }

  const verdict = divergent.length ? 'divergent'
    : checks.some((c) => c.verdict === 'match') ? 'measures-as-claimed'
    : 'insufficient-data';
  return {
    ok: true,
    profile: s.name, label: s.label,
    claimed: { ja4hPull: claimJa4hPull, ja4hPush: claimJa4hPush, ja4hClass: s.expect && s.expect.ja4h, h2: (s.expect && s.expect.h2) || null, cadence: { intervalMs: s.cadence.intervalMs, jitterPct: s.cadence.jitterPct || 0, burst: s.cadence.burst }, batch: s.batch, padding: s.padding },
    measured,
    preFlight: { band: claimFlight.band, score: claimFlight.score },
    flow: flow || null,
    checks, divergent, verdict,
    note: NOTE,
  };
}

// Ring reduction: which JA4H values were observed on the shape's routes, how often, and
// the dominant one. routes=null means "no route filter" (the plain case: everything).
// ATTRIBUTION (honest limit): the fporacle ring is channel-wide; entries carry the
// agent header when the client sent one, but the filter here is ROUTE-based — on a
// channel shared by agents with different shapes, samples can mix. The report carries
// per-route counts so the operator can see the attribution basis.
function measureJa4h(observations, routes) {
  const ring = (Array.isArray(observations) ? observations : []).filter((o) => o && typeof o.ja4h === 'string');
  const mine = routes ? ring.filter((o) => routes.has(o.route)) : ring;
  const perJa4h = {};
  for (const o of mine) perJa4h[o.ja4h] = (perJa4h[o.ja4h] || 0) + 1;
  let dominant = null, best = 0;
  for (const [fp, n] of Object.entries(perJa4h)) if (n > best) { best = n; dominant = fp; }
  return {
    samples: mine.length,
    distinct: Object.keys(perJa4h).length,
    dominant,
    perJa4h,
    routes: routes ? [...routes] : null,
    ringTotal: ring.length,
  };
}
