// VARVEL - beaconscore: the flow-beacon self-test engine (gap#6).
//
// Why it exists: published 2025-2026 ML flow detectors catch periodicity and size
// regularity REGARDLESS of how the jitter was tuned, so tuning jitter blind is not a
// strategy - measuring our own flows against the published features is:
//
//   - RITA (github.com/activecm/rita) beacon scoring, per source/destination pair:
//     interval dispersion (Bowley skew + MADM around the median of the time deltas,
//     30s low-dispersion threshold in the legacy analyzer), connection count vs total
//     duration, data-size dispersion + smallness (32-byte MADM / 64KB smallness legs);
//     v4.8+ dropped the connection-count leg and added explicit DURATION scoring.
//     Score >= 0.8 reads as a strong beacon.
//   - arXiv 2506.08922 (ANSSI, "Striking Back At Cobalt"): metadata-ONLY features -
//     timings, sizes, direction, flow duration, inter-arrival-time statistics - detect
//     masquerading C2 at F1 0.78-1.0 with standard, explainable features (MDI-ranked).
//
// This module scores VARVEL's OWN flows against that published feature family and
// reports exactly which features light up. It runs on the channel's observed check-in
// ring (engine/callback) for live flows, and on synthetic nextGap() samples for
// pre-deployment cadence grading.
//
// THE HONESTY CONTRACT (non-negotiable, same doctrine as tools/detoracle.mjs): this is
// FEATURE evidence, never a vendor verdict - vendor detector weights are secret, so no
// score here can be a claim of detectability OR of undetectability. Fail-closed on thin
// evidence: fewer than 12 points is reported as 'insufficient-data', never guessed.
// Pure logic, no I/O; rand injectable so profile grading is deterministic in tests.

import { malleableProfile, nextGap } from './malleable.mjs';

const MIN_POINTS = 12;   // below this no dispersion statistic is honest (fail-closed)
const HIST_BUCKETS = 20; // gap histogram resolution for the concentration feature

const clamp01 = (x) => Math.min(1, Math.max(0, x));
const _mean = (xs) => xs.reduce((s, x) => s + x, 0) / xs.length;
function _median(xs) {
  const s = xs.slice().sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}
// Population stddev (divide by n): we describe THIS observed series, we do not infer
// a distribution parameter from a sample of it.
const _pstdev = (xs, m) => Math.sqrt(xs.reduce((s, x) => s + (x - m) * (x - m), 0) / xs.length);
const _r = (x, p = 4) => { const k = Math.pow(10, p); return Math.round(x * k) / k; };

// Score one observed flow. times: ascending ms timestamps (they are re-sorted
// defensively). sizes: optional per-event byte counts. mode: 'poll' (default) grades
// the check-in cadence; 'push' is for wires with NO poll cadence (ws) - gap regularity
// does not exist there and is never fabricated.
// Returns { mode, score, band, features, flagged, note }.
export function scoreFlow({ times, sizes = null, mode = 'poll' } = {}) {
  const push = mode === 'push';
  const ts = (Array.isArray(times) ? times : []).map(Number).filter(Number.isFinite).sort((a, b) => a - b);
  const NOTE = 'feature-level measurement against published flow-beacon detectors (RITA beacon scoring; arXiv 2506.08922)'
    + ' -- vendor detector weights are secret, so this is FEATURE evidence, never a vendor verdict;'
    + ' a low score is NOT a claim of undetectability';

  // FAIL-CLOSED: thin evidence gets no score at all.
  if (ts.length < MIN_POINTS) {
    return { mode: push ? 'push' : 'poll', score: null, band: 'insufficient-data', features: null, flagged: [], note: 'fewer than 12 points -- no honest score possible' };
  }

  // --- gap (inter-arrival) features: the primary beacon signal ---
  const gaps = [];
  for (let i = 1; i < ts.length; i++) gaps.push(ts[i] - ts[i - 1]);
  const gapMean = _mean(gaps);
  const gapMedian = _median(gaps);
  const gapStddev = _pstdev(gaps, gapMean);
  const gapCV = gapMean > 0 ? gapStddev / gapMean : 0; // all-same-timestamp: zero dispersion, honestly
  const withinTenPct = gaps.filter((g) => Math.abs(g - gapMedian) <= 0.1 * gapMedian).length / gaps.length;
  // Histogram concentration: a beacon's intervals pile into one bucket (RITA's
  // interval-histogram view of periodicity). A perfectly flat series concentrates fully.
  const gMin = Math.min(...gaps), gMax = Math.max(...gaps);
  let histConcentration = 1;
  if (gMax > gMin) {
    const counts = new Array(HIST_BUCKETS).fill(0);
    for (const g of gaps) counts[Math.min(HIST_BUCKETS - 1, Math.floor(((g - gMin) / (gMax - gMin)) * HIST_BUCKETS))]++;
    histConcentration = Math.max(...counts) / gaps.length;
  }

  // --- duration features: what push transports and patient beacons are graded on ---
  const spanMs = ts[ts.length - 1] - ts[0];
  const spanHours = spanMs / 3600000;
  const eventsPerHour = spanMs > 0 ? (ts.length - 1) / spanHours : null; // zero span: rate undefined, not infinite

  // --- size features (RITA's dsScore family): only when byte counts were observed ---
  let sizeCV = null;
  if (Array.isArray(sizes)) {
    const ss = sizes.map(Number).filter((x) => Number.isFinite(x) && x >= 0);
    if (ss.length >= 2) {
      const m = _mean(ss);
      if (m > 0) sizeCV = _pstdev(ss, m) / m; // all-zero sizes = no payload evidence, not "regular"
    }
  }

  const features = {
    gapMean: push ? null : _r(gapMean, 2),
    gapMedian: push ? null : _r(gapMedian, 2),
    gapStddev: push ? null : _r(gapStddev, 2),
    gapCV: push ? null : _r(gapCV),
    withinTenPct: push ? null : _r(withinTenPct),
    histConcentration: push ? null : _r(histConcentration),
    sizeCV: sizeCV === null ? null : _r(sizeCV),
    spanHours: _r(spanHours),
    eventsPerHour: eventsPerHour === null ? null : _r(eventsPerHour, 1),
    points: ts.length,
  };

  // --- the score: 0-100 beacon-likeness, five legs, weights documented with their basis ---
  //   reg    45  interval dispersion - RITA's tsSkew/tsMADM legs (2/3 of its connection
  //              score) and arXiv 2506.08922's top-MDI inter-arrival stats. Anchors are
  //              the published operating points: gapCV <= 0.05 is metronomic (full
  //              marks), gapCV >= 0.5 is heavy jitter (no signal).
  //   within 20  tightness around the median gap - RITA's MADM-around-the-median idea in
  //              relative form; > 0.8 of gaps within +/-10% of the median = metronomic.
  //   hist   15  histogram mode concentration - RITA's interval-histogram view of the
  //              same periodicity; 1/20 (the 20-bucket uniform baseline) = concentration 0.
  //   size   10  payload regularity - RITA's dsScore legs (skew/MADM/smallness over byte
  //              counts) and the arXiv byte/packet-length stats. NO size evidence = 0
  //              points: absence of evidence is not evidence of regularity.
  //   span   10  duration - RITA v4.8+ duration scoring: long-lived steady contact is the
  //              C2 shape; a 30-second burst proves nothing (1h = full marks).
  const reg = push ? 0 : clamp01(1 - (gapCV - 0.05) / 0.45);
  const win = push ? 0 : clamp01((withinTenPct - 0.15) / 0.65);
  const his = push ? 0 : clamp01((histConcentration - 1 / HIST_BUCKETS) / (1 - 1 / HIST_BUCKETS));
  const siz = sizeCV === null ? 0 : clamp01(1 - sizeCV / 0.5);
  const dur = clamp01(spanHours / 1);
  // push mode: only duration/byte facts exist, so only those 20 points are scoreable -
  // reported on the SAME 0-100 scale (never rescaled: a push flow's low number says
  // "little beacon evidence on the scoreable features", and the flagged note says why
  // that is not a clean bill).
  const score = Math.round(45 * reg + 20 * win + 15 * his + 10 * siz + 10 * dur);
  const band = score >= 70 ? 'machine-metric' : score >= 35 ? 'mixed' : 'human-ish';

  // --- flagged: the exact human-readable warnings per feature that lit up ---
  const flagged = [];
  if (push) {
    flagged.push('push transport: no polling periodicity exists to score -- this is the point of the wire; detectors fall back to duration/byte/fan-out features');
  } else {
    if (gapCV < 0.05 && withinTenPct > 0.8) {
      flagged.push('intervals metronomic: gapCV ' + gapCV.toFixed(2) + ' -- ML flow detectors key on exactly this');
    } else if (gapCV < 0.2) {
      flagged.push('intervals regular: gapCV ' + gapCV.toFixed(2) + ' with ' + Math.round(withinTenPct * 100) + '% of gaps within +/-10% of the median -- inside the band beacon scorers grade');
    }
    if (histConcentration >= 0.5 && gMax > gMin) {
      flagged.push('interval histogram concentrated: ' + Math.round(histConcentration * 100) + '% of gaps in one bucket -- histogram-mode beacon scoring keys on this');
    }
  }
  if (sizeCV !== null && sizeCV < 0.1) {
    flagged.push('payload sizes near-constant: sizeCV ' + sizeCV.toFixed(2));
  }
  if (spanHours >= 1) {
    flagged.push('long-lived contact: ' + _r(spanHours, 1) + 'h span at ' + _r(eventsPerHour, 0) + ' events/hour -- duration is a scored C2 feature (RITA v4.8+)');
  }

  const note = push
    ? 'push channel: no poll cadence exists, so only duration/byte features are scoreable (20 of 100 points by construction). ' + NOTE
    : NOTE;
  return { mode: push ? 'push' : 'poll', score, band, features, flagged, note };
}

// PRE-DEPLOYMENT cadence grading: sample a synthetic check-in series from a malleable
// profile's own sampler (engine/malleable.nextGap) and score it as a poll flow. This
// answers "how beacon-like will this cadence look on the wire?" before an agent ever
// runs it. Deterministic under an injected rand (same rand sequence -> same series ->
// same score). nextGap semantics honored exactly: burst > 1 means that many quick
// cycles at gapMs spacing, then baseline resumes.
export function scoreProfileShape(profile, { samples = 64, rand = Math.random } = {}) {
  const p = malleableProfile(profile);
  const n = Math.max(MIN_POINTS, Math.floor(Number(samples) || 64));
  const times = [0];
  while (times.length < n) {
    const g = nextGap(p, { rand });
    const k = g.burst > 1 ? Math.floor(g.burst) : 1;
    for (let i = 0; i < k && times.length < n; i++) times.push(times[times.length - 1] + g.gapMs);
  }
  return { profile: p.label, samples: n, ...scoreFlow({ times, mode: 'poll' }) };
}
