// VARVEL - transport grader: the delivery-HEALTH oracle behind automatic failover (gap#5).
//
// Why it exists: agents can now fail over between live-verified transports (http, dns,
// icmp, doh, ws, smb) and the channel tags every observed check-in with the transport it
// arrived on (engine/callback). This module grades those observations into a
// per-transport health ladder plus a single operator recommendation. Pure logic - no
// I/O, `now` injectable.
//
// THE HONESTY CONTRACT (non-negotiable, same doctrine as tools/detoracle.mjs): this
// grades DELIVERY HEALTH ONLY - "do governed check-ins keep arriving on this wire?".
// It is NEVER a claim about detectability or undetectability: a 'healthy' transport can
// be fully visible to a defender, and a 'failed' one can be covert-but-blocked. We
// measure delivery; we do not assert stealth. Detection questions belong to detoracle.
//
// The ladder (per transport):
//   unknown - never observed a check-in on it (NO missed-window math is possible)
//   healthy - last seen within `suspectAfter` expected windows
//   suspect - last seen >= `suspectAfter` windows ago (degrading, not dead)
//   failed  - last seen >= `failedAfter` windows ago
//
// The recommendation NEVER switches to an unknown or failed transport: recommending an
// unobserved (or freshly dead) wire as "better" would be a guess, not a grade. Among
// viable (healthy/suspect) alternatives it prefers the most recently seen.

import { DIRECT_TLS_WIRES, INSPECTION_TOLERANT_WIRES } from './tlsinspect.mjs';

// TLS-INSPECTION ADAPTATION (lose-point #5 — engine/tlsinspect detects the SSL-bump; THIS
// is the deliberate decision). When the measured posture is 'tls-inspected' (or 'partial'
// — a bumped reference exists), the operator's tlsinspect.policy steers the ranking:
//   fail-closed (default) — direct TLS wires (http/doh/ws: content legible to the
//     enterprise egress proxy) are EXCLUDED from the ranking, listed with the honest
//     reason. Nothing leaks: the plan cannot recommend a wire the proxy can read.
//   adapt — a scored factor with an honest, visible weight: direct wires take
//     -INSPECTION_PENALTY, inspection-tolerant wires (ghc/stg/dns/icmp) take
//     +INSPECTION_BONUS. The `why` string carries the adjustment, always.
//   ignore — the operator override: ranking is computed UNCHANGED and the result carries
//     a loud warning. The inspection is reported, never hidden.
// smb is NEUTRAL under every policy (an internal pivot relay — the egress proxy never
// sees that segment). ghc/stg are inspection-COMPATIBLE, never inspection-PROOF.
const INSPECTION_PENALTY = 40; // direct TLS wire under an inspected egress
const INSPECTION_BONUS = 20;   // inspection-tolerant wire under an inspected egress

const TRANSPORTS = ['http', 'dns', 'icmp', 'doh', 'ws', 'smb', 'ghc', 'stg'];

// da: the channel's agent record (uses transportLastSeen + lastTransport only).
// Returns { perTransport: { t: { health, missedWindows, lastSeen } }, current,
//           recommendation: { action: 'stay'|'watch'|'switch', to?, reason } }.
export function gradeAgentTransports(da, { now, expectedMs = 5000, suspectAfter = 3, failedAfter = 6 } = {}) {
  const nowMs = Number.isFinite(Number(now)) ? Number(now) : Date.now();
  const expected = Math.max(1, Number(expectedMs) || 5000);
  const sus = Math.max(1, Number(suspectAfter) || 3);
  const fail = Math.max(sus + 1, Number(failedAfter) || 6);
  const lastSeenMap = (da && da.transportLastSeen) || {};

  const perTransport = {};
  for (const t of TRANSPORTS) {
    const seen = Number(lastSeenMap[t]) || 0;
    if (!seen) { perTransport[t] = { health: 'unknown', missedWindows: 0, lastSeen: null }; continue; }
    const missedWindows = Math.max(0, Math.floor((nowMs - seen) / expected));
    const health = missedWindows >= fail ? 'failed' : missedWindows >= sus ? 'suspect' : 'healthy';
    perTransport[t] = { health, missedWindows, lastSeen: seen };
  }

  const current = (da && da.lastTransport) || null;
  const cur = current && perTransport[current] ? perTransport[current] : null;
  // Switch candidates: ONLY transports graded healthy or suspect, most recently seen first.
  const viable = TRANSPORTS
    .filter((t) => t !== current && (perTransport[t].health === 'healthy' || perTransport[t].health === 'suspect'))
    .sort((x, y) => perTransport[y].lastSeen - perTransport[x].lastSeen);

  let recommendation;
  if (cur && cur.health === 'healthy') {
    recommendation = { action: 'stay', reason: 'current transport ' + current + ' is healthy (' + cur.missedWindows + ' missed windows)' };
  } else if (cur && cur.health === 'suspect') {
    recommendation = { action: 'watch', reason: 'current transport ' + current + ' is suspect (' + cur.missedWindows + ' missed windows) - degrading, not dead' };
  } else if (viable.length) {
    const to = viable[0];
    recommendation = { action: 'switch', to, reason: (cur ? 'current transport ' + current + ' is ' + cur.health : 'no current transport observed') + '; ' + to + ' is ' + perTransport[to].health + ' and the most recently seen viable alternative' };
  } else {
    recommendation = { action: 'watch', reason: (cur ? 'current transport ' + current + ' is ' + cur.health : 'no transport observed yet') + ' and no alternative has delivery evidence (never switch to unknown/failed) - keep watching' };
  }
  return { perTransport, current, recommendation };
}

// ————————————————————————————————————————————————————————————————————————————————
// ORACLE-GRADED ADAPTIVE FAILOVER (the shaping pack, part 4): gradeAgentTransports
// answers "does the wire DELIVER?"; rankTransports answers "which wire should we
// PREFER?" by folding in the platform's own detectability measurement per wire —
// the differentiator: the first C2 whose failover ranking is driven by measured
// detectability, not a static order.
//
//   score(t) = healthPts(t) + successPts(t) - shapePenalty(t)
//     healthPts     healthy 60 / suspect 30 / failed 0   (delivery evidence, this module)
//     successPts    min(20, observedCheckins)            (a wire with a longer success
//                    history earns rank; 1pt per accepted check-in, capped)
//     shapePenalty  round(0.4 * beaconScore) 0..40       (the wire's MEASURED
//                    beacon-likeness from the per-transport flow ring; null score =
//                    no shape evidence = 0 penalty, and the entry SAYS that, honestly:
//                    absence of evidence never fabricates a low-detectability claim)
//
// ELIGIBILITY (fail-closed, governance preserved): a transport only enters the ranking
// when its own requirements are met (eligible map in) AND it has delivery evidence
// (unknown = never observed = excluded). ghc needs the engagement's enabled+token
// (the caller passes eligible.ghc only when a client is attached); smb needs an
// enrolled link. An ineligible wire is LISTED with its reason, never silently ranked.
//
// MANUAL OVERRIDE ALWAYS WINS: `pinned` (the operator's assignedTransport) ranks first
// unconditionally and the recommendation refuses to move off it.
//
// HONESTY CONTRACT: identical doctrine to gradeAgentTransports — the beacon score is
// FEATURE evidence (engine/beaconscore), not a detectability verdict; a wire that
// ranks first is "preferred on delivery + measured features", never "undetectable".
// ————————————————————————————————————————————————————————————————————————————————
export function rankTransports({ grades, wireScores = {}, checkins = {}, eligible = {}, pinned = null, current = null, threshold = 70, inspection = null } = {}) {
  const perTransport = (grades && grades.perTransport) || {};
  const th = Math.min(100, Math.max(1, Number(threshold) || 70));
  // TLS-inspection posture (engine/tlsinspect): active when a measured bump exists.
  const insp = inspection && (inspection.posture === 'tls-inspected' || inspection.posture === 'partial')
    ? { posture: inspection.posture, policy: ['fail-closed', 'adapt', 'ignore'].includes(inspection.policy) ? inspection.policy : 'fail-closed' }
    : null;
  const warnings = [];
  if (insp && insp.policy === 'ignore') {
    warnings.push('tlsinspect.policy=ignore — TLS inspection was MEASURED on this egress and the operator overrode it: direct wires keep ranking and their content remains visible to the enterprise egress proxy. Adaptation is a wire CHOICE; the inspection is never claimed away.');
  }
  const ELIGIBILITY_REASONS = {
    ghc: 'ghc needs the engagement ghc2.enabled + a burner token + an attached mailbox client',
    smb: 'smb needs an enrolled pivot link (registerLinkedAgent) — it is a relay, never a direct dial',
    icmp: 'icmp needs the raw-socket bridge armed (privileged)',
    doh: 'doh needs the https arm configured',
    stg: 'stg needs the image channel armed (stg.enabled / VARVEL_STG) — the low-bandwidth fallback wire',
  };
  const FAIL_CLOSED_REASON = 'tlsinspect: egress measured ' + (insp && insp.posture) + ' and tlsinspect.policy is fail-closed — direct TLS wires (content visible to the enterprise egress proxy) REFUSE to carry channel traffic until the posture clears or the policy changes';
  const ranking = [];
  const ineligible = [];
  for (const t of TRANSPORTS) {
    const g = perTransport[t] || { health: 'unknown', missedWindows: 0 };
    const seen = Number(checkins[t]) || 0;
    if (eligible[t] === false) { ineligible.push({ transport: t, reason: ELIGIBILITY_REASONS[t] || 'not available in this configuration' }); continue; }
    if (g.health === 'unknown' && seen === 0) { ineligible.push({ transport: t, reason: 'never observed — no delivery evidence (unknown wires are never ranked)' }); continue; }
    if (insp && insp.policy === 'fail-closed' && DIRECT_TLS_WIRES.has(t)) { ineligible.push({ transport: t, reason: FAIL_CLOSED_REASON }); continue; }
    const ws = wireScores[t];
    const rawBeacon = ws && ws.score;
    const beacon = rawBeacon === null || rawBeacon === undefined || !Number.isFinite(Number(rawBeacon)) ? null : Number(rawBeacon);
    const healthPts = g.health === 'healthy' ? 60 : g.health === 'suspect' ? 30 : 0;
    const successPts = Math.min(20, seen);
    const shapePenalty = beacon === null ? 0 : Math.round(0.4 * beacon);
    // The inspection factor (policy 'adapt' only): honest, visible weight.
    const inspAdj = insp && insp.policy === 'adapt'
      ? (DIRECT_TLS_WIRES.has(t) ? -INSPECTION_PENALTY : INSPECTION_TOLERANT_WIRES.has(t) ? INSPECTION_BONUS : 0)
      : 0;
    const score = healthPts + successPts - shapePenalty + inspAdj + (pinned === t ? 1000 : 0);
    ranking.push({
      transport: t, score,
      why: (pinned === t ? 'operator pin (+override); ' : '')
        + g.health + ' ' + healthPts + ' + success ' + successPts + ' (' + seen + ' observed) - shape penalty ' + shapePenalty
        + (beacon === null ? ' (no shape evidence — no penalty, no claim)' : ' (measured beacon score ' + beacon + ')')
        + (inspAdj !== 0 ? (inspAdj < 0 ? ' - inspection penalty ' + INSPECTION_PENALTY + ' (direct TLS wire, egress measured ' + insp.posture + ' — content visible to the enterprise proxy)' : ' + inspection-tolerant bonus ' + INSPECTION_BONUS + ' (egress measured ' + insp.posture + '; inspection-COMPATIBLE, never inspection-proof)') : ''),
      health: g.health, checkins: seen, beaconScore: beacon,
    });
  }
  ranking.sort((x, y) => y.score - x.score);

  // Recommendation. Pinned = stay, always. Then: if the CURRENT wire's measured
  // detectability crosses the threshold and a strictly better-ranked ELIGIBLE
  // alternative exists, recommend the re-order. Delivery failure switching stays
  // gradeAgentTransports' job — this layer ranks preference, it does not resurrect
  // dead wires (a failed current wire scores 0 health and sinks on its own).
  const cur = current || (grades && grades.current) || null;
  let recommendation;
  const curRank = ranking.find((r) => r.transport === cur) || null;
  if (pinned) {
    recommendation = { action: 'stay', pinned: true, reason: 'operator pin on ' + pinned + ' — manual override always wins; ranking computed but not applied' };
    if (insp && DIRECT_TLS_WIRES.has(pinned)) warnings.push('operator pin holds a DIRECT TLS wire (' + pinned + ') under a measured ' + insp.posture + ' egress — the pin wins, and the exposure is on the record');
  } else if (insp && insp.policy !== 'ignore' && cur && DIRECT_TLS_WIRES.has(cur)) {
    // INSPECTION-DRIVEN re-order: the current wire's content is visible to the egress
    // proxy; policy (fail-closed or adapt) prefers the best-ranked tolerant wire. This
    // bypasses the beacon threshold deliberately — the driver is the measured bump, not
    // the shape score — and says so.
    const better = ranking.find((r) => !DIRECT_TLS_WIRES.has(r.transport));
    if (better) {
      recommendation = { action: 'switch-recommended', to: better.transport, reason: 'egress measured ' + insp.posture + ' and current wire ' + cur + ' is a direct TLS wire — content visible to the enterprise egress proxy; tlsinspect.policy=' + insp.policy + ' elevates ' + better.transport + ' (score ' + better.score + ') — inspection-COMPATIBLE, never inspection-proof' };
    } else {
      recommendation = { action: 'stay', reason: 'egress measured ' + insp.posture + ' and current wire ' + cur + ' is a direct TLS wire, but NO inspection-tolerant wire has delivery evidence/eligibility — ' + (insp.policy === 'fail-closed' ? 'fail-closed means the direct wire must NOT be ridden: stand the agent down or arm ghc/stg/dns/icmp' : 'adapt cannot promote what was never observed; arm an inspection-tolerant wire (ghc/stg/dns/icmp)') };
    }
  } else if (curRank && curRank.beaconScore !== null && curRank.beaconScore >= th) {
    const better = ranking.find((r) => r.transport !== cur && r.score > curRank.score);
    if (better) {
      recommendation = { action: 'switch-recommended', to: better.transport, reason: 'current wire ' + cur + ' measures beacon score ' + curRank.beaconScore + ' (>= threshold ' + th + ' — machine-metric territory); ' + better.transport + ' ranks higher (' + better.score + ' vs ' + curRank.score + ')' };
    } else {
      recommendation = { action: 'stay', reason: 'current wire ' + cur + ' measures beacon score ' + curRank.beaconScore + ' (>= threshold ' + th + ') but no eligible alternative outranks it — staying is the honest choice' };
    }
  } else {
    recommendation = { action: 'stay', reason: cur
      ? 'current wire ' + cur + (curRank && curRank.beaconScore !== null ? ' measures beacon score ' + curRank.beaconScore + ' — below the ' + th + ' re-order threshold' : ' has no shape evidence over the threshold')
      : 'no current wire observed' };
  }
  return { ranking, ineligible, pinned: pinned || null, current: cur, threshold: th, inspection: insp, warnings, recommendation };
}
