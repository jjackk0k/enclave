// VARVEL — shapegrade tool shell: the oracle-graded self-measurement loop (shaping pack
// part 3), detoracle/floworacle's sibling for the APPLIED wire shape. Two compositions
// over engine/shapegrade (pure):
//
//   gradeLive(agentId, api)  — grade the shape a LIVE agent has applied against what the
//     platform's own oracles observed: the channel's JA4H ring (GET /api/fp) and the
//     agent's flow score (GET /api/channel/flow). The applied shape name comes from the
//     channel agent view. Unreachable routes come back { ok:false, error } — never thrown.
//   preflightShapes()        — pre-deployment: every library profile's CLAIM (expected
//     JA4H + cadence pre-flight score) side by side, before anything touches a wire.
//
// THE HONESTY CONTRACT (same doctrine as engine/shapegrade): claimed-vs-measured REPORTS,
// never detectability verdicts. Divergence is the loud case — it is returned in
// `divergent`, never smoothed into a pass.

import { SHAPE_PROFILES, expectedJa4h } from '../engine/malleable.mjs';
import { ja4h } from '../engine/fingerprint.mjs';
import { gradeShape } from '../engine/shapegrade.mjs';
import { scoreProfileShape } from '../engine/beaconscore.mjs';

export async function gradeLive(agentId, api = 'http://127.0.0.1:8971', { rand } = {}) {
  if (!agentId) throw new TypeError('shapegrade.gradeLive needs an agentId');
  const base = String(api || '').replace(/\/+$/, '');
  const get = async (path) => {
    try {
      const r = await fetch(base + path);
      return { status: r.status, body: await r.json().catch(() => null) };
    } catch (e) {
      return { status: 0, body: null, error: 'unreachable at ' + base + ' (' + ((e && e.message) || e) + ') -- is the service up and the channel armed?' };
    }
  };

  const ch = await get('/api/channel');
  if (ch.error) return { ok: false, agentId, error: 'channel view ' + ch.error };
  if (!ch.body || ch.body.armed !== true) return { ok: false, agentId, error: 'channel not armed -- no wire exists to measure' };
  const view = (ch.body.agents || []).find((a) => a.agentId === agentId);
  if (!view) return { ok: false, agentId, error: 'no such agent on the armed channel' };

  const fp = await get('/api/fp');
  const observations = fp.body && Array.isArray(fp.body.observations) ? fp.body.observations : [];
  const flowRes = await get('/api/channel/flow?agent=' + encodeURIComponent(String(agentId)));
  const flow = flowRes.status === 200 && flowRes.body ? flowRes.body : null;

  const opts = { observations, flow };
  if (typeof rand === 'function') opts.rand = rand;
  const report = gradeShape({ shape: view.shape || 'plain', ...opts });
  return { agentId, appliedShape: view.shape || 'plain', ...report };
}

// Pre-deployment: every library profile's claim, with its cadence pre-flight grade.
// Deterministic under an injected rand (threaded into scoreProfileShape).
export function preflightShapes({ rand } = {}) {
  const profiles = {};
  for (const [name, p] of Object.entries(SHAPE_PROFILES)) {
    const cadence = p.cadence
      ? scoreProfileShape({ label: p.label, intervalMs: p.cadence.intervalMs, jitterMs: p.cadence.jitterMs || 0, jitterPct: p.cadence.jitterPct || 0, burst: p.cadence.burst }, rand ? { rand } : {})
      : null;
    profiles[name] = {
      label: p.label,
      ja4hPull: p.http ? expectedJa4h(p, { method: 'GET', ja4hFn: ja4h }) : null,
      ja4hPush: p.http ? expectedJa4h(p, { method: 'POST', ja4hFn: ja4h }) : null,
      ja4hClass: p.expect && p.expect.ja4h,
      h2: (p.expect && p.expect.h2) || null,
      cadence: p.cadence ? { intervalMs: p.cadence.intervalMs, jitterPct: p.cadence.jitterPct || 0 } : null,
      preFlight: cadence ? { score: cadence.score, band: cadence.band, flagged: cadence.flagged } : null,
      note: p.note,
    };
  }
  return { ok: true, profiles, note: 'claims, pre-measurement: ja4h values are the fingerprints these templates WILL produce on this runtime (header names/order only); preFlight scores are the cadence model\'s own beacon-likeness. Apply, then gradeLive to compare against the measured wire.' };
}
