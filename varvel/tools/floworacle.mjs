// VARVEL - floworacle: the flow-beacon self-test oracle (gap#6), detoracle's sibling for
// the wire shape. Two compositions over engine/beaconscore:
//
//   fetchLive(agentId, api)  - score the flow a LIVE agent has actually produced, as
//     observed by the governed channel (GET /api/channel/flow?agent=<id>): the full
//     scoreFlow result (features + flagged + note). 404 surfaces as an honest error
//     object, never an exception-shaped crash.
//   preflight(profileName)   - PRE-DEPLOYMENT cadence grading: sample a synthetic series
//     from the malleable profile's own nextGap() sampler and score it (mode 'poll').
//     Unknown profile names get an honest error naming the known set - never a silent
//     fallback (malleableProfile's ops-tempo default would grade the WRONG cadence).
//
// THE HONESTY CONTRACT (same doctrine as tools/detoracle.mjs, engine/beaconscore.mjs):
// scores are FEATURE evidence against published flow detectors (RITA beacon scoring;
// arXiv 2506.08922) - vendor detector weights are secret, so nothing here is a vendor
// verdict, and a low score is never a claim of undetectability.

import { MALLEABLE_PROFILES } from '../engine/malleable.mjs';
import { scoreProfileShape } from '../engine/beaconscore.mjs';

export async function fetchLive(agentId, api = 'http://127.0.0.1:8971') {
  if (!agentId) throw new TypeError('floworacle.fetchLive needs an agentId');
  const base = String(api || '').replace(/\/+$/, '');
  let r;
  try {
    r = await fetch(base + '/api/channel/flow?agent=' + encodeURIComponent(String(agentId)));
  } catch (e) {
    return { ok: false, agentId, error: 'flow route unreachable at ' + base + ' (' + ((e && e.message) || e) + ') -- is the service up and the channel armed?' };
  }
  const body = await r.json().catch(() => null);
  if (r.status === 404) return { ok: false, agentId, error: (body && body.error) || 'no such agent' };
  if (!r.ok || !body) return { ok: false, agentId, error: 'flow route answered HTTP ' + r.status + ' with an unreadable body' };
  return { ok: true, ...body };
}

export function preflight(profileName, { samples = 64, rand } = {}) {
  const name = String(profileName || '');
  const known = Object.keys(MALLEABLE_PROFILES);
  if (!Object.prototype.hasOwnProperty.call(MALLEABLE_PROFILES, name)) {
    return { ok: false, error: "unknown profile '" + name + "' -- known profiles: " + known.join(', '), known };
  }
  const opts = { samples };
  if (typeof rand === 'function') opts.rand = rand;
  const shape = scoreProfileShape(name, opts);
  return { ok: true, ...shape, label: shape.profile, profile: name };
}
