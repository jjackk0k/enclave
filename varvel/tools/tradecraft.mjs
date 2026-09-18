// VARVEL - tradecraft: the agent-tradecraft oracle (gap#7), detoracle's sibling for the
// operator's command-stream shape. Two compositions over engine/agentsig:
//
//   fetchLive(agentId, api)  - grade the shell-command stream a LIVE agent has actually
//     been tasked with, as recorded in the governed channel's task ledger
//     (GET /api/channel/tradecraft?agent=<id>): the full analyzeCommandStream result
//     (signatures + flagged + note). 404 surfaces as an honest error object, never an
//     exception-shaped crash.
//   preflight(commandsArray) - PRE-TASKING grading: run analyzeCommandStream locally on
//     a PLANNED command list (array of strings) before anything is sent. A planned list
//     has no real timestamps, so the cadence signature honestly reports fired:null
//     ('no timing evidence') - never a fabricated number.
//
// THE HONESTY CONTRACT (same doctrine as tools/detoracle.mjs, engine/beaconscore.mjs):
// grades are SIGNATURE evidence against the published AI-agent command-stream
// fingerprints - vendor detector weights and thresholds are secret, so nothing here is
// a vendor verdict, and a clean grade is never a claim of undetectability. This tier
// reports signatures + evidence only; it offers no evasion guidance.

import { analyzeCommandStream } from '../engine/agentsig.mjs';

export async function fetchLive(agentId, api = 'http://127.0.0.1:8971') {
  if (!agentId) throw new TypeError('tradecraft.fetchLive needs an agentId');
  const base = String(api || '').replace(/\/+$/, '');
  let r;
  try {
    r = await fetch(base + '/api/channel/tradecraft?agent=' + encodeURIComponent(String(agentId)));
  } catch (e) {
    return { ok: false, agentId, error: 'tradecraft route unreachable at ' + base + ' (' + ((e && e.message) || e) + ') -- is the service up and the channel armed?' };
  }
  const body = await r.json().catch(() => null);
  if (r.status === 404) return { ok: false, agentId, error: (body && body.error) || 'no such agent' };
  if (!r.ok || !body) return { ok: false, agentId, error: 'tradecraft route answered HTTP ' + r.status + ' with an unreadable body' };
  return { ok: true, ...body };
}

export function preflight(commands) {
  if (!Array.isArray(commands) || !commands.every((c) => typeof c === 'string')) {
    return { ok: false, error: 'tradecraft.preflight needs an array of command strings (the planned command list)' };
  }
  return { ok: true, planned: commands.length, ...analyzeCommandStream(commands) };
}
