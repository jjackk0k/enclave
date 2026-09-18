// VARVEL — SESSION RESILIENCE: mission checkpoints, crash resume, and session-splitting.
// (Documented gap #2. Two field failures motivate it: (a) a flaky operator network killed
// four agent turns mid-run — 'terminated' / 'fetch failed' — orphaning each mission and
// burning the turn; (b) hour-long campaigns blow past any context window, so a mission
// must survive summarize → checkpoint → clear → resume.)
//
// STORAGE DECISION (justify or change with care): checkpoints live in DEDICATED files
// (`<key('mission:'+id)>.mission.json`) under the same VARVEL_DATA_DIR discipline as
// engine/store.mjs / engine/statestore.mjs — NOT as a statestore entity kind. Reasons:
//   (1) checkpoints are OPERATIONAL runner state (conversation payloads, tool ledger),
//       written at every tool-call boundary — not engagement knowledge to be queried,
//       redacted, or injected into briefs;
//   (2) statestore's upsert/dedup machinery keys entities by domain fields (ip, ref,
//       principal) — a checkpoint has a single natural key (missionId) and one writer;
//   (3) briefSlice must never leak a checkpoint's raw tool results (they can carry
//       target secrets); a separate suffix keeps them out of every state listing.
// Integration with the statestore is by REFERENCE: a checkpoint records the engagement
// id, and a split handoff carries stateRefs (engagement + counts) + a briefSlice —
// never copies of entity records.
//
// PROOF STANDARD: failed hypotheses MUST survive a split. buildHandoff pulls the
// engagement's failure ledger (store.mjs priorFailures) AND the statestore's REFUTED
// findings, and handoffSeedText marks them do-NOT-retry — the next session is seeded
// with refuted paths so it never re-spends turns (or noise) on disproven approaches.

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { dataDir, priorFailures } from './store.mjs';
import { briefSlice, stateCounts, loadState } from './statestore.mjs';

const ensure = () => { const DIR = dataDir(); if (!existsSync(DIR)) mkdirSync(DIR, { recursive: true }); return DIR; };
const key = (s) => String(s || 'engagement').replace(/[^a-z0-9._-]/gi, '_').slice(0, 40) + '-' + createHash('sha1').update(String(s || 'engagement')).digest('hex').slice(0, 8);
const readJson = (p, fb) => { try { return existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : fb; } catch { return fb; } };

// 'running'      = a turn is in flight — ALSO the state a crash/kill leaves behind (resumable)
// 'awaiting-input' = a turn completed cleanly; the mission rests until the next instruction
// 'failed'       = a PERMANENT backend error (4xx auth/quota) ended the last turn — no auto-retry
// 'split'        = superseded by a fresh mission via splitMission (see handoff.newMission)
export const CHECKPOINT_STATUS = ['running', 'awaiting-input', 'failed', 'split'];
export const newMissionId = () => 'msn-' + Date.now().toString(36) + '-' + randomBytes(3).toString('hex');

const missionFile = (id) => join(dataDir(), key('mission:' + id) + '.mission.json');

export function saveCheckpoint(cp) {
  if (!cp || !cp.missionId) throw new TypeError('checkpoint needs a missionId');
  const DIR = ensure();
  const out = { ...cp, v: 1, updated: new Date().toISOString() };
  writeFileSync(join(DIR, key('mission:' + cp.missionId) + '.mission.json'), JSON.stringify(out, null, 2));
  return out;
}

export function loadCheckpoint(missionId) {
  if (!missionId) return null;
  const cp = readJson(missionFile(missionId), null);
  return cp && typeof cp === 'object' && cp.missionId ? cp : null;
}

// Operator-facing listing (cli `missions` / GET /api/missions): SUMMARIES ONLY — msgs and
// ledger result bodies never leave the store through here (they can carry target secrets).
export function listMissions() {
  const DIR = dataDir();
  let files = [];
  try { files = readdirSync(DIR).filter((f) => f.endsWith('.mission.json')); } catch { return []; }
  const out = [];
  for (const f of files) {
    const cp = readJson(join(DIR, f), null);
    if (!cp || !cp.missionId) continue;
    out.push({
      missionId: cp.missionId,
      engagement: cp.engagement || null,
      status: cp.status || 'running',
      turns: cp.turnsTotal || 0,
      bytes: cp.bytes || 0,
      toolCalls: (cp.ledger || []).length,
      retries: (cp.retries || []).length,
      denials: (cp.denials || []).length,
      objective: String(cp.objective || '').slice(0, 120) || null,
      splitFrom: cp.splitFrom || null,
      splits: cp.splits || 0,
      model: cp.model || null,
      created: cp.created || null,
      updated: cp.updated || null,
      error: cp.error ? String(cp.error).slice(0, 160) : null,
    });
  }
  return out.sort((a, b) => String(b.updated || '').localeCompare(String(a.updated || '')));
}

// ---------------------------------------------------------------------------
// SPLIT DECISION. Pure, deterministic, never throws. Thresholds are env-tunable:
// VARVEL_SPLIT_TURNS (default 30 cumulative model turns) and VARVEL_SPLIT_BYTES
// (default 150000 — the persisted conversation size; context pressure, not the window
// itself). The runner evaluates this ONLY at a turn boundary — never mid-tool-call.
export function shouldSplit({ turns = 0, bytes = 0 } = {}, opts = {}) {
  const num = (v, d) => { const n = Number(v); return Number.isFinite(n) && n > 0 ? n : d; };
  const env = opts.env || process.env;
  const maxTurns = Math.floor(num(opts.turns ?? env.VARVEL_SPLIT_TURNS, 30));
  const maxBytes = num(opts.bytes ?? env.VARVEL_SPLIT_BYTES, 150000);
  const t = Number(turns) || 0, b = Number(bytes) || 0;
  if (t >= maxTurns) return { split: true, reason: `turns ${t} >= ${maxTurns} — context fatigue risk; split before the history degrades` };
  if (b >= maxBytes) return { split: true, reason: `conversation ${b} bytes >= ${maxBytes} — split before the window overflows` };
  return { split: false, reason: `within thresholds (turns ${t}/${maxTurns}, bytes ${b}/${maxBytes})` };
}

// The structured handoff a split produces. State travels by REFERENCE (engagement id +
// counts — the fresh session queries the store itself); failed hypotheses travel as
// DATA because they are exactly what a fresh context would otherwise re-try.
export function buildHandoff(cp, opts = {}) {
  if (!cp || !cp.missionId) throw new TypeError('buildHandoff needs a checkpoint (or a missionId with one stored)');
  const eng = cp.engagement || null;
  const failedHypotheses = [];
  if (eng) {
    for (const f of priorFailures(eng))
      failedHypotheses.push({ kind: f.kind || 'failure', phase: f.phase || null, approach: String(f.approach || '').slice(0, 200), at: f.at || null });
    try {
      const st = loadState(eng);
      for (const f of (st ? st.findings : []).filter((x) => x.validation === 'refuted'))
        failedHypotheses.push({ kind: 'refuted-finding', title: f.title || null, ref: f.ref || null, host: f.host || null, note: 'refuted by the validator gate — do NOT re-test' });
    } catch { /* state unreadable — hypotheses from the failure ledger still carry */ }
  }
  let decisions = [];
  try { decisions = eng && loadState(eng) ? loadState(eng).notes.slice(-10).map((n) => ({ text: n.text, at: n.ts, actor: n.provenance && n.provenance.actor })) : []; } catch { decisions = []; }
  // The summary is where the mission STOOD: prefer the last completed turn's text, else
  // the trailing assistant text in the conversation, so the next session starts honest.
  let summary = String(cp.finalText || '');
  if (!summary && Array.isArray(cp.msgs)) {
    for (let i = cp.msgs.length - 1; i >= 0 && !summary; i--) {
      const m = cp.msgs[i];
      if (m && m.role === 'assistant') {
        const blocks = Array.isArray(m.content) ? m.content : [{ type: 'text', text: String(m.content || '') }];
        summary = blocks.filter((b) => b && b.type === 'text').map((b) => b.text || '').join('\n').trim();
      }
    }
  }
  return {
    v: 1,
    kind: 'session-handoff',
    fromMission: cp.missionId,
    at: new Date().toISOString(),
    objective: String(cp.objective || '').slice(0, 500),
    engagement: eng,
    stateRefs: eng ? { engagement: eng, counts: stateCounts(eng) } : null, // REFS, never copies
    decisions,
    pendingGates: Array.isArray(cp.gates) ? cp.gates : [],
    failedHypotheses,
    turns: cp.turnsTotal || 0,
    bytes: cp.bytes || 0,
    summary: summary.slice(0, 1200),
    note: opts.note ? String(opts.note).slice(0, 300) : null,
  };
}

// The seed text a fresh session starts from: the handoff + a live briefSlice of the
// state store. Refused paths are explicitly do-not-retry (PROOF STANDARD).
export function handoffSeedText(handoff, charBudget = 1500) {
  const h = handoff || {};
  const L = [];
  L.push(`[SESSION HANDOFF — mission ${h.fromMission} split at ${h.at}; ${h.turns} turns carried]`);
  L.push(`OBJECTIVE: ${h.objective || '(see prior mission)'}`);
  if (h.stateRefs) {
    const c = h.stateRefs.counts || {};
    L.push(`STATE (structured store, engagement '${h.stateRefs.engagement}' — query it, trust it over memory): hosts ${c.hosts || 0}, creds ${c.creds || 0}, sessions ${c.sessions || 0}, findings ${c.findings || 0}`);
    try {
      const slice = briefSlice(h.stateRefs.engagement, charBudget);
      if (slice) L.push(slice);
    } catch { /* brief unavailable — refs above still name the store */ }
  }
  if (h.decisions && h.decisions.length) {
    L.push('DECISIONS / OPERATOR NOTES MADE SO FAR:');
    for (const d of h.decisions) L.push(`- ${d.text}${d.actor ? ` (${d.actor})` : ''}`);
  }
  L.push(h.pendingGates && h.pendingGates.length
    ? 'PENDING GATES: ' + h.pendingGates.map((g) => (typeof g === 'string' ? g : g.phase || g.id || JSON.stringify(g))).join('; ')
    : 'PENDING GATES: none recorded');
  if (h.failedHypotheses && h.failedHypotheses.length) {
    L.push('FAILED HYPOTHESES / REFUTED PATHS — do NOT retry these (PROOF STANDARD: refuted stays refuted across the split):');
    for (const f of h.failedHypotheses.slice(0, 25))
      L.push('- ' + (f.kind === 'refuted-finding' ? `[refuted] ${f.title || f.ref || '?'}${f.host ? ' @ ' + f.host : ''}` : `[${f.phase || '?'}/${f.kind}] ${f.approach}`));
    if (h.failedHypotheses.length > 25) L.push(`- … +${h.failedHypotheses.length - 25} more in the failure ledger (engagement '${h.engagement}')`);
  } else {
    L.push('FAILED HYPOTHESES: none recorded');
  }
  if (h.summary) L.push(`WHERE THE MISSION STOOD:\n${h.summary}`);
  if (h.note) L.push(`OPERATOR NOTE ON THE SPLIT: ${h.note}`);
  L.push('Continue the mission from here. Do not redo what the state store already proves; do not retry the refuted paths above.');
  return L.join('\n');
}

// THE SPLIT: mark the old mission 'split', seed a FRESH mission whose whole context is
// the handoff + state brief. Returns { handoff, mission, seed } — `mission` is the new
// checkpoint's summary; resume it like any checkpointed mission.
export function splitMission(missionId, opts = {}) {
  const cp = typeof missionId === 'string' ? loadCheckpoint(missionId) : missionId;
  if (!cp) throw new Error('no checkpoint for mission ' + JSON.stringify(missionId));
  if (cp.status === 'split') return { handoff: cp.handoff, mission: listMissions().find((m) => m.missionId === (cp.handoff && cp.handoff.newMission)) || null, seed: null, already: true };
  const handoff = buildHandoff(cp, opts);
  const newId = opts.newMissionId || newMissionId();
  handoff.newMission = newId;
  const seed = handoffSeedText(handoff, opts.charBudget);
  const now = new Date().toISOString();
  saveCheckpoint({ ...cp, status: 'split', handoff, splits: (cp.splits || 0) + 1 });
  const fresh = saveCheckpoint({
    missionId: newId,
    engagement: cp.engagement || null,
    created: now,
    status: 'awaiting-input',
    model: cp.model || null,
    effort: cp.effort || null,
    sessionFile: cp.sessionFile || null,
    wsDir: cp.wsDir || null,
    container: cp.container || '',
    objective: handoff.objective,
    turnsTotal: 0,
    bytes: seed.length,
    msgs: [{ role: 'user', content: seed }],
    ledger: [],
    retries: [],
    denials: [],
    gates: handoff.pendingGates,
    splits: 0,
    splitFrom: cp.missionId,
    finalText: null,
  });
  return { handoff, mission: { missionId: newId, engagement: fresh.engagement, status: fresh.status, splitFrom: fresh.splitFrom, bytes: fresh.bytes }, seed };
}
