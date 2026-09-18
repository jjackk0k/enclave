// VARVEL — autopilot: the durable wide-first scheduler (Jack's directive 2026-09-01:
// "make it automated so VARVEL AI starts getting results and vuls"). ONE orchestrator
// that glues together the pieces that already exist — separately invoked until now —
// so the platform hunts CONTINUOUSLY without human babysitting:
//
//   (a) tools/widerecon.mjs sweep() — roster-wide passive recon, diffed cycle-over-cycle
//       (new catches / gone catches / score moves land in the log + digest).
//   (b) tools/commitwatch.mjs scan(live) — the fix-commit delta watcher over
//       wordpress.org; new leads are reported REVIEW-ONLY (its doctrine stands: a fix
//       commit is a map to a bug class, not a finding).
//   (c) the WP lane — privemap + reachprove --rescore over corpus plugins NOT already
//       covered by a hunt report (.tmp/hunt-*/privemap/*.json ∪ the autopilot's own
//       coverage state), then the top candidates go to the console chat agent for AI
//       adjudication — ONE brief per cycle via POST /api/message, serialized, waited on.
//   (d) the campaign launcher — POST /api/campaign for sweep programs whose bountyline
//       record (data/bountyline/programs/<id>.json) carries automation full|human-cadence
//       AND a signed scope on record, gated HARD on Ghost Mode (see below).
//
// HARD RULES (code, not doctrine — test/autopilot.test.mjs pins them):
//   1. NEVER SUBMITS, NEVER FILES. There is no submission code path in this file — no
//      submit-drive import, no platform API, nothing behind a flag. The autopilot's own
//      HTTP client talks to the LOOPBACK CONSOLE ONLY (127.0.0.1 / localhost / [::1]) —
//      any other host is refused BEFORE a request is built (console-host-not-allowed).
//      Findings surface to the operator (digest + state + chat); the send click is the
//      operator's, always.
//   2. NEVER FABRICATES. Unknowns are recorded UNKNOWN; a failed sweep/scan/launch lands
//      in the log with the error named; a clean cycle is reported clean.
//   3. GHOST-OFF = NO LAUNCHES. GET /api/ghost must answer mode != 'off' AND
//      verified.ok === true, or every launch is REFUSED with the reason named, loudly.
//   4. ONE CAMPAIGN, NEVER A CLOBBER. The console server has a single campaign global —
//      the autopilot reads GET /api/state first and launches ONLY when the status is
//      idle|interactive|done; anything else (running/stalled/errored/chat-busy) SKIPS
//      the launch with the status named. One launch per cycle at most.
//   5. PROHIBITED IS NAMED, VISA IS HARD-EXCLUDED (Jack's rule). LAUNCH_EXCLUDED_PROGRAMS
//      refuses in code, on top of the roster policy and the widerecon pin list; every
//      refusal is logged with its reason.
//   6. Everything lands in .tmp/autopilot/ — run log (autopilot.jsonl), state.json
//      (coverage, last sweep, launches, refusals), sweep copies, WP-lane hunt reports,
//      and a daily digest digest-YYYY-MM-DD.md (what ran, what found, what was refused
//      and why). .tmp is deliverables — the autopilot never deletes, only appends.
//
//   node tools/autopilot.mjs run [--once] [--interval h] [--dry]
//
// ENV: VARVEL_AUTOPILOT_INTERVAL_H (default 4) · VARVEL_AUTOPILOT_DIR (.tmp/autopilot)
//   VARVEL_AUTOPILOT_API (http://127.0.0.1:8971 — loopback enforced regardless)
//   VARVEL_AUTOPILOT_CORPUS (CSV of corpus roots; default the two varvel-kimi trees)
//   VARVEL_AUTOPILOT_WP_MAX_PER_CYCLE (20) · VARVEL_AUTOPILOT_ADJUDICATE_TOP (5)
//   VARVEL_AUTOPILOT_MESSAGE_WAIT_MS (1800000) · VARVEL_AUTOPILOT_LAUNCH=off (launcher off)

import { readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sweep as widereconSweep, PROHIBITED_PROGRAMS } from './widerecon.mjs';
import { liveSource, scan as commitwatchScan, DOCTRINE as COMMITWATCH_DOCTRINE } from './commitwatch.mjs';
import { privemap } from './privemap.mjs';
import { reachproveRescore } from './reachprove.mjs';
import { CADENCE_MAP, loadProgram, verifyScopeFixture } from '../engine/bountyline.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
const VARVEL_ROOT = join(__dir, '..');

// --- configuration (env-overridable; evaluated at call time so tests isolate) --------------
const DIR = () => process.env.VARVEL_AUTOPILOT_DIR || join(VARVEL_ROOT, '.tmp', 'autopilot');
const TMP_ROOT = () => join(VARVEL_ROOT, '.tmp');
const API = () => process.env.VARVEL_AUTOPILOT_API || 'http://127.0.0.1:8971';
const INTERVAL_H = () => Number(process.env.VARVEL_AUTOPILOT_INTERVAL_H) || 4;
const CORPUS_DIRS = () => (process.env.VARVEL_AUTOPILOT_CORPUS
  ? process.env.VARVEL_AUTOPILOT_CORPUS.split(',').map((s) => s.trim()).filter(Boolean)
  : [join(VARVEL_ROOT, '..', '..', 'varvel-kimi', 'research', 'wp-plugin-corpus'), join(VARVEL_ROOT, '..', '..', 'varvel-kimi', 'research', 'wp-plugin-corpus-2')]);
const WP_MAX_PER_CYCLE = () => Number(process.env.VARVEL_AUTOPILOT_WP_MAX_PER_CYCLE) || 20;
const ADJUDICATE_TOP = () => Number(process.env.VARVEL_AUTOPILOT_ADJUDICATE_TOP) || 5;
const MESSAGE_WAIT_MS = () => Number(process.env.VARVEL_AUTOPILOT_MESSAGE_WAIT_MS) || 1800000;
const LAUNCH_ENABLED = () => process.env.VARVEL_AUTOPILOT_LAUNCH !== 'off';

export const LOOPBACK_HOSTS = ['127.0.0.1', 'localhost', '::1', '[::1]'];
// HARD-EXCLUDED from campaign launches, in code (Jack's rule: visa is never auto-launched;
// the widerecon PROHIBITED_PROGRAMS pin rides along — belt-and-braces over roster policy).
export const LAUNCH_EXCLUDED_PROGRAMS = ['visa', ...PROHIBITED_PROGRAMS];
// The console's ONE campaign global is replaced by POST /api/campaign unconditionally —
// these are the ONLY /api/state statuses where replacing it clobbers nothing running.
export const LAUNCHABLE_STATUSES = ['idle', 'interactive', 'done'];
const STATE_RINGS = { launches: 100, refusals: 200, adjudications: 100, pending: 50, knownLeadKeys: 400 };
const BRIEF_CAP = 3900; // the server slices /api/message text at 4000 — stay under, honestly

// --- small persisted-store helpers (the store.mjs discipline: readJson fallback, write-through) ---
const readJson = (p, fb) => { try { return existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : fb; } catch { return fb; } };
const writeJson = (p, obj) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(obj, null, 2) + '\n'); };
const iso = (now) => (now === undefined ? new Date().toISOString() : (typeof now === 'number' ? new Date(now).toISOString() : String(now)));
const stamp = (at) => String(at).replace(/[-:]/g, '').replace('T', '-').replace(/\..*$/, '').slice(0, 15);
const realSleep = (ms) => new Promise((r) => setTimeout(r, ms));
const SLUG_RE = /^[a-z0-9][a-z0-9._-]{0,127}$/i;
const slugOf = (name) => { const s = String(name || '').toLowerCase(); return SLUG_RE.test(s) ? s : null; };

// --- the console client (loopback-only by RULE 1) ---------------------------------------------
// consoleReq(method, path, body, { api, fetchImpl }) → { ok, status, json } | { ok:false, error, reason }.
// NEVER throws; the host allowlist is enforced HERE, before any request is built — the
// autopilot's own network is the loopback console and nothing else.
export async function consoleReq(method, path, body, { api, fetchImpl, timeoutMs = 30000 } = {}) {
  let u;
  try { u = new URL(path, api || API()); } catch { return { ok: false, error: 'bad-url', reason: `'${path}' did not parse against ${api || API()}` }; }
  if (!LOOPBACK_HOSTS.includes(u.hostname)) {
    return { ok: false, error: 'console-host-not-allowed', reason: `refused ${u.host} — the autopilot talks to the loopback console ONLY (${LOOPBACK_HOSTS.join(', ')}); no request was sent` };
  }
  let res;
  try {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), timeoutMs);
    try {
      res = await (fetchImpl || fetch)(u, {
        method,
        headers: { accept: 'application/json', ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        signal: ac.signal,
      });
    } finally { clearTimeout(t); }
  } catch (e) {
    return { ok: false, error: 'console-unreachable', reason: `${method} ${u} failed (${(e && e.message) || e}) — is the console server up (npm run serve)? Nothing was fabricated` };
  }
  let json = null;
  try { json = await res.json(); } catch (e) { return { ok: false, error: 'console-bad-response', status: res.status, reason: `${method} ${u} answered HTTP ${res.status} with an unparseable body (${(e && e.message) || e})` }; }
  if (!res.ok) return { ok: false, error: 'console-http-error', status: res.status, json, reason: `${method} ${u} answered HTTP ${res.status}` };
  return { ok: true, status: res.status, json };
}

// --- state -------------------------------------------------------------------------------------
const EMPTY_STATE = () => ({
  version: 1, cycles: 0, createdAt: null, lastCycleAt: null,
  prevSweep: { at: null, programs: [], catches: [] },
  commitwatch: { knownLeadKeys: [] },
  wp: { covered: {}, pending: [] },
  launches: [], refusals: [], adjudications: [],
});
export function loadState(dir) {
  const st = readJson(join(dir || DIR(), 'state.json'), null);
  if (!st || typeof st !== 'object' || st.version !== 1) return EMPTY_STATE();
  return { ...EMPTY_STATE(), ...st, wp: { covered: {}, pending: [], ...(st.wp || {}) }, commitwatch: { knownLeadKeys: [], ...(st.commitwatch || {}) } };
}
export function saveState(st, dir) {
  writeJson(join(dir || DIR(), 'state.json'), st);
}
function ring(list, item, cap) { return [...(Array.isArray(list) ? list : []), item].slice(-cap); }
function logEvent(dir, evt) {
  try { mkdirSync(dir, { recursive: true }); appendFileSync(join(dir, 'autopilot.jsonl'), JSON.stringify({ at: iso(), ...evt }) + '\n'); } catch { /* the log never breaks the cycle */ }
}

// --- sweep diffing (pure) ----------------------------------------------------------------------
const catchKey = (c) => `${c.program}|${c.host}`;
// diffSweeps(prevCatches, curCatches) → { added, removed, scoreChanged } — the cycle delta.
export function diffSweeps(prev, cur) {
  const byKey = new Map((Array.isArray(prev) ? prev : []).map((c) => [catchKey(c), c]));
  const seen = new Set();
  const added = []; const scoreChanged = [];
  for (const c of Array.isArray(cur) ? cur : []) {
    const k = catchKey(c);
    seen.add(k);
    const old = byKey.get(k);
    if (!old) added.push({ program: c.program, host: c.host, score: c.score, kinds: c.kinds || [] });
    else if (Number(old.score) !== Number(c.score)) scoreChanged.push({ program: c.program, host: c.host, from: old.score, to: c.score });
  }
  const removed = [...byKey.entries()].filter(([k]) => !seen.has(k)).map(([, c]) => ({ program: c.program, host: c.host, score: c.score }));
  return { added, removed, scoreChanged };
}
// slimCatches(catches) — what the state file carries forward (score diffs need program/host/score only).
const slimCatches = (catches) => (Array.isArray(catches) ? catches : []).map((c) => ({ program: c.program, host: c.host, score: c.score, kinds: c.kinds || [] }));
// programsForLaunch(report) — the launcher input: one row per swept program with its best catch score.
export function programsForLaunch(report) {
  const top = new Map();
  for (const c of (report && report.catches) || []) {
    const cur = top.get(c.program) || 0;
    if (Number(c.score) > cur) top.set(c.program, Number(c.score));
  }
  return ((report && report.programs) || []).map((p) => ({
    program: p.program, automation: p.automation, status: p.status, topScore: top.get(p.program) || 0,
  }));
}

// --- WP-lane coverage (pure-ish; local reads only) ----------------------------------------------
// corpusPlugins(corpusDirs) → [{ slug, dir }] — one entry per plugin tree (directories only).
export function corpusPlugins(corpusDirs) {
  const out = [];
  for (const root of Array.isArray(corpusDirs) ? corpusDirs : []) {
    let names;
    try { names = readdirSync(root); } catch { continue; }
    for (const n of names) {
      const slug = slugOf(n);
      if (!slug) continue;
      try { if (!statSync(join(root, n)).isDirectory()) continue; } catch { continue; }
      out.push({ slug, dir: join(root, n) });
    }
  }
  return out.sort((a, b) => a.slug.localeCompare(b.slug));
}
// coveredSlugs({ tmpRoot, ownHuntDir }) → Set of slugs that ALREADY have a privemap hunt
// report: historical .tmp/hunt-*/privemap/<slug>.json ∪ the autopilot's own hunt dir.
export function coveredSlugs({ tmpRoot, ownHuntDir } = {}) {
  const covered = new Set();
  const scan = (dir) => {
    let names;
    try { names = readdirSync(dir); } catch { return; }
    for (const n of names) { const m = /^(.+)\.json$/.exec(n); if (m && slugOf(m[1])) covered.add(slugOf(m[1])); }
  };
  let tmpEntries = [];
  try { tmpEntries = readdirSync(tmpRoot || TMP_ROOT()); } catch { tmpEntries = []; }
  for (const e of tmpEntries) {
    if (!/^hunt-/.test(e)) continue;
    scan(join(tmpRoot || TMP_ROOT(), e, 'privemap'));
  }
  scan(ownHuntDir || join(DIR(), 'hunt', 'privemap'));
  return covered;
}

// --- adjudication candidates (pure) --------------------------------------------------------------
const REACH_OK = new Set(['unauth', 'subscriber']);
const REACH_PROVEN_OK = new Set(['UNAUTH', 'SUBSCRIBER']);
// selectAdjudicationCandidates(perSlug, topN) — perSlug: [{ slug, privemap, rescore }].
// Keeps reachprove CONFIRMED|UNCERTAIN results at unauth/subscriber reach (claimed OR
// proven), drops doctrine-gated dead classes (privemap marked them read-only-probe-only;
// the doctrine never files them), ranks by penalized newScore. Every kept row cites its
// evidence (ref + reason); UNKNOWN stays named UNKNOWN.
export function selectAdjudicationCandidates(perSlug, topN) {
  const rows = [];
  for (const { slug, privemap: pm, rescore: rs } of Array.isArray(perSlug) ? perSlug : []) {
    const gatedRefs = new Set(((pm && pm.candidates) || []).filter((c) => c.doctrineGated).map((c) => c.ref));
    const clsByRef = new Map(((pm && pm.candidates) || []).map((c) => [c.ref, c.impactClass]));
    for (const r of (rs && rs.results) || []) {
      if (r.verdict !== 'CONFIRMED' && r.verdict !== 'UNCERTAIN') continue;
      if (!REACH_OK.has(String(r.privemapReach)) && !REACH_PROVEN_OK.has(String(r.provenReach))) continue;
      if (gatedRefs.has(r.ref)) continue;
      rows.push({
        slug, ref: r.ref, title: r.title, impactClass: clsByRef.get(r.ref) || null,
        verdict: r.verdict, privemapReach: r.privemapReach, provenReach: r.provenReach,
        score: r.privemapScore, newScore: r.newScore, reason: r.reason,
      });
    }
  }
  rows.sort((a, b) => (b.newScore - a.newScore) || a.slug.localeCompare(b.slug) || String(a.ref).localeCompare(String(b.ref)));
  return rows.slice(0, Math.max(1, Number(topN) || ADJUDICATE_TOP()));
}

// buildAdjudicationBrief(cands, { at, corpusDirs }) → { text, included, dropped } — the ONE
// brief per cycle. Under the server's 4000-char receipt cap; overflow candidates are
// honestly dropped-and-counted (they ride the pending queue to the next cycle).
export function buildAdjudicationBrief(cands, { at, corpusDirs } = {}) {
  const head = [
    `[AUTOPILOT — WP-lane adjudication request · ${at || iso()}]`,
    'The autopilot swept NEW corpus plugins with privemap + reachprove (static, offline — NOTHING was probed; reports under .tmp/autopilot/hunt/). Adjudicate these top candidates: for each, READ the named tree and answer CONFIRM (reachable + filing-grade per the scope doctrine) / PARK (real but not filing-grade — name why) / KILL (dead — name the gate), citing file:line. REVIEW-ONLY: never file, never submit, never contact a target — your verdicts are read by the operator in this chat.',
    '',
  ].join('\n');
  const foot = `\n\nTrees: ${(corpusDirs || []).join(' , ')}. privemap/reachprove JSON per slug: .tmp/autopilot/hunt/{privemap,reachprove}/<slug>.json.`;
  const lines = [];
  let dropped = 0;
  for (let i = 0; i < (cands || []).length; i++) {
    const c = cands[i];
    const line = `${i + 1}. ${c.slug} — ${c.impactClass || 'UNKNOWN-class'} @ ${c.ref} [privemap ${c.privemapReach} score ${c.score} → reachprove ${c.verdict} (proven ${c.provenReach}) newScore ${c.newScore}]\n   "${String(c.title || '').slice(0, 140)}"\n   reason: ${String(c.reason || 'UNKNOWN').slice(0, 220)}`;
    const candidate = [...lines, line].join('\n');
    if ((head + candidate + foot).length > BRIEF_CAP) { dropped = cands.length - i; break; }
    lines.push(line);
  }
  const text = head + lines.join('\n') + (dropped ? `\n(+${dropped} more queued candidate(s) — next cycle's brief)` : '') + foot;
  return { text, included: lines.length, dropped };
}

// --- the launch decision (pure — every gate named, every refusal returned) ----------------------
// planLaunch({ sweepPrograms, ghost, campaignStatus, lastLaunched, launchEnabled, loadProgramImpl,
//              readScopeImpl, targetsByProgram }) → { decision, reason?, refusals, notes, candidate? }.
// sweepPrograms: programsForLaunch() rows. ghost: GET /api/ghost's json (null = unreadable).
// NEVER throws; a refusal is a first-class result, logged by the caller.
export function planLaunch({
  sweepPrograms, ghost, campaignStatus, lastLaunched, launchEnabled = true,
  loadProgramImpl = loadProgram, readScopeImpl = (p) => readJson(resolve(VARVEL_ROOT, p), null),
  targetsByProgram = {},
} = {}) {
  const refusals = [];
  const notes = [];
  const refuse = (kind, reason, program) => { refusals.push({ kind, program: program || null, reason }); };
  if (!launchEnabled) {
    return { decision: 'skip', reason: 'launcher disabled (VARVEL_AUTOPILOT_LAUNCH=off)', refusals, notes, candidate: null };
  }
  // GHOST GATE (rule 3) — off or unverified = every launch refused, loudly.
  if (!ghost || typeof ghost !== 'object') {
    refuse('ghost-status-unknown', 'GET /api/ghost did not answer with a status — launching blind is never allowed; refusing ALL launches this cycle');
    return { decision: 'refuse', reason: refusals[0].reason, refusals, notes, candidate: null };
  }
  if (ghost.mode === 'off') {
    refuse('ghost-off', 'Ghost Mode is OFF — a launch would expose the operator\'s real source to the target. REFUSED (arm ghost via /api/ghost, then the next cycle launches)');
    return { decision: 'refuse', reason: refusals[0].reason, refusals, notes, candidate: null };
  }
  if (!ghost.verified || ghost.verified.ok !== true) {
    refuse('ghost-unverified', `Ghost Mode is ${ghost.mode} but the exit-IP proof has NOT passed (verified: ${ghost.verified ? (ghost.verified.error || 'pending') : 'absent'}) — REFUSED: the autopilot never launches on an unverified chain`);
    return { decision: 'refuse', reason: refusals[0].reason, refusals, notes, candidate: null };
  }
  // CAMPAIGN GATE (rule 4) — the server has ONE campaign global; never clobber a running one.
  const status = String(campaignStatus || 'unknown');
  if (!LAUNCHABLE_STATUSES.includes(status)) {
    return { decision: 'skip', reason: `campaign busy — /api/state status is '${status}' (launchable only on ${LAUNCHABLE_STATUSES.join('|')}); the running campaign is never clobbered`, refusals, notes, candidate: null };
  }
  // CANDIDATES — swept programs, ranked by their best catch score (0 = no catch: still
  // eligible, ranked last; the campaign does its own recon).
  const ranked = (Array.isArray(sweepPrograms) ? sweepPrograms : [])
    .filter((p) => p && p.status === 'SWEPT')
    .sort((a, b) => (b.topScore - a.topScore) || String(a.program).localeCompare(String(b.program)));
  const eligible = [];
  for (const p of ranked) {
    const id = String(p.program);
    if (LAUNCH_EXCLUDED_PROGRAMS.includes(id.toLowerCase())) {
      refuse('program-hard-excluded', `${id} is HARD-EXCLUDED from autopilot launches (LAUNCH_EXCLUDED_PROGRAMS — Jack's visa rule + the widerecon prohibited pin) — never launched, hunt it by hand`, id);
      continue;
    }
    if (p.automation === 'prohibited') { // belt #2 — SKIPPED-POLICY programs never get here, the check stands anyway
      refuse('automation-prohibited', `${id}: the sweep's policy verdict is prohibited — zero launches`, id);
      continue;
    }
    const rec = loadProgramImpl(id);
    if (!rec) {
      refuse('no-program-record', `${id}: no bountyline record at data/bountyline/programs/${id}.json — the pipeline owns imports; not launching from recon alone`, id);
      continue;
    }
    const policy = rec.automation && rec.automation.policy;
    if (policy === 'prohibited') {
      refuse('automation-prohibited', `${id}: bountyline automation policy is 'prohibited' (${rec.automation.basis}: ${String(rec.automation.evidence || '').slice(0, 120)}) — no campaign is scheduled or run against this program`, id);
      continue;
    }
    if (policy !== 'full' && policy !== 'human-cadence') {
      refuse('automation-unknown', `${id}: bountyline automation policy '${policy}' is not full|human-cadence — UNKNOWN policies never launch`, id);
      continue;
    }
    if (!rec.signedScopePath) {
      refuse('no-signed-scope', `${id}: no signed scope on record — sign the normalized scope (program import --sign) and record it (bountyline add/run --scope); automation never runs unscoped`, id);
      continue;
    }
    const fx = readScopeImpl(rec.signedScopePath);
    const cidrs = fx && typeof fx.engagementScope === 'string' ? fx.engagementScope.split(',').map((s) => s.trim()).filter(Boolean) : [];
    if (!fx || !cidrs.length) {
      refuse('no-signed-scope', `${id}: the signed scope at ${rec.signedScopePath} is unreadable or carries an EMPTY engagementScope — refusing to launch unscoped`, id);
      continue;
    }
    eligible.push({ id, rec, policy, scopeFx: fx, cidrs, topScore: p.topScore });
  }
  if (!eligible.length) {
    return { decision: 'skip', reason: `no eligible program (${refusals.length ? 'every candidate refused — see refusals' : 'no program was SWEPT this cycle'})`, refusals, notes, candidate: null };
  }
  // ROTATION — the same top program every cycle starves the roster: if the last launch
  // was the top candidate and another eligible program exists, take the next one (it
  // rotates back in on a later cycle; nothing is skipped silently).
  let pick = eligible[0];
  if (lastLaunched && eligible.length > 1 && pick.id === lastLaunched) {
    pick = eligible[1];
    notes.push(`rotation: ${eligible[0].id} launched most recently — ${pick.id} takes this cycle (breadth over the roster; nothing starved)`);
  }
  const cadence = CADENCE_MAP[pick.policy] || {};
  const extraHeaders = (pick.rec.extraHeaders && typeof pick.rec.extraHeaders === 'object' && !Array.isArray(pick.rec.extraHeaders)) ? pick.rec.extraHeaders
    : (pick.rec.attestationHeaders && typeof pick.rec.attestationHeaders === 'object' && !Array.isArray(pick.rec.attestationHeaders)) ? pick.rec.attestationHeaders : null;
  const body = {
    mode: 'live',
    scope: {
      engagement: pick.rec.engagement || pick.scopeFx.workspace || pick.id,
      signedBy: pick.scopeFx.principal || null,
      cidrs: pick.cidrs,
    },
    targets: (targetsByProgram[pick.id] || []).slice(0, 10),
    ...JSON.parse(JSON.stringify(cadence)),
    // Chained/autonomous launches park HITL-gated phases for the operator INDEFINITELY
    // (the 2026-08-29 bykea lesson — a 15-min default let a phase die unattended).
    approveTimeoutMs: 0,
    carryForward: true, // inherit the persisted engagement surface — a restart never wipes earned findings
    ...(extraHeaders ? { extraHeaders } : {}),
  };
  return {
    decision: 'launch',
    refusals,
    notes: [...notes, pick.policy === 'human-cadence'
      ? 'human-cadence ceiling FORCED (CADENCE_MAP: stealth paranoid, maxSteps 50, crawl 5 pages, vuln 3 probes)'
      : 'automation full — the engagement settings floor governs; the pipeline adds no ceiling'],
    candidate: { id: pick.id, rec: pick.rec, policy: pick.policy, scopePath: pick.rec.signedScopePath, cidrs: pick.cidrs, topScore: pick.topScore, body },
  };
}

// --- the digest -----------------------------------------------------------------------------------
function appendDigest(dir, at, lines) {
  const date = String(at).slice(0, 10);
  const file = join(dir, `digest-${date}.md`);
  mkdirSync(dir, { recursive: true });
  if (!existsSync(file)) writeFileSync(file, `# VARVEL autopilot digest — ${date}\n\n> What ran, what found, what was refused and why. Detail: autopilot.jsonl + state.json in this directory. The autopilot NEVER submits and NEVER files — findings surface here for the operator.\n`);
  appendFileSync(file, `\n## Cycle ${String(at).slice(11, 16)} UTC\n\n${lines.join('\n')}\n`);
}

// --- ONE CYCLE --------------------------------------------------------------------------------------
// runCycle(opts) — (a) widerecon sweep + diff, (b) commitwatch live scan, (c) WP-lane
// sweep of NEW corpus plugins + ONE adjudication brief, (d) the gated campaign launch.
// Every phase's failure is recorded and the cycle continues; the state file is
// write-through after every phase. With dry:true NOTHING is written and NO request is
// made — the plan is computed from the state on record (UNKNOWNs named).
export async function runCycle({
  now, dry = false,
  dir = DIR(), api = API(), tmpRoot = TMP_ROOT(), corpusDirs = CORPUS_DIRS(),
  wpMaxPerCycle = WP_MAX_PER_CYCLE(), adjudicateTop = ADJUDICATE_TOP(),
  messageWaitMs = MESSAGE_WAIT_MS(), pollMs = 15000, launchEnabled = LAUNCH_ENABLED(),
  fetchImpl, sleepImpl = realSleep, log = () => {},
  sweepImpl, commitScanImpl, privemapImpl, reachproveRescoreImpl,
  loadProgramImpl, verifyScopeImpl, readScopeImpl, shouldStop,
} = {}) {
  const at = iso(now);
  const st = loadState(dir);
  if (!st.createdAt) st.createdAt = at;
  const say = (line) => { log(line); if (!dry) logEvent(dir, { type: 'line', line }); };
  const event = (type, o) => { if (!dry) logEvent(dir, { type, ...o }); };
  const stopped = () => (typeof shouldStop === 'function' ? !!shouldStop() : false);
  const cycle = { at, dry, steps: [], refusals: [], errors: [], partial: false };
  const recordRefusal = (r) => {
    cycle.refusals.push(r);
    if (!dry) st.refusals = ring(st.refusals, { at, ...r }, STATE_RINGS.refusals);
    event('refusal', r);
    say(`  REFUSED [${r.kind}]${r.program ? ' ' + r.program : ''} — ${r.reason}`);
  };
  const stopIfAsked = (phase) => { if (stopped()) { cycle.partial = true; cycle.steps.push(`${phase}: skipped — stop requested (SIGINT/SIGTERM); the state on disk is consistent through the previous phase`); } return cycle.partial; };

  say(`[autopilot] cycle ${at}${dry ? ' (DRY — plan only; nothing written, nothing requested)' : ''}`);

  // (a) WIDERECON SWEEP + DELTA -------------------------------------------------------------------
  let sweepReport = null;
  if (dry) {
    cycle.steps.push(st.prevSweep.at
      ? `widerecon: DRY — would re-sweep the roster (last sweep ${st.prevSweep.at}: ${st.prevSweep.programs.length} programs, ${st.prevSweep.catches.length} catches)`
      : 'widerecon: DRY — would run the FIRST roster sweep (no sweep on record; the launch plan below is computed without catch scores)');
    sweepReport = st.prevSweep.at ? { programs: st.prevSweep.programs, catches: st.prevSweep.catches } : null;
  } else {
    try {
      sweepReport = await (sweepImpl ? sweepImpl({ onLog: (t, o) => event(t, o) }) : widereconSweep({ onLog: (t, o) => event(t, o) }));
      const delta = diffSweeps(st.prevSweep.catches, sweepReport.catches);
      writeJson(join(dir, 'sweeps', `widerecon-${stamp(at)}.json`), sweepReport);
      st.prevSweep = { at, programs: programsForLaunch(sweepReport), catches: slimCatches(sweepReport.catches) };
      st.lastSweepAt = at;
      cycle.steps.push(`widerecon: ${sweepReport.stats.swept}/${sweepReport.stats.programs} programs swept · ${sweepReport.stats.hosts} hosts · ${sweepReport.stats.catches} catches · Δ +${delta.added.length} new / −${delta.removed.length} gone / ~${delta.scoreChanged.length} rescored`);
      if (sweepReport.skippedPolicy.length) cycle.steps.push(`widerecon SKIPPED-POLICY (zero requests): ${sweepReport.skippedPolicy.map((s) => s.program).join(', ')}`);
      for (const a of delta.added.slice(0, 10)) cycle.steps.push(`  NEW catch: ${a.program} ${a.host} (score ${a.score}${a.kinds.length ? ', ' + a.kinds.join(',') : ''})`);
      if (delta.added.length > 10) cycle.steps.push(`  … and ${delta.added.length - 10} more new catches (see the sweep json)`);
      for (const r of delta.removed.slice(0, 5)) cycle.steps.push(`  GONE: ${r.program} ${r.host} (was score ${r.score}) — the surface changed; recorded, not alarmed`);
      for (const s of delta.scoreChanged.slice(0, 5)) cycle.steps.push(`  RESCORED: ${s.program} ${s.host} ${s.from} → ${s.to}`);
      event('widerecon.done', { programs: sweepReport.stats.programs, swept: sweepReport.stats.swept, hosts: sweepReport.stats.hosts, catches: sweepReport.stats.catches, added: delta.added.length, removed: delta.removed.length, rescored: delta.scoreChanged.length, skippedPolicy: sweepReport.skippedPolicy.map((s) => s.program) });
    } catch (e) {
      cycle.errors.push(`widerecon: ${String((e && e.message) || e).slice(0, 200)} — the sweep failed; the previous sweep stays on record (nothing fabricated)`);
      event('widerecon.error', { error: String((e && e.message) || e).slice(0, 300) });
      sweepReport = st.prevSweep.at ? { programs: st.prevSweep.programs, catches: st.prevSweep.catches } : null;
    }
    saveState(st, dir);
  }
  if (stopIfAsked('commitwatch')) return finishCycle();

  // (b) COMMITWATCH — the fix-commit watcher (leads are REVIEW-ONLY) ---------------------------------
  if (dry) {
    cycle.steps.push('commitwatch: DRY — would run the gated live scan (wordpress.org hosts only, read-only); ' + COMMITWATCH_DOCTRINE);
  } else {
    try {
      const scanRes = await (commitScanImpl ? commitScanImpl() : commitwatchScan({ source: liveSource({ allow: true }) }));
      if (!scanRes.ok) {
        cycle.errors.push(`commitwatch: ${scanRes.error} — ${String(scanRes.reason || '').slice(0, 160)}`);
        event('commitwatch.error', { error: scanRes.error });
      } else {
        const known = new Set(st.commitwatch.knownLeadKeys);
        const fresh = (scanRes.leads || []).filter((l) => !known.has(`${l.slug}@${l.revision}`));
        for (const l of scanRes.leads || []) known.add(`${l.slug}@${l.revision}`);
        st.commitwatch.knownLeadKeys = [...known].slice(-STATE_RINGS.knownLeadKeys);
        cycle.steps.push(`commitwatch: ${scanRes.scanned}/${scanRes.watched} plugins scanned · ${scanRes.changesets} changesets · ${fresh.length} NEW lead(s)${scanRes.errors && scanRes.errors.length ? ` · ${scanRes.errors.length} plugin error(s) (named in state)` : ''} — leads are REVIEW-ONLY`);
        for (const l of fresh.slice(0, 8)) cycle.steps.push(`  LEAD [${l.band} ${l.score}] r${l.revision} ${l.slug} — ${(l.classes || []).join(', ') || l.summary || 'see commitwatch report'}`);
        event('commitwatch.done', { scanned: scanRes.scanned, watched: scanRes.watched, newLeads: fresh.map((l) => `${l.slug}@${l.revision}`) });
      }
    } catch (e) {
      cycle.errors.push(`commitwatch: ${String((e && e.message) || e).slice(0, 200)} — scan failed; previous watcher state untouched`);
      event('commitwatch.error', { error: String((e && e.message) || e).slice(0, 300) });
    }
    saveState(st, dir);
  }
  if (stopIfAsked('wp-lane')) return finishCycle();

  // (c) WP LANE — privemap + reachprove over NEW corpus plugins, then ONE adjudication brief --------
  const corpus = corpusPlugins(corpusDirs);
  const covered = coveredSlugs({ tmpRoot, ownHuntDir: join(dir, 'hunt', 'privemap') });
  const freshPlugins = corpus.filter((p) => !covered.has(p.slug));
  if (dry) {
    cycle.steps.push(`WP lane: DRY — corpus ${corpus.length} plugin(s) over ${corpusDirs.length} root(s); covered by existing hunt reports: ${corpus.length - freshPlugins.length}; NEW (would sweep, cap ${wpMaxPerCycle}): ${freshPlugins.length ? freshPlugins.slice(0, wpMaxPerCycle).map((p) => p.slug).join(', ') : 'none'}${freshPlugins.length > wpMaxPerCycle ? ` … +${freshPlugins.length - wpMaxPerCycle} more next cycles` : ''}`);
    cycle.steps.push(`adjudication: DRY — pending queue ${st.wp.pending.length} candidate(s); would POST ONE brief to /api/message when the queue is non-empty and the chat agent is free`);
  } else {
    const swept = [];
    for (const p of freshPlugins.slice(0, wpMaxPerCycle)) {
      try {
        const pm = privemapImpl ? privemapImpl(p.dir) : privemap(p.dir);
        writeJson(join(dir, 'hunt', 'privemap', `${p.slug}.json`), pm);
        const rs = reachproveRescoreImpl ? reachproveRescoreImpl(p.dir, pm) : reachproveRescore(p.dir, pm);
        writeJson(join(dir, 'hunt', 'reachprove', `${p.slug}.json`), rs);
        st.wp.covered[p.slug] = { at, dir: p.dir, privemap: join(dir, 'hunt', 'privemap', `${p.slug}.json`), reachprove: join(dir, 'hunt', 'reachprove', `${p.slug}.json`), candidates: (pm.candidates || []).length, verdicts: rs.summary || null };
        swept.push({ slug: p.slug, privemap: pm, rescore: rs });
        event('wp.swept', { slug: p.slug, candidates: (pm.candidates || []).length, summary: rs.summary || null });
      } catch (e) {
        cycle.errors.push(`WP lane ${p.slug}: ${String((e && e.message) || e).slice(0, 160)} — plugin skipped; NOT marked covered (a failed sweep is not coverage)`);
        event('wp.error', { slug: p.slug, error: String((e && e.message) || e).slice(0, 300) });
      }
    }
    if (freshPlugins.length > wpMaxPerCycle) cycle.steps.push(`WP lane: ${freshPlugins.length - wpMaxPerCycle} new plugin(s) remain queued for later cycles (per-cycle cap ${wpMaxPerCycle})`);
    const newCands = selectAdjudicationCandidates(swept, 50);
    // The pending queue: previously-unadjudicated candidates + this cycle's, deduped by slug|ref.
    const seen = new Set();
    const queue = [...st.wp.pending, ...newCands].filter((c) => { const k = `${c.slug}|${c.ref}`; if (seen.has(k)) return false; seen.add(k); return true; })
      .sort((a, b) => (b.newScore - a.newScore) || a.slug.localeCompare(b.slug));
    st.wp.pending = queue.slice(0, STATE_RINGS.pending);
    cycle.steps.push(`WP lane: ${swept.length} new plugin(s) swept (${swept.map((s) => s.slug).join(', ') || 'none'} — corpus ${corpus.length}, covered ${covered.size}) · ${newCands.length} adjudication-grade candidate(s) · queue depth ${st.wp.pending.length}`);
    // THE ONE BRIEF — serialized: busy chat = deferred, never interleaved.
    if (st.wp.pending.length && !stopIfAsked('adjudication')) {
      const brief = buildAdjudicationBrief(st.wp.pending.slice(0, adjudicateTop), { at, corpusDirs });
      const r = await consoleReq('POST', '/api/message', { text: brief.text }, { api, fetchImpl });
      if (!r.ok) {
        cycle.errors.push(`adjudication: ${r.error} — ${String(r.reason || '').slice(0, 140)} · the queue KEEPS its ${st.wp.pending.length} candidate(s)`);
        event('adjudication.error', { error: r.error });
      } else if (r.json && r.json.busy) {
        cycle.steps.push(`adjudication: DEFERRED — the chat agent is mid-turn (one turn at a time); the ${st.wp.pending.length} queued candidate(s) ride to the next cycle`);
        event('adjudication.deferred', { reason: 'chat-busy', queued: st.wp.pending.length });
      } else if (!r.json || !r.json.thinking) {
        cycle.steps.push('adjudication: no model backend attached to the console — the brief was received but no agent will read it; queue kept, named honestly');
        event('adjudication.no-agent', { queued: st.wp.pending.length });
      } else {
        event('adjudication.posted', { included: brief.included, dropped: brief.dropped });
        // Wait for completion (rule: serialized) — poll /api/state until the agent is done.
        const deadline = Date.now() + messageWaitMs;
        let done = false;
        while (Date.now() < deadline && !stopped()) {
          await sleepImpl(pollMs);
          const s = await consoleReq('GET', '/api/state', undefined, { api, fetchImpl });
          if (s.ok && s.json && s.json.agentThinking === false) { done = true; break; }
        }
        const briefed = new Set(st.wp.pending.slice(0, brief.included).map((c) => `${c.slug}|${c.ref}`));
        if (done) {
          st.wp.pending = st.wp.pending.filter((c) => !briefed.has(`${c.slug}|${c.ref}`));
          st.adjudications = ring(st.adjudications, { at, candidates: [...briefed], status: 'completed' }, STATE_RINGS.adjudications);
          cycle.steps.push(`adjudication: brief posted (${brief.included} candidate(s)${brief.dropped ? `, ${brief.dropped} queued for next cycle` : ''}) — the agent COMPLETED; verdicts live in the console chat for the operator`);
          event('adjudication.completed', { candidates: [...briefed] });
        } else {
          st.adjudications = ring(st.adjudications, { at, candidates: [...briefed], status: stopped() ? 'interrupted' : 'timeout' }, STATE_RINGS.adjudications);
          cycle.steps.push(`adjudication: brief posted but the agent did not finish within ${Math.round(messageWaitMs / 60000)}min — the queue KEEPS the candidates (nothing assumed about the verdicts)`);
          event('adjudication.timeout', { candidates: [...briefed] });
        }
      }
    }
    saveState(st, dir);
  }
  if (stopIfAsked('campaign-launch')) return finishCycle();

  // (d) THE CAMPAIGN LAUNCHER — ghost-gated, one at a time, prohibited named, visa hard-excluded ----
  const sweepPrograms = sweepReport ? (sweepReport.programs || []).map((p) => (p.topScore !== undefined ? p : { program: p.program, automation: p.automation, status: p.status, topScore: Math.max(0, ...((sweepReport.catches || []).filter((c) => c.program === p.program).map((c) => Number(c.score) || 0)), 0) })) : [];
  const targetsByProgram = {};
  for (const c of (sweepReport && sweepReport.catches) || []) (targetsByProgram[c.program] = targetsByProgram[c.program] || []).push(c.host);
  if (dry) {
    // DRY launch plan: the runtime gates (ghost, campaign status) are UNKNOWN — named, not
    // queried. Eligibility IS computed (synthetic pass-gates) so the plan shows what WOULD
    // launch IF the gates pass, plus the standing per-program refusals.
    const decision = planLaunch({
      sweepPrograms, ghost: { mode: 'required', verified: { ok: true, exitIp: 'UNKNOWN-dry' } }, campaignStatus: 'idle',
      lastLaunched: (st.launches[st.launches.length - 1] || {}).program, launchEnabled, loadProgramImpl, readScopeImpl,
    });
    cycle.steps.push(`campaign: DRY — ghost/campaign status UNKNOWN (not queried); the gates are decided at run time (ghost-off/unverified = REFUSE, busy = SKIP). ${decision.refusals.length ? `Standing refusals: ${decision.refusals.map((r) => `[${r.kind}] ${r.program || ''}`).join('; ')}` : 'No standing per-program refusals.'}`);
    if (decision.candidate) cycle.steps.push(`  top candidate IF the gates pass: ${decision.candidate.id} (${decision.candidate.policy}, ${decision.candidate.cidrs.length} signed CIDRs, top catch score ${decision.candidate.topScore})`);
    else cycle.steps.push(`  no eligible candidate on record — ${decision.reason}`);
  } else {
    const ghostRes = await consoleReq('GET', '/api/ghost', undefined, { api, fetchImpl });
    const stateRes = await consoleReq('GET', '/api/state', undefined, { api, fetchImpl });
    const ghost = ghostRes.ok ? ghostRes.json : null;
    const campaignStatus = stateRes.ok ? String((stateRes.json && stateRes.json.status) || 'unknown') : 'unknown';
    if (!ghostRes.ok) cycle.errors.push(`ghost check: ${ghostRes.error} — ${String(ghostRes.reason || '').slice(0, 140)}`);
    if (!stateRes.ok) cycle.errors.push(`campaign status check: ${stateRes.error} — ${String(stateRes.reason || '').slice(0, 140)}`);
    const decision = planLaunch({
      sweepPrograms, ghost, campaignStatus,
      lastLaunched: (st.launches[st.launches.length - 1] || {}).program,
      launchEnabled, loadProgramImpl, readScopeImpl, targetsByProgram,
    });
    for (const r of decision.refusals) recordRefusal(r);
    for (const n of decision.notes) say(`  launch note: ${n}`);
    if (decision.decision === 'launch') {
      // The signed scope is re-verified HERE (shape + seam signature when importable); a
      // failure refuses the launch even after every other gate passed.
      const v = verifyScopeImpl ? await verifyScopeImpl(decision.candidate.scopePath) : await verifyScopeFixture(decision.candidate.scopePath);
      if (!v.ok) {
        recordRefusal({ kind: v.error || 'scope-verification-failed', program: decision.candidate.id, reason: `${decision.candidate.id}: ${String(v.reason || 'the signed scope failed verification').slice(0, 200)} — launch REFUSED` });
      } else {
        if (v.gap) say(`  scope verification: ${v.verification} — ${v.gap}`);
        const post = await consoleReq('POST', '/api/campaign', decision.candidate.body, { api, fetchImpl });
        if (!post.ok) {
          cycle.errors.push(`campaign launch ${decision.candidate.id}: ${post.error} — ${String(post.reason || '').slice(0, 160)}`);
          event('campaign.error', { program: decision.candidate.id, error: post.error });
        } else {
          st.launches = ring(st.launches, { at, program: decision.candidate.id, policy: decision.candidate.policy, engagement: post.json.engagement, status: post.json.status, scopeVerification: v.verification, targets: decision.candidate.body.targets.length, cidrs: decision.candidate.cidrs.length }, STATE_RINGS.launches);
          cycle.steps.push(`campaign: LAUNCHED ${decision.candidate.id} (${decision.candidate.policy}, ghost ${ghost.mode} verified exit ${ghost.verified.exitIp || 'UNKNOWN'}) — engagement '${post.json.engagement}', status '${post.json.status}' · ${decision.candidate.body.targets.length} seeded targets · HITL gates parked for the operator (approveTimeoutMs 0) · the campaign + validator own proving; progress via GET /api/state`);
          event('campaign.launched', { program: decision.candidate.id, policy: decision.candidate.policy, engagement: post.json.engagement, status: post.json.status });
        }
      }
    } else {
      cycle.steps.push(`campaign: ${decision.decision === 'refuse' ? 'REFUSED' : 'SKIPPED'} — ${decision.reason}`);
      event('campaign.skipped', { decision: decision.decision, reason: decision.reason });
    }
    saveState(st, dir);
  }

  return finishCycle();

  // ----
  function finishCycle() {
    if (!dry) {
      st.cycles += 1;
      st.lastCycleAt = at;
      saveState(st, dir);
      const lines = [
        ...cycle.steps.map((s) => `- ${s}`),
        ...(cycle.refusals.length ? [`- **REFUSALS (${cycle.refusals.length})**: ${cycle.refusals.map((r) => `[${r.kind}]${r.program ? ' ' + r.program : ''}`).join('; ')} — reasons in autopilot.jsonl`] : []),
        ...(cycle.errors.length ? [`- **ERRORS (${cycle.errors.length})**: ${cycle.errors.map((e) => e.split('—')[0].trim()).join('; ')}`] : []),
        ...(cycle.partial ? ['- PARTIAL CYCLE — stop requested mid-run; state consistent through the last completed phase'] : []),
      ];
      try { appendDigest(dir, at, lines); } catch { /* the digest never breaks the cycle */ }
      event('cycle.done', { steps: cycle.steps.length, refusals: cycle.refusals.length, errors: cycle.errors.length, partial: cycle.partial });
    }
    say(`[autopilot] cycle done — ${cycle.steps.length} step(s), ${cycle.refusals.length} refusal(s), ${cycle.errors.length} error(s)${cycle.partial ? ' · PARTIAL' : ''}`);
    return cycle;
  }
}

// --- the loop -----------------------------------------------------------------------------------
export async function runForever(opts = {}) {
  const intervalH = Number.isFinite(Number(opts.intervalH)) && Number(opts.intervalH) > 0 ? Number(opts.intervalH) : INTERVAL_H();
  const intervalMs = Math.round(intervalH * 3600000);
  const sleep = typeof opts.sleepImpl === 'function' ? opts.sleepImpl : realSleep;
  let stopped = false;
  const stop = () => { stopped = true; };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
  const log = typeof opts.log === 'function' ? opts.log : (l) => console.log(l);
  try {
    log(`[autopilot] run — interval ${intervalH}h (${Math.round(intervalMs / 60000)}min)${opts.once ? ' · --once: a single cycle' : ''}${opts.dry ? ' · DRY' : ''} · dir ${opts.dir || DIR()} · console ${opts.api || API()}`);
    while (!stopped) {
      await runCycle({ ...opts, shouldStop: () => stopped, log });
      if (opts.once) break;
      if (!stopped) {
        log(`[autopilot] sleeping ${intervalH}h — next cycle ${new Date(Date.now() + intervalMs).toISOString()} (SIGINT to stop)`);
        await sleep(intervalMs);
      }
    }
  } finally {
    process.off('SIGINT', stop);
    process.off('SIGTERM', stop);
  }
  return { stopped };
}

// --- CLI -----------------------------------------------------------------------------------------
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  const args = process.argv.slice(2);
  const cmd = args[0];
  const has = (name) => args.includes('--' + name);
  const opt = (name) => { const i = args.indexOf('--' + name); return i >= 0 ? args[i + 1] : null; };
  if (cmd !== 'run') {
    console.error('usage: node tools/autopilot.mjs run [--once] [--interval h] [--dry]');
    console.error('  run      loop forever: widerecon sweep+diff → commitwatch live → WP-lane privemap/reachprove of NEW corpus plugins → ONE adjudication brief → ghost-gated campaign launch');
    console.error('  --once   a single cycle, then exit');
    console.error('  --interval h   hours between cycles (default 4; env VARVEL_AUTOPILOT_INTERVAL_H)');
    console.error('  --dry    print the plan ONLY — nothing written, no requests (UNKNOWNs named)');
    process.exit(64);
  }
  const intervalH = opt('interval') !== null ? Number(opt('interval')) : undefined;
  if (intervalH !== undefined && (!Number.isFinite(intervalH) || intervalH <= 0)) {
    console.error(`--interval must be hours > 0 (got '${opt('interval')}') — refusing to guess`);
    process.exit(64);
  }
  if (has('dry')) {
    // The DRY contract: ONE planning pass — nothing written, no requests; the plan is
    // printed (log lines + the structured summary), UNKNOWNs named UNKNOWN.
    const cycle = await runCycle({ dry: true, log: (l) => console.log(l) });
    console.log(JSON.stringify({ dry: true, at: cycle.at, plan: cycle.steps, refusals: cycle.refusals, errors: cycle.errors }, null, 2));
    process.exit(0);
  }
  await runForever({ once: has('once'), intervalH, log: (l) => console.log(l) });
  process.exit(0);
}
