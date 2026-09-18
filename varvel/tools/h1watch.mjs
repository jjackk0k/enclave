// VARVEL — h1watch: the HackerOne opportunity watcher (the bounty pipeline's EYES).
// The bounty pipeline is offline-by-design (engine/bountyline.mjs carries NO network
// code, by doctrine) — this tool is how it sees: watch HackerOne's public program
// directory + each program's structured scope, DIFF what changed against the recorded
// state, rank the fresh ground, and turn it into operator-REVIEWABLE intake files in
// an outbox dir. The watcher NEVER signs and NEVER runs: outbox files wait for the
// operator to feed `program import` / `bountyline add` by hand.
//
// THE DOCTRINE LINE — carried on every output object, embedded in every outbox file,
// printed by every CLI sub-command:
//   "fresh ground found is an opportunity list, not authorization — scope must be
//    signed before any contact."
//
// HARD RULES:
//   1. NEVER auto-signs, NEVER auto-runs. This module imports NOTHING from
//      tools/program.mjs and ONLY deriveAutomation from engine/bountyline.mjs (the
//      automation-policy vocabulary, reused verbatim — never reimplemented regexes).
//      test/h1watch.test.mjs pins this with a static scan of this file.
//   2. HONESTY: API unreachable / credential absent / refused / rate-limited =>
//      a loud NAMED error ('h1-unreachable' | 'h1-token-missing' | 'h1-auth' |
//      'h1-rate-limited' | 'h1-http-error' | 'h1-bad-response') — program data is
//      NEVER fabricated. A program whose SCOPE fetch fails keeps its previous state:
//      a failed fetch is not an empty scope.
//   3. SAFE DIRECTION: policy text silent on automation derives 'prohibited' (basis
//      'default-silent') via deriveAutomation — the exact doctrine bountyline applies
//      at intake, so the watcher's hint and the pipeline's gate can never disagree.
//   4. TOKEN DOCTRINE: the credential comes from the env var NAMED VARVEL_H1_TOKEN
//      (the API identifier from VARVEL_H1_USER). This file carries the NAMES only;
//      the VALUE is read at call time into the Authorization header and is never
//      logged, persisted, or rendered.
//
// CONFIGURABLE CONSTANTS — THE ASSUMED H1 API SHAPE. Built WITHOUT internet access:
// these are the best-known documented shapes, kept behind the thin client layer so a
// live run that disagrees changes THIS TABLE, not the diff engine. Every assumption is
// ALSO recorded in gaps[] at scan time:
//   H1_API.BASE      'https://api.hackerone.com/v1' — H1's documented JSON:API root.
//   H1_API.DIRECTORY '/hackers/programs' — the HACKER namespace (confirmed live
//       2026-08-24: the program-manager /programs namespace 401s hacker credentials).
//       GET one page:
//       { data: [ { id, type:'program', attributes:{ handle, name, offers_bounties, … } } ],
//         links: { next } } — paginate by following links.next (absolute or relative).
//   H1_API.PROGRAM(handle) — GET one program's detail (policy, safe_harbor,
//       bounty_table, offers_bounties) as JSON:API attributes.
//   H1_API.SCOPES(handle) — GET the structured scopes:
//       { data: [ { attributes:{ asset_identifier, asset_type, eligible_for_submission,
//       eligible_for_bounty, instruction, max_severity } } ] } — the SAME field names
//       tools/program.mjs's hackerone adapter documents, so the emitted intake file IS
//       the adapter's input shape (the normalizer is fed, never duplicated).
//   AUTH: H1 documents HTTP Basic (identifier:token) — sent when VARVEL_H1_USER is set;
//       without it the token rides as a Bearer header and a gap says so (a 401 then
//       means: set the identifier env var too).
//   KNOWN UNCERTAINTY (no internet at build time): the exact directory endpoint, the
//       pagination parameter style, and whether structured scopes ride the program
//       detail or their own endpoint. The readers tolerate JSON:API AND plain shapes;
//       whatever they cannot parse lands EMPTY with a named gap — never guessed.

import { readFileSync, writeFileSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { deriveAutomation } from '../engine/bountyline.mjs';
import { resolveGhostChain, ghostFetch } from './ghostfetch.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));

export const H1_API = {
  BASE: 'https://api.hackerone.com/v1',
  // Hacker namespace confirmed live 2026-08-24: /v1/programs (the program-manager
  // namespace) answers 401 to hacker credentials; the hacker API lives under /hackers.
  DIRECTORY: '/hackers/programs',
  PROGRAM: (handle) => `/hackers/programs/${encodeURIComponent(handle)}`,
  SCOPES: (handle) => `/hackers/programs/${encodeURIComponent(handle)}/structured_scopes`,
  PAGE_SIZE: 100,
  MAX_PAGES: 50, // pagination safety cap — a runaway links.next loop is cut loudly
};
export const TOKEN_ENV = 'VARVEL_H1_TOKEN';
export const USER_ENV = 'VARVEL_H1_USER';
export const DOCTRINE = 'fresh ground found is an opportunity list, not authorization — scope must be signed before any contact.';
const EVENTS_CAP = 200; // the state ring keeps the newest 200 events

// Persistence root: varvel/data/h1watch (the bountyline ROOT() discipline), evaluated at
// call time so tests isolate via VARVEL_H1WATCH_DIR. Outbox default: <root>/outbox.
const ROOT = () => process.env.VARVEL_H1WATCH_DIR || join(__dir, '..', 'data', 'h1watch');
const STATE_FILE = () => join(ROOT(), 'state.json');
const OUTBOX = () => join(ROOT(), 'outbox');

// --- small persisted-store helpers (the store.mjs discipline: readJson fallback, write-through) ---
const readJson = (p, fb) => { try { return existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : fb; } catch { return fb; } };
const writeJson = (p, obj) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(obj, null, 2) + '\n'); };
const iso = (now) => (now === undefined ? new Date().toISOString() : (typeof now === 'number' ? new Date(now).toISOString() : String(now)));
const sha256 = (x) => 'sha256:' + createHash('sha256').update(typeof x === 'string' ? x : JSON.stringify(x)).digest('hex');

// --- the readers (pure; JSON:API AND plain shapes -> ONE canonical form) ----------------
// attrs: unwrap a JSON:API resource object ({ type, attributes }) or pass a plain object
// through — the ONE reader both shapes cross.
function attrs(node) {
  if (!node || typeof node !== 'object' || Array.isArray(node)) return {};
  if (node.attributes && typeof node.attributes === 'object' && !Array.isArray(node.attributes)) return { id: node.id, ...node.attributes };
  return node;
}

// parseDirectory(raw, gaps) -> { programs: [{ handle, name, offersBounties, url }], next }
// offersBounties is true | false | null (absent = UNKNOWN — never read as a promise of
// payment; scan names the gap). Entries without a handle are skipped, never invented.
export function parseDirectory(raw, gaps = []) {
  let list; let next = null;
  if (Array.isArray(raw)) list = raw;
  else if (raw && Array.isArray(raw.data)) { list = raw.data; next = (raw.links && raw.links.next) || null; }
  else if (raw && Array.isArray(raw.programs)) list = raw.programs;
  else { gaps.push('directory page arrived in an unrecognized shape — parsed as EMPTY (no programs invented); check H1_API.DIRECTORY against the live API'); list = []; }
  const programs = [];
  for (const node of list) {
    const a = attrs(node);
    if (!a.handle) { gaps.push('a directory entry carries no handle — skipped (never invented)'); continue; }
    programs.push({
      handle: String(a.handle),
      name: a.name || String(a.handle),
      offersBounties: a.offers_bounties === true ? true : (a.offers_bounties === false ? false : null),
      url: a.url || `https://hackerone.com/${a.handle}`,
    });
  }
  return { programs, next };
}

// docFromResponses(handle, programRaw, scopesRaw, gaps) -> the CANONICAL program doc —
// exactly the HackerOne structured-scope export shape tools/program.mjs's adapter
// documents ({ handle, name, url, policy, safe_harbor, bounty_table, structured_scopes })
// plus offers_bounties when the API said it. This is the shape the diff engine snapshots,
// the outbox emits, and program import consumes — one doc end to end, zero duplication.
export function docFromResponses(handle, programRaw, scopesRaw, gaps = []) {
  const a = attrs(programRaw && programRaw.data && !Array.isArray(programRaw.data) ? programRaw.data : programRaw);
  const node = scopesRaw != null ? scopesRaw : (a.structured_scopes != null ? a.structured_scopes : null);
  let list;
  if (Array.isArray(node)) list = node;
  else if (node && Array.isArray(node.data)) list = node.data;
  else if (node && Array.isArray(node.structured_scopes)) list = node.structured_scopes;
  else if (node != null) { gaps.push(`structured scopes for ${handle} arrived in an unrecognized shape — recorded EMPTY; check H1_API.SCOPES against the live API`); list = []; }
  else list = [];
  const structured_scopes = [];
  for (const s of list) {
    const sa = attrs(s);
    if (sa.asset_identifier == null) { gaps.push(`a structured-scope entry for ${handle} carries no asset_identifier — skipped (never invented)`); continue; }
    structured_scopes.push({
      asset_identifier: String(sa.asset_identifier),
      asset_type: sa.asset_type || '',
      ...(sa.eligible_for_submission !== undefined ? { eligible_for_submission: sa.eligible_for_submission === true } : {}),
      ...(sa.eligible_for_bounty !== undefined ? { eligible_for_bounty: sa.eligible_for_bounty === true } : {}),
      ...(sa.instruction ? { instruction: String(sa.instruction).slice(0, 300) } : {}),
      ...(sa.max_severity ? { max_severity: sa.max_severity } : {}),
    });
  }
  return {
    handle,
    name: a.name || handle,
    url: a.url || `https://hackerone.com/${handle}`,
    policy: a.policy || null,
    safe_harbor: a.safe_harbor || null,
    ...(Array.isArray(a.bounty_table) ? { bounty_table: a.bounty_table } : (Array.isArray(a.rewards) ? { bounty_table: a.rewards } : {})),
    ...(a.offers_bounties !== undefined ? { offers_bounties: a.offers_bounties === true } : {}),
    structured_scopes,
  };
}

// snapshotDoc(doc, { directory }) -> the diffable per-program snapshot: sorted unique
// in/out asset lists, the three hashes the state diffs on (scope/policy/bounty), the
// automation hint in bountyline's own vocabulary, and the doc itself (for the outbox).
// eligible_for_submission === false marks an OUT-of-scope entry (program.mjs's rule).
// Scope hashes cover ASSET IDENTIFIERS only — an instruction edit is not a scope event
// (documented; the next scan simply re-records it inside the doc).
export function snapshotDoc(doc, { directory } = {}) {
  const inScope = []; const outScope = [];
  for (const s of doc.structured_scopes || []) {
    if (!s || s.asset_identifier == null) continue;
    (s.eligible_for_submission === false ? outScope : inScope).push(String(s.asset_identifier));
  }
  const inS = [...new Set(inScope)].sort();
  const outS = [...new Set(outScope)].sort();
  const offersBounties = doc.offers_bounties !== undefined
    ? doc.offers_bounties === true
    : (directory ? directory.offersBounties : null);
  const policyText = [doc.policy, doc.safe_harbor].filter(Boolean).join('\n');
  return {
    handle: doc.handle,
    name: doc.name,
    url: doc.url,
    offersBounties,
    inScope: inS,
    outScope: outS,
    scopeHash: sha256({ in: inS, out: outS }),
    policyHash: sha256(policyText),
    bountyHash: sha256(doc.bounty_table || null),
    automation: deriveAutomation({ policy: doc.policy, safeHarbor: doc.safe_harbor }),
    doc,
  };
}

// --- THE DIFF ENGINE (pure — old state record vs new snapshot -> events) ---------------
// Event vocabulary: new-program | scope-added | scope-removed | policy-changed |
// bounty-table-changed. Scope events carry a side: 'in' (fresh/lost ground) or 'out'
// (the EXCLUSION list moved — safety-critical to know before touching anything; the
// program.mjs doctrine: an exclusion is never dropped, so a diff never hides one).
export const EVENT_TYPES = ['new-program', 'scope-added', 'scope-removed', 'policy-changed', 'bounty-table-changed'];

export function diffProgram(oldRec, snap, { now } = {}) {
  const at = iso(now);
  if (!oldRec) {
    return [{ at, type: 'new-program', handle: snap.handle, name: snap.name, offersBounties: snap.offersBounties, assets: snap.inScope, exclusions: snap.outScope, automation: snap.automation }];
  }
  const events = [];
  const oldIn = (oldRec.scope && oldRec.scope.in) || [];
  const oldOut = (oldRec.scope && oldRec.scope.out) || [];
  if (oldRec.lastSeenScopeHash !== snap.scopeHash) {
    const added = snap.inScope.filter((a) => !oldIn.includes(a));
    const removed = oldIn.filter((a) => !snap.inScope.includes(a));
    const addedOut = snap.outScope.filter((a) => !oldOut.includes(a));
    const removedOut = oldOut.filter((a) => !snap.outScope.includes(a));
    if (added.length) events.push({ at, type: 'scope-added', side: 'in', handle: snap.handle, offersBounties: snap.offersBounties, assets: added });
    if (removed.length) events.push({ at, type: 'scope-removed', side: 'in', handle: snap.handle, assets: removed });
    if (addedOut.length) events.push({ at, type: 'scope-added', side: 'out', handle: snap.handle, assets: addedOut, note: 'NEW EXCLUSION — this ground is now OFF LIMITS; honor it before any contact' });
    if (removedOut.length) events.push({ at, type: 'scope-removed', side: 'out', handle: snap.handle, assets: removedOut, note: 'an exclusion was lifted — the SIGNED scope still governs until re-signed' });
  }
  if (oldRec.policyHash !== snap.policyHash) {
    events.push({ at, type: 'policy-changed', handle: snap.handle, automation: { from: oldRec.automation || null, to: snap.automation } });
  }
  const offersFlip = oldRec.offersBounties !== snap.offersBounties;
  if (oldRec.bountyHash !== snap.bountyHash || offersFlip) {
    events.push({ at, type: 'bounty-table-changed', handle: snap.handle, ...(offersFlip ? { offersBounties: { from: oldRec.offersBounties ?? null, to: snap.offersBounties } } : {}) });
  }
  return events;
}

// --- THE FRESH-GROUND RANKING (documented order) ----------------------------------------
//   1  new-program, offers bounties                          — untouched ground that pays
//   2  scope-added (in-scope) on a bountied program          — fresh surface that pays
//   3  bounty-table-changed on a bountied program            — the reward math moved
//   4  new-program, no bounties (VDP)                        — reputation ground
//   5  scope-added (in-scope), no bounties
//   6  policy-changed · scope-added on the EXCLUSION list    — know it BEFORE any contact
//   7  everything else (scope-removed, non-bountied bounty moves) — informational
export function rankEvent(e) {
  if (!e || !e.type) return 7;
  if (e.type === 'new-program') return e.offersBounties === true ? 1 : 4;
  if (e.type === 'scope-added' && e.side !== 'out') return e.offersBounties === true ? 2 : 5;
  if (e.type === 'bounty-table-changed') return (e.offersBounties ? e.offersBounties.to === true : true) ? 3 : 7;
  if (e.type === 'policy-changed') return 6;
  if (e.type === 'scope-added' && e.side === 'out') return 6;
  return 7;
}

export function freshGround(events) {
  return (Array.isArray(events) ? events : [])
    .map((e) => ({ ...e, rank: rankEvent(e) }))
    .sort((a, b) => a.rank - b.rank || String(a.at).localeCompare(String(b.at)) || String(a.handle).localeCompare(String(b.handle)));
}

// --- state -------------------------------------------------------------------------------
export function loadState() {
  const st = readJson(STATE_FILE(), null);
  return st && typeof st === 'object' && st.programs ? st : { programs: {}, events: [], lastScan: null };
}

function saveState(st) {
  writeJson(STATE_FILE(), st);
}

// --- the sources --------------------------------------------------------------------------
// h1Get: the THIN client layer — one GET with the auth header, mapping every failure to
// a named error. The token VALUE exists only inside the `auth` string for the lifetime of
// the request; it is never returned, logged, or persisted.
//
// TIMEOUT DOCTRINE (the 2026-09-09 live-hunt wedge): the deadline covers the WHOLE
// operation — connect, headers AND the body read. The old code cleared the timer the
// moment fetch resolved, leaving `await res.json()` uncovered: a headers-then-silence
// response parked the watcher forever on one idle ESTABLISHED connection. An abort
// inside the window is the NAMED error 'h1-timeout', distinct from 'h1-unreachable'
// (the connection never answered). An outer signal (the hunt loop's stage watchdog)
// rides AbortSignal.any alongside our own timeout controller.
export async function h1Get({ url, auth, fetchImpl = fetch, timeoutMs = 20000, signal }) {
  const ac = new AbortController();
  const timedOut = { v: false };
  const t = setTimeout(() => { timedOut.v = true; ac.abort(); }, timeoutMs);
  const sig = signal ? AbortSignal.any([ac.signal, signal]) : ac.signal;
  let res;
  try {
    res = await fetchImpl(url, { headers: { authorization: auth, accept: 'application/json' }, signal: sig });
  } catch (e) {
    clearTimeout(t);
    if (timedOut.v || (e && e.name === 'AbortError')) {
      return { ok: false, error: 'h1-timeout', reason: `GET ${url} exceeded the ${timeoutMs}ms whole-operation deadline (the body never finished arriving — a stall, not a wait); no program data was fabricated` };
    }
    if (e && e.code === 'ghost-chain-down') {
      return { ok: false, error: 'ghost-chain-down', reason: `GET ${url} FAILED CLOSED: ${e.message}` };
    }
    return { ok: false, error: 'h1-unreachable', reason: `GET ${url} failed (${(e && e.message) || e}) — the API is unreachable; no program data was fabricated` };
  }
  let body;
  try {
    if (res.status === 401 || res.status === 403) return { ok: false, error: 'h1-auth', status: res.status, reason: `GET ${url} answered ${res.status} — the credential in ${TOKEN_ENV} was refused (H1 documents HTTP Basic identifier:token; check ${USER_ENV}); no program data was fabricated` };
    if (res.status === 429) return { ok: false, error: 'h1-rate-limited', status: 429, reason: `GET ${url} answered 429 — rate limited; back off and re-scan later` };
    if (!res.ok) return { ok: false, error: 'h1-http-error', status: res.status, reason: `GET ${url} answered HTTP ${res.status} — no program data was fabricated` };
    body = await res.json(); // INSIDE the timeout window — the wedge fix
  } catch (e) {
    if (timedOut.v || (e && e.name === 'AbortError')) {
      return { ok: false, error: 'h1-timeout', reason: `GET ${url} exceeded the ${timeoutMs}ms whole-operation deadline while reading the body (headers arrived, the body stalled); no program data was fabricated` };
    }
    return { ok: false, error: 'h1-bad-response', status: res.status, reason: `GET ${url} returned a body that is not JSON (${(e && e.message) || e}) — no program data was fabricated` };
  } finally {
    clearTimeout(t);
  }
  return { ok: true, status: res.status, json: body };
}

// The default wire: when a ghost chain is armed (env VARVEL_GHOST_CHAIN or the
// settings store), external H1 traffic rides it via tools/ghostfetch.mjs —
// FAIL CLOSED, never direct. Local targets stay direct inside ghostfetch
// (rule: local stays local). No chain armed = plain fetch, named in gaps.
function defaultWire({ env }) {
  const chainInfo = resolveGhostChain({ env });
  if (!chainInfo) return { fetchImpl: fetch, note: null };
  return {
    fetchImpl: ghostFetch(chainInfo.chain),
    note: `ghost chain armed via ${chainInfo.source} (${chainInfo.chain}) — H1 API traffic rides the chain, FAIL CLOSED`,
    chainInfo,
  };
}

// liveSource: the real client. The token comes from the env var NAMED TOKEN_ENV — absent
// is a named refusal BEFORE any request is ever attempted. The WIRE: an explicit
// fetchImpl wins (tests/the loop inject); otherwise defaultWire() — a ghost chain armed
// in env/settings routes ALL external H1 traffic through it (FAIL CLOSED); none armed
// = plain fetch, named in gaps. `signal` threads the caller's abort (the hunt loop's
// stage watchdog) into every GET.
export function liveSource({ base = H1_API.BASE, env = process.env, fetchImpl, timeoutMs = 20000, signal } = {}) {
  const token = env[TOKEN_ENV];
  if (!token) {
    return { ok: false, error: 'h1-token-missing', reason: `the live scan needs an API credential in the env var ${TOKEN_ENV} (the NAME only — its value is never stored or logged); offline/test runs use --fixture <file> with the same code path` };
  }
  const wire = fetchImpl ? { fetchImpl, note: null } : defaultWire({ env });
  const wireFetch = wire.fetchImpl;
  const user = env[USER_ENV];
  const auth = user ? 'Basic ' + Buffer.from(`${user}:${token}`).toString('base64') : 'Bearer ' + token;
  const gaps = [
    `H1 API shape assumed: JSON:API at ${base} — directory GET ${H1_API.DIRECTORY} (paginates via links.next), detail GET ${H1_API.PROGRAM('<handle>')}, scopes GET ${H1_API.SCOPES('<handle>')}; if the live API disagrees, the readers land EMPTY with a named gap — never guessed data`,
  ];
  if (wire.note) gaps.push(wire.note);
  else gaps.push('no ghost chain armed — H1 API traffic goes DIRECT (arm ghost.chain in data/settings.json or VARVEL_GHOST_CHAIN; the hunt loop refuses to run without a verified chain)');
  if (!user) gaps.push(`auth scheme: ${USER_ENV} unset — sending the token as a Bearer header; H1 documents HTTP Basic (identifier:token), so a 401 means set ${USER_ENV} too`);
  return {
    ok: true,
    gaps,
    ghost: wire.chainInfo || null,
    listPrograms: async () => {
      const programs = [];
      let url = `${base}${H1_API.DIRECTORY}?page%5Bsize%5D=${H1_API.PAGE_SIZE}`;
      for (let page = 0; page < H1_API.MAX_PAGES; page++) {
        const r = await h1Get({ url, auth, fetchImpl: wireFetch, timeoutMs, signal });
        if (!r.ok) return r;
        const parsed = parseDirectory(r.json, gaps);
        programs.push(...parsed.programs);
        if (!parsed.next) return { ok: true, programs };
        // links.next arrives absolute, root-relative, or base-relative depending on the
        // API — resolve against the base with the platform URL rules (naive string concat
        // double-prefixes a root-relative next: base/v1 + /v1/programs?page=2).
        url = new URL(parsed.next, base.endsWith('/') ? base : base + '/').href;
      }
      gaps.push(`directory pagination hit the ${H1_API.MAX_PAGES}-page safety cap — the remainder was NOT scanned this run`);
      return { ok: true, programs };
    },
    programDoc: async (handle) => {
      const det = await h1Get({ url: base + H1_API.PROGRAM(handle), auth, fetchImpl: wireFetch, timeoutMs, signal });
      let programRaw = null;
      if (det.ok) programRaw = det.json;
      else gaps.push(`${handle}: program detail GET failed (${det.error}${det.status ? ' HTTP ' + det.status : ''}) — continuing on the directory entry + scopes; policy absent means the automation hint stays at the safe default (prohibited)`);
      const sc = await h1Get({ url: base + H1_API.SCOPES(handle), auth, fetchImpl: wireFetch, timeoutMs, signal });
      if (!sc.ok) return sc; // a scope-fetch FAILURE keeps the program's previous state — it is never an empty scope
      return { ok: true, doc: docFromResponses(handle, programRaw, sc.json, gaps) };
    },
  };
}

// fixtureSource: a recorded API snapshot through the SAME readers as the live client.
// Documented fixture shape:
//   { "directory": <raw directory page (JSON:API or plain array)>,
//     "programs":  { "<handle>": <raw program detail (JSON:API single or plain; may carry
//                                policy/safe_harbor/bounty_table/structured_scopes inline)> },
//     "scopes":    { "<handle>": <raw structured-scopes page (JSON:API list, plain array,
//                                or { structured_scopes: [...] })> } }
export function fixtureSource(file) {
  let fx;
  try { fx = JSON.parse(readFileSync(file, 'utf8')); }
  catch (e) { return { ok: false, error: 'unreadable-fixture', reason: `cannot read/parse ${file}: ${(e && e.message) || e}` }; }
  const gaps = [`fixture source: ${file} — a recorded API snapshot, parsed through the SAME directory/program/scope readers as the live client`];
  return {
    ok: true,
    gaps,
    listPrograms: async () => ({ ok: true, programs: parseDirectory(fx.directory, gaps).programs }),
    programDoc: async (handle) => {
      const prog = fx.programs && fx.programs[handle];
      const scopes = fx.scopes && fx.scopes[handle];
      if (prog === undefined && scopes === undefined) return { ok: false, error: 'h1-http-error', status: 404, reason: `fixture has no program '${handle}'` };
      return { ok: true, doc: docFromResponses(handle, prog, scopes, gaps) };
    },
  };
}

// --- THE SCAN ------------------------------------------------------------------------------
// scan({ source, now, emit, outboxDir, onProgress, shouldStop }) — list the directory,
// snapshot each program, diff against state, persist, rank. Per-program fetch failures
// are recorded and the program's previous state is KEPT (rule 2). The state file is
// written on every COMPLETED walk (write-through). emit:true runs the intake bridge on
// the just-scanned snapshots (outbox files only — the watcher never signs and never runs).
//
// THE RESUMABLE WALK (the 2026-09-10 soak finding): a full directory walk through the
// ghost proxy runs at ~0.5 units/s — a 589-program walk is ~20 min, so ANY stage
// budget calibrated for a warm diff can (and did) abort 25 walks in a row, each
// restarting at unit 0. The walk therefore CHECKPOINTS as it goes:
//   <root>/walk-checkpoint.json = { at, total, docs: { handle: doc|null } }
// — the per-unit fetched docs, written through EVERY unit (crash- and kill-safe; a
// process restart resumes too). A unit whose fetch FAILED is marked null (done-with-
// error, so the walk can still complete; it is retried on a later walk). The next scan
// RESUMES from the unscanned remainder — fingerprinted units are never re-fetched
// within one walk. Only a COMPLETED walk diffs, ranks, and touches the main state
// (a partial walk is checkpoint material, never a misleading partial diff). A
// checkpoint older than WALK_TTL_MS is discarded (stale ground is re-walked).
//
// LIVENESS HOOKS: onProgress({ scanned, total, handle, errors, resumedFrom }) fires per
// program unit (scanned = the walk's done-count, checkpoint included); shouldStop() is
// checked BETWEEN units — a true return stops the walk honestly with the checkpoint
// persisted and stopped:true.
export const WALK_TTL_MS = 12 * 3600 * 1000;
const WALK_FILE = () => join(ROOT(), 'walk-checkpoint.json');

export function loadWalkCheckpoint() {
  const w = readJson(WALK_FILE(), null);
  if (!w || typeof w !== 'object' || !w.docs || typeof w.docs !== 'object') return null;
  if (!Number.isFinite(w.at) || Date.now() - w.at > WALK_TTL_MS) return null; // stale ground is re-walked
  return { at: w.at, total: Number.isFinite(w.total) ? w.total : 0, docs: w.docs, done: Object.keys(w.docs).length };
}
const saveWalk = (w) => writeJson(WALK_FILE(), w);
const clearWalk = () => { try { rmSync(WALK_FILE()); } catch { /* absent is fine */ } };

export async function scan({ source, now, emit = false, outboxDir, onProgress, shouldStop } = {}) {
  if (!source || source.ok !== true) {
    return { ok: false, error: (source && source.error) || 'no-source', reason: (source && source.reason) || 'scan needs a source (fixtureSource or liveSource)', gaps: (source && source.gaps) || [], doctrine: DOCTRINE };
  }
  const st = loadState();
  const gaps = [...(source.gaps || [])];
  const listed = await source.listPrograms();
  if (!listed.ok) return { ok: false, error: listed.error, status: listed.status, reason: listed.reason, gaps, doctrine: DOCTRINE };
  const at = iso(now);
  const events = []; const errors = [];
  const total = listed.programs.length;
  const byHandle = Object.fromEntries(listed.programs.map((p) => [p.handle, p]));

  // RESUME: seed the walk from the checkpoint, pruned to the current listing (a
  // program that left the directory drops out of the walk — never fetched, never kept).
  const prior = loadWalkCheckpoint();
  const walk = { at: Date.now(), total, docs: {} };
  let resumedFrom = 0;
  if (prior) {
    for (const [h, d] of Object.entries(prior.docs)) {
      if (byHandle[h]) walk.docs[h] = d;
    }
    resumedFrom = Object.keys(walk.docs).length;
    if (resumedFrom) gaps.push(`walk RESUMED from checkpoint: ${resumedFrom}/${total} unit(s) already fingerprinted (no re-fetch) — ${total - resumedFrom} to go`);
  }

  let stopped = false;
  const fetchMs = [];
  for (const p of listed.programs) {
    if (p.handle in walk.docs) continue; // checkpoint unit — resume material, never re-fetched
    if (shouldStop && shouldStop()) { stopped = true; break; }
    let got;
    const t0 = Date.now();
    try { got = await source.programDoc(p.handle); }
    catch (e) { got = { ok: false, error: 'h1-unreachable', reason: `programDoc(${p.handle}) threw: ${(e && e.message) || e}` }; }
    fetchMs.push(Date.now() - t0);
    if (!got.ok) {
      errors.push({ handle: p.handle, error: got.error, reason: got.reason });
      walk.docs[p.handle] = null; // done-with-error: the walk completes; retried on a later one
    } else {
      walk.docs[p.handle] = got.doc;
    }
    saveWalk(walk); // write-through EVERY unit — crash-safe, kill-safe, restart-safe
    try { if (onProgress) onProgress({ scanned: Object.keys(walk.docs).length, total, handle: p.handle, errors: errors.length, resumedFrom }); } catch { /* a progress listener never breaks the scan */ }
  }

  const done = Object.keys(walk.docs).length;
  const unitMs = fetchMs.length ? Math.round(fetchMs.reduce((a, b) => a + b, 0) / fetchMs.length) : null;
  if (stopped) {
    gaps.push(`walk STOPPED by the caller at ${done}/${total} program unit(s) — the checkpoint persists; the NEXT scan RESUMES from the unscanned remainder (a partial walk is checkpoint material, never a misleading partial diff)`);
    return {
      ok: true, stopped: true, at, scanned: Object.values(walk.docs).filter((d) => d).length, total, resumedFrom, remaining: total - done, unitMs,
      baseline: { complete: false, done, total, resumedFrom },
      events: [], ranked: [], errors, gaps, stateFile: STATE_FILE(), doctrine: DOCTRINE,
    };
  }

  // The walk COMPLETED — one snapshot pass, one diff, one state write (the pre-resume
  // semantics, unchanged).
  clearWalk();
  const snaps = [];
  for (const p of listed.programs) {
    const doc = walk.docs[p.handle];
    if (!doc) continue; // failed unit — no snapshot (its previous state is kept)
    const snap = snapshotDoc(doc, { directory: p });
    if (snap.offersBounties === null) gaps.push(`${p.handle}: offers_bounties absent from the directory AND the program detail — the ranking treats it as UNKNOWN, never as a promise of payment`);
    snaps.push(snap);
  }
  for (const snap of snaps) {
    const old = st.programs[snap.handle] || null;
    const evs = diffProgram(old, snap, { now: at }); // ONE pinned scan timestamp — events, state, and lastScan.at agree exactly (report matches on it)
    events.push(...evs);
    st.programs[snap.handle] = {
      handle: snap.handle,
      name: snap.name,
      url: snap.url,
      offersBounties: snap.offersBounties,
      lastSeenScopeHash: snap.scopeHash,
      scope: { in: snap.inScope, out: snap.outScope },
      policyHash: snap.policyHash,
      bountyHash: snap.bountyHash,
      automation: snap.automation,
      firstSeen: old ? old.firstSeen : at,
      lastChanged: evs.length ? at : (old ? old.lastChanged : at),
      lastScan: at,
    };
  }
  st.events = [...(st.events || []), ...events].slice(-EVENTS_CAP);
  st.lastScan = { at, programs: snaps.length, events: events.length, errors };
  saveState(st);
  const out = { ok: true, at, scanned: snaps.length, total, resumedFrom, remaining: 0, unitMs, baseline: { complete: true, done, total, resumedFrom }, events, ranked: freshGround(events), errors, gaps, stateFile: STATE_FILE(), doctrine: DOCTRINE };
  if (emit) out.outbox = emitIntake(events, Object.fromEntries(snaps.map((s) => [s.handle, s])), { outboxDir, now: at });
  return out;
}

// --- THE INTAKE BRIDGE ---------------------------------------------------------------------
// emitIntake(events, snapsByHandle, { outboxDir, now }) — ONE program.mjs-compatible
// intake JSON per event (the canonical doc + an _h1watch envelope: the event, the
// doctrine line, and the operator's next steps). The normalizer is FED, never duplicated
// — program.mjs ignores the envelope and reads the doc. The watcher NEVER signs the
// result and NEVER feeds the pipeline itself.
export function emitIntake(events, snapsByHandle, { outboxDir, now } = {}) {
  const dir = outboxDir || OUTBOX();
  const written = [];
  for (const e of Array.isArray(events) ? events : []) {
    const snap = snapsByHandle && snapsByHandle[e.handle];
    if (!snap || !snap.doc) continue;
    const fname = `${e.handle}-${e.type}${e.side === 'out' ? '-exclusion' : ''}-${iso(now).replace(/[:.]/g, '-')}.json`;
    const file = join(dir, fname);
    const payload = {
      _h1watch: {
        note: DOCTRINE,
        event: e,
        scannedAt: iso(now),
        next: `operator review, then BY HAND: node tools/cli.mjs program import "${file}" --platform hackerone --out <record.json> ; node tools/cli.mjs bountyline add <record.json> — the watcher NEVER signs and NEVER runs`,
      },
      ...snap.doc,
    };
    mkdirSync(dir, { recursive: true });
    writeFileSync(file, JSON.stringify(payload, null, 2) + '\n');
    written.push({ event: e.type, side: e.side || 'in', handle: e.handle, file });
  }
  return { ok: true, dir, written, note: DOCTRINE };
}

// --- report / show --------------------------------------------------------------------------
// report({ all }) — the ranked fresh-ground list FROM STATE: default the most recent
// scan's events; --all the whole ring (newest EVENTS_CAP).
export function report({ all = false } = {}) {
  const st = loadState();
  const evs = all ? (st.events || []) : (st.events || []).filter((e) => st.lastScan && e.at === st.lastScan.at);
  return {
    ok: true,
    at: st.lastScan ? st.lastScan.at : null,
    tracked: Object.keys(st.programs).length,
    events: freshGround(evs),
    ...(st.lastScan ? {} : { note: 'no scan on record — run: h1watch scan [--fixture <file>]' }),
    doctrine: DOCTRINE,
  };
}

export function show(handle) {
  const st = loadState();
  const rec = st.programs[String(handle || '')];
  if (!rec) return { ok: false, error: 'unknown-program', reason: `no program '${handle}' in the h1watch state — run: h1watch scan [--fixture <file>]`, doctrine: DOCTRINE };
  return { ok: true, program: rec, events: (st.events || []).filter((e) => e.handle === rec.handle), doctrine: DOCTRINE };
}
