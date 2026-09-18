// VARVEL — huntloop: the 24/7 autonomous bounty-hunt engine (the ops console's
// right hand). Glues the existing rungs into ONE crash-resumable loop:
//
//   h1watch diff → program intake → scope-check (out-of-scope always wins +
//   the automation gate) → recon (the brain) → testing (in the isolated
//   sandbox) → VM-verification (replay) → evidence → report → ledger →
//   cleanup → sleep → repeat.
//
// It is driven BY HAND or by the VARVEL Ops Console (spark-menu): the console
// spawns `node tools/huntloop.mjs` as a tracked child, tails events.jsonl into
// the stage board, and stops it via the STOP file (graceful) or a
// cmdline-checked kill (fallback). Every stage the board shows is an event
// THIS loop actually wrote — the console never invents one.
//
// HARD RULES (the revenue-safe doctrine, same as engine/bountyline.mjs):
//   1. THE LOOP NEVER SUBMITS. There is no network submission code path in
//      this file — no fetch, no http, no platform API, not behind a flag. The
//      ONLY remote endpoint the loop ever talks to is the LOCAL brain
//      (OpenAI-compatible chat-completions), and that call is made through
//      engine/brain-provider.mjs callOpenAI (reuse, never reimplement).
//      Reports land in <dir>/outbox for the operator's hand, always.
//      test/huntloop.test.mjs pins this with a static scan of this file.
//   2. NEVER FAKE A STATE. 'verified' is stamped ONLY after a replay of the
//      finding's check in a FRESH isolated sandbox matched its expected
//      marker; 'verified-clean' ONLY after the cleanup verify snippet actually
//      ran and found no residue. A finding whose replay fails (or never ran)
//      stays UNVERIFIED and is reported as such — the honesty contract is
//      absolute (AGENTS.md).
//   3. THE BRAIN NEVER RUNS ON THE HOST SHELL. Brain-drafted check snippets
//      execute ONLY inside the isolation sandbox (poc/isolation providers:
//      firecracker/hyperv → docker --network none --read-only --cap-drop ALL →
//      local-process dev tier). When no kernel-isolated tier is available,
//      brain-drafted checks are SKIPPED LOUDLY ('no-kernel-isolation') and the
//      finding stays unverified — only operator-supplied deterministic checks
//      (--mock-brain / fixtures) may run on the dev tier.
//   4. SCOPE IS LAW. Out-of-scope always wins (tools/program.mjs overlap
//      precedence, recorded loudly); a program whose policy prohibits
//      automation is skipped by the automation gate (engine/bountyline.mjs
//      deriveAutomation — the SAME derivation, never reimplemented regexes).
//   5. IDEMPOTENT + CRASH-RESUMABLE. state.json records processed opportunity
//      keys + counters; a restarted loop skips finished opportunities and
//      re-runs an interrupted one from its first stage (every stage is
//      re-runnable by design). Loud on failure: a stage failure lands as a
//      'failed' event with the reason named, and the loop moves on.
//
// FILES (under <dir>, env VARVEL_HUNTLOOP_DIR, default varvel/data/huntloop):
//   events.jsonl    the stage-board stream the console tails (one JSON per line)
//   state.json      crash-resume state (cycles, counters, processed opportunities)
//   findings.jsonl  the findings ledger (one line per finding, verdict inside)
//   outbox/*.md     drafted reports — HUMAN REVIEW ONLY, never sent anywhere
//   evidence/<opp>/<finding>/  the proof bundle per finding:
//     replay-transcript.txt  timestamped full replay transcript (the "video proof"
//                            that shipped on this box — asciinema was ABSENT at
//                            build time; when present, replay.cast is recorded too)
//     env.json               environment hash bundle (sha256 of the check snippet,
//                            node/platform/arch, sandbox provider+tier, timestamps)
//     result.json            { verified, expected, matched, stdout }
//   logs/huntloop.log  human-readable full log (mirrors the events)
//   STOP / PAUSE       control files the console writes (checked at every stage
//                      boundary — graceful stop/pause, no orphaned work)
//
// Direct run:
//   node tools/huntloop.mjs [--dir d] [--fixture f.json] [--mock-brain] [--once]
//                           [--interval s] [--max-opps n] [--model id] [--base-url u]
//                           [--validate]   (the refuter pass: VARVEL_REFUTER_BASE_URL/_MODEL must be set)
//   --fixture = the SAME h1watch code path offline; the live watch needs the
//   VARVEL_H1_TOKEN env NAME (h1watch doctrine — absent is a loud refusal).
//   --mock-brain = a deterministic operator-supplied brain for the dry-run —
//   proves the loop mechanics end-to-end with NO lane (the lane is training).

import { readFileSync, writeFileSync, appendFileSync, mkdirSync, existsSync, readdirSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';

import { scan as h1Scan, fixtureSource as h1FixtureSource, liveSource as h1LiveSource, snapshotDoc, loadState as h1LoadState, loadWalkCheckpoint } from './h1watch.mjs';
import { normalizeProgram } from './program.mjs';
import { deriveAutomation } from '../engine/bountyline.mjs';
import { bountyReport } from './bountyreport.mjs';
import { resolveBrain, callOpenAI, listOpenAIModels } from '../engine/brain-provider.mjs';
import { resolveGhostChain, ghostPreflight } from './ghostfetch.mjs';
import { gatherOpportunity, mechanicalCandidates } from './gather.mjs';
import { resolveRefuter, refuteFinding } from './refuter.mjs';
import { cveCheck } from '../engine/cvepacks.mjs';
import { intakeGate } from '../engine/lanes.mjs';
import dockerProvider from '../../poc/isolation/providers/docker.mjs';
import localProvider from '../../poc/isolation/providers/local-process.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));

// Persistence root, evaluated at call time so tests isolate via VARVEL_HUNTLOOP_DIR.
const ROOT = () => process.env.VARVEL_HUNTLOOP_DIR || join(__dir, '..', 'data', 'huntloop');

export const DOCTRINE = 'the hunt loop watches, tests in the sandbox, verifies by replay, drafts for review — it NEVER submits; the send click is the operator\'s, always.';
export const STAGES = ['watch', 'intake', 'scope-check', 'recon', 'testing', 'vm-verification', 'evidence', 'report', 'poc-forge', 'ledger', 'cleanup'];
export const DEFAULT_INTERVAL_S = 900; // module default between cycles — the launcher picks the live value (console: 300s since the 2026-09-12 cadence review)
export const STAGE_WATCHDOG_MS = 180000; // a stage that exceeds 3 min is FAILED LOUDLY, never parked (the 2026-09-09 stall lesson)
export const OPP_WATCHDOG_MS = 900000; // per-opportunity pipeline budget — a THINKING brain's recon legitimately runs minutes (the 2026-09-11 120s brain timeouts); heartbeats still prove liveness, a true wedge still dies LOUDLY at 15 min
export const BRAIN_RECON_TIMEOUT_MS = 600000; // the recon brain call itself — 10 min (xhigh thinking on a scope doc can run minutes; the old 120s default starved recon attempts)
export const HEARTBEAT_MS = 30000; // long stages emit a heartbeat at most this often

// THE STAGE WATCHDOG — a stage that runs past its deadline is aborted (its
// AbortController kills in-flight GETs) and recorded 'failed' with
// 'stage-watchdog-timeout', never silently hung. The run's late rejection is
// tracked so it can never crash the loop as an unhandled rejection.
// (exported for tools/pocforge.mjs — the on-demand PoC stage reuses it, never reimplements)
export async function withWatchdog(ms, ctl, run) {
  let timer;
  const fired = new Promise((_, reject) => {
    timer = setTimeout(() => {
      try { ctl.abort(); } catch { /* no controller */ }
      reject(Object.assign(new Error(`stage exceeded its ${ms}ms watchdog — in-flight work aborted, the stage fails LOUDLY`), { code: 'stage-watchdog-timeout' }));
    }, ms);
  });
  fired.catch(() => {});
  const tracked = Promise.resolve().then(run);
  tracked.catch(() => {}); // if the watchdog wins, the run's late failure is handled
  try {
    return await Promise.race([tracked, fired]);
  } finally {
    clearTimeout(timer);
  }
}

// The sandbox tiers, strongest first (sandbox-manager's order; firecracker/hyperv
// are Linux/Windows-VM tiers unavailable here — docker is the kernel-isolated
// container tier, local-process the dev fallback that is NAMED as such).
const KERNEL_TIERS = [dockerProvider];
export function selectSandbox(provider) {
  if (provider) return provider; // injected (tests)
  for (const p of KERNEL_TIERS) { try { if (p.available()) return p; } catch { /* unavailable */ } }
  return localProvider;
}
export const KERNEL_ISOLATED = (p) => p && p.name !== 'local-process';

const sha256 = (x) => createHash('sha256').update(typeof x === 'string' ? x : JSON.stringify(x)).digest('hex');
const iso = (now) => (now === undefined ? new Date().toISOString() : (typeof now === 'number' ? new Date(now).toISOString() : String(now)));
const readJson = (p, fb) => { try { return existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : fb; } catch { return fb; } };
const writeJson = (p, obj) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(obj, null, 2) + '\n'); };
const slug = (s) => String(s || 'finding').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48) || 'finding';

// --- the event stream + log ---------------------------------------------------------------
// emit() is the ONLY way state reaches the board — every stage event is written
// when the work actually happened, never ahead of it (rule 2).
export function makeEmitter({ dir = ROOT(), now, log = true } = {}) {
  const eventsFile = join(dir, 'events.jsonl');
  const logFile = join(dir, 'logs', 'huntloop.log');
  const line = (ev) => {
    const rec = { ts: iso(now), ...ev };
    mkdirSync(dirname(eventsFile), { recursive: true });
    appendFileSync(eventsFile, JSON.stringify(rec) + '\n');
    if (log) {
      mkdirSync(dirname(logFile), { recursive: true });
      const human = `${rec.ts} ${ev.type}${ev.stage ? '/' + ev.stage : ''}${ev.state ? ' ' + ev.state : ''}${ev.msg ? ' — ' + ev.msg : ''}`;
      appendFileSync(logFile, human + '\n');
    }
    return rec;
  };
  return {
    stage: (stage, state, extra = {}) => line({ type: 'stage', stage, state, ...extra }),
    loop: (state, msg, extra = {}) => line({ type: 'loop', state, msg, ...extra }),
    counters: (counters) => line({ type: 'counters', data: { ...counters } }),
    vm: (state, provider, extra = {}) => line({ type: 'vm', state, provider: provider && { name: provider.name, tier: provider.tier }, ...extra }),
    proof: (opp, finding, data) => line({ type: 'proof', opp, finding, ...data }),
    error: (msg, extra = {}) => line({ type: 'error', msg, ...extra }),
    raw: line,
  };
}

// --- state (crash-resume) -------------------------------------------------------------------
export function loadState(dir = ROOT()) {
  const st = readJson(join(dir, 'state.json'), null);
  return st && typeof st === 'object' && st.processed ? st : { cycles: 0, counters: zeroCounters(), processed: {}, updatedAt: null };
}
export function saveState(st, dir = ROOT()) {
  st.updatedAt = new Date().toISOString();
  writeJson(join(dir, 'state.json'), st);
}
export const zeroCounters = () => ({ seen: 0, opportunities: 0, tested: 0, verified: 0, unverified: 0, drafted: 0, cleaned: 0, failed: 0, killed: 0, parked: 0, submittable: 0, firm: 0 });

// One opportunity = one ranked watch event. The key is stable across restarts so
// crash-resume never double-hunts the same ground.
export function oppKey(e) {
  return `${e.handle}:${e.type}:${e.side || 'in'}:${sha256((e.assets || []).slice().sort()).slice(0, 12)}`;
}
// The filesystem-safe form (Windows paths cannot carry ':') — evidence dirs use this.
export const oppKeySlug = (e) => oppKey(e).replace(/[:<>|?*]/g, '_');

// --- the brain --------------------------------------------------------------------------------
// The loop's ONLY remote conversation. resolveBrain reads VARVEL_BRAIN_* env; an
// unreachable/absent brain is an honest 'brain-wait', never invented findings.
// The brain is asked for STRICT JSON candidate findings; unparseable output is
// zero findings, loudly logged (rule: nothing fabricated).
export const BRAIN_SYSTEM = [
  'You are the VARVEL hunt brain. You judge EVIDENCE, never vibes: a bounded bundle of REAL pages fetched from the in-scope assets (tech, versions, headers, statuses, passive endpoints) plus any platform-matched CVE candidates.',
  'Answer with ONE fenced json block and nothing else:',
  '```json',
  '{ "findings": [ { "title": "...", "sev": "crit|high|med|low|info", "evidence": "what the bundle shows and why it matters",',
  '  "check": "node snippet (CommonJS) that performs the test and prints a marker",',
  '  "expect": "the exact marker stdout must contain for the finding to verify",',
  '  "cleanup": "node snippet that removes every artifact the check created",',
  '  "verifyClean": "node snippet printing CLEAN when no residue remains, RESIDUE otherwise" } ] }',
  '```',
  'SANDBOX CONTRACT (load-bearing): checks run ISOLATED (--network none, read-only, NO host paths). Three variables are predefined:',
  '  TARGET   — a writable scratch dir for artifacts your check creates.',
  '  EVIDENCE — the gathered evidence as a PARSED OBJECT ({ assets: [{ host, status, techs[], headers{}, endpoints[] }] }) — the ONLY way to read evidence. Judge it, quote it, test against it.',
  '  BUNDLE   — a host-side path that does NOT exist in the sandbox; never read it.',
  'NEVER readFileSync / require fs paths for evidence: a check that references a file path for evidence is DROPPED at intake as a contract defect.',
  'Rules: judge ONLY what the evidence supports — a candidate the bundle cannot back is a hallucination and it WILL fail replay-verification;',
  'SEVERITY BAR (the 2026-09-11 lesson — verified-but-worthless is still worthless): propose ONLY candidates whose verified impact a bug-bounty program would plausibly PAY for. NEVER propose informational disclosures: robots.txt contents by themselves, missing/banner headers, style-only CSP observations, tech/version fingerprints without a specific known-exploitable CVE, generic best-practice gaps. Worth proposing: authn/authz breaks, injection classes (sqli/cmdi/ssti/xss with a demonstrated sink), SSRF with a reachable proof, sensitive data exposure with a demonstrated read, dangerous defaults with demonstrated impact.',
  'do not re-propose the platform\'s mechanical CVE candidates (they are already in the pipeline);',
  'every artifact a check creates MUST be removed by its cleanup; a finding without a check/expect pair is dropped;',
  'if the evidence supports nothing checkable, answer { "findings": [] } — an empty answer is honest, an invented one is not.',
].join('\n');

export function parseBrainFindings(text) {
  const t = String(text || '');
  const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/);
  let doc = null;
  for (const cand of [fence && fence[1], t]) {
    if (!cand) continue;
    try { doc = JSON.parse(cand.trim()); break; } catch { /* try the next shape */ }
  }
  if (!doc || !Array.isArray(doc.findings)) return { ok: false, findings: [], reason: 'the brain answer carried no parseable { findings: [...] } json block — treated as ZERO findings (nothing invented)' };
  const kept = [];
  let dropped = 0;
  const defects = [];
  // THE CONTRACT DEFECT (2026-09-11): a check that reads its evidence from a FILE
  // PATH can never evaluate in the isolated sandbox (--network none, read-only, no
  // host paths) — it would crash unread and misread as 'unproven'. Evidence reaches
  // checks ONLY through the EVIDENCE object the sandbox predefines. Dropped at
  // intake, named — never passed to the sandbox to die.
  const EVIDENCE_PATH_RE = /readFileSync|createReadStream|readFile\s*\(|\bBUNDLE\b|evidence[\\/]gather|mock-target[\\/]/;
  for (const f of doc.findings) {
    if (!f || typeof f !== 'object' || !f.title || !f.check || !f.expect || !f.cleanup || !f.verifyClean) { dropped++; continue; }
    if (EVIDENCE_PATH_RE.test(String(f.check))) {
      defects.push(String(f.title).slice(0, 60));
      continue;
    }
    kept.push({ title: String(f.title), sev: String(f.sev || 'info'), evidence: String(f.evidence || ''), check: String(f.check), expect: String(f.expect), cleanup: String(f.cleanup), verifyClean: String(f.verifyClean) });
  }
  const reasons = [];
  if (dropped) reasons.push(`${dropped} brain finding(s) dropped — missing title/check/expect/cleanup/verifyClean (the honesty contract drops, never repairs)`);
  if (defects.length) reasons.push(`${defects.length} brain finding(s) dropped — check-references-unreachable-evidence: the check reads a file path (readFileSync/BUNDLE/gather path) that cannot exist in the isolated sandbox; evidence reaches checks ONLY via the EVIDENCE object (${defects.join('; ')})`);
  return { ok: true, findings: kept, dropped, defects: defects.length ? defects : undefined, ...(reasons.length ? { reason: reasons.join(' | ') } : {}) };
}

export async function brainHunt({ brain, intake, evidenceText, mechanical, now, timeoutMs = 120000, emit, opp }) {
  // brain: { baseUrl, model, key? } OR an injected async (system, user) -> text (tests/mock).
  const summary = JSON.stringify({ program: intake.program, inScope: intake.inScope, outOfScope: intake.outOfScope, policy: intake.policy ? String(intake.policy).slice(0, 600) : null }, null, 1);
  const evidence = evidenceText
    ? `\n\nGATHERED EVIDENCE (real pages, fetched through the ghost chain — judge THIS, not the scope names):\n${evidenceText}`
    : '\n\nGATHERED EVIDENCE: none (gather was skipped or empty — the candidate judgment runs on scope alone; say so in your evidence fields)';
  const mech = (mechanical && mechanical.length)
    ? `\n\nPLATFORM-MECHANICAL CANDIDATES (already in the pipeline — do NOT re-propose; build on them only if the evidence shows more):\n${mechanical.map((m) => `- ${m.title}`).join('\n')}`
    : '';
  const user = `Program intake summary:\n${summary}${evidence}${mech}\n\nPropose candidate findings the EVIDENCE supports, for the in-scope assets only. Out-of-scope entries are OFF LIMITS — never touch them.`;
  if (typeof brain === 'function') return brain(BRAIN_SYSTEM, user);
  const env = brain && brain.env ? brain.env : process.env;
  let cfg;
  try {
    cfg = resolveBrain({ env, request: brain || null });
  } catch (err) {
    // MID-HUNT LANE-UP: the console only knows the model id if the lane was UP AT
    // SPAWN; a hunt started while the lane trained carries none, and without this
    // the recon stage would fail every cycle FOREVER with 'needs a model id'
    // (the console's "recon waits for the lane" promise would be false). When the
    // ONLY gap is the missing model, ask the lane for its own roster — a lane that
    // has come up answers and the recon wait ends; one that is still down is a
    // null and the original named refusal stands. (The lane conversation stays in
    // engine/brain-provider.mjs — the never-submits pin allows no fetch here.)
    if (err instanceof TypeError && /needs a model id/.test(err.message)) {
      const base = String((brain && brain.baseUrl) || env.VARVEL_BRAIN_BASE_URL || '');
      const id = await listOpenAIModels({ baseUrl: base, timeoutMs: 10000 });
      if (id) {
        cfg = resolveBrain({ env, request: { ...(brain || {}), model: id } });
        if (emit && emit.raw) emit.raw({ type: 'brain', state: 'model-resolved', opp: opp ? opp.handle || opp : undefined, msg: `lane answered mid-hunt — model resolved from its own /models roster: ${id} (the spawn carried none; the recon wait is over)` });
      }
    }
    if (!cfg) throw err;
  }
  if (cfg.provider !== 'openai-compatible') {
    const e = new Error(`brain provider resolved to '${cfg.provider}' — the hunt loop drives an OpenAI-compatible local lane (VARVEL_BRAIN_PROVIDER=openai-compatible); refusing to hunt without it`);
    e.code = 'brain-not-openai-compatible';
    throw e;
  }
  const key = cfg.apiKeyEnv ? process.env[cfg.apiKeyEnv] : undefined;
  const r = await callOpenAI({
    baseUrl: brain && brain.baseUrl ? brain.baseUrl : cfg.baseUrl,
    model: brain && brain.model ? brain.model : cfg.model,
    key, system: BRAIN_SYSTEM,
    messages: [{ role: 'user', content: user }],
    maxTokens: Number(env.VARVEL_BRAIN_MAX_TOKENS) > 0 ? Number(env.VARVEL_BRAIN_MAX_TOKENS) : 16384, // callOpenAI's own default — reasoning lanes burn reasoning_content BEFORE the text channel; 8192 truncated mid-JSON (the td-bank lesson)
    timeoutMs: brain && brain.timeoutMs !== undefined ? brain.timeoutMs : timeoutMs,
  });
  const text = (r.content || []).filter((b) => b && b.type === 'text').map((b) => b.text).join('\n');
  // DIAGNOSTIC (2026-09-16, the td-bank unparseable-answer lesson): an honest ZERO must be
  // DISTINGUISHABLE from a budget truncation. Qwen3.8-class lanes are reasoning models —
  // they burn reasoning_content tokens BEFORE the text channel — so an 8192 ceiling can
  // truncate the answer mid-JSON (finish 'length') and the parser would silently record
  // 'no parseable block' with no trace of WHY. Log the answer's shape (bounded), never
  // invent from it: the parse contract below is unchanged.
  if (emit && emit.raw) {
    const think = (r.content || []).filter((b) => b && b.type === 'thinking').map((b) => b.thinking).join('').length;
    emit.raw({ type: 'brain', state: 'answer-shape', opp: opp ? opp.handle || opp : undefined, msg: `text=${text.length}ch reasoning=${think}ch finish=${r.stop_reason || 'unknown'}` });
    if (r.stop_reason === 'max_tokens' || (text && !text.includes('```'))) {
      emit.raw({ type: 'brain', state: 'answer-head', opp: opp ? opp.handle || opp : undefined, msg: text.slice(0, 400) });
    }
  }
  return text;
}

// The deterministic dry-run brain — operator-supplied, NOT the lane. Proves the
// loop mechanics end-to-end with the lane down: one candidate finding whose
// check writes a marker into the mock target dir, whose cleanup removes it,
// and whose verify proves the residue is gone.
export function mockBrain() {
  return async () => JSON.stringify({
    findings: [{
      title: 'Mock: unauthenticated marker write into the target scratch (loop-mechanics proof)',
      sev: 'med',
      evidence: 'DRY-RUN finding: the mock brain\'s check writes HUNT-POC into the mock target dir; verification replays the write in a FRESH sandbox and matches the marker; cleanup removes the marker and verifies no residue. Proves watch→intake→scope→recon→testing→vm-verification→evidence→report→ledger→cleanup with no lane.',
      check: "const fs=require('node:fs');fs.mkdirSync(TARGET,{recursive:true});fs.writeFileSync(require('node:path').join(TARGET,'hunt-poc-marker.txt'),'HUNT-POC '+new Date().toISOString());console.log('MARKER-WRITTEN');",
      expect: 'MARKER-WRITTEN',
      cleanup: "require('node:fs').rmSync(require('node:path').join(TARGET,'hunt-poc-marker.txt'),{force:true});console.log('CLEANED');",
      verifyClean: "console.log(require('node:fs').existsSync(require('node:path').join(TARGET,'hunt-poc-marker.txt'))?'RESIDUE':'CLEAN');",
    }],
  });
}

// --- the sandbox runs (testing / vm-verification / cleanup) -----------------------------------
// One provision-run-destroy per run, ALWAYS torn down (the cleanup doctrine).
// code runs as a node program with TARGET (the finding's target dir), BUNDLE (the
// host-side evidence path — host-only, see below), and EVIDENCE — the gathered
// evidence INLINED as a parsed object (bounded by the bundle cap by design), the
// ONLY evidence channel that works on the --network none / read-only docker tier
// (the 2026-09-11 defect: brain checks read an EMPTY evidence path and auto-failed;
// no sandbox tier may ever reach a host path).
export function sandboxRun(provider, code, { target, sessionId, trusted = false, bundle, evidence } = {}) {
  if (!KERNEL_ISOLATED(provider) && !trusted) {
    return { ok: false, skipped: 'no-kernel-isolation', reason: `sandbox tier '${provider && provider.name}' is the dev tier (no kernel isolation) — brain-drafted checks are SKIPPED here (rule 3); only operator-supplied deterministic checks run on it`, provider: provider && provider.name };
  }
  const evInline = JSON.stringify(evidence && typeof evidence === 'object' ? evidence : { assets: [] });
  const program = `const TARGET=${JSON.stringify(target || '')};\nconst BUNDLE=${JSON.stringify(bundle || '')};\nconst EVIDENCE=JSON.parse(${JSON.stringify(evInline)});\n${code}`;
  // The session id is TRACEABLE and never REUSABLE: the caller's label is the prefix
  // (which finding, which stage) and a random suffix makes every invocation a fresh
  // name. The 2026-09-17 defect this closes: the id was fully deterministic
  // (`hunt-verify-<slug>`, slug capped at 48 chars), so a container leaked by a killed
  // run (docker `--rm` does not reap a never-started 'Created' container) made every
  // later run die at create with 'Conflict. The container name ... is already in use'
  // — and that throw aborted the WHOLE opportunity (11 mechanical findings lost), over
  // and over. Names are never authority; the run's own teardown is.
  const sandbox = provider.create({ session_id: `${sessionId || 'hunt-' + sha256(program).slice(0, 12)}-${randomBytes(4).toString('hex')}` });
  try {
    const r = provider.run(sandbox, program);
    return { ok: true, code: r.code, stdout: String(r.stdout || ''), stderr: String(r.stderr || ''), provider: provider.name, tier: provider.tier };
  } finally {
    try { provider.destroy(sandbox); } catch { /* teardown is best-effort; the ledger records what ran */ }
  }
}

// --- THE EVIDENCE GRADE: what a replay actually proves -----------------------------------------
// THE LIE THIS KILLS (2026-09-18, the operator's findings-board report): the console, the ledger
// and the draft headers called every replay-passed finding "VERIFIED", and the board showed 61 of
// them. But a replay runs INSIDE the isolated sandbox (`--network none`), where a mechanical check
// is literally `JSON.parse(<the recorded bundle>)` + a version-string compare: it passes for ANY
// bundle by construction. It re-derives the recorded bytes; it NEVER re-probes the host. "Verified"
// therefore claimed a live confirmation that never happened — and those were the version→CVE
// matches most programs (ours included) explicitly exclude.
//
// The grade names what actually stands:
//   poc-demonstrated — the forge captured the DECLARED impact marker in a LIVE response
//                      (read-only, scope-guarded, ghost-routed). The only strong grade there is.
//   firm             — a live fingerprint (the gathered bundle) re-derived offline, deterministically.
//                      Real and useful; NOT a submittability claim.
//   unproven / check-defect / unverified — exactly what classifyVerdict said; unchanged.
export function findingGrade({ verdict, forge } = {}) {
  if (forge && forge.verdictClass === 'poc-verified') return 'poc-demonstrated';
  if (verdict === 'verified') return 'firm';
  return verdict || 'unverified';
}

// SUBMITTABLE — never asserted, always COMPUTED: a demonstrated PoC, or the report gate's own
// `ready` over a NON-self-referential target re-probe (tools/bountyreport.mjs's contract). An
// offline replay alone is never submittable, whatever verdict it carries.
export function isSubmittable({ grade, readiness, oracleKind } = {}) {
  if (grade === 'poc-demonstrated') return true;
  return readiness === 'ready' && oracleKind === 'target-repro';
}

// makeAutoForge({ brain, env }) -> the loop's AUTO-FORGE stage, or null when switched off.
// The real forge is tools/pocforge.mjs — the SAME one the console's per-row VERIFY button drives
// (engine reuse, never a reimplementation). VARVEL_HUNTLOOP_FORGE=off|0|false disables it, and a
// mock-brain run never forges (there is no real finding to demonstrate). The forge is injected, so
// tests pass a fake and stay offline and deterministic.
export function makeAutoForge({ brain, env = process.env, importForge } = {}) {
  const mode = String(env.VARVEL_HUNTLOOP_FORGE === undefined ? 'on' : env.VARVEL_HUNTLOOP_FORGE).toLowerCase();
  if (['off', '0', 'false', 'no'].includes(mode)) return null;
  return async ({ finding, evidenceDir, dir, emit, now, chain }) => {
    const mod = importForge ? await importForge() : await import('./pocforge.mjs');
    return mod.pocForge({ finding, evidenceDir, brain, chain, emit, dir, outboxDir: join(dir, 'outbox'), now });
  };
}

// --- video proof ------------------------------------------------------------------------------
// asciinema on the box -> record the replay as replay.cast; absent -> the
// timestamped full replay transcript + environment hash bundle stands (that is
// what shipped on this box; probeOnce records which).
export function probeRecorder(spawn = spawnSync) {
  try {
    const r = spawn('asciinema', ['--version'], { encoding: 'utf8', timeout: 5000 });
    if (r.status === 0) return { recorder: 'asciinema', note: 'replay runs are recorded as asciinema casts (replay.cast) next to the transcript' };
  } catch { /* absent */ }
  return { recorder: 'transcript+hash', note: 'asciinema NOT found on this box — video proof ships as the timestamped full replay transcript + environment hash bundle per finding (documented in the README)' };
}

// env.json — the environment hash bundle: proves WHAT ran WHERE, so the
// transcript cannot be confused with output from another machine or snippet.
export function envBundle({ finding, provider, target, recorder, now }) {
  return {
    recordedAt: iso(now),
    snippetSha256: sha256(finding.check),
    expectSha256: sha256(finding.expect),
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    sandbox: provider ? { name: provider.name, tier: provider.tier, enforces: provider.enforces || null } : null,
    kernelIsolated: KERNEL_ISOLATED(provider),
    targetDir: target,
    recorder,
  };
}

// --- ONE finding through testing → verification → evidence → cleanup ---------------------------
// THE VERDICT CLASSES (the 2026-09-11 evidence-path defect): a check that CRASHES in
// the sandbox (nonzero exit / provider timeout — READ_ERROR, ENOENT on an unreachable
// path) was NEVER EVALUATED — that is 'check-defect', a defect in the check, and it can
// never masquerade as an evaluated-and-unproven finding. A check that RAN CLEAN (exit 0)
// but never printed its marker is 'unproven'. 'verified' stays what it always was:
// the marker reproduced in a fresh sandbox. The ledger/proof carry the class; the
// console's verified-vs-unverified split counts unproven+defect together.
export function classifyVerdict({ test, replay, expect }) {
  const testCrashed = !test.ok || test.code !== 0; // null status = killed by the provider timeout — a crash, never an evaluation
  const replayCrashed = !replay.ok || replay.code !== 0;
  const testMatched = test.ok === true && String(test.stdout || '').includes(expect);
  const matched = replay.ok === true && String(replay.stdout || '').includes(expect);
  if (testMatched && matched) {
    return { verdict: 'verified', matched, testMatched, reason: 'replay-verification PASSED: the check re-ran in a fresh isolated sandbox and printed its expected marker' };
  }
  if (testCrashed || replayCrashed) {
    const crash = testCrashed ? test : replay;
    const why = test.code === null && replay.code === null ? 'timeout-beyond-budget' : `exit ${crash.code}`;
    return {
      verdict: 'check-defect', matched, testMatched,
      reason: `the check CRASHED in the sandbox (${why}${crash.stderr ? ': ' + String(crash.stderr).split('\n')[0].slice(0, 140) : ''}) — it was NEVER EVALUATED; this is a defect in the check (an unreachable path, a thrown read, a timeout), NOT an evaluated-and-unproven finding`,
    };
  }
  if (!testMatched) {
    return { verdict: 'unproven', matched, testMatched, reason: 'the probe ran clean but never printed its expected marker — evaluated and UNPROVEN (the claim did not hold; reported honestly)' };
  }
  return { verdict: 'unproven', matched, testMatched, reason: 'the replay run did NOT reproduce the marker in a fresh sandbox — evaluated and UNPROVEN (fixed-or-changed, reported honestly)' };
}

export function runFinding({ finding, opp, intake, provider, recorder, emit, dir = ROOT(), now, trusted = false, targetRoot, bundlePath, evidence }) {
  const fslug = slug(finding.title);
  const target = join(targetRoot || join(dir, 'mock-target'), opp.handle);
  const evDir = join(dir, 'evidence', oppKeySlug(opp), fslug);
  mkdirSync(evDir, { recursive: true });
  const transcript = [];
  const tlog = (s) => transcript.push(`${iso(now)} ${s}`);

  // THE CHECK TEXT IS PERSISTED (a finding must be re-runnable forever — the two
  // 2026-09-11 defect findings were unreplayable because only a hash survived).
  writeFileSync(join(evDir, 'check.txt'), String(finding.check));

  // TESTING — the check runs in the sandbox (the board's "AI testing on a VM" state).
  emit.stage('testing', 'active', { opp: opp.handle, finding: finding.title });
  emit.vm('active', provider, { opp: opp.handle, finding: fslug, purpose: 'testing' });
  const test = sandboxRun(provider, finding.check, { target, sessionId: 'hunt-test-' + fslug, trusted, bundle: bundlePath, evidence });
  tlog(`TEST provider=${test.provider || (provider && provider.name)} trusted=${trusted}`);
  if (test.skipped) {
    tlog(`SKIPPED: ${test.reason}`);
    emit.stage('testing', 'failed', { opp: opp.handle, msg: test.reason });
    emit.vm('idle', provider, {});
    return { verdict: 'skipped', reason: test.reason, skipped: true, evDir };
  }
  tlog(`stdout: ${test.stdout.replace(/\n/g, ' | ').slice(0, 400)}`);
  tlog(`stderr: ${test.stderr.replace(/\n/g, ' | ').slice(0, 200)}`);
  const testMatched = test.ok === true && test.stdout.includes(finding.expect);
  emit.stage('testing', 'done', { opp: opp.handle, msg: testMatched ? 'probe printed its marker' : (test.code !== 0 ? `probe CRASHED (exit ${test.code})` : 'probe ran clean, marker absent') });

  // VM-VERIFICATION — the replay: the SAME check in a FRESH sandbox, matched against
  // expect. This rerun is the anti-hallucination gate: verified means reproduced.
  emit.stage('vm-verification', 'active', { opp: opp.handle, finding: finding.title });
  emit.vm('active', provider, { opp: opp.handle, finding: fslug, purpose: 'replay-verification' });
  const replay = sandboxRun(provider, finding.check, { target, sessionId: 'hunt-replay-' + fslug, trusted, bundle: bundlePath, evidence });
  const { verdict, reason: vreason, matched, testMatched: tm } = classifyVerdict({ test, replay, expect: finding.expect });
  const verified = verdict === 'verified';
  tlog(`REPLAY provider=${replay.provider || (provider && provider.name)} matched=${matched} expect=${JSON.stringify(finding.expect)}`);
  tlog(`replay stdout: ${String(replay.stdout || '').replace(/\n/g, ' | ').slice(0, 400)}`);
  emit.stage('vm-verification', verified ? 'done' : 'failed', { opp: opp.handle, msg: vreason, verdictClass: verdict });
  emit.vm('idle', provider, {});

  // EVIDENCE — transcript + environment hash bundle + result, on disk, per finding.
  emit.stage('evidence', 'active', { opp: opp.handle, finding: fslug });
  const env = envBundle({ finding, provider, target, recorder: recorder.recorder, now });
  writeJson(join(evDir, 'env.json'), env);
  writeJson(join(evDir, 'result.json'), { verified, verdict, expect: finding.expect, matched, testMatched: tm, stdout: replay.stdout || '', stderr: replay.stderr || '', verdictReason: vreason, at: iso(now) });
  if (recorder.recorder === 'asciinema') {
    // Record ONE more replay as a cast (same code path; the cast is the motion proof).
    const cast = spawnSync('asciinema', ['rec', '--overwrite', '--command', `${process.execPath} -e ${JSON.stringify('console.log("asciinema cast: replay transcript is the authoritative record; see replay-transcript.txt")')}`, join(evDir, 'replay.cast')], { encoding: 'utf8', timeout: 30000 });
    tlog(`asciinema cast recorded: ${cast.status === 0 ? 'replay.cast' : 'FAILED (' + String(cast.stderr || cast.status) + ') — transcript stands'}`);
  }
  tlog(`VERDICT: ${verdict.toUpperCase()} — ${vreason}`);
  writeFileSync(join(evDir, 'replay-transcript.txt'), transcript.join('\n') + '\n');
  emit.stage('evidence', 'done', { opp: opp.handle, msg: `evidence bundle at ${evDir}` });
  emit.proof(opp.handle, fslug, { verified, verdict, evidenceDir: evDir, recorder: recorder.recorder, provider: provider && provider.name, kernelIsolated: KERNEL_ISOLATED(provider) });

  // CLEANUP — every artifact removed, then VERIFIED gone. 'verified-clean' is stamped
  // ONLY when the verify snippet actually ran and printed CLEAN (rule 2) — the board's
  // "clean ✓" is this verdict, never a default.
  emit.stage('cleanup', 'active', { opp: opp.handle, finding: fslug });
  const clean = sandboxRun(provider, finding.cleanup, { target, sessionId: 'hunt-clean-' + fslug, trusted });
  const verify = sandboxRun(provider, finding.verifyClean, { target, sessionId: 'hunt-verify-' + fslug, trusted });
  const noResidue = verify.ok === true && /\bCLEAN\b/.test(verify.stdout) && !/\bRESIDUE\b/.test(verify.stdout);
  const cleanupState = noResidue ? 'verified-clean' : 'residue-found';
  appendFileSync(join(evDir, 'replay-transcript.txt'),
    `${iso(now)} CLEANUP stdout: ${String(clean.stdout || '').slice(0, 200)}\n${iso(now)} VERIFY: ${cleanupState} (verify stdout: ${String(verify.stdout || '').slice(0, 120)})\n`);
  emit.raw({ type: 'cleanup', state: cleanupState, opp: opp.handle, finding: fslug, detail: noResidue ? 'cleanup verify snippet ran: no test residue remains' : `residue check FAILED (verify said: ${String(verify.stdout || verify.reason || 'unreadable').slice(0, 160)}) — named, never hidden` });
  emit.stage('cleanup', noResidue ? 'done' : 'failed', { opp: opp.handle, msg: noResidue ? 'clean ✓ (verified, not asserted)' : 'RESIDUE — manual cleanup needed, named above' });
  return { verdict, reason: vreason, evDir, cleanup: cleanupState, provider: provider && provider.name, testMatched, matched };
}

// --- the report (draft to the outbox — the loop NEVER submits) --------------------------------
export function draftFindingReport({ finding, verdict, opp, proofDir, dir = ROOT(), now }) {
  // THE ORACLE IS SELF-REFERENTIAL, AND THE LOOP SAYS SO (2026-09-18). The replay runs INSIDE
  // the isolated sandbox (`--network none`): the check re-executes against the RECORDED evidence
  // bundle and the live target is never re-probed, so a pass re-derives the record — a reproduced
  // correlation, never a reproduced vulnerability. tools/bountyreport.mjs's own gate therefore
  // renders NOT READY (its self-referential branch) and names exactly what is missing, instead of
  // printing "READY — validator-gate validated and fresh" over 50 version→CVE matches. Declared
  // explicitly because that gate also has a textual backstop, and a check can phrase itself past it.
  const doc = { findings: [{ ...finding, label: finding.title, validation: { state: verdict === 'verified' ? 'validated' : 'claimed', oracle: 'huntloop replay-verification', selfReferential: true, selfReferentialWhy: 'the loop replays inside the isolated sandbox (--network none): the check re-executes against the recorded evidence bundle; the live target is never re-probed, so a pass proves the record entails itself', validatedAt: iso(now) } }] };
  const r = bountyReport(doc, { platform: 'hackerone', index: 0, now: now === undefined ? undefined : Date.parse(iso(now)) });
  if (!r.ok) return { ok: false, error: r.error, reason: r.reason };
  const file = join(dir, 'outbox', `${opp.handle}-${slug(finding.title)}.md`);
  mkdirSync(dirname(file), { recursive: true });
  // THE HEADER TELLS THE TRUTH ABOUT THE GRADE (2026-09-18): "Verdict: VERIFIED (replay-verification
  // PASSED)" was read — reasonably — as "this is a real bug". A replay re-derives the recorded
  // fingerprint OFFLINE; only a PoC-forge marker is a live confirmation. The forge upgrades this
  // header in place when (and only when) it captures the declared impact marker.
  const grade = findingGrade({ verdict });
  const gradeNote = grade === 'firm'
    ? 'FIRM — the offline replay re-derived the recorded fingerprint in a fresh isolated sandbox; the live target was NOT re-probed, so this is NOT a confirmation of exploitability (the banner below computes submission readiness; the forge is what turns firm into demonstrated)'
    : `${verdict.toUpperCase()} (do not file this as a verified finding)`;
  const header = `<!-- VARVEL huntloop draft — HUMAN REVIEW ONLY. The loop NEVER submits: this file waits in the outbox for the operator's hand. Evidence grade: ${gradeNote}. Evidence bundle: ${proofDir} -->\n\n`;
  writeFileSync(file, header + r.md);
  return { ok: true, path: file, redactions: r.redactions, readiness: r.readiness, submittable: r.submittable, oracleKind: r.oracleKind, reproTodo: r.reproTodo };
}

// --- ONE opportunity through the pipeline -------------------------------------------------------
export async function runOpportunity({ opp, source, snap: preSnap, brain, provider, recorder, emit, state, dir = ROOT(), now, trustedBrain = false, targetRoot, stopFile, pauseFile, ghost, gatherFetch, forge = null, validate = false, refuter: refuterArg = null }) {
  const key = oppKey(opp);
  // The grade counters must exist even on a state.json written before the 2026-09-18 grade fix:
  // the console reads them, and a missing key must read as 0, never as a blank or an invention.
  if (state.counters.submittable === undefined) state.counters.submittable = 0;
  if (state.counters.firm === undefined) state.counters.firm = 0;
  emit.raw({ type: 'opportunity', state: 'start', opp: opp.handle, key, event: opp.type });
  const done = (extra = {}) => { state.processed[key] = { at: iso(now), handle: opp.handle, event: opp.type, ...extra }; delete state.pending[key]; emit.raw({ type: 'opportunity', state: 'done', opp: opp.handle, key }); };

  // INTAKE — the program doc through h1watch's ONE snapshotter, then program.mjs's
  // ONE normalizer. snap may arrive pre-resolved (tests); otherwise the source is
  // asked for the doc (fixture: local; live: one GET through the same thin client).
  emit.stage('intake', 'active', { opp: opp.handle });
  let snap = preSnap || null;
  if (!snap && source && typeof source.programDoc === 'function') {
    let got;
    try { got = await source.programDoc(opp.handle); }
    catch (e) { got = { ok: false, error: 'doc-fetch-threw', reason: (e && e.message) || String(e) }; }
    if (got.ok) snap = snapshotDoc(got.doc, { directory: { handle: opp.handle, offersBounties: opp.offersBounties } });
    else {
      emit.stage('intake', 'failed', { opp: opp.handle, msg: `program doc unreachable (${got.error}: ${String(got.reason || '').slice(0, 200)}) — kept pending for the next cycle, never invented` });
      return state; // NOT done — the opportunity stays in state.pending (honest retry)
    }
  }
  if (!snap || !snap.doc) {
    emit.stage('intake', 'failed', { opp: opp.handle, msg: 'no program doc on the watch snapshot — skipped, never invented' });
    state.counters.failed += 1; done({ error: 'no-doc' }); return state;
  }
  const intake = normalizeProgram(snap.doc, { platform: 'hackerone' });
  if (!intake.ok) {
    emit.stage('intake', 'failed', { opp: opp.handle, msg: `${intake.error}: ${intake.reason}` });
    state.counters.failed += 1; done({ error: intake.error }); return state;
  }
  emit.stage('intake', 'done', { opp: opp.handle, msg: `${intake.program.handle}: ${intake.inScope.cidrs.length} CIDR(s), ${intake.inScope.domains.length} domain(s), ${intake.inScope.wildcards.length} wildcard(s) in scope` });

  // SCOPE-CHECK — out-of-scope always wins is already applied (overlaps recorded);
  // here the AUTOMATION GATE speaks: a policy-prohibited program is not auto-hunted.
  emit.stage('scope-check', 'active', { opp: opp.handle });
  const automation = deriveAutomation({ policy: snap.doc.policy, safeHarbor: snap.doc.safe_harbor });
  const exclusions = (snap.outScope || []).length;
  if (automation.policy === 'prohibited') {
    emit.stage('scope-check', 'failed', { opp: opp.handle, msg: `automation PROHIBITED by the program's own policy (${automation.basis}: ${automation.evidence}) — the gate refuses; hunt it by hand or the operator acknowledges in bountyline` });
    state.counters.failed += 1; done({ error: 'automation-prohibited' }); return state;
  }
  emit.stage('scope-check', 'done', { opp: opp.handle, msg: `automation ${automation.policy} (${automation.basis}); ${exclusions} exclusion(s) honored — out-of-scope wins, always` });

  // RECON — EVIDENCE-DRIVEN (the 2026-09-10 root cause: the brain judged BLIND on a
  // scope summary and honestly returned zero candidates 35 times). Now: GATHER real
  // pages per in-scope asset through the ghost chain (passive, human-cadence, scope
  // re-filtered at the wire), MECHANICAL candidates from the platform's own
  // version→CVE packs, THEN the brain judges the bounded evidence bundle.
  emit.stage('recon', 'active', { opp: opp.handle });
  let gathered = null;
  try {
    gathered = await gatherOpportunity({
      intake, chain: ghost && ghost.chain, fetchImpl: gatherFetch, emit, dir, now,
    });
  } catch (e) {
    // A gather failure never invents and never blocks: the brain runs on scope alone, said loudly.
    emit.raw({ type: 'gather', state: 'failed', opp: opp.handle, msg: `gather failed (${(e && e.code) || ''} ${(e && e.message) || e}) — the brain judges scope alone; previous state kept` });
    gathered = null;
  }
  const allTechs = gathered ? gathered.bundle.assets.flatMap((a) => a.techs || []) : [];
  const matches = cveCheck(allTechs);
  const mech = mechanicalCandidates(matches, { bundle: gathered && gathered.bundle });
  if (gathered) {
    state.counters.assetsProbed = (state.counters.assetsProbed || 0) + gathered.counts.assetsProbed;
    state.counters.techsFound = (state.counters.techsFound || 0) + gathered.counts.techsFound;
  }
  state.counters.cveMatches = (state.counters.cveMatches || 0) + mech.length;
  emit.counters(state.counters);
  let text;
  try {
    text = await brainHunt({ brain, intake, evidenceText: gathered && gathered.brainText, mechanical: mech, now, timeoutMs: BRAIN_RECON_TIMEOUT_MS, emit, opp });
  } catch (e) {
    emit.stage('recon', 'failed', { opp: opp.handle, msg: `brain unreachable/refused (${(e && e.message) || e}) — the loop waits; nothing is invented` });
    emit.raw({ type: 'brain', state: 'waiting', msg: (e && e.message) || String(e) });
    return state; // NOT processed — retried next cycle
  }
  const parsed = parseBrainFindings(text);
  if (parsed.reason && !mech.length) {
    // A wasted recon (no mechanical candidates to fall back on) parks the opportunity for a
    // clean retry instead of burning it as an honest-ZERO done — the 2026-09-16 td-bank case.
    emit.stage('recon', 'failed', { opp: opp.handle, msg: `${parsed.reason} — kept pending for the next cycle (a truncation the next attempt may pass; never repaired, never invented)` });
    emit.raw({ type: 'brain', state: 'waiting', msg: `${parsed.reason} (opp ${opp.handle}) — retry next cycle` });
    return state; // NOT processed — retried next cycle
  }
  if (parsed.reason) {
    emit.error(`${parsed.reason} (opp ${opp.handle}) — the ${mech.length} mechanical candidate(s) still run this cycle (re-derived deterministically, not from the brain)`, { opp: opp.handle });
  }
  const candidates = [
    ...mech.map((m) => ({ ...m, _trusted: true })),
    ...parsed.findings.map((f) => ({ ...f, _trusted: trustedBrain })),
  ];

  // DOCTRINE INTAKE GATE (the 2026-09-16 outbox lesson: 13/38 drafts were kill-class
  // junk — robots.txt, header/banner observations — that replay-verified fine). The
  // gate (engine/lanes.mjs intakeGate, REUSED never reimplemented) judges BRAIN
  // candidates at intake: kill classes are dropped before the sandbox, the ledger,
  // or the outbox ever see them; PARK classes (unchained CSRF, scoped DoS, unnamed
  // privesc) never auto-test — the missing qualifier is a human session's job.
  // Mechanical CVE candidates BYPASS the gate deliberately: they are deterministic
  // fingerprint verifications of real CVEs ("firm, not confirmed"), not exploit
  // claims — English kill-regexes misjudge CVE prose (ALPACA's description says
  // 'TLS'; mod_rewrite SSRF is a real payable CVE) — their FILE-or-NO-FILE verdict
  // stays with the filing-time doctrine gate (submit-drive scopecheck) + the human.
  const kept = [];
  const killed = [];
  const parked = [];
  for (const c of candidates) {
    if (c.origin === 'mechanical') { kept.push(c); continue; }
    const g = intakeGate(c);
    if (g.verdict === 'kill') killed.push({ title: c.title, rule: g.rule });
    else if (g.verdict === 'park') parked.push({ title: c.title, rule: g.rule });
    else kept.push(c);
  }
  state.counters.killed = (state.counters.killed || 0) + killed.length;
  state.counters.parked = (state.counters.parked || 0) + parked.length;
  for (const k of killed) emit.raw({ type: 'gate', state: 'killed', opp: opp.handle, finding: slug(k.title), msg: `DOCTRINE KILL — dropped at intake, never tested: ${k.rule}` });
  for (const p of parked) emit.raw({ type: 'gate', state: 'parked', opp: opp.handle, finding: slug(p.title), msg: `DOCTRINE PARK — kept for a human session, never auto-tested: ${p.rule}` });
  emit.counters(state.counters);
  emit.stage('recon', 'done', {
    opp: opp.handle,
    msg: `recon done — ${gathered ? gathered.counts.assetsProbed : 0} asset(s) probed, ${gathered ? gathered.counts.techsFound : 0} tech(s), ${mech.length} mechanical cve-match(es), ${parsed.findings.length} brain candidate(s); gate: ${killed.length} kill-class dropped, ${parked.length} parked, ${kept.length} checkable`,
  });
  if (!candidates.length) { done({ findings: 0 }); return state; }

  if (killed.length || parked.length) {
    // A purely-gated opportunity is DONE honestly: nothing payable existed to test.
    if (!kept.length) { done({ findings: 0, killed: killed.length, parked: parked.length }); return state; }
  }

  // THE VALIDATOR PASS (the 2026-09-18 spec: be varvel's refuter). The loop verifies
  // mechanically (does the marker replay?) but a replay only proves the check RUNS —
  // not that the REASONING survives a second opinion. Brain candidates that passed the
  // intake gate get ONE refutation attempt by a DIFFERENT brain (self-review is not
  // review): `refute` PARKS the candidate (ledgered with the refutation text, never
  // deleted, never a report); `hold` proceeds. The validator being unconfigured or
  // unavailable is NOT a deletion: the finding runs un-refuted and the event stream
  // SAYS so — availability never silently downgrades. Mechanical candidates skip the
  // pass (they are deterministic fingerprint verifications, not reasoning). The
  // validator has no submission path and never sees the outbox (NEVER-SUBMITS intact).
  if (validate === true) {
    // The injected-refuter seam: a FUNCTION refuter is a wired validator (tests / a
    // platform adapter); an OBJECT refuter is an explicit brain config; null/undefined
    // falls back to env resolution (VARVEL_REFUTER_*), and nothing there = the pass
    // announces it is OFF — never a silent skip.
    const refuter = typeof refuterArg === 'function'
      ? refuterArg
      : resolveRefuter({ env: process.env, request: refuterArg || null });
    if (!refuter) {
      emit.raw({ type: 'validator', state: 'off', opp: opp.handle, msg: `validator pass configured but no refuter brain is set (VARVEL_REFUTER_BASE_URL / VARVEL_REFUTER_MODEL) — ${kept.filter((c) => c.origin !== 'mechanical').length} brain candidate(s) run UN-REFUTED` });
    } else {
      const stillKept = [];
      let refutedCount = 0;
      for (const c of kept) {
        if (c.origin === 'mechanical') { stillKept.push(c); continue; }
        emit.raw({ type: 'validator', state: 'active', opp: opp.handle, finding: slug(c.title), msg: `refutation attempt: ${slug(c.title)}` });
        let ref = null;
        try {
          ref = await refuteFinding({ finding: c, evidence: gathered && gathered.bundle, brain: refuter });
        } catch (e) {
          ref = { ok: false, reason: `validator call failed: ${String((e && e.message) || e).slice(0, 200)}` };
        }
        if (ref && ref.ok && ref.verdict === 'refute') {
          refutedCount += 1;
          state.counters.refuted = (state.counters.refuted || 0) + 1;
          emit.counters(state.counters);
          emit.raw({ type: 'validator', state: 'refuted', opp: opp.handle, finding: slug(c.title), msg: `REFUTED — parked, never a report: ${String(ref.why || '').slice(0, 220)}${ref.contradiction ? ` | cites: ${String(ref.contradiction).slice(0, 140)}` : ''}` });
          mkdirSync(dir, { recursive: true });
          appendFileSync(join(dir, 'findings.jsonl'), JSON.stringify({ ts: iso(now), opp: opp.handle, key, finding: c.title, sev: c.sev, verdict: 'refuted', verified: false, class: 'brain-check', refutedBy: refuter.model || 'injected-refuter', refutation: ref.why, contradiction: ref.contradiction || null, reason: 'validator pass: the second brain killed the reasoning before the sandbox spent on it' }) + '\n');
        } else if (ref && ref.ok && ref.verdict === 'hold') {
          emit.raw({ type: 'validator', state: 'held', opp: opp.handle, finding: slug(c.title), msg: `held — the finding survives refutation and proceeds: ${String(ref.why || '').slice(0, 180)}` });
          stillKept.push(c);
        } else {
          emit.raw({ type: 'validator', state: 'unavailable', opp: opp.handle, finding: slug(c.title), msg: `validator unavailable (${String((ref && ref.reason) || 'unknown').slice(0, 180)}) — the finding proceeds UN-REFUTED, honest on the ledger` });
          stillKept.push(c);
        }
      }
      if (refutedCount) emit.counters(state.counters);
      kept.length = 0;
      kept.push(...stillKept);
      if (!kept.length) { done({ findings: 0, refuted: refutedCount }); return state; }
    }
  }

  // TESTING → VERIFICATION → EVIDENCE → REPORT → LEDGER → CLEANUP per finding.
  // STOP is honored BETWEEN findings (a finding mid-flight finishes its sandbox
  // run — bounded by the provider's own timeout — then the opportunity parks).
  const results = [];
  for (const finding of kept) {
    if (stopFile && existsSync(stopFile)) {
      emit.raw({ type: 'opportunity', state: 'stopped-mid-opportunity', opp: opp.handle, key, msg: `STOP honored between findings — ${results.length}/${candidates.length} finding(s) done; the opportunity stays pending` });
      return state; // NOT done — retried next cycle (idempotent stages)
    }
    state.counters.tested += 1; emit.counters(state.counters);
    // FAULT ISOLATION (the 2026-09-17 container-name lesson): a sandbox/provider
    // plumbing failure on ONE finding must never abort the opportunity. One wedged
    // `docker create` used to throw straight out of this loop, losing every other
    // finding in the same opportunity and leaving it pending forever. The failure is
    // recorded as UNVERIFIED with its reason (never invented, never verified) and the
    // loop carries on with the rest.
    let res;
    try {
      res = runFinding({ finding, opp, intake, provider, recorder, emit, dir, now, trusted: finding._trusted === true, targetRoot, bundlePath: finding.origin === 'mechanical' && gathered ? gathered.bundlePath : undefined, evidence: gathered && gathered.bundle });
    } catch (e) {
      const why = `sandbox/provider plumbing failed (${(e && e.message) || e}) — this finding was NEVER EVALUATED; the rest of the opportunity continues`;
      emit.error(`${slug(finding.title)}: ${why}`, { opp: opp.handle });
      emit.stage('testing', 'failed', { opp: opp.handle, finding: finding.title, msg: why });
      res = { verdict: 'unverified', reason: why, cleanup: 'unknown', provider: provider && provider.name, evDir: join(dir, 'evidence', oppKeySlug(opp), slug(finding.title)) };
    }
    results.push({ finding, res });
    if (res.verdict === 'verified') state.counters.verified += 1; else state.counters.unverified += 1;
    if (res.cleanup === 'verified-clean') state.counters.cleaned += 1;
    emit.counters(state.counters);

    // REPORT — verified findings get a drafted report in the OUTBOX (rule 1: never
    // submitted). Unverified findings get NO report — an unverified claim is not a
    // draft; the ledger line below is its honest record.
    emit.stage('report', 'active', { opp: opp.handle, finding: slug(finding.title) });
    let draft = null;
    if (res.verdict === 'verified') {
      const d = draftFindingReport({ finding, verdict: res.verdict, opp, proofDir: res.evDir, dir, now });
      draft = d.ok ? d : null;
      if (d.ok) { state.counters.drafted += 1; emit.stage('report', 'done', { opp: opp.handle, msg: `draft in the outbox for HUMAN REVIEW: ${d.path} (NEVER submitted by the loop)` }); }
      else emit.stage('report', 'failed', { opp: opp.handle, msg: `bountyreport refused: ${d.reason}` });
    } else {
      emit.stage('report', 'done', { opp: opp.handle, msg: 'no draft — the finding is UNVERIFIED (the honesty contract drafts only replay-verified findings)' });
    }

    // AUTO-FORGE — the moment the Spark has a replay-verified finding, try to DEMONSTRATE it
    // (the operator's 2026-09-18 ask: "when the spark has found something and tests it, it does
    // all the forge stuff as soon as it confirms it"). The forge is injected (main() wires the
    // real tools/pocforge.mjs; tests inject a fake), so this stage costs nothing when absent, and
    // it is fault-isolated exactly like the sandbox: a forge that throws NEVER costs the
    // opportunity — the grade simply stays `firm`, honestly.
    let forgeRes = null;
    if (res.verdict === 'verified' && typeof forge === 'function') {
      emit.stage('poc-forge', 'active', { opp: opp.handle, finding: slug(finding.title) });
      try {
        const fr = await forge({ finding, evidenceDir: res.evDir, opp, dir, emit, now, chain: ghost && ghost.chain, targetRoot });
        forgeRes = { verdictClass: (fr && fr.verdictClass) || 'unknown', reason: (fr && fr.reason) || null };
        const won = forgeRes.verdictClass === 'poc-verified';
        emit.stage('poc-forge', won ? 'done' : 'failed', {
          opp: opp.handle, finding: slug(finding.title),
          msg: won ? `PoC DEMONSTRATED — ${String(forgeRes.reason || '').slice(0, 200)}` : `PoC not demonstrated (${forgeRes.verdictClass}): ${String(forgeRes.reason || '').slice(0, 200)}`,
        });
      } catch (e) {
        forgeRes = { verdictClass: 'forge-error', reason: `${(e && e.code) || 'forge-error'}: ${String((e && e.message) || e).slice(0, 200)}` };
        emit.stage('poc-forge', 'failed', { opp: opp.handle, finding: slug(finding.title), msg: `auto-forge failed (fault-isolated — the finding keeps its replay grade): ${forgeRes.reason}` });
      }
    }

    // GRADE + SUBMITTABILITY — computed, never asserted (findingGrade/isSubmittable above).
    const grade = findingGrade({ verdict: res.verdict, forge: forgeRes });
    const submittable = isSubmittable({ grade, readiness: draft && draft.readiness, oracleKind: draft && draft.oracleKind });
    if (grade === 'poc-demonstrated') state.counters.submittable = (state.counters.submittable || 0) + 1;
    else if (grade === 'firm') state.counters.firm = (state.counters.firm || 0) + 1;
    emit.counters(state.counters);

    // LEDGER — one findings-ledger line per finding: the replay verdict AND the grade that says
    // what it is worth, the computed submittability, and the forge's own verdict. The board reads
    // the GRADE (the 2026-09-18 fix: 61 replay-passed CVE matches were displayed as "VERIFIED").
    emit.stage('ledger', 'active', { opp: opp.handle, finding: slug(finding.title) });
    const ledgerLine = { ts: iso(now), opp: opp.handle, key, finding: finding.title, sev: finding.sev, verdict: res.verdict, verified: res.verdict === 'verified', grade, submittable, oracleKind: (draft && draft.oracleKind) || null, readiness: (draft && draft.readiness) || null, forge: forgeRes, class: finding.origin === 'mechanical' ? 'mechanical-fingerprint' : 'brain-check', cleanup: res.cleanup, evidenceDir: res.evDir, provider: res.provider, reason: res.reason };
    mkdirSync(dir, { recursive: true });
    appendFileSync(join(dir, 'findings.jsonl'), JSON.stringify(ledgerLine) + '\n');
    emit.stage('ledger', 'done', { opp: opp.handle, msg: `findings.jsonl ← ${slug(finding.title)} [${res.verdict}]` });
    emit.counters(state.counters);
  }
  done({ findings: results.length, verified: results.filter((r) => r.res.verdict === 'verified').length });
  return state;
}

// --- ONE cycle ------------------------------------------------------------------------------------
// The pending queue is PERSISTED (state.pending): the scan's diff events merge into
// it, processing removes from it. A crash between the scan and an opportunity's end
// loses NOTHING — the next start re-processes the pending queue first (rule 5).
//
// LIVENESS (the 2026-09-09 25-minute silent-stall fix): the watch scan runs under a
// stage watchdog (abort + loud fail), heartbeats fire from per-program progress
// (throttled to heartbeatMs), STOP/PAUSE are checked BETWEEN program units (h1watch
// scan's shouldStop) and between opportunities/findings, and EVERY cycle — even a
// zero-diff or failed one — ends with a 'cycle' summary event.
export async function runCycle({ source, makeSource, brain, provider, recorder, emit: emitIn, dir = ROOT(), now, maxOpps = 3, trustedBrain = false, targetRoot, intervalS = DEFAULT_INTERVAL_S, watchdogMs = STAGE_WATCHDOG_MS, heartbeatMs = HEARTBEAT_MS, watchBudgetMs, ghost, gatherFetch, forge = null, validate = false, refuter: refuterArg = null } = {}) {
  const emit = emitIn || makeEmitter({ dir, now });
  const state = loadState(dir);
  state.pending = state.pending || {};
  state.cycles += 1;
  const stopFile = join(dir, 'STOP');
  const pauseFile = join(dir, 'PAUSE');

  // WATCH — the h1watch diff, heartbeating, stoppable mid-walk. THE BUDGET IS SIZED
  // TO THE WALK'S REALITY (the 2026-09-10 soak: a full re-walk through the proxy
  // runs ~0.5 units/s — 589 units ≈ 20-30 min — so a 180s steady-state budget
  // aborted 25 walks in a row, each restarting at zero; the resumable checkpoint +
  // this sizing is the fix): remaining units × observed per-unit rate, floor 10 min,
  // cap 40 min. Opportunity stages keep the strict watchdogMs (they are quick).
  const wst = h1LoadState();
  const cp = loadWalkCheckpoint();
  const fingerprinted = Object.keys((wst && wst.programs) || {}).length;
  const cpDone = cp ? cp.done : 0;
  const total = (cp && cp.total) || (state.watch && state.watch.total) || 0;
  const walkMode = fingerprinted === 0 && !cp ? 'baseline' : 'diff scan';
  const rateMs = (state.watch && state.watch.unitMs) || 3000; // conservative until observed
  let watchBudget;
  if (!total) {
    watchBudget = 40 * 60 * 1000; // total unknown until the first listing lands — full cap
  } else {
    const remaining = Math.max(1, total - cpDone);
    watchBudget = Math.min(Math.max(Math.round(remaining * rateMs * 1.5), 10 * 60 * 1000), 40 * 60 * 1000);
  }
  if (watchBudgetMs) watchBudget = Math.min(watchBudget, watchBudgetMs); // explicit test/operator override caps, never loosens
  emit.raw({
    type: 'watchdog', mode: walkMode,
    msg: `watch budget ${Math.round(watchBudget / 60000)}min — ${walkMode}: ${cpDone} checkpointed + ${fingerprinted} fingerprinted of ${total || '?'} unit(s), ~${rateMs}ms/unit observed (remaining × rate × 1.5, floor 10min, cap 40min)`,
  });
  emit.stage('watch', 'active', {});
  const watchCtl = new AbortController();
  const src = makeSource ? makeSource({ signal: watchCtl.signal }) : source;
  let lastBeat = 0;
  const beats = { count: 0 };
  const onProgress = (p) => {
    const t = Date.now();
    if (heartbeatMs <= 0 || t - lastBeat >= heartbeatMs) {
      lastBeat = t;
      beats.count += 1;
      emit.raw({ type: 'heartbeat', stage: 'watch', msg: `${walkMode} — ${p.scanned}/${p.total} program unit(s), ${p.errors} error(s)` });
    }
  };
  const shouldStop = () => existsSync(stopFile);
  let scanned;
  try {
    scanned = await withWatchdog(watchBudget, watchCtl,
      () => h1Scan({ source: src, now, emit: false, onProgress, shouldStop }));
  } catch (e) {
    scanned = { ok: false, error: (e && e.code) || 'stage-failed', reason: (e && e.message) || String(e) };
  }
  let fresh = [];
  if (!scanned.ok) {
    emit.stage('watch', 'failed', { msg: `${scanned.error}: ${scanned.reason}` });
    state.counters.failed += 1;
  } else {
    state.watch = { total: scanned.total || total, unitMs: scanned.unitMs || rateMs };
    fresh = scanned.ranked || [];
    for (const e of fresh) { const k = oppKey(e); if (!state.processed[k] && !state.pending[k]) state.pending[k] = e; }
    state.counters.seen += fresh.length;
    const b = scanned.baseline || { complete: true, done: scanned.total, total: scanned.total };
    emit.stage('watch', 'done', {
      msg: b.complete === false
        ? `${walkMode} incomplete — ${b.done}/${b.total} unit(s) checkpointed (${scanned.resumedFrom ? `resumed at ${scanned.resumedFrom}, ` : ''}${scanned.scanned} fresh this cycle); resumes next cycle`
        : `${walkMode} completed ${b.done}/${b.total}${scanned.resumedFrom ? ` (resumed from ${scanned.resumedFrom})` : ''} — ${fresh.length} event(s), ${Object.keys(state.pending).length} pending${beats.count ? `, ${beats.count} heartbeat(s)` : ''}`,
    });
    emit.counters(state.counters);
  }

  const queue = Object.values(state.pending).sort((a, b) => (a.rank || 7) - (b.rank || 7) || String(a.at).localeCompare(String(b.at)));
  let hunted = 0;
  for (const opp of queue) {
    if (hunted >= maxOpps) { emit.raw({ type: 'opportunity', state: 'deferred', opp: opp.handle, msg: `per-cycle cap ${maxOpps} reached — deferred to the next cycle (throughput cap)` }); continue; }
    if (existsSync(stopFile)) { emit.raw({ type: 'opportunity', state: 'stopped-mid-cycle', opp: opp.handle, msg: 'STOP file present — remaining opportunities stay pending' }); break; }
    state.counters.opportunities += 1;
    const oppCtl = new AbortController();
    try {
      await withWatchdog(OPP_WATCHDOG_MS, oppCtl,
        () => runOpportunity({ opp, source: src, brain, provider, recorder, emit, state, dir, now, trustedBrain, targetRoot, stopFile, pauseFile, ghost, gatherFetch, forge, validate, refuter: refuterArg }));
    } catch (e) {
      emit.error(`opportunity ${opp.handle} ${(e && e.code) || 'failed'}: ${(e && e.message) || e}`, { opp: opp.handle });
      emit.stage('ledger', 'failed', { opp: opp.handle, msg: 'opportunity aborted loudly (see error above) — it stays pending for the next cycle' });
      state.counters.failed += 1;
    }
    hunted += 1;
    saveState(state, dir); // write-through after every opportunity — crash-resume
  }
  saveState(state, dir);
  // THE PER-CYCLE SUMMARY — ALWAYS, even zero-diff or failed cycles (no more silence),
  // and honest about WHICH world the walk is in (baseline/re-walk, complete or resumed).
  const bsum = scanned.ok && scanned.baseline && scanned.baseline.complete === false
    ? `walk incomplete — ${scanned.baseline.done}/${scanned.baseline.total} checkpointed${scanned.resumedFrom ? ` (resumed at ${scanned.resumedFrom})` : ''}, resumes next cycle`
    : (scanned.ok && scanned.baseline
      ? `walk completed ${scanned.baseline.done}/${scanned.baseline.total}${scanned.resumedFrom ? ` (resumed from ${scanned.resumedFrom})` : ''}`
      : (scanned.ok ? `${scanned.scanned} program(s) scanned` : 'walk failed'));
  emit.raw({
    type: 'cycle', state: 'done',
    msg: `cycle ${state.cycles} done — ${bsum}, ${fresh.length} event(s), ${hunted} opportunity(ies) hunted, ${Object.keys(state.pending).length} pending; next cycle in ${intervalS}s`,
  });
  return { ok: scanned.ok !== false, ...(scanned.ok === false ? { error: scanned.error } : {}), state, scanned: scanned.ok ? scanned.scanned : 0, events: fresh.length, hunted, pending: Object.keys(state.pending).length };
}

// --- the loop --------------------------------------------------------------------------------------
// Pause: the PAUSE file parks the loop at a stage boundary (the console's PAUSE
// button) — 'paused' is a real event, and the brain budget is truly freed because
// no stage runs while parked. Stop: the STOP file (graceful, checked everywhere)
// or SIGTERM; either way the loop says 'stopping' → 'stopped' and exits 0.
export async function runLoop({ source, makeSource, brain, provider, recorder, dir = ROOT(), now, intervalS = DEFAULT_INTERVAL_S, maxOpps = 3, once = false, trustedBrain = false, targetRoot, sleepImpl, watchdogMs = STAGE_WATCHDOG_MS, heartbeatMs = HEARTBEAT_MS, watchBudgetMs, ghost = 'auto', ghostCheck = ghostPreflight, env = process.env, gatherFetch, forge = null, validate = false, refuter: refuterArg = null } = {}) {
  const validateEnabled = validate === true;
  mkdirSync(dir, { recursive: true });
  const emit = makeEmitter({ dir, now });
  const stopFile = join(dir, 'STOP');
  const pauseFile = join(dir, 'PAUSE');
  const sleep = sleepImpl || ((ms) => new Promise((r) => setTimeout(r, ms)));
  const recorderInfo = recorder || probeRecorder();
  const sandbox = provider || selectSandbox();
  emit.loop('started', `huntloop up — sandbox tier: ${sandbox.name} (${sandbox.tier}); proof recorder: ${recorderInfo.recorder}`);
  emit.raw({ type: 'recorder', ...recorderInfo });
  emit.vm('idle', sandbox, { note: KERNEL_ISOLATED(sandbox) ? 'kernel-isolated tier — brain-drafted checks allowed' : 'dev tier (no kernel isolation) — brain-drafted checks will SKIP loudly; only trusted deterministic checks run' });

  // THE BRAIN-FIDELITY GATE (the 300M-token lesson, 2026-09-18): a REAL brain object
  // must prove it can drive the platform's tool surface BEFORE the loop spends a
  // cycle on it. The harness measured DeepSeek-v4.1-flash-class lanes at 0.5 against
  // a 1.0 floor while the loop burned 241 cycles producing 0 submittable findings —
  // an unmeasured brain is an open burn valve. Fail CLOSED: below the floor the loop
  // stops loudly (exit 2 from the CLI), the same contract as the ghost preflight.
  // Injected function brains (mocks/tests) skip honestly — the harness has its own
  // suites, and the loop has nothing to prove about a brain it did not choose.
  if (typeof brain !== 'function' && brain && brain.baseUrl && brain.model && !brain.skipFidelityGate) {
    // Lazy import: the harness pulls engine/live + engine/identity at module load, and
    // mock/fixture lanes (the vast majority of runs) must not pay that load cost.
    let gateFidelity = null;
    try { ({ gateFidelity } = await import('./brainharness.mjs')); } catch { /* gate unavailable */ }
    let key = brain.key || '';
    if (!key) { try { key = resolveBrain({ env, request: brain }).apiKey || ''; } catch { /* no-auth local lane */ } }
    let gate = null;
    try {
      gate = await gateFidelity({ brain: { baseUrl: brain.baseUrl, model: brain.model, timeoutMs: brain.timeoutMs }, key });
    } catch (e) {
      emit.raw({ type: 'brain-fidelity', state: 'error', msg: `fidelity gate could not run: ${String((e && e.message) || e).slice(0, 200)}` });
    }
    emit.raw({
      type: 'brain-fidelity', state: gate ? (gate.pass ? 'pass' : 'fail') : 'error',
      ...(gate ? { score: gate.score, passed: gate.passed, total: gate.total, floor: gate.floor,
        scenarios: gate.scenarios.map((s) => ({ name: s.name, pass: s.pass, error: s.error || null })) } : {}),
      ...(brain.model ? { model: brain.model } : {}),
      msg: gate
        ? `brain fidelity ${gate.passed}/${gate.total} (score ${gate.score}, floor ${gate.floor}) — ${gate.pass ? 'the lane drives the tool surface; the hunt may spend' : 'BELOW FLOOR — the loop refuses to spend on a brain that cannot make the platform\'s tool calls (same fail-closed contract as the ghost preflight)'}`
        : 'fidelity gate did not complete — treat as unmeasured',
    });
    if (!gate || !gate.pass) {
      emit.raw({ type: 'loop', state: 'stopped', msg: !gate ? 'brain fidelity UNMEASURED — fail closed, no cycle ran' : 'brain fidelity BELOW FLOOR — fail closed, no cycle ever ran (raise the lane or lower the floor deliberately)' });
      return { fidelityFailed: true, ...(loadState(dir)) };
    }
  }

  // THE GHOST PREFLIGHT (the loop's own, fail-closed — it never trusts that the
  // console checked): a configured chain must dial AND CONNECT the H1 API host
  // through the proxy, else the loop refuses to start (dies loudly, exit 2 in the
  // CLI). No chain configured = 'off', said honestly (fixture/dry-run lane).
  let ghostInfo = null;
  if (ghost === 'skip') {
    emit.raw({ type: 'ghost', state: 'skipped', msg: 'ghost preflight skipped by the caller (test/fixture lane)' });
  } else {
    ghostInfo = resolveGhostChain({ env });
    if (!ghostInfo) {
      emit.raw({ type: 'ghost', state: 'off', msg: 'no ghost chain configured (env VARVEL_GHOST_CHAIN or settings.json ghost.chain) — external traffic would go DIRECT; the console gate blocks a real hunt here' });
    } else {
      const pf = await ghostCheck(ghostInfo.chain, {});
      if (!pf.ok) {
        emit.raw({ type: 'ghost', state: 'down', chain: ghostInfo.chain, msg: `GHOST CHAIN DOWN — the loop refuses to start: ${pf.detail}` });
        emit.error(`ghost-chain-down: ${pf.detail}`, {});
        emit.loop('stopped', 'ghost preflight FAILED — fail closed, no cycle ever ran');
        return { ghostFailed: true, ...loadState(dir) };
      }
      emit.raw({ type: 'ghost', state: 'in-use', chain: ghostInfo.chain, msg: `ghost chain VERIFIED by the loop's own dial (${pf.detail}) — all external hunt traffic rides it, fail-closed; the brain stays direct (local)` });
    }
  }

  let stopping = false;
  const onSig = () => { stopping = true; emit.loop('stopping', 'SIGTERM received — finishing the current stage boundary, then down'); };
  try { process.on('SIGTERM', onSig); process.on('SIGINT', onSig); } catch { /* non-main contexts */ }

  const paused = async () => {
    if (!existsSync(pauseFile)) return false;
    emit.loop('paused', 'PAUSE file present — the hunt is parked; ALL model capacity is free (no stage runs)');
    while (existsSync(pauseFile) && !existsSync(stopFile) && !stopping) await sleep(2000);
    if (!existsSync(pauseFile)) emit.loop('resumed', 'PAUSE lifted — the hunt resumes; ALL model capacity returns to the hunt');
    return true;
  };

  try {
    while (!stopping && !existsSync(stopFile)) {
      await paused();
      if (stopping || existsSync(stopFile)) break;
      await runCycle({ source, makeSource, brain, provider: sandbox, recorder: recorderInfo, emit, dir, now, maxOpps, trustedBrain, targetRoot, intervalS, watchdogMs, heartbeatMs, watchBudgetMs, ghost: ghostInfo, gatherFetch, forge, validate: validateEnabled, refuter: refuterArg });
      if (once) break;
      emit.loop('sleeping', `cycle done — sleeping ${intervalS}s (STOP/PAUSE files checked every 2s)`);
      const deadline = Date.now() + intervalS * 1000;
      while (Date.now() < deadline && !stopping && !existsSync(stopFile)) await sleep(Math.min(2000, Math.max(50, deadline - Date.now())));
    }
  } finally {
    if (existsSync(stopFile)) { try { rmSync(stopFile); } catch { /* next start re-checks */ } }
    emit.loop('stopped', 'huntloop down — no orphan stages; the console reaps the child');
  }
  return loadState(dir);
}

// --- direct-run CLI -----------------------------------------------------------------------------------
const isMain = (() => { try { return process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]; } catch { return false; } })();

if (isMain) {
  const a = process.argv.slice(2);
  const opt = (flag) => { const i = a.indexOf(flag); return i !== -1 && a[i + 1] && !a[i + 1].startsWith('--') ? a[i + 1] : undefined; };
  const dir = opt('--dir') || ROOT();
  if (opt('--dir')) process.env.VARVEL_HUNTLOOP_DIR = dir;
  const fixture = opt('--fixture');
  const mock = a.includes('--mock-brain');
  const validateEnabled = a.includes('--validate'); // the refuter pass: brain candidates must survive a second brain before the sandbox spends
  const once = a.includes('--once');
  const intervalS = opt('--interval') !== undefined ? Number(opt('--interval')) : DEFAULT_INTERVAL_S;
  const maxOpps = opt('--max-opps') !== undefined ? Number(opt('--max-opps')) : 3;
  const brain = mock ? mockBrain() : { baseUrl: opt('--base-url'), model: opt('--model'), env: process.env };

  const main = async () => {
    let source = null;
    let makeSource = null;
    let ghostMode = 'auto';
    if (fixture) {
      source = h1FixtureSource(fixture);
      // A fixture run is self-contained: its watcher state defaults UNDER the
      // hunt dir, so a dry-run NEVER writes fixture programs into the real
      // h1watch state (an explicit VARVEL_H1WATCH_DIR always wins). Offline lane:
      // no external traffic exists, so the ghost preflight is skipped honestly.
      if (!process.env.VARVEL_H1WATCH_DIR) process.env.VARVEL_H1WATCH_DIR = join(dir, 'h1watch');
      ghostMode = 'skip';
    } else {
      // LIVE: the source is rebuilt PER CYCLE with the cycle's watchdog signal
      // threaded into every GET (h1watch liveSource default-wires the ghost
      // chain itself — FAIL CLOSED; the loop's own ghost preflight runs first
      // and refuses to start when the chain is down).
      makeSource = ({ signal }) => {
        const s = h1LiveSource({ signal });
        if (s.ok && s.ghost) console.log(`huntloop: ghost wire — ${s.ghost.chain} via ${s.ghost.source}`);
        return s;
      };
      const probe = makeSource({});
      if (!probe.ok) {
        console.error(`huntloop: the live watch refused — ${probe.error}: ${probe.reason}`);
        process.exitCode = 2;
        return;
      }
    }
    // Intake resolves each opportunity's program doc lazily THROUGH THE SOURCE
    // (fixture: local; live: one GET via the same thin client) — no pre-pass needed.
    console.log(`huntloop: dir=${dir} once=${once} mockBrain=${mock} interval=${intervalS}s — ${DOCTRINE}`);
    const r = await runLoop({ source, makeSource, brain, dir, intervalS, maxOpps, once, trustedBrain: mock, ghost: ghostMode, forge: mock ? null : makeAutoForge({ brain, env: process.env }), validate: validateEnabled });
    if (r && r.ghostFailed) process.exitCode = 2; // fail closed, loudly
    if (r && r.fidelityFailed) process.exitCode = 2; // the brain-fidelity gate, same fail-closed contract
  };
  main().catch((e) => { console.error('huntloop FATAL:', (e && e.stack) || e); process.exitCode = 1; });
}
