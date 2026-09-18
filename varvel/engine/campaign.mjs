// VARVEL — campaign engine (the spine).
// Phased FSM over the governed agent loop; builds one shared attack-surface, an
// OPSEC ledger, and a lenient operator activity feed. LENIENT at the app level; the
// hard, unbypassable governance + tamper-evident audit are the Enclave's (L2).
//
// Hardened for autonomy (audited): NOTHING a single phase does — a malformed agent
// result, a throwing/hanging/odd approve hook, a throwing observer hook, a bad
// budget, a huge/adversarial ingest array — can crash or hang the campaign. Every
// such failure is caught, logged as an event, and the run proceeds. HITL fails
// CLOSED. Budget + step counts are validated. Cross-session findings accumulate.

import { runGovernedAgent } from '../../agent-backend.mjs';
import { Surface, CONFIRM_AT } from './surface.mjs';
import { hasObjectiveOracle, validationUrl, reRead, planValidation, verdictFor, GATE_NOTE, UNTESTABLE_NOTE } from './validator.mjs';
import { parseIp, inAnyCidr } from './ipaddr.mjs';
import { pathPrefixAllowed, sanitizePathPrefixes } from './scopepath.mjs';
import { PHASES } from './phases.mjs';
import { Opsec } from './opsec.mjs';
import { saveSurface, loadSurface, priorFindings, recordFindings, priorFailures, recordFailures } from './store.mjs';
import { fireteam, reconSpecialists, specialistsFor } from './fireteam.mjs';
import { selectSkills, skillsBriefing } from './skills.mjs';
import { recon, tcpProbe } from '../tools/recon.mjs';
import { webScan } from '../tools/webscan.mjs';
import { apiSurface } from '../tools/apisurface.mjs';
import { crawl } from '../tools/crawl.mjs';
import { vulnCheck } from '../tools/vulncheck.mjs';
import { osFingerprint } from '../tools/osfp.mjs';
import { canaryScan } from '../tools/canary.mjs';
import { ldapEnum } from '../tools/ldapenum.mjs';
import { passiveRecon } from '../tools/passiv.mjs';
import { subdomainScan } from '../tools/dns.mjs';
import { analyzeTls } from '../tools/tlsscan.mjs';
import { assessProgress, replanHint, productivity } from './auditor.mjs';
import { guidedWebSearch } from './webpaths.mjs';
import { shouldDeepThink, deepThinkPrompt } from './deepthink.mjs';
import { StealthBudget } from './budget.mjs';
import { OpsecWatchdog } from './opsec-watchdog.mjs';
import { Settings } from './settings.mjs';
import { chainforge } from './chainforge.mjs';
import { composeChains, findingFromChain } from './chaincompose.mjs';
import { runChain } from '../tools/chainrun.mjs';
import { authzSweep, harvestExchanges, synthesizeCandidates, sanitizeAuthzCfg, provisionSession, fetchExchange } from '../tools/authzsweep.mjs';
import { mine as jsMine } from '../tools/jsminer.mjs';
import { OobServer, oobProbe } from '../tools/oob.mjs';
import { domXssCanary, playwrightDriverFactory } from '../tools/browseragent.mjs';
import { scoreSurface, preScoreTargets } from '../tools/targetscore.mjs';
import { aiSurfacePass, aiHintKind } from '../tools/aisurface.mjs';
import { CoverageLedger, kindOfLabel, COVERAGE_KINDS } from './coverage.mjs';
import { getLiveSession, defaultProbe } from '../tools/sessionbroker.mjs';
import { stealthProfile, makePacer } from './stealth.mjs';
import { chainEgressId } from './ghost.mjs';
import { detectStack } from './target-profile.mjs';
import { autoApprove } from './autogate.mjs';
import { readFileSync, statSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import { shelveTool, SHELF_KINDS } from './toolshelf.mjs';

const MAX_INGEST = 5000;                 // per-phase array cap (DoS guard)
const ACTIVITY_CAP = 2000;               // ring cap on the operator feed — seq stays monotonic via this._seq
const nnum = (v) => Math.max(0, Number(v) || 0); // non-negative number or 0
// The ghost-level shaping policy (engine/stealth normalizeShaperConfig) a campaign pacer
// is policed by — null when ghost is off or no shaper is armed. Read-only consult.
const ghostShaper = (g) => (g && g.shaper) || null;

// Robust: prefers the LAST parseable ```json block; falls back to a first-{ .. last-}
// balanced scan for unfenced/odd output. Never throws.
export function parseJsonBlock(text) {
  if (!text || typeof text !== 'string') return null;
  const blocks = [...text.matchAll(/```json\s*([\s\S]*?)```/gi)].map((m) => m[1]);
  for (let i = blocks.length - 1; i >= 0; i--) { try { return JSON.parse(blocks[i].trim()); } catch {} }
  const a = text.indexOf('{'), b = text.lastIndexOf('}');
  if (a >= 0 && b > a) { try { return JSON.parse(text.slice(a, b + 1)); } catch {} }
  return null;
}

export class Campaign {
  constructor({ engine, scope, hooks = {}, runAgent, budget = {}, fireteam: useFireteam = false, targets = [], tooledRecon = false, reconOpts = {}, approveTimeoutMs = 900000, maxReplan = 1, carryForward = false, reconOnly = false, inform = '', bridgeApproval = false, guidedSearch = false, stealth = null, ghost = null, extraHeaders = null, authz = null, jsminer = false, jsminerVerify = false, jsminerVerifyEndpoints = null, oob = null, browseragent = false, browserDriverFactory = null, targetScore, aiProbe = false, aiSurface, sessionBroker = null, cveHypotheses = null, wsDir = null, stallAfterMs, stallCheckMs, now } = {}) {
    this.engine = engine || {};
    this.ghost = ghost; // Ghost Mode engine (server singleton); null = identity stealth off
    // Per-engagement attestation headers a program REQUIRES on all test traffic (e.g.
    // HackerOne's X-Hackerone: <handle>) — threaded into the shared pacer, so every
    // paced tool carries them. Opt-in per campaign launch; never set globally.
    this.extraHeaders = (extraHeaders && typeof extraHeaders === 'object' && !Array.isArray(extraHeaders)) ? { ...extraHeaders } : null;
    this.scope = scope || { engagement: 'engagement', signedBy: null, cidrs: [] };
    this.inform = typeof inform === 'string' ? inform : ''; // operator "inform" preamble (identity context for the agent)
    // The agent's sealed workspace dir (server.mjs passes the same wsDir the runAgent
    // backend uses) — the auto-shelve reads declared scratch-tool bytes out of it before
    // the disposable workspace is reaped. null = read-back unavailable (inline "content"
    // declarations still shelve).
    this.wsDir = typeof wsDir === 'string' && wsDir ? wsDir : null;
    this.bridgeApproval = !!bridgeApproval; // live mode: relay a countersigned HITL gate to the Enclave's approval context
    this.surface = new Surface(this.scope);
    this.hooks = hooks || {};
    this.runAgent = runAgent || runGovernedAgent;
    this.opsec = new Opsec();
    // Operational stealth (authorized tradecraft): a named profile whose pacing is ENFORCED
    // in our native tools (recon/webscan) and whose noise BUDGET is tracked + proven. null =
    // no stealth ceiling. This is what RedAmon's autonomous agent lacks — enforcement, not a
    // prompt. Still fully audited by the Enclave. `stealth:'auto'` = fingerprint the target's
    // defenses (WAF/CDN/rate-limit) at run start and CALIBRATE the profile to it — the
    // adaptive stealth RedAmon punts to its LLM (see engine/target-profile.mjs).
    this.autoStealth = stealth === 'auto';
    this.stealthName = this.autoStealth ? 'auto' : (stealth ? stealthProfile(stealth).label : null);
    this.noise = new StealthBudget(this.autoStealth ? 'normal' : (this.stealthName || 'loud')); // 'loud' = unlimited when no profile
    // Per-engagement noise sizing (launch option budget.maxNoise, mapped from the
    // top-level maxNoise in server.mjs startCampaign — the maxSteps pattern): sizes
    // the cumulative ceiling ON TOP of the stealth preset — a 30-host wildcard recon
    // needs more than the 'normal' 120 without dropping the profile's pacing/peak.
    // Re-applied after 'auto' calibration rebuilds the budget (_calibrateStealth).
    const mn = Number(budget.maxNoise);
    this.noiseCap = Number.isFinite(mn) && mn > 0 ? mn : null;
    if (this.noiseCap) this.noise.maxNoise = this.noiseCap;
    // Per-engagement settings: DEFAULTS under every explicit option (the operator's floor,
    // never an invisible override). See engine/settings.mjs.
    const stSettings = Settings.for(this.scope.engagement);
    // ONE shared pacer governs the whole engagement's target-visible cadence (every host +
    // every follow-up + every web request share its emission clock). null when no stealth /
    // still 'auto' (built once calibrated in _calibrateStealth).
    this.pacer = (this.stealthName && !this.autoStealth) ? makePacer(this.stealthName, { extraHeaders: this.extraHeaders, maxWaitMs: (reconOpts || {}).paceMaxWaitMs, shaper: ghostShaper(this.ghost) }) : null;
    this.targetProfile = null; // detected defenses + calibration (set by _calibrateStealth when auto)
    // The footprint section's reflex arc: watches every charged noise event, advises on
    // budget escalations, and (bounded, logged) widens the emission gap when the budget
    // goes critical. pacer is a GETTER so the 'auto'-calibrated pacer is reached too.
    this.watchdog = new OpsecWatchdog({
      budget: this.noise,
      pacer: () => this.pacer,
      autoThrottle: ((reconOpts || {}).watchdog || {}).autoThrottle !== undefined ? (reconOpts.watchdog || {}).autoThrottle : stSettings.get('stealth.autoThrottle'),
      onEvent: (type, obj) => { this._log(type, obj); if (obj && (obj.kind || obj.throttled != null)) this.surface.note('opsec', `watchdog: ${obj.kind || 'throttle'}`); },
    });
    this.useFireteam = useFireteam;
    // URL targets (e.g. the agoda seed 'https://www.agoda.com/book/') scan by HOSTNAME —
    // the sweep dials hosts, not URLs ('https://…' never resolves, scans nothing). The
    // path portion is NOT scope: the path-prefix guard (scope.pathPrefixes) owns that.
    this.targets = (Array.isArray(targets) ? targets : []).map((t) => {
      try { const u = new URL(String(t)); return u.hostname; } catch { return String(t); }
    });
    this.guidedTrace = null;    // LATS tree trace retained for the Task Tree console panel
    this.waves = [];            // fireteam wave summaries (phase + per-member outcomes) for the panel
    this.useTooledRecon = tooledRecon;
    this.reconOnly = !!reconOnly;   // stop after recon (a real, discovery-only sweep — no downstream agent fiction)
    this.guidedSearch = !!guidedSearch; // run the value-guided (LATS) path search before the exploit phase
    this.exploitFocus = null;       // ranked promising paths the guided search surfaced (for the exploit prompt)
    this.chainPlans = null;         // chainforge-compiled exploit chains from the live surface
    this.composedChains = null;     // chaincompose v2 typed-primitive compositions (post-validate)
    // Build 1 (2026-08-31): the two-account authorization oracle (IDOR/BOLA, the #1
    // critical-paying class per docs/research/crit-class-analysis-2026-08-30.md).
    // authz = launch option (or scope.authz): { accounts: [A, B] (cookie or login each),
    // writes?, deletes?, escalate?, templates?, maxEndpoints? }. Reads always; the
    // write/delete/ladder rungs fire ONLY under the countersigned exploit window.
    this.authz = sanitizeAuthzCfg(authz || this.scope.authz);
    this.authzSweepResult = null;   // last runAuthzSweep result (summary + verdicts + bundles)
    // Build 2 (2026-08-30 hunting-tools wiring): the four standalone hunting tools as
    // campaign lanes. jsminer rides the recon phase; oob + browseragent ride the gated
    // exploit phase; the authz victim-object seeding hook lives in runAuthzSweep. All of
    // them charge the SEPARATE budget.tools bucket (never the agent step counter) and run
    // under per-lane killfast budgets, so these parts can't flood the campaign's limits.
    this.jsminer = !!jsminer;               // launch option jsminer:true — JS/sourcemap mining (default OFF)
    this.jsminerVerify = !!jsminerVerify;   // launch option jsminerVerify:true — the OPT-IN live-use secret oracle
    this.jsminerVerifyEndpoints = (jsminerVerifyEndpoints && typeof jsminerVerifyEndpoints === 'object') ? jsminerVerifyEndpoints : null; // test seam: point verifiers at a lab mock
    this.oob = (oob && typeof oob === 'object' && !Array.isArray(oob))
      ? { publicBaseUrl: typeof oob.publicBaseUrl === 'string' ? oob.publicBaseUrl : null, adminToken: oob.adminToken != null ? String(oob.adminToken) : null, kinds: Array.isArray(oob.kinds) ? oob.kinds.filter((k) => typeof k === 'string') : null, deadlineMs: Number.isFinite(Number(oob.deadlineMs)) && Number(oob.deadlineMs) > 0 ? Number(oob.deadlineMs) : null }
      : null;                               // launch option oob:{publicBaseUrl, adminToken} — blind-class OOB correlation
    this.browseragent = !!browseragent;     // launch option browseragent:true — DOM-XSS canary over reflected params
    this.browserDriverFactory = typeof browserDriverFactory === 'function' ? browserDriverFactory : null; // test seam: fake driver (real = playwright Firefox, ghost-pinned)
    this.jsminerResult = null;              // last JS-mining pass rollup (null = not run)
    this.oobResult = null;                  // last OOB pass rollup
    this.browserResult = null;              // last DOM-XSS canary pass rollup
    // Build 3 (2026-08-31): the two research-driven additions — the target-scoring
    // ROI layer (deterministic, no LLM call; REORDERS per-host tool budgets by
    // expected yield, never skips/hides an in-scope host, refusal rules unchanged)
    // and the AI/LLM attack-surface lane (detection passive-ish in the gated
    // exploit phase; aiProbe:true arms the canary-proof active probes — a model
    // complying with a naughty string is NEVER a finding).
    this.targetScoreEnabled = targetScore !== undefined ? !!targetScore : !!tooledRecon; // default ON under tooledRecon
    this.aiSurfaceEnabled = aiSurface !== false;        // detection lane default ON; aiSurface:false kills it outright
    this.aiProbe = !!aiProbe;                           // launch option aiProbe:true arms the canary-proof probes
    this.targetScoreRollup = null;                      // last runTargetScoring rollup (null = not run)
    this.aiSurfaceResult = null;                        // last runAiSurfacePass rollup
    this._reconWebBases = [];               // http(s) service bases discovered by tooled recon (jsminer feeds on them)
    this._reflectedParams = [];             // GET-form/query params recon surfaced (the DOM-XSS canary's targets)
    this._paramEndpointSeen = new Set();    // dedupe for harvested ?param= endpoint nodes (Build 2)
    this.reconOpts = reconOpts || {};
    // Settings-backed defaults (explicit reconOpts still win per-key).
    this.reconOpts.crawl = { maxPages: stSettings.get('recon.maxPages'), ...(this.reconOpts.crawl || {}) };
    this.reconOpts.vuln = { maxProbes: stSettings.get('recon.maxProbes'), ...(this.reconOpts.vuln || {}) };
    // When a concrete stealth profile is active, ENFORCE its pacing inside the native tools:
    // the port sweep + content discovery pace/serialize themselves in code (engine/
    // stealth.mjs), so quietness doesn't depend on the agent choosing gentle flags. For
    // 'auto' we thread nothing yet — _calibrateStealth() resolves + threads the profile at
    // run start once the target's defenses are fingerprinted.
    if (this.stealthName && !this.autoStealth) {
      this.reconOpts.stealth = this.stealthName;
      this.reconOpts.web = { ...(this.reconOpts.web || {}), stealth: this.stealthName };
    }
    // Path-prefix scope (2026-08-31, agoda-class programs): when the signed scope
    // carries pathPrefixes, EVERY web tool is confined to them — threaded like the
    // stealth profile; explicit per-tool reconOpts.pathPrefixes win. The tools refuse
    // out-of-prefix requests before the wire; refusals land as scope.path.refused.
    this.pathPrefixes = sanitizePathPrefixes(this.scope.pathPrefixes);
    if (this.pathPrefixes) {
      this.reconOpts.pathPrefixes = this.reconOpts.pathPrefixes || this.pathPrefixes; // the sweep's own fingerprint/favicon follow-ups honor it too
      for (const k of ['web', 'api', 'crawl', 'vuln']) {
        this.reconOpts[k] = { pathPrefixes: this.pathPrefixes, ...(this.reconOpts[k] || {}) };
      }
    }
    const ms = Number(budget.maxSteps);
    this.budget = { maxSteps: (Number.isFinite(ms) && ms >= 0) ? ms : 200, usedSteps: 0 };
    // budget.tools (2026-08-30): a SEPARATE bucket for the hunting-tool lanes
    // (jsminer / oob / browseragent / authz-seeding). Their requests charge HERE —
    // never against budget.maxSteps (agent steps) — so these lanes can't flood the
    // campaign's step/noise limits. Exhaustion is an honest budget.exhausted event
    // ({bucket:'tools'}), recorded in getState() and the report's governance section.
    const tb = (budget && typeof budget.tools === 'object' && budget.tools) || {};
    const tmr = Number(tb.maxRequests), tmm = Number(tb.maxMs);
    this.toolBudget = {
      maxRequests: Number.isFinite(tmr) && tmr > 0 ? Math.floor(tmr) : 200,
      maxMs: Number.isFinite(tmm) && tmm > 0 ? Math.floor(tmm) : 600000,
      used: 0, t0: Date.now(), exhaustedAt: null,
    };
    const at = Number(approveTimeoutMs);
    this.approveTimeoutMs = Number.isFinite(at) && at >= 0 ? at : 900000;
    const mr = Number(maxReplan);
    this.maxReplan = Number.isFinite(mr) && mr >= 0 ? mr : 1;
    this.assessments = [];  // per-phase honesty/productivity audits
    this.stuck = 0;         // deterministic no-growth streak (LLM-independent stuck signal)
    this._lastText = '';
    this.activity = [];
    this._seq = 0;        // monotonic event counter — survives the activity ring cap
    // Campaign-level stall detector (2026-08-31 — the tripcom/bykea silent-freeze report):
    // no activity event for stallAfterMs (default 10 min) => the campaign is wedged on SOME
    // await. Log campaign.stall with the last event + await context and park VISIBLE as
    // stalled:<phase> — silent freezing is a banned failure mode. `now` is an injectable
    // clock seam (fake-clock tests); stallCheckMs: 0 disables the interval (tests then call
    // _checkStall() manually). Never false-fires on legit long tool runs (their watchdog
    // budgets < stallAfterMs) or while parked at a HITL gate (_awaitingApproval).
    this._now = typeof now === 'function' ? now : Date.now;
    const sa = Number(stallAfterMs);
    this._stallAfterMs = Number.isFinite(sa) && sa >= 0 ? sa : 600000;
    const sc = Number(stallCheckMs);
    this._stallCheckMs = Number.isFinite(sc) && sc >= 0 ? sc : 30000;
    this._lastActivityAt = this._now();
    this._awaitingApproval = 0; // >0 while parked at a HITL gate — a legit, visible wait
    this.stall = null;          // { phase, since, elapsedMs, lastEvent, reason } while stalled
    if (this._stallCheckMs > 0 && this._stallAfterMs > 0) {
      this._stallTimer = setInterval(() => { try { this._checkStall(); } catch { /* the detector itself never throws into the campaign */ } }, this._stallCheckMs);
      if (this._stallTimer.unref) this._stallTimer.unref(); // never hold the event loop open
    }
    this.phaseIndex = 0;
    this.status = 'idle';
    this.transcript = [];
    this.messages = [];
    this.prior = priorFindings(this.scope.engagement) || [];
    if (this.prior.length) this._log('memory.inherit', { findings: this.prior.length });
    this.failures = [];  // approaches that failed THIS session (persisted for the next)
    this.priorFail = priorFailures(this.scope.engagement) || [];  // failed approaches from PAST sessions
    if (this.priorFail.length) this._log('memory.inherit', { failures: this.priorFail.length });
    this.carryForward = !!carryForward;
    this._inheritedSurface = null; // raw persisted prior surface (pre-seedFrom) — freshness gate reads sweptAt off it
    this._wedgeTrips = new Map();  // host -> consecutive recon.watchdog trips this session
    this._degradedHosts = new Set(); // hosts at 2+ trips: halved budgets + non-essential extras skipped
    this._budgetOverride = null;   // null = budget-override gate not yet asked; true/false = HITL decision (cached)
    if (carryForward) { try { this._inheritedSurface = loadSurface(this.scope.engagement); const seeded = this.surface.seedFrom(this._inheritedSurface); if (seeded) this._log('surface.inherit', { nodes: seeded }); } catch { /* prior surface unreadable — start fresh */ } }
    // Write-through persistence (2026-08-29, Jack's rule): a restart must never cost us
    // findings. Every surface mutation (all node types flow through surface.add) schedules
    // a debounced snapshot — surface AND the deduped findings ledger — so a mid-run death
    // loses at most the debounce window, not the engagement. The done-path save below stays
    // the authoritative final write. Best-effort mid-run: never throws into the campaign.
    let _persistPending = false;
    this._persistSoon = () => {
      if (_persistPending) return;
      _persistPending = true;
      const t = setTimeout(() => {
        _persistPending = false;
        try {
          saveSurface(this.scope.engagement, this.surface.toJSON());
          const fs = [...this.surface.nodes.values()].filter((n) => n.type === 'finding').map((n) => ({ label: n.label, sev: n.sev, risk: n.risk, ref: n.ref }));
          recordFindings(this.scope.engagement, fs); // deduped by ref|label — safe to repeat
        } catch { /* mid-run persistence is opportunistic; the done path is authoritative */ }
      }, 2000);
      if (t.unref) t.unref(); // never hold the event loop open for a snapshot
    };
    const _surfaceAdd = this.surface.add.bind(this.surface);
    this.surface.add = (...args) => { const r = _surfaceAdd(...args); this._persistSoon(); return r; };
    // Coverage-completion gate (winner-copyables build, Tool 3 — the
    // `confirm_testing_complete` pattern): every endpoint recon puts on the surface is
    // QUEUED for testing; exploit lanes MARK what they actually exercised; run() reports
    // DONE-CLEAN only when the queue is drained, else COVERAGE-INCOMPLETE with the
    // remaining queue itemized. Pure core: engine/coverage.mjs.
    this.coverage = new CoverageLedger({ now: () => this._now() });
    this.coverageVerdict = null; // set by run() at completion (null = campaign not finished)
    // CVE lane (2026-08-31 wide-recon-cve build): tools/cvelane.mjs emits known-CVE
    // HYPOTHESES for recon-detected (software, version) tuples. They enter the campaign
    // as coverage-gate QUEUED surface — a hypothesis is never a finding; it is work the
    // validator must drain (or consciously leave in the COVERAGE-INCOMPLETE ledger)
    // before the campaign may report DONE-CLEAN. Fail-closed: a hypothesis whose host
    // is not among this campaign's targets is logged cvelane.skip and never queued.
    this.cveHypotheses = Array.isArray(cveHypotheses) ? cveHypotheses : [];
    this._cvelaneStats = { received: this.cveHypotheses.length, queued: 0, skipped: 0 };
    for (const h of this.cveHypotheses) {
      try {
        const host = String((h && h.host) || '');
        const key = String((h && (h.key || h.path)) || '/').slice(0, 400);
        const inTargets = host && (!this.targets.length || this.targets.some((t) => host === t || host.endsWith('.' + t) || t.endsWith('.' + host)));
        if (!inTargets) { this._cvelaneStats.skipped++; this._log('cvelane.skip', { host: host || null, cve: (h && h.cve) || null, reason: 'hypothesis host is not among this campaign\'s targets — fail-closed, never queued' }); continue; }
        this.coverage.queue({ kind: COVERAGE_KINDS.includes(h && h.kind) ? h.kind : 'endpoint', key, host, source: 'cvelane-hypothesis' });
        this._cvelaneStats.queued++;
        this._log('cvelane.queue', { host, key, cve: (h && h.cve) || null, note: 'HYPOTHESIS queued for the validator path — a version match is not exploitability' });
      } catch { /* hypothesis bookkeeping never breaks the campaign */ }
    }
    // Session broker (winner-copyables build, Tool 1): authz accounts may carry a
    // sessionRef 'program:label' instead of a literal cookie; runAuthzSweep resolves a
    // LIVE session (canary-checked, refresh→relogin recovery) before provisioning.
    // allowSpawn defaults FALSE — no headless-browser relogin unless the operator
    // explicitly opts in. getLiveSessionImpl is the hermetic test seam.
    this.sessionBroker = (sessionBroker && typeof sessionBroker === 'object')
      ? {
          dir: sessionBroker.dir || undefined,
          allowSpawn: !!sessionBroker.allowSpawn,
          getLiveSessionImpl: typeof sessionBroker.getLiveSessionImpl === 'function' ? sessionBroker.getLiveSessionImpl : null
        }
      : null;
    const _surfaceEndpoint = this.surface.endpoint.bind(this.surface);
    this.surface.endpoint = (hostId, url, method) => {
      const r = _surfaceEndpoint(hostId, url, method);
      try {
        const hn = this.surface.nodes.get(hostId);
        this.coverage.queue({ kind: kindOfLabel(url), key: String(url), host: hn ? (hn.ip || hn.label || null) : null, source: 'recon-harvest' });
      } catch { /* coverage bookkeeping never breaks recon */ }
      return r;
    };
    // Mark helper for lanes: exact key first, then a path-without-query fallback (a lane
    // that exercised '/ai/chat' covers the queued '/ai/chat' even when the queue key
    // carried a query string). Bookkeeping never throws into a lane.
    this._covMark = (key, lane, note) => {
      try {
        const k = String(key || '');
        if (this.coverage.mark(k, lane, note ? { note } : {})) return true;
        const bare = k.split('?')[0];
        if (bare !== k && this.coverage.has(bare)) return this.coverage.mark(bare, lane, note ? { note } : {});
        // bare-path input covering a queued parameterized key ('/ai/chat' exercised ⇒
        // the queued '/ai/chat?x=' is covered) — matched against the UNTESTED queue.
        const hit = this.coverage.status().untested.find((i) => i.key.split('?')[0] === k || i.key.split('?')[0] === bare);
        if (hit) return this.coverage.mark(hit.key, lane, note ? { note } : {});
        return false;
      } catch { return false; }
    };
    // Engagement egress record (audit, 2026-09-01): WHICH identity chain and exit this
    // engagement rides — recorded at build time into the activity/audit stream, so the
    // ledger always names the exit each engagement used (the frontegg lesson: a
    // WAF-blocked pinned exit with no recorded rotation policy meant a stalled engagement
    // and a manual re-pin). Canonical egress id only — proxy creds and the operator
    // baseline NEVER enter the ledger.
    if (this.ghost && this.ghost.mode && this.ghost.mode !== 'off') {
      try {
        const g = this.ghost;
        this._log('ghost.engagement', {
          mode: g.mode,
          egress: chainEgressId(g.chain || []),
          hops: (g.chain || []).length,
          verified: typeof g.verifiedOk === 'function' ? g.verifiedOk() : null,
          exitIp: (g._verified && g._verified.exitIp) || null,
          pin: g._pin || null,
          shaper: g.shaper || null,
          note: 'egress identity at campaign build; verify()/exitCheck() freshness is the operator gate (fail-closed in required mode)',
        });
      } catch { /* the audit tap never breaks a campaign */ }
    }
  }

  _log(kind, data) {
    this._lastActivityAt = this._now(); // stall detector's heartbeat
    // Genuine activity after a stall: clear the parked state and restore the running status.
    if (this.stall && kind !== 'campaign.stall') {
      const phase = (PHASES[this.phaseIndex] || {}).id;
      this.stall = null;
      if (String(this.status || '').startsWith('stalled:')) this.status = 'running' + (phase ? ':' + phase : '');
    }
    const e = { seq: this._seq++, at: new Date().toISOString(), kind, data };
    this.activity.push(e);
    if (this.activity.length > ACTIVITY_CAP) this.activity.splice(0, this.activity.length - ACTIVITY_CAP); // ring cap: drop oldest, keep seq monotonic
    if (this.hooks.onEvent) { try { this.hooks.onEvent(e); } catch {} }
    return e;
  }
  _fail(kind, approach, phase) {
    if (!approach) return;
    this.failures.push({ kind, approach: String(approach).slice(0, 200), phase: phase || null, at: new Date().toISOString() });
  }
  // Single footprint chokepoint: record the activity in the OPSEC ledger AND charge the
  // stealth-noise budget, so the two never drift. When the activity would push over the
  // budget ceiling under an active stealth profile, log it as a budget event (advisory for
  // non-destructive recon; the exploit/post-ex phases are already HITL-gated).
  // `authorized` = this activity is the dominant action of a HITL-gated phase that the
  // operator countersigned, so its (possibly loud) noise is approved, not a surprise
  // breach — recorded with override so the after-action proof stays honest.
  _noise({ kind, host = null, count = 1, authorized = false } = {}) {
    const ev = this.opsec.act({ kind, host, count });
    if (!ev) return ev; // unknown kind — nothing to charge
    if (this.stealthName && !authorized) {
      // Phase-aware check: the per-phase reserve (recon ≤70%, validate+exploit keep
      // 30%) rides on top of the raw budget check — a reserve breach logs as
      // budget.reserve so the console can tell it from a full-budget exceed.
      const phaseId = (PHASES[this.phaseIndex] || {}).id || null;
      const v = this.noise.checkPhase ? this.noise.checkPhase(kind, count, phaseId) : this.noise.check(kind, count);
      if (v.escalate) {
        this._log(v.overReserve ? 'budget.reserve' : 'budget.exceed', { kind, cost: v.cost, remaining: v.remaining, ...(v.reserveCap !== undefined ? { reserveCap: v.reserveCap } : {}), phase: phaseId, reason: v.reason });
        this.surface.note('opsec', `stealth budget: ${v.reason}`);
      }
    }
    this.noise.record(kind, count, { override: authorized });
    this.watchdog.check(); // the reflex: advise (and bounded auto-throttle) on budget escalations
    return ev;
  }
  _onSurface() { if (this.hooks.onSurface) { try { this.hooks.onSurface(this); } catch {} } }
  _onPhase(phase) { if (this.hooks.onPhase) { try { this.hooks.onPhase(phase, this); } catch {} } }

  budgetLeft() { return this.budget.maxSteps - this.budget.usedSteps; }

  // Bridge note (tool builder): ghost.agents() returns { httpAgent, httpsAgent }; the
  // hunting tools take the authzsweep key shape { http, https }. Mapped here, once.
  _bridgedAgents() {
    const g = this.ghost && typeof this.ghost.agents === 'function' ? this.ghost.agents() : null;
    return g ? { http: g.httpAgent, https: g.httpsAgent } : null;
  }

  // budget.tools ledger: jsminer/oob/browseragent/authz-seeding requests charge HERE,
  // never against budget.maxSteps — the hunting lanes cannot flood the campaign's step
  // budget. Exhaustion is an honest budget.exhausted {bucket:'tools'} activity event,
  // mirroring the existing budget events; the lane that trips it stops honestly.
  _toolBudgetOk() {
    const b = this.toolBudget;
    return !b.exhaustedAt && b.used < b.maxRequests && (Date.now() - b.t0) < b.maxMs;
  }
  _toolCharge(tool, n = 1) {
    const b = this.toolBudget;
    b.used += Math.max(0, Number(n) || 0);
    const elapsedMs = Date.now() - b.t0;
    if (!b.exhaustedAt && (b.used >= b.maxRequests || elapsedMs >= b.maxMs)) {
      b.exhaustedAt = new Date().toISOString();
      this._log('budget.exhausted', { bucket: 'tools', tool, used: b.used, maxRequests: b.maxRequests, elapsedMs, maxMs: b.maxMs });
      this.surface.note('governance', `tool budget (bucket: tools) EXHAUSTED at ${tool} — ${b.used}/${b.maxRequests} requests, ${Math.round(elapsedMs / 1000)}s/${Math.round(b.maxMs / 1000)}s; hunting lanes stop honestly`);
      this._onSurface();
    }
    return !b.exhaustedAt;
  }

  // Kill-fast per-hypothesis budget: the lane's tool runs under a hard call/ms cap —
  // the tool's own budget hook IS the counter (no hidden requests). When the cap
  // trips, the stop is logged (killfast.stop, with the reason) and the partial result
  // is marked { stopped: 'killfast' }. Actual usage settles into the budget.tools
  // bucket afterwards, so a capped lane still counts what it spent.
  async _killfast(name, fn, { maxCalls = 40, maxMs = 300000 } = {}) {
    let tripped = null;
    const onLog = (obj) => {
      if (obj && obj.type === 'budget.exhausted') tripped = `${obj.tool || name}: ${obj.what || 'cap'} — used ${obj.used}/${obj.maxRequests}`;
      if (obj && obj.type) this._log(obj.type, obj);
    };
    const remaining = Math.max(1, this.toolBudget.maxRequests - this.toolBudget.used);
    const budget = { maxRequests: Math.max(1, Math.min(Math.floor(maxCalls), remaining)), maxMs };
    let out = null;
    try { out = await fn({ budget, onLog }); }
    catch (e) { this._log('phase.error', { phase: (PHASES[this.phaseIndex] || {}).id || 'unknown', error: `${name}: ${String((e && e.message) || e)}` }); }
    const used = out && out.budget && Number.isFinite(out.budget.used) ? out.budget.used : 0;
    if (used) this._toolCharge(name, used);
    if (tripped) {
      this._log('killfast.stop', { name, reason: tripped, requests: used });
      if (out && typeof out === 'object') out.stopped = 'killfast';
      else out = { stopped: 'killfast', partial: out === undefined ? null : out };
    }
    return out;
  }

  // HITL: fail CLOSED. Throws -> hold. Hangs -> timeout -> hold. Only a strict
  // boolean `true` approves (a truthy sentinel does NOT).
  async _approve(phase) {
    this._awaitingApproval++; // a HITL wait is a LEGIT park — the stall detector skips it
    try { return await this._approveInner(phase); }
    finally { this._awaitingApproval--; }
  }
  async _approveInner(phase) {
    // Operator pre-authorization (engine/autogate.mjs) is decided BEFORE the human hook:
    // a live grant countersigns; anything else — no grant, expired, exhausted, mis-scoped,
    // or a broken autogate itself — falls through to the human gate UNCHANGED. A refusal
    // here never weakens the gate; it just isn't an approval.
    let auto = { ok: false, reason: 'autogate-error' };
    try { auto = autoApprove(phase.id, this.scope); } catch (e) { this._log('gate.auto.error', { phase: phase.id, error: String((e && e.message) || e) }); }
    if (auto.ok) {
      this._log('gate.auto', { phase: phase.id, grant: auto.grant, remaining: auto.remaining });
      this.surface.note(phase.id, `auto-approved — operator grant ${auto.grant} (${auto.remaining} left; audited in data/autogate-log.jsonl)`);
      return true;
    }
    if (auto.audited) this._log('gate.auto.refused', { phase: phase.id, reason: auto.reason });
    if (typeof this.hooks.approve !== 'function') return false;
    try {
      const p = Promise.resolve(this.hooks.approve(phase));
      if (this.approveTimeoutMs > 0) {
        let to;
        const timer = new Promise((res) => { to = setTimeout(() => res('__timeout__'), this.approveTimeoutMs); });
        let r;
        // finally, not inline: a REJECTING hook must also clear the gate timer, or the
        // full-length timeout stays ref'd and holds the process open (found 2026-08-11:
        // pipeline-hardening's throwing-approve test hung the runner for 15 minutes).
        try { r = await Promise.race([p, timer]); } finally { clearTimeout(to); }
        if (r === '__timeout__') { this._log('gate.timeout', { phase: phase.id }); return false; }
        return r === true;
      }
      return (await p) === true;
    } catch (e) { this._log('gate.error', { phase: phase.id, error: String((e && e.message) || e) }); return false; }
  }

  _ingest(phaseId, data) {
    const s = this.surface;
    if (!data || typeof data !== 'object') return;
    // The model often answers with a PHASE-WRAPPED object ({"recon": {hosts…}, "exploit": {…}})
    // — unwrap it or NOTHING lands (this is why interactive runs showed an empty surface).
    if (!data.hosts && !data.findings && !data.exploits && !data.routes && !data.artifacts) {
      const unwrapped = {};
      for (const k of ['recon', 'validate', 'exploit', 'postex', 'report']) {
        if (data[k] && typeof data[k] === 'object') Object.assign(unwrapped, data[k]);
      }
      if (Object.keys(unwrapped).length) data = { ...unwrapped, ...data };
    }
    const gated = phaseId === 'exploit' || phaseId === 'postex'; // HITL-gated phases → their noise is authorized
    const arr = (v) => (Array.isArray(v) ? v.slice(0, MAX_INGEST) : []);
    // TOOL AUTHORING contract (operatingBrief): the agent declares scratch tools it built.
    // Unknown fields are ignored by the ingest below; this one we TOLERATE AND LOG so the
    // operator can audit/promote them — never an ingest failure.
    if (Array.isArray(data.scratchTools) && data.scratchTools.length) {
      this._log('scratch-tools', { phase: phaseId, tools: data.scratchTools.map((t) => String(t && (t.name || t))).slice(0, 10) });
      this.surface.note(phaseId, `agent authored scratch tool(s): ${data.scratchTools.map((t) => String(t && (t.name || t))).slice(0, 5).join(', ')}`);
      this._shelveScratchTools(phaseId, data.scratchTools); // auto-shelve the bytes — best-effort, never throws
    }
    const byName = (name) => [...s.nodes.values()].find((n) => n.ip === name || n.label === name);
    const hostId = (name) => { const n = byName(name); return n ? n.id : null; };

    for (const h of arr(data.hosts)) {
      if (!h || typeof h !== 'object' || (h.ip == null && h.label == null)) continue;
      const hid = s.host(h.ip, { label: h.label || h.ip });
      this.opsec.observe({ host: h.ip });
      for (const sv of arr(h.services)) if (sv && typeof sv === 'object') s.service(hid, sv.port, sv.proto, sv.name);
      for (const sd of arr(h.subdomains)) if (typeof sd === 'string') s.subdomain(hid, sd);
      for (const ep of arr(h.endpoints)) if (ep) s.endpoint(hid, typeof ep === 'string' ? ep : ep.url, ep && ep.method);
      for (const t of arr(h.tech)) if (t) s.tech(hid, typeof t === 'string' ? t : t.name, t && t.version);
    }
    for (const f of arr(data.findings)) {
      if (!f || typeof f !== 'object') continue;
      const hid = hostId(f.host) || s.root;
      // Numeric confidence if the agent gave one; else map string/evidence to a tier.
      let conf = typeof f.confidence === 'number' ? f.confidence : (f.confidence === 'confirmed' || f.evidence ? 85 : 40);
      // VALIDATOR GATE (deterministic, no model call): a confirmed-tier claim whose
      // evidence/ref cite NO objective oracle is DOWNGRADED to suspected at ingest —
      // never deleted, never blocked; the note says exactly why, and /api/validate is
      // the way back up. Suspected was never exploitable anyway; this makes it real.
      const gated = conf >= CONFIRM_AT && !hasObjectiveOracle(f);
      if (gated) conf = Math.min(conf, CONFIRM_AT - 1);
      const fid = s.finding(hid, { title: f.title, sev: f.sev, cve: f.cve, ref: f.ref, confidence: conf, evidence: f.evidence });
      if (gated) {
        const n = s.nodes.get(fid);
        if (n) (n.notes = n.notes || []).push(GATE_NOTE);
        this._log('validator.gate', { title: f.title, ref: f.ref, note: GATE_NOTE });
        s.note('validate', `gate: "${f.title || 'finding'}" downgraded to suspected — ${GATE_NOTE}`);
      }
      if (f.cve) s.cve(f.cve, f.cvss, hid);
      this._log('finding', { title: f.title, sev: f.sev, ref: f.ref });
    }
    for (const e of arr(data.exploits)) {
      if (!e || typeof e !== 'object') continue;
      const fn = [...s.nodes.values()].find((n) => n.type === 'finding' && n.label === e.finding);
      const xid = s.exploit(fn ? fn.id : s.root, { title: e.title, ref: e.ref, state: e.result === 'proved' ? 'proved' : 'proposed' });
      if (e.cred) s.cred(xid, e.cred, e.credKind);
      if (e.foothold) { const h = hostId(e.host); if (h) s.foothold(h, e.foothold); }
      if (e.result === 'failed') this._fail('failed-exploit', e.title, phaseId);
      this._log('exploit', { title: e.title, result: e.result, ref: e.ref });
    }
    for (const r of arr(data.routes)) {
      if (!r || typeof r !== 'object') continue;
      const from = hostId(r.from), to = hostId(r.to);
      if (from && to) { s.route(from, to, r.via); this._noise({ kind: 'pivot', host: r.to, authorized: gated }); this._log('route', { from: r.from, to: r.to, via: r.via }); }
    }
    for (const a of arr(data.artifacts)) {
      if (!a || typeof a !== 'object') continue;
      s.note('postex', `artifact ${a.kind} @ ${a.host}:${a.path} -> cleanup: ${a.cleanup || 'PENDING'}`);
      this.opsec.record({ host: a.host, kind: a.kind, path: a.path, cleanup: a.cleanup });
      this.noise.record('file-drop', 1, { override: gated }); // keep the budget in step; post-ex drops are HITL-authorized
      this._log('artifact', { host: a.host, kind: a.kind, path: a.path });
    }
  }

  // AUTO-SHELVE (2026-09-01 lab wiring): the workspace is disposable — scratch tools used
  // to VANISH with it; only their names were logged. Now the declared script bytes are
  // persisted to the tool shelf (engine/toolshelf) as QUARANTINED entries — DATA, never
  // executed; promotion into the pinned arsenal stays a human decision. Bytes come from
  // the declaration itself (inline "content" / "files[]") or are read back out of the
  // agent's sealed workspace (confined to wsDir — traversal is refused). Best-effort: a
  // shelf/IO failure is logged, never thrown into the campaign.
  _shelveScratchTools(phaseId, tools) {
    this._shelvedScratch = this._shelvedScratch || new Set(); // one shelf entry per tool per campaign
    const base = (p) => String(p || '').split(/[\\/]/).pop();
    const readWs = (rel) => { // confined read-back: never outside the workspace, the shelf's size cap applies
      if (!this.wsDir || typeof rel !== 'string' || !rel || rel.length > 200) return null;
      const root = resolve(this.wsDir);
      const p = resolve(root, rel);
      if (p !== root && !p.startsWith(root + sep)) return null;
      try {
        const st = statSync(p);
        if (!st.isFile() || st.size > 256 * 1024) return null; // the shelf's own MAX_FILE_BYTES
        return readFileSync(p, 'utf8');
      } catch { return null; }
    };
    for (const t of tools.slice(0, 10)) {
      try {
        const name = String((t && typeof t === 'object' && t.name) || t || '').trim();
        if (!name || this._shelvedScratch.has(name)) continue;
        const files = [];
        if (t && typeof t === 'object') {
          if (typeof t.content === 'string' && t.content) files.push({ name: base(t.file || t.path || name), content: t.content });
          if (Array.isArray(t.files)) for (const f of t.files.slice(0, 20)) {
            if (f && typeof f.content === 'string' && f.content) files.push({ name: base(f.name || 'tool.txt'), content: f.content });
          }
        }
        if (!files.length) { // workspace read-back: the script the agent ran, copied out before the reap
          const rel = (t && typeof t === 'object' && typeof t.path === 'string' && t.path) || name;
          const content = readWs(rel);
          if (content != null) files.push({ name: base(rel), content });
        }
        if (!files.length) continue; // a bare name carries no bytes — the log above still records it
        const kind = SHELF_KINDS.includes(t && t.kind) ? t.kind : 'utility';
        const e = shelveTool({
          name, kind,
          description: (t && typeof t === 'object' && t.description) || `scratch tool declared in ${phaseId} phase`,
          files,
          origin: { agent: (this.engine && this.engine.model) || 'campaign-agent', session: (this.scope && this.scope.engagement) || null },
        });
        this._shelvedScratch.add(name);
        this._log('scratch-tools.shelved', { phase: phaseId, name, id: e.id, files: e.files.length });
        this.surface.note(phaseId, `scratch tool "${name}" auto-shelved as quarantined data (shelf id ${e.id}) — operator review/promote in Settings`);
      } catch (err) {
        this._log('scratch-tools.shelve-error', { phase: phaseId, tool: String(t && (t.name || t)).slice(0, 80), error: String((err && err.message) || err) });
      }
    }
  }

  async tooledRecon() {
    if (this.reconOpts.domain) {
      // PASSIVE FIRST — public datasets (CT logs + Wayback) cost ZERO target contact, so they
      // run before a single packet touches the scope. No _noise charge: there is no noise.
      // reconOpts.passive === false disables it outright (tests must never hit real providers).
      if (this.reconOpts.passive !== false) {
      try {
        // Watchdog-wrapped (2026-08-31): passiveRecon awaits external providers with no
        // campaign-side coverage — a wedged provider await froze the campaign silently.
        const pv = await this._withBudget(
          (this.reconOpts.passiveImpl || passiveRecon)(this.reconOpts.domain, this.reconOpts.passive || {}),
          this.reconOpts.passiveWatchdogMs || 60000, 'passive:' + this.reconOpts.domain
        ) || { subdomains: [], endpoints: [], sources: [] };
        const passiveHosts = new Map(); // name -> host id (placeholder hosts: discovered, not yet resolved)
        const ph = (name) => {
          if (!passiveHosts.has(name)) { const hid = this.surface.host(null, { label: name }); this.surface.subdomain(hid, name); passiveHosts.set(name, hid); }
          return passiveHosts.get(name);
        };
        for (const s of pv.subdomains) ph(s.name);
        for (const e of pv.endpoints) this.surface.endpoint(ph(e.host), e.path, 'GET');
        if (pv.subdomains.length || pv.endpoints.length) this._log('recon.tool', { passive: true, subdomains: pv.subdomains.length, endpoints: pv.endpoints.length, sources: pv.sources });
      } catch (e) { this._log('phase.error', { phase: 'recon', error: 'passive: ' + ((e && e.message) || e) }); }
      } // end passive !== false
      // Watchdog-wrapped (2026-08-31): a wedged DNS resolver await must skip, not freeze.
      const sd = await this._withBudget(
        (this.reconOpts.dnsImpl || subdomainScan)(this.reconOpts.domain, this.reconOpts),
        this.reconOpts.dnsWatchdogMs || 120000, 'subdomain:' + this.reconOpts.domain
      ) || { subdomains: [] };
      for (const s of sd.subdomains) { const hid = this.surface.host(s.ips[0], { label: s.name }); this.surface.subdomain(hid, s.name); this._log('recon.tool', { subdomain: s.name, ip: s.ips[0] }); }
      this._noise({ kind: 'subdomain-brute', host: this.reconOpts.domain });
      // Deception scan — DATA-FED ONLY over what the engagement already resolved (subs +
      // their CNAME/IPs): zero new requests, so no noise charge. Full TXT/MX/honey-path
      // scan is available to the agent via the CLI (canary command).
      if (this.reconOpts.canary !== false) {
        try {
          // Watchdog-wrapped (2026-08-31): try/catch alone does NOTHING for a hung promise.
          const dec = await this._withBudget(
            (this.reconOpts.canaryImpl || canaryScan)({
              target: this.reconOpts.domain,
              dnsData: { a: [], cname: sd.subdomains.map((s) => s.name), txt: [], mx: [], subs: sd.subdomains.map((s) => ({ name: s.name, ips: s.ips || [] })) },
              customPatterns: this.reconOpts.canaryPatterns,
            }),
            this.reconOpts.canaryWatchdogMs || 30000, 'canary:' + this.reconOpts.domain
          );
          if (dec) {
          if (dec.artifacts.length) this._log('recon.tool', { deception: dec.verdict, suspicion: dec.suspicion, artifacts: dec.artifacts.length });
          this.surface.note('deception', `${dec.verdict} (suspicion ${dec.suspicion}/100, ${dec.artifacts.length} artifact(s))`);
          this.deception = { verdict: dec.verdict, suspicion: dec.suspicion, artifacts: dec.artifacts };
          }
        } catch (e) { this._log('phase.error', { phase: 'recon', error: 'canary: ' + ((e && e.message) || e) }); }
      }
    }
    const fresh = this._freshInheritedTargets();
    let sweepTargets = this.targets.filter((t) => !fresh.ips.has(String(t)));
    // Build 3 (targetscore): the PRE-SWEEP ordering pass — score from what is known
    // before recon runs (hostname keywords + a fresh inherited surface's detail) and
    // sweep soft/high-value hosts FIRST. REORDERS ONLY: every in-scope host is still
    // swept, nothing is skipped or hidden; the full scoring runs post-sweep once real
    // recon data exists (runTargetScoring below).
    if (this.targetScoreEnabled && sweepTargets.length > 1) {
      try {
        const pre = preScoreTargets(sweepTargets, this._inheritedSurface);
        sweepTargets = pre.map((r) => r.target);
        this._log('targetscore.preorder', { order: pre.map((r) => ({ target: r.target, score: r.score })), basis: 'hostname keywords + inherited surface only — full scoring after recon gathers real data' });
      } catch (e) { this._log('phase.error', { phase: 'recon', error: 'targetscore-pre: ' + ((e && e.message) || e) }); }
    }
    // Watchdog-wrapped sweep (2026-08-31): recon() has a PER-host watchdog but no overall
    // budget and emitted ZERO events until every host finished — a long paced sweep read as
    // a freeze. Now: an overall budget (hosts x hostBudgetMs + slack) and a per-host
    // heartbeat (recon.sweep.host) so the operator feed and the stall detector see progress.
    const hbMs = this.reconOpts.hostBudgetMs || 240000;
    const sweepBudgetMs = this.reconOpts.sweepWatchdogMs || (sweepTargets.length * hbMs + 30000);
    if (sweepTargets.length) this._log('recon.sweep.start', { hosts: sweepTargets.length, budgetMs: sweepBudgetMs });
    const res = sweepTargets.length
      ? (await this._withBudget(
          recon(sweepTargets, { ...this.reconOpts, pacer: this.pacer, onHost: (h) => this._log('recon.sweep.host', { host: h && h.ip, services: (h && h.services || []).length, stalled: !!(h && h.stalled) }) }),
          sweepBudgetMs, 'sweep')) || { hosts: [], stalled: sweepTargets.slice(), scanned: 0 }
      : { hosts: [], stalled: [], scanned: 0 };
    if (res.stalled && res.stalled.length) this._log('recon.watchdog', { stalled: res.stalled, note: 'host scan exceeded its budget — skipped, sweep continues (honest gap, not hidden)' });
    for (const host of res.hosts) {
      this._log('recon.host', { host: host.label || host.ip, services: (host.services || []).length });
      if (host.scopeRefusals && host.scopeRefusals.length) this._log('scope.path.refused', { tool: 'recon-sweep', host: host.ip, refused: host.scopeRefusals.length, sample: host.scopeRefusals.slice(0, 8), prefixes: this.pathPrefixes });
      const hid = this.surface.host(host.ip, { label: host.label });
      const hn = this.surface.nodes.get(hid);
      if (hn) hn.sweptAt = new Date().toISOString(); // freshness gate reads this next session
      this.opsec.observe({ host: host.ip, toolCalls: 1 });
      this._noise({ kind: 'tcp-scan', host: host.ip });
      // Noise-budget gate (2026-08-31, fix B): a SPENT budget used to produce a bare
      // "escalate to HITL" log line and nothing else. Now the escalation is a real
      // countersign gate; refused/timed-out => the host is marked budgetExhausted, its
      // remaining loud tools are skipped, and recon completes honestly (phase advances).
      if (!(await this._budgetGate(hid, host.ip))) continue;
      for (const t of host.tech || []) this.surface.tech(hid, t.name);
      for (const sv of host.services) {
        this.surface.service(hid, sv.port, sv.proto, sv.name);
        if (sv.tls && sv.tls.subject) this.surface.tech(hid, 'TLS:' + sv.tls.subject);
        this._log('recon.tool', { host: host.ip, port: sv.port, name: sv.name });
        if (sv.name === 'http' || sv.name === 'https') {
          const base = (sv.name === 'https' ? 'https' : 'http') + '://' + host.ip + ':' + sv.port;
          // Ghost Mode gate: in 'required' mode, PUBLIC egress is fail-closed until the chain
          // is verified (refusal is logged and this service is skipped — honest, not hidden).
          if (this.ghost) {
            try {
              // Watchdog-wrapped (2026-08-31): a wedged identity-chain assertion is a hung
              // promise — try/catch can't help; trip the budget, skip the service, move on.
              const eg = await this._withBudget(this.ghost.assertEgress(base), this._toolBudget(host.ip, this.reconOpts.ghostGateMs || 15000), 'ghost-egress:' + host.ip + ':' + sv.port, { host: host.ip });
              if (eg === null) { this._log('recon.skip', { host: host.ip, port: sv.port, tools: ['webscan', 'apisurface', 'crawl', 'vulncheck', ...(sv.name === 'https' ? ['tls'] : [])], reason: 'ghost egress gate wedged — watchdog tripped, service skipped (honest, not hidden)' }); continue; }
            }
            catch (e) { if (e.ghostRefused) { this._log('ghost.refused', { host: host.ip, base, note: 'identity chain unverified — public web tooling skipped (fail-closed)' }); continue; } throw e; }
          }
          const pf = await this._preflight(host.ip, sv.port);
          if (!pf.ok) {
            this._log('recon.skip', { host: host.ip, port: sv.port, tools: ['webscan', 'apisurface', 'crawl', 'vulncheck', ...(sv.name === 'https' ? ['tls'] : [])], reason: pf.reason, probeMs: pf.ms });
            continue; // tls below shares this host:port — dead for it too
          }
          if (!this._reconWebBases.includes(base)) this._reconWebBases.push(base); // jsminer feeds on the discovered web bases
          const ghostAgents = this.ghost ? this.ghost.agents() : null;
          const discovered = []; // paths this engagement already paid for — vulncheck audits these, never guesses
          let svcTech = [];      // fingerprinted stack — drives the version→CVE packs
          const ws = await this._withBudget(webScan(base, { ...(this.reconOpts.web || {}), pacer: this.pacer, agents: ghostAgents }), this._toolBudget(host.ip, this.reconOpts.toolWatchdogMs || 180000), 'webscan:' + host.ip, { host: host.ip }) || { endpoints: [], findings: [] };
          this._logPathRefusals('webscan', ws, host.ip);
          this._noise({ kind: 'web-content-scan', host: host.ip });
          for (const ep of ws.endpoints) { this.surface.endpoint(hid, ep.path, 'GET'); discovered.push(ep.path); }
          for (const f of ws.findings) { const fid = this.surface.finding(hid, { title: f.title, sev: f.sev, ref: f.ref, confidence: 'confirmed' }); const fn = this.surface.nodes.get(fid); if (fn && f.soft404Baselined) fn.soft404Baselined = true; this._log('finding', { title: f.title, sev: f.sev, ref: f.ref }); }
          this._recordSoft404('webscan', ws, hid, host.ip);
          // Native API/endpoint/parameter surface discovery (non-destructive, stealth-aware) —
          // maps what the app volunteers (robots/sitemap/OpenAPI/GraphQL/HTML+JS) into the graph.
          try {
            const api = await this._withBudget(apiSurface(base, { ...(this.reconOpts.api || {}), pacer: this.pacer, agents: ghostAgents }), this._toolBudget(host.ip, this.reconOpts.toolWatchdogMs || 120000), 'apisurface:' + host.ip, { host: host.ip }) || { endpoints: [], params: [], descriptors: [], findings: [] };
            this._logPathRefusals('apisurface', api, host.ip);
            this._noise({ kind: 'http-methods', host: host.ip });
            for (const ep of api.endpoints) { this.surface.endpoint(hid, ep.path, (ep.methods && ep.methods[0]) || 'GET'); discovered.push(ep.path); }
            for (const f of api.findings) { this.surface.finding(hid, { title: f.title, sev: f.sev, ref: f.ref, confidence: 'confirmed' }); this._log('finding', { title: f.title, sev: f.sev, ref: f.ref }); }
            // reflected query params feed the exploit-phase DOM-XSS canary (browseragent lane)
            // AND land on the surface as ?param= endpoints so the OOB lane fires (Build 2 fix:
            // apisurface now tags each harvested param with the path it was seen on).
            for (const p of api.params || []) {
              if (!p || p.where !== 'query' || typeof p.name !== 'string') continue;
              try { this._reflectedParams.push({ base: new URL(p.path || '/', base).href, param: p.name }); } catch { /* unparseable param source — skip */ }
              if (p.path) this._paramEndpoint(hid, p.path, p.name);
            }
            if (api.endpoints.length || api.params.length || api.descriptors.length) this._log('recon.tool', { host: host.ip, apiEndpoints: api.endpoints.length, apiParams: api.params.length, descriptors: api.descriptors.length });
          } catch (e) { this._log('phase.error', { phase: 'recon', error: 'apisurface: ' + ((e && e.message) || e) }); }
          // Native crawler — BFS over the site's OWN links/forms (never guesses paths), so it
          // finds the navigable surface wordlists can't, at a lower noise kind than brute-force
          // content discovery. Same pacer, same budget discipline, same-origin enforced.
          try {
            const cw = await this._withBudget(crawl(base, { ...(this.reconOpts.crawl || {}), pacer: this.pacer, agents: ghostAgents }), this._toolBudget(host.ip, this.reconOpts.toolWatchdogMs || 180000), 'crawl:' + host.ip, { host: host.ip }) || { endpoints: [], tech: [], findings: [], pages: [], forms: [] };
            this._logPathRefusals('crawl', cw, host.ip);
            this._noise({ kind: 'web-crawl', host: host.ip });
            for (const ep of cw.endpoints) { this.surface.endpoint(hid, ep.path, (ep.methods && ep.methods[0]) || 'GET'); discovered.push(ep.path); }
            for (const t of cw.tech || []) { this.surface.tech(hid, t.label, t.version); }
            svcTech = cw.tech || [];
            // Harvested query params (Build 2 fix): land as ?param= endpoint nodes so the
            // OOB lane sees parameterized endpoints, and feed the DOM-XSS canary list.
            for (const p of cw.params || []) {
              if (!p || p.where !== 'query' || typeof p.name !== 'string') continue;
              try { this._reflectedParams.push({ base: new URL(p.path || '/', base).href, param: p.name }); } catch { /* skip */ }
              if (p.path) this._paramEndpoint(hid, p.path, p.name);
            }
            // GET-form fields are reflected-param candidates for the DOM-XSS canary lane —
            // and a GET form at /search with field q IS the parameterized endpoint /search?q=
            for (const f of cw.forms || []) {
              if (String(f.method || 'GET').toUpperCase() !== 'GET') continue;
              for (const field of f.fields || f.inputs || []) {
                try { this._reflectedParams.push({ base: new URL(f.action || f.page || '/', base).href, param: field }); } catch { /* skip */ }
                this._paramEndpoint(hid, f.action || f.page || '/', field);
              }
            }
            for (const f of cw.findings) { this.surface.finding(hid, { title: f.title, sev: f.sev, ref: f.ref, confidence: 'confirmed' }); this._log('finding', { title: f.title, sev: f.sev, ref: f.ref }); }
            if (cw.pages.length) this._log('recon.tool', { host: host.ip, crawled: cw.pages.length, crawlEndpoints: cw.endpoints.length, forms: cw.forms.length, tech: (cw.tech || []).length });
          } catch (e) { this._log('phase.error', { phase: 'recon', error: 'crawl: ' + ((e && e.message) || e) }); }
          // Native vuln-check engine — curated known-exposure probes (content-VERIFIED, so every
          // finding is confirmed) + header/cookie/CORS/body-leak audits riding on pages the
          // engagement already fetched. The Nuclei slot, without 9,000 templates of volume.
          try {
            const vc = await this._withBudget(vulnCheck(base, { ...(this.reconOpts.vuln || {}), pagePaths: discovered, tech: svcTech, pacer: this.pacer, agents: ghostAgents }), this._toolBudget(host.ip, this.reconOpts.toolWatchdogMs || 120000), 'vulncheck:' + host.ip, { host: host.ip }) || { vulnerabilities: [], requests: 0 };
            this._logPathRefusals('vulncheck', vc, host.ip);
            this._noise({ kind: 'vuln-check', host: host.ip });
            for (const v of vc.vulnerabilities) { const fid = this.surface.finding(hid, { title: v.title, sev: v.sev, ref: v.ref, confidence: v.confidence }); const fn = this.surface.nodes.get(fid); if (fn && v.soft404Baselined) fn.soft404Baselined = true; this._log('finding', { title: v.title, sev: v.sev, ref: v.ref }); }
            this._recordSoft404('vulncheck', vc, hid, host.ip);
            if (vc.vulnerabilities.length) this._log('recon.tool', { host: host.ip, vulnChecks: vc.requests, vulns: vc.vulnerabilities.length });
          } catch (e) { this._log('phase.error', { phase: 'recon', error: 'vulncheck: ' + ((e && e.message) || e) }); }
        }
        if (sv.name === 'https') {
          this._noise({ kind: 'tls-probe', host: host.ip });
          const t = await this._withBudget(analyzeTls(host.ip, sv.port).catch(() => null), this._toolBudget(host.ip, 45000), 'tls:' + host.ip, { host: host.ip });
          if (t && t.findings) for (const f of t.findings) { this.surface.finding(hid, { title: 'TLS: ' + f.title, sev: f.sev, ref: f.ref, confidence: 'confirmed' }); this._log('finding', { title: f.title, sev: f.sev, ref: f.ref }); }
        }
      }
      // Native OS fingerprint — ONLY when recon already earned the signal (445 open): one
      // SMB negotiate, honest version band, no nmap-style probe battery. Kill: reconOpts.osfp===false.
      const smbPorts = this.reconOpts.smbPorts || [445]; // test seam: fixtures point at a stand-in port
      const osfpWanted = this.reconOpts.osfp !== false && host.services.some((s) => smbPorts.includes(s.port));
      if (osfpWanted && this._degraded(host.ip)) {
        this._log('recon.skip', { host: host.ip, tools: ['osfp'], reason: 'host degraded (2+ consecutive wedge trips) — non-essential extra skipped' });
      } else if (osfpWanted) {
        try {
          const fp = await this._withBudget((this.reconOpts.osfpImpl || osFingerprint)(host.ip, { signals: ['smb'] }), this._toolBudget(host.ip, 45000), 'osfp:' + host.ip, { host: host.ip }) || { family: 'unknown' };
          this._noise({ kind: 'os-fingerprint', host: host.ip });
          if (fp.family !== 'unknown') this.surface.tech(hid, 'OS:' + fp.family + (fp.version ? ' — ' + fp.version : ''));
          this._log('recon.tool', { host: host.ip, osFamily: fp.family, osVersion: fp.version, osConfidence: fp.confidence });
        } catch (e) { this._log('phase.error', { phase: 'recon', error: 'osfp: ' + ((e && e.message) || e) }); }
      }
      // Native LDAP rootDSE read — only when a directory port presented itself (389/636/3268).
      // Anonymous, one connection, honest whether the directory refuses. Kill: reconOpts.ldap===false.
      const ldapPorts = this.reconOpts.ldapPorts || [389, 636, 3268]; // test seam: fixtures point at a stand-in port
      const ldapSvc = host.services.find((s) => ldapPorts.includes(s.port));
      const ldapWanted = this.reconOpts.ldap !== false && ldapSvc;
      if (ldapWanted && this._degraded(host.ip)) {
        this._log('recon.skip', { host: host.ip, tools: ['ldap'], reason: 'host degraded (2+ consecutive wedge trips) — non-essential extra skipped' });
      } else if (ldapWanted) {
        try {
          const ghostDial = this.ghost && this.ghost.mode !== 'off' ? (h, p, t) => this.ghost.connect({ host: h, port: p, timeout: t }) : undefined;
          const le = await this._withBudget((this.reconOpts.ldapImpl || ldapEnum)(host.ip, { port: ldapSvc.port, connectImpl: ghostDial }), this._toolBudget(host.ip, 45000), 'ldap:' + host.ip, { host: host.ip }) || { anonymous: false, verdict: 'watchdog-skipped' };
          this._noise({ kind: 'ldap-enum', host: host.ip });
          if (le.anonymous && le.defaultNamingContext) { this.surface.tech(hid, 'LDAP:' + le.vendorGuess); this.surface.note('ldap', host.ip + ': ' + le.defaultNamingContext + ' (' + (le.functionality.domain || 'unknown level') + ')'); }
          this._log('recon.tool', { host: host.ip, ldap: le.verdict });
        } catch (e) { this._log('phase.error', { phase: 'recon', error: 'ldap: ' + ((e && e.message) || e) }); }
      }
    }
    if (this._reflectedParams.length > 64) this._reflectedParams = this._reflectedParams.slice(0, 64); // cap the canary target list
    // Build 2: JS/sourcemap mining lane (launch option jsminer:true) — runs AFTER
    // crawl/apisurface so harvested endpoints join the same surface the authz oracle
    // harvests. Dormant lane: runJsMiner logs jsminer.skip itself.
    try { await this.runJsMiner(); } catch (e) { this._log('phase.error', { phase: 'recon', error: 'jsminer: ' + ((e && e.message) || e) }); }
    // Build 3: full target scoring from the data recon just gathered — per-host
    // {score 0-100, reasons, classes} land ON the host nodes; downstream lanes order
    // their per-host tool budgets by score descending and the report renders the
    // "Target scoring" section. Dormant layer: runTargetScoring logs its own skip.
    try { this.runTargetScoring(); } catch (e) { this._log('phase.error', { phase: 'recon', error: 'targetscore: ' + ((e && e.message) || e) }); }
    this.surface.note('recon', 'tooled recon · native scanner + content discovery');
  }

  // Honest path-scope accounting: a tool that refused out-of-prefix requests reports
  // them; the campaign puts the refusal on the record (scope.path.refused).
  _logPathRefusals(tool, res, host) {
    const refs = res && Array.isArray(res.scopeRefusals) ? res.scopeRefusals : [];
    if (refs.length) this._log('scope.path.refused', { tool, host, refused: refs.length, sample: refs.slice(0, 8), prefixes: this.pathPrefixes });
  }

  // Soft-404 honesty (Build 1): a baseline-matched response is NOT a finding — but the
  // debunk goes ON the record (soft404.match event + surface debunk ledger), so the
  // report shows what a status-only scanner would have filed and why we didn't.
  _recordSoft404(tool, res, hid, host) {
    const s = res && res.soft404;
    if (!s || !Array.isArray(s.matched) || !s.matched.length) return;
    const hn = this.surface.nodes.get(hid);
    const hostLabel = (hn && (hn.label || hn.ip)) || host;
    for (const m of s.matched) {
      this._log('soft404.match', { tool, host: hostLabel, path: m.path, title: m.title || m.id, note: 'response fingerprint-matched the SPA fallback baseline — debunked, NOT filed' });
      this.surface.debunk({ host: hostLabel, path: m.path, title: m.title || m.id || 'catch-all 200', tool });
    }
    this.surface.note('recon', `soft-404 baseline (${tool}): ${s.matched.length} claim(s) DEBUNKED on ${hostLabel} — SPA fallback fingerprint match, not exposures`);
  }

  // Build 2: a harvested query param lands on the surface as a PARAMETERIZED endpoint
  // (/path?name=) so the OOB lane's filter sees it. Deduped per campaign run.
  _paramEndpoint(hid, path, name) {
    const p = String(path || '/').split('?')[0] || '/';
    const n = String(name || '').trim();
    if (!n || n.length > 64 || !/^[\w.-]+$/.test(n)) return;
    const label = p + '?' + n + '=';
    if (this._paramEndpointSeen.has(hid + label)) return;
    this._paramEndpointSeen.add(hid + label);
    this.surface.endpoint(hid, label, 'GET');
  }

  // Hard per-call watchdog for the recon pipeline (2026-08-29 — Jack's stall report):
  // a wedged tool await (DNS stall with no timeout, peer-hung socket whose handlers
  // never settle) must skip + log, never freeze the campaign. Resolves null on trip;
  // callers pair it with a safe fallback object. The trip is LOGGED, never hidden.
  // 2026-08-30 dead-time follow-up: trips now feed _noteWedgeTrip so a host that keeps
  // wedging tools gets degraded (halved budgets, non-essential extras skipped) instead
  // of repeatedly sitting out full budgets.
  _withBudget(p, ms, label, { host } = {}) {
    return Promise.race([
      p,
      new Promise((resolve) => {
        const t = setTimeout(() => {
          this._log('recon.watchdog', { tool: label, budgetMs: ms, note: 'wedged await tripped — tool skipped, campaign continues' });
          this._noteWedgeTrip(host || String(label || '').split(':').pop());
          resolve(null);
        }, ms);
        if (t.unref) t.unref();
      }),
    ]);
  }

  // Pre-flight reachability probe (2026-08-30 — recon dead-time elimination). A host that
  // closed/filtered the port AFTER the sweep (or silently drops everything) makes every web
  // tool burn its full per-request deadlines until the watchdog trips — 180+120+180+120+45s
  // of pure dead time per service. One cheap TCP probe (same socket the sweep already used)
  // tells us in ≤ preflightMs whether ANY request can be answered. This ADDS one packet and
  // REMOVES hundreds of doomed ones; the wire profile only shrinks. Kill: preflight===false.
  async _preflight(host, port) {
    if (this.reconOpts.preflight === false) return { ok: true, ms: 0 };
    const budgetMs = this.reconOpts.preflightMs || 3000;
    const started = Date.now();
    // 2026-08-31 stall fix: the pace() await used to sit OUTSIDE the probe's race below —
    // a backlogged shared emission clock (zombie race-losers keep pacing) froze the campaign
    // here with zero watchdog coverage (bykea's last event was the line above this await).
    // The pace wait is now bounded by the same preflight budget; the pacer's own maxWaitMs
    // clamp (engine/stealth.mjs) is the systemic bound underneath it.
    if (this.pacer && this.pacer.pace) {
      await Promise.race([
        Promise.resolve().then(() => this.pacer.pace()).catch(() => {}),
        new Promise((resolve) => { const t = setTimeout(resolve, budgetMs); if (t.unref) t.unref(); }),
      ]);
    }
    const probe = (this.reconOpts.probeImpl || tcpProbe)(host, port, budgetMs);
    const r = await Promise.race([
      Promise.resolve(probe).catch(() => null),
      new Promise((resolve) => { const t = setTimeout(() => resolve(null), budgetMs + 250); if (t.unref) t.unref(); }),
    ]);
    const ms = Date.now() - started;
    if (r == null) return { ok: false, ms, reason: 'preflight probe wedged — treated as filtered' };
    if (!r.open) return { ok: false, ms, reason: 'port closed/filtered at tool time — web tools would burn full deadlines for nothing' };
    return { ok: true, ms };
  }

  _noteWedgeTrip(host) {
    if (!host) return;
    const trips = (this._wedgeTrips.get(host) || 0) + 1;
    this._wedgeTrips.set(host, trips);
    if (trips >= 2 && !this._degradedHosts.has(host)) {
      this._degradedHosts.add(host);
      this._log('recon.degraded', { host, trips, action: 'tool budgets halved, non-essential extras skipped', note: 'host wedged 2+ tools in a row — it cannot answer at full pace; stop paying full budgets for silence' });
    }
  }
  _degraded(host) { return this._degradedHosts.has(host); }
  // Halved, never zero — the host answered the sweep, so SOME traffic is warranted; we just
  // stop paying full price for a host that demonstrably can't keep up. Floor 50ms keeps
  // test-scale budgets halving literally.
  _toolBudget(host, baseMs) { return this._degraded(host) ? Math.max(50, Math.floor(baseMs / 2)) : baseMs; }

  // Campaign-level stall detector (2026-08-31): no activity event for stallAfterMs while
  // running => some await wedged WITHOUT watchdog coverage (the tripcom/bykea failure
  // mode). Log campaign.stall with the last event + await context and park VISIBLE as
  // stalled:<phase> with the reason. Skips: not running, parked at a HITL gate
  // (_awaitingApproval), already stalled. Re-arms automatically on the next real event
  // (_log clears this.stall). Returns the stall object when firing/parked, else null.
  _checkStall() {
    if (this._stallAfterMs <= 0) return null; // explicit kill switch
    const st = String(this.status || '');
    if (!st.startsWith('running') && !st.startsWith('stalled')) return null;
    if (this._awaitingApproval > 0) return null; // a countersign wait is a legit, visible park
    if (this.stall) return this.stall;           // already parked — stay visible, don't spam
    const now = this._now();
    const elapsed = now - (this._lastActivityAt || now);
    if (elapsed < this._stallAfterMs) return null; // legit long tool runs stay under their watchdog budgets (< stallAfterMs)
    const phase = (PHASES[this.phaseIndex] || {}).id || 'unknown';
    const last = this.activity[this.activity.length - 1] || null;
    this.stall = {
      phase, since: new Date(now).toISOString(), elapsedMs: Math.round(elapsed),
      lastEvent: last ? { kind: last.kind, at: last.at, seq: last.seq } : null,
      reason: `no activity for ${Math.round(elapsed / 1000)}s (threshold ${Math.round(this._stallAfterMs / 1000)}s) during ${phase} — last event: ${last ? last.kind : 'none'}. An await is wedged without watchdog coverage; the campaign is parked, not silently frozen.`,
    };
    this.status = 'stalled:' + phase;
    this._log('campaign.stall', this.stall);
    this.surface.note(phase, 'STALLED — ' + this.stall.reason);
    this._onSurface();
    return this.stall;
  }

  // Noise-budget gate for the per-host recon tooling (2026-08-31 — fix B of the live-stall
  // report). When the budget is SPENT, the old code logged "escalate to HITL" and nothing
  // else — a bare string, no approval, no completion path. Now the escalation is REAL:
  // the countersign gate (_approve → state.pendingApproval in live mode, with the console's
  // approve path) is asked ONCE per campaign. Granted => tooling continues, charged as an
  // HITL-authorized override. Refused/timed-out/no-hook (fail-closed) => the host is marked
  // budgetExhausted on the surface, logged as recon.budget, its remaining loud tools are
  // skipped, and recon COMPLETES honestly so the campaign advances to validate.
  async _budgetGate(hid, host) {
    if (!this.noise || this.noise.maxNoise === Infinity) return true; // no stealth ceiling — nothing to gate
    if (this.noise.remaining() > 0) return true;
    if (this._budgetOverride == null) {
      this._log('recon.budget', { host, spent: this.noise.spent(), maxNoise: this.noise.maxNoise, note: 'noise budget exhausted — escalating to HITL via the real countersign gate; refusal/timeout completes recon honestly with loud tools skipped' });
      this.surface.note('recon', 'noise budget exhausted — requesting an HITL override (gate: budget-override)');
      this._log('gate.request', { phase: 'budget-override' });
      this._budgetOverride = await this._approve({ id: 'budget-override', gate: 'sigil' });
      this._log('gate.decision', { phase: 'budget-override', signed: this._budgetOverride });
    }
    if (this._budgetOverride) return true;
    const hn = this.surface.nodes.get(hid);
    if (hn && !hn.budgetExhausted) hn.budgetExhausted = true;
    this._log('recon.budget', { host, spent: this.noise.spent(), maxNoise: this.noise.maxNoise, budgetExhausted: true, note: 'host marked budgetExhausted — HITL override refused/timed out; remaining loud recon tools skipped, recon completes honestly (partial detail is an honest gap, not hidden)' });
    this.surface.note('recon', `${host}: budgetExhausted — noise budget spent, no HITL override; recon detail is partial and the campaign advances`);
    return false;
  }

  // Cross-session freshness gate (2026-08-30): a host whose prior surface is fresh
  // (< resweepAfterMs, default 24h) AND still carries service+endpoint detail does not
  // need to be swept again — resweeping is the single largest dead-time source on replans
  // (bykea: 249 watchdog trips / 15 hosts ≈ 16.6 trips per host = repeated full re-runs).
  // Non-lossy: the host's prior services+endpoints are seeded into the LIVE surface and
  // marked inherited, so downstream phases see the same shape they would after a resweep.
  // resweepAfterMs: 0 forces always-resweep (old behaviour).
  _freshInheritedTargets() {
    const out = { ips: new Set(), targets: [] };
    if (!this.carryForward || !this._inheritedSurface || !Array.isArray(this._inheritedSurface.nodes)) return out;
    const maxAge = this.reconOpts.resweepAfterMs == null ? 24 * 3600 * 1000 : this.reconOpts.resweepAfterMs;
    if (maxAge === 0) return out; // explicit always-resweep
    const nodes = this._inheritedSurface.nodes;
    const edges = this._inheritedSurface.edges || [];
    const now = Date.now();
    for (const t of this.targets) {
      const h = nodes.find((n) => n.type === 'host' && n.ip != null && String(n.ip) === String(t));
      if (!h || !h.sweptAt) continue;
      const age = now - Date.parse(h.sweptAt);
      if (!Number.isFinite(age) || age >= maxAge) continue;
      const services = nodes.filter((n) => n.type === 'service' && n.host === h.id);
      const endpoints = nodes.filter((n) => n.type === 'endpoint' && edges.some((e) => e.kind === 'exposes' && e.from === h.id && e.to === n.id));
      if (!services.length || !endpoints.length) continue; // thin record — not safe to skip
      // Seed the detail into the live surface (seedFrom carries hosts+findings only).
      const hid = this.surface.host(h.ip, { label: h.label });
      for (const s of services) { const sid = this.surface.service(hid, s.port, s.proto, s.name); const sn = this.surface.nodes.get(sid); if (sn) sn.inherited = true; }
      for (const e of endpoints) { const eid = this.surface.endpoint(hid, e.label, e.method); const en = this.surface.nodes.get(eid); if (en) en.inherited = true; }
      this._log('recon.inherited', { host: t, sweptAt: h.sweptAt, ageMin: Math.round(age / 60000), services: services.length, endpoints: endpoints.length, note: 'fresh prior surface — resweep skipped, detail carried forward (honest, marked inherited)' });
      out.ips.add(String(t));
      out.targets.push(t);
    }
    return out;
  }

  _webBases() {
    const ro = this.reconOpts || {};
    const ports = ro.webPorts instanceof Set ? [...ro.webPorts] : (Array.isArray(ro.ports) ? ro.ports : []);
    const bases = [];
    for (const t of this.targets) for (const p of ports) bases.push(`${p === 443 || p === 8443 ? 'https' : 'http'}://${t}:${p}`);
    return bases;
  }
  _firstHostId() { for (const n of this.surface.nodes.values()) if (n.type === 'host') return n.id; return this.surface.root; }

  // Auto-stealth: fingerprint the target's defensive stack (WAF/CDN/rate-limit/challenge)
  // and CALIBRATE the enforced profile + noise budget to it, before recon runs. This is the
  // adaptive stealth RedAmon names but punts to its LLM — VARVEL decides it from measured
  // signals. Falls back to 'normal' if the target can't be profiled. Never throws.
  async _calibrateStealth() {
    if (!this.autoStealth) return;
    const base = this._webBases()[0] || (this.targets[0] ? `http://${this.targets[0]}` : null);
    let rec = 'normal', prof = null;
    if (base) {
      try { prof = await detectStack(base, { timeout: 2500, agents: this.ghost ? this.ghost.agents() : null }); } catch { prof = null; }
      if (prof && prof.calibration && prof.calibration.recommended) rec = prof.calibration.recommended;
    }
    this.targetProfile = prof;
    this.stealthName = rec;
    this.noise = new StealthBudget(rec);
    if (this.noiseCap) this.noise.maxNoise = this.noiseCap; // the launch-sized ceiling survives calibration
    this.pacer = makePacer(rec, { extraHeaders: this.extraHeaders, maxWaitMs: this.reconOpts.paceMaxWaitMs, shaper: ghostShaper(this.ghost) }); // the shared engagement pacer, now that the profile is resolved
    this.reconOpts.stealth = rec;
    this.reconOpts.web = { ...(this.reconOpts.web || {}), stealth: rec };
    const vendors = prof ? (prof.defenses || []).map((d) => d.vendor) : [];
    this._log('stealth.calibrate', { base, recommended: rec, defenses: prof ? (prof.defenses || []).map((d) => d.id) : [], reasons: prof && prof.calibration ? prof.calibration.reasons : [] });
    this.surface.note('recon', `stealth auto-calibrated → ${rec}${vendors.length ? ' (' + vendors.join(', ') + ')' : ' (no WAF/CDN/rate-limit detected)'}`);
  }

  // Concrete surface state handed to the validate/exploit/post-ex agent so it acts on
  // what recon already found instead of blindly re-discovering (which causes out-of-scope
  // + workspace-escape denials and wasted turns). Includes the scope + workspace boundary.
  _surfaceBriefing() {
    const all = [...this.surface.nodes.values()];
    const svcs = all.filter((n) => n.type === 'service');
    const eps = all.filter((n) => n.type === 'endpoint');
    const findings = all.filter((n) => n.type === 'finding');
    const confirmed = findings.filter((f) => f.confidence === 'confirmed');
    const bases = this._webBases();
    const L = [];
    const targets = bases.length ? bases.join(', ') : (this.targets.join(', ') || (this.scope.cidrs || []).join(', '));
    L.push(`\n[surface] Target(s): ${targets}. Signed scope: ${(this.scope.cidrs || []).join(', ') || 'n/a'}.`);
    if (this.pathPrefixes) L.push(`[surface] PATH-SCOPED engagement: ONLY URLs under ${this.pathPrefixes.join(', ')} are in scope on the signed host(s) — every other path (including the site root) is REFUSED by the platform; do not attempt it. Seed from the prefix URL itself.`);
    L.push('Operate ONLY within the signed scope, and confine file operations to your workspace directory — anything outside is DENIED by the platform, so do not attempt it (it is wasted effort and noise). These are REMOTE HTTP targets: use curl/HTTP, not local file reads.');
    if (svcs.length) L.push(`Services: ${svcs.slice(0, 12).map((v) => `${v.name || '?'}:${v.port}`).join(', ')}.`);
    if (confirmed.length) L.push(`Confirmed findings to act on: ${confirmed.slice(0, 10).map((f) => `${f.label} [${f.sev}]`).join('; ')}.`);
    else if (findings.length) L.push(`Findings so far: ${findings.slice(0, 10).map((f) => `${f.label} [${f.sev}]`).join('; ')}.`);
    if (eps.length) L.push(`Known endpoints: ${eps.slice(0, 18).map((e) => e.label).join(', ')}.`);
    return L.join('\n');
  }

  // chainforge: compile executable exploit chains from the LIVE surface (the deterministic
  // exploit brain — the campaign proposes chains from evidence instead of the agent
  // improvising). Runs at exploit-prep alongside the guided search. Never throws.
  compileChains() {
    try {
      const nodes = [...this.surface.nodes.values()];
      const endpoints = nodes.filter((n) => n.type === 'endpoint').map((n) => ({ path: n.label, method: n.method || 'GET' }));
      const findings = nodes.filter((n) => n.type === 'finding').map((n) => ({ id: n.ref || '', title: n.label || '' }));
      const material = {};
      for (const e of endpoints) {
        if (/legacy|bundle|auth\.js/i.test(e.path) && !material.bundlePath) material.bundlePath = e.path;
        if (/^\/login$/i.test(e.path) && !material.loginPath) material.loginPath = e.path;
        if (/^\/admin$/i.test(e.path) && !material.adminPath) material.adminPath = e.path;
        if (/admin\/(content|banner|message|config)/i.test(e.path) && !material.writePath) material.writePath = e.path;
      }
      this.chainPlans = chainforge({ endpoints, findings, material });
      if (this.chainPlans.plans.length) {
        this._log('chainforge', { compiled: this.chainPlans.plans.map((p) => p.rule) });
        this.surface.note('exploit', `chainforge compiled ${this.chainPlans.plans.length} chain(s): ${this.chainPlans.plans.map((p) => p.rule).join(', ')}`);
      } else if (this.chainPlans.gaps.length) {
        this._log('chainforge', { compiled: [], gaps: this.chainPlans.gaps.length });
      }
      return this.chainPlans;
    } catch (e) { this._log('phase.error', { phase: 'exploit', error: 'chainforge: ' + ((e && e.message) || e) }); return null; }
  }

  // chaincompose v2: after validate, compose candidate chains from typed PRIMITIVES over
  // the live surface (validated + suspected lows/meds ARE the primitive instances — the
  // mapping is honest: a finding only feeds composition through the endpoints/findings it
  // actually produced; no mapping, no primitive). Composed candidates are logged
  // (chain.composed) and parked on the surface as exploit nodes (state 'proposed',
  // the compiled chain document attached). Never throws; honest-empty is a result.
  async composeChainsFromSurface() {
    try {
      const nodes = [...this.surface.nodes.values()];
      const endpoints = nodes.filter((n) => n.type === 'endpoint').map((n) => ({ path: n.label, method: n.method || 'GET' }));
      const findings = nodes.filter((n) => n.type === 'finding').map((n) => ({ id: n.ref || '', title: n.label || '', sev: n.sev }));
      const out = await composeChains({ endpoints, findings, material: { endpoints } });
      this.composedChains = out;
      if (out.chains.length) {
        for (const chain of out.chains) {
          const xid = this.surface.exploit(this.surface.root, { title: chain.name, state: 'proposed' });
          const n = this.surface.nodes.get(xid);
          if (n) { n.composed = true; n.chain = { steps: chain.steps, impact: chain.impact || null, primitives: chain.primitives }; }
        }
        this._log('chain.composed', { chains: out.chains.map((c) => c.name), search: out.search });
        this.surface.note('validate', `chaincompose composed ${out.chains.length} candidate chain(s) from validated primitives: ${out.chains.map((c) => c.name.slice(0, 60)).join(', ')}`);
      } else {
        this._log('chain.composed', { chains: [], gaps: out.gaps.length, note: 'honest empty — no primitive composition fits the surface' });
      }
      this._onSurface();
      return out;
    } catch (e) { this._log('phase.error', { phase: 'validate', error: 'chaincompose: ' + ((e && e.message) || e) }); return null; }
  }

  // Execute ONE composed chain through the governed executor (chainrun v2 — impact
  // assertion included). Impact-proven chains land as findings via findingFromChain()
  // (validator-oracle-citing evidence, confirmed tier) and their surface node flips to
  // 'proved'. A hollow success (steps green, impact absent) is a FAILURE: logged, fed
  // to the failure ledger, node flipped to 'failed'. Scope-gated like validateFinding.
  async runComposedChain(sel, { base } = {}) {
    const chains = (this.composedChains && this.composedChains.chains) || [];
    const chain = typeof sel === 'number' ? chains[sel] : chains.find((c) => c.name === sel);
    if (!chain) return { ok: false, error: 'no such composed chain: ' + String(sel) };
    const target = base || this._webBases()[0];
    if (!target) return { ok: false, error: 'no web base known for the engagement — recon has not surfaced one' };
    let host = '';
    try { host = new URL(target).hostname; } catch { return { ok: false, error: 'unparseable base URL' }; }
    const asIp = parseIp(host);
    const inScope = asIp
      ? inAnyCidr(asIp.text, this.scope.cidrs || [])
      : [...this.surface.nodes.values()].some((n) => (n.type === 'host' || n.type === 'subdomain') && (n.label === host || n.ip === host));
    if (!inScope) { this._log('chain.refused', { chain: chain.name, target, reason: 'out-of-scope' }); return { ok: false, error: `refused: ${host} is outside the signed scope (fail-closed)` }; }

    const node = [...this.surface.nodes.values()].find((n) => n.type === 'exploit' && n.composed && n.label === chain.name);
    const run = await runChain({ name: chain.name, base: target, steps: chain.steps, ...(chain.impact ? { impact: chain.impact } : {}) }, { pacer: this.pacer, pathPrefixes: this.pathPrefixes || undefined });
    this._noise({ kind: 'exploit-attempt', host, authorized: true });

    if (run.ok && run.impact && run.impact.ok) {
      const f = findingFromChain(run, { title: chain.name });
      const hid = ([...this.surface.nodes.values()].find((n) => (n.type === 'host') && (n.ip === host || n.label === host)) || {}).id || this.surface.root;
      this.surface.finding(hid, { title: f.title, sev: f.sev, ref: f.ref, confidence: f.confidence, evidence: f.evidence });
      if (node) node.state = 'proved';
      this._log('chain.proved', { chain: chain.name, steps: run.stepsCompleted + '/' + run.stepsTotal, impact: run.impact.detail });
      this.surface.note('exploit', `chain PROVED with impact: ${chain.name}`);
    } else {
      if (node) node.state = 'failed';
      const why = run.hollowSuccess ? 'hollow success — steps passed, impact assertion failed' : 'chain did not complete';
      this._fail('failed-chain', `${chain.name} (${why})`, 'exploit');
      this._log('chain.failed', { chain: chain.name, hollow: run.hollowSuccess === true, detail: run.impact ? run.impact.detail : null });
      this.surface.note('exploit', `chain FAILED honestly: ${chain.name} — ${why}`);
    }
    this._onSurface();
    return { ok: run.ok, chain: chain.name, run };
  }

  // Build 1 — the two-account authorization oracle as a campaign primitive (IDOR/BOLA).
  // Given two provisioned accounts (launch option authz.accounts — cookies or login
  // recipes), this: HARVESTS object references from both sessions' traffic over the
  // known surface endpoints, CROSS-REPLAYS every reference across sessions + unauth
  // (the control), CLASSIFIES read/write/delete cross-tenant, attempts the
  // mass-assignment ESCALATION LADDER where write-capable, and lands proven
  // violations as CONFIRMED findings with report-ready evidence bundles (control +
  // violation raw HTTP pairs; observation vs inference vs impact labeled).
  // Scope-gated fail-closed like runComposedChain; path-prefix confined; ghost-gated;
  // paced; every request charged to the noise budget. Writes/deletes require the
  // countersigned exploit window (caller's responsibility — the auto-run fires from
  // the gated exploit phase only). Never throws into the campaign.
  async runAuthzSweep({ base, writes, deletes } = {}) {
    const cfg = this.authz;
    if (!cfg) { this._log('authz.skip', { reason: 'no-config' }); return { ok: false, error: 'no authz config — two provisioned accounts required (launch option authz.accounts)' }; }
    // Base resolution: explicit call arg, then the config's pinned base (account-bound
    // host), then recon-derived web bases. 2026-08-30 lesson: a live launch whose
    // reconOpts carry no ports leaves _webBases() EMPTY — the skip must be LOUD
    // (activity + surface note), never a silent no-op of a gated capability.
    const target = base || cfg.base || this._webBases()[0];
    if (!target) {
      this._log('authz.skip', { reason: 'no-web-base', note: 'reconOpts carried no web ports and authz.base is unset — set authz.base or reconOpts.webPorts' });
      this.surface.note('exploit', 'authzsweep SKIPPED: no web base known (set authz.base or reconOpts.webPorts) — the oracle did NOT run');
      this._onSurface();
      return { ok: false, error: 'no web base known for the engagement — recon has not surfaced one' };
    }
    let host = '';
    try { host = new URL(target).hostname; } catch { this._log('authz.skip', { reason: 'unparseable-base', target }); return { ok: false, error: 'unparseable base URL' }; }
    // Scope gate, fail-closed (identical doctrine to runComposedChain/validateFinding).
    const asIp = parseIp(host);
    const inScope = asIp
      ? inAnyCidr(asIp.text, this.scope.cidrs || [])
      : [...this.surface.nodes.values()].some((n) => (n.type === 'host' || n.type === 'subdomain') && (n.label === host || n.ip === host));
    if (!inScope) { this._log('authz.refused', { target, reason: 'out-of-scope' }); return { ok: false, error: `refused: ${host} is outside the signed scope (fail-closed)` }; }
    // Ghost gate, fail-closed: 'required' mode refuses public egress until the chain verifies.
    if (this.ghost) {
      try { await this.ghost.assertEgress(target); }
      catch (e) {
        if (e && e.ghostRefused) { this._log('ghost.refused', { url: target, note: 'identity chain unverified — authz sweep skipped (fail-closed)' }); return { ok: false, error: 'ghost: identity chain unverified (fail-closed)' }; }
        throw e;
      }
    }
    // Session provisioning: cookie verbatim, or the account's login recipe (paced, charged).
    // Up to FOUR accounts (the 4-role matrix); the write/delete/ladder rungs stay on the
    // first pair. The optional role label rides the session into the evidence trail.
    const sessions = [];
    for (const acct of cfg.accounts) {
      if (this.pacer) await this.pacer.pace();
      let resolved = acct;
      // Broker seam (Tool 1): a sessionRef account's cookie is NOT static config — it is
      // resolved live through the session broker (canary probe → refresh → relogin
      // ladder), riding the same ghost agents + attestation headers as the sweep itself.
      // A dead/unverifiable session is reported honestly and fails the sweep closed.
      if (acct.sessionRef) {
        const ref = String(acct.sessionRef);
        const ci = ref.indexOf(':');
        const prog = ci > 0 ? ref.slice(0, ci) : ref;
        const lbl = ci > 0 ? ref.slice(ci + 1) : '';
        const brokerGet = (this.sessionBroker && this.sessionBroker.getLiveSessionImpl) || getLiveSession;
        const br = await brokerGet(prog, lbl, {
          dir: this.sessionBroker && this.sessionBroker.dir,
          allowSpawn: !!(this.sessionBroker && this.sessionBroker.allowSpawn),
          probe: defaultProbe({ agents: this._bridgedAgents(), extraHeaders: this.extraHeaders })
        });
        if (!br || !br.ok) {
          this._log('authz.session-dead', { account: acct.label, sessionRef: ref, error: br && br.error, reason: br && br.reason });
          return { ok: false, error: `authz: session "${ref}" for account "${acct.label}" is ${br && br.error === 'session-unknown' ? 'unverifiable' : 'dead'}${br && br.reason ? ` (${br.reason})` : ''} — re-authenticate and re-broker it` };
        }
        this._log('authz.session', { account: acct.label, sessionRef: ref, state: br.state, refreshedAt: br.session.refreshedAt || null });
        resolved = { ...acct, cookie: br.session.cookie, headers: br.session.headers || acct.headers };
      }
      const s = await provisionSession(target, resolved, { extraHeaders: this.extraHeaders });
      if (acct.login) this._noise({ kind: 'http-fingerprint', host });
      if (!s) { this._log('authz.error', { account: acct.label, error: 'session provisioning failed' }); return { ok: false, error: `authz: could not provision a session for account "${acct.label}"` }; }
      sessions.push({ ...s, role: acct.role || null });
    }
    // Harvest pass: GET every known surface endpoint with EVERY provisioned session (the
    // "both sessions' traffic" the spec harvests from, generalized to the 4-role matrix —
    // refs per session letter fill the cross-product replay). Read-only; paced; charged.
    const agents = this.ghost ? this.ghost.agents() : null;
    const eps = [...this.surface.nodes.values()].filter((n) => n.type === 'endpoint').map((n) => n.label).slice(0, cfg.maxEndpoints);
    const exchanges = [];
    for (const path of eps) {
      for (let i = 0; i < sessions.length; i++) {
        const ex = await fetchExchange(target, path, {
          session: String.fromCharCode(97 + i), cookie: sessions[i].cookie, authHeaders: sessions[i].headers,
          pacer: this.pacer, extraHeaders: this.extraHeaders, pathPrefixes: this.pathPrefixes, agents,
        });
        this._noise({ kind: 'http-fingerprint', host });
        if (ex) exchanges.push(ex);
        else if (this.pathPrefixes && !pathPrefixAllowed(String(path).split('?')[0], this.pathPrefixes)) this._log('scope.path.refused', { tool: 'authzsweep-harvest', host, refused: 1, sample: [path], prefixes: this.pathPrefixes });
      }
    }
    const harvested = harvestExchanges(exchanges);
    const candidates = synthesizeCandidates(harvested, cfg.templates);
    // Coverage gate: the oracle EXERCISED every surface endpoint it harvested (read
    // under every provisioned session), and every configured/harvested object-id
    // template it replayed. Queue the templates first (configured templates may never
    // have passed through surface.endpoint).
    for (const path of eps) this._covMark(path, 'oracle', 'authz harvest: read under every provisioned session');
    for (const t of cfg.templates) this.coverage.queue({ kind: 'object-id', key: String(t.path), host, source: 'authz-config' });
    const doWrites = writes !== undefined ? !!writes : cfg.writes;
    const doDeletes = deletes !== undefined ? !!deletes : cfg.deletes;
    const res = await authzSweep(target, {
      sessions, candidates,
      writes: doWrites, deletes: doDeletes && doWrites, escalate: cfg.escalate, ladder: cfg.ladder,
      pacer: this.pacer, extraHeaders: this.extraHeaders, pathPrefixes: this.pathPrefixes, agents,
      onRequest: (r) => {
        // Victim-object seeding charges the SEPARATE budget.tools bucket, never the step
        // counter (house rule stands too: every governed request still counts noise).
        if (r.seed) this._toolCharge('authz-seed', 1);
        this._noise({ kind: r.write ? 'exploit-attempt' : 'http-fingerprint', host, authorized: !!r.write });
      },
      onLog: (obj) => { if (obj && obj.type) this._log(obj.type, obj); }, // authz.seed events land on the record
    });
    if (!res.ok) { this._log('authz.error', { error: res.error }); return res; }
    // Coverage: a candidate template counts as exercised ONLY when the differential
    // actually fired requests at it (pairs non-empty) — an inconclusive-no-refs
    // candidate stays on the untested ledger, honestly.
    for (const r0 of res.results) if (r0 && r0.template && Array.isArray(r0.pairs) && r0.pairs.length) this._covMark(r0.template, 'oracle', 'authz differential replay');
    if (res.refusals.length) this._log('scope.path.refused', { tool: 'authzsweep', host, refused: res.refusals.length, sample: res.refusals.slice(0, 8).map((r) => r.path), prefixes: this.pathPrefixes });

    // Proven violations land as CONFIRMED findings — the evidence cites the differential
    // control + readback by name, so the validator gate's objective-oracle rule passes.
    const hid = ([...this.surface.nodes.values()].find((n) => n.type === 'host' && (n.ip === host || n.label === host)) || {}).id || this.surface.root;
    const FILED = {
      idor: { sev: 'high', title: 'IDOR: cross-tenant object read', evidence: 'differential oracle (authzsweep): cross-tenant GET returned 200 with tenant-distinct content while the unauth control was refused; baseline + control recorded' },
      'idor-write': { sev: 'high', title: 'IDOR: cross-tenant object write', evidence: 'differential oracle (authzsweep): cross-tenant write PERSISTED — the canary was read back from the victim session while the unauth control write was refused; reverted best-effort' },
      'idor-delete': { sev: 'crit', title: 'IDOR: cross-tenant object delete', evidence: 'differential oracle (authzsweep): cross-tenant DELETE removed the object (victim-side readback 404) while the unauth control was refused' },
      'mass-assignment': { sev: 'crit', title: 'Mass assignment: privilege field persists', evidence: 'differential oracle (authzsweep): the extra body parameter persisted in the after read-back while before/control read-backs stayed clean — server binds unlisted fields' },
      'unauth-write': { sev: 'crit', title: 'Missing authentication on object write', evidence: 'differential oracle (authzsweep): the UNAUTHENTICATED control write persisted the canary — no auth at all, a distinct worse verdict' },
      'unauth-delete': { sev: 'crit', title: 'Missing authentication on object delete', evidence: 'differential oracle (authzsweep): the UNAUTHENTICATED control delete succeeded — no auth at all, a distinct worse verdict' },
    };
    let filed = 0;
    for (const r of res.results) {
      const verdicts = [
        r.read && r.read.verdict === 'idor' ? 'idor' : null,
        r.write && ['idor-write', 'unauth-write'].includes(r.write.verdict) ? r.write.verdict : null,
        r.delete && ['idor-delete', 'unauth-delete'].includes(r.delete.verdict) ? r.delete.verdict : null,
        ...r.ladder.filter((s) => s.verdict === 'mass-assignment').map(() => 'mass-assignment'),
      ].filter(Boolean);
      for (const v of verdicts) {
        const f = FILED[v];
        const ladderParam = v === 'mass-assignment' ? (r.ladder.find((s) => s.verdict === 'mass-assignment') || {}).param : null;
        const fid = this.surface.finding(hid, {
          title: `${f.title} — ${r.template}${ladderParam ? ` (${ladderParam})` : ''}`,
          sev: f.sev, ref: `authzsweep:${r.template}#${v}`, confidence: 'confirmed',
          evidence: f.evidence + ` | observation/inference/impact + raw HTTP pairs in the authz.sweep evidence bundle (${r.pairs.length} pairs)`,
        });
        const n = this.surface.nodes.get(fid);
        if (n) n.authz = { verdict: v, template: r.template, param: ladderParam || undefined, bundle: { observation: r.observation, inference: r.inference, impact: r.impact, pairs: r.pairs } };
        this._log('finding', { title: f.title, sev: f.sev, ref: `authzsweep:${r.template}#${v}` });
        filed++;
      }
    }
    this.authzSweepResult = res;
    this._log('authz.sweep', {
      candidates: res.summary.candidates, violations: res.summary.violations, filed,
      requests: res.summary.requests, verdicts: res.summary.verdicts,
      modes: res.summary.modes, accounts: res.summary.accounts,
    });
    this.surface.note('exploit', `authzsweep: ${res.summary.candidates} template(s), ${res.summary.violations} proven violation(s), ${filed} finding(s) filed (${res.summary.requests} governed requests)`);
    this._onSurface();
    return res;
  }

  // ——— Build 3 lane (2026-08-31): target scoring / ROI layer ———

  // Score every in-scope host for expected yield from the data recon ALREADY
  // gathered (tools/targetscore.mjs — deterministic, no I/O, no LLM call). Scores
  // land ON the host nodes (persisted with the surface, rendered by the report's
  // "Target scoring" section) and the rollup's `scores` map lets downstream lanes
  // order their per-host tool budgets score-descending. REORDERS ONLY — no host
  // is skipped, hidden, or refused differently because of its score. Default ON
  // under tooledRecon; kill: launch option targetScore:false. Never throws.
  runTargetScoring() {
    if (!this.targetScoreEnabled) { this._log('targetscore.skip', { reason: 'not-enabled', note: 'launch option targetScore:true (default ON under tooledRecon) scores in-scope hosts for expected yield — reorders per-host tool budgets, never skips or hides a host' }); return { ok: false, skipped: 'not-enabled' }; }
    const scored = scoreSurface(this.surface);
    if (!scored.hosts.length) {
      this._log('targetscore.skip', { reason: 'no-hosts', note: 'no host nodes on the surface yet — nothing to score' });
      this.surface.note('recon', 'target scoring SKIPPED: no hosts on the surface yet');
      this._onSurface();
      return { ok: false, skipped: 'no-hosts' };
    }
    const at = new Date().toISOString();
    for (const h of scored.hosts) {
      const n = this.surface.nodes.get(h.hid);
      if (n) n.targetScore = { score: h.score, reasons: h.reasons, classes: h.classes, at };
    }
    this.targetScoreRollup = {
      at, ordered: scored.ordered, scores: scored.scores,
      hosts: scored.hosts.map((h) => ({ host: h.host, score: h.score, classes: h.classes, reasons: h.reasons })),
    };
    const top = scored.hosts[0], bottom = scored.hosts[scored.hosts.length - 1];
    this._log('targetscore.scored', { hosts: scored.hosts.length, top: { host: top.host, score: top.score, classes: top.classes }, bottom: { host: bottom.host, score: bottom.score } });
    this.surface.note('recon', `target scoring: ${scored.hosts.length} host(s) scored for expected yield — top: ${top.host} (${top.score}/100${top.classes.length ? ', ' + top.classes.join('/') : ''}), bottom: ${bottom.host} (${bottom.score}/100); downstream per-host tool budgets order by score descending (reorder ONLY — no host skipped or hidden)`);
    this._onSurface();
    return { ok: true, hosts: scored.hosts.length, ordered: scored.ordered };
  }

  // Score lookup for budget ordering — 0 when the layer hasn't run (no reorder).
  _hostScore(host) {
    const s = this.targetScoreRollup && this.targetScoreRollup.scores;
    if (!s) return 0;
    const v = s[String(host || '').toLowerCase()];
    return Number.isFinite(v) ? v : 0;
  }
  _scoreOfEndpoint(ep) {
    const e = this.surface.edges.find((x) => x.kind === 'exposes' && x.to === ep.id);
    const hn = e ? this.surface.nodes.get(e.from) : null;
    return hn ? this._hostScore(hn.ip || hn.label) : 0;
  }

  // ——— Build 2 lanes (2026-08-30 hunting-tools wiring) ———

  // Recon-phase lane (launch option jsminer:true, default OFF): mine in-scope web
  // bases' JS + sourcemaps for hidden endpoints and secrets. Harvested endpoints land
  // as ENDPOINT NODES — the authz oracle's harvest pass then sees them, which is how
  // oracle candidates appear. Secrets file as findings ONLY when the opt-in live-use
  // verifier (jsminerVerify:true) graduates them; unverified candidates are surface
  // NOTES, never findings. Ghost agents bridged at the seam, paced, path-prefix
  // confined, killfast-budgeted against budget.tools. Dormant = logged jsminer.skip.
  async runJsMiner() {
    if (!this.jsminer) { this._log('jsminer.skip', { reason: 'not-enabled', note: 'launch option jsminer:true mines in-scope JS/sourcemaps for hidden endpoints + secrets' }); return { ok: false, skipped: 'not-enabled' }; }
    const bases = [...new Set([...this._reconWebBases, ...this._webBases()])];
    if (!bases.length) {
      this._log('jsminer.skip', { reason: 'no-web-base', note: 'no http(s) service discovered and reconOpts carry no web ports — the miner did NOT run' });
      this.surface.note('recon', 'jsminer SKIPPED: no web base known — the JS/sourcemap pass did NOT run');
      this._onSurface();
      return { ok: false, skipped: 'no-web-base' };
    }
    if (!this._toolBudgetOk()) { this._log('jsminer.skip', { reason: 'tools-budget-exhausted' }); return { ok: false, skipped: 'tools-budget-exhausted' }; }
    const rollup = { bases: 0, endpoints: 0, secrets: 0, verified: 0, findings: 0, stopped: null };
    for (const base of bases.slice(0, 4)) {
      let host = '';
      try { host = new URL(base).hostname; } catch { continue; }
      // Scope gate, fail-closed (identical doctrine to runAuthzSweep).
      const asIp = parseIp(host);
      const inScope = asIp
        ? inAnyCidr(asIp.text, this.scope.cidrs || [])
        : [...this.surface.nodes.values()].some((n) => (n.type === 'host' || n.type === 'subdomain') && (n.label === host || n.ip === host));
      if (!inScope) { this._log('jsminer.refused', { base, reason: 'out-of-scope' }); continue; }
      if (this.ghost) {
        try { await this.ghost.assertEgress(base); }
        catch (e) { if (e && e.ghostRefused) { this._log('ghost.refused', { url: base, note: 'identity chain unverified — jsminer skipped for this base (fail-closed)' }); continue; } throw e; }
      }
      const hid = ([...this.surface.nodes.values()].find((n) => n.type === 'host' && (n.ip === host || n.label === host)) || {}).id || this._firstHostId();
      const res = await this._killfast('jsminer', ({ budget, onLog }) => jsMine(base, {
        agents: this._bridgedAgents(), pacer: this.pacer, scope: { hosts: [host] },
        pathPrefixes: this.pathPrefixes, budget, onLog,
        verify: this.jsminerVerify === true, verifyEndpoints: this.jsminerVerifyEndpoints || undefined,
        extraHeaders: this.extraHeaders || undefined,
      }), { maxCalls: 40, maxMs: 300000 });
      if (!res) continue;
      if (res.stopped) rollup.stopped = 'killfast';
      if (!res.ok) { this._log('jsminer.error', { base, error: res.error || 'mine failed' }); continue; }
      rollup.bases++;
      this._noise({ kind: 'http-fingerprint', host, count: Math.max(1, (res.budget && res.budget.used) || 1) });
      if (res.refusals && res.refusals.length) this._log('scope.path.refused', { tool: 'jsminer', host, refused: res.refusals.length, sample: res.refusals.slice(0, 8).map((r) => r.url || r.path), prefixes: this.pathPrefixes });
      for (const p of res.endpoints.paths) {
        if (typeof p !== 'string' || !p.startsWith('/')) continue;
        // Keep the query string when it carries a param assignment — a mined
        // '/api/search?q=' IS a parameterized endpoint, and the OOB lane's filter
        // needs to see the '?q=' form (Build 2 fix: it used to be stripped).
        const label = /\?[^=]*=/.test(p) ? p : p.split('?')[0];
        this.surface.endpoint(hid, label, 'GET'); // endpoint nodes feed the authz harvest pass
        rollup.endpoints++;
      }
      const unverified = res.secrets.filter((s) => s.status !== 'verified');
      rollup.secrets += res.secrets.length;
      if (unverified.length) this.surface.note('recon', `jsminer: ${unverified.length} UNVERIFIED secret candidate(s) in client-side JS (${unverified.slice(0, 6).map((s) => `${s.type}:${s.redacted}`).join(', ')}) — candidates, NOT findings; live-use verification is opt-in (jsminerVerify:true)`);
      for (const sec of res.secrets.filter((s) => s.status === 'verified')) {
        const verdict = (res.verification.results || []).find((v) => v.type === sec.type && v.verified);
        const fid = this.surface.finding(hid, {
          title: `Verified ${sec.type} exposed in client-side JS (${sec.redacted})`,
          sev: 'high', ref: `jsminer:${sec.type}:${sec.redacted}`, confidence: 'confirmed',
          evidence: `live-use oracle (jsminer verifySecret): ${(verdict && verdict.detail) || 'verified by live use'} — extracted from ${sec.foundIn || base}, graduated by the verification differential`,
        });
        const n = this.surface.nodes.get(fid);
        if (n) n.jsminer = { type: sec.type, redacted: sec.redacted, foundIn: sec.foundIn || null, verdict: verdict || null };
        this._log('finding', { title: `Verified ${sec.type} in client-side JS`, sev: 'high', ref: `jsminer:${sec.type}:${sec.redacted}` });
        rollup.verified++; rollup.findings++;
      }
    }
    this.jsminerResult = rollup;
    this._log('jsminer.done', rollup);
    this.surface.note('recon', `jsminer: ${rollup.bases} base(s) mined, ${rollup.endpoints} endpoint(s) surfaced, ${rollup.secrets} secret candidate(s), ${rollup.verified} verified${rollup.stopped ? ' — STOPPED by the killfast budget (partial, honest)' : ''}`);
    this._onSurface();
    return { ok: true, ...rollup };
  }

  // Build the oobProbe inject spec for a surface endpoint label: query endpoints
  // inject the FIRST query param; {id} templates inject the path segment.
  _oobInject(label) {
    const s = String(label || '');
    if (s.includes('{id}')) return { method: 'GET', path: s.replace('{id}', '{PAYLOAD}') };
    const qi = s.indexOf('?');
    if (qi < 0) return null;
    const parts = s.slice(qi + 1).split('&').filter(Boolean);
    const first = parts.find((p) => p.includes('='));
    if (!first) return null;
    const key = first.split('=')[0];
    if (!key) return null;
    const rest = parts.filter((p) => p !== first);
    return { method: 'GET', path: s.slice(0, qi) + '?' + key + '={PAYLOAD}' + (rest.length ? '&' + rest.join('&') : '') };
  }

  // Exploit-phase lane (launch option oob:{publicBaseUrl, adminToken}): blind-class
  // probes (SSRF/SSTI/XXE/blind-XSS) against harvested parameterized endpoints, each
  // carrying a crypto-random canary. Verdict 'proven' ONLY on a canary-correlated
  // callback — proven verdicts file as CONFIRMED findings (ssrf high, ssti crit,
  // xxe high, blind-xss med) with the canary journal attached. NO CALLBACK = ZERO
  // FINDINGS, and the surface note says the pass ran and proved nothing.
  async runOobPass() {
    if (!this.oob) { this._log('oob.skip', { reason: 'not-enabled', note: 'launch option oob:{publicBaseUrl, adminToken} enables OOB callback-correlation probes for the blind classes (SSRF/SSTI/XXE/blind-XSS)' }); return { ok: false, skipped: 'not-enabled' }; }
    if (!this.oob.publicBaseUrl) {
      this._log('oob.skip', { reason: 'publicBaseUrl-unset', note: 'OOB callbacks need an operator-provided publicly reachable base — a canary nobody can dial proves nothing' });
      this.surface.note('exploit', 'OOB pass SKIPPED: oob.publicBaseUrl unset — canary URLs would be undialable; no probes fired');
      this._onSurface();
      return { ok: false, skipped: 'publicBaseUrl-unset' };
    }
    let eps = [...this.surface.nodes.values()].filter((n) => n.type === 'endpoint' && /(\?[^=]*=)|\{id\}/.test(n.label));
    // Build 3: spend the probe budget on the softest, highest-value hosts FIRST
    // (score-descending when the ROI layer ran — reorder only; the same endpoints
    // all remain eligible, the cap just favors the soft hosts).
    if (this.targetScoreRollup) eps.sort((a, b) => this._scoreOfEndpoint(b) - this._scoreOfEndpoint(a));
    eps = eps.slice(0, 8);
    if (!eps.length) {
      this._log('oob.skip', { reason: 'no-parameterized-endpoints' });
      this.surface.note('exploit', 'OOB pass SKIPPED: recon surfaced no parameterized endpoints (query string or {id} template) — nothing to inject');
      this._onSurface();
      return { ok: false, skipped: 'no-parameterized-endpoints' };
    }
    if (!this._toolBudgetOk()) { this._log('oob.skip', { reason: 'tools-budget-exhausted' }); return { ok: false, skipped: 'tools-budget-exhausted' }; }
    const SEV = { ssrf: 'high', ssti: 'crit', xxe: 'high', 'blind-xss': 'med' };
    const kinds = (this.oob.kinds && this.oob.kinds.length ? this.oob.kinds : ['ssrf', 'ssti', 'xxe', 'blind-xss']).filter((k) => SEV[k]);
    let server = null;
    try {
      server = new OobServer({ host: '0.0.0.0', port: 0, publicBaseUrl: this.oob.publicBaseUrl, authToken: this.oob.adminToken || undefined, onLog: (obj) => { if (obj && obj.type) this._log(obj.type, obj); } });
      await server.start();
      // LAB SEAM ('auto'): bind the canary base to the loopback listener we just
      // started — test/lab only, honestly logged; production passes the real public base.
      if (this.oob.publicBaseUrl === 'auto') {
        server.publicBaseUrl = server.localUrl();
        this._log('oob.listener', { publicBaseUrl: server.localUrl(), note: "publicBaseUrl:'auto' — loopback LAB binding, not reachable by a real target; production must set the operator's public base" });
      }
    } catch (e) {
      this._log('oob.skip', { reason: 'listener-failed', error: String((e && e.message) || e) });
      this.surface.note('exploit', 'OOB pass SKIPPED: the callback listener failed to start — ' + String((e && e.message) || e));
      this._onSurface();
      return { ok: false, skipped: 'listener-failed' };
    }
    const rollup = { endpoints: 0, probes: 0, proven: 0, stopped: null };
    try {
      for (const ep of eps) {
        const edge = this.surface.edges.find((e) => e.kind === 'exposes' && e.to === ep.id);
        const hostNode = edge ? this.surface.nodes.get(edge.from) : null;
        const host = hostNode ? (hostNode.ip || hostNode.label) : null;
        if (!host) continue;
        const svc = [...this.surface.nodes.values()].find((n) => n.type === 'service' && n.host === hostNode.id && /^(https?):(\d+)$/.test(n.label));
        const svcM = svc ? /^(https?):(\d+)$/.exec(svc.label) : null;
        const base = svcM ? `${svcM[1]}://${host}:${svcM[2]}` : `http://${host}`;
        const inject = this._oobInject(ep.label);
        if (!inject) continue;
        // Scope gate, fail-closed (identical doctrine to runAuthzSweep).
        const asIp = parseIp(host);
        const inScope = asIp
          ? inAnyCidr(asIp.text, this.scope.cidrs || [])
          : [...this.surface.nodes.values()].some((n) => (n.type === 'host' || n.type === 'subdomain') && (n.label === host || n.ip === host));
        if (!inScope) { this._log('oob.refused', { endpoint: ep.label, host, reason: 'out-of-scope' }); continue; }
        if (this.ghost) {
          try { await this.ghost.assertEgress(base); }
          catch (e) { if (e && e.ghostRefused) { this._log('ghost.refused', { url: base, note: 'identity chain unverified — OOB probe skipped for this endpoint (fail-closed)' }); continue; } throw e; }
        }
        const hid = hostNode.id;
        const res = await this._killfast('oob', ({ budget, onLog }) => oobProbe(base, {
          inject, kinds, server,
          agents: this._bridgedAgents(), pacer: this.pacer, scope: { hosts: [host] },
          pathPrefixes: this.pathPrefixes, budget, onLog,
          ...(this.oob.deadlineMs ? { deadlineMs: this.oob.deadlineMs } : {}),
        }), { maxCalls: 24, maxMs: 300000 });
        if (!res) continue;
        if (res.stopped) rollup.stopped = 'killfast';
        if (!res.ok) { this._log('oob.error', { endpoint: ep.label, error: res.error || 'probe failed' }); continue; }
        this._covMark(ep.label, 'oob', `OOB probes fired (${(res.probes || []).length} payload(s))`);
        rollup.endpoints++;
        rollup.probes += (res.probes || []).length;
        this._noise({ kind: 'exploit-attempt', host, count: Math.max(1, (res.budget && res.budget.used) || 1), authorized: true });
        for (const f of res.findings || []) {
          if (f.verdict !== 'proven') continue; // the oracle: no callback, no finding
          const fid = this.surface.finding(hid, {
            title: `${f.kind.toUpperCase()} proven by out-of-band callback — ${ep.label}`,
            sev: SEV[f.kind] || 'med', ref: `oob:${f.kind}:${f.canary}`, confidence: 'confirmed',
            evidence: `out-of-band oracle (oob): ${f.detail}; canary ${f.canary} correlated to the fired probe — canary→payload→request journal attached${f.callback ? `; callback ${f.callback.method} ${f.callback.path} from ${f.callback.remoteAddr}` : ''}`,
          });
          const n = this.surface.nodes.get(fid);
          if (n) n.oob = { kind: f.kind, canary: f.canary, payload: f.payload, request: f.request, response: f.response, callback: f.callback };
          this._log('finding', { title: `${f.kind.toUpperCase()} proven by OOB callback`, sev: SEV[f.kind] || 'med', ref: `oob:${f.kind}:${f.canary}` });
          rollup.proven++;
        }
      }
      this.surface.note('exploit', rollup.proven
        ? `OOB pass: ${rollup.proven} PROVEN blind-class finding(s) from ${rollup.probes} probe(s) across ${rollup.endpoints} endpoint(s) (canary-correlated callbacks)`
        : `OOB pass ran and PROVED NOTHING: ${rollup.probes} probe(s) across ${rollup.endpoints} parameterized endpoint(s), zero canary-correlated callbacks — no callback, no finding${rollup.stopped ? ' (stopped early by killfast)' : ''}`);
    } finally { try { await server.close(); } catch { /* listener teardown is best-effort */ } }
    this.oobResult = rollup;
    this._log('oob.done', rollup);
    this._onSurface();
    return { ok: true, ...rollup };
  }

  // Exploit-phase lane (launch option browseragent:true): the ghost-proxied DOM-XSS
  // canary over the reflected params recon surfaced (GET forms / query params). A
  // probe graduates to 'proven' ONLY on execution (window.__varvelCanary readback or
  // a marker callback) — reflection alone is 'unproven' and emits ZERO findings.
  async runBrowserPass() {
    if (!this.browseragent) { this._log('browseragent.skip', { reason: 'not-enabled', note: 'launch option browseragent:true enables the ghost-proxied DOM-XSS canary over reflected params' }); return { ok: false, skipped: 'not-enabled' }; }
    const targets = this._reflectedParams.slice(0, 8);
    if (!targets.length) {
      this._log('browseragent.skip', { reason: 'no-reflected-params' });
      this.surface.note('exploit', 'DOM-XSS canary SKIPPED: recon surfaced no reflected params (GET forms / query params) — nothing to canary');
      this._onSurface();
      return { ok: false, skipped: 'no-reflected-params' };
    }
    if (!this._toolBudgetOk()) { this._log('browseragent.skip', { reason: 'tools-budget-exhausted' }); return { ok: false, skipped: 'tools-budget-exhausted' }; }
    let driver = null;
    try {
      driver = this.browserDriverFactory
        ? await this.browserDriverFactory()
        : await playwrightDriverFactory({ profileDir: '.tmp/browseragent-profile' });
    } catch (e) {
      this._log('browseragent.skip', { reason: 'driver-unavailable', error: String((e && e.message) || e) });
      this.surface.note('exploit', 'DOM-XSS canary SKIPPED: browser driver unavailable — ' + String((e && e.message) || e));
      this._onSurface();
      return { ok: false, skipped: 'driver-unavailable' };
    }
    const rollup = { pages: 0, params: 0, proven: 0, stopped: null };
    try {
      const byPage = new Map();
      for (const t of targets) { if (!byPage.has(t.base)) byPage.set(t.base, []); byPage.get(t.base).push(t.param); }
      // Build 3: canary the softest, highest-value hosts FIRST when the ROI layer
      // ran (reorder only — same pages, same caps).
      const pages = [...byPage.entries()];
      if (this.targetScoreRollup) pages.sort((a, b) => { const hs = (p) => { try { return this._hostScore(new URL(p).hostname); } catch { return 0; } }; return hs(b[0]) - hs(a[0]); });
      for (const [page, params] of pages) {
        let host = '';
        try { host = new URL(page).hostname; } catch { continue; }
        // Scope gate, fail-closed (identical doctrine to runAuthzSweep).
        const asIp = parseIp(host);
        const inScope = asIp
          ? inAnyCidr(asIp.text, this.scope.cidrs || [])
          : [...this.surface.nodes.values()].some((n) => (n.type === 'host' || n.type === 'subdomain') && (n.label === host || n.ip === host));
        if (!inScope) { this._log('browseragent.refused', { page, reason: 'out-of-scope' }); continue; }
        if (this.ghost) {
          try { await this.ghost.assertEgress(page); }
          catch (e) { if (e && e.ghostRefused) { this._log('ghost.refused', { url: page, note: 'identity chain unverified — DOM-XSS canary skipped for this page (fail-closed)' }); continue; } throw e; }
        }
        const hid = ([...this.surface.nodes.values()].find((n) => n.type === 'host' && (n.ip === host || n.label === host)) || {}).id || this._firstHostId();
        const unique = [...new Set(params)];
        const res = await this._killfast('browseragent', ({ budget, onLog }) => domXssCanary(page, {
          params: unique, driver,
          scopeHosts: [host], pathPrefixes: this.pathPrefixes, budget, onLog,
        }), { maxCalls: 16, maxMs: 300000 });
        if (!res) continue;
        if (res.stopped) rollup.stopped = 'killfast';
        if (!res.ok) { this._log('browseragent.error', { page, error: res.error || 'canary pass failed' }); continue; }
        // Coverage: every param canaried on this page was exercised by the browser lane.
        try { const pn = new URL(page).pathname; for (const prm of unique) this._covMark(pn + '?' + prm + '=', 'browseragent', 'DOM-XSS canary fired'); } catch { /* bookkeeping never breaks the lane */ }
        rollup.pages++;
        rollup.params += (res.probes || []).length;
        for (const f of res.findings || []) {
          if (f.verdict !== 'proven') continue; // execution, not reflection
          const fid = this.surface.finding(hid, {
            title: `DOM-XSS: canary executed in page context — parameter '${f.param}'`,
            sev: 'med', ref: `domxss:${f.param}:${f.canary}`, confidence: 'confirmed',
            evidence: `browser oracle (browseragent): ${f.detail}; screenshot ${f.screenshot || 'unavailable'} + page console log attached`,
          });
          const n = this.surface.nodes.get(fid);
          if (n) n.domxss = { param: f.param, canary: f.canary, url: f.url, payload: f.payload, executedBy: f.executedBy, screenshot: f.screenshot, console: f.console };
          this._log('finding', { title: `DOM-XSS canary executed (${f.param})`, sev: 'med', ref: `domxss:${f.param}:${f.canary}` });
          rollup.proven++;
        }
      }
      this.surface.note('exploit', rollup.proven
        ? `DOM-XSS canary: ${rollup.proven} PROVEN execution(s) across ${rollup.pages} page(s) (${rollup.params} param(s) canaried)`
        : `DOM-XSS canary pass ran and PROVED NOTHING: ${rollup.params} param(s) canaried across ${rollup.pages} page(s), zero executions — reflection without execution is not a finding${rollup.stopped ? ' (stopped early by killfast)' : ''}`);
    } finally { if (driver && typeof driver.close === 'function') { try { await driver.close(); } catch { /* best-effort */ } } }
    this.browserResult = rollup;
    this._log('browseragent.done', rollup);
    this._onSurface();
    return { ok: true, ...rollup };
  }

  // ——— Build 3 lane (2026-08-31): AI/LLM attack surface ———

  // Exploit-phase lane (detection default ON, kill: aiSurface:false; active probes
  // armed ONLY by aiProbe:true). Detection is passive-ish: endpoint shapes recon
  // harvested (/ai, /llm, /copilot, /chat, /completions, /mcp, /sse) + one
  // /.well-known/ai-plugin.json read per web base, an OPTIONS banner, and a benign
  // JSON-RPC initialize/tools-list on MCP-shaped paths — all charged, all paced,
  // all on the record. Detection files NOTHING (an MCP server answering initialize
  // is an inventory fact, a surface note). When armed, probes are CANARY-PROOF
  // ONLY: a finding files CONFIRMED exclusively on an objective oracle — an OOB
  // callback the model's tool/fetch capability initiated (tools/oob.mjs), or the
  // cross-session differential (a FRESH session returns the canary planted in a
  // DIFFERENT session while the unseeded control answered clean). A model merely
  // complying with a naughty string is NEVER a finding. Rides budget.tools +
  // killfast (40 calls / 300s) like the other lanes; bases order score-descending
  // when the ROI layer ran. Dormant = a loud aisurface.skip with the reason.
  async runAiSurfacePass() {
    if (!this.aiSurfaceEnabled) { this._log('aisurface.skip', { reason: 'disabled', note: 'launch option aiSurface:false disables the AI/LLM attack-surface lane outright' }); return { ok: false, skipped: 'disabled' }; }
    // Candidates: harvested endpoints whose path shape smells like an AI surface,
    // grouped per host; every in-scope web base also earns the one-request
    // well-known manifest read (the highest-signal AI marker on a quiet host).
    const perHost = new Map(); // host -> { hostNode, base, paths: Set }
    const hintEps = [...this.surface.nodes.values()].filter((n) => n.type === 'endpoint' && aiHintKind(String(n.label).split('?')[0]));
    for (const ep of hintEps.slice(0, 32)) {
      const edge = this.surface.edges.find((e) => e.kind === 'exposes' && e.to === ep.id);
      const hostNode = edge ? this.surface.nodes.get(edge.from) : null;
      const host = hostNode ? (hostNode.ip || hostNode.label) : null;
      if (!host) continue;
      const svc = [...this.surface.nodes.values()].find((n) => n.type === 'service' && n.host === hostNode.id && /^(https?):(\d+)$/.test(n.label));
      const svcM = svc ? /^(https?):(\d+)$/.exec(svc.label) : null;
      const base = svcM ? `${svcM[1]}://${host}:${svcM[2]}` : `http://${host}`;
      if (!perHost.has(host)) perHost.set(host, { hostNode, base, paths: new Set() });
      perHost.get(host).paths.add(String(ep.label).split('?')[0]);
    }
    for (const base of [...new Set([...this._reconWebBases, ...this._webBases()])]) {
      let host = '';
      try { host = new URL(base).hostname; } catch { continue; }
      if (!perHost.has(host)) {
        const hostNode = [...this.surface.nodes.values()].find((n) => n.type === 'host' && (n.ip === host || n.label === host));
        perHost.set(host, { hostNode: hostNode || null, base, paths: new Set() });
      }
      perHost.get(host).paths.add('/.well-known/ai-plugin.json');
      this.coverage.queue({ kind: 'endpoint', key: '/.well-known/ai-plugin.json', host, source: 'aisurface' }); // the well-known read is queued AND exercised by this same lane
    }
    if (!perHost.size) {
      this._log('aisurface.skip', { reason: 'no-ai-hints', note: 'recon surfaced no AI-shaped endpoints and no web bases exist — the AI-surface lane did NOT run' });
      this.surface.note('exploit', 'AI-surface lane SKIPPED: no AI-shaped endpoints and no web bases — nothing to detect');
      this._onSurface();
      return { ok: false, skipped: 'no-ai-hints' };
    }
    if (!this._toolBudgetOk()) { this._log('aisurface.skip', { reason: 'tools-budget-exhausted' }); return { ok: false, skipped: 'tools-budget-exhausted' }; }
    // The OOB tool-exfil oracle leg reuses the launch's oob config (same listener
    // doctrine as runOobPass, including the 'auto' loopback LAB seam). Without it
    // the cross-session differential still runs and the gap is logged, not hidden.
    let server = null;
    if (this.aiProbe && this.oob && this.oob.publicBaseUrl) {
      try {
        server = new OobServer({ host: '0.0.0.0', port: 0, publicBaseUrl: this.oob.publicBaseUrl, authToken: this.oob.adminToken || undefined, onLog: (obj) => { if (obj && obj.type) this._log(obj.type, obj); } });
        await server.start();
        if (this.oob.publicBaseUrl === 'auto') {
          server.publicBaseUrl = server.localUrl();
          this._log('oob.listener', { publicBaseUrl: server.localUrl(), note: "publicBaseUrl:'auto' — loopback LAB binding for the AI tool-exfil oracle, not reachable by a real target; production must set the operator's public base" });
        }
      } catch (e) {
        this._log('aisurface.skip-oob', { reason: 'listener-failed', error: String((e && e.message) || e) });
        server = null;
      }
    } else if (this.aiProbe) {
      this._log('aisurface.skip-oob', { reason: 'oob-unconfigured', note: 'aiProbe armed but oob.publicBaseUrl unset — the OOB tool-exfil oracle leg is unavailable; the cross-session differential still runs' });
    }
    const rollup = { bases: 0, surfaces: 0, probes: 0, proven: 0, stopped: null };
    try {
      // Build 3: probe the softest, highest-value hosts FIRST when the ROI layer ran.
      const hosts = [...perHost.entries()];
      if (this.targetScoreRollup) hosts.sort((a, b) => this._hostScore(b[0]) - this._hostScore(a[0]));
      for (const [host, plan] of hosts) {
        // Scope gate, fail-closed (identical doctrine to runOobPass).
        const asIp = parseIp(host);
        const inScope = asIp
          ? inAnyCidr(asIp.text, this.scope.cidrs || [])
          : [...this.surface.nodes.values()].some((n) => (n.type === 'host' || n.type === 'subdomain') && (n.label === host || n.ip === host));
        if (!inScope) { this._log('aisurface.refused', { base: plan.base, reason: 'out-of-scope' }); continue; }
        if (this.ghost) {
          try { await this.ghost.assertEgress(plan.base); }
          catch (e) { if (e && e.ghostRefused) { this._log('ghost.refused', { url: plan.base, note: 'identity chain unverified — AI-surface pass skipped for this base (fail-closed)' }); continue; } throw e; }
        }
        const hid = (plan.hostNode && plan.hostNode.id) || this._firstHostId();
        const res = await this._killfast('aisurface', ({ budget, onLog }) => aiSurfacePass(plan.base, {
          endpoints: [...plan.paths], probe: this.aiProbe, server,
          agents: this._bridgedAgents(), pacer: this.pacer, scope: { hosts: [host] },
          pathPrefixes: this.pathPrefixes, budget, onLog,
          ...(this.oob && this.oob.deadlineMs ? { deadlineMs: this.oob.deadlineMs } : {}),
        }), { maxCalls: 40, maxMs: 300000 });
        if (!res) continue;
        if (res.stopped) rollup.stopped = 'killfast';
        if (!res.ok) { this._log('aisurface.error', { base: plan.base, error: res.error || 'pass failed' }); continue; }
        // Coverage: the detection/probe pass exercised every path it was handed.
        for (const p of plan.paths) this._covMark(p, 'aisurface', 'AI-surface detection/probe pass');
        rollup.bases++;
        rollup.probes += res.probes || 0;
        this._noise({ kind: 'exploit-attempt', host, count: Math.max(1, (res.budget && res.budget.used) || 1), authorized: true }); // inside the countersigned exploit window
        if (res.refusals && res.refusals.length) this._log('scope.path.refused', { tool: 'aisurface', host, refused: res.refusals.length, sample: res.refusals.slice(0, 8).map((r) => r.path || r.url), prefixes: this.pathPrefixes });
        // Detection lands as surface NOTES — an inventory fact, never a finding.
        const confirmedSurfaces = (res.surfaces || []).filter((s) => s.confirmed);
        rollup.surfaces += confirmedSurfaces.length;
        for (const s of confirmedSurfaces) this.surface.note('exploit', `AI surface detected on ${host}: ${s.path} [${s.kind}] — ${s.detail}`);
        for (const note of res.notes || []) this.surface.note('exploit', `aisurface (${host}): ${note}`);
        // Findings file CONFIRMED only when the oracle fired (verdict 'proven').
        const FILED = {
          'ai-cross-session-leak': { sev: 'high', title: 'AI cross-session secret leak' },
          'ai-oob-exfil': { sev: 'high', title: 'AI tool exfiltrates to an attacker URL (prompt injection → outbound fetch)' },
        };
        for (const f of res.findings || []) {
          if (f.verdict !== 'proven') continue; // no oracle, no finding — compliance is never a finding
          const meta = FILED[f.kind] || { sev: 'med', title: f.kind };
          const fid = this.surface.finding(hid, {
            title: `${meta.title} — ${f.request && f.request.url ? new URL(f.request.url).pathname : host}`,
            sev: meta.sev, ref: `aisurface:${f.kind}:${f.canary}`, confidence: 'confirmed',
            evidence: `${f.detail}${f.callback ? `; callback ${f.callback.method} ${f.callback.path} from ${f.callback.remoteAddr}` : ''} — canary journal attached`,
          });
          const n = this.surface.nodes.get(fid);
          if (n) n.aisurface = { kind: f.kind, canary: f.canary, request: f.request, response: f.response, callback: f.callback || null };
          this._log('finding', { title: meta.title, sev: meta.sev, ref: `aisurface:${f.kind}:${f.canary}` });
          rollup.proven++;
        }
      }
      this.surface.note('exploit', rollup.proven
        ? `AI-surface pass: ${rollup.proven} PROVEN AI-surface finding(s) from ${rollup.probes} canary-proof probe(s) across ${rollup.bases} base(s) (${rollup.surfaces} surface(s) detected)`
        : `AI-surface pass: ${rollup.surfaces} surface(s) detected as inventory notes, ${rollup.probes} canary-proof probe(s) fired, ZERO proven — no oracle fired, no finding${this.aiProbe ? '' : ' (active probes disarmed — aiProbe:true arms them)'}${rollup.stopped ? ' (stopped early by killfast)' : ''}`);
    } finally { if (server) { try { await server.close(); } catch { /* listener teardown is best-effort */ } } }
    this.aiSurfaceResult = rollup;
    this._log('aisurface.done', rollup);
    this._onSurface();
    return { ok: true, ...rollup };
  }

  // The validator gate's explicit reproduction pass: validate ONE finding, selected by
  // index into the surface's findings (insertion order) or by node id / ref. NEVER
  // auto-fired — the operator or the AI invokes it per finding (POST /api/validate).
  // v2 (the manhuaus doctrine): http-class findings get a PAIRED governed read via the
  // per-class oracle registry (engine/validator.mjs) — the real reproduction AND a
  // garbage-control, both paced, both ghost-riding, both charged to the noise budget,
  // both on the record (validation.requests). Verdict: signature present under real AND
  // absent under control => validated; present under BOTH => refuted 'hollow success
  // signature (control matched)'; absent under real => refuted. A failed read (real or
  // control) is untestable — no claim without a control. The result lands on the finding
  // as validation { state, oracle, at, class, marker, real, control, requests,
  // validatedAt? } — state stays the v1 vocabulary: validated | refuted | untestable.
  // REFUTED is a first-class outcome and flips confidence back to suspected (+note).
  async validateFinding(sel, { reReadImpl, timeout = 4000 } = {}) {
    const findings = [...this.surface.nodes.values()].filter((n) => n.type === 'finding');
    let f = null;
    if (typeof sel === 'number' && Number.isInteger(sel)) f = findings[sel] || null;
    else if (typeof sel === 'string') f = findings.find((n) => n.id === sel || n.ref === sel) || null;
    if (!f) { this._log('validate.error', { sel: String(sel), error: 'no such finding' }); return { ok: false, error: 'no such finding: ' + String(sel) }; }
    const settle = (state, oracle, extra = {}) => {
      f.validation = { state, oracle, at: new Date().toISOString(), ...extra };
      if (state === 'validated') f.validation.validatedAt = f.validation.at; // the staleness clock (render-only)
      if (state === 'refuted') { // the gate's whole point: a claimed finding that does NOT reproduce
        f.confidence = 'suspected';
        f.conf = Math.min(typeof f.conf === 'number' ? f.conf : 40, CONFIRM_AT - 1);
        (f.notes = f.notes || []).push('validator gate: refuted — ' + oracle);
      }
      this._log('validate', { finding: f.label, ref: f.ref || null, state, oracle, control: extra.control && extra.control.line ? extra.control.line : null });
      this.surface.note('validate', `${state}: ${f.label} — ${oracle}`);
      this._onSurface();
      const r = { ok: true, finding: f.label, ref: f.ref || null, state, oracle, at: f.validation.at };
      if (extra.class) r.class = extra.class;
      if (extra.marker) r.marker = extra.marker;
      if (extra.reason) r.reason = extra.reason;
      if (extra.control && extra.control.line) r.control = extra.control.line; // the control-read line
      if (f.validation.validatedAt) r.validatedAt = f.validation.validatedAt;
      if (extra.requests) r.requests = extra.requests;
      return r;
    };
    const url = validationUrl(f, this.surface);
    if (!url) return settle('untestable', UNTESTABLE_NOTE);
    let host = '';
    try { host = new URL(url).hostname; } catch { return settle('untestable', 'unparseable re-read URL — reproduce manually'); }
    // Scope gate, fail-closed: an IP must sit inside the signed CIDR ring; a hostname must
    // be one the engagement already surfaced as in-scope. Anything else is refused.
    const asIp = parseIp(host);
    const inScope = asIp
      ? inAnyCidr(asIp.text, this.scope.cidrs || [])
      : [...this.surface.nodes.values()].some((n) => (n.type === 'host' || n.type === 'subdomain') && (n.label === host || n.ip === host));
    if (!inScope) { this._log('validate.refused', { finding: f.label, url, reason: 'out-of-scope' }); return settle('untestable', `refused: ${host} is outside the signed scope (fail-closed)`); }
    // Path-prefix gate, fail-closed (same layer): with a path-scoped engagement the
    // re-read URL must sit under a signed prefix — refused + logged, never sent.
    if (this.pathPrefixes) {
      let upath = '/';
      try { upath = new URL(url).pathname; } catch { upath = '/'; }
      if (!pathPrefixAllowed(upath, this.pathPrefixes)) {
        this._log('validate.refused', { finding: f.label, url, reason: 'out-of-scope-path', prefixes: this.pathPrefixes });
        return settle('untestable', `refused: ${upath} is outside the signed path prefixes ${this.pathPrefixes.join(', ')} (fail-closed)`);
      }
    }
    // Ghost gate, fail-closed: in 'required' mode public egress is refused until the
    // identity chain verifies — the refusal is logged and NO request leaves.
    if (this.ghost) {
      try { await this.ghost.assertEgress(url); }
      catch (e) {
        if (e && e.ghostRefused) { this._log('ghost.refused', { url, note: 'identity chain unverified — validation re-read skipped (fail-closed)' }); return settle('untestable', 'ghost: identity chain unverified — public egress refused (fail-closed)'); }
        throw e;
      }
    }
    // The PAIRED read: real reproduction + garbage-control. Each request is paced, rides
    // the ghost chain, and is charged to the noise budget like any http fingerprint.
    const plan = planValidation(f, url);
    const read = reReadImpl || reRead;
    const agents = this.ghost ? this.ghost.agents() : null;
    const fire = async (target) => {
      if (this.pacer) await this.pacer.pace();
      const r = await read(target, { timeout, agents });
      this._noise({ kind: 'http-fingerprint', host });
      return r;
    };
    const rReal = await fire(plan.real);
    if (!rReal || !rReal.status) return settle('untestable', `re-read of ${plan.real} failed: ${String((rReal && rReal.error) || 'no response')} — reproduce manually`, { class: plan.class });
    const rCtrl = await fire(plan.control);
    if (!rCtrl || !rCtrl.status) {
      return settle('untestable', `control read of ${plan.control} failed: ${String((rCtrl && rCtrl.error) || 'no response')} — no claim without a control`, {
        class: plan.class, marker: plan.marker || undefined,
        requests: [{ phase: 'real', url: plan.real, status: rReal.status }],
      });
    }
    const v = verdictFor(plan, rReal, rCtrl);
    return settle(v.state, v.oracle, {
      class: plan.class,
      signature: plan.signature,
      marker: plan.marker || undefined,
      reason: v.reason || undefined,
      real: { url: plan.real, status: rReal.status, matched: v.real.hit },
      control: { url: plan.control, status: rCtrl.status, matched: v.control.hit, line: v.controlLine },
      requests: [ // the record shows both reads, honestly
        { phase: 'real', url: plan.real, status: rReal.status, matched: v.real.hit },
        { phase: 'control', url: plan.control, status: rCtrl.status, matched: v.control.hit },
      ],
    });
  }

  // Value-guided (LATS) path search before exploitation: concentrate on the highest-value,
  // quietest paths and hand the agent a focus list. NON-DESTRUCTIVE (GET/OPTIONS only) —
  // detonation stays the countersigned exploit phase. Never crashes the campaign.
  async guidedExploitPrep() {
    const bases = this._webBases();
    if (!bases.length) return null;
    const opsecCost = (d) => Math.min(1, Math.max(0, (String(d.path || '').split('/').filter(Boolean).length - 1) * 0.15)); // deeper crawl = a little noisier
    const priorLabels = (this.prior || []).map((f) => String(f.label || '')).filter(Boolean);
    const prior = (d) => (priorLabels.some((l) => l && String(d.path || '').includes(l)) ? 1 : 0);
    let res;
    try { res = await guidedWebSearch(bases[0], { opsecCost, prior, maxProbes: 60, timeout: 2000, agents: this.ghost ? this.ghost.agents() : null }); }
    catch (e) { this._log('phase.error', { phase: 'exploit', error: 'guided-search: ' + ((e && e.message) || e) }); return null; }
    if (!res || !res.activated) { this.guidedTrace = res ? { activated: false, probes: res.probes, reason: res.reason || null, trace: res.trace || [], best: [] } : null; this._log('guided.search', { activated: false, probes: res ? res.probes : 0 }); return res; }
    // Focus the exploit phase on ACTIONABLE targets first (a write surface or an auth wall
    // to bypass) ahead of already-exposed sensitive files, then by value.
    const ACT = { 'write-candidate': 3, 'auth-wall': 2, 'error-leak': 1 };
    const top = (res.top || []).slice().sort((a, b) => (ACT[b.cls] || 0) - (ACT[a.cls] || 0) || b.score - a.score).slice(0, 5);
    const hid = this._firstHostId();
    for (const s of top) { if (hid && s) this.surface.endpoint(hid, s.descriptor.path, s.descriptor.method || 'GET'); }
    this.exploitFocus = top.map((s) => ({ path: s.descriptor.path, cls: s.cls, score: s.score }));
    // Retain the full trace + best paths for the Task Tree panel (compact — descriptor
    // reduced to its display fields, scores rounded as the search already rounds them).
    this.guidedTrace = {
      activated: true, probes: res.probes,
      trace: (res.trace || []).map((t) => ({ depth: t.depth, path: t.descriptor && (t.descriptor.path || t.descriptor), method: t.descriptor && t.descriptor.method, cls: t.cls, score: t.score, pruned: !!t.pruned })),
      best: (res.best || []).map((p) => ({ score: Math.round(p.score * 100) / 100, depth: p.depth, terminal: p.terminal, path: (p.path || []).map((s) => ({ path: s.descriptor && (s.descriptor.path || s.descriptor), cls: s.cls, score: s.score })) })),
    };
    this._log('guided.search', { activated: true, probes: res.probes, top: this.exploitFocus.length });
    this.surface.note('exploit', `guided search · ${res.probes} probes · ${this.exploitFocus.length} focus path(s)`);
    return res;
  }

  async runPhase(phase, extraHint = '') {
    this.status = 'running:' + phase.id;
    this._log('phase.start', { phase: phase.id, gate: phase.gate });

    // Progression gate: nothing to exploit / post-ex on an empty finding set.
    if ((phase.id === 'exploit' || phase.id === 'postex') && this.surface.counts().confirmed === 0) {
      this._log('phase.skip', { phase: phase.id, reason: 'no confirmed findings to act on' });
      return { skipped: true };
    }
    // Budget BEFORE the HITL gate (don't prompt for a window we'd skip).
    if (this.budgetLeft() <= 0) {
      this.surface.note(phase.id, 'skipped — step budget exhausted');
      this._log('budget.exhausted', { phase: phase.id, maxSteps: this.budget.maxSteps });
      return { skipped: true };
    }
    if (phase.gate === 'sigil') {
      this._log('gate.request', { phase: phase.id });
      const ok = await this._approve(phase);
      this._log('gate.decision', { phase: phase.id, signed: ok });
      if (!ok) {
        this.surface.hold({ action: phase.id, rule: 'HITL-required', target: this.scope.engagement });
        this.opsec.observe({ holds: 1 });
        this.surface.note(phase.id, 'phase held — no countersigned approval');
        this._onSurface();
        return { held: true };
      }
    }

    if (phase.id === 'recon' && this.useTooledRecon && (this.targets.length || this.reconOpts.domain)) {
      try { await this.tooledRecon(); }
      catch (e) { this._log('phase.error', { phase: phase.id, error: 'tooled recon: ' + ((e && e.message) || e) }); }
      this._onSurface();
      return { tooled: true };
    }

    // Fireteam: fan out to parallel independent specialists for any decomposable phase
    // (recon/validate), not just recon. specialistsFor() returns [] when nothing decomposes.
    const ftSpecs = !this.useFireteam ? []
      : phase.id === 'recon' ? reconSpecialists(this.scope)  // recon keeps its dedicated specialists
      : phase.id === 'validate' ? specialistsFor(phase.objective, { scope: this.scope, surface: this.surface.toJSON() })
      : [];
    if (ftSpecs.length) {
      let results = [];
      try { results = await fireteam(this.runAgent, this.engine, ftSpecs); }
      catch (e) { this._log('phase.error', { phase: phase.id, error: 'fireteam: ' + ((e && e.message) || e) }); }
      // Wave summary for the Task Tree panel — per-member outcome, denials counted, errors named.
      this.waves.push({
        phase: phase.id, at: new Date().toISOString(),
        members: results.map((r) => ({ label: (r && r.label) || 'specialist', steps: nnum(r && r.steps), denials: Array.isArray(r && r.denials) ? r.denials.length : 0, error: (r && r.error) || null })),
      });
      let steps = 0;
      for (const r of results) {
        try {
          if (r && r.error) this._log('fireteam.error', { specialist: r.label, error: r.error });
          steps += nnum(r && r.steps);
          this._log('fireteam', { specialist: r && r.label });
          for (const d of Array.isArray(r && r.denials) ? r.denials : []) { this.surface.hold({ action: d, rule: 'enclave-denied', target: this.scope.engagement }); this.opsec.observe({ holds: 1 }); this._log('hold', { action: d, phase: phase.id }); this._fail('held', d, phase.id); }
          this._ingest(phase.id, parseJsonBlock(r && r.text));
        } catch (e) { this._log('phase.error', { phase: phase.id, error: 'fireteam-ingest: ' + ((e && e.message) || e) }); }
      }
      this.budget.usedSteps += steps;
      // Fireteam recon emits real scan traffic — charge it to the noise budget too, or the
      // after-action proof would UNDER-state noise (the exact gap we fault RedAmon's Fireteam for).
      if (phase.id === 'recon') this._noise({ kind: 'tcp-scan', count: Math.max(1, ftSpecs.length) });
      this.surface.note(phase.id, 'fireteam recon');
      this._onSurface();
      return { fireteam: true };
    }

    // Value-guided (LATS) path search before exploitation — concentrates the agent on
    // the highest-value, quietest paths. Non-destructive; detonation stays HITL-gated.
    if (phase.id === 'exploit' && this.guidedSearch && this.targets.length) {
      try { await this.guidedExploitPrep(); } catch (e) { this._log('phase.error', { phase: phase.id, error: 'guided-prep: ' + ((e && e.message) || e) }); }
      // chainforge: compile executable chains from the live surface (the deterministic brain).
      if (phase.id === 'exploit') this.compileChains();
    }
    // Build 1: the two-account authorization oracle runs its differential INSIDE the
    // countersigned exploit window (the sigil gate above already signed this phase).
    // Reads always; the write/delete/mass-assignment rungs follow the launch's authz
    // config. Runs once per campaign.
    if (phase.id === 'exploit' && this.authz && !this.authzSweepResult) {
      try { await this.runAuthzSweep(); } catch (e) { this._log('phase.error', { phase: 'exploit', error: 'authzsweep: ' + ((e && e.message) || e) }); }
    }
    // Build 2 (2026-08-30 hunting-tools wiring): the blind-class OOB callback-correlation
    // lane + the ghost-proxied DOM-XSS canary lane run inside the same countersigned
    // exploit window, under killfast hypothesis budgets against the separate
    // budget.tools bucket. Dormant lanes log *.skip with the reason — never silent.
    if (phase.id === 'exploit') {
      try { await this.runOobPass(); } catch (e) { this._log('phase.error', { phase: 'exploit', error: 'oob: ' + ((e && e.message) || e) }); }
      try { await this.runBrowserPass(); } catch (e) { this._log('phase.error', { phase: 'exploit', error: 'browseragent: ' + ((e && e.message) || e) }); }
      // Build 3: the AI/LLM attack-surface lane rides the same countersigned window.
      try { await this.runAiSurfacePass(); } catch (e) { this._log('phase.error', { phase: 'exploit', error: 'aisurface: ' + ((e && e.message) || e) }); }
    }
    // Concrete surface state + scope/workspace boundary — so the agent acts precisely
    // instead of blindly exploring into out-of-scope / workspace-escape denials.
    const briefNote = (phase.id === 'validate' || phase.id === 'exploit' || phase.id === 'postex') ? this._surfaceBriefing() : '';
    const priorNote = this.prior.length ? `\nPrior sessions already established: ${this.prior.map((f) => f.label).join('; ')}. Build on these; don't redo them.` : '';
    // EvoGraph-class failure memory: tell the agent what already failed so it doesn't repeat it.
    const failNote = this.priorFail.length ? `\nPrior sessions already FAILED these approaches — do NOT repeat them: ${this.priorFail.slice(-8).map((f) => `[${f.phase || '?'}] ${f.approach}`).join('; ')}.` : '';
    const base = this._webBases()[0] || '';
    const focusNote = (phase.id === 'exploit' && this.exploitFocus && this.exploitFocus.length)
      ? `\n[guided search] Highest-value targets the search ranked${base ? ` (base ${base})` : ''} — act here first, quietest first:\n`
        + this.exploitFocus.map((f) => `  ${f.path} — ${f.cls}${f.cls === 'write-candidate' ? ' → accepts writes: prove impact by sending a MINIMAL state-changing request (e.g. POST a small JSON body to change content), confirm the change with a GET, then REVERT it to the original value and record it as an artifact for cleanup' : ''}`).join('\n')
      : '';
    // chainforge: when the compiler produced executable chains from the live surface, hand the
    // agent the deterministic plan instead of leaving it to improvise.
    const forgeNote = (phase.id === 'exploit' && this.chainPlans && this.chainPlans.plans && this.chainPlans.plans.length)
      ? `\n[chainforge] The compiler produced ${this.chainPlans.plans.length} executable chain(s) from the surface evidence — prefer executing these (deterministic, evidence-backed, tested shape):\n`
        + this.chainPlans.plans.map((p) => `  ${p.rule} — ${p.title} [${p.confidence}]:\n` + p.steps.map((s) => `    ${s.id}: ${s.note || ''}`).join('\n')).join('\n')
      : '';
    // chaincompose v2: typed-primitive compositions from the validate phase. The agent is
    // told they exist and given the impact doctrine; deterministic execution is the
    // campaign's runComposedChain (chainrun v2, impact-asserted).
    const compNote = (phase.id === 'exploit' && this.composedChains && this.composedChains.chains && this.composedChains.chains.length)
      ? `\n[chains] The engine composed ${this.composedChains.chains.length} candidate chain(s) from your validated lows/meds (typed primitives — two lows composing into one high):\n`
        + this.composedChains.chains.map((c) => `  ${c.name} [${c.confidence}]:\n` + c.steps.map((s) => `    ${s.id}: ${s.note || ''}`).join('\n')).join('\n')
        + '\n  Execute a composed chain with `node tools/cli.mjs chainrun <chainFile.json>` (write the chain JSON to your workspace first). A chain is "proved" ONLY when its impact assertion passes — steps green with impact absent is a HOLLOW success: report result:"failed", never "proved".'
      : '';
    // Build 1: proven authorization violations from the two-account oracle ride the
    // exploit prompt — already filed + evidenced, so the agent references, not re-proves.
    const authzNote = (phase.id === 'exploit' && this.authzSweepResult && this.authzSweepResult.ok && this.authzSweepResult.summary.violations > 0)
      ? `\n[authzsweep] The two-account authorization oracle PROVED ${this.authzSweepResult.summary.violations} authorization violation(s) by differential replay (cross-tenant + unauth control, victim-side readbacks):\n`
        + Object.entries(this.authzSweepResult.summary.verdicts).filter(([, v]) => !['enforced', 'public', 'inconclusive'].includes(v)).map(([t, v]) => `  ${t} — ${v}`).join('\n')
        + '\n  Already filed as CONFIRMED findings with report-ready evidence bundles (raw HTTP pairs, observation/inference/impact labeled) — reference them in your report; do not re-prove them.'
      : '';
    // Agent Skills: inject the methodology playbooks relevant to this phase + surface.
    let skillNote = '';
    if (phase.id === 'validate' || phase.id === 'exploit') {
      const nodes = [...this.surface.nodes.values()];
      const sel = selectSkills(phase.objective, { findings: nodes.filter((n) => n.type === 'finding'), services: nodes.filter((n) => n.type === 'service'), endpoints: nodes.filter((n) => n.type === 'endpoint') });
      if (sel.length) { skillNote = '\n\n' + skillsBriefing(sel); this._log('skills', { phase: phase.id, selected: sel.map((s) => s.name) }); }
    }
    const system = (this.inform ? this.inform + '\n\n' : '') + phase.system(this.scope);
    // Relay a countersigned HITL gate to the Enclave's approval context so the hook
    // permits the gated action (exploit needs context.approved). Scoped to this phase.
    const bridged = this.bridgeApproval && phase.gate === 'sigil';
    const prevApproval = process.env.ENCLAVE_APPROVAL;
    if (bridged) process.env.ENCLAVE_APPROVAL = 'granted';
    let res;
    try {
      res = await this.runAgent({ ...this.engine, system, messages: [{ role: 'user', content: phase.objective + briefNote + priorNote + failNote + focusNote + forgeNote + compNote + authzNote + skillNote + extraHint }] });
    } catch (e) {
      this._log('phase.error', { phase: phase.id, error: String((e && e.message) || e) });
      this.surface.note(phase.id, 'phase error — ' + ((e && e.message) || e));
      this._onSurface();
      return { error: true };
    } finally {
      if (bridged) { if (prevApproval === undefined) delete process.env.ENCLAVE_APPROVAL; else process.env.ENCLAVE_APPROVAL = prevApproval; }
    }
    if (!res || typeof res !== 'object') { this._log('phase.error', { phase: phase.id, error: 'agent returned no result' }); return { error: true }; }
    this._lastText = String(res.text || '');

    // Everything after a successful return is guarded too — a malformed result must not crash the run.
    try {
      this.budget.usedSteps += nnum(res.steps);
      this._log('phase.result', { phase: phase.id, steps: nnum(res.steps), denials: Array.isArray(res.denials) ? res.denials.length : 0 });
      this.opsec.observe({ toolCalls: nnum(res.steps) });
      // Detection footprint for the phase's dominant activity (post-ex file-drops/pivots
      // are recorded from their concrete artifacts/routes, so they're excluded here).
      const PHASE_FP = { recon: 'tcp-scan', validate: 'service-probe', exploit: 'exploit-attempt' };
      if (PHASE_FP[phase.id]) this._noise({ kind: PHASE_FP[phase.id], count: Math.max(1, nnum(res.steps)), authorized: phase.gate === 'sigil' });
      for (const d of Array.isArray(res.denials) ? res.denials : []) { this.surface.hold({ action: d, rule: 'enclave-denied', target: this.scope.engagement }); this.opsec.observe({ holds: 1 }); this._log('hold', { action: d, phase: phase.id }); this._fail('held', d, phase.id); }
      this._ingest(phase.id, parseJsonBlock(res.text));
      this.surface.note(phase.id, String(res.text || '').split('```')[0].trim().slice(0, 240));
      // chaincompose v2: after the validate turn, compose candidate chains from the
      // validated primitives on the live surface (logged as chain.composed; parked as
      // proposed exploit nodes for the gated exploit phase).
      if (phase.id === 'validate') { try { await this.composeChainsFromSurface(); } catch (e) { this._log('phase.error', { phase: 'validate', error: 'compose: ' + ((e && e.message) || e) }); } }
    } catch (e) {
      this._log('phase.error', { phase: phase.id, error: 'post-result: ' + ((e && e.message) || e) });
    }
    this._onSurface();
    return { text: res.text, denials: res.denials };
  }

  async run() {
    if (this.status !== 'idle') return this.getState(); // re-entrancy guard
    this.status = 'running';
    await this._calibrateStealth(); // auto-stealth: profile the target + pick the profile before recon
    const phases = this.reconOnly ? PHASES.filter((p) => p.id === 'recon') : PHASES;
    this._log('campaign.start', { scope: this.scope, budget: this.budget.maxSteps, reconOnly: this.reconOnly });
    for (this.phaseIndex = 0; this.phaseIndex < phases.length; this.phaseIndex++) {
      const phase = phases[this.phaseIndex];
      this._onPhase(phase);
      for (let attempt = 0; ; attempt++) {
        const before = this.surface.counts();
        this._lastText = '';
        let result;
        // Deep Think: at a transition into a high-significance phase, or when stuck, prepend
        // a structured "emit ≥2 competing hypotheses" step before the agent acts.
        const dt = shouldDeepThink({ phase: phase.id, stuck: this.stuck, transitioned: attempt === 0, iterationsSince: 99 }, {});
        if (dt.fire) this._log('deepthink', { phase: phase.id, reason: dt.reason });
        const hint = (attempt > 0 ? replanHint(phase.id, this._lastDenials || 0, this.stuck >= 2 ? 2 : 1) : '')
          + (dt.fire ? '\n\n' + deepThinkPrompt({ phase: phase.id, objective: phase.objective, stuck: this.stuck }) : '');
        try { result = await this.runPhase(phase, hint); }
        catch (e) { this._log('phase.error', { phase: phase.id, error: 'runPhase: ' + ((e && e.message) || e) }); result = { error: true }; }
        if (phase.id === 'report') break; // report is synthesis, not discovery — not audited
        // HONESTY/PRODUCTIVITY AUDIT: did the surface actually grow, or was progress claimed but hallucinated?
        const a = assessProgress(before, this.surface.counts(), this._lastText);
        this.assessments.push({ phase: phase.id, ...a });
        // Deterministic, LLM-independent stuck signal: consecutive no-growth phases.
        this.stuck = a.realDelta > 0 ? 0 : this.stuck + 1;
        this._log('progress', { phase: phase.id, verdict: a.verdict, realDelta: a.realDelta, stuck: this.stuck });
        if (!a.honest) this._log('progress.flag', { phase: phase.id, note: 'claimed progress with no surface delta' });
        this._lastDenials = Array.isArray(result && result.denials) ? result.denials.length : 0;
        // deny/stall backout: re-plan a recon/validate phase that produced nothing (bounded by maxReplan)
        // Re-plan a no-progress recon; re-plan validate ONLY if nothing is confirmed yet
        // (when recon already confirmed findings, a no-new-node validate is fine, not a stall).
        const canReplan = phase.id === 'recon' || (phase.id === 'validate' && this.surface.counts().confirmed === 0);
        if (a.realDelta === 0 && attempt < this.maxReplan && canReplan && !(result && (result.held || result.skipped || result.error))) {
          this._log('replan', { phase: phase.id, attempt: attempt + 1 });
          continue;
        }
        // A phase that ran but grew nothing is a failed approach — remember it for next session.
        if (a.realDelta === 0 && (a.verdict === 'no-progress' || a.verdict === 'dishonest-or-stalled') && !(result && (result.held || result.skipped || result.error))) {
          this._fail(a.verdict, `${phase.id} — ${((this._lastText || '').split('```')[0].split('\n').filter(Boolean)[0] || 'no result')}`, phase.id);
        }
        break;
      }
    }
    this.status = 'done';
    // COVERAGE-COMPLETION GATE (winner-copyables Tool 3): done-clean is EARNED — every
    // recon-queued surface item exercised by ≥1 lane. Untested queue = COVERAGE-INCOMPLETE,
    // itemized, never silently skipped.
    try {
      const cov = this.coverage.gate();
      this.coverageVerdict = cov.verdict;
      this._log('coverage.gate', { verdict: cov.verdict, queued: cov.queued, tested: cov.tested, remaining: cov.remainingTotal || 0, orphans: (cov.orphans || []).length, overflow: this.coverage.status().overflow });
      if (cov.verdict === 'COVERAGE-INCOMPLETE') {
        this.surface.note('report', `COVERAGE-INCOMPLETE: ${cov.remainingTotal} queued in-scope surface item(s) were never exercised — the campaign is NOT done-clean; remaining queue: ${cov.remaining.slice(0, 8).map((i) => i.key).join(', ')}${cov.truncated ? ' …' : ''}`);
      } else if (cov.verdict === 'DONE-CLEAN') {
        this.surface.note('report', `Coverage gate: DONE-CLEAN — all ${cov.queued} queued surface item(s) exercised (${Object.entries(cov.byLane || {}).map(([l, n]) => `${l}:${n}`).join(', ') || 'no lane marks'})`);
      } else {
        this.surface.note('report', 'Coverage gate: NO-SURFACE-QUEUED — recon harvested no testable surface; a clean bill here is vacuous and is recorded as vacuous');
      }
      this._onSurface();
    } catch (e) { this._log('coverage.error', { error: String((e && e.message) || e) }); }
    this._log('campaign.done', { counts: this.surface.counts(), usedSteps: this.budget.usedSteps, coverage: this.coverageVerdict });
    try {
      const findings = [...this.surface.nodes.values()].filter((n) => n.type === 'finding').map((n) => ({ label: n.label, sev: n.sev, risk: n.risk, ref: n.ref }));
      recordFindings(this.scope.engagement, findings); // accumulate across sessions
      recordFailures(this.scope.engagement, this.failures); // remember what failed
      saveSurface(this.scope.engagement, this.surface.toJSON());
    } catch (e) { this._log('persist.error', { error: String((e && e.message) || e) }); }
    return this.getState();
  }

  getState() {
    return {
      status: this.status,
      phaseIndex: this.phaseIndex,
      reconOnly: this.reconOnly, // discovery-only sweep — the Task Tree shows downstream phases as intentionally out
      surface: this.surface.toJSON(),
      opsec: this.opsec.toJSON(),
      activity: this.activity.slice(), // copy — callers can't corrupt the internal feed
      budget: { maxSteps: this.budget.maxSteps, usedSteps: this.budget.usedSteps, tools: { maxRequests: this.toolBudget.maxRequests, maxMs: this.toolBudget.maxMs, used: this.toolBudget.used, exhausted: !!this.toolBudget.exhaustedAt } },
      stealth: this.stealthName, // active operational-stealth profile (null = none; 'auto' resolves at run start)
      stealthBudget: this.noise.status(), // enforced noise budget + the "we stayed under X" proof line
      watchdog: this.watchdog.latest(), // the OPSEC reflex's latest advice (null = nothing escalated)
      guidedSearch: this.guidedTrace, // LATS tree trace for the Task Tree panel (null = not run)
      waves: this.waves.slice(),      // fireteam wave summaries for the Task Tree panel
      chainPlans: this.chainPlans,    // chainforge-compiled exploit chains from the live surface
      authzSweep: this.authzSweepResult ? this.authzSweepResult.summary : null, // Build 1: two-account authorization oracle rollup (null = not configured/run)
      hunting: { jsminer: this.jsminerResult, oob: this.oobResult, domxss: this.browserResult, aisurface: this.aiSurfaceResult }, // Build 2+3: hunting-tool lane rollups (null = not run)
      targetScore: this.targetScoreRollup, // Build 3: the ROI layer's per-host expected-yield rollup (null = not run)
      coverage: this.coverage.status(), // winner-copyables Tool 3: the per-target exercise ledger (queued/tested/untested, by lane)
      cvelane: this._cvelaneStats, // 2026-08-31: CVE HYPOTHESES queued into the coverage gate (received/queued/skipped — skipped = host outside this campaign's targets)
      completion: this.coverageVerdict, // DONE-CLEAN | COVERAGE-INCOMPLETE | NO-SURFACE-QUEUED (null = campaign not finished)
      deception: this.deception || null, // canary/deception suspicion verdict (null = not scanned / no domain)
      targetProfile: this.targetProfile, // auto-stealth: detected defenses + calibration (null if not auto / undetected)
      productivity: productivity(this.assessments), // honesty/productivity audit summary
      stall: this.stall || null, // campaign-level stall detector: non-null while parked stalled:<phase>
      inheritedFindings: this.prior.length,
      inheritedFailures: this.priorFail.length,
    };
  }
}
