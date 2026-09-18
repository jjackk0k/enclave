// VARVEL — campaign service.
// Serves the console and exposes the engine over HTTP: start a campaign, read
// live state (surface + OPSEC + activity + budget), stream events, countersign
// HITL gates, mark artifacts cleaned, and message the operator's agent.
//
// Transport/orchestration only. Enforcement + the tamper-evident audit of record
// stay in the Enclave layer (every tool call in a live campaign crosses the hook).
// VARVEL keeps only a lenient activity feed here — deliberately not an audit.
//
//   node varvel/server.mjs                 # demo mode (mock agent, no API key)
//   VARVEL_PORT=8971 node varvel/server.mjs
//
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Campaign, parseJsonBlock } from './engine/campaign.mjs';
import { PHASES } from './engine/phases.mjs';
import { mockAgent } from './mock-agent.mjs';
import { renderReport } from './engine/report.mjs';
import { remediation } from './engine/classify.mjs';
import { productivity } from './engine/auditor.mjs';
import { createDemoTarget } from './targets/demo-corp.mjs';
import { createHardTarget } from './targets/premium-hard.mjs';
import { DEFAULT_PATHS } from './tools/webscan.mjs';
import { readOperator, scopeForCampaign, publicIdentity, informBlock } from './engine/identity.mjs';
import { liveEngine, liveReadiness, operatingBrief, DEMO_SESSION } from './engine/live.mjs';
import { vmLabAvailable, vmLabTargetIp } from '../vm-lab.mjs';
import { claudeAvailable, makeClaudeAgent } from './engine/claude-cli.mjs';
import { makeKimiAgent, isKimiModel, KIMI_MODELS, KIMI_EFFORTS, kimiConfig } from './engine/kimi-runagent.mjs';
import { resolveBrain, BRAIN_PROVIDERS, setRuntimeKey, runtimeKeyPresent } from './engine/brain-provider.mjs';
import { queryGraph, pathsToPrivileged } from './engine/graphquery.mjs';
import { CallbackChannel } from './engine/callback.mjs';
import { footprintAiAdvise, advisorBackend } from './engine/footprint-ai.mjs';
import { footprintAdvisor } from './engine/footprint-advisor.mjs';
import { triage, codeFixAgent } from './engine/remediate.mjs';
import { STEALTH_PROFILES } from './engine/stealth.mjs';
import { BUDGET_PRESETS } from './engine/budget.mjs';
import { detectStack } from './engine/target-profile.mjs';
import { comparePosture } from './engine/posture.mjs';
import { shelveTool, shelfList, shelfRead, promoteTool } from './engine/toolshelf.mjs';
import { report as attackbenchReport } from './tools/attackbench.mjs';
import { Settings, SETTINGS_SCHEMA } from './engine/settings.mjs';
import { annotateValidation } from './engine/validator.mjs';
import { briefSlice as stateBriefSlice, loadState as loadEngagementState, redactState, stateCounts } from './engine/statestore.mjs';
import { Ghost, isPrivateDest, resolveGhostChain } from './engine/ghost.mjs';
import { homedir } from 'node:os';

const __dir = dirname(fileURLToPath(import.meta.url));
const CONSOLE = join(__dir, '..', 'docs', 'varvel-console-redblack.html');
const APP = join(__dir, 'app-v6.html');     // LIVE build: Kimi-K3 UI pass (keyboard nav, LINK status, sticky headers, HITL attention)
const APP_V5 = join(__dir, 'app-v5.html');  // previous build (at /v5) — stealth picker + budget meter + target-calibration card
const APP_V4 = join(__dir, 'app-v4.html');  // previous build (at /v4) — NL query, backend chip, confidence meter
const APP_V3 = join(__dir, 'app-v3.html');  // previous build (at /v3)
const APP_V2 = join(__dir, 'app-v2.html');  // premium build (at /v2)
const APP_V1 = join(__dir, 'app.html');     // first data-driven build (at /v1)
const EMBLEM = join(__dir, '..', 'docs', 'brand', 'varvel-emblem.png');
const PORT = Number(process.env.VARVEL_PORT || 8971);
const DEMO_PORT = Number(process.env.VARVEL_DEMO_PORT || 8972);
const HARD_PORT = Number(process.env.VARVEL_HARD_PORT || 8973);

// The bound operator, read from the Enclave console handoff (ENCLAVE_SESSION) at
// startup. Standalone (opened directly) yields an unbound operator — no fabricated
// identity. Clearance INFORMS; the Enclave hook is the only authorizer.
const OPERATOR = await readOperator();
const OPERATOR_SCOPE = scopeForCampaign(OPERATOR);

// The AI model VARVEL runs — starts from the launch env, changeable at runtime via
// GET/POST /api/model (the Settings picker). Changing it re-creates the chat agent.
// Claude models (via the CLI backend) + Kimi models (via the governed direct-API backend —
// `claude -p` hangs on Kimi, so Kimi models route through engine/kimi-runagent.mjs).
const MODELS = ['sonnet', 'opus', 'haiku', 'claude-opus-4-8', 'claude-opus-5', 'claude-sonnet-5', ...KIMI_MODELS];
let currentModel = process.env.VARVEL_MODEL || 'sonnet';
// Reasoning effort — applies to the Kimi backend (K3/K2.7 support low|medium|high; high = deepest).
let currentEffort = KIMI_EFFORTS.includes(process.env.VARVEL_EFFORT) ? process.env.VARVEL_EFFORT : 'high';
// Brain provider (ADDITIVE local-brain seam): null = platform default ('kimi', unchanged);
// 'openai-compatible' points the SAME governed backend at a local OpenAI-compatible endpoint
// (the DGX Spark: vLLM / llama.cpp server). Per-request pick via POST /api/model {provider};
// the Enclave open call forces the same layer with VARVEL_BRAIN_PROVIDER (+_BASE_URL/_MODEL/
// _API_KEY_ENV/_TIMEOUT_MS); the engagement's brain.* settings are the floor. baseUrl/model
// resolve from those layers — they are NOT the picker model (a Claude/Kimi id).
let currentProvider = process.env.VARVEL_BRAIN_PROVIDER || null;
// Effective provider config for API echoes — validated merge of request/env/settings, or an
// honest error string when the merged config is unusable. NEVER carries a key value.
const brainEcho = () => {
  try { const b = resolveBrain({ env: process.env, engagement: (OPERATOR_SCOPE || {}).engagement, request: currentProvider ? { provider: currentProvider } : null });
    // keyPresent is PRESENCE ONLY: a key exported in the environment or pasted into the
    // runtime keyring (this process's memory) — the value itself never leaves the engine.
    return { provider: b.provider, baseUrl: b.baseUrl, model: b.model, apiKeyEnv: b.apiKeyEnv, timeoutMs: b.timeoutMs, source: b.source, keyPresent: b.apiKeyEnv ? runtimeKeyPresent(b.apiKeyEnv, process.env) : false }; }
  catch (e) { return { provider: currentProvider || 'kimi', error: String((e && e.message) || e) }; }
};

// Operational-stealth profile VARVEL runs under — the enforced pacing + noise budget for
// the next campaign (GET/POST /api/stealth). DEFAULT IS 'auto': every engagement fingerprints
// the target and runs calibrated, enforced stealth unless the operator deliberately picks
// another profile ('loud' = explicitly authorized noisy run). Stealth is the default posture,
// not an opt-in — the enforcement RedAmon's autonomous agent lacks: quietness in code, not a
// prompt. VARVEL_STEALTH=off disables the default.
const STEALTH_NAMES = Object.keys(STEALTH_PROFILES); // loud|normal|quiet|paranoid
let currentStealth = process.env.VARVEL_STEALTH === 'off' ? null
  : (process.env.VARVEL_STEALTH && STEALTH_PROFILES[process.env.VARVEL_STEALTH] ? process.env.VARVEL_STEALTH : 'auto');

// Interactive chat: the message box drives a governed Claude CLI agent turn (multi-turn
// via --resume). This is the "talk to / manually drive the AI" path, separate from the
// autonomous campaign pipeline. Every tool call still crosses the Enclave hook.
const chatMessages = [];
let chatAgent = null, chatSessionId = null, chatBusy = false, chatCampaign = null;
// Sync the reviewed native tools INTO the sealed chat workspace so the agent can call them
// as plain commands (node varvel-tools/tools/cli.mjs …) without the hook's workspace
// confinement denying an outside-of-workspace path. Re-synced at agent init (cheap, small).
// The tool set is COMPUTED, never hand-listed: ALL top-level tools/*.mjs plus the engine
// dependency closure (tools import ../engine/X; engine files import ./Y). The old hardcoded
// TOOL_SYNC list went stale twice — missing osfp/canary/ldapenum made cli.mjs crash on load
// (static imports), and missing oracle modules (floworacle/tradecraft/preflight/…) made the
// brief advertise tools the workspace didn't have (the 2026-08-05 manhuaus run).
const IMPORT_RE = /(?:from\s*|import\s*\(\s*)['"](\.\.\/engine\/|\.\/)([\w.-]+\.mjs)['"]/g;
function syncAgentTools(wsDir) {
  try {
    const toolsDir = join(__dir, 'tools');
    const engineDir = join(__dir, 'engine');
    const toolFiles = readdirSync(toolsDir).filter((f) => f.endsWith('.mjs') && statSync(join(toolsDir, f)).isFile());
    const engineNeed = new Set();
    for (const f of toolFiles) {
      const src = readFileSync(join(toolsDir, f), 'utf8');
      for (const m of src.matchAll(IMPORT_RE)) if (m[1] === '../engine/') engineNeed.add(m[2]);
    }
    for (let grew = true; grew;) {   // engine files' own ./Y engine imports, to fixpoint
      grew = false;
      for (const f of [...engineNeed]) {
        let src = ''; try { src = readFileSync(join(engineDir, f), 'utf8'); } catch { continue; }
        for (const m of src.matchAll(IMPORT_RE)) if (m[1] === './' && !engineNeed.has(m[2])) { engineNeed.add(m[2]); grew = true; }
      }
    }
    const writes = [];
    const toT = join(wsDir, 'varvel-tools', 'tools'), toE = join(wsDir, 'varvel-tools', 'engine');
    mkdirSync(toT, { recursive: true }); mkdirSync(toE, { recursive: true });
    for (const f of toolFiles) writes.push([join(toolsDir, f), join(toT, f)]);
    for (const f of engineNeed) writes.push([join(engineDir, f), join(toE, f)]);
    let n = 0;
    for (const [from, to] of writes) { try { writeFileSync(to, readFileSync(from)); n++; } catch {} }
    // tools/clearance/ subtree (broker + its isolated node_modules — patchright-core): the
    // broker dynamically imports the engine from beside itself, so the whole tree rides.
    // 13MB — newer/changed files only, so agent-init stays cheap after the first sync.
    try {
      const clSrc = join(toolsDir, 'clearance');
      if (statSync(clSrc).isDirectory()) {
        const walk = (d, acc) => { for (const e of readdirSync(d, { withFileTypes: true })) { const p = join(d, e.name); e.isDirectory() ? walk(p, acc) : acc.push(p); } return acc; };
        for (const abs of walk(clSrc, [])) {
          const to = join(toT, 'clearance', abs.slice(clSrc.length + 1));
          try {
            const s = statSync(abs); let copy = true;
            try { const t = statSync(to); copy = s.mtimeMs > t.mtimeMs || s.size !== t.size; } catch { /* absent -> copy */ }
            if (copy) { mkdirSync(join(to, '..'), { recursive: true }); writeFileSync(to, readFileSync(abs)); n++; }
          } catch {}
        }
      }
    } catch { /* no clearance module installed — the cli reports the honest unsupported state */ }
    return n;
  } catch { return 0; }
}
function ensureChatAgent() {
  if (chatAgent) return chatAgent;
  const sessionFile = process.env.ENCLAVE_SESSION || DEMO_SESSION;
  const wsDir = join(homedir(), '.enclave-workspaces', 'varvel-chat');
  syncAgentTools(wsDir);
  // A Kimi model → the governed Kimi backend (claude -p hangs on Kimi). Each chat message is a
  // single governed turn (no cross-message resume yet), but it runs on Kimi and stays governed.
  if (currentProvider || isKimiModel(currentModel)) {
    // maxTurns from the engagement settings (default 40; a full breach chain needs ~30).
    // engagement: threads the statestore engagement into mission checkpoints (resume + split).
    try { chatAgent = makeKimiAgent({ sessionFile, wsDir, model: currentModel, effort: currentEffort, container: process.env.ENCLAVE_CONTAINER || '', maxTurns: Settings.for((OPERATOR_SCOPE || {}).engagement).get('agent.maxTurns'), extraEnv: ghostShellEnv(), engagement: (OPERATOR_SCOPE || {}).engagement || null, provider: currentProvider }); } catch { chatAgent = null; }
    return chatAgent;
  }
  if (!claudeAvailable()) return null;
  try { chatAgent = makeClaudeAgent({ sessionFile, wsDir, model: currentModel, extraEnv: ghostShellEnv() }); } catch { chatAgent = null; }
  return chatAgent;
}
// A lightweight surface the CHAT feeds (never run() — just ingest + activity) so the
// graph and activity log reflect what the interactive agent discovers.
function ensureChatCampaign() {
  if (!chatCampaign) chatCampaign = new Campaign({ scope: OPERATOR_SCOPE || { engagement: 'interactive', signedBy: OPERATOR.principal || 'operator', cidrs: (OPERATOR && OPERATOR.cidrs && OPERATOR.cidrs.length) ? OPERATOR.cidrs : ['127.0.0.0/8'] }, runAgent: () => ({ text: '', steps: 0 }), ghost });
  return chatCampaign;
}

// The governed callback channel (C2 maturity track): one channel per server, armed on
// demand with the signed operator scope. Every event lands in the activity feed — the
// channel is quiet to observers and loud in the ledger.
let channel = null;
async function ensureChannel() {
  if (channel && channel.server) return channel;
  const camp = ensureChatCampaign();
  // Env overrides for the VM range: the channel must bind where range targets can reach
  // it (VARVEL_CHANNEL_BIND) with a scope ring covering the lab (VARVEL_SCOPE_CIDRS).
  // Defaults stay loopback + operator scope — nothing changes outside the lab.
  const scopeCidrs = process.env.VARVEL_SCOPE_CIDRS ? process.env.VARVEL_SCOPE_CIDRS.split(',').map((s) => s.trim()).filter(Boolean) : null;
  channel = new CallbackChannel({
    scope: scopeCidrs ? { engagement: 'channel', signedBy: 'operator', cidrs: scopeCidrs } : (OPERATOR_SCOPE && OPERATOR_SCOPE.cidrs && OPERATOR_SCOPE.cidrs.length ? OPERATOR_SCOPE : { engagement: 'channel', signedBy: 'operator', cidrs: ['127.0.0.0/8'] }),
    bind: process.env.VARVEL_CHANNEL_BIND || undefined,
    dnsPort: Number(process.env.VARVEL_DNS_PORT) || 0,   // >0 = real DNS-over-UDP wire transport
    dnsDomain: process.env.VARVEL_DNS_DOMAIN || 'ax.sim',
    // VARVEL_ICMP=1 opts into the native ICMP fallback bridge (raw sockets — the bridge
    // itself reports supported:false honestly if the host can't open one).
    icmp: process.env.VARVEL_ICMP ? { python: process.env.VARVEL_ICMP_PYTHON || undefined } : null,
    // VARVEL_DOH=1 opts into the RFC 8484 DNS-over-HTTPS transport (same governed wire
    // packets, TLS-carried). Operator PEM paths win; absent them the lab-only cert arms.
    doh: process.env.VARVEL_DOH ? { port: Number(process.env.VARVEL_DOH_PORT) || 4453, cert: process.env.VARVEL_DOH_CERT || undefined, key: process.env.VARVEL_DOH_KEY || undefined } : null,
    // stg (roadmap #4): the steganography image channel — envelopes inside PNGs on this
    // same listener. Opt-in like the other special wires: settings stg.enabled (default
    // OFF) or the VARVEL_STG=1 env for the VM range; stg.profile picks the cover scene.
    stg: (process.env.VARVEL_STG || Settings.for((OPERATOR_SCOPE && OPERATOR_SCOPE.engagement) || 'default').get('stg.enabled'))
      ? { profile: Settings.for((OPERATOR_SCOPE && OPERATOR_SCOPE.engagement) || 'default').get('stg.profile') }
      : null,
    onEvent: (type, obj) => { try { camp._log('channel.' + type, obj); } catch {} },
  });
  await channel.arm(Number(process.env.VARVEL_CHANNEL_PORT) || 0);
  return channel;
}

// Ghost Mode (governed identity stealth): singleton engine. Mode/chain live in the
// per-engagement settings (ghost.mode/ghost.chain/ghost.checkUrl) so the console's settings
// panel drives it; arming here just applies + verifies. Events ride the same activity tap.
const ghost = new Ghost({ onEvent: (type, obj) => { try { ensureChatCampaign()._log('ghost.' + type, obj); } catch {} } });
export function ghostEngine() { return ghost; }
async function armGhostFromSettings(eng) {
  const s = Settings.for(eng || 'default');
  const mode = s.get('ghost.mode');
  let chainStr = s.get('ghost.chain');
  // Free-identity fallback (Jack's directive): arming on/required with NO chain uses a
  // detected local Tor automatically; if there is no Tor either, resolveGhostChain throws
  // an honest error naming the free path — never a silent direct-egress arm.
  if (mode && mode !== 'off' && !String(chainStr || '').trim()) {
    const r = await resolveGhostChain({ mode, chain: chainStr });
    chainStr = r.hops.map((h) => `${h.scheme}://${h.host}:${h.port}`).join(', ');
    s.set('ghost.chain', chainStr); // persist so the console shows exactly what is used
  }
  const status = ghost.configure({ mode, chain: chainStr, checkUrl: s.get('ghost.checkUrl') });
  if (ghost.mode !== 'off') await ghost.verify(); // proof (or honest failure) in status()
  await ghost.refreshTor({ force: true });
  return ghost.status() || status;
}

// Shell env for governed agent processes (the interactive Bash path): when Ghost Mode is
// armed AND the engagement reaches public space, shell-native tools (curl etc.) ride the
// chain's first hop via standard proxy vars. Range-only engagements get nothing — private
// traffic goes direct by design, and a proxy would break the sealed lab.
function ghostShellEnv() {
  if (ghost.mode === 'off' || !ghost.chain.length) return {};
  const cidrs = (OPERATOR_SCOPE && OPERATOR_SCOPE.cidrs) || [];
  const publicScope = !cidrs.length || cidrs.some((c) => !isPrivateDest(String(c).split('/')[0]));
  if (!publicScope) return {};
  const hop = ghost.chain[0];
  const auth = hop.user ? `${encodeURIComponent(hop.user)}:${encodeURIComponent(hop.pass)}@` : '';
  const proxy = `${hop.scheme === 'socks5' ? 'socks5' : 'http'}://${auth}${hop.host}:${hop.port}`;
  return { HTTP_PROXY: proxy, HTTPS_PROXY: proxy, ALL_PROXY: proxy, http_proxy: proxy, https_proxy: proxy, all_proxy: proxy, NO_PROXY: '127.0.0.1,localhost', no_proxy: '127.0.0.1,localhost' };
}

// Channel API: agents, tasking (single/tag/all), artifact staging + retrieval.
function channelRoutes(pathname, req, res) {
  const respond = (code, obj) => json(res, code, obj);
  return (async () => {
    if (pathname === '/api/channel' && req.method === 'GET') {
      if (!channel || !channel.server) return respond(200, { armed: false });
      return respond(200, { armed: true, port: channel.port, dnsPort: channel.dnsPort || null, dnsDomain: channel.dnsDomain || 'ax.sim', icmp: channel.icmpStatus(), doh: channel.dohStatus(), ghc: channel.ghcStatus(), stg: channel.stgStatus(), agents: channel.agentsView(), artifacts: channel.artifacts() });
    }
    if (pathname === '/api/channel/arm' && req.method === 'POST') {
      const ch = await ensureChannel();
      return respond(200, { armed: true, port: ch.port });
    }
    // Cloud/SaaS dead-drop transport (engine/ghc2, tools/ghc2): arm reads the ghc2.*
    // settings (default-OFF refusal), threads the armed ghost chain, runs the FREE
    // /rate_limit token+budget check, then attaches the channel's mailbox pump. The
    // burner PAT never appears in any response — presence/class only. Never throws.
    if (pathname === '/api/channel/ghc' && req.method === 'POST') {
      const b = await readBody(req);
      const ch = await ensureChannel();
      const { armGhc, pollGhc, detachGhc } = await import('./tools/ghc2.mjs');
      const engagement = (OPERATOR_SCOPE && OPERATOR_SCOPE.engagement) || 'default';
      if (b.action === 'poll') return respond(200, await pollGhc({ channel: ch }));
      if (b.action === 'detach') return respond(200, detachGhc({ channel: ch }));
      const r = await armGhc({ engagement, channel: ch, ghost, ghostMode: ghost.mode });
      return respond(r.ok ? 200 : 400, r);
    }
    if (pathname === '/api/channel/tasks' && req.method === 'GET') {
      if (!channel) return respond(200, { tasks: [] });
      return respond(200, { tasks: channel.tasksView(new URL(req.url, 'http://x').searchParams.get('agent')) });
    }
    // FULL result bodies (the ledger's 120-char preview truncates evidence-class JSON —
    // the evasion tier's hash evidence never fits a preview). taskId-filtered drain:
    // only the caller's own task results leave the buffer.
    if (pathname === '/api/channel/results' && req.method === 'GET') {
      if (!channel) return respond(200, { results: [] });
      const q = new URL(req.url, 'http://x').searchParams;
      return respond(200, { results: channel.results(q.get('agent'), { taskId: q.get('taskId') || undefined }) });
    }
    if (pathname === '/api/channel/artifact' && req.method === 'GET') {
      const data = channel && channel.artifact(new URL(req.url, 'http://x').searchParams.get('id'));
      if (!data) return respond(404, { error: 'no such artifact' });
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-disposition': 'attachment' });
      return res.end(data);
    }
    // Flow-beacon self-test (gap#6): the full scoreFlow result for one agent (features +
    // flagged + note) over the channel's observed flow ring. Feature evidence, never a
    // vendor verdict. 404 when there is no such agent to score.
    if (pathname === '/api/channel/flow' && req.method === 'GET') {
      if (!channel) return respond(404, { error: 'channel not armed -- no flow evidence exists' });
      const v = channel.flowView(new URL(req.url, 'http://x').searchParams.get('agent'));
      return v ? respond(200, v) : respond(404, { error: 'no such agent' });
    }
    // Agent-tradecraft oracle (gap#7): grade one agent's shell-task stream from the
    // channel ledger against the published AI-agent command signatures (engine/agentsig).
    // Signatures + evidence only, never a vendor verdict. 404 when there is no such agent.
    if (pathname === '/api/channel/tradecraft' && req.method === 'GET') {
      if (!channel) return respond(404, { error: 'channel not armed -- no task ledger exists' });
      const v = channel.tradecraftView(new URL(req.url, 'http://x').searchParams.get('agent'));
      return v ? respond(200, v) : respond(404, { error: 'no such agent' });
    }
    if (pathname === '/api/channel/agent' && req.method === 'POST') {
      const b = await readBody(req);
      const ch = await ensureChannel();
      if (b.action === 'register') { const a = ch.registerAgent({ label: b.label, tags: b.tags || [] }); return respond(200, { ok: true, ...a }); }
      if (b.action === 'kill') { ch.kill(b.agentId); return respond(200, { ok: true }); }
      if (b.action === 'rename') return respond(200, { ok: true, label: ch.renameAgent(b.agentId, b.label) });
      if (b.action === 'tag') return respond(200, { ok: true, tags: ch.tagAgent(b.agentId, b.tag, b.on !== false) });
      if (b.action === 'profile') return respond(200, { ok: true, profile: ch.setProfile(b.agentId, b.profile) });
      // Shaping pack v2: apply/clear a full wire-shape profile ('plain' clears). Unknown
      // names are an honest 400 — never a silent reshape.
      if (b.action === 'shape') { const r = ch.setShapeProfile(b.agentId, b.shape); return respond(r ? 200 : 400, r ? { ok: true, shape: r } : { ok: false, error: 'unknown/killed agent or unknown shape profile (plain|cdn-asset|software-update|telemetry-beacon)' }); }
      if (b.action === 'transport') { const r = ch.setTransport(b.agentId, b.transport); return respond(r ? 200 : 400, r ? { ok: true, assignedTransport: r } : { ok: false, error: 'unknown/killed agent or bad transport (http|dns|icmp|doh|ws|smb|ghc|stg)' }); }
      return respond(400, { error: 'unknown action' });
    }
    if (pathname === '/api/channel/task' && req.method === 'POST') {
      const b = await readBody(req);
      const ch = await ensureChannel();
      // Governance refusals (e.g. inline-dotnet with exec.inMemory OFF, or an over-cap
      // assembly) are thrown by the channel with code GOVERNANCE — answer 403 LOUDLY,
      // never the 404 an unknown/killed agent gets. The refusal is audited channel-side.
      try {
        if (b.agentId) { const taskId = ch.task(b.agentId, b.kind, b.data); return respond(taskId ? 200 : 404, { ok: !!taskId, taskId }); }
        const out = ch.taskWhere({ tag: b.tag, all: !!b.all }, b.kind, b.data);
        return respond(200, { ok: true, tasked: out });
      } catch (e) {
        if (e && e.code === 'GOVERNANCE') return respond(403, { ok: false, error: String(e.message || e) });
        throw e;
      }
    }
    if (pathname === '/api/channel/stage' && req.method === 'POST') {
      const b = await readBody(req);
      const ch = await ensureChannel();
      try {
        const st = ch.stageArtifact(b.agentId, b.name, Buffer.from(String(b.b64 || ''), 'base64'));
        return respond(st ? 200 : 404, st || { error: 'no such agent' });
      } catch (e) { return respond(400, { error: String((e && e.message) || e) }); }
    }
    return respond(404, { error: 'unknown channel endpoint' });
  })().catch((e) => json(res, 500, { error: String((e && e.message) || e) }));
}

// Event-driven OPSEC AI advisor: when the active campaign's footprint hits HIGH risk with
// NEW noise, a CHEAP model gives engagement-specific, transparency-bound reduction advice.
// It is NOT a timer poll of the model — footprintAiAdvise only calls out on a fresh
// high-risk event; quiet/low-risk runs never touch the model. Disable with VARVEL_FOOTPRINT_AI=0.
//
// Backend (2026-08-11 fix): DEFAULT is the Kimi backend (engine/kimi-runagent.mjs) — the
// operator's CURRENT auto-refreshed OAuth subscription, the path the main agent already
// proves alive. The old default (claude-cli on 'haiku') authenticated with a STALE cached
// credential (an exhausted subscription) and died in production with a 403 "usage limit",
// so claude is now ONLY an explicit opt-in: set VARVEL_ADVISOR_MODEL to a claude model AND
// have the CLI present. advisorBackend() (engine/footprint-ai.mjs) is the routing truth.
let advisorAgent = null, lastAdvisedActions = -1, footprintAdvice = null, advisorBusy = false;
const advisorRoute = () => advisorBackend(process.env, { kimiUp: kimiConfig(process.env).ok, claudeUp: claudeAvailable() });
const advisorEnabled = () => !!advisorRoute();
function ensureAdvisorAgent() {
  if (advisorAgent) return advisorAgent;
  const r = advisorRoute();
  if (!r) return null;
  const sessionFile = process.env.ENCLAVE_SESSION || DEMO_SESSION, wsDir = join(homedir(), '.enclave-workspaces', 'varvel-advisor');
  try {
    advisorAgent = r.backend === 'kimi'
      ? makeKimiAgent({ sessionFile, wsDir, model: r.model, effort: r.effort })
      : makeClaudeAgent({ sessionFile, wsDir, model: r.model });
  } catch { advisorAgent = null; }
  return advisorAgent;
}
async function maybeAdvise() {
  if (advisorBusy || !advisorEnabled()) return;
  const active = campaign || chatCampaign;
  if (!active) return;
  const agent = ensureAdvisorAgent();
  if (!agent) return;
  const opsec = active.opsec.toJSON();
  const target = (active.targets && active.targets[0]) || (active.scope && (active.scope.cidrs || [])[0]) || null;
  advisorBusy = true;
  try {
    const r = await footprintAiAdvise(opsec, { target, runAgent: agent, lastActions: lastAdvisedActions });
    if (r.fired) { lastAdvisedActions = r.actions; footprintAdvice = { risk: r.risk, text: r.text, at: new Date().toISOString() }; try { active._log('footprint.advise', { risk: r.risk }); } catch {} }
  } catch { /* best-effort */ } finally { advisorBusy = false; }
}
setInterval(maybeAdvise, 20000);

let campaign = null;
const pendingApprovals = new Map();   // phaseId -> resolve(bool)
const sseClients = new Set();

// Boot the bundled "Acme Robotics" demo target (localhost only). It gives VARVEL a
// realistic, authorized site to breach so the whole pipeline can be demonstrated
// live — no external target, no API key required.
let demoTarget = null, hardTarget = null;
function startDemoTarget() {
  demoTarget = createDemoTarget();
  demoTarget.on('error', (e) => console.warn(`demo target not started: ${e.message}`));
  demoTarget.listen(DEMO_PORT, '127.0.0.1', () => console.log(`Acme demo target (easy) on http://127.0.0.1:${DEMO_PORT}  (breach it via POST /api/breach-demo)`));
  // The premium HARD target — JWT-forge chain, real defenses. For the tougher test.
  hardTarget = createHardTarget();
  hardTarget.on('error', (e) => console.warn(`hard target not started: ${e.message}`));
  hardTarget.listen(HARD_PORT, '127.0.0.1', () => console.log(`Axiom hard target on http://127.0.0.1:${HARD_PORT}  (breach it via POST /api/campaign/live-hard)`));
}

function broadcast(evt) {
  const line = `data: ${JSON.stringify(evt)}\n\n`;
  for (const c of sseClients) { try { c.write(line); } catch { /* client gone */ } }
}

function startCampaign(o = {}) {
  const mode = o.mode || 'demo';
  // Scope precedence: explicit request → the operator's SIGNED engagement scope →
  // an empty, honestly-unsigned demo scope (never a fabricated person/engagement).
  const scope = o.scope || OPERATOR_SCOPE || { engagement: 'demo', signedBy: null, cidrs: [] };
  // reconOpts.webPorts arrives as an array over JSON -> rehydrate to a Set for the tool.
  const reconOpts = o.reconOpts ? { ...o.reconOpts, webPorts: Array.isArray(o.reconOpts.webPorts) ? new Set(o.reconOpts.webPorts) : undefined } : {};
  // Demo mode = mock agent; live mode = the real governed agent (backend + hook + session).
  const engine = mode === 'demo'
    ? { model: 'mock' }
    : liveEngine(process.env, { sessionFile: o.sessionFile, maxSteps: o.maxSteps, effort: o.effort });
  const opts = {
    engine,
    scope,
    // Top-level maxSteps is the operator's campaign step cap too (not just the agent's):
    // map it when the budget object doesn't carry one (was silently dropped -> the 200 default).
    // Top-level maxNoise is the engagement's noise-point ceiling the same way (a 30-host
    // wildcard recon exhausts the 'normal' 120 otherwise) — maps when budget.maxNoise
    // isn't explicit, exactly like maxSteps.
    budget: (o.budget && Number.isFinite(Number(o.budget.maxSteps)))
      ? { ...o.budget, ...(Number.isFinite(Number(o.budget.maxNoise)) || !Number.isFinite(Number(o.maxNoise)) ? {} : { maxNoise: Number(o.maxNoise) }) }
      : { ...(o.budget || {}), ...(Number.isFinite(Number(o.maxSteps)) ? { maxSteps: Number(o.maxSteps) } : {}), ...(Number.isFinite(Number(o.maxNoise)) ? { maxNoise: Number(o.maxNoise) } : {}) },
    targets: o.targets || [],
    // Restart-resilience (2026-08-29): live campaigns inherit the persisted engagement
    // surface by default, so a restart never wipes earned findings; pass carryForward:false
    // in the launch body for a deliberately fresh look at the estate.
    carryForward: o.carryForward !== undefined ? !!o.carryForward : mode === 'live',
    tooledRecon: !!o.tooledRecon,
    reconOnly: !!o.reconOnly,
    reconOpts,
    stealth: o.stealth !== undefined ? o.stealth : currentStealth, // enforced operational-stealth profile
    // HITL gate timeout: default 15 min (constructor). approveTimeoutMs: 0 parks the
    // gated phase for the operator INDEFINITELY instead of silently skipping it — the
    // 2026-08-29 bykea lesson: a 15-min default let the exploit phase die while the
    // operator was away from the console. Chained/autonomous launches pass 0.
    approveTimeoutMs: Number.isFinite(Number(o.approveTimeoutMs)) && Number(o.approveTimeoutMs) >= 0 ? Number(o.approveTimeoutMs) : undefined,
    // Program-required attestation headers (e.g. X-Hackerone: <handle>) — opt-in per launch.
    extraHeaders: (o.extraHeaders && typeof o.extraHeaders === 'object' && !Array.isArray(o.extraHeaders)) ? o.extraHeaders : null,
    // Build 1: two provisioned accounts for the authorization oracle (IDOR/BOLA sweep
    // inside the countersigned exploit window). { accounts:[{label,cookie|login}], writes?, deletes?, templates? }
    authz: (o.authz && typeof o.authz === 'object' && !Array.isArray(o.authz)) ? o.authz : null,
    // Build 2 (2026-08-30): the hunting-tool lanes — JS/sourcemap mining (recon, default
    // off), OOB callback correlation + DOM-XSS canary (gated exploit). budget.tools rides
    // the budget spread above untouched; each lane skips LOUDLY when its option is absent.
    jsminer: !!o.jsminer,
    jsminerVerify: !!o.jsminerVerify,
    oob: (o.oob && typeof o.oob === 'object' && !Array.isArray(o.oob)) ? o.oob : null,
    browseragent: !!o.browseragent,
    // Build 3 (2026-08-31): the target-scoring ROI layer (default ON under
    // tooledRecon — reorders per-host tool budgets, never skips/hides a host) and
    // the AI/LLM attack-surface lane (detection passive-ish in the gated exploit
    // phase; aiProbe:true arms the canary-proof probes — oracle or no finding).
    targetScore: o.targetScore !== undefined ? !!o.targetScore : undefined,
    aiProbe: !!o.aiProbe,
    aiSurface: o.aiSurface !== undefined ? !!o.aiSurface : undefined,
    guidedSearch: !!o.guidedSearch,    // run the value-guided (LATS) path search before exploitation
    bridgeApproval: mode === 'live',   // relay a countersigned gate to the Enclave approval context
    // Live agent gets identity context + the operating brief; mock/demo needs neither.
    inform: informBlock(OPERATOR) + (mode === 'live' ? '\n\n' + operatingBrief() : ''),
    hooks: {
      approve: (phase) => new Promise((resolve) => pendingApprovals.set(phase.id, resolve)),
      onEvent: (e) => broadcast({ type: 'event', ...e }),
      onSurface: (c) => broadcast({ type: 'surface', status: c.status, counts: c.surface.counts() }),
    },
  };
  // Agent selection: demo -> mock; live -> if a KIMI model is picked, the governed Kimi backend
  // (Kimi's raw API + the SAME hook per tool — `claude -p` hangs on Kimi); else the Claude CLI
  // (host-side, governed, reaches the demo) when available.
  const wsDir = join(homedir(), '.enclave-workspaces', 'varvel-' + String(scope.engagement || 'engagement').replace(/[^a-z0-9._-]/gi, '_').slice(0, 40));
  opts.wsDir = wsDir; // the auto-shelve reads declared scratch-tool bytes out of the same workspace the agent backend uses
  if (mode === 'demo') {
    opts.runAgent = mockAgent;
  } else if (currentProvider || isKimiModel(currentModel)) {
    try { opts.runAgent = makeKimiAgent({ sessionFile: o.sessionFile || process.env.ENCLAVE_SESSION, wsDir, model: currentModel, effort: currentEffort, container: process.env.ENCLAVE_CONTAINER || '', extraEnv: ghostShellEnv(), engagement: scope.engagement || null, provider: currentProvider }); }
    catch (e) { broadcast({ type: 'event', kind: 'backend.error', data: { error: String((currentProvider || 'kimi') + ' backend: ' + String(e.message)) } }); }
  } else if (claudeAvailable()) {
    try { opts.runAgent = makeClaudeAgent({ sessionFile: o.sessionFile || process.env.ENCLAVE_SESSION, wsDir, model: currentModel, extraEnv: ghostShellEnv() }); }
    catch (e) { broadcast({ type: 'event', kind: 'backend.error', data: { error: String(e.message) } }); }
  }
  opts.ghost = ghost; // Ghost Mode: fail-closed gate + proxy agents ride every campaign
  campaign = new Campaign(opts);
  campaign.run().catch((e) => { campaign.status = 'error: ' + e.message; broadcast({ type: 'error', message: e.message }); });
  return campaign;
}

const json = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
const readBody = (req) => new Promise((r) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => { try { r(d ? JSON.parse(d) : {}); } catch { r({}); } }); });

const requestHandler = async (req, res) => {
  const { pathname } = new URL(req.url, 'http://x');

  if (pathname === '/' && req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(readFileSync(APP));
  }
  if (pathname === '/v1' && req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(readFileSync(APP_V1));
  }
  if (pathname === '/v5' && req.method === 'GET') {
    if (!existsSync(APP_V5)) return json(res, 404, { error: 'app-v5 not present' });
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(readFileSync(APP_V5));
  }
  if (pathname === '/v4' && req.method === 'GET') {
    if (!existsSync(APP_V4)) return json(res, 404, { error: 'app-v4 not present' });
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(readFileSync(APP_V4));
  }
  if (pathname === '/v3' && req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(readFileSync(APP_V3));
  }
  if (pathname === '/v2' && req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(readFileSync(APP_V2));
  }
  if (pathname === '/console' && req.method === 'GET') {
    if (!existsSync(CONSOLE)) return json(res, 404, { error: 'console not built' });
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(readFileSync(CONSOLE));
  }
  if (pathname === '/assets/emblem.png') {
    if (!existsSync(EMBLEM)) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': 'image/png' });
    return res.end(readFileSync(EMBLEM));
  }
  if (pathname === '/api/phases') return json(res, 200, { phases: PHASES.map((x) => ({ id: x.id, name: x.name, gate: x.gate })) });

  // Session resilience: checkpointed missions with status (summaries only — checkpoint
  // bodies can carry tool output, so msgs/ledger never leave the store through the API).
  if (pathname === '/api/missions' && req.method === 'GET') {
    try { const { listMissions } = await import('./engine/missions.mjs'); return json(res, 200, { missions: listMissions() }); }
    catch (e) { return json(res, 200, { missions: [], error: String((e && e.message) || e) }); }
  }

  // The autonomous bounty pipeline (engine/bountyline.mjs): roster + per-program pipeline
  // state + ledger totals for the console. Read-only summary here; outcome bookkeeping via
  // POST /api/bountyline/mark. THE PIPELINE NEVER SUBMITS — 'queued' is the end of the
  // line; the send click is the operator's, and no submission route exists to add.
  if (pathname === '/api/bountyline' && req.method === 'GET') {
    try { const { bountylineSummary } = await import('./engine/bountyline.mjs'); return json(res, 200, bountylineSummary()); }
    catch (e) { return json(res, 200, { ok: false, programs: [], pipeline: {}, error: String((e && e.message) || e) }); }
  }
  if (pathname === '/api/bountyline/mark' && req.method === 'POST') {
    const b = await readBody(req);
    try {
      const { markOutcome } = await import('./engine/bountyline.mjs');
      const r = markOutcome(b.program, b.outcome, { amount: b.amount, currency: b.currency, report: b.report, note: b.note });
      return json(res, r.ok ? 200 : 400, r);
    } catch (e) { return json(res, 400, { ok: false, error: String((e && e.message) || e) }); }
  }

  // h1watch (tools/h1watch.mjs — the CLI-only HackerOne opportunity watcher): the
  // fresh-ground summary for the console's bounty view — latest scan time + the event
  // ring ranked by the watcher's OWN report() order (new+bountied first; exclusion
  // moves carry their honor-before-any-contact weight; ?all=1 = the whole ring).
  // Reads ONLY the persisted state.json — the H1 credential (VARVEL_H1_TOKEN) is
  // env-only: this route never reads it, so it can never leak it.
  if (pathname === '/api/h1watch' && req.method === 'GET') {
    try {
      const { report } = await import('./tools/h1watch.mjs');
      const all = new URL(req.url, 'http://x').searchParams.get('all') === '1';
      return json(res, 200, report({ all }));
    } catch (e) { return json(res, 200, { ok: false, events: [], error: String((e && e.message) || e) }); }
  }

  // Who is operating VARVEL, per the signed Enclave handoff. Standalone -> unbound.
  if (pathname === '/api/identity') return json(res, 200, { identity: publicIdentity(OPERATOR), inform: informBlock(OPERATOR) });

  // Natural-language query over the live attack-surface graph.
  if (pathname === '/api/query') {
    if (!campaign) return json(res, 200, { count: 0, matched: [], interpretation: 'no campaign' });
    const q = new URL(req.url, 'http://x').searchParams.get('q') || '';
    return json(res, 200, queryGraph(campaign.surface.toJSON(), q));
  }

  // Attack-path view (the AD tier's thin rung): shortest measured path from current
  // access (footholds) to DA-class principals over the roast/lateral evidence edges.
  if (pathname === '/api/ad-paths') {
    if (!campaign) return json(res, 200, { paths: [], assessed: { sources: 0, daClassPrincipals: 0 }, note: 'no campaign' });
    return json(res, 200, pathsToPrivileged(campaign.surface.toJSON()));
  }

  if (pathname === '/api/campaign' && req.method === 'POST') {
    const b = await readBody(req);
    const c = startCampaign(b);
    return json(res, 200, { ok: true, engagement: c.scope.engagement, status: c.status });
  }

  // Is a LIVE run ready? (backend attached, hook present, signed session in scope)
  if (pathname === '/api/live/readiness') return json(res, 200, liveReadiness({ ...process.env, VARVEL_MODEL: currentModel }, { sessionFile: DEMO_SESSION }));

  // The AI model VARVEL runs — the Settings picker reads/sets it. Changing it re-creates the chat agent.
  if (pathname === '/api/model') {
    if (req.method === 'POST') {
      const b = await readBody(req);
      if (b.model && typeof b.model === 'string') { currentModel = b.model.slice(0, 40); chatAgent = null; }
      if (b.effort && KIMI_EFFORTS.includes(b.effort)) { currentEffort = b.effort; chatAgent = null; }
      if (b.provider !== undefined) {
        // Per-request brain override — validated against the FULL merged config (env +
        // engagement settings) so a broken local-brain pick fails HERE, not mid-mission.
        // ''/null clears back to the platform default. Unknown values refuse with the valid set.
        try {
          const sel = (b.provider === null || b.provider === '') ? null : String(b.provider).slice(0, 40);
          if (sel) resolveBrain({ env: process.env, engagement: (OPERATOR_SCOPE || {}).engagement, request: { provider: sel } });
          currentProvider = sel; chatAgent = null;
        } catch (e) { return json(res, 400, { ok: false, error: String((e && e.message) || e), providers: BRAIN_PROVIDERS }); }
      }
      // Runtime key entry (the console's "Brain / API key" card): { apiKeyEnv, apiKey } sets or
      // clears an IN-MEMORY key for that env var. The value is never written to settings.json,
      // never logged, and never echoed — the response carries presence only. An empty apiKey
      // clears it; the exported environment remains the durable path and always wins.
      if (b.apiKey !== undefined || b.apiKeyEnv !== undefined) {
        const envName = String(b.apiKeyEnv || (brainEcho().apiKeyEnv || '')).trim();
        if (!envName) return json(res, 400, { ok: false, error: 'no apiKeyEnv — name the env var that holds the key (setting brain.apiKeyEnv)' });
        try {
          const present = setRuntimeKey(envName, b.apiKey === undefined ? '' : b.apiKey);
          return json(res, 200, { ok: true, model: currentModel, effort: currentEffort, brain: brainEcho(), key: { env: envName, present } });
        } catch (e) { return json(res, 400, { ok: false, error: String((e && e.message) || e) }); }
      }
      return json(res, 200, { ok: true, model: currentModel, effort: currentEffort, brain: brainEcho() });
    }
    // `efforts` apply to the Kimi models; `kimiModels` lets the UI show the effort picker + a
    // "Kimi backend" chip only for those, and `kimiReady` flags whether a Kimi key is configured.
    return json(res, 200, { model: currentModel, available: MODELS, effort: currentEffort, efforts: KIMI_EFFORTS, kimiModels: KIMI_MODELS, kimiReady: kimiConfig().ok, providers: BRAIN_PROVIDERS, brain: brainEcho() });
  }

  // Channel API (governed callback channel): agents, tasking, artifacts.
  if (pathname.startsWith('/api/channel')) return channelRoutes(pathname, req, res);

  // fporacle (fingerprint self-awareness): the channel's passive JA4H/shape observation
  // ring. Read-only; the observer lives on the channel, so unarmed = nothing to report.
  if (pathname === '/api/fp' && req.method === 'GET') {
    if (!channel || !channel.server) return json(res, 200, { ok: false, error: 'channel not armed -- the fingerprint observer starts with the channel' });
    return json(res, 200, { ok: true, ...channel.fpStatus() });
  }

  // Defender-view pre-flight (gap#8): scan our OWN live listeners the way internet-wide
  // defenders (Censys/Shodan) see them -- cert identity, JA4S, JARM, banners/body
  // markers, egress class -- and report the exposure with house findings + honest gaps.
  // Targets the LIVE configured ports only: this API port, the armed channel port, and
  // the DoH port when that transport is configured and armed. Read-only measurement.
  if (pathname === '/api/preflight' && req.method === 'GET') {
    const { report } = await import('./tools/preflight.mjs');
    const ports = [PORT];
    if (channel && channel.server) {
      ports.push(channel.port);
      const d = typeof channel.dohStatus === 'function' ? channel.dohStatus() : null;
      if (d && d.configured && d.armed && Number.isInteger(d.port) && d.port > 0) ports.push(d.port);
    }
    const rep = await report({ host: '127.0.0.1', ports: [...new Set(ports)] });
    // Audit binding: the engagement audit binds this self-view report by HASH only --
    // reportHash is sha256 over the report JSON. The signed scope itself is NOT mutated
    // by this route; the hash is the binding, exactly that and nothing more.
    const reportHash = createHash('sha256').update(JSON.stringify(rep)).digest('hex');
    return json(res, 200, { ...rep, reportHash });
  }

  // Per-engagement settings engine: validated schema + defaults. GET reads the current
  // values (+schema for the UI); POST sets one key (validated or rejected).
  if (pathname === '/api/settings') {
    if (req.method === 'GET') {
      const eng = new URL(req.url, 'http://x').searchParams.get('engagement') || (OPERATOR_SCOPE && OPERATOR_SCOPE.engagement) || 'default';
      return json(res, 200, { schema: Settings.schema(), current: Settings.for(eng).toJSON() });
    }
    if (req.method === 'POST') {
      const b = await readBody(req);
      const eng = b.engagement || (OPERATOR_SCOPE && OPERATOR_SCOPE.engagement) || 'default';
      try {
        const v = Settings.for(eng).set(b.key, b.value);
        // Secret-class keys (ghc2.token): the response echoes presence, NEVER the value.
        const secret = !!(SETTINGS_SCHEMA[b.key] && SETTINGS_SCHEMA[b.key].secret);
        return json(res, 200, { ok: true, key: b.key, value: secret ? (v ? '<redacted:set>' : '') : v, current: Settings.for(eng).toJSON() });
      } catch (e) { return json(res, 400, { error: String((e && e.message) || e) }); }
    }
  }

  // Ghost Mode API: identity-stealth status + arm/verify. GET = live status (also in
  // /api/state); POST {mode,chain,checkUrl} = configure via settings + verify; POST
  // {action:'check'} = re-run the exit-IP proof; POST {action:'exitCheck'} = the egress
  // pre-flight (exit-IP stability + classification + optional expect-exit pin — the
  // cf_clearance rotation killer, measured BEFORE an engagement). Fail-closed honestly.
  if (pathname === '/api/ghost') {
    const eng = (OPERATOR_SCOPE && OPERATOR_SCOPE.engagement) || 'default';
    if (req.method === 'GET') { await ghost.refreshTor(); return json(res, 200, ghost.status()); }
    if (req.method === 'POST') {
      const b = await readBody(req);
      if (b && b.action === 'check') { await ghost.verify(); await ghost.refreshTor(); return json(res, 200, ghost.status()); }
      if (b && b.action === 'exitCheck') {
        const s = Settings.for(eng);
        await ghost.exitCheck({ expectExit: s.get('ghost.expectExit') || undefined, pinStrict: s.get('ghost.pinStrict') === true });
        return json(res, 200, ghost.status().exitCheck || { error: 'exitCheck unavailable on this build' });
      }
      // TLS-inspection probe (lose-point #5): handshake the reference set
      // (tlsinspect.refs), classify each chain, aggregate the posture — then push the
      // posture into the armed channel so failoverPlan applies tlsinspect.policy.
      if (b && b.action === 'tlsinspect') {
        const s = Settings.for(eng);
        const refs = (b.refs !== undefined && b.refs !== null && String(b.refs).trim()) ? b.refs : s.get('tlsinspect.refs');
        const r = await ghost.tlsCheck({ refs });
        try { if (channel && channel.server) channel.setTlsInspection(r.posture, { policy: s.get('tlsinspect.policy'), refs: r.refs.map((x) => ({ ref: x.ref, verdict: x.verdict })), source: 'ghost.tlsCheck' }); } catch { /* posture push never breaks the probe */ }
        return json(res, 200, r);
      }
      try {
        if (b.mode !== undefined) Settings.for(eng).set('ghost.mode', b.mode);
        if (b.chain !== undefined) Settings.for(eng).set('ghost.chain', b.chain);
        if (b.checkUrl !== undefined) Settings.for(eng).set('ghost.checkUrl', b.checkUrl);
        return json(res, 200, await armGhostFromSettings(eng));
      } catch (e) { return json(res, 400, { error: String((e && e.message) || e) }); }
    }
  }

  // Posture scorecard: grade a target's defensive posture 0-100 against real measured
  // references (stripe/github/cloudflare — snapshots dated 2026-07-30 — and our practice
  // targets). Benchmark new tools against references of known hardness.
  if (pathname === '/api/posture') {
    const q = new URL(req.url, 'http://x').searchParams;
    const url = q.get('url') || q.get('target');
    const benchmark = q.get('benchmark') || null;
    if (!url) return json(res, 400, { error: 'pass ?url=<target base URL>' });
    try {
      const fp = await detectStack(url, { timeout: 2500 });
      return json(res, 200, { target: url, ...comparePosture(fp, benchmark) });
    } catch (e) { return json(res, 200, { target: url, error: String((e && e.message) || e), mine: { score: 0, grade: 'unreachable' }, against: [] }); }
  }

  // The tool shelf: persistence for tools the AI writes on the fly. Entries are DATA —
  // quarantined until a human promotes them for a reviewed native port (promotion is
  // logged; nothing on the shelf is ever executed by VARVEL).
  if (pathname === '/api/toolshelf') {
    if (req.method === 'GET') return json(res, 200, { entries: shelfList() });
    if (req.method === 'POST') {
      const b = await readBody(req);
      if (b.action === 'promote') {
        const e = promoteTool(b.id, { by: b.by || 'operator', note: b.note });
        return json(res, e ? 200 : 404, e || { error: 'no such shelf id' });
      }
      try {
        const e = shelveTool({ ...b, origin: { ...(b.origin || {}), agent: (b.origin && b.origin.agent) || currentModel } });
        return json(res, 200, { ok: true, entry: e });
      } catch (err) { return json(res, 400, { error: String((err && err.message) || err) }); }
    }
  }

  // attackbench (engine/attackbench + tools/attackbench): the ATT&CK emulation-coverage
  // benchmark — offline, honest (exists = code on disk, planned = documented, else a
  // named gap), read-only. Coverage is CAPABILITY, never detection; the non-claim rides.
  if (pathname === '/api/attackbench' && req.method === 'GET') {
    const r = attackbenchReport();
    return json(res, r.ok ? 200 : 500, r);
  }

  // The Enclave's disposable Win11 VM-lab target — so VARVEL can point a governed campaign at
  // the high-fidelity range ("test anything we make against the Win11 VM"). Boot the lab from
  // the Enclave console first (VM-lab workload), then launch here with the lab /24 in scope.
  if (pathname === '/api/vm-target') {    try {
      const available = vmLabAvailable();
      return json(res, 200, {
        available,
        targetIp: available ? vmLabTargetIp() : null,
        targetOs: 'Windows 11 Pro (Defender on)',
        scopeCidr: '192.168.50.0/24',
        note: available
          ? 'Boot the lab from the Enclave console (VM-lab workload), then launch a campaign at this IP with the lab /24 inside the signed scope.'
          : 'VM-lab not available on this host (vmrun or the lab VMX files are missing).',
      });
    } catch (e) { return json(res, 200, { available: false, targetIp: null, error: String((e && e.message) || e) }); }
  }

  // The SOC console for the VARVEL-booted Axiom — the blue team's alert feed, served from
  // the SAME process that owns the target instance (running a separate standalone target
  // split the console from the instance the agent was actually attacking).
  if (pathname === '/api/soc') {
    if (!hardTarget || !hardTarget.soc) return json(res, 200, { available: false, alerts: [], summary: 'no SOC target booted' });
    return json(res, 200, { available: true, alerts: hardTarget.soc.alerts(), state: hardTarget.soc.state(), summary: hardTarget.soc.summary() });
  }
  if (pathname === '/soc') {
    if (!hardTarget || !hardTarget.soc) { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<body style="font:14px system-ui;background:#0d1420;color:#dbe4f0;padding:28px">No SOC target booted.</body>'); }
    const esc2 = (s) => String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
    const rows = hardTarget.soc.alerts().slice().reverse().map((e) =>
      `<tr><td style="font-family:monospace">${e.at.slice(11, 19)}</td><td><b>${e.type.toUpperCase()}</b></td><td>${esc2(e.ip || '')}</td><td>${esc2(e.reason || e.note || e.status || '')}</td></tr>`).join('');
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(`<!doctype html><title>Axiom SOC</title><body style="font:14px system-ui;background:#0d1420;color:#dbe4f0;padding:28px">
<h2>◈ Axiom SOC — blue team alert feed</h2><p style="color:#8fa2bd">${esc2(hardTarget.soc.summary())}</p>
<p style="color:#8fa2bd;font-size:12px"><a href="/api/soc" style="color:#7db4ff">JSON</a> · refreshes every 4s</p>
<table cellpadding="7" style="border-collapse:collapse">${rows || '<tr><td style="color:#5c6b84">no alerts yet — the SOC is watching</td></tr>'}</table>
<script>setTimeout(()=>location.reload(),4000)</script></body>`);
  }

  // The operational-stealth profile the NEXT campaign runs under. Enforced pacing (native
  // tools serialize + jitter in code) + a tracked noise budget with an after-action proof.
  // 'loud'/null = no ceiling. Beats RedAmon: enforcement, not a prompt suggestion.
  if (pathname === '/api/stealth') {
    if (req.method === 'POST') {
      const b = await readBody(req);
      const v = typeof b.stealth === 'string' ? b.stealth : b.profile;
      if (v === null || v === '' || v === 'loud') currentStealth = null;
      else if (v === 'auto') currentStealth = 'auto'; // fingerprint the target + calibrate at run start
      else if (typeof v === 'string' && STEALTH_PROFILES[v]) currentStealth = v;
      return json(res, 200, { ok: true, stealth: currentStealth });
    }
    // Expose the profile catalog (pacing + budget posture) so the console can explain each.
    // 'auto' is listed first: it fingerprints the target's defenses and picks the profile.
    const profiles = [
      { name: 'auto', label: 'auto', concurrency: null, delayMs: null, jitterMs: null, note: 'fingerprint the target (WAF/CDN/rate-limit) and auto-pick the quietest fitting profile', budget: { maxNoise: null, peakCeiling: null } },
      ...STEALTH_NAMES.map((n) => ({ name: n, ...STEALTH_PROFILES[n], budget: { maxNoise: BUDGET_PRESETS[n] ? BUDGET_PRESETS[n].maxNoise : null, peakCeiling: BUDGET_PRESETS[n] ? BUDGET_PRESETS[n].peakCeiling : null } })),
    ];
    return json(res, 200, { stealth: currentStealth, available: ['auto', ...STEALTH_NAMES], profiles });
  }

  // One-click LIVE AI breach of the demo: the real governed agent (backend + hook)
  // drives the full pipeline against the demo, under the loopback-scoped demo session.
  // Native tooled recon seeds the surface; the agent validates, exploits (HITL-gated —
  // uses the banner write), and cleans up. Recon works with no container; the agent's
  // network tools need the container tier (readiness says so).
  if (pathname === '/api/campaign/live-demo' && req.method === 'POST') {
    const r = liveReadiness(process.env, { sessionFile: DEMO_SESSION });
    if (!r.backend) return json(res, 400, { ok: false, reason: 'no model backend attached — subscribe to Kimi K3 or set a key', readiness: r });
    const c = startCampaign({
      mode: 'live',
      sessionFile: DEMO_SESSION,             // loopback-scoped signed identity (127.0.0.0/8)
      tooledRecon: true,                     // native recon seeds the surface (reaches the demo, no container needed)
      guidedSearch: true,                    // tree-guided (LATS) probe selection before the exploit phase
      targets: ['127.0.0.1'],
      scope: { engagement: 'DEMO-ACME', signedBy: 'demo · Red-Team-Lead · L4 (loopback)', cidrs: ['127.0.0.0/8'] },
      reconOpts: { ports: [DEMO_PORT], webPorts: [DEMO_PORT], timeout: 2000, web: { paths: [...DEFAULT_PATHS, '/backup/', '/backup/db.sql'] } },
    });
    return json(res, 200, { ok: true, live: true, target: `http://127.0.0.1:${DEMO_PORT}`, engagement: c.scope.engagement, status: c.status, readiness: r });
  }

  // One-click LIVE AI breach of the HARD target (Axiom): agent-driven — the JWT-forge
  // chain is beyond native tools, so the agent must read app.js → the leaked legacy
  // bundle → forge an admin token → change content. A genuinely hard autonomous test.
  if (pathname === '/api/campaign/live-hard' && req.method === 'POST') {
    const r = liveReadiness(process.env, { sessionFile: DEMO_SESSION });
    if (!r.backend) return json(res, 400, { ok: false, reason: 'no model backend attached', readiness: r });
    const c = startCampaign({
      mode: 'live',
      sessionFile: DEMO_SESSION,
      tooledRecon: true,
      guidedSearch: true,
      targets: ['127.0.0.1'],
      scope: { engagement: 'DEMO-AXIOM (hard)', signedBy: 'demo · L4 (loopback)', cidrs: ['127.0.0.0/8'] },
      reconOpts: { ports: [HARD_PORT], webPorts: [HARD_PORT], timeout: 2000, web: { paths: [...DEFAULT_PATHS, '/login', '/dashboard', '/admin', '/docs', '/assets/app.js', '/assets/legacy/auth.bundle.js', '/api/session', '/api/health'] } },
    });
    return json(res, 200, { ok: true, live: true, target: `http://127.0.0.1:${HARD_PORT}`, engagement: c.scope.engagement, status: c.status, readiness: r });
  }

  // One-click live breach of the bundled Acme demo target: a REAL tooled recon +
  // web content discovery sweep (no mock, no API key). Populates the live surface.
  if (pathname === '/api/breach-demo' && req.method === 'POST') {
    const c = startCampaign({
      mode: 'demo',
      reconOnly: true,
      tooledRecon: true,
      targets: ['127.0.0.1'],
      scope: { engagement: 'DEMO-ACME', signedBy: 'demo (local target)', cidrs: ['127.0.0.0/8'] },
      reconOpts: { ports: [DEMO_PORT], webPorts: [DEMO_PORT], timeout: 2000, web: { paths: [...DEFAULT_PATHS, '/backup/', '/backup/db.sql'] } },
    });
    return json(res, 200, { ok: true, target: `http://127.0.0.1:${DEMO_PORT}`, engagement: c.scope.engagement, status: c.status });
  }

  // Primary poll: full campaign state (surface + opsec + activity + budget).
  if (pathname === '/api/state') {
    const active = campaign || chatCampaign; // the chat feeds its own surface when no pipeline is running
    const base = active
      ? { ...active.getState(), status: campaign ? campaign.status : (chatBusy ? 'running:interactive' : 'interactive'), pendingApproval: [...pendingApprovals.keys()][0] || null }
      : { status: 'idle' };
    // Validator-gate v2 staleness render: validated-but-old findings surface as stale in
    // the console API. annotateValidation returns NEW node objects — the stored state
    // vocabulary (validated|refuted|untestable) is never rewritten for a rendering.
    if (base && base.surface && Array.isArray(base.surface.nodes)) {
      const eng = (OPERATOR_SCOPE && OPERATOR_SCOPE.engagement) || 'default';
      base.surface = { ...base.surface, nodes: annotateValidation(base.surface.nodes, { staleDays: Settings.for(eng).get('validator.staleDays') }) };
    }
    return json(res, 200, { ...base, messages: chatMessages, agentThinking: chatBusy, footprintAdvice, ghost: ghost.status() });
  }
  // External state store (engine/statestore.mjs): structured, provenance-tracked engagement
  // knowledge — hosts/creds/sessions/findings — REDACTED on the way out (cred secrets and
  // session tokens never leave the store over the API; reveal is the operator-side CLI only).
  // NOTE: '/api/state' above is the long-standing CAMPAIGN poll, so the store answers here.
  if (pathname === '/api/statestore' && req.method === 'GET') {
    const eng = new URL(req.url, 'http://x').searchParams.get('engagement') || (OPERATOR_SCOPE && OPERATOR_SCOPE.engagement) || 'default';
    return json(res, 200, { engagement: eng, counts: stateCounts(eng), state: redactState(loadEngagementState(eng)) });
  }
  // On-demand OPSEC AI advice (the "advise now" button) — same event-driven advisor.
  if (pathname === '/api/footprint/advise' && req.method === 'POST') {
    const active = campaign || chatCampaign;
    if (!active) return json(res, 200, { fired: false, reason: 'no campaign' });
    const agent = ensureAdvisorAgent();
    if (!agent) return json(res, 400, { fired: false, reason: 'no model backend' });
    const opsec = active.opsec.toJSON();
    const target = (active.targets && active.targets[0]) || null;
    const r = await footprintAiAdvise(opsec, { target, runAgent: agent }); // no lastActions -> force a fresh look
    if (r.fired) { footprintAdvice = { risk: r.risk, text: r.text, at: new Date().toISOString() }; try { active._log('footprint.advise', { risk: r.risk, manual: true }); } catch {} }
    return json(res, 200, r);
  }
  if (pathname === '/api/surface') {
    if (!campaign) return json(res, 200, { status: 'idle', surface: null });
    return json(res, 200, { status: campaign.status, surface: campaign.surface.toJSON() });
  }
  if (pathname === '/api/opsec') {
    if (!campaign) return json(res, 200, { opsec: null });
    return json(res, 200, campaign.opsec.toJSON());
  }
  if (pathname === '/api/remediation') {
    if (!campaign) return json(res, 200, { remediation: [] });
    return json(res, 200, { remediation: remediation(campaign.surface.toJSON()) });
  }
  // Auto-remediation: triage (deterministic, ranked by exploitability) + governed code-fix.
  if (pathname === '/api/triage') {
    const active = campaign || chatCampaign;
    return json(res, 200, active ? triage(active.surface.toJSON()) : { count: 0, items: [] });
  }
  // The validator gate's explicit reproduction pass: validate ONE finding by index (or
  // node id / ref) with the lightest objective oracle available (http-class → ONE governed,
  // paced re-read riding ghost/scope, both fail-closed). NEVER auto-fired — the operator
  // clicks it in the console or the AI calls it per finding; REFUTED is a first-class
  // outcome. This is the same endpoint the console's per-finding "validate" action uses.
  if (pathname === '/api/validate' && req.method === 'POST') {
    const b = await readBody(req);
    const active = campaign || chatCampaign;
    if (!active) return json(res, 400, { ok: false, error: 'no campaign' });
    const sel = b.index !== undefined ? b.index : (b.id !== undefined ? b.id : b.ref);
    if (sel === undefined) return json(res, 400, { ok: false, error: 'pass {index}, {id} or {ref}' });
    try {
      const r = await active.validateFinding(sel);
      return json(res, r.ok ? 200 : 404, r);
    } catch (e) { return json(res, 500, { ok: false, error: String((e && e.message) || e) }); }
  }
  if (pathname === '/api/remediate' && req.method === 'POST') {
    const b = await readBody(req);
    const active = campaign || chatCampaign;
    if (!active) return json(res, 400, { ok: false, reason: 'no campaign' });
    if (!b.repoDir || !existsSync(b.repoDir)) return json(res, 400, { ok: false, reason: 'repoDir required and must exist on disk' });
    if (!claudeAvailable()) return json(res, 400, { ok: false, reason: 'no code-fix backend (Claude CLI)' });
    const agent = makeClaudeAgent({ sessionFile: process.env.ENCLAVE_SESSION || DEMO_SESSION, wsDir: b.repoDir, model: process.env.VARVEL_MODEL || 'sonnet', extraEnv: ghostShellEnv() });
    const r = await codeFixAgent(agent, { surface: active.surface.toJSON(), repoDir: b.repoDir, openPr: !!b.openPr });
    return json(res, 200, r);
  }
  if (pathname === '/api/report') {
    if (!campaign) return json(res, 200, { report: null });
    const eng = (OPERATOR_SCOPE && OPERATOR_SCOPE.engagement) || 'default';
    res.writeHead(200, { 'content-type': 'text/markdown; charset=utf-8' });
    return res.end(renderReport(campaign.surface.toJSON(), { productivity: productivity(campaign.assessments), opsec: campaign.opsec.toJSON(), stealthBudget: campaign.noise.status(), targetProfile: campaign.targetProfile, toolsBudget: campaign.toolBudget, coverage: campaign.coverage ? { ...campaign.coverage.status(), verdict: campaign.coverageVerdict } : null, staleDays: Settings.for(eng).get('validator.staleDays') }));
  }

  if (pathname === '/api/approve' && req.method === 'POST') {
    const b = await readBody(req);
    const resolve = pendingApprovals.get(b.phase);
    if (!resolve) return json(res, 404, { ok: false, reason: 'no pending approval for ' + b.phase });
    pendingApprovals.delete(b.phase);
    resolve(!b.deny);
    return json(res, 200, { ok: true, phase: b.phase, signed: !b.deny });
  }
  if (pathname === '/api/opsec/cleanup' && req.method === 'POST') {
    const b = await readBody(req);
    if (!campaign) return json(res, 404, { ok: false });
    const ok = campaign.opsec.markClean(b.index, b.note);
    return json(res, ok ? 200 : 404, { ok, posture: campaign.opsec.posture() });
  }
  if (pathname === '/api/message' && req.method === 'POST') {
    const b = await readBody(req);
    const text = String(b.text || '').slice(0, 4000);
    if (!text) return json(res, 200, { ok: true });
    chatMessages.push({ who: 'operator', text, at: new Date().toISOString() });
    if (chatMessages.length > 60) chatMessages.splice(0, chatMessages.length - 60);
    const agent = ensureChatAgent();
    if (!agent) { chatMessages.push({ who: 'agent', text: '(No model backend attached — install/login the Claude CLI or set a key to chat with the agent.)', at: new Date().toISOString() }); return json(res, 200, { ok: true }); }
    if (chatBusy) { chatMessages.push({ who: 'agent', text: '(Still working on the previous message — one turn at a time.)', at: new Date().toISOString() }); return json(res, 200, { ok: true, busy: true }); }
    chatBusy = true;
    // The agent message accumulates STEPS (thinking / tool calls / results) live via onStep.
    const agentMsg = { who: 'agent', text: '', steps: [], pending: true, at: new Date().toISOString() };
    chatMessages.push(agentMsg);
    const camp = ensureChatCampaign();
    // Show the AGENT its own noise posture (self-steering, not a separate agent): the
    // footprint panel advises the operator; this note advises the model. When it's
    // getting loud it should shift to quiet methods on its own.
    const nb = camp.noise.status();
    const noiseNote = '\n\nCURRENT NOISE POSTURE (live): ' + (nb.maxNoise === Infinity
      ? `${nb.spent} noise pts so far across ${nb.actions} target actions (no budget ceiling in this interactive session — the operator sees every action in the OPSEC panel).`
      : `${nb.spent}/${nb.maxNoise} noise pts (${nb.pct}%).`)
      + (nb.actualPeak >= 3 || nb.pct >= 50 ? ' You are getting LOUD — prefer passive/quiet methods (crawl, link-following, targeted single requests) over sweeps and brute force, and make every loud action earn its noise.' : ' Stay proportionate: quietest method that answers the question first.')
      + ' When the operator asks a question (e.g. "did the breach work?"), answer THE QUESTION directly and concisely — verdict first (yes/no + the one fact that proves it), then one or two lines of evidence referenced by path/URL, then the next step. NEVER paste whole files, pages, or payloads as your reply; the thread already shows them.'
      + '\n\nNATIVE TOOLS (reviewed, tested, content-verified — use these INSTEAD of hand-writing throwaway scripts): run from the workspace as  node varvel-tools/tools/cli.mjs <cmd> …\n'
      + '  ghost — IDENTITY SELF-CHECK, run it FIRST: the enclave denies raw curl to proxies/IP-echo hosts (egress is research-allowlist-only), so ghost verification rides the server via this command. Never try to curl the proxy or an IP-echo service yourself.\n'
      + '  crawl <baseUrl> [maxPages] · apisurface <baseUrl> · vulncheck <baseUrl> · ssrf "<endpoint with {URL}>" · jwt-decode <token> · jwt-forge "<claimsJson>" <recoveredKey> · jwt-verify <token> <key> · chainrun <chainFile.json> · posture <baseUrl>\n'
      + '  floworacle <agentId> | floworacle profile <name> (cadence pre-flight) · tradecraft <agentId> | tradecraft check <jsonArray> (grade YOUR OWN planned commands) · fporacle ja4s <host> <port> | fporacle http · preflight [host] [ports]\n'
      + '  CHALLENGE TIER (Cloudflare-class defenses): cfcheck <url> (classify ONE response: managed-js/turnstile/captcha/block-1020/rate-limit/labyrinth/none + evidence) · cfmap <baseUrl> (paced per-path posture map; unchallenged paths = findings; a labyrinth-suspect STOPS the map — never follow those links) · originintel <domain> (PASSIVE origin discovery; candidates get NO contact until scope-signed) · egressbench <url> [n] [egresses] (measured challenge rate per egress — a measurement, never a claim) · cfetch <url> (browser fingerprint parity; honestly unsupported without a curl-impersonate binary) · clearance mint <url> (stealth-browser cf_clearance mint — opens a VISIBLE browser window, proven before vaulted) · clearance status [url]. Doctrine: you never claim "bypassed Cloudflare" — only "passed challenge on zone X, config Y, date Z".\n'
      + 'They are governed the same as everything else you do (scope + audit). Prefer them over ad-hoc code; write new code only for things they genuinely cannot do.'
      + '\n\nADAPTIVE-DEFENSE DOCTRINE (this target has a live SOC): prove impact with MINIMAL privileged contact (one write + one revert inside the defender\'s reaction window). Session lifecycle matters: an admin-class action from a source with NO legitimate login is the exact anomaly a SOC hunts (impossible session) — if the target offers a legitimate low-privilege account, establish that session FIRST (log in once), then escalate via the weakness; never jump straight to a privileged action from a cold session. Read the defense: 429 = slow down; uniform 403s with a reference id = change shape or stop; a credential that worked and now fails = the defender ROTATED or revoked it — STOP using it immediately (every retry is another alert), verify liveness once, re-check the source for a changed key, then re-derive or switch weakness class. Never hammer a dead technique. If you are clearly burned, say so honestly — a detected engagement is a result, not a failure.'
      + '\n\nNOISE SELF-RATING: in your closing summary, rate your own stealth honestly (A = barely-visible single-digit noise, B = restrained, C = noticeable, D = loud) with the one change that would have made you quieter. The operator sees the same numbers you do.';
    // IDENTITY POSTURE: Ghost Mode state in the agent's brief — the guarantee layer. The agent
    // must know whether its egress is identity-masked, and the rule is absolute: in 'required'
    // mode it never bypasses the chain — if a method can't ride the proxy, it says so instead
    // of going direct. Private/range destinations stay direct by design (nothing to hide from).
    const gs = ghost.status();
    const ghostNote = '\n\nIDENTITY POSTURE (Ghost Mode): '
      + (gs.mode === 'off'
        ? 'OFF — your egress exposes the operator\'s real source to the target. If the operator asks for identity hiding, Ghost Mode is armed via /api/ghost (mode + proxy chain), and the platform verifies the exit IP is not the operator\'s before any public egress.'
        : `${gs.mode.toUpperCase()} — egress routes through a ${gs.hops}-hop proxy chain (${gs.chain.join(' → ')}); DNS is resolved by the last proxy (no local DNS leak). ${gs.verified ? (gs.verified.ok ? `VERIFIED hidden: exit IP ${gs.verified.exitIp} ≠ operator egress. ` : `NOT VERIFIED (${gs.verified.error || 'pending'}) — `) : 'UNVERIFIED — '}`
        + (gs.mode === 'required' ? 'FAIL-CLOSED: public egress is refused until verification passes — never bypass the chain; if a method cannot ride the proxy, say so instead of going direct. ' : 'best-effort: keep public traffic on ghost-covered paths (the native tools ride the chain); flag anything that cannot. ')
        + 'Private/range destinations (RFC1918, loopback — e.g. 192.168.50.0/24) go direct by design: the lab is sealed, there is no external identity to expose. Never claim identity protection you have not verified — if asked, quote this posture exactly.');
    // OPSEC ADVISOR → agent loop closure: the advisor's advice used to be operator-facing
    // only (the footprint panel) while the agent making the noise never heard it (gap Jack
    // spotted). Inject the latest advice into the brief when fresh (15min), clearly labeled
    // ADVISORY — the model weighs it against the mission; it is not a command.
    const adv = footprintAdvice;
    const advisorNote = (adv && adv.at && (Date.now() - Date.parse(adv.at) < 15 * 60 * 1000))
      ? '\n\nOPSEC ADVISOR (latest, advisory — weigh it, never obey blindly): [' + String(adv.risk || 'n/a').toUpperCase() + '] ' + String(adv.text || '').slice(0, 500)
      : '';
    // EXTERNAL STATE STORE → brief: structured, provenance-tracked engagement knowledge
    // (live sessions > cred meta > validated findings > claimed findings > hosts). The
    // agent's conversation memory fades past ~5 steps; this store does not — so it is told
    // to trust THIS over its memory. Secrets are never injected (cred meta only).
    const stateEng = (((campaign || camp).scope || {}).engagement) || (OPERATOR_SCOPE && OPERATOR_SCOPE.engagement) || 'default';
    let stateNote = '';
    try { const sl = stateBriefSlice(stateEng, 1200); if (sl) stateNote = '\n\nSTATE (structured, provenance-tracked — trust this over your memory):\n' + sl; } catch { /* state store unreadable — the brief goes without it */ }
    const brief = operatingBrief() + '\n\n' + informBlock(OPERATOR) + noiseNote + ghostNote + advisorNote + stateNote + (campaign ? '\n\n' + campaign._surfaceBriefing() : '\n\n' + camp._surfaceBriefing() + '\n\nNo pipeline campaign is running — this is an interactive session. To assess or breach a target, run your own reconnaissance first with your tools, staying within the signed scope. When you change something, make it minimal and reversible; revert it afterward UNLESS the operator asks you to LEAVE it in place for verification — then leave it exactly as they asked and note it for cleanup. Answer status questions from the SURFACE STATE above and your own step history — if you achieved admin access and proved a change, say so plainly, even if you later lost access. Follow the operator\'s explicit instructions.');
    // Footprint the interactive path too: a chat-driven action against the target makes the
    // SAME noise as a campaign one — before this, interactive runs showed 0 footprint (a real
    // gap Jack spotted mid-test). Classification mirrors the hook's: scanners → tcp-scan,
    // exploit tooling → exploit-attempt, http(s) to an in-scope/private host → http-fingerprint.
    const chargeToolNoise = (step) => {
      if (step.kind !== 'tool' || step.name !== 'Bash') return;
      let cmd = '';
      try { cmd = String(JSON.parse(step.detail || '{}').command || ''); } catch {}
      if (!cmd) return;
      const low = cmd.toLowerCase();
      let kind = null;
      if (/\b(nmap|masscan|zmap|rustscan|unicornscan)\b/.test(low)) kind = 'tcp-scan';
      else if (/\b(msfconsole|metasploit|sqlmap|hydra|mimikatz|crackmapexec|impacket)\b/.test(low)) kind = 'exploit-attempt';
      else if (/https?:\/\/(10\.|127\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(low)) kind = 'http-fingerprint';
      if (kind) { try { camp._noise({ kind, host: (low.match(/https?:\/\/([0-9.]+)/) || [])[1] || null }); } catch {} }
    };
    // Log each tool call to the activity feed LIVE as it happens (so the console shows moves).
    // Retry/checkpoint/split events ride the same feed — a backend retry is mission noise and
    // is NEVER silent (a quiet retry would falsify the noise record the OPSEC panel shows).
    const onStep = (step) => {
      agentMsg.steps.push(step);
      if (agentMsg.steps.length > 240) agentMsg.steps.splice(0, agentMsg.steps.length - 240);
      chargeToolNoise(step);
      if (step.kind === 'tool') { try { camp._log('agent.tool', { name: step.name, detail: (step.detail || '').slice(0, 80) }); } catch {} }
      if (step.kind === 'retry') { try { camp._log('agent.retry', { attempt: step.attempt, maxAttempts: step.maxAttempts, waitMs: step.waitMs, error: step.error }); } catch {} }
      if (step.kind === 'checkpoint' || step.kind === 'split') { try { camp._log('agent.' + step.kind, { text: (step.text || '').slice(0, 160) }); } catch {} }
    };
    // Give the governed agent CONVERSATION CONTINUITY: PRIOR exchanges travel with the turn
    // (truncated), so "continue" actually continues. The CURRENT operator instruction is not
    // history — it rides LAST and IN FULL (bounded only by the 4000-char receipt cap).
    // (Bug found 2026-08-10: the old slice(0,-1) swept the current message into history and
    // gutted a 2951-char mission brief at exactly 1500 chars, mid-word — the AI reported the
    // truncation byte-exactly. Priors are capped; the active instruction never is.)
    const prior = chatMessages.slice(0, -2).slice(-8).map((m) => ({
      role: m.who === 'agent' ? 'assistant' : 'user',
      content: String(m.text || '(see prior steps)').slice(0, 1500),
    }));
    const current = chatMessages[chatMessages.length - 2];
    const history = [...prior, { role: 'user', content: String((current && current.text) || '') }];
    agent({ system: brief, messages: history, resumeId: chatSessionId, onStep })
      .then((r) => {
        chatSessionId = r.sessionId || chatSessionId;
        // Always close with an HONEST status, never a hollow "(no summary)": a turn-cap
        // stop mid-work says exactly that (and how to continue); a backend error says so too.
        agentMsg.text = r.text
          || (r.hitTurnCap ? `(Reached the turn cap (${r.maxTurns || 'N'} tool turns) mid-work — the last actions are in the steps above. Send "continue" to keep going from here.)`
          : (r.steps > 0 ? '(Turn ended without a closing summary — see the steps above for what was actually done.)' : '(no summary)'));
        agentMsg.denials = (r.denials && r.denials.length) || 0;
        agentMsg.pending = false;
        // Feed the graph from what the agent found (findings/hosts/endpoints in its JSON block).
        try { camp._ingest('chat', parseJsonBlock(r.text)); } catch { /* best-effort */ }
      })
      .catch((e) => { agentMsg.text = '(agent error: ' + ((e && e.message) || e) + ')'; agentMsg.pending = false; })
      .finally(() => { chatBusy = false; });
    return json(res, 200, { ok: true, thinking: true });
  }

  // Live event stream for the console (Server-Sent Events).
  if (pathname === '/api/events') {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
    res.write('retry: 3000\n\n');
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
    return;
  }

  res.writeHead(404); res.end('not found');
};

createServer(requestHandler).listen(PORT, process.env.VARVEL_API_BIND || '127.0.0.1', () => {
  console.log(`VARVEL service on http://${process.env.VARVEL_API_BIND || 'localhost'}:${PORT}  (console at /, API at /api/*) — loopback-only by default (VARVEL_API_BIND overrides; the operator's PC must never expose the console to the LAN)`);
  const who = OPERATOR.bound ? `${OPERATOR.principal} · ${OPERATOR.role || '?'} · L${OPERATOR.clearance ?? '?'}${OPERATOR.verified ? '' : ' (UNVERIFIED)'}` : 'standalone (no bound operator)';
  console.log(`Operator: ${who}${OPERATOR_SCOPE ? '  · signed scope ' + OPERATOR_SCOPE.cidrs.join(', ') : ''}`);
  startDemoTarget();
  // Ghost Mode: arm from persisted settings (a 'required' mode is fail-closed from boot).
  armGhostFromSettings((OPERATOR_SCOPE && OPERATOR_SCOPE.engagement) || 'default')
    .then((s) => { if (s.mode !== 'off') console.log(`Ghost Mode: ${s.mode} · ${s.hops} hop(s) · verified=${s.verified ? s.verified.ok : false}`); })
    .catch((e) => console.log('Ghost Mode arm failed: ' + ((e && e.message) || e)));
});

// Lab bind: the range's agents register through THIS api (va-boot -> http://192.168.50.1:8971).
// The console stays loopback-only by default; the SAME handler is exposed on the lab NIC only
// when the range spawn says so (VARVEL_CHANNEL_BIND — the env that also binds the C2 channel).
// Without this, the loopback hardening severed va-boot's registration path (regression, 2026-08-05).
if (process.env.VARVEL_CHANNEL_BIND) {
  createServer(requestHandler).listen(PORT, process.env.VARVEL_CHANNEL_BIND, () => console.log('VARVEL service also on http://' + process.env.VARVEL_CHANNEL_BIND + ':' + PORT + '  (lab NIC — agent registration path, gated on VARVEL_CHANNEL_BIND)'));
}
