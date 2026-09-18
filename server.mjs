#!/usr/bin/env node
// server.mjs — run the Enclave console LIVE, attached to YOUR Claude CLI.
//
//   node server.mjs                         → attaches to your `claude` CLI (no API key; uses your login)
//   ENCLAVE_MODEL=haiku node server.mjs     → cheaper/faster model for iterating
//   ANTHROPIC_API_KEY=…   node server.mjs   → falls back to the API broker if the CLI isn't found
//
// In CLI mode, every chat turn spawns real `claude -p` inside a sealed, per-operator
// workspace, governed by the Enclave PreToolUse hook → Cedar. Every tool call the model
// makes is allowed or denied by the operator's SIGNED clearance (not by anything the
// model says), and each decision is appended to the hash-chained audit ledger.
// This is the product thesis, running for real — the console you can actually test.

import http from 'node:http';
import https from 'node:https';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname, normalize, basename, delimiter } from 'node:path';
import { homedir } from 'node:os';
import { runGovernedAgent, normalizeKimiModel } from './agent-backend.mjs';
import { labUp, labDown, cleanupOrphans, vmLabAvailable, kaliShellEnv, vmLabTargetIp, labStatus } from './vm-lab.mjs';

const ROOT   = process.env.ENCLAVE_ROOT || dirname(fileURLToPath(import.meta.url));
const PORT   = Number(process.env.PORT) || 8977;
const MODEL  = process.env.ENCLAVE_MODEL || 'sonnet';
const SEAM   = join(ROOT, 'poc', 'enforcement-seam');
const HOOK   = join(SEAM, 'hook', 'pretooluse-hook.mjs');
const LEDGER = join(SEAM, 'audit-ledger.jsonl');
// Sealed workspaces live OUTSIDE the product tree — never nested in this repo, or the
// AI's `git`/`cat` would walk up into Enclave's own source. Each gets its own git init.
const LIVE   = process.env.ENCLAVE_WORKSPACES || join(homedir(), '.enclave-workspaces');
const WIN    = process.platform === 'win32';
const fwd    = p => p.replace(/\\/g, '/');   // forward-slash path (JSON-safe + claude.exe-safe)

const MIME = { '.html':'text/html', '.js':'text/javascript', '.css':'text/css', '.json':'application/json', '.svg':'image/svg+xml', '.md':'text/markdown' };
const send = (res, code, body, type='application/json') => { res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store' }); res.end(body); };

// locate the claude CLI (native exe on Windows, script elsewhere)
function findClaude() {
  const r = spawnSync(WIN ? 'where' : 'which', ['claude'], { encoding: 'utf8', windowsHide: true });
  if (r.status === 0) { const line = (r.stdout || '').split(/\r?\n/).map(s => s.trim()).find(Boolean); if (line) return line; }
  return null;
}
const CLAUDE = findClaude();
const MODE = CLAUDE ? 'cli' : (process.env.ANTHROPIC_API_KEY ? 'api' : 'scripted');

// Reuse your k3 / KimiCode login: read ~/.kimicode/config.json EXACTLY as k3 does, so
// Enclave auto-follows whatever k3 is set to — the free OpenRouter tier now, the Kimi
// MEMBERSHIP (api.kimi.com/coding) once you `--sub`. Nothing to paste; Kimi replaces
// Claude as the brain, governed by the SAME hook. Enclave env vars override.
// Force a backend with ENCLAVE_BACKEND=kimi|cli|api.
function readKimiConfig() {
  const dir = process.env.KIMICODE_HOME || join(homedir(), '.kimicode');
  let cfg = {};
  try { cfg = JSON.parse(readFileSync(join(dir, 'config.json'), 'utf8')) || {}; } catch {}
  let base = cfg.baseUrl || 'https://api.moonshot.ai/v1';
  let type = (cfg.apiType && cfg.apiType !== 'auto') ? cfg.apiType : (/\/anthropic|kimi\.com\/coding/i.test(base) ? 'anthropic' : 'openai');
  let model = (cfg.models && cfg.models.main) || 'kimi-k3';
  if (cfg.subscription)  { base = 'https://api.kimi.com/coding'; type = 'anthropic'; model = (cfg.models && cfg.models.main) || 'k3'; }
  else if (cfg.freeTier) { base = 'https://openrouter.ai/api/v1'; type = 'openai'; model = (cfg.models && cfg.models.main) || 'qwen/qwen3-coder:free'; }
  const key = process.env.KIMI_API_KEY || process.env.MOONSHOT_API_KEY || process.env.OPENROUTER_API_KEY || process.env.ENCLAVE_KIMI_KEY || process.env.ANTHROPIC_AUTH_TOKEN || cfg.apiKey || '';
  // Kimi's raw coding API wants the BASE id (`k3`), never the k3 config's display id
  // (`kimi-k3[1m]`) — normalize so logs/readiness/downstream all see the wire id. For
  // OpenAI-shape backends (moonshot platform / OpenRouter) only the [1m] tag is stripped.
  const effType = process.env.KIMI_APITYPE || type;
  model = process.env.KIMI_MODEL || model;
  model = effType === 'anthropic' ? normalizeKimiModel(model) : model.replace(/\s*\[1m\]\s*$/i, '').trim();
  return { baseUrl: process.env.KIMI_BASE_URL || base, apiType: effType, model, apiKey: key, source: cfg.subscription ? 'kimi-subscription' : (cfg.freeTier ? 'k3-free-tier' : 'k3-config') };
}
const KIMI = readKimiConfig();
const KIMI_OK = !!KIMI.apiKey;
// Auto-attach, but land on a WORKING model: prefer Kimi when it's the paid K3
// subscription (reliable + filter-free) or explicitly requested; the free OpenRouter
// tier churns (routes vanish), so default to Claude there. Falls through to whatever's
// actually present. Force any backend with ENCLAVE_BACKEND=kimi|cli|api.
const FORCED = (process.env.ENCLAVE_BACKEND || '').toLowerCase();
const kimiPreferred = KIMI_OK && (KIMI.source === 'kimi-subscription' || FORCED === 'kimi');
const BACKEND = FORCED || (kimiPreferred ? 'kimi' : (CLAUDE ? 'cli' : (KIMI_OK ? 'kimi' : (process.env.ANTHROPIC_API_KEY ? 'api' : 'scripted'))));

// console persona key  →  SIGNED identity file  +  sealed workspace  +  default workload
const PERSONA = {
  jr:   { session: 'sam.json',    ws: 'triage-queue',      workload: 'incident-response' },
  grc:  { session: 'priya.json',  ws: 'soc2-evidence-q3',  workload: 'grc-audit' },
  ir:   { session: 'dana.json',   ws: 'incident-2231',     workload: 'incident-response' },
  red:  { session: 'marcus.json', ws: 'pentest-northwind', workload: 'red-team' },
  lead: { session: 'alex.json',   ws: 'command-deck',      workload: 'incident-response' },
};

// Stage 2 — the container tier. A workload with a provisioned image runs its tools
// INSIDE a sealed per-enclave container (--network none, workspace mounted at /work,
// non-root); the model reaches them via `enclave-shell`. Workloads without an image
// fall back to the host tier (governance still applies, but no baked-in toolchain).
const WORKLOAD_IMAGE = {
  'incident-response': 'enclave-forensics:latest',
  'red-team':          'enclave-redteam:latest',
  'tool-dev':          'enclave-tooldev:latest',
  'code-review':       'enclave-codereview:latest',
  'grc-audit':         'enclave-grcaudit:latest',
};
const DOCKER_OK = (() => { try { return spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { encoding: 'utf8' }).status === 0; } catch { return false; } })();
const BIN = join(LIVE, 'bin');

// the enclave-shell wrapper the model uses to run tools in its sealed container
async function ensureBin() {
  await mkdir(BIN, { recursive: true });
  await writeFile(join(BIN, 'enclave-shell'),
    '#!/usr/bin/env bash\n' +
    '# Enclave — run a command inside this enclave\'s sealed workload container, OR the VM-lab Kali attacker.\n' +
    'export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL=\'*\'\n' +
    'if [ -n "$ENCLAVE_KALI_VMX" ]; then\n' +
    '  # VM-LAB tier: run the command INSIDE the Kali attacker VM via VMware guest-ops, capture output.\n' +
    '  "$ENCLAVE_VMRUN" -T ws -gu "$ENCLAVE_KALI_USER" -gp "$ENCLAVE_KALI_PASS" runScriptInGuest "$ENCLAVE_KALI_VMX" /bin/bash "{ $*; } >/tmp/.eshell 2>&1" >/dev/null 2>&1\n' +
    '  rm -f "$ENCLAVE_KALI_OUT" 2>/dev/null   # vmrun refuses to overwrite an existing host file → delete first\n' +
    '  "$ENCLAVE_VMRUN" -T ws -gu "$ENCLAVE_KALI_USER" -gp "$ENCLAVE_KALI_PASS" copyFileFromGuestToHost "$ENCLAVE_KALI_VMX" /tmp/.eshell "$ENCLAVE_KALI_OUT" >/dev/null 2>&1\n' +
    '  cat "$ENCLAVE_KALI_OUT" 2>/dev/null; exit 0\n' +
    'fi\n' +
    'if [ -z "$ENCLAVE_CONTAINER" ]; then echo "enclave-shell: no sealed container for this workload (host tier)" >&2; exit 3; fi\n' +
    '# exec the tool + args DIRECTLY (no intermediate shell) so quoting is preserved and a\n' +
    '# tool argument cannot inject into the local shell. For pipes/redirects: enclave-shell bash -lc "..."\n' +
    'exec docker exec -i -w /work "$ENCLAVE_CONTAINER" "$@"\n',
    { mode: 0o755 });
}

// the egress broker: enclaves sit on an --internal net (no direct route out); their ONLY
// path to the internet is a broker that permits allowlisted hosts and refuses the rest.
const NET_INTERNAL = 'enclave-internal', NET_EGRESS = 'enclave-egress', BROKER = 'enclave-broker';
let brokerReady = null;
function ensureBrokerNet() {
  if (!DOCKER_OK) return false;
  if (brokerReady !== null) return brokerReady;
  spawnSync('docker', ['network', 'create', '--internal', NET_INTERNAL], { stdio: 'ignore' }); // idempotent
  spawnSync('docker', ['network', 'create', NET_EGRESS], { stdio: 'ignore' });
  const up = spawnSync('docker', ['ps', '-q', '-f', 'name=^' + BROKER + '$'], { encoding: 'utf8' });
  if (!(up.status === 0 && up.stdout.trim())) {
    spawnSync('docker', ['rm', '-f', BROKER], { stdio: 'ignore' });
    const r = spawnSync('docker', ['run', '-d', '--name', BROKER, '--network', NET_INTERNAL,
      '-v', fwd(SEAM) + ':/seam:ro', 'node:22-alpine', 'node', '/seam/broker-proxy.mjs'], { encoding: 'utf8' });
    if (r.status !== 0) { console.log('[broker] start failed:', (r.stderr || '').slice(0, 200)); brokerReady = false; return false; }
    spawnSync('docker', ['network', 'connect', NET_EGRESS, BROKER], { stdio: 'ignore' }); // dual-home: the broker (only) gets internet
    console.log('[broker] enclave-broker up — allowlist-enforced egress for the container tier');
  }
  brokerReady = true;
  return true;
}

// ---- the RANGE: an isolated, disposable, deliberately-vulnerable practice target ----
// so operators can safely fire what they build at something INSIDE the sealed range
// instead of a real system. It sits on a lab network at a fixed IP that falls inside
// the offensive workloads' signed engagement scope, so scanning/exploiting IT (and
// only it) is permitted. Nothing else on that net; no internet.
const LAB_NET = 'enclave-lab', LAB_TARGET = 'enclave-range-target', LAB_IMAGE = 'enclave-range-target:latest';
const LAB_SUBNET = '10.10.0.0/16', LAB_IP = '10.10.5.20';
const LAB_WORKLOADS = new Set(['red-team', 'tool-dev']);
// ---- HIGH-FIDELITY VMware tier: a real Win11 target + Kali attacker, EPHEMERAL (see vm-lab.mjs) ----
const VM_LAB_WORKLOADS = new Set(['vm-range']);        // workload that uses the VMware lab instead of Docker
let vmLabSession = null;                               // the ONE ws currently holding the lab
let vmLabTimer = null;                                 // idle watchdog → tears the lab down if the browser vanishes
// Lab HOLDs: auto-expiring leases (per-owner) that defer EVERY Enclave-side teardown
// (watchdog, session churn) while a test/verification is mid-flight. The self-clean
// design is preserved: holds expire on read (max 60min), so a forgotten hold never
// wedges the lab. Per-owner map: a consumer's release never eats someone else's hold.
const vmLabHolds = new Map();                          // owner -> { owner, until }
function labHoldActive() {
  const now = Date.now();
  for (const [k, h] of vmLabHolds) if (h.until <= now) { console.log('[vm-lab] hold expired (' + k + ')'); vmLabHolds.delete(k); }
  return vmLabHolds.size ? [...vmLabHolds.values()][0] : null;
}
function holdLab(owner, minutes) {
  const mins = Math.max(1, Math.min(60, Number(minutes) || 15));
  const h = { owner: String(owner || 'unknown').slice(0, 60), until: Date.now() + mins * 60000 };
  vmLabHolds.set(h.owner, h);
  console.log('[vm-lab] hold set by ' + h.owner + ' for ' + mins + 'min');
  return h;
}
function armLabWatchdog(ws) {
  clearTimeout(vmLabTimer);
  vmLabTimer = setTimeout(() => { if (vmLabSession === ws) { console.log('[vm-lab] idle timeout → teardown'); disarmLab(ws); } },
    Number(process.env.ENCLAVE_VMLAB_IDLE_MS) || 12 * 60 * 1000);
}
function disarmLab(ws) {                               // revert-to-clean + power-off the lab (idempotent)
  if (vmLabSession && (!ws || ws === vmLabSession)) {
    const h = labHoldActive();
    if (h) { console.log('[vm-lab] teardown DEFERRED — hold active (' + h.owner + ', ' + Math.round((h.until - Date.now()) / 60000) + 'min left)'); return; }
    const s = vmLabSession; vmLabSession = null; clearTimeout(vmLabTimer);
    labDown().then(() => console.log('[vm-lab] ' + s + ' torn down — reverted to clean + powered off'));
  }
}
function vmLabBriefing(lab) {
  const ip = (lab && lab.targetIp) || vmLabTargetIp();
  return `\n\nVM RANGE — HIGH-FIDELITY LAB (INSIDE your signed scope): a REAL, disposable Windows 11 Pro box with live Microsoft Defender is booted at ${ip} on the sealed lab net. Your attacker is Kali — your Bash runs THERE. Fire tools from Kali AT ${ip} and read results back:  enclave-shell nmap -sV ${ip}  ·  enclave-shell arping -c3 ${ip}  ·  enclave-shell whoami . Build a payload, drop it, see if it survives Defender. This is the realistic tier the container range can't be. The whole lab reverts to a clean snapshot and powers off when the session ends.`;
}
let labReady = null;
function ensureLab() {
  if (!DOCKER_OK) return null;
  if (labReady !== null) return labReady;
  if (spawnSync('docker', ['image', 'inspect', LAB_IMAGE], { stdio: 'ignore' }).status !== 0) { labReady = false; return null; }
  spawnSync('docker', ['network', 'create', '--subnet', LAB_SUBNET, LAB_NET], { stdio: 'ignore' }); // idempotent
  const up = spawnSync('docker', ['ps', '-q', '-f', 'name=^' + LAB_TARGET + '$'], { encoding: 'utf8' });
  if (!(up.status === 0 && up.stdout.trim())) {
    spawnSync('docker', ['rm', '-f', LAB_TARGET], { stdio: 'ignore' });
    const r = spawnSync('docker', ['run', '-d', '--name', LAB_TARGET, '--network', LAB_NET, '--ip', LAB_IP, LAB_IMAGE], { encoding: 'utf8' });
    if (r.status !== 0) { console.log('[range] target failed:', (r.stderr || '').slice(0, 160)); labReady = false; return null; }
    console.log(`[range] lab target up at ${LAB_IP} (${LAB_NET}) — vulnerable practice box, in-scope for offensive workloads`);
  }
  labReady = LAB_IP;
  return LAB_IP;
}

// ensure a persistent, sealed per-enclave container is running for this workload
function ensureContainer(ws, workload, wsDir) {
  if (!DOCKER_OK) return null;
  const image = WORKLOAD_IMAGE[workload];
  if (!image) return null;                                     // no image → host tier
  if (spawnSync('docker', ['image', 'inspect', image], { stdio: 'ignore' }).status !== 0) return null; // image not built → host tier
  // container keyed by (session workspace + workload) so MULTIPLE toolchains can attach to
  // the SAME engagement workspace — build a tool in tool-dev, test it in red-team, all on /work.
  const name = 'enclave-' + sane(ws) + '-' + sane(workload);
  const ps = spawnSync('docker', ['ps', '-q', '-f', 'name=^' + name + '$'], { encoding: 'utf8' });
  if (ps.status === 0 && ps.stdout.trim()) return name;        // already running
  spawnSync('docker', ['rm', '-f', name], { stdio: 'ignore' });// clear any stopped leftover
  const broker = ensureBrokerNet();
  const netArgs = broker ? ['--network', NET_INTERNAL] : ['--network', 'none'];
  const noProxy = 'localhost,127.0.0.1,' + LAB_IP + ',' + LAB_SUBNET;  // lab traffic bypasses the research broker
  const proxyEnv = broker ? ['-e', 'HTTP_PROXY=http://enclave-broker:8888', '-e', 'HTTPS_PROXY=http://enclave-broker:8888',
    '-e', 'http_proxy=http://enclave-broker:8888', '-e', 'https_proxy=http://enclave-broker:8888',
    '-e', 'NO_PROXY=' + noProxy, '-e', 'no_proxy=' + noProxy] : [];
  const run = spawnSync('docker', ['run', '-d', '--name', name, ...netArgs, ...proxyEnv,
    '-v', wsDir.replace(/\\/g, '/') + ':/work', '-w', '/work', image, 'tail', '-f', '/dev/null'],
    { encoding: 'utf8' });
  if (run.status !== 0) { console.log('[container] start failed:', (run.stderr || '').slice(0, 200)); return null; }
  // offensive workloads get a line into the sealed lab range (the practice target)
  let labIp = null;
  if (LAB_WORKLOADS.has(workload)) { labIp = ensureLab(); if (labIp) spawnSync('docker', ['network', 'connect', LAB_NET, name], { stdio: 'ignore' }); }
  console.log(`[container] ${name} up (${image}) · /work mounted · egress: ${broker ? 'allowlist-broker' : 'sealed'}${labIp ? ' · range target ' + labIp : ''}`);
  return name;
}

// ---- session lifecycle: ONE ephemeral workspace + container per browser session ----
// A fresh page load / new AI session gets a fresh workspace (last session's files are
// gone) and a fresh container; the previous one is torn down. Sandboxes are ephemeral.
const EFFORTS = ['low', 'medium', 'high', 'xhigh', 'max'];   // Opus 4.6+/5 accept all five (verified against the CLI)
const sessions = new Map();                                    // base workspace -> current physical wsName
const sane = s => String(s || '').replace(/[^\w.-]/g, '_');
const wsNameFor = (baseWs, token) => token ? sane(baseWs) + '__' + sane(token).slice(0, 24) : sane(baseWs);
function teardownSession(wsName) {
  disarmLab(wsName);                                           // if this session held the VM lab, revert + power it off
  try {                                                        // all toolchain containers for this session
    const ps = spawnSync('docker', ['ps', '-aq', '-f', 'name=^enclave-' + sane(wsName) + '-'], { encoding: 'utf8' });
    const ids = (ps.stdout || '').split(/\s+/).filter(Boolean);
    if (ids.length) spawnSync('docker', ['rm', '-f', ...ids], { stdio: 'ignore' });
  } catch {}
  try { rmSync(join(LIVE, wsName), { recursive: true, force: true }); } catch {}
  console.log('[teardown] session ' + wsName + ' — toolchains + workspace wiped');
}
function cleanupAllContainers() {
  if (!DOCKER_OK) return;
  try {
    const ps = spawnSync('docker', ['ps', '-aq', '-f', 'name=^enclave-'], { encoding: 'utf8' });
    const ids = (ps.stdout || '').split(/\s+/).filter(Boolean);
    if (ids.length) { spawnSync('docker', ['rm', '-f', ...ids], { stdio: 'ignore' }); console.log(`[cleanup] removed ${ids.length} enclave container(s)`); }
  } catch {}
}

// the hook needs its Cedar policy engine — install once, on first boot
function ensureDeps() {
  if (MODE !== 'cli') return;
  if (!existsSync(join(SEAM, 'node_modules', '@cedar-policy'))) {
    console.log('  · installing the policy engine for the enforcement hook (one-time)…');
    spawnSync('npm', ['install', '--no-audit', '--no-fund'], { cwd: SEAM, stdio: 'ignore', shell: WIN });
  }
}
// the sealed enclave toolset: local work tools only (Read/Write/Edit/Bash/Grep/Glob).
// Everything below is stripped from the box: egress (web/publish), orchestration
// (subagents/skills/tool-search), persistence/automation, external comms, and fs
// escape. --strict-mcp-config additionally removes ALL the operator's MCP servers
// (pccheck, github, …). Defense-in-depth: classify.mjs also fail-closes these names.
// NOTE: WebFetch/WebSearch are deliberately NOT here — they are a GOVERNED research
// channel (the PreToolUse hook allows only allowlisted, DLP-clean, read-only fetches;
// see poc/enforcement-seam/egress-allowlist.mjs). Artifact stays blocked: it publishes
// off-box (claude.ai) and is a pure exfil vector, not research.
const SEAL_DISALLOW = [
  'Artifact',                                                            // publish / exfil to claude.ai
  'Task', 'Agent', 'Workflow', 'Skill', 'ToolSearch',                    // orchestration / surface expansion
  'CronCreate', 'CronList', 'CronDelete', 'ScheduleWakeup',              // persistence / automation
  'RemoteTrigger', 'PushNotification', 'SendMessage', 'DesignSync',      // external comms / notify
  'EnterWorktree', 'ExitWorktree', 'Monitor',                           // fs / process escape
  'TaskCreate', 'TaskList', 'TaskGet', 'TaskUpdate', 'TaskStop', 'TaskOutput',
  'ListMcpResourcesTool', 'ReadMcpResourceTool', 'ReadMcpResourceDirTool',
];
// picker value -> the exact string handed to `claude --model`. Generic aliases resolve to the
// latest of each tier; the explicit IDs let the operator pin a specific Opus for testing.
const MODEL_ALIAS = {
  sonnet: 'sonnet', haiku: 'haiku', opus: 'opus',
  'opus-5':   'claude-opus-5',
  'opus-4-8': 'claude-opus-4-8',
  'opus-4-7': 'claude-opus-4-7',
  'opus-4-6': 'claude-opus-4-6',
  // Kimi coding models — VARVEL runs these through its governed direct-API backend
  // (claude -p hangs on Kimi). Effort is passed separately as VARVEL_EFFORT.
  'k3': 'k3', 'kimi-k3': 'k3', 'kimi-k2.7-code': 'kimi-k2.7-code', 'kimi-2.7': 'kimi-k2.7-code',
};
const KIMI_EFFORTS = ['low', 'medium', 'high'];

// a sealed per-operator workspace whose settings.json wires in the PreToolUse hook
function settingsPath(ws) { return join(LIVE, '.settings', ws + '.json'); }
async function ensureWorkspace(ws) {
  await mkdir(join(LIVE, '.settings'), { recursive: true });
  await writeFile(join(LIVE, 'no-mcp.json'), '{"mcpServers":{}}');   // strict-mcp baseline: zero servers
  const dir = join(LIVE, ws);
  await mkdir(dir, { recursive: true });
  // give the workspace its OWN empty git repo so `git status` stays local and can never
  // walk up into a host repo (belt-and-braces with the out-of-tree location above)
  if (!existsSync(join(dir, '.git'))) { try { spawnSync('git', ['init', '-q'], { cwd: dir, stdio: 'ignore' }); } catch {} }
  // hook settings live OUTSIDE the workspace — the operator's AI never sees the host path to the hook
  const settings = { hooks: { PreToolUse: [ { matcher: '*', hooks: [ { type: 'command', command: `node --no-warnings ${fwd(HOOK)}` } ] } ] } };
  await writeFile(settingsPath(ws), JSON.stringify(settings));
  if (!existsSync(join(dir, 'README.enclave.md'))) await writeFile(join(dir, 'README.enclave.md'), `# ${ws}\nSealed Enclave workspace. Tool calls here are governed by your clearance.\n`);
  return dir;
}

// CLI mode: spawn real `claude -p`, governed by the hook, in the sealed workspace
function callClaudeCLI({ message, persona, resumeId, system, model, workload, session, effort }) {
  return new Promise(async (resolve, reject) => {
    const P = PERSONA[persona] || PERSONA.lead;
    const sessionFile = join(SEAM, 'session', P.session);
    if (!existsSync(sessionFile)) return reject(new Error('no signed identity for persona ' + persona));
    const wsName = wsNameFor(P.ws, session);            // ephemeral per-browser-session workspace
    const prev = sessions.get(P.ws);
    if (prev && prev !== wsName) teardownSession(prev); // fresh page/AI session → wipe the previous one
    sessions.set(P.ws, wsName);
    const dir = await ensureWorkspace(wsName);
    await ensureBin();
    const wl = workload || P.workload;
    const isVmLab = VM_LAB_WORKLOADS.has(wl) && vmLabAvailable();
    const container = isVmLab ? null : ensureContainer(wsName, wl, dir);  // sealed per-session container (null → host/VM-lab)
    let sysAug = system || '';
    // A held lab is someone's mid-test work: DON'T revert it under them — hand the
    // session the running lab instead (logged); normal clean-boot behavior otherwise.
    if (isVmLab) {
      const h = labHoldActive();
      const st = h ? await labStatus() : null;
      const lab = (h && st && st.targetRunning) ? st : await labUp();
      if (h && st && st.targetRunning) console.log('[vm-lab] hold active (' + h.owner + ') — session joined the RUNNING lab, no revert');
      vmLabSession = wsName; armLabWatchdog(wsName); sysAug += vmLabBriefing(lab);
    }
    if (container) sysAug += `\n\nRUNTIME — CONTAINER TIER: a sealed ${wl} container ("${container}", non-root, your workspace mounted at /work) is live. Its network egress is restricted to an allowlist broker — approved research sources (CVE/NVD, MITRE ATT&CK, GitHub, package registries, docs) reach out; everything else is refused. Run any provisioned security tool INSIDE it via:  enclave-shell <command>  — e.g.  enclave-shell nmap -sV 10.0.0.5  ·  enclave-shell vol -f /work/mem.raw windows.pslist  ·  enclave-shell nuclei -u https://target . Those tools are NOT on the host; your plain Bash runs on the host, confined to the workspace. Use enclave-shell for the workload toolchain.`;
    const labIp = (container && LAB_WORKLOADS.has(wl)) ? ensureLab() : null;
    if (labIp) sysAug += `\n\nRANGE — SAFE PRACTICE TARGET: a disposable, deliberately-vulnerable lab box is live at ${labIp} on your engagement network, INSIDE your signed scope — so you may freely scan and exploit IT (and only it) to test what you build. It serves a web app on :8080 with a command-injection bug at GET /ping?host=. Try:  enclave-shell nmap -sV ${labIp}  ·  enclave-shell curl "http://${labIp}:8080/ping?host=127.0.0.1;id"  (that ;id is the injection → runs on the target). Nothing else on the range is reachable; this is where you test offensive tooling instead of a real system.`;
    const useModel = MODEL_ALIAS[model] || MODEL;
    const args = ['-p', message,
      '--settings', settingsPath(wsName),
      '--output-format', 'json',
      '--model', useModel,
      ...(EFFORTS.includes(effort) ? ['--effort', effort] : []),
      '--strict-mcp-config', '--mcp-config', join(LIVE, 'no-mcp.json'),  // seal: no inherited MCP servers
      '--disallowedTools', ...SEAL_DISALLOW];                            // seal: no web / no subagents
    if (sysAug)   args.push('--append-system-prompt', sysAug);
    if (resumeId) args.push('--resume', resumeId);
    const child = spawn(CLAUDE, args, { cwd: dir, windowsHide: true,
      env: { ...process.env, ENCLAVE_SESSION: sessionFile, ENCLAVE_WORKSPACE_DIR: dir,
             ENCLAVE_CONTAINER: container || '', ...(isVmLab ? kaliShellEnv() : {}), PATH: BIN + delimiter + (process.env.PATH || ''), NODE_NO_WARNINGS: '1' } });
    let out = '', err = '';
    const killer = setTimeout(() => { child.kill(); reject(new Error('claude timed out (180s)')); }, 180000);
    child.stdout.on('data', d => (out += d));
    child.stderr.on('data', d => (err += d));
    child.on('error', e => { clearTimeout(killer); reject(e); });
    child.on('close', () => { clearTimeout(killer);
      try {
        const j = JSON.parse(out);
        // the "real" model = the top-tier one actually used (modelUsage also lists a small helper model)
        const models = Object.keys(j.modelUsage || {});
        const primary = models.filter(m => !/haiku/i.test(m)).sort((a, b) => (j.modelUsage[b].inputTokens || 0) - (j.modelUsage[a].inputTokens || 0))[0] || models[0] || useModel;
        resolve({ text: j.result || j.subtype || '(no output)', sessionId: j.session_id,
          denials: (j.permission_denials || []).map(d => d.tool_name || d.tool || 'tool'),
          cost: j.total_cost_usd, numTurns: j.num_turns, isError: !!j.is_error,
          usage: j.usage || null, model: primary, models });
      } catch (e) { reject(new Error('could not parse claude output: ' + (err || out || e.message).slice(0, 300))); }
    });
    child.stdin.end();
  });
}

// Kimi (or any OpenAI-compatible model) turn — same sealed workspace + container +
// governance as the Claude path; only the reasoning engine changes.
async function callKimi({ message, persona, system, workload, session, effort, messages }) {
  const P = PERSONA[persona] || PERSONA.lead;
  const sessionFile = join(SEAM, 'session', P.session);
  if (!existsSync(sessionFile)) throw new Error('no signed identity for persona ' + persona);
  const wsName = wsNameFor(P.ws, session);
  const prev = sessions.get(P.ws);
  if (prev && prev !== wsName) teardownSession(prev);
  sessions.set(P.ws, wsName);
  const dir = await ensureWorkspace(wsName);
  await ensureBin();
  const wl = workload || P.workload;
  const container = ensureContainer(wsName, wl, dir);
  let sysAug = (system || '') + '\n\nYou have function-calling tools: Read, Write, Edit, Bash, Grep, Glob. EVERY call is intercepted by the Enclave policy hook and allowed/denied by this operator’s signed clearance + certifications — you cannot override it. If a call is denied, state what it needs and take the in-policy path. Operate only inside the workspace.';
  if (container) sysAug += `\n\nRUNTIME — CONTAINER TIER: a sealed ${wl} container is live (egress via allowlist broker, workspace at /work). Run the workload toolchain INSIDE it through Bash:  enclave-shell <command>  (e.g. enclave-shell nmap -sV <in-scope-target>, enclave-shell vol -f /work/mem.raw windows.pslist).`;
  const labIp = (container && LAB_WORKLOADS.has(wl)) ? ensureLab() : null;
  if (labIp) sysAug += `\n\nRANGE — SAFE PRACTICE TARGET at ${labIp} (in your signed scope): a disposable, deliberately-vulnerable lab box to test tooling against instead of a real system. Web app on :8080 with a command-injection bug at GET /ping?host=. e.g. enclave-shell nmap -sV ${labIp} · enclave-shell curl "http://${labIp}:8080/ping?host=127.0.0.1;id". Only it is reachable.`;
  const hist = (Array.isArray(messages) && messages.length) ? messages : [{ role: 'user', content: message }];
  const norm = hist.map(m => ({ role: m.role === 'assistant' ? 'assistant' : (m.role === 'system' ? 'system' : 'user'), content: typeof m.content === 'string' ? m.content : JSON.stringify(m.content) }));
  const r = await runGovernedAgent({
    apiBase: KIMI.baseUrl, apiKey: KIMI.apiKey, apiType: KIMI.apiType, model: KIMI.model, system: sysAug, messages: norm,
    hookPath: HOOK, sessionFile, wsDir: dir, container, binPath: BIN,
    effort: EFFORTS.includes(effort) ? effort : undefined,
  });
  return { text: r.text, denials: r.denials, sessionId: session || wsName, mode: 'kimi', model: KIMI.model, usage: null };
}

// API fallback: inject the key server-side, forward to Claude (key never reaches the browser)
function callClaudeAPI({ system, messages }) {
  return new Promise((resolve, reject) => {
    const key = process.env.ANTHROPIC_API_KEY;
    if (!key) return reject(Object.assign(new Error('no ANTHROPIC_API_KEY set on the server'), { code: 'NO_KEY' }));
    const payload = JSON.stringify({ model: process.env.ENCLAVE_API_MODEL || 'claude-sonnet-5', max_tokens: 1024, system, messages });
    const req = https.request({ hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload), 'x-api-key': key, 'anthropic-version': '2023-06-01' } },
      r => { let b = ''; r.on('data', c => (b += c)); r.on('end', () => { try { const j = JSON.parse(b); if (j.error) return reject(new Error(j.error.message || 'api error')); resolve({ text: (j.content || []).map(x => x.text).filter(Boolean).join('\n') }); } catch (e) { reject(e); } }); });
    req.on('error', reject); req.write(payload); req.end();
  });
}

// recent REAL hook decisions from the hash-chained ledger (for the console's audit view)
function recentAudit(n = 25) {
  if (!existsSync(LEDGER)) return [];
  const lines = readFileSync(LEDGER, 'utf8').trim().split('\n').filter(Boolean).slice(-300);
  const out = [];
  for (const l of lines) { try { const e = JSON.parse(l); if (e.event === 'pretooluse.decision')
    out.push({ principal: e.principal, clearance: e.clearance, tool: e.tool, action: e.mapped_action, decision: e.decision, ts: e.ts }); } catch {} }
  return out.slice(-n);
}

// ---- VARVEL launcher --------------------------------------------------------
// Open the governed red-team platform FROM the console, bound to the current
// operator. Identity handoff is identical to every other governed module: the SIGNED
// session token via ENCLAVE_SESSION. VARVEL reads it, shows who you are, and sources
// its engagement scope from the signed engagementScope — nothing is typed or faked.
// One instance; re-bound when a different persona opens it.
const VARVEL_PORT  = Number(process.env.VARVEL_PORT) || 8971;
const VARVEL_ENTRY = join(ROOT, 'varvel', 'server.mjs');
let varvelProc = null, varvelBound = null, varvelModel = null, varvelEffort = null, varvelBrain = null;

// Brain passthrough (the local-brain seam, varvel/engine/brain-provider.mjs): when the
// open body carries a `brain` object, forward its fields to the spawned VARVEL as
// VARVEL_BRAIN_* env — the SAME precedence layer that module documents (env sits between
// per-request and engagement settings). Only the five known fields cross; apiKeyEnv is an
// env-var NAME (a key VALUE never crosses this boundary). Absent brain => the kimi default
// open is byte-identical to before — the forced {"persona":"red","model":"k3","effort":"high"}
// behavior is load-bearing (open would otherwise default to sonnet) and is NOT touched.
function normalizeBrain(brain) {
  if (!brain || typeof brain !== 'object') return null;
  const out = {};
  if (brain.provider !== undefined) out.provider = String(brain.provider);
  if (brain.baseUrl !== undefined) out.baseUrl = String(brain.baseUrl);
  if (brain.model !== undefined) out.model = String(brain.model);
  if (brain.apiKeyEnv !== undefined) out.apiKeyEnv = String(brain.apiKeyEnv);
  if (brain.timeoutMs !== undefined) out.timeoutMs = String(Math.floor(Number(brain.timeoutMs) || 0));
  return Object.keys(out).length ? out : null;
}
const brainEnvOf = (b) => !b ? {} : {
  ...(b.provider !== undefined ? { VARVEL_BRAIN_PROVIDER: b.provider } : {}),
  ...(b.baseUrl !== undefined ? { VARVEL_BRAIN_BASE_URL: b.baseUrl } : {}),
  ...(b.model !== undefined ? { VARVEL_BRAIN_MODEL: b.model } : {}),
  ...(b.apiKeyEnv !== undefined ? { VARVEL_BRAIN_API_KEY_ENV: b.apiKeyEnv } : {}),
  ...(b.timeoutMs !== undefined ? { VARVEL_BRAIN_TIMEOUT_MS: b.timeoutMs } : {}),
};

const varvelAlive = () => !!(varvelProc && varvelProc.exitCode === null && !varvelProc.killed);

// Free the VARVEL port from any stale/foreign instance so the one we spawn (bound to the
// picked identity) actually binds — otherwise the console would open an old, unbound
// VARVEL that shows "standalone" instead of the operator you selected.
function freePort(port) {
  try {
    if (WIN) {
      const r = spawnSync('netstat', ['-ano'], { encoding: 'utf8' });
      const pids = [...new Set((r.stdout || '').split(/\r?\n/)
        .filter((l) => /LISTENING/.test(l) && new RegExp(':' + port + '\\b').test(l))
        .map((l) => l.trim().split(/\s+/).pop())
        .filter((p) => /^\d+$/.test(p) && p !== '0' && Number(p) !== process.pid))];
      for (const pid of pids) spawnSync('taskkill', ['/PID', pid, '/F'], { stdio: 'ignore' });
    } else {
      const r = spawnSync('bash', ['-c', `lsof -ti:${port} 2>/dev/null`], { encoding: 'utf8' });
      for (const pid of (r.stdout || '').split(/\s+/).filter(Boolean)) if (Number(pid) !== process.pid) spawnSync('kill', ['-9', pid], { stdio: 'ignore' });
    }
  } catch { /* best effort */ }
}
const pingVarvel = () => new Promise((resolve) => {
  const req = http.get({ host: '127.0.0.1', port: VARVEL_PORT, path: '/api/phases', timeout: 800 }, (r) => { r.resume(); resolve(r.statusCode === 200); });
  req.on('error', () => resolve(false));
  req.on('timeout', () => { req.destroy(); resolve(false); });
});
async function waitForVarvel(ms = 6000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) { if (await pingVarvel()) return true; await new Promise((r) => setTimeout(r, 200)); }
  return false;
}
function killVarvel() { if (varvelAlive()) { try { varvelProc.kill(); } catch {} } varvelProc = null; varvelBound = null; varvelBrain = null; }

async function openVarvel(personaKey, model, effort, brain) {
  const key = PERSONA[personaKey] ? personaKey : 'red';   // VARVEL is a red-team console; default to the red persona
  const P = PERSONA[key];
  const sessionFile = join(SEAM, 'session', P.session);
  if (!existsSync(sessionFile)) throw new Error('no signed session for persona ' + key);
  if (!existsSync(VARVEL_ENTRY)) throw new Error('VARVEL not installed at ' + fwd(VARVEL_ENTRY));
  const useModel = MODEL_ALIAS[model] || model || MODEL;   // the AI VARVEL runs — matches the model picked in the console
  const useEffort = KIMI_EFFORTS.includes(effort) ? effort : 'high';   // Kimi effort (xhigh/max → high); ignored by Claude models
  const useBrain = normalizeBrain(brain);                // local-brain passthrough (null = the unchanged kimi default)
  const brainKey = useBrain ? JSON.stringify(useBrain) : '';

  // Reuse only if OUR child is up, bound to this persona AND running this model + effort + brain.
  if (varvelAlive() && varvelBound === key && varvelModel === useModel && varvelEffort === useEffort && (varvelBrain || '') === brainKey && await pingVarvel()) {
    return { ok: true, url: `http://localhost:${VARVEL_PORT}`, operator: key, model: useModel, effort: useEffort, ...(useBrain ? { brain: useBrain } : {}), reused: true };
  }
  killVarvel();                 // stop our own child if any
  freePort(VARVEL_PORT);        // and evict any stale/foreign VARVEL so ours binds + shows the picked identity
  await new Promise((r) => setTimeout(r, 350));

  varvelProc = spawn(process.execPath, [VARVEL_ENTRY], {
    cwd: join(ROOT, 'varvel'),
    env: { ...process.env, ENCLAVE_SESSION: sessionFile, ENCLAVE_WORKSPACE_DIR: join(LIVE, P.ws), VARVEL_PORT: String(VARVEL_PORT), VARVEL_MODEL: useModel, VARVEL_EFFORT: useEffort,
      // Local-brain passthrough (additive): VARVEL_BRAIN_* when the open body carried a
      // brain object — nothing at all when it did not (the kimi default stays untouched).
      ...brainEnvOf(useBrain),
      // VM-range channel defaults (overridable): the governed callback channel binds the
      // lab interface on a stable port so range agents can reach it and keep their config
      // across restarts; the scope ring still gates every check-in.
      VARVEL_CHANNEL_BIND: process.env.VARVEL_CHANNEL_BIND || '192.168.50.1',
      VARVEL_SCOPE_CIDRS: process.env.VARVEL_SCOPE_CIDRS || '127.0.0.0/8,192.168.50.0/24',
      VARVEL_CHANNEL_PORT: process.env.VARVEL_CHANNEL_PORT || '49561',
      VARVEL_DNS_PORT: process.env.VARVEL_DNS_PORT || '5335',
      // DNS-over-HTTPS transport (gap#2): TLS-carried governed wire on 4453, lab cert
      // unless VARVEL_DOH_CERT/KEY point at operator PEMs.
      VARVEL_DOH: process.env.VARVEL_DOH || '1',
      // Native ICMP fallback: the bridge self-probes and reports honestly if the host
      // can't move raw frames, so arming it here is safe on any host.
      VARVEL_ICMP: process.env.VARVEL_ICMP || '1' },
    stdio: 'ignore', windowsHide: true,
  });
  varvelBound = key; varvelModel = useModel; varvelEffort = useEffort; varvelBrain = brainKey;
  varvelProc.on('exit', () => { if (varvelBound === key) { varvelProc = null; varvelBound = null; varvelModel = null; varvelEffort = null; varvelBrain = null; } });
  const up = await waitForVarvel();
  return { ok: up, url: `http://localhost:${VARVEL_PORT}`, operator: key, model: useModel, effort: useEffort, ...(useBrain ? { brain: useBrain } : {}), reused: false, up };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');

  if (url.pathname === '/api/health') {
    return send(res, 200, JSON.stringify({ live: BACKEND !== 'scripted', mode: BACKEND, backend: BACKEND,
      model: BACKEND === 'kimi' ? KIMI.model : MODEL, source: BACKEND === 'kimi' ? KIMI.source : null,
      kimi: KIMI_OK, claude: CLAUDE ? basename(CLAUDE) : null,
      available: { kimi: KIMI_OK, claude: !!CLAUDE, api: !!process.env.ANTHROPIC_API_KEY },
      keyPresent: !!process.env.ANTHROPIC_API_KEY }));
  }
  if (url.pathname === '/api/audit') {
    return send(res, 200, JSON.stringify({ decisions: recentAudit(Number(url.searchParams.get('n')) || 25) }));
  }
  // VM-lab HOLD API: auto-expiring leases that defer Enclave-side teardowns while a
  // test/verify flow is mid-flight (the range still self-cleans — holds lapse, max 60min).
  if (url.pathname === '/api/vm-lab') {
    return (async () => {
      const st = await labStatus();
      labHoldActive(); // sweep expired so the listing is honest
      send(res, 200, JSON.stringify({ ...st, holds: [...vmLabHolds.values()].map((h) => ({ owner: h.owner, until: new Date(h.until).toISOString(), minutesLeft: Math.max(0, Math.round((h.until - Date.now()) / 60000)) })) }));
    })();
  }
  if (url.pathname === '/api/vm-lab/hold' && req.method === 'POST') {
    let body = '';
    req.on('data', c => (body += c));
    req.on('end', () => {
      try { const { owner, minutes } = JSON.parse(body || '{}'); const h = holdLab(owner, minutes); send(res, 200, JSON.stringify({ ok: true, owner: h.owner, until: new Date(h.until).toISOString() })); }
      catch (e) { send(res, 400, JSON.stringify({ error: e.message })); }
    });
    return;
  }
  if (url.pathname === '/api/vm-lab/release' && req.method === 'POST') {
    let body = '';
    req.on('data', c => (body += c));
    req.on('end', () => {
      let owner = null;
      try { owner = JSON.parse(body || '{}').owner || null; } catch {}
      labHoldActive(); // sweep first
      if (owner) { const had = vmLabHolds.delete(owner); if (had) console.log('[vm-lab] hold released (' + owner + ')'); return send(res, 200, JSON.stringify({ ok: true, released: had ? owner : null })); }
      const n = vmLabHolds.size; vmLabHolds.clear();
      if (n) console.log('[vm-lab] all holds released (' + n + ')');
      return send(res, 200, JSON.stringify({ ok: true, released: n }));
    });
    return;
  }
  if (url.pathname === '/api/varvel/status') {
    return send(res, 200, JSON.stringify({ running: varvelAlive(), boundTo: varvelBound, model: varvelModel, url: `http://localhost:${VARVEL_PORT}` }));
  }
  if (url.pathname === '/api/varvel/stop' && req.method === 'POST') {
    const was = varvelBound;
    killVarvel();
    freePort(VARVEL_PORT); // evict even a foreign/stale instance
    console.log(`[varvel] stopped (was ${was || 'none'})`);
    return send(res, 200, JSON.stringify({ ok: true, stopped: was || null }));
  }
  if (url.pathname === '/api/varvel/open' && req.method === 'POST') {
    let body = '';
    req.on('data', c => (body += c));
    req.on('end', async () => {
      try { const { persona, model, effort, brain } = JSON.parse(body || '{}'); const r = await openVarvel(persona, model, effort, brain); console.log(`[varvel] open as ${r.operator} · ${r.model}${r.effort ? '/' + r.effort : ''}${r.brain ? ' · brain=' + (r.brain.provider || 'openai-compatible') : ''} · reused=${!!r.reused} · up=${r.up !== false}`); send(res, 200, JSON.stringify(r)); }
      catch (e) { send(res, 502, JSON.stringify({ error: e.message })); }
    });
    return;
  }
  if (url.pathname === '/api/chat' && req.method === 'POST') {
    let body = '';
    req.on('data', c => (body += c));
    req.on('end', async () => {
      try {
        const { message, persona, resumeId, system, messages, model, workload, session, effort } = JSON.parse(body || '{}');
        if (BACKEND === 'kimi') {
          if (!message && !(Array.isArray(messages) && messages.length)) return send(res, 400, JSON.stringify({ error: 'no message' }));
          const r = await callKimi({ message, persona, system, workload, session, effort, messages });
          console.log(`[kimi] ${persona} · ${KIMI.model} (${KIMI.source}) · → ${r.text.length}b · denials=${r.denials.length}`);
          return send(res, 200, JSON.stringify({ ...r }));
        }
        if (BACKEND === 'cli') {
          if (!message) return send(res, 400, JSON.stringify({ error: 'no message' }));
          const r = await callClaudeCLI({ message, persona, resumeId, system, model, workload, session, effort });
          console.log(`[cli] ${persona} · ${model || MODEL} · ${(message || '').slice(0, 36)}… → ${r.text.length}b · denials=${r.denials.length} · $${(r.cost || 0).toFixed(4)}`);
          return send(res, 200, JSON.stringify({ ...r, mode: 'cli' }));
        }
        if (!Array.isArray(messages) || !messages.length) return send(res, 400, JSON.stringify({ error: 'no messages' }));
        const r = await callClaudeAPI({ system, messages });
        console.log(`[api] ${messages.length} msgs → ${r.text.length}b`);
        return send(res, 200, JSON.stringify({ ...r, mode: 'api' }));
      } catch (e) { send(res, e.code === 'NO_KEY' ? 400 : 502, JSON.stringify({ error: e.message, code: e.code || 'ERR' })); }
    });
    return;
  }

  if (url.pathname === '/api/ingest' && req.method === 'POST') {
    let body = ''; let tooBig = false;
    req.on('data', c => { body += c; if (body.length > 30e6) { tooBig = true; req.destroy(); } });
    req.on('end', async () => {
      if (tooBig) return;
      try {
        const { persona, files, session } = JSON.parse(body || '{}');
        const P = PERSONA[persona] || PERSONA.lead;
        const dir = await ensureWorkspace(wsNameFor(P.ws, session));
        const written = [];
        for (const f of (files || [])) {
          const name = basename(String(f.name || 'file')).replace(/[^\w.\- ]/g, '_').slice(0, 120);
          if (!name) continue;
          await writeFile(join(dir, name), Buffer.from(f.b64 || '', 'base64'));
          written.push(name);
        }
        console.log(`[ingest] ${persona} · ${written.length} file(s) → ${P.ws}`);
        send(res, 200, JSON.stringify({ ok: true, written }));
      } catch (e) { send(res, 502, JSON.stringify({ error: e.message })); }
    });
    return;
  }

  // static files (repo root), path-traversal guarded
  const p = url.pathname === '/' ? '/index.html' : url.pathname;
  const filePath = normalize(join(ROOT, decodeURIComponent(p)));
  if (!filePath.startsWith(ROOT)) return send(res, 403, 'forbidden', 'text/plain');
  if (!existsSync(filePath)) return send(res, 404, 'not found', 'text/plain');
  try { send(res, 200, await readFile(filePath), MIME[extname(filePath)] || 'application/octet-stream'); }
  catch { send(res, 500, 'error', 'text/plain'); }
});

ensureDeps();
cleanupAllContainers();                                        // wipe any enclave containers left by a prior run
cleanupOrphans().then(r => { if (r && r.swept) console.log(`[vm-lab] startup sweep: powered off ${r.swept} orphaned lab VM(s)`); }); // backstop: no lab VM survives a crash
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { killVarvel(); cleanupAllContainers(); const bye = () => process.exit(0); const t = setTimeout(bye, 15000); labDown().finally(() => { clearTimeout(t); bye(); }); });
process.on('exit', () => { killVarvel(); cleanupAllContainers(); });   // best-effort teardown when the server stops
server.listen(PORT, '127.0.0.1', () => {
  console.log(`\n  ◈ Enclave console — live at  http://localhost:${PORT}/app.html\n`);
  if (BACKEND === 'kimi')     console.log(`  ATTACHED TO KIMI via your k3 login · ${KIMI.model} @ ${KIMI.baseUrl} (${KIMI.apiType}, ${KIMI.source}) · governed by the Enclave hook · no cyber-content classifier`);
  else if (BACKEND === 'cli') console.log(`  attached to your Claude CLI (${basename(CLAUDE)}) · model ${MODEL} · every tool call gated by clearance`);
  else if (BACKEND === 'api') console.log(`  Claude API broker (ANTHROPIC_API_KEY) · governance hook not applied`);
  else                        console.log(`  no model backend — scripted demo mode.`);
  if (BACKEND !== 'kimi' && !KIMI_OK) console.log(`  → to attach Kimi via k3 (no cyber filters, same governance): configure k3 (~/.kimicode/config.json) and restart`);
  if (BACKEND !== 'kimi' && KIMI_OK && FORCED) console.log(`  (Kimi available via k3, but ENCLAVE_BACKEND=${FORCED} is forcing ${BACKEND})`);
  if (BACKEND !== 'kimi' && KIMI_OK && !FORCED) console.log(`  (Kimi detected via k3 [${KIMI.source}] — defaulting to Claude; subscribe to K3, or set ENCLAVE_BACKEND=kimi, to use Kimi)`);
  console.log(DOCKER_OK ? '  container tier: on (sealed per-session containers) · sessions ephemeral' : '  container tier: off (Docker not detected) — host tier');
  console.log('');
});
