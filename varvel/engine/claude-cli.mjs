// VARVEL — Claude CLI backend (the host-side governed agent).
//
// VARVEL's default live agent (runGovernedAgent) runs tools inside a sealed Docker
// container. This backend instead drives the real `claude -p` on the HOST, governed by
// the SAME Enclave PreToolUse hook (wired via --settings). Two consequences that matter:
//   • it reaches host-local targets (e.g. the bundled demo on 127.0.0.1:8972) with no
//     container/network plumbing, and
//   • every tool call still crosses the hook → Cedar → allow/deny, against the SIGNED
//     identity — governance is identical to the enclave console's CLI mode.
//
// Exposes a `runAgent`-shaped function ({ system, messages }) -> { text, denials, steps }
// so the campaign can use it as a drop-in for the default agent. It never throws — a
// spawn/parse failure resolves as error text so the resilient campaign keeps going.

import { spawn, spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { HOOK_PATH, readBackend, kimiRoutable } from './live.mjs';

const WIN = process.platform === 'win32';
const fwd = (p) => p.replace(/\\/g, '/');

// Kimi is Anthropic-API-compatible, so the real `claude` CLI can run on it. When a Kimi
// backend is configured (via ~/.kimicode/config.json subscription/key or KIMI_API_KEY),
// return the env overrides that route THIS spawned claude at Kimi — SCOPED to the child
// process, so the operator's own interactive Claude Code (a different Anthropic account)
// is never affected. The key is read from the operator's config at runtime; VARVEL never
// writes or transmits it. No Kimi key configured → null (runs on the ambient Claude account).
// The kimi-code OAuth credential (the operator's CURRENT coding subscription, auto-refreshed
// by their CLI login) — the same file engine/kimi-runagent.mjs resolves its key from.
const OAUTH_FILE = join(homedir(), '.kimi-code', 'credentials', 'kimi-code.json');
// A FRESH OAuth access_token, or null. READ-ONLY (freshness margin 120s, like kimi-runagent);
// refresh/write-back stays kimi-runagent's job. env.KIMI_OAUTH_FILE overrides the path so
// tests stay hermetic on machines with a live login.
export function freshOauthToken(env = process.env, now = Math.floor(Date.now() / 1000)) {
  try {
    const j = JSON.parse(readFileSync(env.KIMI_OAUTH_FILE || OAUTH_FILE, 'utf8'));
    return j && j.access_token && Number(j.expires_at || 0) - now > 120 ? String(j.access_token) : null;
  } catch { return null; }
}

export function kimiBackend(env = process.env) {
  const b = readBackend(env);
  // Credential precedence (the 2026-08-05 kimi-runagent fix, applied to the CLI route):
  // explicit env keys -> the live OAuth token -> the legacy static cfg key LAST. A STALE
  // static key otherwise shadows the live subscription and every call fails server-side
  // before a packet leaves the box (verified 2026-09-02: cfg key -> HTTP 500, OAuth -> 200).
  // The env-key list must mirror readBackend's k3key chain (everything except cfg.apiKey).
  const envKey = env.VARVEL_API_KEY || env.KIMI_API_KEY || env.MOONSHOT_API_KEY || env.OPENROUTER_API_KEY || env.ENCLAVE_KIMI_KEY || env.ANTHROPIC_AUTH_TOKEN || '';
  const kimiKey = envKey || freshOauthToken(env) || b.kimiKey;
  // Route only with a Kimi-SCOPED key AND a Kimi/Moonshot Anthropic endpoint (kimiRoutable),
  // so the operator's ambient ANTHROPIC_API_KEY is never shipped to Kimi's servers.
  if (!kimiRoutable({ ...b, kimiKey })) return null;
  const model = b.model || 'kimi-k3';
  return {
    model, source: b.source, apiBase: b.apiBase,
    env: {
      ANTHROPIC_BASE_URL: b.apiBase,
      ANTHROPIC_AUTH_TOKEN: kimiKey, // Kimi-scoped ONLY — never a bare ambient ANTHROPIC_API_KEY
      ANTHROPIC_MODEL: model,
      // Map the aliases VARVEL passes via --model (sonnet/opus/haiku) onto the Kimi model.
      ANTHROPIC_DEFAULT_OPUS_MODEL: model,
      ANTHROPIC_DEFAULT_SONNET_MODEL: model,
      ANTHROPIC_DEFAULT_HAIKU_MODEL: model,
      CLAUDE_CODE_SUBAGENT_MODEL: model,
      // Moonshot's Kimi endpoint doesn't support the tool-search feature yet — leaving it on
      // makes tool calls misbehave, and VARVEL is entirely tool-driven. Force it off.
      ENABLE_TOOL_SEARCH: 'false',
    },
  };
}

// Ghost proxy vars (extraEnv, server.mjs ghostShellEnv) are for the agent's SHELL tools —
// curl rides the chain. They must NEVER route the CLI's OWN model-API connection: the fetch
// stack rejects the socks5 scheme outright ('UnsupportedProxyProtocol'), so every campaign
// phase died at the API call with zero tool calls and zero surface (the 2026-09-02 alsco
// run). Exempt the effective API host via NO_PROXY — the CLI reaches its model direct,
// exactly like makeKimiAgent whose server-side fetch never gets the proxy vars — while
// target-bound shell traffic keeps riding the chain. No proxy vars -> env untouched.
export function exemptApiHostFromProxy(env, apiBase) {
  const proxied = ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'].some((k) => env[k]);
  if (!proxied) return env;
  let host = '';
  try { host = new URL(String(apiBase || '')).hostname || ''; } catch { host = ''; }
  if (!host) host = 'api.anthropic.com'; // the CLI's default endpoint when no base URL is configured
  for (const k of ['NO_PROXY', 'no_proxy']) {
    const parts = String(env[k] || '').split(',').map((s) => s.trim()).filter(Boolean);
    if (!parts.includes(host)) parts.push(host);
    env[k] = parts.join(',');
  }
  return env;
}

export function findClaude() {
  try {
    const r = spawnSync(WIN ? 'where' : 'which', ['claude'], { encoding: 'utf8', windowsHide: true });
    if (r.status === 0) { const line = (r.stdout || '').split(/\r?\n/).map((s) => s.trim()).find(Boolean); if (line) return line; }
  } catch { /* not found */ }
  return null;
}
// VARVEL_NO_CLI=1 force-disables the CLI backend (used by hermetic tests, and to force
// the Kimi/container path).
export const claudeAvailable = (env = process.env) => env.VARVEL_NO_CLI !== '1' && !!findClaude();

// Same seal the enclave console applies: no publish/exfil, no sub-agents, no web, no
// scheduling/comms tools — only the sandboxed file/shell/search tools remain.
const SEAL_DISALLOW = [
  'Artifact', 'Task', 'Agent', 'Workflow', 'Skill', 'ToolSearch',
  'CronCreate', 'CronList', 'CronDelete', 'ScheduleWakeup',
  'RemoteTrigger', 'PushNotification', 'SendMessage', 'DesignSync',
  'EnterWorktree', 'ExitWorktree', 'Monitor',
  'TaskCreate', 'TaskList', 'TaskGet', 'TaskUpdate', 'TaskStop', 'TaskOutput',
  'ListMcpResourcesTool', 'ReadMcpResourceTool', 'ReadMcpResourceDirTool',
];

// Wire the PreToolUse hook into a settings file + a zero-server MCP baseline, in a
// sealed workspace directory the agent is confined to.
function ensureWorkspace(dir) {
  mkdirSync(dir, { recursive: true });
  const noMcp = join(dir, 'no-mcp.json'); writeFileSync(noMcp, '{"mcpServers":{}}');
  const settings = join(dir, 'settings.json');
  writeFileSync(settings, JSON.stringify({ hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: `node --no-warnings ${fwd(HOOK_PATH)}` }] }] } }));
  if (!existsSync(join(dir, '.git'))) { try { spawnSync('git', ['init', '-q'], { cwd: dir, stdio: 'ignore', windowsHide: true }); } catch { /* git optional */ } }
  if (!existsSync(join(dir, 'README.enclave.md'))) writeFileSync(join(dir, 'README.enclave.md'), '# VARVEL sealed workspace\nGoverned by the Enclave PreToolUse hook.\n');
  return { settings, noMcp };
}

// Human-readable one-liner for a tool call (what the operator sees as the "move").
function summarizeInput(name, input) {
  if (!input || typeof input !== 'object') return '';
  if (name === 'Bash') return String(input.command || '').replace(/\s+/g, ' ').slice(0, 220);
  if (name === 'Read' || name === 'Write' || name === 'Edit') return String(input.file_path || '').slice(0, 180);
  if (name === 'Grep' || name === 'Glob') return String(input.pattern || input.path || '').slice(0, 140);
  try { return JSON.stringify(input).slice(0, 180); } catch { return ''; }
}
function extractResult(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) return content.map((b) => (typeof b === 'string' ? b : (b && b.text) || '')).join(' ');
  return '';
}

// Build a runAgent function backed by the Claude CLI. `sessionFile` = the SIGNED session
// (identity + scope); `wsDir` = the sealed workspace; `model` = a `claude --model` value.
//
// STREAMS: uses --output-format stream-json so each move (thinking text, tool call, tool
// result) surfaces live via the optional `onStep` callback and is collected in `stepLog`.
// `steps` stays a NUMBER (turn count) for the campaign's budget accounting.
export function makeClaudeAgent({ sessionFile, wsDir, model = 'sonnet', timeoutMs = 180000, claudePath, extraEnv = {} } = {}) {
  const CLAUDE = claudePath || findClaude();
  if (!CLAUDE) throw new Error('claude CLI not found on PATH');
  const { settings, noMcp } = ensureWorkspace(wsDir);
  const kimi = kimiBackend();               // resolve once: are we routing this backend at Kimi?
  const effModel = kimi ? kimi.model : model; // on Kimi, always use the Kimi model name

  return function claudeAgent({ system, messages, resumeId, onStep }) {
    return new Promise((resolve) => {
      const message = (messages && messages[0] && messages[0].content) || '';
      const args = ['-p', message, '--settings', settings, '--output-format', 'stream-json', '--verbose', '--model', effModel,
        '--strict-mcp-config', '--mcp-config', noMcp, '--disallowedTools', ...SEAL_DISALLOW];
      if (resumeId) args.push('--resume', resumeId); // multi-turn continuity for interactive chat
      if (system) args.push('--append-system-prompt', system);
      // Child env: Enclave handoff + (when configured) the scoped Kimi routing. Deleting
      // ANTHROPIC_API_KEY stops an ambient Anthropic key from shadowing the Kimi token.
      const cenv = { ...process.env, ENCLAVE_SESSION: sessionFile, ENCLAVE_WORKSPACE_DIR: wsDir, ENCLAVE_CONTAINER: '', NODE_NO_WARNINGS: '1' };
      if (kimi) {
        Object.assign(cenv, kimi.env);
        delete cenv.ANTHROPIC_API_KEY;         // stop an ambient Anthropic key shadowing the Kimi token (dual-header 401)
        delete cenv.CLAUDE_CODE_USE_BEDROCK;   // an inherited Bedrock/Vertex flag makes the CLI ignore ANTHROPIC_BASE_URL →
        delete cenv.CLAUDE_CODE_USE_VERTEX;    // Kimi routing would silently fail AND send VARVEL's prompts to the op's cloud
      }
      // extraEnv parity with makeKimiAgent (ghost shell-proxy vars ride here; they carry
      // no ANTHROPIC_* keys, so the Kimi routing above is untouched).
      Object.assign(cenv, extraEnv);
      // ...but the proxy vars are for the agent's SHELL tools only — exempt the model API
      // host or the CLI's own connection dies on the socks5 scheme (see exemptApiHostFromProxy).
      exemptApiHostFromProxy(cenv, kimi ? kimi.apiBase : cenv.ANTHROPIC_BASE_URL);
      const child = spawn(CLAUDE, args, { cwd: wsDir, windowsHide: true, env: cenv });
      let buf = '', err = '', final = null, sessionId = null, turns = 0, settled = false;
      const denials = [], stepLog = [];
      const emit = (step) => { stepLog.push(step); if (onStep) { try { onStep(step); } catch {} } };
      const handleLine = (line) => {
        let j; try { j = JSON.parse(line); } catch { return; }
        if (j.type === 'assistant' && j.message && Array.isArray(j.message.content)) {
          turns++;
          for (const b of j.message.content) {
            if (b.type === 'text' && b.text && b.text.trim()) emit({ kind: 'text', text: b.text });
            else if (b.type === 'tool_use') emit({ kind: 'tool', name: b.name, detail: summarizeInput(b.name, b.input) });
          }
        } else if (j.type === 'user' && j.message && Array.isArray(j.message.content)) {
          for (const b of j.message.content) {
            if (b.type === 'tool_result') {
              const t = extractResult(b.content);
              const denied = /denied by the enclave|DENIED\b/i.test(t);
              if (denied) denials.push('tool');
              emit({ kind: 'result', text: String(t).replace(/\s+/g, ' ').slice(0, 300), denied });
            }
          }
        } else if (j.type === 'result') {
          final = j.result || ''; sessionId = j.session_id || sessionId; turns = j.num_turns || turns;
          for (const d of (j.permission_denials || [])) denials.push(d.tool_name || d.tool || 'tool');
        } else if (j.type === 'system' && j.session_id) { sessionId = j.session_id; }
      };
      const done = (extra = {}) => { if (settled) return; settled = true; clearTimeout(killer); resolve({ text: final != null ? final : (extra.text || ''), denials, steps: turns || 1, stepLog, sessionId, model, ...extra }); };
      const killer = setTimeout(() => { try { child.kill(); } catch {} done({ text: final || '(claude timed out)', error: 'timeout' }); }, timeoutMs);
      child.stdout.on('data', (d) => { buf += d; let nl; while ((nl = buf.indexOf('\n')) >= 0) { const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1); if (line) handleLine(line); } });
      child.stderr.on('data', (d) => (err += d));
      child.on('error', (e) => done({ text: '(claude spawn error: ' + e.message + ')', error: e.message }));
      child.on('close', () => { if (buf.trim()) handleLine(buf.trim()); if (final == null && !stepLog.length && err) done({ text: '(no output)', error: err.slice(0, 200) }); else done(); });
      child.stdin.end();
    });
  };
}
