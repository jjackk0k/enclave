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
import { existsSync, readFileSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname, normalize, basename } from 'node:path';
import { homedir } from 'node:os';

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
  const r = spawnSync(WIN ? 'where' : 'which', ['claude'], { encoding: 'utf8' });
  if (r.status === 0) { const line = (r.stdout || '').split(/\r?\n/).map(s => s.trim()).find(Boolean); if (line) return line; }
  return null;
}
const CLAUDE = findClaude();
const MODE = CLAUDE ? 'cli' : (process.env.ANTHROPIC_API_KEY ? 'api' : 'scripted');

// console persona key  →  SIGNED identity file  +  sealed workspace name
const PERSONA = {
  jr:   { session: 'sam.json',    ws: 'triage-queue'     },
  grc:  { session: 'priya.json',  ws: 'soc2-evidence-q3' },
  ir:   { session: 'dana.json',   ws: 'incident-2231'    },
  red:  { session: 'marcus.json', ws: 'pentest-northwind'},
  lead: { session: 'alex.json',   ws: 'command-deck'     },
};

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
const MODEL_ALIAS = { opus: 'opus', sonnet: 'sonnet', haiku: 'haiku' };

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
function callClaudeCLI({ message, persona, resumeId, system, model }) {
  return new Promise(async (resolve, reject) => {
    const P = PERSONA[persona] || PERSONA.lead;
    const sessionFile = join(SEAM, 'session', P.session);
    if (!existsSync(sessionFile)) return reject(new Error('no signed identity for persona ' + persona));
    const dir = await ensureWorkspace(P.ws);
    const useModel = MODEL_ALIAS[model] || MODEL;
    const args = ['-p', message,
      '--settings', settingsPath(P.ws),
      '--output-format', 'json',
      '--model', useModel,
      '--strict-mcp-config', '--mcp-config', join(LIVE, 'no-mcp.json'),  // seal: no inherited MCP servers
      '--disallowedTools', ...SEAL_DISALLOW];                            // seal: no web / no subagents
    if (system)   args.push('--append-system-prompt', system);
    if (resumeId) args.push('--resume', resumeId);
    const child = spawn(CLAUDE, args, { cwd: dir, windowsHide: true,
      env: { ...process.env, ENCLAVE_SESSION: sessionFile, NODE_NO_WARNINGS: '1' } });
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

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');

  if (url.pathname === '/api/health') {
    return send(res, 200, JSON.stringify({ live: MODE !== 'scripted', mode: MODE, model: MODEL,
      claude: CLAUDE ? basename(CLAUDE) : null, keyPresent: !!process.env.ANTHROPIC_API_KEY }));
  }
  if (url.pathname === '/api/audit') {
    return send(res, 200, JSON.stringify({ decisions: recentAudit(Number(url.searchParams.get('n')) || 25) }));
  }
  if (url.pathname === '/api/chat' && req.method === 'POST') {
    let body = '';
    req.on('data', c => (body += c));
    req.on('end', async () => {
      try {
        const { message, persona, resumeId, system, messages, model } = JSON.parse(body || '{}');
        if (MODE === 'cli') {
          if (!message) return send(res, 400, JSON.stringify({ error: 'no message' }));
          const r = await callClaudeCLI({ message, persona, resumeId, system, model });
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
        const { persona, files } = JSON.parse(body || '{}');
        const P = PERSONA[persona] || PERSONA.lead;
        const dir = await ensureWorkspace(P.ws);
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
server.listen(PORT, '127.0.0.1', () => {
  console.log(`\n  ◈ Enclave console — live at  http://localhost:${PORT}/app.html\n`);
  if (MODE === 'cli')      console.log(`  attached to your Claude CLI (${basename(CLAUDE)}) · model ${MODEL} · every tool call gated by clearance`);
  else if (MODE === 'api') console.log(`  Claude CLI not found — using API broker (ANTHROPIC_API_KEY) · governance hook not applied`);
  else                     console.log(`  no Claude CLI and no ANTHROPIC_API_KEY — console runs in scripted demo mode`);
  console.log('');
});
