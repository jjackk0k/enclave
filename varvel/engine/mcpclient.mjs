// VARVEL — Direction B: VARVEL as an MCP CLIENT (consume the community ecosystem).
//
// External MCP servers are POWERFUL and UNTRUSTED. The discipline:
//   1. They are never auto-discovered. The ONLY source is an operator-written JSON
//      config (data/mcp.servers.json, or VARVEL_MCP_SERVERS) naming each server by
//      ABSOLUTE path. mcp.allowExternal=false (the default) refuses to even spawn one
//      — spawning a community server IS executing untrusted code, so the setting
//      gates the spawn itself.
//   2. Every tools/call crosses the governance bridge (engine/mcpgov.mjs) BEFORE the
//      child sees it: target args are extracted and classified against the signed
//      scope and the research egress allowlist. A call naming an out-of-scope host
//      is DENIED before dispatch — with lazy spawn, before the child is even started.
//   3. Everything is audited: the spawn decision and every call's verdict.
//   4. Timeouts, child reaping, never-throw: a hung/wedged/crashed external server
//      returns { ok:false } — it can never take the platform down with it.

import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { isAbsolute, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createFrameDecoder, encodeMessage, MCP_PROTOCOL_VERSION } from './mcprpc.mjs';
import { judgeCall, externalPolicy, makeAuditEntry, VERDICT } from './mcpgov.mjs';
import { McpScreen, SCREEN_POLICY } from './mcpguard.mjs';

// Env allowlist handed to the untrusted child (plus the entry's own `env` overrides):
// enough to run, NOT the operator's whole credential-laden environment.
const CHILD_ENV_KEYS = ['PATH', 'PATHEXT', 'COMSPEC', 'SystemRoot', 'WINDIR', 'HOME', 'USERPROFILE', 'TEMP', 'TMP', 'NODE_ENV'];

export function defaultServersFile(env = process.env) {
  if (env.VARVEL_MCP_SERVERS) return env.VARVEL_MCP_SERVERS;
  return join(dirname(fileURLToPath(import.meta.url)), '..', 'data', 'mcp.servers.json');
}

// Load + validate the external-server registry. NEVER throws — a malformed config
// yields zero usable servers and named errors (fail-closed, honestly reported).
// Config shape:
//   { "servers": [ { "name": "fs", "command": "C:\\abs\\path\\server.mjs",
//                    "args": ["--flag"], "env": {"K":"V"}, "timeoutMs": 20000 } ] }
export function loadExternalServers(file) {
  const out = { ok: false, file: String(file || ''), servers: [], errors: [] };
  let cfg;
  try {
    if (!file || !existsSync(file)) { out.errors.push('no external-server config at ' + (file || '(unset)') + ' — external MCP servers are operator-configured by absolute path, never auto-discovered'); return out; }
    cfg = JSON.parse(readFileSync(file, 'utf8'));
  } catch (e) { out.errors.push('unreadable/invalid config: ' + String((e && e.message) || e)); return out; }
  const list = Array.isArray(cfg && cfg.servers) ? cfg.servers : [];
  for (const s of list) {
    const name = s && typeof s.name === 'string' ? s.name.trim() : '';
    const command = s && typeof s.command === 'string' ? s.command : '';
    if (!name) { out.errors.push('a server entry has no name — skipped'); continue; }
    if (!command || !isAbsolute(command)) { out.errors.push(`server '${name}': command must be an ABSOLUTE path (got ${JSON.stringify(command || '')}) — skipped`); continue; }
    out.servers.push({
      name,
      command,
      args: Array.isArray(s.args) ? s.args.map(String) : [],
      env: s.env && typeof s.env === 'object' ? Object.fromEntries(Object.entries(s.env).map(([k, v]) => [String(k), String(v)])) : {},
      timeoutMs: Number.isFinite(Number(s.timeoutMs)) && Number(s.timeoutMs) > 0 ? Math.floor(Number(s.timeoutMs)) : undefined,
      // Operator override for the content screen: named tools are exempt from
      // quarantine (findings are still scanned/audited — override narrows
      // quarantine, never visibility). See engine/mcpguard.mjs.
      trustedTools: Array.isArray(s.trustedTools) ? s.trustedTools.map(String) : [],
    });
  }
  out.ok = true;
  return out;
}

export class McpClient {
  // `server`: one validated entry from loadExternalServers. `spawnImpl` is the test
  // seam (spy assertion: a DENIED call must never reach spawn). `externalAllowed`
  // is settings mcp.allowExternal. All I/O methods return { ok, ... } — never throw.
  constructor({ server, scope, ghost = { mode: 'off', verifiedOk: false }, knownHosts = [], externalAllowed = false, auditSink = () => {}, spawnImpl = spawn, timeoutMs = 30000, screenPolicy = SCREEN_POLICY.QUARANTINE, trustedTools, listingCache = 'off' } = {}) {
    if (!server || typeof server.command !== 'string' || !server.command) throw new TypeError('McpClient needs a server entry with a command');
    this.server = server;
    this.scope = scope && typeof scope === 'object' ? scope : { cidrs: [] };
    this.ghost = ghost;
    this.knownHosts = knownHosts;
    this.externalAllowed = !!externalAllowed;
    this.auditSink = typeof auditSink === 'function' ? auditSink : () => {};
    this._spawn = typeof spawnImpl === 'function' ? spawnImpl : spawn;
    this.timeoutMs = Math.max(1000, Math.floor(Number(server.timeoutMs || timeoutMs) || 30000));
    // Content screen (mcpguard): scans every listing and every tool output for
    // instruction-like content and descriptor drift. Default QUARANTINE — a poisoned
    // tool is refused, never silently executed. `trustedTools` (server config or
    // explicit opt) is the operator override. `listingCache`: 'off' (default — every
    // listTools re-lists and re-screens, so a rug-pull is seen at the next listing)
    // or 'session' (legacy first-listing cache; audited as an accepted staleness risk).
    this._screen = new McpScreen({
      server: server.name,
      policy: screenPolicy,
      trustedTools: [...(Array.isArray(server.trustedTools) ? server.trustedTools : []), ...(Array.isArray(trustedTools) ? trustedTools : [])],
    });
    this.listingCache = listingCache === 'session' ? 'session' : 'off';
    this._cacheAuditDone = false;
    this._child = null;
    this._starting = null;   // memoized start promise
    this._nextId = 1;
    this._pending = new Map(); // id -> { resolve, timer }
    this._tools = null;        // last screened tools/list (for status; served only when listingCache==='session')
    this._stderr = '';         // bounded diagnostics (8KB)
    this.dead = false;         // set when the child exited/was reaped
  }

  _audit(tool, args, verdict) {
    try { this.auditSink(makeAuditEntry({ direction: 'external', server: this.server.name, tool, args, verdict, at: new Date().toISOString() })); } catch { /* audit tap never breaks the client */ }
  }

  _childEnv() {
    const env = {};
    for (const k of CHILD_ENV_KEYS) if (process.env[k] !== undefined) env[k] = process.env[k];
    return { ...env, ...(this.server.env || {}) };
  }

  _failAllPending(error) {
    for (const [, p] of this._pending) { clearTimeout(p.timer); p.resolve({ ok: false, error }); }
    this._pending.clear();
  }

  _spawnChild() {
    const child = this._spawn(this.server.command, this.server.args || [], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: this._childEnv(),
    });
    child.unref && child.unref(); // the child must never hold the parent process open
    child.stdout.setEncoding('utf8');
    const decoder = createFrameDecoder({
      onMessage: (msg) => {
        const id = msg && msg.id;
        if (id === undefined || id === null || !this._pending.has(id)) return; // stray/notification
        const p = this._pending.get(id);
        this._pending.delete(id);
        clearTimeout(p.timer);
        if (msg.error) p.resolve({ ok: false, error: `RPC ${msg.error.code}: ${msg.error.message}` });
        else p.resolve({ ok: true, result: msg.result });
      },
      onError: () => { /* a peer emitting garbage frames: its requests time out honestly */ },
    });
    child.stdout.on('data', (c) => decoder.push(c));
    child.stderr && child.stderr.on('data', (c) => { this._stderr = (this._stderr + c).slice(-8192); });
    child.on('error', (e) => { if (this._child !== child) return; this.dead = true; this._failAllPending('external MCP server failed to start: ' + String((e && e.message) || e)); });
    // Stale-child guard: a reaped child's exit event can arrive AFTER a fresh child
    // was spawned — it must never fail the new child's pending requests (found by the
    // timeout-then-respawn test).
    child.on('exit', (code) => { if (this._child !== child) return; this.dead = true; this._failAllPending(`external MCP server '${this.server.name}' exited (code ${code})`); });
    child.stdin.on('error', () => { /* EPIPE on a dead child: the exit path reports it */ });
    return child;
  }

  // One JSON-RPC request with timeout. On timeout the child is KILLED — a wedged
  // external server is distrusted; the next call respawns fresh.
  _request(method, params) {
    if (!this._child || this.dead) return Promise.resolve({ ok: false, error: 'external MCP server is not running' });
    const id = this._nextId++;
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this._pending.delete(id);
        this._reap();
        resolve({ ok: false, error: `external MCP server '${this.server.name}' timed out after ${this.timeoutMs}ms (${method}) — child reaped`, timeout: true });
      }, this.timeoutMs);
      timer.unref && timer.unref();
      this._pending.set(id, { resolve, timer });
      try { this._child.stdin.write(encodeMessage({ jsonrpc: '2.0', id, method, params })); }
      catch (e) { this._pending.delete(id); clearTimeout(timer); resolve({ ok: false, error: 'write to external MCP server failed: ' + String((e && e.message) || e) }); }
    });
  }

  // Lazy start: the FIRST allowed use spawns the child. A denied call never reaches
  // here — that is the whole point of the bridge (denial before the child exists).
  async _ensureStarted() {
    if (this._child && !this.dead) return { ok: true };
    if (this._starting) return this._starting;
    this._starting = (async () => {
      if (!this.externalAllowed) {
        const verdict = { verdict: 'deny', reason: 'external MCP calls are disabled (mcp.allowExternal=false)' };
        this._audit('mcp.external.spawn', { command: this.server.command }, verdict);
        return { ok: false, error: verdict.reason };
      }
      this._audit('mcp.external.spawn', { command: this.server.command, args: this.server.args || [] }, { verdict: 'allow', reason: 'operator-configured external server' });
      this.dead = false;
      try { this._child = this._spawnChild(); }
      catch (e) { this.dead = true; return { ok: false, error: 'spawn failed: ' + String((e && e.message) || e) }; }
      const init = await this._request('initialize', {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: 'varvel', version: '0.1.0' },
      });
      if (!init.ok) { this._reap(); return { ok: false, error: 'MCP handshake failed: ' + init.error }; }
      this._write({ jsonrpc: '2.0', method: 'notifications/initialized' });
      this._serverInfo = init.result || {};
      return { ok: true };
    })();
    try { return await this._starting; }
    finally { this._starting = null; }
  }

  _write(msg) { try { this._child && this._child.stdin.write(encodeMessage(msg)); } catch { /* dead child — pending requests time out */ } }

  _reap() {
    const c = this._child;
    this._child = null;
    this.dead = true;
    this._tools = null;
    if (c) {
      try { c.stdin.end(); } catch { /* */ }
      try { c.kill(); } catch { /* already gone */ }
    }
  }

  // Content-screen audit lane: findings land in the SAME ledger as call verdicts
  // (makeAuditEntry shape), with verdict 'flag' — a screen observation, not a call
  // disposition. Quarantine REFUSALS are audited as 'deny' on the tool itself.
  _auditScreen(tool, args, reason) {
    this._audit(tool, args, { verdict: VERDICT.FLAG, reason });
  }

  // tools/list — requires the spawn gate (externalAllowed) like everything else.
  // Every fresh listing is content-screened BEFORE it becomes usable: description
  // scan (poison) + descriptor drift vs the baseline listing (rug-pull). Default
  // cache policy 'off': each call re-lists, so a mutation is seen at the NEXT
  // listing instead of the client acting on a stale approval snapshot forever.
  async listTools({ refresh = false } = {}) {
    try {
      if (this.listingCache === 'session') {
        if (this._tools && !refresh) {
          if (!this._cacheAuditDone) {
            this._cacheAuditDone = true;
            this._auditScreen('mcp.screen.cache', { policy: 'session' }, 'session listing cache enabled — descriptor mutation between listings is invisible until an explicit refresh; accepted operator risk');
          }
          return { ok: true, tools: this._tools, quarantined: this._screen.quarantined(), cached: true };
        }
      }
      const st = await this._ensureStarted();
      if (!st.ok) return st;
      const r = await this._request('tools/list', {});
      if (!r.ok) return r;
      const tools = (r.result && Array.isArray(r.result.tools)) ? r.result.tools : [];
      const screen = this._screen.screenListing(tools);
      for (const f of screen.findings) {
        this._auditScreen('mcp.screen.listing', { tool: f.tool, detector: f.detector, kind: f.kind || null, rules: (f.hits || []).map((h) => h.rule) },
          `content screen: ${f.detector} flagged '${f.tool}'${f.kind ? ' (' + f.kind + ')' : ''}`);
      }
      for (const t of screen.quarantined) {
        this._auditScreen('mcp.screen.quarantine', { tool: t, reasons: this._screen.quarantineReasons(t) },
          `tool '${t}' QUARANTINED — refused until the operator trusts it (policy: ${this._screen.policy})`);
      }
      for (const t of screen.overridden) {
        this._auditScreen('mcp.screen.override', { tool: t }, `operator trustedTools override: '${t}' flagged but callable (still output-scanned)`);
      }
      this._tools = tools;
      return { ok: true, tools, quarantined: this._screen.quarantined(), screenFindings: screen.findings.length };
    } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
  }

  // tools/call: governance bridge FIRST (a scope-denied call must never even spawn
  // the child), then the CONTENT SCREEN: if no screened listing exists yet, mount
  // one (list + screen) before dispatch — never call a tool whose description no
  // screen has seen. Quarantined tools are refused, audited 'deny'. Allowed results
  // are output-scanned: steering content in a tool RESULT is flagged + audited +
  // annotated on the return (the result already exists; the consumer must SEE it).
  async callTool(name, args = {}) {
    try {
      const verdict = judgeCall({
        direction: 'external', tool: name, args,
        policy: externalPolicy(), scope: this.scope, ghost: this.ghost,
        knownHosts: this.knownHosts, externalAllowed: this.externalAllowed,
      });
      this._audit(String(name || ''), args, verdict);
      if (verdict.verdict === 'deny') return { ok: false, denied: true, verdict, error: 'DENIED by the VARVEL governance bridge: ' + verdict.reason };
      if (verdict.verdict === 'hold') return { ok: false, held: true, verdict, error: 'HELD by the VARVEL governance bridge: ' + verdict.reason };
      if (this._tools === null) { // mount path: screen a listing before the first call
        const l = await this.listTools();
        if (!l.ok) return { ...l, verdict };
      }
      if (this._screen.isQuarantined(name)) {
        const reasons = this._screen.quarantineReasons(name);
        this._audit(String(name || ''), args, { verdict: VERDICT.DENY, reason: `quarantined by the MCP content screen (${reasons.join(', ')}) — an operator can release it via trustedTools after review` });
        return { ok: false, denied: true, quarantined: true, error: 'QUARANTINED by the MCP content screen: ' + reasons.join(', ') };
      }
      const st = await this._ensureStarted();
      if (!st.ok) return { ...st, verdict };
      const r = await this._request('tools/call', { name: String(name), arguments: args && typeof args === 'object' ? args : {} });
      if (!r.ok) return { ...r, verdict };
      const outText = (r.result && Array.isArray(r.result.content))
        ? r.result.content.filter((c) => c && c.type === 'text').map((c) => c.text).join('\n') : '';
      const outFindings = this._screen.screenOutput(name, outText);
      if (outFindings.length) {
        for (const f of outFindings) {
          this._auditScreen('mcp.screen.output', { tool: f.tool, rules: f.hits.map((h) => h.rule) },
            `content screen: output-scan flagged '${f.tool}' result — possible steering/injection content (${f.hits.map((h) => h.rule).join(', ')})`);
        }
        return { ok: true, result: r.result, verdict, screen: { flagged: true, findings: outFindings } };
      }
      return { ok: true, result: r.result, verdict };
    } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
  }

  // Reap the child; always safe to call, never throws.
  async close() {
    try { this._reap(); } catch { /* */ }
    this._failAllPending('client closed');
  }

  status() {
    return { server: this.server.name, command: this.server.command, running: !!(this._child && !this.dead), toolsCached: this._tools ? this._tools.length : 0, externalAllowed: this.externalAllowed, screen: { policy: this._screen.policy, listingCache: this.listingCache, quarantined: this._screen.quarantined() } };
  }
}
