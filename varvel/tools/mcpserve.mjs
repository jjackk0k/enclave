#!/usr/bin/env node
// VARVEL — Direction A: VARVEL AS an MCP server (stdio transport).
//
// Any MCP-speaking client (Claude, an IDE, another agent) can now call VARVEL's
// governed tools — but NOTHING here bypasses the platform: every tools/call crosses
// the governance bridge (engine/mcpgov.mjs) with the SAME scope classification the
// Enclave seam uses, the ghost posture, and the audit ledger, before the tool runs.
// This exposes the curated tool surface the AI itself gets (the recon/query tools of
// tools/cli.mjs), NOT a raw CLI passthrough — each tool declares its policy and the
// bridge enforces it.
//
//   node tools/mcpserve.mjs                      # stdio server (newline-delimited JSON-RPC)
//   VARVEL_MCP_SCOPE=127.0.0.0/8 node tools/mcpserve.mjs
//
// Scope resolution order (fail-closed, mirrors server.mjs):
//   1. VARVEL_MCP_SCOPE (cidr csv) — explicit operator/test override
//   2. the signed Enclave session's engagement scope (readOperator -> scopeForCampaign)
//   3. standalone fallback: 127.0.0.0/8 ONLY (loopback — the demo's ring; nothing else)
// Ghost posture: ghost.mode from the engagement settings; verifiedOk comes from
// VARVEL_GHOST_VERIFIED=1 (the console sets it after a fresh verify when it spawns
// this server). mode=required without that proof => target-touching calls DENIED.
// Gate: mcp.serverEnabled setting must be true OR VARVEL_MCP_SERVER=1 (a direct CLI
// launch by the operator is itself the enable — the setting governs programmatic
// spawns). Every call is audited to data/mcp-audit.jsonl (VARVEL_MCP_AUDIT_FILE).

import { crawl } from './crawl.mjs';
import { apiSurface } from './apisurface.mjs';
import { webScan } from './webscan.mjs';
import { analyzeTls } from './tlsscan.mjs';
import { scanHost } from './recon.mjs';
import { Settings } from '../engine/settings.mjs';
import { stateCounts, query, redact, KINDS } from '../engine/statestore.mjs';
import { parseChain } from '../engine/ghost.mjs';
import { readOperator, scopeForCampaign } from '../engine/identity.mjs';
import { judgeCall, makeAuditEntry, fileAuditSink, defaultAuditFile, POLICY_CLASS } from '../engine/mcpgov.mjs';
import { createRouter, createFrameDecoder, encodeMessage, initializeResult, toolsListResult, toolCallResult, parseToolCall } from '../engine/mcprpc.mjs';

const READONLY = POLICY_CLASS.READONLY, TARGET = POLICY_CLASS.TARGET;

// The curated surface. Each tool: MCP descriptor + governance policy + runner.
// `run` executes ONLY after the bridge says allow. Every runner returns JSON-safe
// data; the honesty contracts of the underlying tools (content-verified, budget-
// capped, stealth-paced) are untouched.
export function varvelTools({ engagement = 'default', readImpl = {} } = {}) {
  const R = readImpl; // test seams: { scanHost, webScan, apiSurface, crawl, analyzeTls }
  return [
    {
      name: 'varvel_ghost_status',
      description: 'Ghost Mode posture for this engagement (mode, proxy chain as host:port hops, verification state as configured). Read-only — answers even when the chain is down.',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      policy: { class: READONLY, targetFields: [] },
      async run() {
        let mode = 'off', chain = '';
        try { const s = Settings.for(engagement); mode = s.get('ghost.mode'); chain = s.get('ghost.chain'); } catch { /* unreadable -> ghost off */ }
        let hops = [];
        try { hops = parseChain(chain).map((h) => `${h.scheme}://${h.host}:${h.port}`); } catch { hops = []; } // never credentials
        return { engagement, mode, chain: hops, hops: hops.length, verified: process.env.VARVEL_GHOST_VERIFIED === '1' || null };
      },
    },
    {
      name: 'varvel_state_query',
      description: 'External state store: counts by kind (hosts/creds/sessions/findings/notes) and optionally a REDACTED listing of one kind — secrets never leave the store.',
      inputSchema: {
        type: 'object',
        properties: {
          kind: { type: 'string', enum: KINDS, description: 'optional — list this kind (redacted)' },
        },
        additionalProperties: false,
      },
      policy: { class: READONLY, targetFields: [] },
      async run({ kind } = {}) {
        const out = { engagement, counts: stateCounts(engagement) };
        if (kind && KINDS.includes(kind)) out[kind] = query(engagement, kind).map(redact);
        return out;
      },
    },
    {
      name: 'varvel_recon',
      description: 'Port/service recon of ONE host (banner + version + HTTP/TLS fingerprint + favicon hash). Target-touching: the host must sit inside the signed scope.',
      inputSchema: {
        type: 'object',
        properties: {
          host: { type: 'string', description: 'target host (IP literal or engagement-surfaced name)' },
          ports: { type: 'array', items: { type: 'integer' }, description: 'optional explicit port list (default: the curated common set)' },
        },
        required: ['host'],
        additionalProperties: false,
      },
      policy: { class: TARGET, targetFields: ['host'] },
      async run({ host, ports } = {}) {
        const fn = R.scanHost || scanHost;
        const opts = {};
        if (Array.isArray(ports) && ports.length) opts.ports = ports.map((p) => Math.floor(Number(p))).filter((p) => p > 0 && p < 65536).slice(0, 256);
        return await fn(String(host || ''), opts);
      },
    },
    {
      name: 'varvel_webscan',
      description: 'Web content discovery + sensitive-exposure scan (soft-404-calibrated, content-validated, GET-only). Target-touching: signed scope required.',
      inputSchema: {
        type: 'object',
        properties: { url: { type: 'string', description: 'base URL of the target (http(s)://host[:port])' } },
        required: ['url'],
        additionalProperties: false,
      },
      policy: { class: TARGET, targetFields: ['url'] },
      async run({ url } = {}) { return await (R.webScan || webScan)(String(url || '')); },
    },
    {
      name: 'varvel_apisurface',
      description: 'API surface mining: robots/sitemap/OpenAPI/GraphQL/JS endpoints. Target-touching: signed scope required.',
      inputSchema: {
        type: 'object',
        properties: { url: { type: 'string', description: 'base URL of the target' } },
        required: ['url'],
        additionalProperties: false,
      },
      policy: { class: TARGET, targetFields: ['url'] },
      async run({ url } = {}) { return await (R.apiSurface || apiSurface)(String(url || '')); },
    },
    {
      name: 'varvel_crawl',
      description: 'BFS crawl of the target\'s own links/forms into endpoints+params+tech (page-budgeted). Target-touching: signed scope required.',
      inputSchema: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'base URL of the target' },
          maxPages: { type: 'integer', minimum: 1, maximum: 200, description: 'page budget (default: engine default)' },
        },
        required: ['url'],
        additionalProperties: false,
      },
      policy: { class: TARGET, targetFields: ['url'] },
      async run({ url, maxPages } = {}) {
        const opts = {};
        if (Number.isFinite(Number(maxPages)) && Number(maxPages) > 0) opts.maxPages = Math.min(200, Math.floor(Number(maxPages)));
        return await (R.crawl || crawl)(String(url || ''), opts);
      },
    },
    {
      name: 'varvel_tlsscan',
      description: 'TLS posture of one host:port (protocol, cipher, cert validity, weak-protocol probes). Target-touching: signed scope required.',
      inputSchema: {
        type: 'object',
        properties: {
          host: { type: 'string', description: 'target host (IP literal or engagement-surfaced name)' },
          port: { type: 'integer', minimum: 1, maximum: 65535, description: 'default 443' },
        },
        required: ['host'],
        additionalProperties: false,
      },
      policy: { class: TARGET, targetFields: ['host'] },
      async run({ host, port } = {}) {
        const p = Math.floor(Number(port));
        return await (R.analyzeTls || analyzeTls)(String(host || ''), p > 0 && p < 65536 ? p : 443);
      },
    },
  ];
}

// The whole server as an injectable unit: (msg) -> response | null, plus the shared
// context. Tests drive handleMessage in-process; main() wires it to stdio.
export function createVarvelMcpServer({ scope, ghost, engagement = 'default', knownHosts = [], auditSink = () => {}, tools, serverEnabled = true } = {}) {
  const toolList = tools || varvelTools({ engagement });
  const byName = new Map(toolList.map((t) => [t.name, t]));
  const audit = (direction, tool, args, verdict, server = null) => {
    try { auditSink(makeAuditEntry({ direction, server, tool, args, verdict, at: new Date().toISOString() })); } catch { /* audit tap never breaks the server */ }
  };

  const route = createRouter({
    handlers: {
      initialize(params = {}) {
        audit('server', 'mcp.initialize', { protocolVersion: params.protocolVersion || null }, { verdict: serverEnabled ? 'allow' : 'deny', reason: serverEnabled ? 'handshake' : 'mcp.serverEnabled=false' });
        if (!serverEnabled) {
          const e = new Error('VARVEL MCP server is disabled (mcp.serverEnabled=false)'); e.rpcCode = -32603; throw e;
        }
        return initializeResult({
          clientVersion: params.protocolVersion,
          instructions: 'VARVEL governed red-team tools. Every call crosses the governance bridge: signed scope, ghost posture, audit. A DENIED or HELD result is final for this session — do not rephrase to get past it.',
        });
      },
      ping() { return {}; },
      'tools/list'() { return toolsListResult(toolList); },
      async 'tools/call'(params = {}) {
        const { name, args } = parseToolCall(params, [...byName.keys()]);
        const tool = byName.get(name);
        const verdict = judgeCall({ direction: 'server', tool: name, args, policy: tool.policy, scope, ghost, knownHosts });
        audit('server', name, args, verdict);
        if (verdict.verdict === 'deny') return toolCallResult(`DENIED by the VARVEL governance bridge: ${verdict.reason}`, { isError: true });
        if (verdict.verdict === 'hold') return toolCallResult(`HELD by the VARVEL governance bridge: ${verdict.reason}. An operator can resolve this hold (surface the target into scope) and re-issue the call.`, { isError: true });
        const value = await tool.run(args);
        return toolCallResult(value);
      },
    },
    onNotification() { /* initialized/cancelled: acknowledged, nothing to do */ },
  });

  return { handleMessage: (msg) => route(msg, {}), tools: toolList };
}

// ── stdio wiring (main) ───────────────────────────────────────────────────────

async function resolveScope(env = process.env) {
  if (env.VARVEL_MCP_SCOPE) {
    const cidrs = String(env.VARVEL_MCP_SCOPE).split(',').map((s) => s.trim()).filter(Boolean);
    return { scope: { engagement: env.VARVEL_ENGAGEMENT || 'mcp-explicit', signedBy: 'operator (VARVEL_MCP_SCOPE)', cidrs }, note: 'explicit env scope' };
  }
  try {
    const op = await readOperator(env);
    const s = scopeForCampaign(op);
    if (s) return { scope: s, note: 'signed Enclave session scope' };
  } catch { /* no session -> fall through */ }
  // Standalone fallback: loopback ONLY — the demo's ring, mirroring server.mjs's
  // interactive fallback. An MCP client in a bare checkout can touch the demo and
  // nothing else.
  return { scope: { engagement: env.VARVEL_ENGAGEMENT || 'standalone', signedBy: 'standalone (no signed session)', cidrs: ['127.0.0.0/8'] }, note: 'standalone fallback: loopback only' };
}

function resolveGhost(env = process.env) {
  let mode = 'off';
  try { mode = Settings.for(env.VARVEL_ENGAGEMENT || 'default').get('ghost.mode'); } catch { /* unreadable -> off */ }
  return { mode, verifiedOk: env.VARVEL_GHOST_VERIFIED === '1' };
}

async function main() {
  const env = process.env;
  const engagement = env.VARVEL_ENGAGEMENT || 'default';
  let enabled = env.VARVEL_MCP_SERVER === '1';
  if (!enabled) { try { enabled = Settings.for(engagement).get('mcp.serverEnabled') === true; } catch { enabled = false; } }

  const { scope, note } = await resolveScope(env);
  const ghost = resolveGhost(env);
  const auditSink = fileAuditSink(defaultAuditFile(env));

  // Known in-scope names = what the engagement state store has surfaced (host keys
  // and labels). The bridge holds (never blindly denies) unsurfaced hostnames.
  const knownHosts = [];
  try {
    for (const h of query(engagement, 'hosts')) { if (h.key) knownHosts.push(h.key); if (h.label) knownHosts.push(h.label); if (h.ip) knownHosts.push(h.ip); }
  } catch { /* no store -> empty known set */ }

  const live = createVarvelMcpServer({ scope, ghost, engagement, knownHosts, auditSink, serverEnabled: enabled });

  const send = (msg) => { if (msg) process.stdout.write(encodeMessage(msg)); };
  const decoder = createFrameDecoder({
    onMessage: (msg) => { Promise.resolve(live.handleMessage(msg)).then(send).catch(() => {}); },
    onError: (err) => { send({ jsonrpc: '2.0', id: null, error: err }); },
  });
  process.stdin.on('data', (chunk) => decoder.push(chunk));
  process.stdin.on('end', () => decoder.end());
  process.stderr.write(`varvel-mcp: ${live.tools.length} tools, scope=${scope.cidrs.join(',')} (${note}), ghost=${ghost.mode}${ghost.verifiedOk ? '/verified' : ''}, enabled=${enabled}\n`);
}

const invokedAsMain = process.argv[1] && /mcpserve\.mjs$/i.test(process.argv[1].replace(/\\/g, '/'));
if (invokedAsMain) main().catch((e) => { process.stderr.write('varvel-mcp fatal: ' + String((e && e.message) || e) + '\n'); process.exitCode = 1; });
