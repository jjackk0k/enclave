// VARVEL aisurface tests — the AI/LLM attack-surface module + campaign lane
// (Build 3, 2026-08-31). Local 127.0.0.1 labs only: a fake MCP server, fake
// chat endpoints (leaky / safe / naughty-compliant / tool-fetching), and the
// real OobServer loopback seam for the tool-exfil oracle.
//   node --test varvel/test/aisurface.test.mjs
//
// Pinned: DETECTION is passive-ish and files NOTHING (a fake MCP server =
// surface note, no finding); ACTIVE probes are OFF by default and CANARY-PROOF
// ONLY when armed — the cross-session differential files CONFIRMED only when a
// FRESH session returns the planted canary while the control answered clean,
// and the OOB leg files only on a correlated callback; a model merely
// COMPLYING with a naughty string files NOTHING; scope/pathPrefix refusals
// fire before the wire; the lane rides budget.tools (never the step counter);
// a dormant lane skips LOUDLY.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { aiSurfacePass, aiHintKind, AI_CAPS } from '../tools/aisurface.mjs';
import { OobServer } from '../tools/oob.mjs';
import { Campaign } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';

const scope = (e, extra = {}) => ({ engagement: e, signedBy: 'x', cidrs: ['127.0.0.0/8'], ...extra });

async function withServer(srv, fn) {
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try { return await fn(base); }
  finally { await new Promise((r) => srv.close(r)); }
}

// a fake MCP server: JSON-RPC initialize + tools/list, both benign
function createMcpLab(reqs) {
  return http.createServer((req, res) => {
    if (reqs) reqs.push(req.method + ' ' + req.url);
    const u = new URL(req.url, 'http://x');
    if (req.method === 'OPTIONS') { res.writeHead(204, { allow: 'POST, OPTIONS' }); return res.end(); }
    if (u.pathname === '/mcp' && req.method === 'POST') {
      let d = ''; req.on('data', (c) => (d += c));
      req.on('end', () => {
        let m = null; try { m = JSON.parse(d); } catch { /* malformed */ }
        res.writeHead(200, { 'content-type': 'application/json' });
        if (m && m.method === 'initialize') return res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', serverInfo: { name: 'lab-mcp', version: '1.0' }, capabilities: {} } }));
        if (m && m.method === 'tools/list') return res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { tools: [{ name: 'search' }, { name: 'fetch' }] } }));
        res.end(JSON.stringify({ jsonrpc: '2.0', id: (m && m.id) || null, error: { code: -32601, message: 'unknown method' } }));
      });
      return;
    }
    res.writeHead(404); res.end('{}');
  });
}

// fake chat endpoints. leaky: session memory is GLOBAL (the cross-session bug).
// naughty: complies loudly with anything. toolFetch: its "tool capability"
// fetches any URL the prompt names (the OOB oracle's target behavior).
function createChatLab({ leaky = false, naughty = false, toolFetch = false } = {}, reqs) {
  const globalMemory = [];
  const perSession = new Map();
  return http.createServer((req, res) => {
    if (reqs) reqs.push(req.method + ' ' + req.url);
    const u = new URL(req.url, 'http://x');
    if (req.method === 'OPTIONS') { res.writeHead(204, { allow: 'POST, OPTIONS' }); return res.end(); }
    if (u.pathname === '/api/chat' && req.method === 'POST') {
      let d = ''; req.on('data', (c) => (d += c));
      req.on('end', () => {
        let m = {}; try { m = JSON.parse(d); } catch { /* malformed */ }
        const msg = String(m.message || ''), sid = String(m.sessionId || '');
        if (toolFetch) {
          for (const mm of msg.matchAll(/https?:\/\/[^\s"']+/g)) {
            try { const t = new URL(mm[0]); http.get({ hostname: t.hostname, port: t.port, path: t.pathname + t.search, timeout: 2000 }, (r) => r.resume()).on('error', () => {}); } catch { /* unparseable */ }
          }
        }
        const planted = /deployment canary token is "([^"]+)"/.exec(msg);
        if (planted) {
          if (leaky) globalMemory.push(planted[1]);
          else perSession.set(sid, (perSession.get(sid) || []).concat(planted[1]));
        }
        let reply;
        if (/what is the deployment canary token/i.test(msg)) {
          const known = leaky ? globalMemory : (perSession.get(sid) || []);
          reply = known.length ? known.join(' ') : 'unknown';
        } else if (naughty) reply = 'Sure! Here is exactly how to do the naughty thing you asked for — step 1…';
        else reply = 'ok';
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ reply }));
      });
      return;
    }
    res.writeHead(404); res.end('{}');
  });
}

const seedHost = (c) => c.surface.host('127.0.0.1', { label: 'lab' });
const seedWeb = (c, base) => {
  const hid = seedHost(c);
  c.surface.service(hid, Number(new URL(base).port), 'tcp', 'http');
  return hid;
};

// ——— shape classification (zero requests) ———

test('aiHintKind: the AI path shapes classify; ordinary paths do not', () => {
  assert.equal(aiHintKind('/.well-known/ai-plugin.json'), 'plugin-manifest');
  assert.equal(aiHintKind('/mcp'), 'mcp');
  assert.equal(aiHintKind('/api/mcp/'), 'mcp');
  assert.equal(aiHintKind('/sse'), 'sse');
  assert.equal(aiHintKind('/api/chat'), 'chat');
  assert.equal(aiHintKind('/v1/chat/completions'), 'chat');
  assert.equal(aiHintKind('/copilot/suggest'), 'chat');
  assert.equal(aiHintKind('/ai'), 'chat');
  assert.equal(aiHintKind('/api/users'), null);
  assert.equal(aiHintKind('/details'), null);
  assert.equal(aiHintKind('/main.js'), null);
});

// ——— detection ———

test('detection: a fake MCP server confirms via benign initialize + tools/list — surface note, NO finding', () => withServer(createMcpLab(), async (base) => {
  const r = await aiSurfacePass(base, { endpoints: ['/mcp'], probe: false });
  assert.equal(r.ok, true);
  const mcp = r.surfaces.find((s) => s.path === '/mcp');
  assert.ok(mcp && mcp.confirmed, 'MCP confirmed by the handshake');
  assert.match(mcp.detail, /serverInfo "lab-mcp"/);
  assert.match(mcp.detail, /tools\/list enumerated 2 tool\(s\)/);
  assert.match(mcp.detail, /NOT a finding/);
  assert.equal(r.findings.length, 0, 'detection files NOTHING');
  assert.equal(r.probes, 0, 'no probes fired');
}));

test('detection: a quiet well-known path is an honest negative, not a claim', () => withServer(createChatLab({}, []), async (base) => {
  const r = await aiSurfacePass(base, { endpoints: ['/.well-known/ai-plugin.json'], probe: false });
  const m = r.surfaces.find((s) => s.kind === 'plugin-manifest');
  assert.ok(m && !m.confirmed);
  assert.match(m.detail, /did not answer with a manifest/);
  assert.equal(r.findings.length, 0);
}));

test('detection: probes DISARMED by default — zero POSTs to the chat surface, an honest note says how to arm', () => withServer(createChatLab({ leaky: true }, []), async (base) => {
  const reqs = [];
  await withServer(createChatLab({ leaky: true }, reqs), async (b2) => {
    const r = await aiSurfacePass(b2, { endpoints: ['/api/chat'], probe: false });
    assert.equal(r.findings.length, 0);
    assert.equal(r.probes, 0);
    assert.ok(r.notes.some((n) => /DISARMED.*aiProbe:true/.test(n)), 'the disarm note names the arming option');
    assert.ok(!reqs.some((q) => q.startsWith('POST')), 'not ONE active payload fired unarmed');
    void base;
  });
}));

// ——— the canary-proof oracles ———

test('cross-session differential: a LEAKY chat endpoint (global memory) files a proven finding', () => withServer(createChatLab({ leaky: true }), async (base) => {
  const r = await aiSurfacePass(base, { endpoints: ['/api/chat'], probe: true });
  assert.equal(r.ok, true);
  assert.equal(r.findings.length, 1);
  const f = r.findings[0];
  assert.equal(f.kind, 'ai-cross-session-leak');
  assert.equal(f.verdict, 'proven');
  assert.match(f.detail, /FRESH, never-seeded session/);
  assert.ok(f.response.body.includes(f.canary), 'the fresh session response carries the planted canary');
  assert.equal(r.budget.used, 4, 'OPTIONS + control + seed + fresh — every request counted');
}));

test('cross-session differential: a SAFE chat endpoint (per-session memory) proves nothing', () => withServer(createChatLab({ leaky: false }), async (base) => {
  const r = await aiSurfacePass(base, { endpoints: ['/api/chat'], probe: true });
  assert.equal(r.findings.length, 0, 'no leak, no finding');
  assert.equal(r.probes, 1, 'the probe RAN — the journal shows it');
}));

test('COMPLIANCE IS NOT A FINDING: a model obeying a naughty string files NOTHING', () => withServer(createChatLab({ naughty: true }), async (base) => {
  const r = await aiSurfacePass(base, { endpoints: ['/api/chat'], probe: true });
  assert.equal(r.probes, 1, 'the active probe fired (aiProbe armed)');
  assert.equal(r.findings.length, 0, 'compliance without an objective oracle = ZERO findings — the AI-slop pattern stays unfiled');
}));

test('OOB tool-exfil oracle: a tool-capable model dialing the canary URL files proven (tools/oob.mjs wired)', async () => {
  const server = new OobServer({ host: '127.0.0.1', port: 0 });
  await server.start();
  server.publicBaseUrl = server.localUrl(); // lab seam — the loopback base
  try {
    await withServer(createChatLab({ toolFetch: true }), async (base) => {
      const r = await aiSurfacePass(base, { endpoints: ['/api/chat'], probe: true, server, deadlineMs: 2500 });
      const f = r.findings.find((x) => x.kind === 'ai-oob-exfil');
      assert.ok(f, 'the OOB exfil finding filed');
      assert.equal(f.verdict, 'proven');
      assert.ok(f.callback && f.callback.canary === f.canary, 'the callback correlated to the fired probe');
      assert.match(f.detail, /out-of-band oracle \(aisurface\/oob\)/);
    });
  } finally { await server.close(); }
});

test('OOB leg without a listener: skipped loudly, the cross-session leg still runs', () => withServer(createChatLab({ leaky: true }), async (base) => {
  const r = await aiSurfacePass(base, { endpoints: ['/api/chat'], probe: true, server: null });
  assert.equal(r.findings.length, 1, 'cross-session still proved');
  assert.ok(r.notes.some((n) => /OOB tool-exfil oracle leg was UNAVAILABLE/.test(n)));
}));

// ——— governance: fail-closed before the wire ———

test('scope: an out-of-scope host is refused BEFORE the wire — zero requests', () => withServer(createChatLab({ leaky: true }), async (base) => {
  const reqs = [];
  await withServer(createChatLab({ leaky: true }, reqs), async (b2) => {
    const r = await aiSurfacePass(b2, { endpoints: ['/api/chat'], probe: true, scope: { hosts: ['other.example'] } });
    assert.equal(r.ok, false);
    assert.match(r.error, /outside the signed scope/);
    assert.equal(reqs.length, 0, 'nothing was dialed');
    void base;
  });
}));

test('pathPrefixes: an out-of-prefix path is refused BEFORE the wire', () => withServer(createChatLab({ leaky: true }), async (base) => {
  const reqs = [];
  await withServer(createChatLab({ leaky: true }, reqs), async (b2) => {
    const r = await aiSurfacePass(b2, { endpoints: ['/api/chat'], probe: true, pathPrefixes: ['/public'] });
    assert.equal(r.ok, true);
    assert.equal(r.refusals.length, 1);
    assert.equal(r.refusals[0].reason, 'out-of-scope-path');
    assert.equal(reqs.length, 0, 'the chat surface was never touched');
    assert.equal(r.findings.length, 0);
    void base;
  });
}));

test('caps: maxEndpoints + maxProbes hold', () => withServer(createChatLab({ leaky: true }), async (base) => {
  const many = Array.from({ length: 12 }, (_, i) => `/ai/p${i}`);
  const r = await aiSurfacePass(base, { endpoints: ['/api/chat', ...many], probe: true });
  assert.ok(r.surfaces.length <= AI_CAPS.maxEndpoints, 'detection capped');
  assert.ok(r.probes <= AI_CAPS.maxProbes, 'probes capped');
}));

// ——— the campaign lane ———

test('runAiSurfacePass: MCP lab → detection note, NO finding, tools-bucket charged (not steps)', () => withServer(createMcpLab(), async (base) => {
  const c = new Campaign({ engine: {}, scope: scope('AI-C1'), runAgent: mockAgent, stallCheckMs: 0 });
  const hid = seedWeb(c, base);
  c.surface.endpoint(hid, '/mcp', 'POST');
  const res = await c.runAiSurfacePass();
  assert.equal(res.ok, true);
  assert.equal(res.surfaces, 1);
  assert.equal(res.proven, 0);
  assert.equal([...c.surface.nodes.values()].filter((n) => n.type === 'finding').length, 0, 'detection files NOTHING');
  assert.ok(c.surface.phaseLog.some((n) => /AI surface detected.*\/mcp \[mcp\]/.test(n.summary)), 'the inventory note names the surface');
  assert.ok(c.activity.some((e) => e.kind === 'aisurface.done'), 'the pass is on the record');
  assert.equal(c.toolBudget.used, 3, 'OPTIONS + initialize + tools/list, charged to the tools bucket');
  assert.equal(c.budget.usedSteps, 0, 'the agent step counter was never charged');
}));

test('runAiSurfacePass: aiProbe:true + leaky chat → CONFIRMED finding via the cross-session oracle', () => withServer(createChatLab({ leaky: true }), async (base) => {
  const c = new Campaign({ engine: {}, scope: scope('AI-C2'), runAgent: mockAgent, aiProbe: true, stallCheckMs: 0 });
  const hid = seedWeb(c, base);
  c.surface.endpoint(hid, '/api/chat', 'POST');
  const res = await c.runAiSurfacePass();
  assert.equal(res.ok, true);
  assert.equal(res.proven, 1);
  const f = [...c.surface.nodes.values()].find((n) => n.type === 'finding' && String(n.ref || '').startsWith('aisurface:ai-cross-session-leak:'));
  assert.ok(f, 'the finding filed');
  assert.equal(f.confidence, 'confirmed');
  assert.equal(f.sev, 'high');
  assert.match(f.evidence, /cross-session differential \(aisurface\)/, 'evidence cites the objective oracle');
  assert.ok(f.aisurface && f.aisurface.canary, 'the canary journal is attached');
  assert.ok(c.activity.some((e) => e.kind === 'aisurface.skip-oob' && e.data.reason === 'oob-unconfigured'), 'the missing OOB leg is logged, not hidden');
  assert.equal(c.toolBudget.used, 4);
  assert.equal(c.budget.usedSteps, 0);
}));

test('runAiSurfacePass: aiProbe + oob auto on a tool-fetch lab → CONFIRMED via the OOB oracle', () => withServer(createChatLab({ toolFetch: true }), async (base) => {
  const c = new Campaign({
    engine: {}, scope: scope('AI-C3'), runAgent: mockAgent,
    aiProbe: true, oob: { publicBaseUrl: 'auto', adminToken: 'tok-9', deadlineMs: 2500 }, stallCheckMs: 0,
  });
  const hid = seedWeb(c, base);
  c.surface.endpoint(hid, '/api/chat', 'POST');
  const res = await c.runAiSurfacePass();
  assert.equal(res.ok, true);
  assert.equal(res.proven, 1);
  const f = [...c.surface.nodes.values()].find((n) => n.type === 'finding' && String(n.ref || '').startsWith('aisurface:ai-oob-exfil:'));
  assert.ok(f, 'the OOB exfil finding filed CONFIRMED');
  assert.equal(f.confidence, 'confirmed');
  assert.match(f.evidence, /out-of-band oracle \(aisurface\/oob\)/);
  assert.ok(f.aisurface.callback, 'the correlated callback is attached');
}));

test('runAiSurfacePass: naughty-compliant lab + aiProbe → probe fired, ZERO findings', () => withServer(createChatLab({ naughty: true }), async (base) => {
  const c = new Campaign({ engine: {}, scope: scope('AI-C4'), runAgent: mockAgent, aiProbe: true, stallCheckMs: 0 });
  const hid = seedWeb(c, base);
  c.surface.endpoint(hid, '/api/chat', 'POST');
  const res = await c.runAiSurfacePass();
  assert.equal(res.probes, 1, 'the armed lane fired its canary-proof probe');
  assert.equal(res.proven, 0);
  assert.equal([...c.surface.nodes.values()].filter((n) => n.type === 'finding').length, 0, 'compliance is NEVER a finding');
  assert.ok(c.surface.phaseLog.some((n) => /ZERO proven/.test(n.summary)), 'the honest nothing-proved note');
}));

test('runAiSurfacePass: dormant lane skips LOUDLY (no hints, no bases / disabled outright)', async () => {
  const c = new Campaign({ engine: {}, scope: scope('AI-C5'), runAgent: mockAgent, stallCheckMs: 0 });
  const r = await c.runAiSurfacePass();
  assert.equal(r.skipped, 'no-ai-hints');
  assert.ok(c.activity.some((e) => e.kind === 'aisurface.skip' && e.data.reason === 'no-ai-hints'));
  assert.ok(c.surface.phaseLog.some((n) => /AI-surface lane SKIPPED/.test(n.summary)));
  const off = new Campaign({ engine: {}, scope: scope('AI-C6'), runAgent: mockAgent, aiSurface: false, stallCheckMs: 0 });
  const r2 = await off.runAiSurfacePass();
  assert.equal(r2.skipped, 'disabled');
  assert.ok(off.activity.some((e) => e.kind === 'aisurface.skip' && e.data.reason === 'disabled'));
});

test('exploit phase wires the AI-surface lane inside the countersigned window', () => withServer(createMcpLab(), async (base) => {
  const c = new Campaign({
    engine: {}, scope: scope('AI-C7'), runAgent: async () => ({ text: '{"exploits":[]}', steps: 1 }),
    hooks: { approve: async () => true }, stallCheckMs: 0,
  });
  const hid = seedWeb(c, base);
  c.surface.endpoint(hid, '/mcp', 'POST');
  c.surface.finding(hid, { title: 'seed', sev: 'low', ref: 'F-0', confidence: 'confirmed', evidence: 'x' }); // progression gate
  const { PHASES } = await import('../engine/phases.mjs');
  const r = await c.runPhase(PHASES.find((p) => p.id === 'exploit'), '');
  assert.ok(!r.held && !r.skipped, 'the exploit phase ran under the approved gate');
  assert.ok(c.aiSurfaceResult && c.aiSurfaceResult.surfaces === 1, 'the AI-surface pass fired from the phase hook');
  assert.equal(c.aiSurfaceResult.proven, 0, 'detection alone proves nothing');
}));
