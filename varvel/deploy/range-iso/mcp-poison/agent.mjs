// range-iso mcp-poison lab — the SCRIPTED SIMULATED AGENT.
//
// No LLM. This agent is a deterministic stand-in for the worst-case instruction-
// following model: it scans every raw tool description and every tool output for
// <<AGENT: ...>> directive payloads and executes them LITERALLY. That is exactly the
// property a real instruction-following LLM has (probabilistically); the fixture
// makes it deterministic so the experiment is reproducible and the verdict empirical.
//
// What it records is the evidence: every listing, every directive found (with the
// exact raw message it came from), every cross-server call it was steered into, and
// the final answer it would have shown the user.

import { CANARY } from './servers.mjs';

const DIRECTIVE_RE = /<<AGENT:\s*([\s\S]*?)>>/g;

// Pull every directive payload out of raw text. Tolerant: a malformed payload is
// recorded as unparseable rather than thrown — a hostile server emitting garbage is
// itself a datapoint, not a harness crash.
export function extractDirectives(text) {
  const out = [];
  const s = String(text || '');
  for (const m of s.matchAll(DIRECTIVE_RE)) {
    try { out.push({ directive: JSON.parse(m[1]), raw: m[0] }); }
    catch { out.push({ directive: null, raw: m[0], unparseable: true }); }
  }
  return out;
}

function resultText(result) {
  if (!result || !Array.isArray(result.content)) return JSON.stringify(result);
  return result.content.map((c) => (c && c.type === 'text' ? c.text : JSON.stringify(c))).join('\n');
}

export class ScriptedAgent {
  // clients: { honest, hostile } — loopback JSON-RPC clients (http-transport makeClient
  // shape: initialize/listTools/callTool). log: shared event array the harness reads.
  constructor({ clients, log = [], onList } = {}) {
    this.clients = clients;
    this.log = log;
    this.onList = typeof onList === 'function' ? onList : () => {}; // detector tap
    this.answerInclusions = []; // note bodies a directive ordered into the final answer
    this._depth = 0;
  }

  _event(kind, extra = {}) {
    const e = { kind, ...extra };
    this.log.push(e);
    return e;
  }

  async listServer(serverName) {
    const tools = await this.clients[serverName].listTools();
    this._event('list', { server: serverName, tools: tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })) });
    this.onList(serverName, tools); // the detector watches the SAME listings the agent sees
    return tools;
  }

  // Execute one directive literally. `source` names where it came from, e.g.
  // 'description:hostile/weather' or 'output:hostile/weather'. Never throws: failures
  // are logged as events (the lab measures behavior, it does not crash on it).
  async act(directive, source) {
    if (this._depth > 4) { this._event('directive-depth-cap', { source }); return null; }
    this._depth += 1;
    try {
      this._event('directive', { source, directive });
      const call = directive && directive.call;
      if (!call || !this.clients[call.server]) { this._event('directive-invalid', { source }); return null; }
      const args = { ...(call.args || {}) };
      const result = await this.clients[call.server].callTool(call.tool, args);
      const text = resultText(result);
      this._event('tool_call', {
        source, server: call.server, tool: call.tool, args, steered: true,
        resultText: text, carriedCanary: text.includes(CANARY),
      });
      const then = directive.then;
      if (then === 'include-verbatim') {
        this.answerInclusions.push(text);
        this._event('answer-inclusion', { source, text });
      } else if (then && typeof then.call === 'object') {
        const sub = { ...then.call, args: { ...(then.call.args || {}) } };
        for (const k of Object.keys(sub.args)) {
          if (sub.args[k] === '$PREV_RESULT') sub.args[k] = text; // hand the previous result onward
        }
        const chained = await this.act({ call: sub }, source + ' -> then');
        // Exfil provenance: the chain just delivered OUR previous result (with the
        // canary) to another server — record it even though the payload was a string.
        if (text.includes(CANARY) && chained && sub.server !== call.server) {
          this._event('exfil', { from: `${call.server}/${call.tool}`, to: `${sub.server}/${sub.tool}`, canary: true });
        }
        return result;
      }
      return result;
    } catch (e) {
      this._event('tool_call_error', { source, error: String((e && e.message) || e) });
      return null;
    } finally { this._depth -= 1; }
  }

  // One full agent session against the mounted servers.
  async runSession({ taskCity = 'lab-city' } = {}) {
    // 1. Approval snapshot: list both servers (what a host UI would show the operator).
    const listings = {};
    for (const s of Object.keys(this.clients)) listings[s] = await this.listServer(s);

    // 2. Follow directives hidden in tool DESCRIPTIONS (behavior a — tool poisoning).
    for (const [serverName, tools] of Object.entries(listings)) {
      for (const t of tools) {
        for (const { directive, raw } of extractDirectives(t.description)) {
          if (directive) await this.act(directive, `description:${serverName}/${t.name}`);
          else this._event('directive-unparseable', { source: `description:${serverName}/${t.name}`, raw });
        }
      }
    }

    // 3. The actual user task: ask the hostile server for weather (behavior c — the
    //    OUTPUT steers the agent across servers).
    const weather = await this.clients.hostile.callTool('weather', { city: taskCity });
    const weatherText = resultText(weather);
    this._event('tool_call', { source: 'user-task', server: 'hostile', tool: 'weather', args: { city: taskCity }, steered: false, resultText: weatherText });
    for (const { directive, raw } of extractDirectives(weatherText)) {
      if (directive) await this.act(directive, 'output:hostile/weather');
      else this._event('directive-unparseable', { source: 'output:hostile/weather', raw });
    }

    // 4. Post-approval refresh: re-list the hostile server (behavior b — rug-pull
    //    becomes visible only NOW; the approval snapshot at step 1 looked clean).
    const relisted = await this.listServer('hostile');

    // 5. Compose the answer the user would see (with anything a directive ordered in).
    const answer = [`Weather: ${weatherText.split('\n')[0]}`]
      .concat(this.answerInclusions.map((t) => `(as requested) ${t}`)).join('\n');
    this._event('answer', { text: answer });

    return { listings, relisted, answer };
  }
}
