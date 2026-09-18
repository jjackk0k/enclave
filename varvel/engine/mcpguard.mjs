// VARVEL — MCP CONTENT SCREEN (engine/mcpguard.mjs). PURE: no I/O, no clock.
//
// The governance bridge (mcpgov.mjs) classifies WHERE a call goes (scope, egress,
// ghost). It is structurally blind to the channel the Direction-1 lab (deploy/
// range-iso/mcp-poison/) proved exploitable: INSTRUCTIONS embedded in tool metadata
// and tool output, aimed at the agent itself. This module is that missing layer,
// graduated from the lab after it caught the known-knowns (docs/research/
// mcp-poison-lab-2026-08-29.md):
//
//   1. description-scan — instruction-like / UI-hidden content in tool descriptions
//      (HTML comments a listing UI would render away, <<AGENT-style machine
//      directives, imperative phrases: "before answering", "do not tell the user").
//   2. descriptor-drift — sha256 of every served descriptor per tools/list; a tool
//      whose description/schema CHANGES between listings is a rug-pull (hyp-001).
//   3. output-scan — the same pattern class applied to tool RESULTS (hyp-002's
//      cross-server steering channel; description-scan cannot see it at all).
//
// Posture model (the deliberate refuse-vs-flag decision):
//   quarantine (DEFAULT) — a tool whose description trips the scan or whose
//       descriptor mutates is QUARANTINED: McpClient refuses to call it. Never
//       silently execute a poisoned tool. Findings are audited as 'flag'.
//   flag-only — findings are audited and returned, tools stay callable. Explicitly
//       NOT the default: autonomous operation must not ride on flagged tools.
//   trustedTools (operator override) — named tools are exempt from quarantine;
//       findings are STILL scanned, reported and audited with overridden:true, and
//       their outputs are STILL output-scanned. Override narrows quarantine, never
//       visibility.
//
// Calibration honesty: these patterns are calibrated on the lab fixture. They are a
// pinned control against a KNOWN class, not a proof against phrasing variants a real
// LLM would follow — that is what the real-agent round in the writeup is for.

import { createHash } from 'node:crypto';

const sha256 = (s) => createHash('sha256').update(String(s)).digest('hex');

export const SCREEN_POLICY = Object.freeze({ QUARANTINE: 'quarantine', FLAG_ONLY: 'flag-only' });

// Instruction-like patterns. Each rule names what it matches and WHY it is hostile
// in a data field, so a finding is explainable to an operator.
export const INSTRUCTION_PATTERNS = [
  { rule: 'hidden-html-comment', re: /<!--[\s\S]*?-->/, why: 'content invisible in a rendered tool listing' },
  { rule: 'agent-directive-marker', re: /<<AGENT:/, why: 'explicit machine directive embedded in data' },
  { rule: 'imperative-before-answering', re: /\bbefore (answering|responding|replying)\b/i, why: 'imperative timed around the agent\'s answer' },
  { rule: 'imperative-you-must', re: /\byou (must|should|need to)\b/i, why: 'second-person imperative aimed at the agent' },
  { rule: 'concealment', re: /\bdo not (tell|inform|show) (the )?user\b/i, why: 'orders concealment from the user' },
  { rule: 'ignore-prior', re: /\bignore (all |any )?(previous|prior) (instructions|context)\b/i, why: 'classic prompt-injection override' },
  { rule: 'file-read-order', re: /\b(read|open|cat)\s+(the\s+)?file\b/i, why: 'orders a file read from a data field' },
];

export function scanText(text, patterns = INSTRUCTION_PATTERNS) {
  const hits = [];
  const s = String(text || '');
  for (const p of patterns) if (p.re.test(s)) hits.push({ rule: p.rule, why: p.why });
  return hits;
}

// Scan one server listing's raw descriptions. -> findings[] (empty = clean).
export function scanToolDescriptions(serverName, tools) {
  const findings = [];
  for (const t of Array.isArray(tools) ? tools : []) {
    const hits = scanText(t.description);
    if (hits.length) findings.push({ detector: 'description-scan', server: String(serverName), tool: String(t.name), hits });
  }
  return findings;
}

// Scan one tool OUTPUT (the channel description-scan cannot see). -> findings[].
export function scanToolOutput(serverName, toolName, outputText) {
  const hits = scanText(outputText);
  return hits.length ? [{ detector: 'output-scan', server: String(serverName), tool: String(toolName), hits }] : [];
}

// Canonical form of a served descriptor: exactly the fields tools/list emits.
function canon(tool) {
  return JSON.stringify({
    name: String(tool.name),
    description: String(tool.description || ''),
    inputSchema: tool.inputSchema && typeof tool.inputSchema === 'object' ? tool.inputSchema : {},
  });
}

// Drift watcher: first listing per server is the BASELINE (returns no findings —
// drift needs something to diff against, honestly); later listings are diffed.
export class SchemaDriftWatcher {
  constructor() { this._snapshots = new Map(); } // server -> Map(toolName -> hash)

  observe(serverName, tools) {
    const server = String(serverName);
    const findings = [];
    const prev = this._snapshots.get(server);
    const cur = new Map();
    for (const t of Array.isArray(tools) ? tools : []) cur.set(String(t.name), sha256(canon(t)));
    if (prev) {
      for (const [name, hash] of cur) {
        if (!prev.has(name)) findings.push({ detector: 'schema-drift', server, tool: name, kind: 'tool-added' });
        else if (prev.get(name) !== hash) findings.push({ detector: 'schema-drift', server, tool: name, kind: 'descriptor-mutated', before: prev.get(name), after: hash });
      }
      for (const name of prev.keys()) if (!cur.has(name)) findings.push({ detector: 'schema-drift', server, tool: name, kind: 'tool-removed' });
    }
    this._snapshots.set(server, cur);
    return findings;
  }
}

// The screen one McpClient mounts for one external server. Holds the quarantine
// state; every method is pure-ish (mutates only its own maps) and never throws.
export class McpScreen {
  constructor({ server = 'external', policy = SCREEN_POLICY.QUARANTINE, trustedTools = [] } = {}) {
    this.server = String(server);
    this.policy = policy === SCREEN_POLICY.FLAG_ONLY ? SCREEN_POLICY.FLAG_ONLY : SCREEN_POLICY.QUARANTINE;
    this.trusted = new Set(Array.from(trustedTools || [], (t) => String(t)));
    this._drift = new SchemaDriftWatcher();
    this._quarantined = new Map(); // tool -> reasons[]
  }

  // Screen one tools/list result. -> { findings, quarantined, overridden }
  // Quarantine inputs: description-scan hits (any listing) and descriptor-mutated
  // drift. tool-added/removed are audit flags only (MCP's listChanged is a real,
  // legitimate thing; a poisoned ADDED tool still gets description-scanned).
  screenListing(tools) {
    const findings = [
      ...this._drift.observe(this.server, tools),
      ...scanToolDescriptions(this.server, tools),
    ];
    const quarantinedNow = [];
    const overridden = [];
    if (this.policy === SCREEN_POLICY.QUARANTINE) {
      for (const f of findings) {
        const poisoned = f.detector === 'description-scan';
        const mutated = f.detector === 'schema-drift' && f.kind === 'descriptor-mutated';
        if (!poisoned && !mutated) continue;
        if (this.trusted.has(f.tool)) { overridden.push(f.tool); continue; }
        const reasons = (f.hits || [{ rule: f.kind, why: 'served descriptor changed after the approval baseline' }])
          .map((h) => h.rule);
        this._quarantined.set(f.tool, reasons);
        quarantinedNow.push(f.tool);
      }
    }
    return { findings, quarantined: quarantinedNow, overridden };
  }

  isQuarantined(tool) { return this._quarantined.has(String(tool)); }
  quarantineReasons(tool) { return this._quarantined.get(String(tool)) || []; }
  quarantined() { return [...this._quarantined.keys()]; }

  // Screen one tool result's text. Output findings NEVER quarantine retroactively
  // (the output was already produced) — they flag + annotate; the caller decides.
  screenOutput(tool, outputText) {
    return scanToolOutput(this.server, tool, outputText);
  }
}
