// sandbox-manager.mjs — provisions an isolated sandbox per session, gates every
// tool call at the REAL PreToolUse PEP (the enforcement seam) before it runs, and
// tears the sandbox down. It picks the strongest AVAILABLE provider automatically:
// Firecracker (prod KVM host) -> Docker (daemon up) -> local process (always).

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { appendAudit } from '../enforcement-seam/util.mjs';
import local from './providers/local-process.mjs';
import docker from './providers/docker.mjs';
import firecracker from './providers/firecracker.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const PEP_HOOK = join(HERE, '..', 'enforcement-seam', 'hook', 'pretooluse-hook.mjs');
export const LEDGER = join(HERE, 'isolation-ledger.jsonl');

const PROVIDERS = [firecracker, docker, local]; // strongest first
export function selectProvider() {
  for (const p of PROVIDERS) { try { if (p.available()) return p; } catch { /* unavailable */ } }
  return local;
}

// Spawn the real enforcement-seam hook; the identity+policy decision lives OUTSIDE
// the sandbox and cannot be influenced by anything running inside it.
function callPEP(sessionFile, toolCall) {
  return new Promise(resolve => {
    const env = { ...process.env, ENCLAVE_SESSION: sessionFile, NODE_NO_WARNINGS: '1' };
    const c = spawn(process.execPath, [PEP_HOOK], { env });
    let out = '', err = '';
    c.stdout.on('data', d => (out += d));
    c.stderr.on('data', d => (err += d));
    c.on('close', () => {
      try { resolve(JSON.parse(out).hookSpecificOutput); }
      catch { resolve({ permissionDecision: 'deny', permissionDecisionReason: 'PEP unavailable — fail-closed (' + (err || out).slice(0, 160) + ')' }); }
    });
    c.stdin.write(JSON.stringify(toolCall)); c.stdin.end();
  });
}

export class SandboxManager {
  constructor() { this.provider = selectProvider(); }

  provision(session) {
    const sandbox = this.provider.create(session);
    appendAudit(LEDGER, { ts: new Date().toISOString(), event: 'sandbox.provision', session_id: session.session_id, provider: this.provider.name });
    return sandbox;
  }

  // Gate at the PEP first; only run inside the sandbox if allowed.
  async exec(sandbox, session, sessionFile, toolCall, code) {
    const d = await callPEP(sessionFile, toolCall);
    const allowed = d.permissionDecision === 'allow';
    appendAudit(LEDGER, { ts: new Date().toISOString(), event: 'sandbox.exec', session_id: session.session_id, tool: toolCall.tool_name, decision: d.permissionDecision, provider: this.provider.name });
    if (!allowed) return { decision: 'deny', reason: d.permissionDecisionReason, ran: false };
    return { decision: 'allow', ran: true, result: this.provider.run(sandbox, code) };
  }

  teardown(sandbox, session) {
    const wiped = this.provider.destroy(sandbox);
    appendAudit(LEDGER, { ts: new Date().toISOString(), event: 'sandbox.teardown', session_id: session.session_id, provider: this.provider.name, wiped });
    return wiped;
  }
}
