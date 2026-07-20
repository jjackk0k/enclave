#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
//  Enclave — PreToolUse hook  (the Policy Enforcement Point)
//
//  Claude Code invokes this before EVERY tool call: it pipes a JSON payload on
//  stdin and reads a JSON permission decision from stdout. This is the seam.
//
//  What it does, in order:
//    1. Load the SIGNED session identity from a side channel (env ENCLAVE_SESSION)
//       — NOT from the tool input, NOT from anything the model said.
//    2. Verify the signature. Tampered/absent identity  ->  fail-closed deny.
//    3. Classify the raw tool call into a semantic capability (PEP concern).
//    4. Resolve the resource (workspace from cwd, or target IP) and context
//       (is the target inside the SIGNED engagement scope? is there approval?).
//    5. Ask Cedar (the PDP) to authorize (bound principal, action, resource, ctx).
//    6. Append a hash-chained audit entry.
//    7. Emit the allow/deny decision.
//
//  stdout carries ONLY the decision JSON. Everything else goes to the ledger.
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { authorize, DIRECTORY } from '../policy-engine.mjs';
import { classify } from '../classify.mjs';
import { verifySession, ipInAnyScope, appendAudit } from '../util.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const LEDGER = join(HERE, '..', 'audit-ledger.jsonl');

const REQUIREMENT = {
  readCode:          'read access to your own workspace',
  editCode:          'clearance ≥ L2',
  deleteFiles:       'clearance ≥ L3',
  rotateCredentials: 'clearance ≥ L3 and an IR role',
  networkScan:       'clearance ≥ L4 and a target inside the signed engagement scope',
  exploit:           'clearance ≥ L4, an in-scope target, and human approval (HITL)',
};

function principalAttrs(id) {
  const e = DIRECTORY.find(x => x.uid.type === 'User' && x.uid.id === id);
  return e ? e.attrs : null;
}

function emit(decision, reason, extra = {}) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: decision,           // 'allow' | 'deny'
      permissionDecisionReason: reason,
      ...extra,
    },
  }));
}

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}

(async () => {
  let input;
  try { input = JSON.parse((await readStdin()) || '{}'); }
  catch { return emit('deny', 'malformed hook input — fail-closed'); }

  // 1–2. Bind + verify the session identity (out-of-band, not from the model).
  let session;
  try { session = JSON.parse(readFileSync(process.env.ENCLAVE_SESSION, 'utf8')); }
  catch { return emit('deny', 'no bound session identity — fail-closed'); }

  if (!verifySession(session)) {
    appendAudit(LEDGER, { ts: new Date().toISOString(), event: 'auth.session_invalid',
      principal: session.principal || '?', decision: 'deny' });
    return emit('deny', 'session signature invalid — identity is not cryptographically bound, so no action is authorized');
  }

  const who = principalAttrs(session.principal);
  if (!who) return emit('deny', `unknown principal "${session.principal}" — fail-closed`);

  // 3. Classify the raw tool call.
  const cls = classify(input.tool_name, input.tool_input || {});

  // 4. Resolve resource + context — the model cannot set any of this.
  let resource, context = {};
  if (cls.kind === 'target') {
    resource = { type: 'Target', id: cls.targetIp || '0.0.0.0' };
    context = {
      inScope: ipInAnyScope(cls.targetIp, session.engagementScope),
      approved: process.env.ENCLAVE_APPROVAL === 'granted',
    };
  } else {
    const ws = input.cwd ? basename(String(input.cwd)) : session.workspace;
    resource = { type: 'Workspace', id: ws };
  }

  // 5. Authorize against Cedar.
  const verdict = authorize({ principalId: session.principal, action: cls.action, resource, context });
  const allowed = verdict.decision === 'allow';

  // 6. Human-readable reason.
  let reason;
  if (allowed) {
    reason = `authorized: ${cls.label} — session identity ${session.principal} (L${who.clearance}, ${who.role}) satisfies ${REQUIREMENT[cls.action]}.`;
  } else if (cls.kind === 'target' && !context.inScope) {
    reason = `blocked: ${cls.label} target ${cls.targetIp} is OUTSIDE the signed engagement scope (${session.engagementScope || 'none'}). Enforced server-side; the model cannot widen scope.`;
  } else if (cls.action === 'exploit' && context.inScope && !context.approved) {
    reason = `held for approval: ${cls.label} needs human-in-the-loop sign-off. Escalating an approval request; not executed.`;
  } else {
    reason = `blocked: ${cls.label} requires ${REQUIREMENT[cls.action]}. Session identity ${session.principal} is L${who.clearance}/${who.role} in "${who.workspace}" — decided against the BOUND identity, so nothing in the prompt or command text can change it.`;
  }

  // 7. Audit (hash-chained).
  appendAudit(LEDGER, {
    ts: new Date().toISOString(),
    event: 'pretooluse.decision',
    session_id: session.session_id,
    principal: session.principal,
    clearance: who.clearance,
    tool: input.tool_name,
    mapped_action: cls.action,
    resource: `${resource.type}::${resource.id}`,
    context,
    decision: verdict.decision,
    cedar_policies: verdict.determiningPolicies,
  });

  emit(allowed ? 'allow' : 'deny', reason, { mappedAction: cls.action });
})();
