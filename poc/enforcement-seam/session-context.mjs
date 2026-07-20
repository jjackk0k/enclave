// session-context.mjs — builds the READ-ONLY context block the AI is given at
// the start of a session, so it KNOWS its environment and how authorized the
// operator is. This is the "inform" half of "clearance informs, never authorizes":
//
//   • It is derived from the SAME signed identity and the SAME Cedar policies the
//     enforcement layer uses — so what the model is told can never drift from what
//     is actually allowed.
//   • It is injected as read-only context (system prompt / SessionStart hook). The
//     model cannot edit it, and it grants nothing: every action is still checked
//     per-call by the PEP (hook/pretooluse-hook.mjs).

import { authorize, DIRECTORY } from './policy-engine.mjs';

const WORKSPACE_ACTIONS = [
  ['readCode', 'read source & evidence'],
  ['editCode', 'edit source'],
  ['deleteFiles', 'run destructive file operations'],
  ['rotateCredentials', 'rotate credentials'],
];

function principalAttrs(id) {
  const e = DIRECTORY.find(x => x.uid.type === 'User' && x.uid.id === id);
  return e ? e.attrs : null;
}

/** Returns { permitted:string[], escalate:string[] } derived from live policy. */
export function capabilities(session) {
  const permitted = [], escalate = [];
  for (const [action, label] of WORKSPACE_ACTIONS) {
    const v = authorize({ principalId: session.principal, action, resource: { type: 'Workspace', id: session.workspace }, context: {} });
    (v.decision === 'allow' ? permitted : escalate).push(label);
  }
  if (session.engagementScope) {
    permitted.push(`network scans against the signed engagement scope (${session.engagementScope})`);
    escalate.push('exploits — each one needs explicit human approval');
  } else {
    escalate.push('any offensive network action (not in scope for this workspace)');
  }
  return { permitted, escalate };
}

/** Builds the full read-only context string handed to the model. */
export function buildContext(session) {
  const who = principalAttrs(session.principal);
  if (!who) return null;
  const workload = session.engagementScope ? 'red team ops' : 'secure code review';
  const egress = session.engagementScope
    ? `deny-all — scoped to the signed target CIDRs, plus the Claude API & case-ledger via the audited proxy`
    : `deny-all — only api.anthropic.com and the case-ledger (no other network reachable)`;
  const { permitted, escalate } = capabilities(session);

  return [
    '# Enclave session context  — READ-ONLY, informational. This is NOT authorization.',
    '',
    '## Your environment',
    `- Workspace: ${session.workspace}   ·   workload: ${workload}`,
    '- Isolation: a sealed, per-session micro-VM; everything here is destroyed on teardown.',
    `- Egress: ${egress}.`,
    '- Audit: every prompt, tool call, and file touch is written to an immutable ledger.',
    '',
    '## Who you are assisting  (from the cryptographically-signed identity)',
    `- ${who.role}, clearance L${who.clearance}${who.licenses ? ` · licensed: ${who.licenses.join(', ')}` : ''}.`,
    '',
    '## How that shapes your help',
    `- Within this operator's authorization, you may propose to: ${permitted.join('; ')}.`,
    `- Beyond it (expect a block, or a human-approval step): ${escalate.join('; ')}.`,
    '',
    '## The one rule that matters',
    'Use the above to tailor HOW you help — surface the right tools, phrase findings for this',
    "operator's role, and warn when something is outside their remit before trying it. But it grants",
    'nothing: every action is checked server-side against the signed identity, so never try to argue',
    'past, reword, or bypass a denial — a block is final.',
  ].join('\n');
}
