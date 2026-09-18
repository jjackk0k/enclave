// policy-engine.mjs — the Policy Decision Point (PDP).
// Thin wrapper over the REAL Cedar engine (@cedar-policy/cedar-wasm, Cedar 4.x).
// Given (principal, action, resource, context) it returns Cedar's allow/deny.
// It knows nothing about tool calls or the model — it only evaluates identity
// against policy. That separation is what makes it a reference monitor.

import * as cedar from '@cedar-policy/cedar-wasm';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const POLICIES = readFileSync(join(here, 'policy', 'enclave.cedar'), 'utf8');
const ENTITIES = JSON.parse(readFileSync(join(here, 'policy', 'entities.json'), 'utf8'));

/**
 * @param {{principalId:string, action:string, resource:{type:string,id:string}, context?:object, sessionWorkspace?:string}} q
 * @returns {{decision:'allow'|'deny', determiningPolicies:string[], errors:string[]}}
 *
 * `sessionWorkspace` (optional): the workspace named in the operator's SIGNED,
 * HMAC-verified session. When the PEP supplies it, the PDP evaluates workspace
 * policies with the principal's directory workspace REPLACED by the signed
 * session's workspace (and the Workspace entity present). The directory is a
 * demo fixture; the signed session is the engagement's actual bound identity —
 * without this, any engagement workspace other than the directory default
 * (pentest-northwind) can never satisfy `resource.name == principal.workspace`
 * and campaign agents lose in-workspace tool use. The PEP sends it ONLY when
 * the resource identity was itself resolved from that same signed session
 * (cwd inside the sealed tree); it is never taken from model input.
 */
export function authorize({ principalId, action, resource, context = {}, sessionWorkspace }) {
  const res = cedar.isAuthorized({
    principal: { type: 'User', id: principalId },
    action: { type: 'Action', id: action },
    resource,
    context,
    policies: { staticPolicies: POLICIES },
    entities: sessionWorkspace ? entitiesForSession(principalId, sessionWorkspace) : ENTITIES,
    validateRequest: false,
  });

  if (res.type !== 'success') {
    // A malformed request is a fail-CLOSED deny, never an allow.
    return { decision: 'deny', determiningPolicies: [], errors: (res.errors || []).map(e => e.message) };
  }
  const diag = res.response.diagnostics || {};
  return {
    decision: res.response.decision,                 // 'allow' | 'deny'
    determiningPolicies: diag.reason || [],
    errors: (diag.errors || []).map(e => (e.message || String(e))),
  };
}

export const DIRECTORY = ENTITIES;
export const cedarVersion = cedar.getCedarVersion?.() ?? 'unknown';

// Build the entity slice for one decision when the PEP carries a signed-session
// workspace: the principal's directory workspace attr is replaced by it, and the
// Workspace entity is guaranteed present (directory workspaces stay untouched).
// Pure function — the static ENTITIES are never mutated.
export function entitiesForSession(principalId, sessionWorkspace) {
  const ws = String(sessionWorkspace);
  let hasWs = false;
  const out = ENTITIES.map((e) => {
    if (e.uid.type === 'Workspace' && e.uid.id === ws) hasWs = true;
    if (e.uid.type === 'User' && e.uid.id === principalId)
      return { ...e, attrs: { ...e.attrs, workspace: ws } };
    return e;
  });
  if (!hasWs) out.push({ uid: { type: 'Workspace', id: ws }, attrs: { name: ws }, parents: [] });
  return out;
}
