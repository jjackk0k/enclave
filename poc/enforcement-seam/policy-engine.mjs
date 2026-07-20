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
 * @param {{principalId:string, action:string, resource:{type:string,id:string}, context?:object}} q
 * @returns {{decision:'allow'|'deny', determiningPolicies:string[], errors:string[]}}
 */
export function authorize({ principalId, action, resource, context = {} }) {
  const res = cedar.isAuthorized({
    principal: { type: 'User', id: principalId },
    action: { type: 'Action', id: action },
    resource,
    context,
    policies: { staticPolicies: POLICIES },
    entities: ENTITIES,
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
