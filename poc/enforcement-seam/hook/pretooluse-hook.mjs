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
import { dirname, join, relative, isAbsolute } from 'node:path';
import { authorize, DIRECTORY } from '../policy-engine.mjs';
import { classify } from '../classify.mjs';
import { verifySession, ipInAnyScope, appendAudit } from '../util.mjs';
import { hostAllowed, urlClean } from '../egress-allowlist.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const LEDGER = join(HERE, '..', 'audit-ledger.jsonl');

// The PDP call. Default: evaluate Cedar in-process (self-contained demo). If
// ENCLAVE_PDP_URL is set, call the networked Cedar PDP service instead (production
// shape) — and fail CLOSED if it's unreachable, so a PDP outage can never fail-open.
async function decide(q) {
  const url = process.env.ENCLAVE_PDP_URL;
  if (!url) return authorize(q);
  try {
    const r = await fetch(url.replace(/\/$/, '') + '/authorize',
      { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(q) });
    if (!r.ok) throw new Error('PDP HTTP ' + r.status);
    return await r.json();
  } catch (e) {
    return { decision: 'deny', determiningPolicies: [], errors: ['PDP unreachable (fail-closed): ' + e.message] };
  }
}

const REQUIREMENT = {
  readCode:          'read access to your own workspace',
  editCode:          'clearance ≥ L2',
  deleteFiles:       'clearance ≥ L3',
  rotateCredentials: 'clearance ≥ L3 and an IR role',
  provisionInfra:    'clearance ≥ L4 and a platform/cloud certification (CKA, Terraform-Assoc, …)',
  networkScan:       'clearance ≥ L4, an in-scope target, and an offensive certification (OSCP, OSEP, CRTO, …)',
  exploit:           'clearance ≥ L4, an in-scope target, an offensive certification, and human approval',
  sealedToolBlocked: 'a tool that is not available inside a sealed enclave (egress / orchestration / external MCP are removed)',
  webResearch:       'a read-only fetch/search to an allowlisted research source (DLP-clean)',
};

// Qualification gates — CLEARANCE says how trusted; QUALIFICATION says what you're
// certified to do. They are different axes; a powerful action needs the right cert,
// not just a high number. (In production these arrive as verifiable credentials.)
const OFFENSIVE_CERTS = ['OSCP', 'OSEP', 'CRTO', 'GPEN', 'GXPN'];
const PLATFORM_CERTS  = ['CKA', 'CKAD', 'AWS-SA-Pro', 'Terraform-Assoc'];
const holds = (lic, set) => (lic || []).some(l => set.includes(l));

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
  } else if (cls.kind === 'egress') {
    // Governed research egress: allowlisted host + DLP-clean request. WebSearch is a
    // read-only query (no host to exfil to), so it is treated as allowlisted.
    const isSearch = cls.host === 'search';
    resource = { type: 'Endpoint', id: cls.host || 'unknown' };
    context = { hostAllowed: isSearch || hostAllowed(cls.host), urlClean: urlClean(cls.url) };
  } else {
    const ws = input.cwd ? basename(String(input.cwd)) : session.workspace;
    resource = { type: 'Workspace', id: ws };
  }

  // 4b. Workspace confinement: a file op whose path escapes the sealed workspace is
  // denied outright — even at L5. (Bash-level filesystem confinement is provided by the
  // container/Firecracker tier; this guards the file tools in every tier, incl. local.)
  const fpath = input.tool_input && input.tool_input.file_path;
  if (fpath && input.cwd) {
    const abs = isAbsolute(String(fpath)) ? String(fpath) : join(String(input.cwd), String(fpath));
    const rel = relative(String(input.cwd), abs);
    if (rel.split(/[\\/]/)[0] === '..' || isAbsolute(rel)) {
      appendAudit(LEDGER, { ts: new Date().toISOString(), event: 'pretooluse.decision', session_id: session.session_id,
        principal: session.principal, clearance: who.clearance, tool: input.tool_name, mapped_action: 'workspaceEscape',
        resource: `Path::${abs}`, context: {}, decision: 'deny', cedar_policies: [] });
      return emit('deny', `blocked: path "${fpath}" is OUTSIDE the sealed workspace. File access is confined to this enclave's directory and cannot escape it — enforced regardless of clearance.`, { mappedAction: 'workspaceEscape' });
    }
  }

  // 5. Authorize against Cedar.
  const verdict = await decide({ principalId: session.principal, action: cls.action, resource, context });
  const allowed = verdict.decision === 'allow';

  // 6. Human-readable reason.
  let reason;
  const lic = `[${(who.licenses || []).join(', ') || 'none'}]`;
  const idTag = `${session.principal} (L${who.clearance}, ${who.role}, ${lic})`;

  if (allowed) {
    if (cls.action === 'webResearch')
      reason = `authorized: ${cls.label}${cls.host && cls.host !== 'search' ? ` to "${cls.host}"` : ''} — allowlisted read-only research source, request is DLP-clean, logged. Egress stays deny-all otherwise.`;
    else
      reason = `authorized: ${cls.label} — ${idTag} satisfies ${REQUIREMENT[cls.action]}.`;
  } else if (cls.action === 'webResearch') {
    if (!context.urlClean)
      reason = `blocked: ${cls.label} — the request looks like it is carrying data OUT (failed egress DLP). Research egress is read-only: pull from approved sources, don't push data to them.`;
    else
      reason = `blocked: ${cls.label} to "${cls.host || 'unknown host'}" — not on this enclave's research allowlist. Egress is deny-all except a curated read-only set (CVE/NVD, ATT&CK, ExploitDB, GitHub, package registries, language docs, …). Use an approved source.`;
  } else if (cls.action === 'networkScan' || cls.action === 'exploit') {
    // Report the FIRST failing gate: clearance -> qualification -> scope -> approval.
    if (who.clearance < 4)
      reason = `blocked: ${cls.label} requires clearance ≥ L4. ${idTag} — decided against the bound identity.`;
    else if (!holds(who.licenses, OFFENSIVE_CERTS))
      reason = `blocked: ${cls.label} needs an OFFENSIVE certification (${OFFENSIVE_CERTS.slice(0, 3).join(', ')}, …). ${session.principal} is L${who.clearance} but holds ${lic} — clearance is high enough; the QUALIFICATION is missing. A high clearance never substitutes for the cert.`;
    else if (!context.inScope)
      reason = `blocked: ${cls.label} target ${cls.targetIp} is OUTSIDE the signed engagement scope (${session.engagementScope || 'none'}). Enforced server-side; the model cannot widen scope.`;
    else
      reason = `held for approval: ${cls.label} needs human-in-the-loop sign-off. Escalating an approval request; not executed.`;
  } else if (cls.action === 'provisionInfra') {
    if (who.clearance < 4)
      reason = `blocked: ${cls.label} requires clearance ≥ L4. ${idTag}.`;
    else
      reason = `blocked: ${cls.label} needs a PLATFORM/cloud certification (${PLATFORM_CERTS.slice(0, 2).join(', ')}, …). ${session.principal} is L${who.clearance} but holds ${lic} — a red-team/IR cert does not unlock infrastructure.`;
  } else {
    reason = `blocked: ${cls.label} requires ${REQUIREMENT[cls.action]}. ${idTag} in "${who.workspace}" — decided against the BOUND identity, so nothing in the prompt or command text can change it.`;
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
