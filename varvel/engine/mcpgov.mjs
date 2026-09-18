// VARVEL — the MCP GOVERNANCE BRIDGE (the crux of MCP adoption).
//
// One choke-point both MCP directions ride:
//   (A) inbound  (tools/mcpserve.mjs): an external MCP client calls a VARVEL tool —
//       the bridge decides allow | hold | deny BEFORE the tool runs.
//   (B) outbound (engine/mcpclient.mjs): VARVEL calls an EXTERNAL MCP tool server —
//       the bridge classifies the call's target vs the signed scope and the
//       public-egress allowlist BEFORE the child process is even spawned.
//
// The classification doctrine is the Enclave enforcement seam's, reused directly:
// scope math is engine/ipaddr.mjs (the SAME strict parser/inCidr the seam imports),
// and the public-egress discipline is the seam's research allowlist
// (poc/enforcement-seam/egress-allowlist.mjs — hostAllowed/extractHost), exactly the
// data the PreToolUse hook enforces with. A target the bridge cannot read is never
// silently waved through: fail-CLOSED for IP literals outside the signed ring, fail
// to HOLD (audited, operator-resolvable) for names it cannot prove in scope.
//
// Verdict model (pure — no I/O, no clock except an injected one):
//   allow — run/dispatch now; audited.
//   hold  — the platform's existing hold pattern: NOT forbidden, but needs an
//           operator. Audited with rule 'mcp-hold'; the call returns a visible
//           HELD result and never executes. An operator resolves it by putting the
//           target in scope (or the known-hosts set) and re-issuing.
//   deny  — final. Out-of-scope IP, public egress off the allowlist, ghost-required
//           down, external MCP not enabled. Audited; the tool never runs, the child
//           never spawns.

import { createHash } from 'node:crypto';
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseIp, inAnyCidr } from './ipaddr.mjs';
import { hostAllowed, extractHost } from '../../poc/enforcement-seam/egress-allowlist.mjs';

export const VERDICT = Object.freeze({ ALLOW: 'allow', HOLD: 'hold', DENY: 'deny', FLAG: 'flag' }); // FLAG: content-screen finding (engine/mcpguard.mjs) — audited, not a call disposition

// Policy classes every exposed tool declares. read-only tools answer even when the
// ghost chain is down and never name a target; target-touching tools name at least
// one target and ride the full classification.
export const POLICY_CLASS = Object.freeze({ READONLY: 'read-only', TARGET: 'target-touching' });

// Argument names the bridge inspects for EXTERNAL tool calls (direction B), in order.
// Community servers don't declare VARVEL policies, so the bridge looks where targets
// conventionally live. Top-level string args only — documented, never recursive.
export const EXTERNAL_TARGET_FIELDS = ['url', 'uri', 'endpoint', 'target', 'host', 'hostname', 'domain', 'ip', 'baseUrl'];

// ── target extraction ─────────────────────────────────────────────────────────

// Normalize one raw argument value into a host token: full URLs go through the
// seam's extractHost (userinfo/port/bracket/debris-stripping — the same cleanup the
// classifier relies on); bare 'host' / 'host:port' / '[v6]:port' are stripped here.
// Returns '' when nothing legible is present. Never throws.
export function normalizeTargetHost(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return '';
  if (/https?:\/\//i.test(s)) return extractHost(s) || '';
  let h = s;
  if (h.startsWith('[')) { const e = h.indexOf(']'); h = e >= 0 ? h.slice(1, e) : h.slice(1); }
  else if (/^[^:\s]+:\d+$/.test(h)) h = h.slice(0, h.lastIndexOf(':')); // host:port (v6 unbracketed keeps its colons)
  h = h.trim().toLowerCase();
  // Legible host = valid IP literal or a plain DNS name; anything else is parser
  // debris and must NOT reach scope math (the seam's 'canonical, never debris' rule).
  if (parseIp(h)) return h;
  return /^(?=.{1,253}$)[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/.test(h) ? h : '';
}

// Pull every declared target out of a tool call's arguments.
// -> [{ field, raw, host, ip|null }]; a field whose value normalizes to '' is
// reported with host '' so the caller can fail closed on an ILLEGIBLE target.
export function extractTargets(args, targetFields) {
  const out = [];
  const a = args && typeof args === 'object' ? args : {};
  for (const f of Array.isArray(targetFields) ? targetFields : []) {
    if (typeof a[f] !== 'string' || !a[f].trim()) continue;
    const host = normalizeTargetHost(a[f]);
    out.push({ field: f, raw: a[f], host, ip: host ? (parseIp(host) || {}).text || null : null });
  }
  return out;
}

// ── the verdict ───────────────────────────────────────────────────────────────

// Judge ONE MCP call. `ctx`:
//   direction   'server' (A: inbound to a VARVEL tool) | 'external' (B: outbound)
//   tool        tool name (for the audit trail + messages)
//   args        the call arguments
//   policy      { class, targetFields[] } — direction A declares it per tool;
//               direction B gets the synthetic external policy (below)
//   scope       { cidrs: [] } — the SIGNED operator scope (empty = nothing granted)
//   knownHosts  iterable of hostnames/IPs the engagement already surfaced as in-scope
//               (the campaign.mjs validate-gate rule: a name must be surfaced, an IP
//               must sit inside the signed CIDR ring)
//   ghost       { mode: 'off'|'on'|'required', verifiedOk: bool } — posture only;
//               'required' + unverified FAILS CLOSED for every target-touching call
//   externalAllowed  bool — settings mcp.allowExternal (direction B only)
// Never throws. Every outcome is one of VERDICT with a plain-language reason.
export function judgeCall(ctx = {}) {
  const direction = ctx.direction === 'external' ? 'external' : 'server';
  const tool = String(ctx.tool || '');
  const policy = ctx.policy && typeof ctx.policy === 'object' ? ctx.policy : null;
  const cidrs = (ctx.scope && Array.isArray(ctx.scope.cidrs)) ? ctx.scope.cidrs : [];
  const known = new Set(Array.from(ctx.knownHosts || [], (h) => String(h || '').toLowerCase()).filter(Boolean));
  const ghost = ctx.ghost && typeof ctx.ghost === 'object' ? ctx.ghost : { mode: 'off', verifiedOk: false };
  const say = (verdict, reason, extra = {}) => ({ verdict, reason, tool, direction, ...extra });

  if (!policy || (policy.class !== POLICY_CLASS.TARGET && policy.class !== POLICY_CLASS.READONLY)) {
    return say(VERDICT.DENY, 'no governance policy declared for this tool — undeclared tools never ride the bridge');
  }

  if (direction === 'external' && !ctx.externalAllowed) {
    return say(VERDICT.DENY, 'external MCP calls are disabled (mcp.allowExternal=false) — the operator must explicitly enable and configure external servers');
  }

  if (policy.class === POLICY_CLASS.READONLY) {
    // Read-only tools touch no target and ride no egress: they answer even when the
    // ghost chain is down (posture answers are exactly what an operator needs then).
    return say(VERDICT.ALLOW, 'read-only tool — no target, no egress', { targets: [] });
  }

  // target-touching from here on.
  const ghostDown = ghost.mode === 'required' && !ghost.verifiedOk;

  const targets = extractTargets(ctx.args, policy.targetFields);
  if (!targets.length) {
    return say(direction === 'external' ? VERDICT.HOLD : VERDICT.DENY,
      direction === 'external'
        ? 'no legible target in the call arguments — an unclassifiable external call is held for the operator, never dispatched blind'
        : 'target-touching tool called with no legible target — fail-closed');
  }

  const decided = [];
  for (const t of targets) {
    if (!t.host) {
      return say(VERDICT.DENY, `target in '${t.field}' is illegible (${JSON.stringify(String(t.raw)).slice(0, 80)}) — fail-closed`, { targets: decided.concat(t) });
    }
    if (t.ip) {
      // IP literal: the signed CIDR ring decides, family-strict, fail-closed —
      // exactly the campaign validate gate's rule.
      if (inAnyCidr(t.ip, cidrs)) { decided.push({ ...t, class: 'scope', verdict: VERDICT.ALLOW }); continue; }
      return say(VERDICT.DENY, `${t.ip} is outside the signed scope (${cidrs.join(', ') || 'none granted'}) — a denial is final`, { targets: decided.concat({ ...t, class: 'scope', verdict: VERDICT.DENY }) });
    }
    // Hostname: in-scope only if the engagement already surfaced it (mirrors
    // campaign.mjs: a hostname must be one the engagement surfaced as in-scope).
    if (known.has(t.host)) { decided.push({ ...t, class: 'scope', verdict: VERDICT.ALLOW }); continue; }
    // Public-egress discipline (direction B's research channel): an allowlisted
    // research host is governed egress, not an engagement target.
    if (direction === 'external' && hostAllowed(t.host)) { decided.push({ ...t, class: 'egress-allowlist', verdict: VERDICT.ALLOW }); continue; }
    if (direction === 'external') {
      return say(VERDICT.DENY, `public host '${t.host}' is neither in the signed scope nor on the research egress allowlist`, { targets: decided.concat({ ...t, class: 'egress', verdict: VERDICT.DENY }) });
    }
    // Inbound direction: an unsurfaced name is not forbidden — it is HELD for the
    // operator (the platform's hold pattern: audited, operator-resolvable).
    return say(VERDICT.HOLD, `hostname '${t.host}' is not in the signed scope and has not been surfaced by this engagement — held for the operator`, { targets: decided.concat({ ...t, class: 'scope', verdict: VERDICT.HOLD }) });
  }

  if (ghostDown) {
    return say(VERDICT.DENY, 'ghost mode is REQUIRED but the identity chain is unverified — target-touching calls fail closed until it verifies (read-only tools still answer)', { targets: decided });
  }
  return say(VERDICT.ALLOW, 'in-scope' + (ghost.mode === 'required' ? ' (ghost verified)' : ''), { targets: decided });
}

// The synthetic policy for direction B: community servers declare no VARVEL policy,
// so the bridge treats every external call as target-touching and hunts targets in
// the conventional argument names.
export function externalPolicy() {
  return { class: POLICY_CLASS.TARGET, targetFields: EXTERNAL_TARGET_FIELDS };
}

// ── the audit trail ───────────────────────────────────────────────────────────

const sha256 = (s) => createHash('sha256').update(String(s)).digest('hex');
// Keys whose VALUES must never reach the ledger (the statestore SECRET_FIELDS set,
// plus the obvious synonyms — an MCP tool arg named token/secret/password is not rare).
const SECRET_KEY = /^(secret|token|cookie|password|passwd|api[-_]?key|key|authorization|auth|credential)s?$/i;

// Recursively redact secret-class keys (in place on a COPY). Strings are capped so a
// 40KB payload can't blow up the preview. Pure.
export function redactArgs(value, depth = 0) {
  if (depth > 6) return '[...]';
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redactArgs(v, depth + 1));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = SECRET_KEY.test(k) ? '[REDACTED]' : redactArgs(v, depth + 1);
    return out;
  }
  if (typeof value === 'string' && value.length > 300) return value.slice(0, 300) + '…(' + value.length + ' chars)';
  return value;
}

// One ledger entry: WHO called WHAT, the args as a DIGEST + a REDACTED preview
// (never raw secrets), and the verdict + reason. Shape mirrors the kimi-runagent
// mission ledger (sha256 inputDigest + capped preview) so both trails read alike.
// `at` is injected — pass new Date().toISOString() at the I/O edge.
export function makeAuditEntry({ direction, server = null, tool, args, verdict, at } = {}) {
  const canon = JSON.stringify(args === undefined ? {} : args);
  return {
    at: at || 'unknown',
    kind: 'mcp.call',
    direction: direction === 'external' ? 'external' : 'server',
    server: server ? String(server) : null,
    tool: String(tool || ''),
    argsDigest: 'sha256:' + sha256(canon),
    argsPreview: JSON.stringify(redactArgs(args === undefined ? {} : args)).slice(0, 200),
    verdict: (verdict && verdict.verdict) || 'unknown',
    reason: (verdict && verdict.reason) || '',
    targets: ((verdict && verdict.targets) || []).map((t) => ({ field: t.field, host: t.host, class: t.class, verdict: t.verdict })),
  };
}

// Default ledger location — beside settings.json, never the OS temp dir.
export function defaultAuditFile(env = process.env) {
  if (env.VARVEL_MCP_AUDIT_FILE) return env.VARVEL_MCP_AUDIT_FILE;
  return join(dirname(fileURLToPath(import.meta.url)), '..', 'data', 'mcp-audit.jsonl');
}

// THE ONLY IMPURE SEAM IN THIS MODULE: the append-only JSONL ledger sink the two
// live surfaces (mcpserve, mcpclient) wire in as their audit tap. Tests inject a
// plain array-push function instead — every verdict path above stays pure.
// A ledger failure must never break governance: write errors are swallowed, loudly
// flagged on the returned sink object for the operator to notice.
export function fileAuditSink(file) {
  const sink = (entry) => {
    try {
      mkdirSync(dirname(file), { recursive: true });
      appendFileSync(file, JSON.stringify(entry) + '\n');
    } catch (e) { sink.lastError = String((e && e.message) || e); }
  };
  sink.lastError = null;
  return sink;
}
