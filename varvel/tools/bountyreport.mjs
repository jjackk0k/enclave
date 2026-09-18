// VARVEL — bountyreport: the payable-report rung. Converts a VARVEL findings JSON into
// a submission-ready Markdown bug-bounty report. The revenue counterpart of pocdoc
// (which fills the Wordfence CNA template for zero-day disclosure): this one targets
// bounty platforms (HackerOne default; Bugcrowd and generic severity vocabularies
// supported).
//
// INPUT SHAPES (all normalize through ONE path):
//   1. a campaign SURFACE JSON (engine/surface.mjs toJSON — { scope, nodes, edges,
//      holds, counts }) — findings are the type:'finding' nodes, the host is resolved
//      through the 'finding' edge, the signed scope feeds the attestation line;
//   2. a tool result { findings: [...] } (vulncheck/cvepacks/wafbypass shape:
//      title|label, sev, ref, cve, confidence, evidence);
//   3. a bare array of findings, or a single finding object.
// One report covers ONE finding (one submission per finding) — --ref/--index selects;
// the default is the highest-severity finding, and the footer NAMES the others left
// uncovered (never silently dropped).
//
// HONESTY CONTRACT (absolute — a report never claims more than the evidence):
//   * the validator gate's state is stated verbatim: 'validated' (oracle + when),
//     'claimed/unvalidated' (never reproduced — a claim, not a proof), 'untestable'
//     (no oracle exists), 'refuted' (the gate DISPROVED it — the report renders with a
//     DO-NOT-SUBMIT banner; the document exists for the record), and validated-but-stale
//     (past the TTL — revalidate first), reusing engine/validator.mjs isStale.
//   * fields the finding cannot know print TODO(validate) (the pocdoc marker
//     convention) — never fabricated.
//   * the footer lists EVERY unverified gap; submission readiness is computed
//     (validated && fresh), never asserted.
//
// OPSEC (the cookie-never-reaches-report doctrine, engine/statestore.mjs): secrets,
// cookies, tokens, and authorization material are REDACTED from evidence before it
// lands in the document — the [REDACTED] mark is visible withholding, never the value.
// The redaction count is reported in the footer so a reviewer sees THAT withholding
// happened without seeing WHAT was withheld.

import { normSev, sevRank } from '../engine/severity.mjs';
import { isStale } from '../engine/validator.mjs';
import { classify } from '../engine/classify.mjs';
import { REDACTED } from '../engine/statestore.mjs';
import { TODO_MARKER } from '../engine/pocdoc.mjs';

export const PLATFORMS = ['hackerone', 'bugcrowd', 'generic'];

// VARVEL's canonical sev scale (crit>high>med>low>info) -> the platform's vocabulary.
// Bugcrowd's P-scale includes its own label so the line reads naturally in both worlds.
export const SEV_MAP = {
  hackerone: { crit: 'Critical', high: 'High', med: 'Medium', low: 'Low', info: 'None (informational)' },
  bugcrowd: { crit: 'P1 (Critical)', high: 'P2 (High)', med: 'P3 (Medium)', low: 'P4 (Low)', info: 'P5 (Informational)' },
  generic: { crit: 'critical', high: 'high', med: 'medium', low: 'low', info: 'informational' },
};

// --- evidence redaction ---------------------------------------------------------------
// Ordered: whole-header rules first (a Cookie: line's value would otherwise half-match
// the key=value rule), then structured JSON fields, then key=value params, then bare
// token shapes. Every replacement is the platform's REDACTED mark with the kind named.
const SECRET_ALT = 'secret|token|cookie|password|passwd|session|jwt|api[-_]?key|access[-_]?token|refresh[-_]?token|auth(?:orization)?|cf_clearance|sessionid|sid';
export const REDACTION_RULES = [
  { kind: 'cookie-header', re: /\b(Cookie|Set-Cookie)(\s*:\s*)[^\r\n]*/gi, sub: `$1$2${REDACTED}` },
  { kind: 'authorization-header', re: /\b(Authorization|Proxy-Authorization|X-Api-Key|X-Auth-Token)(\s*:\s*)[^\r\n]*/gi, sub: `$1$2${REDACTED}` },
  { kind: 'json-secret-field', re: new RegExp(`("(?:${SECRET_ALT})"\\s*:\\s*")[^"]*(")`, 'gi'), sub: `$1${REDACTED}$2` },
  // key may CARRY a secret word with a prefix (DB_PASSWORD, AWS_SECRET_ACCESS_KEY) —
  // over-redaction is the safe direction in a report; the key name stays visible.
  { kind: 'param-secret', re: new RegExp(`\\b(\\w*(?:${SECRET_ALT})\\w*)\\s*=\\s*([^\\s;&"']+)`, 'gi'), sub: `$1=${REDACTED}` },
  { kind: 'bearer-token', re: /\bBearer\s+[A-Za-z0-9._~+/=-]+/g, sub: `Bearer ${REDACTED}` },
  { kind: 'jwt', re: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, sub: REDACTED },
];

// redactEvidence(text) → { text, redactions, kinds }. Pure; counts so the footer can
// state THAT withholding happened without stating WHAT was withheld.
export function redactEvidence(text) {
  let out = String(text == null ? '' : text);
  let redactions = 0;
  const kinds = {};
  for (const r of REDACTION_RULES) {
    out = out.replace(r.re, (...a) => { redactions++; kinds[r.kind] = (kinds[r.kind] || 0) + 1; return typeof r.sub === 'function' ? r.sub(...a) : r.sub.replace(/\$(\d)/g, (m, i) => a[+i] ?? m); });
  }
  return { text: out, redactions, kinds };
}

// --- findings intake (ONE normalizer for every input shape) ----------------------------
export function normalizeFindings(doc) {
  if (Array.isArray(doc)) return { ok: true, sourceShape: 'array', findings: doc, scope: null, holds: [] };
  if (!doc || typeof doc !== 'object') return { ok: false, error: 'bad-input', reason: 'expected a surface JSON, a { findings: [...] } result, a findings array, or one finding object' };
  if (Array.isArray(doc.nodes)) {
    // Campaign surface: findings hang off hosts via 'finding' edges — resolve the host
    // label/ip so the report can name the affected asset without inventing one.
    const hostOf = {};
    const byId = new Map(doc.nodes.map((n) => [n && n.id, n]));
    for (const e of doc.edges || []) {
      if (e && e.kind === 'finding' && byId.has(e.from)) hostOf[e.to] = byId.get(e.from);
    }
    const findings = doc.nodes.filter((n) => n && n.type === 'finding').map((n) => {
      const h = hostOf[n.id];
      return { ...n, host: h ? (h.ip || h.label || null) : null };
    });
    return { ok: true, sourceShape: 'surface', findings, scope: doc.scope || null, holds: doc.holds || [] };
  }
  if (Array.isArray(doc.findings)) return { ok: true, sourceShape: 'tool-result', findings: doc.findings, scope: doc.scope || null, holds: doc.holds || [] };
  if (doc.title || doc.label) return { ok: true, sourceShape: 'single', findings: [doc], scope: doc.scope || null, holds: doc.holds || [] };
  return { ok: false, error: 'no-findings', reason: 'the JSON carries no findings (no nodes[], findings[], or finding fields)' };
}

// One report = one finding. --ref picks by ref/label fragment, --index by position;
// the default is the highest-severity finding (ties: input order).
export function selectFinding(findings, { ref, index } = {}) {
  const list = (Array.isArray(findings) ? findings : []).filter((f) => f && typeof f === 'object');
  if (!list.length) return { finding: null, rest: [] };
  if (ref != null) {
    const needle = String(ref).toLowerCase();
    const hit = list.find((f) => String(f.ref || '').toLowerCase() === needle || String(f.label || f.title || '').toLowerCase().includes(needle));
    if (hit) return { finding: hit, rest: list.filter((f) => f !== hit) };
    return { finding: null, rest: list, error: `no finding matches --ref '${ref}'` };
  }
  if (index != null) {
    const i = Number(index);
    if (Number.isInteger(i) && i >= 0 && i < list.length) return { finding: list[i], rest: list.filter((_, j) => j !== i) };
    return { finding: null, rest: list, error: `--index ${index} out of range (${list.length} finding(s))` };
  }
  let best = 0;
  for (let i = 1; i < list.length; i++) if (sevRank(list[i].sev) < sevRank(list[best].sev)) best = i;
  return { finding: list[best], rest: list.filter((_, j) => j !== best) };
}

// bountyReport(doc, opts) → { ok, md, readiness, gaps, finding } — pure, no I/O, no
// wall-clock unless the caller injects `now` (tests stay deterministic).
export function bountyReport(doc, { platform = 'hackerone', ref, index, researcher, staleDays = 30, now = Date.now() } = {}) {
  if (!PLATFORMS.includes(platform)) return { ok: false, error: 'unknown-platform', reason: `platform must be one of ${PLATFORMS.join('|')}` };
  const norm = normalizeFindings(doc);
  if (!norm.ok) return norm;
  const { finding, rest, error } = selectFinding(norm.findings, { ref, index });
  if (!finding) return { ok: false, error: error ? 'no-such-finding' : 'no-findings', reason: error || 'the input carried zero findings — nothing to report' };

  const label = String(finding.label || finding.title || 'finding');
  const sev = normSev(finding.sev);
  const sevLabel = SEV_MAP[platform][sev];
  const confidence = finding.confidence || (typeof finding.conf === 'number' ? (finding.conf >= 70 ? 'confirmed' : 'suspected') : null) || 'suspected';
  const val = finding.validation && typeof finding.validation === 'object' ? finding.validation : null;
  const valState = val ? String(val.state || 'claimed') : null;
  const stale = valState === 'validated' ? isStale(val, { now, staleDays }) : false;
  const gaps = [];

  // SUBMISSION-SHAPE HONESTY (2026-09-16 — the outbox lesson): 'validated' is a claim
  // about the ORACLE, not about submittability. A gate state of validated with (a) a
  // SELF-REFERENTIAL oracle or (b) steps that are still TODO stubs is a reproduced
  // CORRELATION, not a reproduced VULNERABILITY, and must never render READY.
  //
  //   (a) SELF-REFERENTIAL ORACLE — the replay check reads its conclusion out of data it
  //       was handed (an inlined bundle, its own EVIDENCE blob, a recorded file) instead
  //       of re-probing the target. The replay then "passes" by construction: it proves
  //       the recorded bytes entail themselves. That is a valid COLUMN-VERIFICATION
  //       (a version→CVE match is real), never an exploitability proof.
  //   (b) TODO STEPS — the report's own Steps to Reproduce still carry TODO(validate)
  //       placeholders, i.e. no reproducible path exists on the record. A READY banner
  //       over TODO steps is the exact defect this guard removes.
  // Both are REPORTED (never silently withheld): they render as named gaps + NOT READY.
  const oracleText = String((val && val.oracle) || '') + '\n' + String((val && val.check) || '') + '\n' + String(finding.check || '');
  const SELF_REF_ORACLE_RE = /\b(?:JSON\.parse|readFileSync|createReadStream|BUNDLE|bundlePath|EVIDENCE)\b|CVE-MATCH-OK/i;
  // An EXPLICIT declaration wins over the textual heuristic (2026-09-18): tools/huntloop.mjs
  // replays every check inside the isolated sandbox (`--network none`), so its oracle re-executes
  // the RECORDED evidence and never re-probes the target — it says so with val.selfReferential,
  // because a check can always phrase itself past a regex. The regex stays as the backstop for
  // callers that only have the text.
  const selfReferential = valState === 'validated'
    && ((val && val.selfReferential === true) || SELF_REF_ORACLE_RE.test(oracleText));
  // Steps to reproduce: only what the record actually carries. Anything else is a marked
  // TODO — the pocdoc honesty convention, never a fabricated narrative. REPRO-BLOCKING
  // stubs (no host, no ref, no validated reproduction) are counted separately from the
  // standing "full impact demonstration" marker, which is operator sign-off territory by
  // design and therefore must NOT by itself make every report NOT READY.
  const steps = [];
  let reproTodo = 0;
  const host = finding.host || null;
  if (host) steps.push(`Reach \`${host}\` (the finding's host in the campaign surface).`);
  else { steps.push(`${TODO_MARKER} — affected host/URL (the input carried no host binding for this finding; name the exact asset from your validated session)`); reproTodo++; }
  if (finding.ref) steps.push(`Exercise the affected component at \`${finding.ref}\` with the input class the finding title names.`);
  else { steps.push(`${TODO_MARKER} — exact endpoint/parameter (the finding carries no ref; write the precise request from your validated session)`); reproTodo++; }
  if (valState === 'validated') steps.push(`Reproduce the proof exactly as the validator gate did: ${val.oracle || 'oracle unnamed'}${val.marker ? ` — marker \`${redactEvidence(val.marker).text}\`` : ''}.`);
  else { steps.push(`${TODO_MARKER} — reproduction proof (no validator-gate reproduction is on record; the steps above are the claim's shape, not a proven path)`); reproTodo++; }
  steps.push(`${TODO_MARKER} — full impact demonstration (state-changing proof is operator sign-off territory; attach only the verified exchange)`);

  // Submission readiness is COMPUTED from the gate, never asserted: validated && fresh
  // && the oracle is NOT self-referential && no REPRO-BLOCKING TODO step remains.
  const ready = valState === 'validated' && !stale && !selfReferential && reproTodo === 0;
  if (valState === 'refuted') gaps.push(`REFUTED by the validator gate (${val.oracle || 'oracle unnamed'}${val.at ? ', ' + val.at : ''}) — the claim did NOT reproduce; this document is for the record, DO NOT SUBMIT`);
  else if (valState === 'untestable') gaps.push(`the validator gate has no oracle for this finding class (${val && val.oracle || 'none recorded'}) — it is UNTESTABLE by the platform; independent manual proof is required before submission`);
  else if (valState === 'validated' && stale) gaps.push(`validated ${val.validatedAt || val.at || 'unknown date'} — older than the ${staleDays}-day TTL; revalidate before submission (a stale validation is a rendering of validated, not a fresh proof)`);
  else if (selfReferential) gaps.push(`the validator-gate oracle is SELF-REFERENTIAL (${val.oracle || 'unnamed'}): the replay check reads its own recorded input (inlined bundle / EVIDENCE blob) instead of re-probing the target, so a pass proves the record entails itself — a reproduced CORRELATION, not a reproduced vulnerability. Re-probe the live target before submission`);
  else if (valState === 'validated') { /* fresh proof, non-self-referential — the strong case */ }
  else gaps.push('never reproduced by the validator gate — this report states a CLAIM, not a proof; run the validation pass before submission');
  if (reproTodo) gaps.push(`${reproTodo} reproduction-blocking step(s) in this report are still ${TODO_MARKER} placeholders — no reproducible path exists on the record; fill them from the validated session before submission`);
  if (confidence !== 'confirmed') gaps.push(`confidence is '${confidence}' — the platform did not confirm this finding end-to-end`);

  // Evidence: verbatim (the finding's stored evidence + the gate's own artifacts),
  // through the redactor FIRST — the cookie-never-reaches-report doctrine.
  const evidenceBlocks = [];
  let redactions = 0;
  const redactKinds = {};
  const pushEvidence = (title, body) => {
    if (body == null || body === '') return;
    const r = redactEvidence(body);
    redactions += r.redactions;
    for (const [k, v] of Object.entries(r.kinds)) redactKinds[k] = (redactKinds[k] || 0) + v;
    evidenceBlocks.push({ title, text: r.text });
  };
  pushEvidence('stored evidence', finding.evidence);
  if (val) {
    pushEvidence('validator oracle', val.oracle);
    if (val.control && val.control.line) pushEvidence('control read (garbage-control paired read)', val.control.line);
    if (val.marker) pushEvidence('reproduction marker', val.marker);
  }
  if (redactions) gaps.push(`${redactions} secret-bearing value(s) REDACTED from the evidence per the OPSEC doctrine (secrets/cookies/tokens never reach a report) — kinds: ${Object.keys(redactKinds).join(', ')}`);
  if (!evidenceBlocks.length) gaps.push('the finding carries NO stored evidence — a bounty submission without evidence is noise; attach the verified exchange before submitting');

  // (Steps to reproduce are built ABOVE, before the readiness computation, so the
  // TODO-stub count can gate READY — the 2026-09-16 defect.)
  const m = classify(label);
  const scope = norm.scope || null;
  const attestation = scope && (scope.cidrs || []).length
    ? `All activity evidenced in this report stayed inside the signed engagement scope (${scope.cidrs.join(', ')}) for \`${scope.engagement || 'the engagement'}\`${scope.signedBy ? `, authorized by ${scope.signedBy}` : ''}. Out-of-scope assets were not contacted; the platform's enforcement gate holds every action to the signed scope, and every out-of-scope entry in the program's published scope was honored.`
    : `${TODO_MARKER} — scope attestation (the input carried no signed scope; attach the program scope + authorization before submission — a report without an attestation reads as unscoped testing)`;
  if (!(scope && (scope.cidrs || []).length)) gaps.push('no signed scope in the input — the attestation line could not be rendered from evidence');
  if ((norm.holds || []).length) gaps.push(`${norm.holds.length} governance hold(s) were recorded during the engagement (actions the platform blocked in-flight) — they are on the audit ledger if the program asks`);
  if (rest.length) gaps.push(`${rest.length} other finding(s) in the input are NOT covered by this report (one submission per finding): ${rest.slice(0, 5).map((f) => `[${normSev(f.sev)}] ${String(f.label || f.title || 'finding').slice(0, 80)}`).join('; ')}${rest.length > 5 ? ` … and ${rest.length - 5} more` : ''}`);
  if (!researcher) gaps.push('no researcher handle supplied (--researcher) — the platform credit line is a TODO, never a fabricated name');

  const L = [];
  L.push(`# ${label}`);
  L.push('');
  if (valState === 'refuted') L.push('> **DO NOT SUBMIT — the validator gate REFUTED this claim.** The reproduction below is the record of what was tried; the footer names the refuting oracle.');
  L.push(`> Submission readiness: **${ready ? 'READY' : 'NOT READY'}** — ${ready ? 'validator-gate validated and fresh' : selfReferential ? 'the validator-gate oracle is self-referential (a reproduced correlation, not an exploitability proof); see the honesty footer' : reproTodo ? `${reproTodo} reproduction-blocking step(s) are still ${TODO_MARKER} stubs; see the honesty footer` : 'see the honesty footer; this report never claims more than the evidence'}.`);
  L.push('');
  L.push(`**Severity:** ${sevLabel}  `);
  L.push(`**Severity (internal scale):** ${sev} · **confidence:** ${confidence}${finding.cve ? ` · **CVE:** ${finding.cve}` : ''}  `);
  L.push(`**Reported to:** ${platform === 'generic' ? '(generic program)' : platform}${researcher ? ` · **Researcher:** ${researcher}` : ''}`);
  L.push('');
  L.push('## Summary');
  L.push('');
  L.push(`${label}. ${host ? `Affected asset: \`${host}\`. ` : ''}Severity ${sevLabel.split(' ')[0]}, confidence ${confidence}, validation state ${valState || 'unvalidated'}${stale ? ' (stale)' : ''}.`);
  L.push('');
  L.push('## Steps to Reproduce');
  L.push('');
  for (let i = 0; i < steps.length; i++) L.push(`${i + 1}. ${steps[i]}`);
  L.push('');
  L.push('## Evidence');
  L.push('');
  if (!evidenceBlocks.length) L.push(`_${TODO_MARKER} — no evidence on record; attach the verified request/response exchange._`);
  for (const b of evidenceBlocks) { L.push(`${b.title}:`); L.push(''); L.push('```'); L.push(b.text); L.push('```'); L.push(''); }
  if (redactions) L.push(`_${redactions} secret-bearing value(s) withheld as ${REDACTED} per the OPSEC doctrine — the platform records THAT withholding happened, never the value._`);
  L.push('');
  L.push('## Impact');
  L.push('');
  L.push(`${TODO_MARKER} — concrete impact statement (derive from the VERIFIED repro at ${confidence} confidence: what does a successful exploit READ, CHANGE, or REACH? The static record does not state impact, so this report does not either)`);
  L.push('');
  L.push('## Remediation');
  L.push('');
  L.push(`- ${m.fix}`);
  L.push(`- Maps to: ${m.owasp} · MITRE ${m.attack}`);
  L.push('');
  L.push('## Scope Attestation');
  L.push('');
  L.push(attestation);
  L.push('');
  L.push('## Honesty — unverified gaps');
  L.push('');
  if (!gaps.length) L.push('- none — every claim above is backed by the recorded evidence');
  for (const g of gaps) L.push(`- ${g}`);
  L.push('');
  L.push('---');
  L.push('_Evidence is verbatim-minus-redactions; gaps are listed, never hidden; readiness is computed from the validator gate, never asserted._');

  return { ok: true, md: L.join('\n'), platform, readiness: ready ? 'ready' : 'not-ready', submittable: ready, oracleKind: selfReferential ? 'self-referential' : (valState === 'validated' ? 'target-repro' : 'none'), reproTodo, redactions, gaps, finding: { label, sev, ref: finding.ref || null, cve: finding.cve || null, validation: valState || 'unvalidated' }, others: rest.length };
}
