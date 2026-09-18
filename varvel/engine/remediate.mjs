// VARVEL — auto-remediation (RedAmon's CypherFix, the DEFENSIVE close of the loop).
//
// Two stages, both here:
//   1) triage(surface) — pure/deterministic: dedup findings, rank by EXPLOITABILITY, and
//      attach OWASP/MITRE + a concrete code-level fix hint. This is the whole value with
//      no AI at all, and it's fully testable.
//   2) codeFixAgent(runAgent, …) — drives a GOVERNED code agent over a client REPO to
//      implement the ranked fixes and (optionally) open a GitHub PR. This only FIXES
//      code — the safe, defensive half of the engagement. runAgent is injected so it's
//      testable with a mock and reuses the same governed backend.

import { classify } from './classify.mjs';
import { readFileSync, writeFileSync, unlinkSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname, resolve, sep } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { spawn as nodeSpawn } from 'node:child_process';
import { dataDir } from './store.mjs';
import { isStale } from './validator.mjs';

const SEV_W = { crit: 40, high: 30, med: 18, low: 8, info: 3 };
function exploitability(f, exploited) {
  const conf = typeof f.conf === 'number' ? f.conf * 0.4 : (f.confidence === 'confirmed' ? 34 : 16);
  return Math.min(100, Math.round((SEV_W[f.sev] || 10) + conf + (exploited ? 26 : 0)));
}

// Concrete code-level fix guidance, matched by finding pattern.
const FIX_HINTS = [
  [/sql inject|sqli/i, 'Use parameterized queries / prepared statements; never concatenate user input into SQL. Prefer an ORM or a query builder that binds parameters.'],
  [/wp-config|\.env|secret|dotenv|credential|jwt.?secret|api.?key|stripe/i, 'Move secrets out of the web root into env vars / a secrets manager the app does not serve; ROTATE any exposed secret immediately.'],
  [/\.git|\.svn|\.hg/i, 'Deny access to VCS metadata at the web server (block /.git, /.svn, /.hg) and never deploy the VCS directory.'],
  [/unauth\w*.*(write|content|api|banner|admin)|broken access|access control|function.?level/i, 'Enforce server-side authorization on the endpoint (authenticated + role check); never rely on obscurity or client-side checks.'],
  [/idor|insecure direct object|ownership/i, 'Add an ownership/tenant check on every object access; do not trust a client-supplied id.'],
  [/jwt|token|alg.?none|signature|forge/i, 'Verify the JWT signature with a strong secret / asymmetric key; pin the expected alg; reject alg:none; never ship the signing key in a client bundle.'],
  [/cors/i, 'Restrict Access-Control-Allow-Origin to an explicit allowlist; never reflect an arbitrary Origin together with credentials.'],
  [/directory listing/i, 'Disable directory autoindex on the web server.'],
  [/database dump|\.sql|backup/i, 'Remove backups/dumps from the web root; store them off the public server with access control.'],
  [/missing.*(header|csp|x-frame|hsts|content-security)/i, 'Add the missing security headers: Content-Security-Policy, X-Frame-Options, HSTS, X-Content-Type-Options.'],
  [/traversal|lfi|local file/i, 'Canonicalize and validate file paths against an allowlist; never pass user input to file APIs.'],
  [/xss|cross-site script/i, 'Context-aware output encoding + a strict CSP; validate and sanitize input.'],
  [/command inject|rce|os command/i, 'Avoid shell calls with user input; use safe library APIs and allowlists; if unavoidable, strictly validate and escape.'],
  [/config (file )?exposed|config\.json/i, 'Do not serve application config from the web root; keep it out of the public directory.'],
];
function fixHint(title) { for (const [re, fix] of FIX_HINTS) if (re.test(title || '')) return fix; return 'Restrict and validate the exposed functionality; apply least privilege and enforce checks server-side.'; }

// Stage 1 — triage the attack surface into a deduped, exploitability-ranked fix plan.
export function triage(surface) {
  const nodes = (surface && surface.nodes) || [];
  const edges = (surface && surface.edges) || [];
  const findings = nodes.filter((n) => n.type === 'finding');
  const exploits = nodes.filter((n) => n.type === 'exploit');
  const exploitedNames = new Set(exploits.map((e) => e.label));
  const hostOf = (id) => { const h = nodes.find((n) => n.type === 'host' && edges.some((e) => e.from === n.id && e.to === id)); return h ? (h.label || h.ip) : null; };
  const seen = new Map();
  for (const f of findings) {
    const host = hostOf(f.id);
    const key = (f.label || '') + '|' + (host || '');
    const exploited = exploitedNames.has(f.label) || edges.some((e) => e.from === f.id && exploits.some((x) => x.id === e.to));
    const m = classify(f.label);
    const item = { title: f.label, sev: f.sev, ref: f.ref, host, confidence: f.confidence, validation: (f.validation && f.validation.state) || null, exploited, owasp: m.owasp, attack: m.attack, fix: fixHint(f.label), score: exploitability(f, exploited) };
    if (!seen.has(key) || seen.get(key).score < item.score) seen.set(key, item);
  }
  const items = [...seen.values()].sort((a, b) => b.score - a.score);
  return { count: items.length, items, topFix: items[0] || null };
}

// Prompt for the code-fix agent, from the triaged plan.
export function codeFixBriefing(items, { repoDir } = {}) {
  const list = (Array.isArray(items) ? items : []).slice(0, 12);
  const L = [
    'You are VARVEL\'s REMEDIATION engineer. Your ONLY job is to FIX the vulnerabilities below',
    `in the repository${repoDir ? ' at ' + repoDir : ''} — defensive work only, never exploitation.`,
    'For each, locate the responsible code, implement the minimal correct fix, and keep changes tight.',
    'Ranked by exploitability (fix the top items first):',
    ...list.map((f, i) => `${i + 1}. [${String(f.sev || '').toUpperCase()} · score ${f.score}${f.exploited ? ' · PROVEN' : ''}] ${f.title}${f.host ? ' @ ' + f.host : ''} — ${f.fix} (${f.owasp})`),
    '',
    'Work in the repo with your file/edit/grep tools. Do not run exploits or touch anything outside the repo.',
    'When done, summarize the files changed and how each fix closes the finding.',
  ];
  return L.join('\n');
}

// Stage 2 — drive a governed code agent to apply the fixes in a repo (optionally open a PR).
// runAgent is injected ({system,messages}=>{text,...}); never throws.
export async function codeFixAgent(runAgent, { surface, items, repoDir, openPr = false, branch = 'varvel/remediation' } = {}) {
  const plan = items || (triage(surface).items);
  if (!plan.length) return { ok: true, fixed: 0, note: 'no findings to remediate' };
  if (typeof runAgent !== 'function') return { ok: false, reason: 'no code agent available', plan };
  const prNote = openPr ? `\n\nAfter fixing, create a branch \`${branch}\`, commit the fixes with a clear message, and open a GitHub pull request via the \`gh\` CLI describing the findings closed.` : '';
  try {
    const r = await runAgent({
      system: 'You are a defensive security remediation engineer. You only FIX code; you never exploit, scan, or exfiltrate. Stay within the given repository.',
      messages: [{ role: 'user', content: codeFixBriefing(plan, { repoDir }) + prNote }],
    });
    return { ok: true, planned: plan.length, summary: String((r && r.text) || '').trim(), openedPr: openPr };
  } catch (e) { return { ok: false, reason: String((e && e.message) || e), plan }; }
}

/* ═══════════════════════════════════════════════════════════════════════════════
   THE AUTO-REMEDIATION PR LOOP (roadmap #7) — the remediation RECORD lifecycle
   and local patch materialization/verification. This module stays PURE of
   settings and network: the gates (remediate.prEnabled / remediate.remoteAllow /
   remediate.ghToken), the ghost threading, and the git-push/PR-open leg all live
   in tools/rempr.mjs. Doctrine:
     · ELIGIBILITY — only findings in the validator state 'validated' may enter
       the loop (enforced at intake in createRemediation). No remediation of
       unproven claims; REFUTED is a first-class refusal.
     · HITL — nothing here pushes or opens anything. The loop produces a local
       patch + a PR DRAFT (title/body/diff preview); tools/rempr.mjs opens the PR
       only on the operator's explicit `open-pr` action. Every stage is audited
       on the record itself (record.audit — token-free by construction: this
       module never sees a token).
     · HONEST VERIFY — patch-works is MEASURED (apply → run the record's declared
       probe against the patched checkout → read the exit code), never asserted.
       A record with no declared probe verifies 'undeclared' and says so.
     · LOCAL ONLY — the operator supplies a checkout path (repoDir). VARVEL never
       clones autonomously this wave; single-repo; the merge is always the
       client's act.
   Record: { id, engagement, findingRef, status: draft|patched|pr-opened|merged|rejected,
             patch (intake), diff, diffstat, files, verify, verifyResult, pr, pushed,
             createdAt, updatedAt, provenance, audit[] }.
   ═══════════════════════════════════════════════════════════════════════════════ */

export const REM_STATUS = Object.freeze(['draft', 'patched', 'pr-opened', 'merged', 'rejected']);
// The lifecycle rail: forward-only, and 'pr-opened' is reachable ONLY from 'patched'
// (a verified-materialized patch) — never straight from draft.
export const REM_TRANSITIONS = Object.freeze({
  draft: ['patched', 'rejected'],
  patched: ['pr-opened', 'rejected'],
  'pr-opened': ['merged', 'rejected'],
  merged: [],
  rejected: [],
});

// Per-engagement record store, file-backed under the same dataDir() discipline as
// store.mjs (VARVEL_DATA_DIR-overridable, so tests stay hermetic). Key derivation
// mirrors store.mjs: sanitized name + short hash, no cross-engagement bleed.
const remKey = (s) => String(s || 'default').replace(/[^a-z0-9._-]/gi, '_').slice(0, 40) + '-' + createHash('sha1').update(String(s || 'default')).digest('hex').slice(0, 8);
export const remediationStorePath = (engagement) => join(dataDir(), remKey(engagement) + '.remediations.json');
function loadRemediations(engagement) {
  try { const p = remediationStorePath(engagement); return existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : []; } catch { return []; }
}
function saveRemediations(engagement, records) {
  try { const p = remediationStorePath(engagement); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(records, null, 2)); return true; } catch { return false; }
}

export function listRemediations({ engagement = 'default' } = {}) {
  return loadRemediations(engagement).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
}
export function getRemediation({ engagement = 'default', id } = {}) {
  return loadRemediations(engagement).find((r) => r.id === id) || null;
}
export function saveRemediation(record) {
  const records = loadRemediations(record.engagement);
  const i = records.findIndex((x) => x.id === record.id);
  if (i >= 0) records[i] = record; else records.push(record);
  saveRemediations(record.engagement, records);
  return record;
}

// THE ELIGIBILITY GATE: validator-state 'validated' only. 'stale' is a rendering of
// validated (validator.mjs), not a disqualifier — it is flagged on the provenance so
// the PR draft can advise revalidation. Never throws.
export function eligibleFinding(f, { staleDays = 30 } = {}) {
  if (!f || typeof f !== 'object') return { ok: false, reason: 'no such finding' };
  const v = f.validation;
  if (!v || !v.state) {
    return { ok: false, reason: 'finding is claimed-unvalidated — the remediation loop only remediates PROVEN claims (validator state: validated). Run the validator first.' };
  }
  if (v.state === 'refuted') {
    return { ok: false, reason: 'finding is REFUTED by the validator gate (' + (v.reason || 'no reason recorded') + ') — there is nothing to remediate' };
  }
  if (v.state !== 'validated') {
    return { ok: false, reason: "finding validation state is '" + v.state + "' — only 'validated' findings are eligible for the remediation loop" };
  }
  return { ok: true, stale: isStale(v, { staleDays }) };
}

// Locate a finding on a surface (live Surface or its JSON) by ref or node id.
export function findFindingByRef(surface, ref) {
  const r = String(ref || '');
  if (!r || !surface) return null;
  const nodes = surface.nodes instanceof Map ? [...surface.nodes.values()] : (surface.nodes || []);
  return nodes.find((n) => n && n.type === 'finding' && (n.ref === r || n.id === r)) || null;
}

// INTAKE — create the remediation record for a VALIDATED finding. The eligibility
// gate fires HERE, before anything is stored. patch: { diff } (unified) and/or
// { files: [{ path, content }] } (full replacement set); verify: { cmd, expect:
// 'zero'|'nonzero' (default 'nonzero' — the reproduction probe should FAIL once the
// fix lands) }. Never throws: refusals are data.
export function createRemediation({ engagement = 'default', surface, findingRef, patch = null, verify = null, fix = null } = {}) {
  const ref = String(findingRef || '');
  if (!ref) return { ok: false, reason: 'findingRef required' };
  const f = findFindingByRef(surface, ref);
  if (!f) return { ok: false, reason: "no finding with ref '" + ref + "' on the stored surface for engagement '" + engagement + "'" };
  const elig = eligibleFinding(f);
  if (!elig.ok) return { ok: false, gate: 'eligibility', reason: elig.reason, findingRef: ref };
  if (patch && !patch.diff && !(Array.isArray(patch.files) && patch.files.length)) {
    return { ok: false, reason: 'patch must carry a unified diff (patch.diff) and/or a patched file set (patch.files[{path,content}])' };
  }
  if (verify && !verify.cmd) {
    return { ok: false, reason: 'verify must declare a probe command (verify.cmd) — an assertion without a probe is not verification' };
  }
  const now = new Date().toISOString();
  const record = {
    id: 'rem-' + randomBytes(4).toString('hex'),
    engagement,
    findingRef: ref,
    status: 'draft',
    patch: patch ? { diff: patch.diff || null, files: patch.files || null } : null,
    diff: null,
    diffstat: null,
    files: [],
    verify: verify ? { cmd: String(verify.cmd), expect: verify.expect === 'zero' ? 'zero' : 'nonzero' } : null,
    verifyResult: null,
    pr: null,
    pushed: null,
    createdAt: now,
    updatedAt: now,
    provenance: {
      engagement,
      source: 'varvel-remediate',
      finding: {
        ref,
        title: f.label,
        sev: f.sev,
        confidence: f.confidence || null,
        evidence: f.evidence ? String(f.evidence).slice(0, 600) : null,
        validation: { state: f.validation.state, oracle: f.validation.oracle || null, at: f.validation.validatedAt || f.validation.at || null },
      },
      fix: fix || fixHint(f.label),
      stale: !!elig.stale,
    },
    audit: [{ stage: 'draft', at: now, detail: 'remediation record created for VALIDATED finding ' + ref + (elig.stale ? ' (STALE: validated beyond the freshness window — revalidation advised)' : '') }],
  };
  const records = loadRemediations(engagement);
  records.push(record);
  saveRemediations(engagement, records);
  return { ok: true, record };
}

// Lifecycle transition with the rail enforced (REM_TRANSITIONS). Never throws.
export function transitionRemediation({ engagement = 'default', id, to, detail } = {}) {
  const records = loadRemediations(engagement);
  const r = records.find((x) => x.id === id);
  if (!r) return { ok: false, reason: 'no remediation record ' + id };
  if (!REM_STATUS.includes(to)) return { ok: false, reason: "unknown remediation status '" + to + "'", record: r };
  if (!REM_TRANSITIONS[r.status].includes(to)) {
    return { ok: false, reason: 'invalid lifecycle transition ' + r.status + ' -> ' + to + ' (allowed from ' + r.status + ': ' + (REM_TRANSITIONS[r.status].join(', ') || 'none — terminal') + ')', record: r };
  }
  r.status = to;
  r.updatedAt = new Date().toISOString();
  r.audit.push({ stage: to, at: r.updatedAt, detail: detail || ('status -> ' + to) });
  saveRemediations(engagement, records);
  return { ok: true, record: r };
}

/* ---------- local git plumbing (spawn-injectable; LOCAL ONLY — no network leg) ---------- */

// The default spawn: promise-wrapped, capped output, timeout-killed, NEVER throws.
// Signature is the injectable seam: spawnFn(cmd, args, { cwd, input, env, timeoutMs, shell }).
export function defaultSpawn(cmd, args, { cwd, input, env, timeoutMs = 30000, shell = false } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    let p;
    try { p = nodeSpawn(cmd, args, { cwd, env: env ? { ...process.env, ...env } : process.env, shell, windowsHide: true }); } catch (e) { return done({ code: -1, stdout: '', stderr: String((e && e.message) || e) }); }
    let stdout = '', stderr = '';
    p.stdout.on('data', (d) => { stdout += d; if (stdout.length > 1e6) stdout = stdout.slice(-1e6); });
    p.stderr.on('data', (d) => { stderr += d; if (stderr.length > 1e6) stderr = stderr.slice(-1e6); });
    const to = setTimeout(() => { try { p.kill(); } catch {} done({ code: -1, stdout, stderr: stderr + '\n[timeout ' + timeoutMs + 'ms — killed]' }); }, timeoutMs);
    p.on('error', (e) => { clearTimeout(to); done({ code: -1, stdout, stderr: String((e && e.message) || e) }); });
    p.on('close', (code) => { clearTimeout(to); done({ code: code == null ? -1 : code, stdout, stderr }); });
    try { if (input != null) p.stdin.write(input); p.stdin.end(); } catch { /* spawn already failed; the error handler reports it */ }
  });
}

const diffPaths = (diff) => {
  const out = [];
  const re = /^diff --git a\/(.+?) b\/.+$/gm;
  let m;
  while ((m = re.exec(String(diff || '')))) out.push(m[1]);
  return [...new Set(out)];
};
const isInsideDir = (root, abs) => abs === root || abs.startsWith(root.endsWith(sep) ? root : root + sep);

// PATCH MATERIALIZATION + MEASURED VERIFY against a LOCAL checkout:
//   apply (git apply for a stored diff; full-file writes for a file set)
//   → capture the unified diff + diffstat + patched file set FROM GIT (measured,
//     not restated) → run the record's declared probe → REVERT the working tree
//     (the checkout is left exactly as found; the diff lives on the record).
// The tree is patched DURING the probe so 'verify' measures the fixed state.
// On success the record transitions draft -> patched. Never throws.
export async function materializePatch(record, { repoDir, spawn: spawnFn, timeoutMs = 30000 } = {}) {
  const audit = (stage, detail) => { record.audit.push({ stage, at: new Date().toISOString(), detail }); record.updatedAt = new Date().toISOString(); };
  const fail = (stage, reason) => { audit(stage, reason); return { ok: false, stage, reason, record }; };
  if (!record || !record.id) return { ok: false, stage: 'patch-refused', reason: 'no remediation record' };
  const patch = record.patch;
  if (!patch || (!patch.diff && !(patch.files && patch.files.length))) {
    return fail('patch-refused', 'record ' + record.id + ' carries no patch — attach a unified diff or a patched file set first');
  }
  if (!repoDir) return fail('patch-refused', 'a LOCAL checkout path (repoDir) is required — VARVEL never clones autonomously');
  const git = (args, opts = {}) => (spawnFn || defaultSpawn)('git', ['-C', repoDir, ...args], { timeoutMs, ...opts });

  const inside = await git(['rev-parse', '--is-inside-work-tree']);
  if (inside.code !== 0 || !/true/.test(inside.stdout)) {
    return fail('patch-refused', "'" + repoDir + "' is not a git work tree — the loop patches a real local checkout, nothing else");
  }

  // 1) apply
  let originals = []; // files-mode rollback journal { rel, abs, existed, content }
  if (patch.diff) {
    const check = await git(['apply', '--check'], { input: patch.diff });
    if (check.code !== 0) return fail('patch-failed', 'git apply --check rejected the stored diff: ' + check.stderr.trim());
    const ap = await git(['apply'], { input: patch.diff });
    if (ap.code !== 0) return fail('patch-failed', 'git apply failed: ' + ap.stderr.trim());
  } else {
    const root = resolve(repoDir);
    for (const f of patch.files) { // validate ALL paths before writing ANY
      const rel = String((f && f.path) || '');
      const abs = resolve(root, rel);
      if (!rel || !isInsideDir(root, abs)) return fail('patch-refused', 'patch path escapes the checkout: ' + rel);
      let existed = false, content = null;
      try { content = readFileSync(abs, 'utf8'); existed = true; } catch { /* new file */ }
      originals.push({ rel, abs, existed, content, newContent: String((f && f.content) ?? '') });
    }
    try {
      for (const o of originals) { mkdirSync(dirname(o.abs), { recursive: true }); writeFileSync(o.abs, o.newContent); }
    } catch (e) { return fail('patch-failed', 'could not write the patched file set: ' + String((e && e.message) || e)); }
  }

  const paths = patch.diff ? diffPaths(patch.diff) : originals.map((o) => o.rel);
  const revert = async () => {
    if (patch.diff) { await git(['apply', '-R'], { input: patch.diff }); return; }
    for (const o of originals) { try { if (o.existed) writeFileSync(o.abs, o.content); else unlinkSync(o.abs); } catch { /* best-effort restore; tests assert a clean tree */ } }
    const created = originals.filter((o) => !o.existed).map((o) => o.rel);
    if (created.length) await git(['reset', '-q', '--', ...created]); // clear intent-to-add
  };

  // intent-to-add so brand-new files show in `git diff`
  const ija = await git(['add', '-N', '--', ...paths]);
  if (ija.code !== 0) { await revert(); return fail('patch-failed', 'git add -N failed: ' + ija.stderr.trim()); }

  // 2) capture the MEASURED diff/stat/patched contents from git itself
  const d = await git(['diff', '--', ...paths]);
  const ds = await git(['diff', '--stat', '--', ...paths]);
  if (!d.stdout.trim()) { await revert(); return fail('patch-failed', 'the patch produced NO change against the checkout (empty diff) — nothing to PR'); }
  const patchedFiles = paths.map((rel) => { let content = null; try { content = readFileSync(join(repoDir, rel), 'utf8'); } catch {} return { path: rel, content }; });

  // 3) MEASURED verify: run the declared probe against the PATCHED tree
  let verifyResult;
  if (record.verify && record.verify.cmd) {
    const expect = record.verify.expect === 'zero' ? 'zero' : 'nonzero';
    const v = await (spawnFn || defaultSpawn)(record.verify.cmd, [], { cwd: repoDir, shell: true, timeoutMs });
    const met = expect === 'zero' ? v.code === 0 : v.code !== 0;
    verifyResult = {
      ran: true, cmd: record.verify.cmd, exit: v.code, expect,
      verdict: met ? 'patch-works' : 'patch-fails',
      at: new Date().toISOString(),
      note: met
        ? 'the declared probe ' + (expect === 'nonzero' ? 'now FAILS (the finding no longer reproduces)' : 'passes') + ' against the patched tree — MEASURED, not asserted'
        : 'the declared probe did NOT meet its expectation (exit ' + v.code + ', expected ' + expect + ') — the patch does NOT verify',
      tail: String((v.stdout || '') + (v.stderr || '')).slice(-800),
    };
  } else {
    verifyResult = { ran: false, verdict: 'undeclared', at: new Date().toISOString(), note: 'the record declares no verification probe — patch-works is NOT claimed' };
  }

  // 4) revert the checkout exactly as found
  await revert();

  // 5) persist onto the record
  record.diff = d.stdout;
  record.diffstat = ds.stdout.trim();
  record.files = patchedFiles;
  record.verifyResult = verifyResult;
  audit('patch-applied', 'applied against ' + repoDir + ' — ' + paths.length + ' file(s): ' + paths.join(', ') + '; working tree reverted after capture');
  audit('verify', verifyResult.verdict + (verifyResult.ran ? ' (probe exit ' + verifyResult.exit + ', expected ' + verifyResult.expect + ')' : ' (no probe declared)'));
  if (record.status === 'draft' && REM_TRANSITIONS.draft.includes('patched')) {
    record.status = 'patched';
    audit('patched', 'status draft -> patched (materialized + measured)');
  }
  return { ok: true, record, verify: verifyResult, diffstat: record.diffstat, files: paths };
}

/* ---------- the PR DRAFT (pure): title + body + diff preview, token-free ---------- */

export function buildPrDraft(record) {
  const p = record.provenance || {};
  const f = p.finding || {};
  const v = f.validation || {};
  const ver = record.verifyResult;
  const title = 'fix: ' + (f.title || record.findingRef) + ' [varvel ' + record.id + ']';
  const verifySection = !ver || ver.verdict === 'undeclared'
    ? 'NOT VERIFIED — the record declared no reproduction probe; patch-works is **not** claimed.'
    : ver.verdict === 'patch-works'
    ? 'MEASURED **patch-works**: probe exit ' + ver.exit + ' (expected ' + ver.expect + ') — the finding no longer reproduces against the patched tree.'
    : 'MEASURED **patch-FAILS**: probe exit ' + ver.exit + ' (expected ' + ver.expect + ') — this PR is opened on explicit operator action with verification failing; review accordingly.';
  const body = [
    '## Finding',
    '',
    '- **' + (f.title || record.findingRef) + '** (' + String(f.sev || '?').toUpperCase() + ', ref ' + (f.ref || record.findingRef) + (f.confidence ? ', ' + f.confidence : '') + ')',
    f.evidence ? '- Evidence: ' + f.evidence : '- Evidence: (none recorded on the finding)',
    p.fix ? '- Fix guidance: ' + p.fix : null,
    '',
    '## Validation proof',
    '',
    '- Validator state: **' + (v.state || 'unknown') + '**' + (v.at ? ' at ' + v.at : ''),
    v.oracle ? '- Oracle: ' + v.oracle : null,
    p.stale ? '- ⚠ STALE: validated beyond the freshness window — revalidation advised before merge.' : null,
    '',
    '## Fix verification',
    '',
    verifySection,
    '',
    '## Changes',
    '',
    '```',
    (record.diffstat || '(diffstat unavailable)').trim(),
    '```',
    '',
    '## Rollback',
    '',
    'Merge is always the client\'s act. Until then this branch is inert; closing this PR abandons the fix with zero residue, and after merge a single `git revert` of this branch\'s commit restores the prior state.',
    '',
    '---',
    '_Opened by the VARVEL auto-remediation loop (' + record.id + ') from a validator-**validated** finding, via the operator\'s burner account. Every stage (draft → patch → verify → push → open) is audited on the remediation record._',
  ].filter((l) => l !== null).join('\n');
  return { title, body, diffstat: record.diffstat || '' };
}

// House-style commit message for the remediation branch (lowercase, plain, provenance-carried).
export function remediationCommitMessage(record) {
  const f = (record.provenance && record.provenance.finding) || {};
  const ver = record.verifyResult;
  return [
    'remediate: ' + (f.title || record.findingRef) + ' [varvel ' + record.id + ']',
    '',
    'finding: ' + (f.ref || record.findingRef) + ' (' + String(f.sev || '?') + ', validator ' + (((f.validation || {}).state) || 'unknown') + ')',
    'verify: ' + (ver ? ver.verdict : 'undeclared') + (ver && ver.ran ? ' (probe exit ' + ver.exit + ', expected ' + ver.expect + ')' : ' — patch-works not claimed'),
  ].join('\n');
}
