// tools/rempr.mjs — the GOVERNED legs of the auto-remediation PR loop (roadmap #7;
// engine/remediate.mjs owns the pure record lifecycle + patch materialization).
//
// GATES (doctrine, enforced HERE in order, each refusal is data — never a throw):
//   1. remediate.prEnabled   — the whole loop is DEFAULT-OFF; draft/verify/open-pr
//                              all refuse until the engagement opts in.
//   2. remediate.remoteAllow — the git-push/PR-open leg is a SECOND, separate gate;
//                              draft/verify stay local-only even with the loop on.
//   3. remediate.ghToken     — the burner PAT (secret-class settings key).
//   4. lifecycle             — only a PATCHED record (materialized + measured) can
//                              be pushed/opened; 'pr-opened' re-runs are idempotent.
//
// HITL (absolute): openRemediationPr is invoked ONLY by the operator's explicit
// `remediate open-pr <id>` CLI action. Nothing in the draft/verify/list paths —
// and nothing anywhere else in the platform — imports or calls the push leg.
//
// TOKEN DOCTRINE (same as ghc2): the token is an OPERATOR-SUPPLIED BURNER account
// PAT (repo scope), NEVER the operator's real account, NEVER committed, NEVER
// logged. Reports and audit entries carry tokenMeta() — presence + class only.
// PUSH TRANSPORT: the token rides the push child's ENVIRONMENT as a transient
// git config (GIT_CONFIG_COUNT/GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0 =
// http.extraHeader Authorization: Bearer …) — it is NEVER in the remote URL,
// NEVER in argv, and NEVER persisted to .git/config. All git output is scrubbed
// defensively (token → <redacted>) before it can touch a report or audit entry.
//
// GHOST THREADING (the ghc2 parity decision, and WHY): remediation calls to
// api.github.com are OVERT client work, so the default is DIRECT (ghost off →
// direct, labeled honestly). But the posture is identical to ghc2 when ghost is
// armed: ghost on + chain → the REST leg rides ghost.agents(); ghost 'required'
// to a PUBLIC api base + unverified/no chain → REFUSED fail-closed (the operator
// egress must never touch the SaaS directly when required mode is armed).
// Loopback/private api bases are always direct (ghost doctrine: lab traffic never
// leaves the lab — also the hermetic-test path).

import http from 'node:http';
import https from 'node:https';
import { tokenMeta } from '../engine/ghc2.mjs';
import { scrubHeaders, isPrivateDest } from '../engine/ghost.mjs';
import { ghostRideState } from './clearance/broker.mjs';
import { Settings } from '../engine/settings.mjs';
import { createRemediation, getRemediation, saveRemediation, materializePatch, transitionRemediation, buildPrDraft, remediationCommitMessage, defaultSpawn } from '../engine/remediate.mjs';

const msg = (e) => String((e && e.message) || e);

// Read the remediate.* settings bucket. Never throws — an unreadable store reads as
// disabled/absent (the gates below then name exactly what is missing). The token
// comes back RAW here (the push/REST legs must hand it onward) — it is never logged
// and never appears in any report this file returns.
export async function readRemSettings({ engagement, settings } = {}) {
  try {
    const s = settings || Settings.for(engagement || 'default');
    return {
      prEnabled: s.get('remediate.prEnabled') === true,
      remoteAllow: s.get('remediate.remoteAllow') === true,
      token: String(s.get('remediate.ghToken') || ''),
    };
  } catch {
    return { prEnabled: false, remoteAllow: false, token: '' };
  }
}

const PR_DISABLED = 'the auto-remediation PR loop is DISABLED (remediate.prEnabled=false — the default). Validated finding → verified fix → one-click PR is opt-in: settings set remediate.prEnabled true';

// DRAFT leg (local): the eligibility gate (validated-only) fires inside
// createRemediation at intake. Never throws.
export async function draftRemediation({ engagement = 'default', surface, findingRef, patch, verify, settings } = {}) {
  const cfg = await readRemSettings({ engagement, settings });
  if (!cfg.prEnabled) return { ok: false, gate: 'remediate.prEnabled', reason: PR_DISABLED };
  return createRemediation({ engagement, surface, findingRef, patch, verify });
}

// VERIFY leg (local): materialize the patch against the operator-supplied checkout
// and run the record's declared probe. LOCAL git spawns only — no network, ever.
export async function verifyRemediation({ engagement = 'default', id, repoDir, settings, spawn } = {}) {
  const cfg = await readRemSettings({ engagement, settings });
  if (!cfg.prEnabled) return { ok: false, gate: 'remediate.prEnabled', reason: PR_DISABLED };
  const record = getRemediation({ engagement, id });
  if (!record) return { ok: false, reason: 'no remediation record ' + id + " for engagement '" + engagement + "'" };
  const m = await materializePatch(record, { repoDir, spawn });
  saveRemediation(record);
  return m;
}

// MARK leg (local bookkeeping): merged/rejected — the client's acts, recorded by the operator.
export async function markRemediation({ engagement = 'default', id, to, detail } = {}) {
  return transitionRemediation({ engagement, id, to, detail });
}

// Ghost threading for the REMOTE leg (the cfride/ghc2 parity shape):
//   loopback/private api base  -> direct, always (lab traffic never leaves the lab)
//   ghost off                  -> direct — remediation is OVERT client work (default)
//   ghost on + chain           -> ride ghost.agents()
//   ghost on, no chain         -> direct, honestly labeled (best-effort mode)
//   ghost required             -> chain REQUIRED and verified, else REFUSED fail-closed
// Result: { ok, direct, agents, transport } or { ok:false, reason }. Never throws.
export async function resolveRemTransport({ ghost, ghostMode, apiBase = 'https://api.github.com' } = {}) {
  const mode = ghostMode || (ghost && ghost.mode) || 'off';
  try {
    let host = '';
    try { host = new URL(String(apiBase)).hostname; } catch { return { ok: false, reason: 'unparseable remediation api base URL — refusing (fail-closed)' }; }
    if (isPrivateDest(host)) {
      return { ok: true, direct: true, agents: null, transport: 'direct (private/loopback api base — ghost doctrine: lab traffic never leaves the lab)' };
    }
    if (mode === 'off') return { ok: true, direct: true, agents: null, transport: 'direct (ghost off — remediation PR traffic is overt client work)' };
    if (!ghost || !ghost.chain || !ghost.chain.length) {
      if (mode === 'required') return { ok: false, reason: 'ghost mode is REQUIRED but no chain is armed — the operator egress must never touch the SaaS remote directly. Arm a chain first. remediation open-pr REFUSED (fail-closed).' };
      return { ok: true, direct: true, agents: null, transport: 'direct (ghost on but no chain armed — best-effort mode, labeled honestly)' };
    }
    if (mode === 'required' && !ghost.verifiedOk()) {
      try { await ghost.verify(); } catch { /* handled by the check below */ }
      if (!ghost.verifiedOk()) {
        return { ok: false, reason: 'ghost mode is REQUIRED but the chain exit is NOT verified — public SaaS egress REFUSED (fail-closed). Run the ghost self-check first.' };
      }
    }
    return { ok: true, direct: false, agents: ghost.agents(), transport: 'ghost chain (' + ghost.chain.length + ' hop(s))' };
  } catch (e) {
    return { ok: false, reason: 'remediation transport resolution failed (' + msg(e) + ') — refusing (fail-closed)' };
  }
}

// The push env: the burner token as a TRANSIENT git config via the child's
// environment (git ≥2.31). Never the remote URL, never argv, never .git/config.
// GIT_TERMINAL_PROMPT=0: fail-closed instead of an interactive credential prompt.
export function pushEnv(token) {
  return {
    GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'http.extraHeader',
    GIT_CONFIG_VALUE_0: 'Authorization: Bearer ' + String(token || ''),
    GIT_TERMINAL_PROMPT: '0',
  };
}

/* ---------- the GitHub REST client for the PR leg (never throws; token-safe) ---------- */

const RP_UA = 'git/2.45.2.windows.1'; // GitHub rejects UA-less requests; a git-shaped UA is ordinary dev-box traffic.
const RP_BODY_CAP = 1024 * 1024;      // a pulls response is small — bounded read

// RemPrApi speaks EXACTLY ONE endpoint: POST /repos/:owner/:repo/pulls. apiBase is
// injectable (hermetic loopback tests); `agents` rides the ghost chain like ghc2.
// The TOKEN only ever leaves in the Authorization header — every return value and
// error string is token-free by construction.
export class RemPrApi {
  constructor({ token, owner, repo, apiBase = 'https://api.github.com', agents = null, timeoutMs = 15000 } = {}) {
    if (!owner || !repo) throw new TypeError('RemPrApi: owner + repo required (the client repo the PR targets)');
    this._token = String(token || '');
    this.owner = String(owner);
    this.repo = String(repo);
    this.apiBase = String(apiBase).replace(/\/+$/, '');
    this.agents = agents || null;
    this.timeoutMs = Math.max(1000, Number(timeoutMs) || 15000);
  }

  tokenMeta() { return tokenMeta(this._token); }

  openPr({ title, body, head, base }) {
    return new Promise((resolve) => {
      let u;
      try { u = new URL(this.apiBase + '/repos/' + encodeURIComponent(this.owner) + '/' + encodeURIComponent(this.repo) + '/pulls'); } catch { return resolve({ ok: false, status: 0, error: 'unparseable apiBase' }); }
      const lib = u.protocol === 'https:' ? https : http;
      const payload = Buffer.from(JSON.stringify({ title: String(title || ''), body: String(body || ''), head: String(head || ''), base: String(base || 'main') }), 'utf8');
      const headers = scrubHeaders({
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
        authorization: 'Bearer ' + this._token,
        'content-type': 'application/json',
        'content-length': payload.length,
      }, { ua: RP_UA });
      let settled = false;
      const done = (v) => { if (!settled) { settled = true; resolve(v); } };
      let req;
      try {
        req = lib.request({
          hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
          path: u.pathname + u.search, method: 'POST', timeout: this.timeoutMs,
          rejectUnauthorized: false,
          agent: this.agents ? (u.protocol === 'https:' ? this.agents.httpsAgent : this.agents.httpAgent) : undefined,
          headers,
        }, (res) => {
          const chunks = [];
          let size = 0, tooBig = false;
          res.on('data', (d) => { size += d.length; if (size > RP_BODY_CAP) { tooBig = true; res.destroy(); return; } chunks.push(d); });
          res.on('end', () => {
            if (tooBig) return done({ ok: false, status: res.statusCode || 0, error: 'response exceeded the 1MB read cap' });
            let json = null;
            try { json = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* surfaced via status */ }
            const status = res.statusCode || 0;
            if (status < 200 || status >= 300) {
              return done({ ok: false, status, error: status === 401
                ? 'token REJECTED (401 Unauthorized) — bad/revoked burner PAT'
                : status === 403
                ? 'forbidden (403) — the burner PAT lacks repo scope on ' + this.owner + '/' + this.repo + ' (or is rate-capped)'
                : status === 404
                ? 'not found (404) — the burner account cannot see ' + this.owner + '/' + this.repo + ' (push a fork/branch it can reach)'
                : status === 422
                ? 'unprocessable (422) — ' + String((json && json.message) || 'the PR already exists or the head/base ref is wrong')
                : 'HTTP ' + status + (json && json.message ? ' — ' + json.message : '') });
            }
            done({ ok: true, status, pr: { url: String((json && json.html_url) || ''), number: Number(json && json.number) || null } });
          });
          res.on('error', () => done({ ok: false, status: res.statusCode || 0, error: 'response stream error' }));
        });
      } catch (e) { return done({ ok: false, status: 0, error: String((e && e.message) || e) }); }
      req.on('timeout', () => { try { req.destroy(); } catch {} done({ ok: false, status: 0, error: 'request timed out (' + this.timeoutMs + 'ms)' }); });
      req.on('error', (e) => done({ ok: false, status: 0, error: String((e && e.message) || e) }));
      req.write(payload);
      req.end();
    });
  }
}

/* ---------- THE REMOTE LEG — operator-invoked only (the `open-pr` action) ---------- */

// openRemediationPr: branch → commit → push (burner token via child env) → open the
// PR via REST. Every stage is audited on the record (token-free). Idempotent: a
// 'pr-opened' record returns its PR without re-pushing; a record whose branch was
// pushed by an earlier failed attempt resumes at the REST leg. Never throws.
export async function openRemediationPr({ engagement = 'default', id, repoDir, owner, repo, base = 'main', branch, apiBase = 'https://api.github.com', settings, ghost, ghostMode, spawn, client } = {}) {
  try {
    const record = getRemediation({ engagement, id });
    if (!record) return { ok: false, reason: 'no remediation record ' + id + " for engagement '" + engagement + "'" };
    const audit = (stage, detail) => { record.audit.push({ stage, at: new Date().toISOString(), detail }); record.updatedAt = new Date().toISOString(); saveRemediation(record); };

    // Idempotency: never re-push / double-open.
    if (record.status === 'pr-opened' && record.pr) {
      return { ok: true, already: true, pr: record.pr, verify: record.verifyResult, note: 'PR already opened for this record — nothing re-pushed, nothing re-opened' };
    }

    // GATES — every refusal lands BEFORE any spawn or network call.
    const cfg = await readRemSettings({ engagement, settings });
    if (!cfg.prEnabled) return { ok: false, gate: 'remediate.prEnabled', reason: PR_DISABLED };
    if (!cfg.remoteAllow) {
      return { ok: false, gate: 'remediate.remoteAllow', reason: 'the REMOTE leg (git push + PR open) is a SECOND, separate gate and it is OFF (remediate.remoteAllow=false — the default). Draft/verify stay local. To allow the push leg: settings set remediate.remoteAllow true' };
    }
    if (!cfg.token) {
      return { ok: false, gate: 'remediate.ghToken', reason: "no remediate.ghToken — the doctrine is a BURNER account's PAT (repo scope), operator-supplied at engagement time: settings set remediate.ghToken <burner-pat>. NEVER the operator's real account token" };
    }
    if (record.status !== 'patched') {
      return { ok: false, gate: 'lifecycle', reason: "record is '" + record.status + "' — only a PATCHED record (materialized + measured via `remediate verify`) can be pushed/opened; draft → patched first" };
    }
    if (!record.diff) return { ok: false, gate: 'lifecycle', reason: 'record has no materialized diff — run `remediate verify ' + id + ' --repo <path>` first' };
    if (!owner || !repo) return { ok: false, reason: '--gh <owner/repo> required — the client repo the PR targets (a fork/branch the burner account can push to)' };
    if (!repoDir) return { ok: false, reason: 'a LOCAL checkout path (--repo) is required — VARVEL never clones autonomously' };

    const st = (ghost || ghostMode) ? { ghost, ghostMode } : ghostRideState(engagement);
    const t = client ? { ok: true, direct: true, agents: null, transport: 'injected client (test/embedder seam)' }
      : await resolveRemTransport({ ghost: st.ghost, ghostMode: st.ghostMode, apiBase });
    if (!t.ok) return { ok: false, reason: t.reason };

    const tok = cfg.token;
    const scrub = (s) => String(s || '').split(tok).join('<redacted>'); // defensive: git output can never carry the token into a report/audit
    const spawnFn = spawn || defaultSpawn;
    const git = (args, opts = {}) => spawnFn('git', ['-C', repoDir, ...args], { timeoutMs: 30000, ...opts });
    const br = branch || (record.pushed && record.pushed.branch) || ('varvel/' + record.id);
    const draft = buildPrDraft(record);

    // The git leg — skipped on resume (branch already pushed by an earlier attempt).
    if (!(record.pushed && record.pushed.branch === br)) {
      const inside = await git(['rev-parse', '--is-inside-work-tree']);
      if (inside.code !== 0 || !/true/.test(inside.stdout)) return { ok: false, stage: 'repo', reason: "'" + repoDir + "' is not a git work tree — the loop patches a real local checkout, nothing else" };
      let b = await git(['checkout', '-b', br]);
      if (b.code !== 0) {
        b = await git(['checkout', br]); // branch exists locally (a retry): check it out instead
        if (b.code !== 0) return { ok: false, stage: 'branch', reason: 'cannot create or check out branch ' + br + ': ' + scrub(b.stderr.trim()) };
      }
      const ap = await git(['apply'], { input: record.diff });
      if (ap.code !== 0) return { ok: false, stage: 'apply', reason: 'the materialized diff no longer applies cleanly to ' + repoDir + ': ' + scrub(ap.stderr.trim()) };
      const paths = record.files.map((f) => f.path);
      const add = await git(['add', '--', ...paths]);
      if (add.code !== 0) return { ok: false, stage: 'add', reason: 'git add failed: ' + scrub(add.stderr.trim()) };
      // Transient identity (-c, never config mutation): the commit is attributable to
      // the VARVEL loop, not impersonating the operator or the client.
      const ci = await git(['-c', 'user.name=VARVEL Remediation', '-c', 'user.email=varvel-remediate@localhost', 'commit', '-q', '-m', remediationCommitMessage(record)]);
      if (ci.code !== 0) return { ok: false, stage: 'commit', reason: 'git commit failed: ' + scrub(ci.stderr.trim()) };
      const remote = 'https://github.com/' + owner + '/' + repo + '.git'; // token NEVER in the URL
      const push = await git(['push', remote, br], { env: pushEnv(tok) });
      if (push.code !== 0) return { ok: false, stage: 'push', reason: 'git push failed: ' + scrub(push.stderr.trim()) };
      record.pushed = { branch: br, remote: owner + '/' + repo, at: new Date().toISOString() };
      const tm = tokenMeta(tok);
      audit('pushed', 'branch ' + br + ' pushed to ' + owner + '/' + repo + ' (token ' + (tm.present ? 'present, ' + tm.class : 'ABSENT') + ' — the value rode the push child env as transient http.extraHeader; never the URL, argv, .git/config, or this audit)');
    } else {
      audit('push-resumed', 'branch ' + br + ' was already pushed to ' + record.pushed.remote + ' — resuming at the PR-open leg');
    }

    // The REST leg — the ONLY api.github.com call of the loop.
    const api = client || new RemPrApi({ token: tok, owner, repo, apiBase, agents: t.agents });
    const r = await api.openPr({ title: draft.title, body: draft.body, head: br, base });
    if (!r.ok) {
      audit('pr-open-failed', 'PR open failed: ' + scrub(r.error || ('HTTP ' + r.status)) + ' — the branch IS pushed; re-running open-pr resumes at this leg');
      return { ok: false, stage: 'pr-open', reason: 'PR open failed (' + scrub(r.error || ('HTTP ' + r.status)) + ') — the branch IS pushed; re-running `remediate open-pr ' + id + '` resumes at the PR leg', pushed: record.pushed };
    }
    record.pr = { url: r.pr.url, number: r.pr.number, head: br, base, openedAt: new Date().toISOString() };
    record.status = 'pr-opened';
    audit('pr-opened', 'PR #' + r.pr.number + ' opened: ' + r.pr.url + ' (token presence/class only: ' + JSON.stringify(api.tokenMeta ? api.tokenMeta() : tokenMeta(tok)) + ')');
    return {
      ok: true,
      pr: record.pr,
      verify: record.verifyResult,
      transport: t.transport,
      token: api.tokenMeta ? api.tokenMeta() : tokenMeta(tok), // presence + class ONLY
      warning: record.verifyResult && record.verifyResult.verdict === 'patch-fails'
        ? 'verify measured patch-FAILS — opened on explicit operator action; the PR body says so'
        : record.verifyResult && record.verifyResult.verdict === 'undeclared'
        ? 'the record declared no verification probe — the PR body says patch-works is NOT claimed'
        : undefined,
    };
  } catch (e) {
    return { ok: false, reason: 'open-pr failed (' + msg(e) + ')' };
  }
}
