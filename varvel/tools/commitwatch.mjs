// VARVEL — commitwatch: the WP-plugin commit-diff watcher (the vuln-discovery layer's
// EYES on wordpress.org). Big-Sleep-style (research/SOTA-VULN-DISCOVERY-2026-08-25.md
// §6 item 3): watch the tracked plugins' SVN trunk for fresh changesets, diff what
// changed against the recorded last-seen revision, run engine/commitwatch.mjs's
// security-relevance classifier over the diffs, and record ranked REVIEW-ONLY leads —
// a commit ADDING a nonce/capability/sanitization check names the vuln class, the
// affected older versions, and the sibling paths the fix probably missed.
//
// THE DOCTRINE LINE — carried on every output object, embedded in every lead, printed
// by every CLI sub-command:
//   "a fix commit is a map to a bug class, not a finding — leads are review-only;
//    nothing is hunted, probed, or filed from here."
//
// HARD RULES:
//   1. NEVER hunts, NEVER submits. This module imports NOTHING from privemap or
//      variantsweep (the suggested-seed vocabulary rides as strings for the operator
//      to feed BY HAND) and contains no hunt/submission execution path, behind any
//      flag. test/commitwatch.test.mjs pins this with a static scan of both files.
//   2. NETWORK = WORDPRESS.ORG HOSTS ONLY, read-only GETs, and ONLY in the gated live
//      path: liveSource() refuses without an explicit opt-in flag (CLI: --live); the
//      thin client REJECTS any non-wordpress.org host with a named error. Tests run on
//      fixtures through the SAME code path — the operator runs live scans deliberately.
//   3. HONESTY: unreachable / refused / rate-limited / unparseable => a loud NAMED
//      error ('wporg-unreachable' | 'wporg-rate-limited' | 'wporg-http-error' |
//      'wporg-bad-response' | 'commitwatch-host-not-allowed' | 'commitwatch-live-not-requested'
//      | 'unreadable-fixture' | 'unreadable-targets') — revision/diff data is NEVER
//      fabricated. A plugin whose fetch fails keeps its previous state: a failed fetch
//      is not a frozen plugin.
//   4. THE WATCH SET IS DATA-DRIVEN: slugs live in <root>/targets.json (default
//      varvel/data/commitwatch/targets.json — the 14 >=50k AI-surface targets from
//      varvel-kimi/research/ai-feature-target-list-2026-08-25.md §1 + madara-core),
//      overridable per scan (--targets <file>); tests point it at fixtures. Nothing
//      about the target set is hard-coded here.
//
// CONFIGURABLE CONSTANTS — THE WORDPRESS.ORG SHAPES. The trunk-index shape was
// CONFIRMED live 2026-08-25 (one polite fetch: plugins.svn.wordpress.org/akismet/trunk/
// answers "Revision 3666159: /akismet/trunk"). The changeset-diff shape is the
// best-known Trac convention (UNVERIFIED at build time — a live run that disagrees
// changes THIS TABLE, not the engine; whatever the reader cannot parse lands EMPTY
// with a named gap, never guessed):
//   WPORG.SVN_TRUNK(slug)  plugins.svn.wordpress.org/<slug>/trunk/ — mod_dav_svn HTML
//       index; the title carries "Revision <N>: /<slug>/trunk" (the repo head).
//   WPORG.LOG_RSS(slug)    plugins.trac.wordpress.org/log/<slug>/trunk?format=rss — the
//       recent-changeset feed; revision numbers parse from /changeset/<N>/ links.
//   WPORG.CHANGESET(slug, rev) plugins.trac.wordpress.org/changeset/<rev>/<slug>?format=diff
//       — the changeset as a unified diff download (Index: <path> + ---/+++ hunks).
//
// SVN FALLBACK (added 2026-08-26 — the day ALL trac endpoints started answering 403
// through the exit): trac stays PRIMARY whenever it works; ONLY an HTTP 403 engages
// the fallback (any other failure stays a named error). Fallback = the same
// mod_dav_svn HTML index the trunk reader already uses: enumerate /<slug>/tags/,
// diff the NEWEST tag against the PREVIOUS tag (added/removed .php files certain;
// common files content-compared pairwise, capped), synthesize ONE changeset whose
// message says exactly that — a RELEASE-PAIR delta, per-commit granularity
// unavailable. Every cap overflow / unparseable index lands EMPTY or partial with a
// named gap — never a fabricated revision, tag list, or diff.
//
// RELEASE GATING (2026-08-26, the global-revision lesson): plugins.svn.wordpress.org
// is ONE repo with a GLOBAL revision counter — the index "Revision <n>" is repo-wide
// HEAD, so any commit anywhere bumps every plugin's displayed revision. HEAD alone
// must NEVER trigger a diff (it fired on all 17 targets in one scan — mostly stale
// release churn). The plugin's OWN release signal is readme.txt's "Stable tag: X":
// the tag-to-tag diff fires ONLY when the stable tag CHANGED vs state
// (lastStableTag in state.json). HEAD stays as a cheap liveness check.
//   WPORG.SVN_TRUNK(slug)  plugins.svn.wordpress.org/<slug>/trunk/ — mod_dav_svn HTML
//       index; the title carries "Revision <N>: /<slug>/trunk" (the repo head).
//   WPORG.LOG_RSS(slug)    plugins.trac.wordpress.org/log/<slug>/trunk?format=rss — the
//       recent-changeset feed; revision numbers parse from /changeset/<N>/ links.
//   WPORG.CHANGESET(slug, rev) plugins.trac.wordpress.org/changeset/<rev>/<slug>?format=diff
//       — the changeset as a unified diff download (Index: <path> + ---/+++ hunks).

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseChangesetDiff, buildLead, rankLeads } from '../engine/commitwatch.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));

export const WPORG = {
  SVN_BASE: 'https://plugins.svn.wordpress.org',
  TRAC_BASE: 'https://plugins.trac.wordpress.org',
  SVN_TRUNK: (slug) => `/${encodeURIComponent(slug)}/trunk/`,
  SVN_PLUGIN: (slug) => `/${encodeURIComponent(slug)}/`,
  SVN_TAGS: (slug) => `/${encodeURIComponent(slug)}/tags/`,
  LOG_RSS: (slug) => `/log/${encodeURIComponent(slug)}/trunk?format=rss`,
  CHANGESET: (slug, rev) => `/changeset/${encodeURIComponent(String(rev))}/${encodeURIComponent(slug)}?format=diff`,
  MAX_REVS_PER_SCAN: 10, // a runaway backfill is cut loudly — the n newest changesets per plugin per scan
  SVN_MAX_DIRS: 80,     // fallback: directory-index walk cap per tag (overflow = named gap, partial list kept)
  SVN_MAX_FILES: 400,   // fallback: .php files indexed per tag
  SVN_MAX_COMPARE: 25,  // fallback: common files content-compared pairwise per tag-pair (2 GETs each)
  SVN_MAX_DIFF_CELLS: 4000000, // fallback: LCS table cap — bigger files skip with a named gap
  TIMEOUT_MS: 20000,
};
export const ALLOWED_HOSTS = ['plugins.svn.wordpress.org', 'plugins.trac.wordpress.org'];
export const DOCTRINE = 'a fix commit is a map to a bug class, not a finding — leads are review-only; nothing is hunted, probed, or filed from here.';
const LEADS_CAP = 200; // the state ring keeps the newest 200 leads

// Persistence root: varvel/data/commitwatch (the bountyline/h1watch ROOT() discipline),
// evaluated at call time so tests isolate via VARVEL_COMMITWATCH_DIR.
const ROOT = () => process.env.VARVEL_COMMITWATCH_DIR || join(__dir, '..', 'data', 'commitwatch');
const STATE_FILE = () => join(ROOT(), 'state.json');
const TARGETS_FILE = () => join(ROOT(), 'targets.json');

// --- small persisted-store helpers (the store.mjs discipline: readJson fallback, write-through) ---
const readJson = (p, fb) => { try { return existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : fb; } catch { return fb; } };
const writeJson = (p, obj) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(obj, null, 2) + '\n'); };
const iso = (now) => (now === undefined ? new Date().toISOString() : (typeof now === 'number' ? new Date(now).toISOString() : String(now)));

// --- THE WATCH SET (data-driven — rule 4) ---------------------------------------------------
// loadTargets(file) -> { ok, targets: [{ slug, note? }], gaps } — documented shape:
//   [ "<slug>", … ]  or  [ { "slug": "…", "note": "…" }, … ]
// An unreadable/malformed file is a NAMED error — a scan with a guessed watch set is a
// fabricated scan; refuse it instead.
export function loadTargets(file) {
  const p = file || TARGETS_FILE();
  let raw;
  try { raw = JSON.parse(readFileSync(p, 'utf8')); }
  catch (e) { return { ok: false, error: 'unreadable-targets', reason: `cannot read/parse ${p}: ${(e && e.message) || e} — the watch set is data-driven; provide --targets <file> or restore ${p}`, gaps: [] }; }
  const list = Array.isArray(raw) ? raw : (raw && Array.isArray(raw.targets) ? raw.targets : null);
  if (!list) return { ok: false, error: 'unreadable-targets', reason: `${p} is not a slug array ({ "targets": [...] } or [...]) — the watch set was not guessed`, gaps: [] };
  const gaps = [];
  const targets = [];
  for (const t of list) {
    const slug = typeof t === 'string' ? t : (t && typeof t === 'object' ? t.slug : null);
    if (!slug || typeof slug !== 'string') { gaps.push('a targets entry carries no slug — skipped (never invented)'); continue; }
    targets.push({ slug, ...(t && typeof t === 'object' && t.note ? { note: String(t.note) } : {}) });
  }
  if (!targets.length) return { ok: false, error: 'unreadable-targets', reason: `${p} named ZERO usable slugs — an empty watch set watches nothing; not scanning`, gaps };
  return { ok: true, targets, file: p, gaps };
}

// --- the readers (pure; wp.org shapes -> ONE canonical form) ---------------------------------
// parseTrunkIndex(html) -> revision number | null. CONFIRMED shape 2026-08-25:
// <title> - Revision 3666159: /akismet/trunk</title>.
export function parseTrunkIndex(html, gaps = [], slug = '?') {
  const m = typeof html === 'string' && html.match(/Revision\s+(\d+)\s*:/);
  if (!m) { gaps.push(`${slug}: trunk index carried no "Revision <N>:" marker — the live shape may have moved; head revision NOT guessed`); return null; }
  return Number(m[1]);
}

// parseLogRss(xml) -> [rev, …] newest-first. RSS items link /changeset/<N>/<slug>;
// anything else lands EMPTY with a named gap.
export function parseLogRss(xml, gaps = [], slug = '?') {
  if (typeof xml !== 'string' || !xml) { gaps.push(`${slug}: empty changeset log response`); return []; }
  const revs = [...xml.matchAll(/\/changeset\/(\d+)\//g)].map((m) => Number(m[1]));
  const uniq = [...new Set(revs)];
  if (!uniq.length) gaps.push(`${slug}: changeset log carried no /changeset/<N>/ links — the live shape may have moved; revisions NOT guessed`);
  return uniq;
}

// parseStableTag(text) -> 'X.Y.Z' | null. The plugin's OWN release signal, read from
// trunk/readme.txt (or README.txt — case varies by plugin). No line = a named gap,
// never a guessed version.
export function parseStableTag(text, gaps = [], slug = '?') {
  if (typeof text !== 'string' || !text) { gaps.push(`${slug}: empty readme response — no stable-tag signal`); return null; }
  const m = text.match(/^\s*Stable tag:\s*([^\s]+)\s*$/mi);
  if (!m) { gaps.push(`${slug}: readme carried no "Stable tag:" line — the release signal is unreadable (named gap, never guessed)`); return null; }
  return m[1];
}

// --- the SVN fallback readers (trac 403 → mod_dav_svn HTML indexes) ----------------
// parseSvnIndex(html) -> { revision, dirs, files } | null. The index shape is the
// SAME one the trunk reader's CONFIRMED marker comes from: a "Revision <N>:" title
// plus <a href> entries (trailing '/' = directory). A page with neither is a moved
// shape — null with a named gap, never guessed.
export function parseSvnIndex(html, gaps = [], slug = '?') {
  if (typeof html !== 'string' || !html) { gaps.push(`${slug}: empty SVN index response`); return null; }
  const rm = html.match(/Revision\s+(\d+)\s*:/);
  const dirs = [];
  const files = [];
  for (const m of html.matchAll(/<a href="([^"?#]+)">/g)) {
    const name = decodeURIComponent(m[1]);
    if (name === '../' || name === '..') continue;
    if (name.endsWith('/')) dirs.push(name.slice(0, -1));
    else files.push(name);
  }
  if (!rm && !dirs.length && !files.length) { gaps.push(`${slug}: SVN index carried no "Revision <N>:" marker and no entries — the live shape may have moved; nothing guessed`); return null; }
  return { revision: rm ? Number(rm[1]) : null, dirs, files };
}

// Version-like tag directory names (1.2.3, 2.0-rc1) sorted newest-first, numeric
// segment by segment (1.10 > 1.9 — lexical order would lie).
export function sortTagsDesc(names) {
  const key = (s) => s.split(/[^0-9]+/).map((x) => (x === '' ? -1 : Number(x)));
  const cmp = (a, b) => {
    const ka = key(a); const kb = key(b);
    for (let i = 0; i < Math.max(ka.length, kb.length); i++) {
      const d = (kb[i] ?? -1) - (ka[i] ?? -1);
      if (d) return d;
    }
    return b.localeCompare(a);
  };
  return names.filter((n) => /^\d/.test(n)).sort(cmp);
}

// LCS line diff → op list [{ t:' '|'-'|'+', line }]. Capped — a huge file pair
// returns null and the caller names the gap instead of diffing.
export function lcsDiff(a, b) {
  const n = a.length; const m = b.length;
  if (n * m > WPORG.SVN_MAX_DIFF_CELLS) return null;
  const dp = new Uint32Array((n + 1) * (m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i * (m + 1) + j] = a[i] === b[j] ? dp[(i + 1) * (m + 1) + j + 1] + 1 : Math.max(dp[(i + 1) * (m + 1) + j], dp[i * (m + 1) + j + 1]);
    }
  }
  const ops = [];
  let i = 0; let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { ops.push({ t: ' ', line: a[i] }); i++; j++; }
    else if (dp[(i + 1) * (m + 1) + j] >= dp[i * (m + 1) + j + 1]) { ops.push({ t: '-', line: a[i] }); i++; }
    else { ops.push({ t: '+', line: b[j] }); j++; }
  }
  while (i < n) ops.push({ t: '-', line: a[i++] });
  while (j < m) ops.push({ t: '+', line: b[j++] });
  return ops;
}

// Ops → unified-diff text in the Index:/---/+++ shape the engine's parser reads
// (change regions with ≤3 context lines each side; long unchanged runs elided
// behind a @@ cut).
function opsToDiffText(ops, oldPath, newPath) {
  const lines = [];
  let i = 0;
  while (i < ops.length) {
    let j = i;
    while (j < ops.length && ops[j].t === ' ') j++;
    if (j >= ops.length) break;
    lines.push('@@');
    for (let k = Math.max(i, j - 3); k < j; k++) lines.push(' ' + ops[k].line);
    let last = j;
    while (last < ops.length) {
      if (ops[last].t === ' ') {
        let ahead = last;
        while (ahead < ops.length && ops[ahead].t === ' ' && ahead - last < 4) ahead++;
        if (ahead < ops.length && ops[ahead].t !== ' ') {
          for (let k = last; k < ahead; k++) lines.push(' ' + ops[k].line);
          last = ahead;
          continue;
        }
        for (let k = last; k < Math.min(ops.length, last + 3); k++) lines.push(' ' + ops[k].line);
        break;
      }
      lines.push(ops[last].t + ops[last].line);
      last++;
    }
    i = last;
  }
  return `Index: ${newPath}\n===================================================================\n--- ${oldPath}\n+++ ${newPath}\n${lines.join('\n')}\n`;
}

// svnTagDiff(slug, rev, { fromTag, toTag }): the 403-fallback changeset. With an
// explicit pair (the release-gated path — state's lastStableTag → the readme's new
// stable tag) the diff IS the exact version transition; without one it falls back to
// the two NEWEST tags and says so. Returns { ok, rev, message, diff } or a NAMED
// error; every impossible pair lands EMPTY with a named gap.
async function svnTagDiff(slug, rev, { fetchImpl, timeoutMs, fromTag = null, toTag = null }, gaps) {
  const empty = (reason) => { gaps.push(`${slug}: ${reason}`); return { ok: true, rev: Number(rev), message: `svn-fallback: no tag-pair delta (${reason})`, diff: '' }; };
  // 1. the plugin root index (confirms the plugin exists on wp.org SVN — a 404 here
  //    is the madara-core shape: expected, named, NOT a watcher failure).
  const root = await wpOrgGet({ url: WPORG.SVN_BASE + WPORG.SVN_PLUGIN(slug), fetchImpl, timeoutMs });
  if (!root.ok) return root;
  const rootIdx = parseSvnIndex(root.text, gaps, slug);
  if (!rootIdx) return { ok: false, error: 'wporg-bad-response', reason: `${slug}: plugin root index unparseable (gap recorded) — no tag data fabricated` };
  if (!rootIdx.dirs.includes('tags')) return empty('no tags/ directory in the plugin SVN root — nothing to diff (gap, not silence)');
  // 2. the tag list.
  const tagsRes = await wpOrgGet({ url: WPORG.SVN_BASE + WPORG.SVN_TAGS(slug), fetchImpl, timeoutMs });
  if (!tagsRes.ok) return tagsRes;
  const tagsIdx = parseSvnIndex(tagsRes.text, gaps, slug);
  if (!tagsIdx) return { ok: false, error: 'wporg-bad-response', reason: `${slug}: tags index unparseable (gap recorded) — no tag data fabricated` };
  let newTag; let prevTag;
  if (fromTag || toTag) {
    // The release-gated pair: exact version transition, never a guessed one.
    if (!fromTag || !toTag) return empty(`incomplete release pair (${fromTag || '?'} → ${toTag || '?'}) — both ends are required`);
    if (toTag === 'trunk' || fromTag === 'trunk') return empty(`stable tag is 'trunk' — no immutable release snapshot to diff against (gap, not silence)`);
    if (!tagsIdx.dirs.includes(fromTag)) return empty(`previous stable tag ${fromTag} has no directory in /tags/ (deleted or renamed) — the release pair cannot be formed (named gap)`);
    if (!tagsIdx.dirs.includes(toTag)) return empty(`new stable tag ${toTag} has no directory in /tags/ yet (readme moved, the tag did not) — the release pair cannot be formed (named gap)`);
    prevTag = fromTag;
    newTag = toTag;
  } else {
    const tags = sortTagsDesc(tagsIdx.dirs);
    if (tags.length < 2) return empty(`only ${tags.length} tag(s) present — a tag-PAIR is required for the fallback diff; per-commit granularity stays unavailable`);
    [newTag, prevTag] = tags;
  }
  // 3. enumerate .php files under each tag (bounded recursive index walk). Keys are
  //    TAG-RELATIVE paths — the tag prefixes differ by construction, so prefix-keyed
  //    maps would pair NOTHING as common and every unchanged file would read as
  //    "added" (the AIOSEO byte-identical false-positive, 2026-08-26).
  const walk = async (tag) => {
    const files = new Map(); // tag-RELATIVE path -> url
    const tagRoot = `${slug}/tags/${tag}/`;
    const queue = [tagRoot];
    let dirs = 0;
    while (queue.length) {
      if (dirs >= WPORG.SVN_MAX_DIRS) { gaps.push(`${slug}: tag ${tag} directory walk hit the ${WPORG.SVN_MAX_DIRS}-dir cap — the file list is PARTIAL (named, never padded)`); break; }
      const dir = queue.shift();
      dirs++;
      const r = await wpOrgGet({ url: `${WPORG.SVN_BASE}/${dir.split('/').map(encodeURIComponent).join('/')}`, fetchImpl, timeoutMs });
      if (!r.ok) { gaps.push(`${slug}: index GET /${dir} failed (${r.error}) — subtree skipped`); continue; }
      const idx = parseSvnIndex(r.text, gaps, slug);
      if (!idx) continue;
      for (const d of idx.dirs) queue.push(`${dir}${d}/`);
      for (const f of idx.files) {
        if (!/\.php$/i.test(f)) continue;
        if (files.size >= WPORG.SVN_MAX_FILES) { gaps.push(`${slug}: tag ${tag} file walk hit the ${WPORG.SVN_MAX_FILES}-file cap — the file list is PARTIAL (named, never padded)`); break; }
        files.set(`${dir.slice(tagRoot.length)}${f}`, `${WPORG.SVN_BASE}/${dir.split('/').map(encodeURIComponent).join('/')}${encodeURIComponent(f)}`);
      }
    }
    return files;
  };
  const [newFiles, oldFiles] = await Promise.all([walk(newTag), walk(prevTag)]);
  // 4. added/removed paths are certain; common files are content-compared pairwise
  //    (capped) and LCS-diffed — the synthesized changeset never claims more.
  const chunks = [];
  const rel = (p) => p; // keys are tag-relative already (kept for the gap messages)
  let compared = 0;
  const commons = [...newFiles.keys()].filter((p) => oldFiles.has(p));
  for (const p of commons) {
    if (compared >= WPORG.SVN_MAX_COMPARE) { gaps.push(`${slug}: common-file content comparison capped at ${WPORG.SVN_MAX_COMPARE} of ${commons.length} — the remaining files may hide unexamined changes (named, not hidden)`); break; }
    compared++;
    const [a, b] = await Promise.all([
      wpOrgGet({ url: oldFiles.get(p), fetchImpl, timeoutMs }),
      wpOrgGet({ url: newFiles.get(p), fetchImpl, timeoutMs }),
    ]);
    if (!a.ok || !b.ok) { gaps.push(`${slug}: content GET for ${rel(p)} failed — file skipped`); continue; }
    if (a.text === b.text) continue;
    const ops = lcsDiff(a.text.replace(/\r\n?/g, '\n').split('\n'), b.text.replace(/\r\n?/g, '\n').split('\n'));
    if (!ops) { gaps.push(`${slug}: ${rel(p)} exceeds the LCS size cap — the change is REAL but its diff is unemitted (fetch the two tags by hand)`); continue; }
    chunks.push(opsToDiffText(ops, p, p));
  }
  // Added/removed whole files (all lines +/-), after the common-file chunks.
  for (const p of newFiles.keys()) {
    if (oldFiles.has(p)) continue;
    const r = await wpOrgGet({ url: newFiles.get(p), fetchImpl, timeoutMs });
    if (!r.ok) { gaps.push(`${slug}: added file ${rel(p)} unreadable — path listed, content skipped`); continue; }
    chunks.push(opsToDiffText(r.text.replace(/\r\n?/g, '\n').split('\n').map((line) => ({ t: '+', line })), p, p));
  }
  for (const p of oldFiles.keys()) {
    if (newFiles.has(p)) continue;
    const r = await wpOrgGet({ url: oldFiles.get(p), fetchImpl, timeoutMs });
    if (!r.ok) { gaps.push(`${slug}: removed file ${rel(p)} unreadable — path listed, content skipped`); continue; }
    chunks.push(opsToDiffText(r.text.replace(/\r\n?/g, '\n').split('\n').map((line) => ({ t: '-', line })), p, p));
  }
  return {
    ok: true,
    rev: Number(rev),
    message: `svn-fallback: tag-to-tag diff ${prevTag} → ${newTag} (trac answered 403 — RELEASE-PAIR delta; per-commit granularity unavailable; ${commons.length ? `${compared}/${commons.length} common files content-compared` : 'no common files'})`,
    diff: chunks.join(''),
  };
}

// --- the sources -----------------------------------------------------------------------------
// wpOrgGet: the THIN client layer — one read-only GET against an ALLOWED wordpress.org
// host (the allowlist is enforced HERE, in code — not doctrine), every failure mapped to
// a named error. Text in, text out: the readers own all parsing.
export async function wpOrgGet({ url, fetchImpl = fetch, timeoutMs = WPORG.TIMEOUT_MS }) {
  let host;
  try { host = new URL(url).hostname; } catch { return { ok: false, error: 'commitwatch-host-not-allowed', reason: `'${url}' is not a URL — refused before any request` }; }
  if (!ALLOWED_HOSTS.includes(host)) {
    return { ok: false, error: 'commitwatch-host-not-allowed', reason: `refused to GET ${url} — the watcher touches wordpress.org hosts ONLY (${ALLOWED_HOSTS.join(', ')}); no request was sent` };
  }
  let res;
  try {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), timeoutMs);
    try { res = await fetchImpl(url, { headers: { accept: 'text/html,application/rss+xml,text/plain,*/*', 'user-agent': 'VARVEL-commitwatch/1.0 (read-only security research; wordpress.org public SVN)' }, signal: ac.signal }); }
    finally { clearTimeout(t); }
  } catch (e) {
    return { ok: false, error: 'wporg-unreachable', reason: `GET ${url} failed (${(e && e.message) || e}) — wordpress.org is unreachable; no revision data was fabricated` };
  }
  if (res.status === 429) return { ok: false, error: 'wporg-rate-limited', status: 429, reason: `GET ${url} answered 429 — rate limited; back off and re-scan later` };
  if (!res.ok) return { ok: false, error: 'wporg-http-error', status: res.status, reason: `GET ${url} answered HTTP ${res.status} — no revision data was fabricated` };
  try { return { ok: true, status: res.status, text: await res.text() }; }
  catch (e) { return { ok: false, error: 'wporg-bad-response', status: res.status, reason: `GET ${url}'s body could not be read (${(e && e.message) || e}) — no revision data was fabricated` }; }
}

// liveSource: the real client — GATED (rule 2). Without allow:true the source refuses
// BEFORE any request is built: live scans are operator-deliberate, never ambient.
// headRevision(slug) / logRevisions(slug) / changeset(slug, rev) — the same canonical
// forms fixtureSource produces.
export function liveSource({ allow = false, fetchImpl = fetch, timeoutMs = WPORG.TIMEOUT_MS } = {}) {
  if (!allow) {
    return { ok: false, error: 'commitwatch-live-not-requested', reason: 'the live path is gated: pass --live (CLI) or liveSource({ allow: true }) to scan wordpress.org — offline runs use --fixture <file> with the SAME code path' };
  }
  const gaps = [
    `wp.org shapes: trunk index CONFIRMED live 2026-08-25 (Revision marker in the SVN HTML index); changeset RSS/diff are best-known Trac conventions — if the live shape disagrees, readers land EMPTY with a named gap, never guessed`,
    `SVN fallback armed: a trac 403 (only a 403) switches this source to tag-to-tag diffs over plugins.svn.wordpress.org — release-pair granularity, named in the changeset message; every other failure stays a named error`,
  ];
  // Instance state: set on the FIRST trac 403 so the rest of the scan stops
  // hammering trac — polite AND fast; every subsequent call goes straight to SVN.
  const state = { tracBlocked: false };
  return {
    ok: true,
    gaps,
    headRevision: async (slug) => {
      const r = await wpOrgGet({ url: WPORG.SVN_BASE + WPORG.SVN_TRUNK(slug), fetchImpl, timeoutMs });
      if (!r.ok) return r;
      const rev = parseTrunkIndex(r.text, gaps, slug);
      return rev === null ? { ok: false, error: 'wporg-bad-response', reason: `${slug}: trunk index parsed to no revision (gap recorded)` } : { ok: true, revision: rev };
    },
    logRevisions: async (slug) => {
      if (!state.tracBlocked) {
        const r = await wpOrgGet({ url: WPORG.TRAC_BASE + WPORG.LOG_RSS(slug), fetchImpl, timeoutMs });
        if (r.ok) return { ok: true, revisions: parseLogRss(r.text, gaps, slug) };
        if (r.status !== 403) return r; // ONLY a 403 falls back — every other failure stays a named error
        state.tracBlocked = true;
        gaps.push(`${slug}: trac log answered HTTP 403 — SVN tag-to-tag fallback ACTIVE for the rest of this scan (release-pair granularity; per-commit changesets unavailable)`);
      }
      return { ok: true, revisions: [], svnFallback: true };
    },
    changeset: async (slug, rev, hint = null) => {
      if (!state.tracBlocked) {
        const r = await wpOrgGet({ url: WPORG.TRAC_BASE + WPORG.CHANGESET(slug, rev), fetchImpl, timeoutMs });
        if (r.ok) {
          const m = r.text.match(/^#\d+:\s*(.+)$/m) || r.text.match(/<title>([^<]+)<\/title>/);
          return { ok: true, rev: Number(rev), message: m ? m[1].trim().slice(0, 300) : '', diff: r.text };
        }
        if (r.status !== 403) return r; // ONLY a 403 falls back
        state.tracBlocked = true;
        gaps.push(`${slug}: trac changeset answered HTTP 403 — SVN tag-to-tag fallback ACTIVE for the rest of this scan (release-pair granularity; per-commit changesets unavailable)`);
      }
      return svnTagDiff(slug, rev, { fetchImpl, timeoutMs, ...(hint || {}) }, gaps);
    },
    // The plugin's OWN release signal (the fallback's ONLY trigger): trunk
    // readme.txt's "Stable tag:" — readme.txt first, README.txt on a 404 (case
    // varies by plugin); both missing / no line = a NAMED failure, never guessed.
    stableTag: async (slug) => {
      for (const name of ['readme.txt', 'README.txt']) {
        const r = await wpOrgGet({ url: WPORG.SVN_BASE + WPORG.SVN_TRUNK(slug) + name, fetchImpl, timeoutMs });
        if (!r.ok) {
          if (r.status === 404) continue; // try the other case
          return r; // 403/429/unreachable are real named errors, not a missing readme
        }
        const tag = parseStableTag(r.text, gaps, slug);
        return tag
          ? { ok: true, tag, file: `trunk/${name}` }
          : { ok: false, error: 'wporg-bad-response', reason: `${slug}: trunk/${name} carries no "Stable tag:" line (gap recorded) — release gating impossible` };
      }
      return { ok: false, error: 'wporg-http-error', status: 404, reason: `${slug}: neither trunk/readme.txt nor trunk/README.txt exists (404) — release gating impossible (named gap, never guessed)` };
    },
  };
}

// fixtureSource: a recorded wp.org snapshot through the SAME readers as the live client.
// Documented fixture shape:
//   { "plugins": { "<slug>": { "head": <rev>,
//        "changesets": [ { "rev": <n>, "message": "…", "diff": "<unified diff text>" } ] } } }
export function fixtureSource(file) {
  let fx;
  try { fx = JSON.parse(readFileSync(file, 'utf8')); }
  catch (e) { return { ok: false, error: 'unreadable-fixture', reason: `cannot read/parse ${file}: ${(e && e.message) || e}` }; }
  const gaps = [`fixture source: ${file} — a recorded wp.org snapshot, parsed through the SAME trunk/log/changeset readers as the live client`];
  const plug = (slug) => (fx.plugins && fx.plugins[slug]) || null;
  return {
    ok: true,
    gaps,
    headRevision: async (slug) => {
      const p = plug(slug);
      if (!p || typeof p.head !== 'number') return { ok: false, error: 'wporg-http-error', status: 404, reason: `fixture has no plugin '${slug}' (or no head revision)` };
      return { ok: true, revision: p.head };
    },
    logRevisions: async (slug) => {
      const p = plug(slug);
      if (!p) return { ok: false, error: 'wporg-http-error', status: 404, reason: `fixture has no plugin '${slug}'` };
      return { ok: true, revisions: (p.changesets || []).map((c) => c.rev).filter((n) => typeof n === 'number').sort((a, b) => b - a) };
    },
    changeset: async (slug, rev) => {
      const p = plug(slug);
      const cs = p && (p.changesets || []).find((c) => c.rev === Number(rev));
      if (!cs) return { ok: false, error: 'wporg-http-error', status: 404, reason: `fixture has no changeset ${slug}@${rev}` };
      return { ok: true, rev: Number(rev), message: cs.message || '', diff: cs.diff || '' };
    },
    stableTag: async (slug) => {
      const p = plug(slug);
      if (!p || typeof p.stable !== 'string') return { ok: false, error: 'wporg-http-error', status: 404, reason: `fixture has no stable tag for '${slug}'` };
      return { ok: true, tag: p.stable, file: 'fixture' };
    },
  };
}

// --- state -----------------------------------------------------------------------------------
export function loadState() {
  const st = readJson(STATE_FILE(), null);
  return st && typeof st === 'object' && st.plugins ? st : { plugins: {}, leads: [], lastScan: null };
}

function saveState(st) {
  writeJson(STATE_FILE(), st);
}

// --- THE SCAN ---------------------------------------------------------------------------------
// scan({ source, targetsFile, now }) — for each watched slug: read the head revision;
// if it moved past lastSeenRev, pull the newest changesets (cap MAX_REVS_PER_SCAN), parse
// each diff, classify, and record leads. Per-plugin fetch failures are recorded and the
// plugin's previous state is KEPT (rule 3). The state file is written on every
// successful scan (write-through). Leads are REVIEW-ONLY — the scan never hunts them.
export async function scan({ source, targetsFile, now } = {}) {
  if (!source || source.ok !== true) {
    return { ok: false, error: (source && source.error) || 'no-source', reason: (source && source.reason) || 'scan needs a source (fixtureSource or liveSource)', gaps: (source && source.gaps) || [], doctrine: DOCTRINE };
  }
  const tt = loadTargets(targetsFile);
  if (!tt.ok) return { ok: false, error: tt.error, reason: tt.reason, gaps: [...(source.gaps || []), ...tt.gaps], doctrine: DOCTRINE };
  const st = loadState();
  const gaps = [...(source.gaps || []), ...tt.gaps];
  const at = iso(now);
  const leads = []; const errors = []; const scanned = []; let noise = 0;
  for (const t of tt.targets) {
    const slug = t.slug;
    const old = st.plugins[slug] || null;
    let head;
    try { head = await source.headRevision(slug); }
    catch (e) { head = { ok: false, error: 'wporg-unreachable', reason: `headRevision(${slug}) threw: ${(e && e.message) || e}` }; }
    if (!head.ok) { errors.push({ slug, error: head.error, reason: head.reason }); continue; }
    const lastSeen = old && typeof old.lastSeenRev === 'number' ? old.lastSeenRev : null;
    const revs = [];
    const revHints = new Map(); // rev -> { fromTag, toTag } (the release-gated pair)
    let stableForState = old && typeof old.lastStableTag === 'string' ? old.lastStableTag : undefined;
    let stablePending = null; // a new stable tag whose diff has not LANDED yet
    const readStable = async () => {
      if (typeof source.stableTag !== 'function') return { ok: false, reason: 'source has no stable-tag reader' };
      try { return await source.stableTag(slug); }
      catch (e) { return { ok: false, reason: `stableTag(${slug}) threw: ${(e && e.message) || e}` }; }
    };
    if (lastSeen === null) {
      // First sight: record the head ONLY — backfilling history on first scan would
      // misread old fixes as fresh; the watcher hunts FORWARD from first sight.
      gaps.push(`${slug}: first sight at r${head.revision} — baseline recorded, history NOT backfilled (old fixes are not fresh leads)`);
      // Baseline the release signal too, or the first post-fix bump could not diff.
      const stag = await readStable();
      if (stag.ok) stableForState = stag.tag;
    } else if (head.revision > lastSeen) {
      let log;
      try { log = await source.logRevisions(slug); }
      catch (e) { log = { ok: false, error: 'wporg-unreachable', reason: `logRevisions(${slug}) threw: ${(e && e.message) || e}` }; }
      if (!log.ok) { errors.push({ slug, error: log.error, reason: log.reason }); continue; }
      if (log.svnFallback) {
        // RELEASE-GATED fallback (2026-08-26): plugins.svn is ONE repo with a GLOBAL
        // revision counter — HEAD alone NEVER triggers a diff (it fired on all 17
        // targets in one scan). The plugin's own readme "Stable tag:" must have
        // CHANGED vs state. HEAD stays a liveness check only.
        const stag = await readStable();
        if (!stag.ok) {
          gaps.push(`${slug}: ${stag.reason || stag.error} — release gating unavailable, diff skipped (named gap, never guessed)`);
        } else if (stableForState === undefined) {
          // First run with gating (pre-fix state has no lastStableTag): baseline
          // SILENTLY — no diff, exactly the first-seen-revision doctrine.
          gaps.push(`${slug}: stable tag baselined at ${stag.tag} (first run with release gating — NO diff, same doctrine as first-seen revision)`);
          stableForState = stag.tag;
        } else if (stableForState !== stag.tag) {
          revs.push(head.revision);
          revHints.set(head.revision, { fromTag: stableForState, toTag: stag.tag });
          stablePending = stag.tag; // advances ONLY when the changeset lands
        } else {
          gaps.push(`${slug}: global HEAD moved r${lastSeen} -> r${head.revision} but stable tag unchanged (${stag.tag}) — repo-global revision is not a plugin release signal; no diff`);
        }
      } else {
        const fresh = log.revisions.filter((r) => r > lastSeen && r <= head.revision).sort((a, b) => a - b);
        if (!fresh.length) gaps.push(`${slug}: head moved r${lastSeen} -> r${head.revision} but the log named no new changesets — the revision advanced with no enumerable diff (gap, not silence)`);
        revs.push(...fresh.slice(-WPORG.MAX_REVS_PER_SCAN));
        if (fresh.length > WPORG.MAX_REVS_PER_SCAN) gaps.push(`${slug}: ${fresh.length} new changesets exceeds the ${WPORG.MAX_REVS_PER_SCAN}-per-scan cap — the OLDEST ${fresh.length - WPORG.MAX_REVS_PER_SCAN} were skipped this scan (backfill deliberately)`);
      }
    }
    for (const rev of revs) {
      let cs;
      try { cs = await source.changeset(slug, rev, revHints.get(rev) || null); }
      catch (e) { cs = { ok: false, error: 'wporg-unreachable', reason: `changeset(${slug}, ${rev}) threw: ${(e && e.message) || e}` }; }
      if (!cs.ok) { errors.push({ slug, error: cs.error, reason: cs.reason }); continue; }
      if (stablePending) stableForState = stablePending; // the release-pair diff LANDED — advance the release baseline
      const fileDiffs = parseChangesetDiff(cs.diff);
      const lead = buildLead({ slug, revision: rev, message: cs.message, fileDiffs, at });
      if (lead) leads.push(lead);
      else noise++;
    }
    st.plugins[slug] = {
      slug,
      ...(t.note ? { note: t.note } : {}),
      lastSeenRev: head.revision,
      ...(stableForState !== undefined ? { lastStableTag: stableForState } : {}),
      firstSeen: old ? old.firstSeen : at,
      lastChanged: leads.some((l) => l.slug === slug) || revs.length ? at : (old ? old.lastChanged : at),
      lastScan: at,
    };
    scanned.push(slug);
  }
  st.leads = [...(st.leads || []), ...leads].slice(-LEADS_CAP);
  st.lastScan = { at, watched: tt.targets.length, scanned: scanned.length, changesets: leads.length + noise, leads: leads.length, noise, errors };
  saveState(st);
  return { ok: true, at, watched: tt.targets.length, scanned: scanned.length, changesets: leads.length + noise, noise, leads, ranked: rankLeads(leads), errors, gaps, targetsFile: tt.file, stateFile: STATE_FILE(), doctrine: DOCTRINE };
}

// --- report / show ----------------------------------------------------------------------------
// report({ all }) — the ranked lead list FROM STATE: default the most recent scan's
// leads; --all the whole ring (newest LEADS_CAP).
export function report({ all = false } = {}) {
  const st = loadState();
  const ls = all ? (st.leads || []) : (st.leads || []).filter((l) => st.lastScan && l.at === st.lastScan.at);
  return {
    ok: true,
    at: st.lastScan ? st.lastScan.at : null,
    watched: Object.keys(st.plugins).length,
    leads: rankLeads(ls),
    ...(st.lastScan ? {} : { note: 'no scan on record — run: commitwatch scan --fixture <file> (offline) | commitwatch scan --live (gated, wordpress.org only)' }),
    doctrine: DOCTRINE,
  };
}

export function show(slug) {
  const st = loadState();
  const rec = st.plugins[String(slug || '')];
  if (!rec) return { ok: false, error: 'unknown-plugin', reason: `no plugin '${slug}' in the commitwatch state — run: commitwatch scan [--fixture <file> | --live]`, doctrine: DOCTRINE };
  return { ok: true, plugin: rec, leads: rankLeads((st.leads || []).filter((l) => l.slug === rec.slug)), doctrine: DOCTRINE };
}
