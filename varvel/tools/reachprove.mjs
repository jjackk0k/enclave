// VARVEL — reachprove tool wrapper: fs-walk a local PHP source tree into
// engine/reachability.mjs and return the mechanical reachability verdicts (and,
// in rescore mode, the rescored privemap report).
//
// HOUSE CONTRACT: tools touch fs but NEVER throw. Unreadable dirs, unreadable/
// oversized/binary files are reported in skipped[] with reasons — a partial model
// with honest gaps beats an exception that loses the whole scan. The engine stays
// pure; all I/O is here.
//
//   import { reachprove, reachproveRescore } from './reachprove.mjs';
//   const report = reachprove('C:/path/to/plugin');
//   // → { root, entries, scannedFiles, skipped, gaps, stats }
//   const rescored = reachproveRescore('C:/path/to/plugin', privemapReportObject);
//   // → { root, results, summary, scannedFiles, skipped, gaps, stats }

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { buildReachabilityModel, analyzeAll, analyzeRegistration, findEntries, rescoreCandidates } from '../engine/reachability.mjs';

const DEFAULT_MAX_FILE_BYTES = 512 * 1024; // PHP sources are small; bigger = generated/minified junk
const DEFAULT_MAX_FILES = 20000;           // hard cap so a wrongly-pointed root stays bounded

// The same walk as tools/privemap.mjs — kept in lock-step deliberately: the model
// must see exactly the files the miner saw, or rescore verdicts drift from the
// report they adjudicate.
function collectPhpRecords(root, { maxFileBytes, maxFiles, skipped }) {
  const records = [];
  const skip = (path, reason) => { if (skipped.length < 200) skipped.push({ path, reason }); };
  function walk(dir) {
    if (records.length >= maxFiles) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      skip(dir, 'dir unreadable: ' + ((e && e.code) || (e && e.message) || e));
      return;
    }
    for (const ent of entries) {
      if (records.length >= maxFiles) { skip(dir, `file cap ${maxFiles} reached — subtree truncated`); return; }
      const p = join(dir, ent.name);
      try {
        if (ent.isDirectory()) { walk(p); continue; }
        if (!ent.isFile()) continue; // symlinks/junctions not followed (loop-safe)
        if (!/\.php$/i.test(ent.name)) continue;
        const st = statSync(p);
        if (st.size > maxFileBytes) { skip(p, `oversized (${st.size}B > ${maxFileBytes}B)`); continue; }
        if (st.size === 0) continue;
        const content = readFileSync(p, 'utf8');
        if (content.includes(String.fromCharCode(0))) { skip(p, 'binary (NUL bytes) — not PHP source'); continue; }
        records.push({ path: p, content });
      } catch (e) {
        skip(p, 'unreadable: ' + ((e && e.code) || (e && e.message) || e));
      }
    }
  }
  try {
    const st = statSync(String(root || ''));
    if (!st.isDirectory()) skip(root, 'not a directory');
    else walk(root);
  } catch (e) {
    skip(root, 'root unreadable: ' + ((e && e.code) || (e && e.message) || e));
  }
  return records;
}

function build(root, opts) {
  const skipped = [];
  const records = collectPhpRecords(root, { ...opts, skipped });
  let model;
  try {
    model = buildReachabilityModel(records);
  } catch (e) {
    // Engine is pure and tested against garbage; if it ever throws, the tool's
    // contract still holds — report the failure as a gap, not a crash.
    return { model: null, scannedFiles: records.length, skipped, gaps: [{ ref: String(root), reason: 'model build failed: ' + ((e && e.message) || e) }] };
  }
  return { model, scannedFiles: records.length, skipped, gaps: model.gaps };
}

// Root-relative refs: the report stays portable when the tree moves between machines.
function relativize(rootStr, obj) {
  const rootNorm = String(rootStr || '').replace(/\\/g, '/').replace(/\/?$/, '/');
  const rel = (ref) => (typeof ref === 'string' && ref.replace(/\\/g, '/').startsWith(rootNorm) ? ref.replace(/\\/g, '/').slice(rootNorm.length) : ref);
  return JSON.parse(JSON.stringify(obj, (k, v) => (k === 'ref' || k === 'registration' ? rel(v) : v)));
}

// Full-tree analysis: one verdict per registration found.
export function reachprove(root, { maxFileBytes = DEFAULT_MAX_FILE_BYTES, maxFiles = DEFAULT_MAX_FILES } = {}) {
  const b = build(root, { maxFileBytes, maxFiles });
  if (!b.model) return { root: String(root || ''), entries: [], scannedFiles: b.scannedFiles, skipped: b.skipped, gaps: b.gaps, stats: { functions: 0, registrations: 0, cronHooks: 0 } };
  const entries = analyzeAll(b.model);
  return relativize(root, { root: String(root || ''), entries, scannedFiles: b.scannedFiles, skipped: b.skipped, gaps: b.gaps, stats: b.model.stats });
}

// Single-entry analysis (--entry <file:line|hook>).
export function reachproveEntry(root, spec, { maxFileBytes = DEFAULT_MAX_FILE_BYTES, maxFiles = DEFAULT_MAX_FILES } = {}) {
  const b = build(root, { maxFileBytes, maxFiles });
  if (!b.model) return { root: String(root || ''), entries: [], scannedFiles: b.scannedFiles, skipped: b.skipped, gaps: b.gaps, stats: { functions: 0, registrations: 0, cronHooks: 0 } };
  const regs = findEntries(b.model, spec);
  if (!regs.length) {
    return relativize(root, {
      root: String(root || ''), entries: [], scannedFiles: b.scannedFiles, skipped: b.skipped, gaps: b.gaps, stats: b.model.stats,
      notFound: `no registration matches '${spec}' (file:line of a registration, a hook name, a REST route, or an ability name) — UNCERTAIN by default, never guessed`,
    });
  }
  const entries = regs.map((reg) => analyzeRegistration(b.model, reg));
  return relativize(root, { root: String(root || ''), entries, scannedFiles: b.scannedFiles, skipped: b.skipped, gaps: b.gaps, stats: b.model.stats });
}

// Rescore mode: a privemap report object (already parsed — file/stdin reading lives
// in the CLI layer) re-adjudicated against the model built from the SAME tree.
export function reachproveRescore(root, report, { maxFileBytes = DEFAULT_MAX_FILE_BYTES, maxFiles = DEFAULT_MAX_FILES } = {}) {
  const b = build(root, { maxFileBytes, maxFiles });
  if (!b.model) return { root: String(root || ''), results: [], summary: { CONFIRMED: 0, DEGRADED: 0, KILLED: 0, UNCERTAIN: 0 }, scannedFiles: b.scannedFiles, skipped: b.skipped, gaps: b.gaps, stats: { functions: 0, registrations: 0, cronHooks: 0 } };
  const candidates = report && Array.isArray(report.candidates) ? report.candidates : [];
  const { results, summary } = rescoreCandidates(b.model, candidates);
  return relativize(root, {
    root: String(root || ''), results, summary,
    privemapRoot: report && report.root ? report.root : undefined,
    scannedFiles: b.scannedFiles, skipped: b.skipped, gaps: b.gaps, stats: b.model.stats,
  });
}
