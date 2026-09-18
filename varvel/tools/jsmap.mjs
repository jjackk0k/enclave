// VARVEL — jsmap tool wrapper: fs-walk a local Node/JS source tree into
// engine/jsmap.mjs and return the ranked impact-primitive report.
//
// HOUSE CONTRACT (same as tools/privemap.mjs): tools touch fs but NEVER throw.
// Unreadable dirs, unreadable/oversized/binary files are reported in skipped[] with
// reasons — a partial map with honest gaps beats an exception that loses the whole
// scan. The engine stays pure; all I/O is here.
//
//   import { jsmap } from './jsmap.mjs';
//   const report = jsmap('C:/path/to/node-app');
//   // → { root, candidates, scannedFiles, skipped, gaps, stats }

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { mineJs } from '../engine/jsmap.mjs';

const DEFAULT_MAX_FILE_BYTES = 768 * 1024; // JS runs bigger than plugin PHP; beyond that is bundle/minified junk
const DEFAULT_MAX_FILES = 20000;           // hard cap so a wrongly-pointed root stays bounded
const SOURCE_RE = /\.(?:js|mjs|cjs|jsx|ts|tsx)$/i;
// Dependency/build trees are not the app's own source — mining them ranks OTHER
// people's code. Excluded by default (includeDirs can re-admit for a targeted look).
const DEFAULT_EXCLUDE_DIRS = new Set(['node_modules', '.git', '.hg', '.svn']);

export function jsmap(root, { maxFileBytes = DEFAULT_MAX_FILE_BYTES, maxFiles = DEFAULT_MAX_FILES, excludeDirs = DEFAULT_EXCLUDE_DIRS } = {}) {
  const skipped = [];
  const records = [];
  let scannedFiles = 0;
  const rootStr = String(root || '');

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
        if (ent.isDirectory()) {
          if (excludeDirs && excludeDirs.has(ent.name)) continue;
          walk(p);
          continue;
        }
        if (!ent.isFile()) continue; // symlinks/junctions not followed (loop-safe by construction)
        if (!SOURCE_RE.test(ent.name)) continue;
        const st = statSync(p);
        if (st.size > maxFileBytes) { skip(p, `oversized (${st.size}B > ${maxFileBytes}B)`); continue; }
        if (st.size === 0) continue; // empty: nothing to mine, not worth a skipped row
        const content = readFileSync(p, 'utf8');
        if (content.includes(String.fromCharCode(0))) { skip(p, 'binary (NUL bytes) — not JS source'); continue; }
        records.push({ path: p, content });
        scannedFiles++;
      } catch (e) {
        skip(p, 'unreadable: ' + ((e && e.code) || (e && e.message) || e));
      }
    }
  }

  try {
    const st = statSync(rootStr);
    if (!st.isDirectory()) skip(rootStr, 'not a directory');
    else walk(rootStr);
  } catch (e) {
    skip(rootStr, 'root unreadable: ' + ((e && e.code) || (e && e.message) || e));
  }

  let mined;
  try {
    mined = mineJs(records);
  } catch (e) {
    // Engine is pure and tested against garbage; if it ever does throw, the tool's
    // contract still holds — report the failure as a gap, not a crash.
    return { root: rootStr, candidates: [], scannedFiles, skipped, gaps: [{ ref: rootStr, reason: 'miner failed: ' + ((e && e.message) || e) }], stats: { functions: 0, routes: 0, unresolvedHandlers: 0 } };
  }

  // Root-relative refs: the report stays portable when the tree moves between machines.
  const rootNorm = rootStr.replace(/\\/g, '/').replace(/\/?$/, '/');
  const candidates = mined.candidates.map((c) => ({
    ...c,
    ref: c.ref.replace(/\\/g, '/').startsWith(rootNorm) ? c.ref.replace(/\\/g, '/').slice(rootNorm.length) : c.ref,
  }));

  return { root: rootStr, candidates, scannedFiles, skipped, gaps: mined.gaps, stats: mined.stats };
}
