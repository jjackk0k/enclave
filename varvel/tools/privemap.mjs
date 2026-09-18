// VARVEL — privemap tool wrapper: fs-walk a local PHP source tree into
// engine/privemap.mjs and return the ranked privesc/impact-primitive report.
//
// HOUSE CONTRACT: tools touch fs but NEVER throw. Unreadable dirs, unreadable/oversized/
// binary files are reported in skipped[] with reasons — a partial map with honest gaps
// beats an exception that loses the whole scan. The engine stays pure; all I/O is here.
//
//   import { privemap } from './privemap.mjs';
//   const report = privemap('C:/path/to/wp-content/plugins/some-plugin');
//   // → { root, candidates, scannedFiles, skipped, gaps, stats }

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { minePrivesc } from '../engine/privemap.mjs';

const DEFAULT_MAX_FILE_BYTES = 512 * 1024; // PHP sources are small; bigger = generated/minified junk
const DEFAULT_MAX_FILES = 20000;           // hard cap so a wrongly-pointed root (e.g. C:\) stays bounded

export function privemap(root, { maxFileBytes = DEFAULT_MAX_FILE_BYTES, maxFiles = DEFAULT_MAX_FILES } = {}) {
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
        if (ent.isDirectory()) { walk(p); continue; }
        if (!ent.isFile()) continue; // symlinks/junctions not followed (loop-safe by construction)
        if (!/\.php$/i.test(ent.name)) continue;
        const st = statSync(p);
        if (st.size > maxFileBytes) { skip(p, `oversized (${st.size}B > ${maxFileBytes}B)`); continue; }
        if (st.size === 0) continue; // empty: nothing to mine, not worth a skipped row
        const content = readFileSync(p, 'utf8');
        if (content.includes(String.fromCharCode(0))) { skip(p, 'binary (NUL bytes) — not PHP source'); continue; }
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
    mined = minePrivesc(records);
  } catch (e) {
    // Engine is pure and tested against garbage; if it ever does throw, the tool's
    // contract still holds — report the failure as a gap, not a crash.
    return { root: rootStr, candidates: [], scannedFiles, skipped, gaps: [{ ref: rootStr, reason: 'miner failed: ' + ((e && e.message) || e) }], stats: { functions: 0, registrations: 0, unresolvedCallbacks: 0 } };
  }

  // Root-relative refs: the report stays portable when the tree moves between machines.
  const rootNorm = rootStr.replace(/\\/g, '/').replace(/\/?$/, '/');
  const candidates = mined.candidates.map((c) => ({
    ...c,
    ref: c.ref.replace(/\\/g, '/').startsWith(rootNorm) ? c.ref.replace(/\\/g, '/').slice(rootNorm.length) : c.ref,
  }));

  return { root: rootStr, candidates, scannedFiles, skipped, gaps: mined.gaps, stats: mined.stats };
}
