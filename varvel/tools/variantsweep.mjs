// VARVEL — variantsweep tool wrapper: fs-walk a local WordPress corpus into
// engine/variantsweep.mjs and return the ranked same-shape hit list for one signature.
//
// HOUSE CONTRACT: tools touch fs but NEVER throw. Unreadable dirs, unreadable/oversized/
// binary files are reported in skipped[] with reasons; a bad signature lands in errors[]
// — a partial sweep with honest gaps beats an exception that loses the whole scan.
//
//   import { variantsweep } from './variantsweep.mjs';
//   const report = variantsweep('C:/path/to/corpus', { kind: 'pattern', id: '…', match: '…', anchors: { hooks: ['admin_init'] } });
//   // → { root, signature, hits, scannedFiles, skipped, gaps, errors, stats }

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { sweepVariants } from '../engine/variantsweep.mjs';

const DEFAULT_MAX_FILE_BYTES = 512 * 1024; // PHP sources are small; bigger = generated/minified junk
const DEFAULT_MAX_FILES = 20000;           // hard cap so a wrongly-pointed root (e.g. C:\) stays bounded

export function variantsweep(root, signature, { maxFileBytes = DEFAULT_MAX_FILE_BYTES, maxFiles = DEFAULT_MAX_FILES } = {}) {
  const skipped = [];
  const errors = [];
  const records = [];
  let scannedFiles = 0;
  const rootStr = String(root || '');

  // The signature may arrive as a JSON string (CLI) or an object (library/tests).
  let sig = signature;
  if (typeof sig === 'string') {
    try {
      sig = JSON.parse(sig);
    } catch (e) {
      errors.push('signature is not valid JSON: ' + ((e && e.message) || e));
      sig = null;
    }
  }

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
        if (st.size === 0) continue; // empty: nothing to sweep, not worth a skipped row
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

  let swept;
  try {
    swept = sweepVariants(records, sig);
  } catch (e) {
    // Engine is pure and tested against garbage; if it ever does throw, the tool's
    // contract still holds — report the failure, not a crash.
    return { root: rootStr, signature: null, hits: [], scannedFiles, skipped, gaps: [], errors: [...errors, 'sweep failed: ' + ((e && e.message) || e)], stats: { inputFiles: scannedFiles, prefilteredFiles: 0, candidatesConsidered: 0 } };
  }

  // Root-relative refs: the report stays portable when the tree moves between machines.
  const rootNorm = rootStr.replace(/\\/g, '/').replace(/\/?$/, '/');
  const hits = swept.hits.map((h) => ({
    ...h,
    ref: h.ref.startsWith(rootNorm) ? h.ref.slice(rootNorm.length) : h.ref,
  }));

  return {
    root: rootStr,
    signature: swept.signature,
    hits,
    scannedFiles,
    skipped,
    gaps: swept.gaps,
    errors: [...errors, ...swept.errors],
    stats: swept.stats,
  };
}
