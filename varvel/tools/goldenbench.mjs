// VARVEL — goldenbench tool wrapper: load the golden manifest, run privemap over each
// entry's root, grade recall/precision with engine/goldenbench.mjs, return the verdict.
//
// HOUSE CONTRACT: tools touch fs but NEVER throw. A missing/unparseable manifest, an
// absent corpus root, or a privemap failure is reported (errors[] / status:'skip' with
// a named reason) — a partial bench with honest gaps beats an exception, and a cleaned
// .tmp corpus must NEVER fail the gate (skip ≠ fail).
//
//   import { goldenbench } from './goldenbench.mjs';
//   const report = goldenbench();                       // default data/goldenbench/manifest.json
//   const report = goldenbench({ manifestPath: '…' });  // alternate manifest
//   // → { manifest, entries, totals, verdict, errors }

import { existsSync, readFileSync, statSync } from 'node:fs';
import { join, dirname, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { privemap } from './privemap.mjs';
import { validateManifest, gradeEntry, summarize } from '../engine/goldenbench.mjs';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const DEFAULT_MANIFEST = join(REPO_ROOT, 'data', 'goldenbench', 'manifest.json');

// loadManifest(path) -> { entries, errors } — parse + validate, never throw.
export function loadManifest(manifestPath) {
  let text;
  try {
    text = readFileSync(manifestPath, 'utf8');
  } catch (e) {
    return { entries: [], errors: [`manifest unreadable: ${manifestPath} (${(e && e.message) || e})`] };
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return { entries: [], errors: [`manifest is not valid JSON: ${manifestPath} (${(e && e.message) || e})`] };
  }
  return validateManifest(parsed);
}

// Roots may be absolute (the madara research mirror) or repo-relative (.tmp corpus,
// test fixtures) — relative resolves against the repo root so the bench is portable.
const resolveRoot = (root, repoRoot) => (isAbsolute(root) ? root : join(repoRoot, root));

export function goldenbench({ manifestPath = DEFAULT_MANIFEST, repoRoot = REPO_ROOT } = {}) {
  const errors = [];
  const { entries, errors: manifestErrors } = loadManifest(manifestPath);
  errors.push(...manifestErrors);

  const results = [];
  for (const entry of entries) {
    const root = resolveRoot(entry.root, repoRoot);
    try {
      const st = statSync(root);
      if (!st.isDirectory()) {
        results.push({ id: entry.id, root, expectation: entry.expectation, status: 'skip',
          reason: `root is not a directory: ${root}${entry.skipNote ? ` — ${entry.skipNote}` : ''}` });
        continue;
      }
    } catch {
      // Corpus-absent is NORMAL (a cleaned .tmp, another host) — skip with the reason
      // named; it never fails the bench.
      results.push({ id: entry.id, root, expectation: entry.expectation, status: 'skip',
        reason: `corpus absent: ${root}${entry.skipNote ? ` — ${entry.skipNote}` : ''}` });
      continue;
    }
    try {
      const report = privemap(root);
      results.push({ ...gradeEntry(entry, report), root });
    } catch (e) {
      // privemap's own contract is never-throw; if it ever does, the bench records the
      // entry as errored (fails the bench loudly) instead of crashing the whole run.
      results.push({ id: entry.id, root, expectation: entry.expectation, status: 'error',
        failures: [`privemap run failed: ${(e && e.message) || e}`] });
    }
  }

  const totals = summarize(results, errors);
  return { manifest: manifestPath, entries: results, totals, verdict: totals.verdict, errors };
}
