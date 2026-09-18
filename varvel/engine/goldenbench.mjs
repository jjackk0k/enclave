// VARVEL — goldenbench ENGINE: recall/precision grading for privemap against the
// golden plugin set (research/SOTA-VULN-DISCOVERY-2026-08-25.md §6 item 9 — the
// benchmark harness; Aardvark's 92%-recall golden repos and AIxCC's 86%-of-synthetic
// are how the field proves capability; internally this quantifies regression when
// privemap rules change). This is THE GATE every privemap edit must pass.
//
// PURE MODULE: no fs, no network, no import-time side effects. The tools wrapper
// (tools/goldenbench.mjs) loads the manifest, runs tools/privemap.mjs per entry, and
// feeds the reports here. This module imports NOTHING from privemap — candidates are
// consumed as plain records, so an engine change can't silently move the goalposts.
//
// THE GRADING CONTRACT (honesty rules, pinned by test/goldenbench.test.mjs):
//   - must-hit: every pinned ref must appear in candidates with the pinned impactClass
//     at/ABOVE its minReachability (order: unknown < admin-gated < shortcode <
//     subscriber < unauth). A MISS fails loudly — the ref is named in missed[] and in
//     the entry's failures[]. A same-file/same-class candidate at a DIFFERENT line is
//     recorded as nearMiss (line drift is information, not a silent pass).
//   - must-stay-clean: zero candidates in the entry's forbid band (default the
//     CONFIRMED band: reachability unauth AND confidence high AND severity high|crit —
//     the engine's own conviction levels). Everything BELOW the band is counted, not
//     hidden: unauth candidates by confidence, all candidates by severity band.
//   - SKIP is not FAIL: a corpus-absent entry never fails the bench (the .tmp corpus
//     may be cleaned between rounds); the wrapper marks it skip with a named reason.
//   - A malformed manifest entry lands in errors[] and counts as an error entry —
//     the bench never throws and never silently drops a broken pin.

export const REACH_ORDER = ['unknown', 'admin-gated', 'shortcode', 'subscriber', 'unauth'];
export const CONF_ORDER = ['low', 'medium', 'high'];
export const SEV_ORDER = ['info', 'low', 'med', 'high', 'crit'];

// The CONFIRMED band: what "zero confirmed unauth candidates" means in engine terms.
export const DEFAULT_FORBID = { reachability: 'unauth', confidence: 'high', severity: 'high' };

const atOrAbove = (order, found, expected) => {
  const f = order.indexOf(found);
  const e = order.indexOf(expected);
  return f !== -1 && e !== -1 && f >= e;
};

const normRef = (ref) => String(ref || '').replace(/\\/g, '/');
const refPath = (ref) => normRef(ref).replace(/:\d+$/, '');

// --- manifest validation ---------------------------------------------------------

// validateManifest(parsed) -> { entries, errors }. Every survivable entry is
// normalized (defaults applied); every broken entry is an errors[] row, never a throw.
export function validateManifest(parsed) {
  const errors = [];
  const entries = [];
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { entries, errors: ['manifest is not a JSON object'] };
  }
  if (!Array.isArray(parsed.plugins)) {
    return { entries, errors: ['manifest.plugins is not an array'] };
  }
  parsed.plugins.forEach((p, i) => {
    const tag = `plugins[${i}]${p && p.id ? ` (${p.id})` : ''}`;
    if (!p || typeof p !== 'object') { errors.push(`${tag}: entry is not an object`); return; }
    if (typeof p.id !== 'string' || !p.id) { errors.push(`${tag}: missing id`); return; }
    if (typeof p.root !== 'string' || !p.root) { errors.push(`${tag}: missing root`); return; }
    if (p.expectation !== 'must-hit' && p.expectation !== 'must-stay-clean') {
      errors.push(`${tag}: expectation must be 'must-hit' or 'must-stay-clean' (got ${JSON.stringify(p.expectation)})`); return;
    }
    const entry = {
      id: p.id,
      root: p.root,
      expectation: p.expectation,
      ...(p.scope ? { scope: p.scope } : {}),
      ...(p.provenance ? { provenance: p.provenance } : {}),
      ...(p.skipNote ? { skipNote: p.skipNote } : {}),
    };
    if (p.expectation === 'must-hit') {
      if (!Array.isArray(p.hits) || p.hits.length === 0) { errors.push(`${tag}: must-hit needs a non-empty hits[]`); return; }
      const hits = [];
      for (const [j, h] of p.hits.entries()) {
        const htag = `${tag} hits[${j}]`;
        if (!h || typeof h !== 'object') { errors.push(`${htag}: not an object`); return; }
        if (typeof h.ref !== 'string' || !/:\d+$/.test(normRef(h.ref))) { errors.push(`${htag}: ref must be 'relative/path.php:<line>' (got ${JSON.stringify(h.ref)})`); return; }
        if (typeof h.class !== 'string' || !h.class) { errors.push(`${htag}: missing class`); return; }
        const minReach = h.minReachability || 'unauth';
        if (!REACH_ORDER.includes(minReach)) { errors.push(`${htag}: minReachability must be one of ${REACH_ORDER.join('|')} (got ${JSON.stringify(h.minReachability)})`); return; }
        hits.push({ ref: normRef(h.ref), class: h.class, minReachability: minReach, ...(h.handler ? { handler: h.handler } : {}), ...(h.note ? { note: h.note } : {}) });
      }
      entry.hits = hits;
    } else {
      const forbid = { ...DEFAULT_FORBID, ...(p.forbid && typeof p.forbid === 'object' ? p.forbid : {}) };
      if (!REACH_ORDER.includes(forbid.reachability)) { errors.push(`${tag}: forbid.reachability must be one of ${REACH_ORDER.join('|')}`); return; }
      if (!CONF_ORDER.includes(forbid.confidence)) { errors.push(`${tag}: forbid.confidence must be one of ${CONF_ORDER.join('|')}`); return; }
      if (!SEV_ORDER.includes(forbid.severity)) { errors.push(`${tag}: forbid.severity must be one of ${SEV_ORDER.join('|')}`); return; }
      entry.forbid = forbid;
    }
    entries.push(entry);
  });
  return { entries, errors };
}

// --- per-hit recall matching ------------------------------------------------------

// One pinned hit vs a privemap candidates[] list. Exact = ref (path:line) + class.
export function matchHit(hit, candidates) {
  const exact = (candidates || []).find((c) => normRef(c.ref) === hit.ref && c.impactClass === hit.class);
  if (exact) {
    return { ref: hit.ref, class: hit.class, minReachability: hit.minReachability, found: true,
      reachability: exact.reachability, reachOk: atOrAbove(REACH_ORDER, exact.reachability, hit.minReachability),
      candidate: { ref: exact.ref, sev: exact.sev, confidence: exact.confidence, handler: exact.handler, score: exact.score, rank: exact.rank }, nearMiss: null };
  }
  const near = (candidates || []).find((c) => refPath(c.ref) === refPath(hit.ref) && c.impactClass === hit.class);
  return { ref: hit.ref, class: hit.class, minReachability: hit.minReachability, found: false, reachability: null, reachOk: false, candidate: null,
    nearMiss: near ? { ref: normRef(near.ref), reachability: near.reachability, note: 'same file+class at a different line — line drift, not a match' } : null };
}

// --- per-entry grading ------------------------------------------------------------

// gradeEntry(entry, report) — report is the tools/privemap.mjs report for the entry's
// root. Returns the graded entry result; status is pass|fail (skip is the wrapper's
// call — no report, no grading).
export function gradeEntry(entry, report) {
  const candidates = (report && report.candidates) || [];
  const measured = {
    scannedFiles: report ? report.scannedFiles : 0,
    candidates: candidates.length,
    gapsReported: report ? report.gaps.length : 0,
    unresolvedCallbacks: report && report.stats ? report.stats.unresolvedCallbacks : 0,
  };
  const failures = [];

  if (entry.expectation === 'must-hit') {
    const hits = entry.hits.map((h) => matchHit(h, candidates));
    const missed = hits.filter((h) => !h.found).map((h) => h.ref);
    const belowReach = hits.filter((h) => h.found && !h.reachOk).map((h) => `${h.ref} (reachability ${h.reachability} < expected ${h.minReachability})`);
    for (const m of missed) failures.push(`MISS: pinned ref ${m} not found in candidates${(hits.find((h) => h.ref === m).nearMiss ? ` — near miss at ${hits.find((h) => h.ref === m).nearMiss.ref}` : '')}`);
    for (const b of belowReach) failures.push(`DOWNGRADE: ${b}`);
    return {
      id: entry.id, root: entry.root, expectation: entry.expectation,
      ...(entry.provenance ? { provenance: entry.provenance } : {}),
      status: failures.length ? 'fail' : 'pass',
      failures,
      recall: { expected: hits.length, found: hits.filter((h) => h.found && h.reachOk).length, missed, belowReach },
      hits, measured,
    };
  }

  // must-stay-clean: zero candidates in the forbid band; everything below it counted.
  const f = entry.forbid;
  const inBand = (c) => atOrAbove(REACH_ORDER, c.reachability, f.reachability) &&
    atOrAbove(CONF_ORDER, c.confidence, f.confidence) && atOrAbove(SEV_ORDER, c.sev, f.severity);
  const violations = candidates.filter(inBand).map((c) => ({ ref: normRef(c.ref), impactClass: c.impactClass, sev: c.sev, confidence: c.confidence, reachability: c.reachability, handler: c.handler }));
  for (const v of violations) failures.push(`CONFIRMED-BAND HIT on a verified-clean plugin: ${v.ref} (${v.impactClass}, ${v.sev}/${v.confidence})`);
  const unauthByConfidence = { high: 0, medium: 0, low: 0 };
  for (const c of candidates.filter((x) => x.reachability === 'unauth')) {
    if (unauthByConfidence[c.confidence] !== undefined) unauthByConfidence[c.confidence]++;
  }
  const bySeverity = { crit: 0, high: 0, med: 0, low: 0, info: 0 };
  for (const c of candidates) if (bySeverity[c.sev] !== undefined) bySeverity[c.sev]++;
  return {
    id: entry.id, root: entry.root, expectation: entry.expectation,
    ...(entry.scope ? { scope: entry.scope } : {}),
    ...(entry.provenance ? { provenance: entry.provenance } : {}),
    status: violations.length ? 'fail' : 'pass',
    failures,
    precision: { band: { ...f }, violations, unauthByConfidence, bySeverity },
    measured,
  };
}

// --- bench-level summary ----------------------------------------------------------

// summarize(results, errors) -> totals + verdict. Skips never fail; a fail or error
// entry fails the bench. Per-class recall breakdown covers every must-hit pin.
export function summarize(results, errors = []) {
  const graded = results.filter((r) => r.status === 'pass' || r.status === 'fail');
  const failed = results.filter((r) => r.status === 'fail');
  const skipped = results.filter((r) => r.status === 'skip');
  const errored = results.filter((r) => r.status === 'error');

  const recallHits = results.flatMap((r) => (r.recall ? [r.recall] : []));
  const expected = recallHits.reduce((n, r) => n + r.expected, 0);
  const found = recallHits.reduce((n, r) => n + r.found, 0);

  const byClass = {};
  for (const r of results) {
    for (const h of r.hits || []) {
      const b = byClass[h.class] || (byClass[h.class] = { expected: 0, found: 0, missed: [] });
      b.expected++;
      if (h.found && h.reachOk) b.found++;
      else b.missed.push(`${r.id}:${h.ref}`);
    }
  }

  const violations = results.flatMap((r) => (r.precision ? r.precision.violations.map((v) => ({ plugin: r.id, ...v })) : []));

  // Per-plugin gap counts — the scanner-coverage dial. Recorded so a parser fix
  // (e.g. the [ $this, 'm' ] short-array REST callback gap) is measurable before/after.
  const gaps = {};
  for (const r of results) {
    if (r.measured) gaps[r.id] = { reported: r.measured.gapsReported, unresolvedCallbacks: r.measured.unresolvedCallbacks };
  }

  const verdict = failed.length || errored.length || errors.length ? 'FAIL' : 'PASS';
  return {
    verdict,
    entries: { total: results.length, graded: graded.length, passed: graded.length - failed.length, failed: failed.length, skipped: skipped.length, errored: errored.length },
    recall: { expected, found, missed: expected - found, pct: expected ? Math.round((found / expected) * 1000) / 10 : null },
    precision: { cleanPlugins: results.filter((r) => r.precision).length, violations: violations.length, violationRefs: violations.map((v) => `${v.plugin}:${v.ref}`) },
    byClass,
    gaps,
  };
}
