// VARVEL — variantsweep: given a vulnerability SIGNATURE (a known sink shape from a
// confirmed finding/CVE), sweep a local WordPress-plugin corpus and report every OTHER
// plugin carrying the same shape — ranked, with evidence refs.
//
// PROVENANCE: research/SOTA-VULN-DISCOVERY-2026-08-25.md §6 item 1 (top-ranked build) —
// Wordfence pays explicit multipliers for same-code-multi-plugin findings, and sweeping
// first-to-file beats the duplicate tax (§4). The method is the proven two-stage shape:
// a fast regex/string PREFILTER over the whole corpus, then a CONFIRM pass on the
// prefiltered files only — the confirm pass is engine/privemap.mjs's minePrivesc itself,
// so reachability/mitigation/taint analysis is reused, not duplicated.
//
// SIGNATURE MODEL (v1, deliberately small and honest):
//   pattern — { kind:'pattern', id, label, match: string|RegExp, anchors? } where the
//             regex must match the SINK LINE (privemap candidate evidence) and anchors
//             constrain context: hooks[] (e.g. ['admin_init']), reachability[], taint[],
//             impactClass, mitigationFree. Example: update_option on raw $_POST within an
//             admin_init-registered handler (the Madara option-overwrite shape).
//   class   — { kind:'class', class: '<privemap sink class id>', anchors? } reuses a
//             named privemap sink class as the sweep query (see sinkClasses()).
//
// HONESTY CONTRACT: every hit records { plugin, ref (file:line), class, confidence,
// status: '' } — the novelty/CVE-status field is left BLANK for the operator; the sweep
// never claims CVE status. Confidence is privemap's per-candidate estimate, unchanged.
// LINE-BASED HEURISTICS STILL APPLY: privemap's documented blind spots are inherited.
//
// records: [{ path, content }]. Pure: no fs, no network, no import-time side effects.

import { minePrivesc, sinkClasses } from './privemap.mjs';

const KNOWN_ANCHORS = new Set(['hooks', 'reachability', 'taint', 'impactClass', 'mitigationFree']);
const KNOWN_REACH = new Set(['unauth', 'subscriber', 'shortcode', 'admin-gated', 'unknown']);
const KNOWN_TAINT = new Set(['direct', 'tainted-var', 'ambient', 'none']);

// Plugin slug out of a record path: wp-content/plugins|themes/<slug>/… when the tree has
// the WordPress shape, else the first path segment ('(root)' for bare file names).
export function pluginOf(path) {
  const norm = String(path).replace(/\\/g, '/');
  const m = norm.match(/wp-content\/(?:plugins|themes)\/([^/]+)/);
  if (m) return m[1];
  const i = norm.indexOf('/');
  return i === -1 ? '(root)' : norm.slice(0, i);
}

// RegExp.test with lastIndex reset — a /g-flagged signature regex is stateful.
function testRe(re, s) {
  re.lastIndex = 0;
  return re.test(s);
}

function compileRe(src, flags, errors, what) {
  if (src instanceof RegExp) return new RegExp(src.source, src.flags);
  if (typeof src !== 'string' || !src) { errors.push(`${what}: must be a non-empty regex string or RegExp`); return null; }
  try {
    return new RegExp(src, typeof flags === 'string' ? flags : undefined);
  } catch (e) {
    errors.push(`${what}: invalid regex — ${(e && e.message) || e}`);
    return null;
  }
}

// Validate + normalize a signature into an executable form. Returns null on hard error
// (reasons accumulate in errors[]); anchor typos are hard errors — a misspelled anchor
// silently ignored would be a dishonest sweep.
function normalizeSignature(signature, errors) {
  if (!signature || typeof signature !== 'object' || Array.isArray(signature)) {
    errors.push('signature must be an object ({ kind:"pattern"|"class", … })');
    return null;
  }
  const anchors = signature.anchors || {};
  if (typeof anchors !== 'object' || Array.isArray(anchors)) {
    errors.push('anchors must be an object');
    return null;
  }
  let bad = false;
  for (const k of Object.keys(anchors)) {
    if (!KNOWN_ANCHORS.has(k)) { errors.push(`unknown anchor '${k}' — known: ${[...KNOWN_ANCHORS].join(', ')}`); bad = true; }
  }
  for (const k of ['hooks', 'reachability', 'taint']) {
    if (anchors[k] !== undefined && (!Array.isArray(anchors[k]) || !anchors[k].length || anchors[k].some((x) => typeof x !== 'string'))) {
      errors.push(`anchor '${k}' must be a non-empty array of strings`); bad = true; continue;
    }
    if (k === 'reachability' && anchors[k] && anchors[k].some((x) => !KNOWN_REACH.has(x))) {
      errors.push(`anchor 'reachability' values must be one of ${[...KNOWN_REACH].join(', ')}`); bad = true;
    }
    if (k === 'taint' && anchors[k] && anchors[k].some((x) => !KNOWN_TAINT.has(x))) {
      errors.push(`anchor 'taint' values must be one of ${[...KNOWN_TAINT].join(', ')}`); bad = true;
    }
  }
  if (bad) return null;

  const base = {
    id: typeof signature.id === 'string' && signature.id ? signature.id : '(unnamed)',
    label: typeof signature.label === 'string' ? signature.label : '',
    anchors,
  };
  if (signature.kind === 'pattern') {
    const match = compileRe(signature.match, signature.flags, errors, 'match');
    if (!match) return null;
    return { ...base, kind: 'pattern', match, prefilter: match };
  }
  if (signature.kind === 'class') {
    const cls = sinkClasses().find((s) => s.id === signature.class);
    if (!cls) {
      errors.push(`unknown sink class '${signature.class}' — known: ${sinkClasses().map((s) => s.id).join(', ')}`);
      return null;
    }
    return { ...base, kind: 'class', class: cls.id, prefilter: cls.re };
  }
  errors.push(`unknown signature kind '${signature.kind}' — expected 'pattern' or 'class'`);
  return null;
}

function anchorsMatch(c, anchors) {
  if (anchors.hooks && !anchors.hooks.includes(c.hook)) return false;
  if (anchors.impactClass && c.impactClass !== anchors.impactClass) return false;
  if (anchors.reachability && !anchors.reachability.includes(c.reachability)) return false;
  if (anchors.taint && !anchors.taint.includes(c.taint)) return false;
  if (anchors.mitigationFree && c.mitigations.length > 0) return false;
  return true;
}

// JSON-safe view of a normalized signature (no live RegExp objects).
function publicSig(sig) {
  return {
    id: sig.id, kind: sig.kind, label: sig.label,
    ...(sig.kind === 'pattern' ? { match: sig.match.source, flags: sig.match.flags } : { class: sig.class }),
    anchors: sig.anchors,
  };
}

export function sweepVariants(records, signature) {
  const errors = [];
  const sig = normalizeSignature(signature, errors);

  const norm = [];
  for (const rec of Array.isArray(records) ? records : []) {
    try {
      // Same ingestion rules as privemap: CRLF/CR → LF (line refs are normalized-text
      // line numbers) and path separators → '/' (refs print file:line).
      const content = String(rec && rec.content != null ? rec.content : '').replace(/\r\n?/g, '\n');
      const path = String(rec && rec.path != null ? rec.path : '?').replace(/\\/g, '/');
      if (!content.trim()) continue;
      norm.push({ path, content });
    } catch (e) {
      errors.push(`record skipped: ${(e && e.message) || e}`);
    }
  }

  if (!sig) {
    return { signature: null, hits: [], errors, gaps: [], stats: { inputFiles: norm.length, prefilteredFiles: 0, candidatesConsidered: 0 } };
  }

  // Stage 1 — PREFILTER: raw-content regex test over the whole corpus. Cheap by design;
  // false positives here are fine (the confirm pass decides), false negatives are not.
  const prefiltered = norm.filter((r) => testRe(sig.prefilter, r.content));
  if (!prefiltered.length) {
    return { signature: publicSig(sig), hits: [], errors, gaps: [], stats: { inputFiles: norm.length, prefilteredFiles: 0, candidatesConsidered: 0 } };
  }

  // Stage 2 — CONFIRM: privemap over prefiltered files only, then signature filters.
  const mined = minePrivesc(prefiltered);
  const hits = [];
  for (const c of mined.candidates) {
    if (sig.kind === 'class' && c.impactClass !== sig.class) continue;
    if (sig.kind === 'pattern' && !testRe(sig.match, c.evidence)) continue;
    if (!anchorsMatch(c, sig.anchors)) continue;
    hits.push({
      plugin: pluginOf(c.ref),
      ref: c.ref,
      class: c.impactClass,
      confidence: c.confidence,
      status: '', // novelty/CVE status is the operator's call — the sweep never fills it
      evidence: c.evidence,
      hook: c.hook,
      handler: c.handler,
      reachability: c.reachability,
      taint: c.taint,
      score: c.score,
    });
  }
  hits.sort((a, b) => b.score - a.score || (a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0));
  hits.forEach((h, i) => { h.rank = i + 1; });

  return {
    signature: publicSig(sig),
    hits,
    errors,
    gaps: mined.gaps,
    stats: { inputFiles: norm.length, prefilteredFiles: prefiltered.length, candidatesConsidered: mined.candidates.length },
  };
}

// DOCUMENTED BLIND SPOTS (on top of privemap's own, which the confirm pass inherits):
//  - The PREFILTER is the recall ceiling: a file whose only carrier of the shape never
//    literally matches the signature regex (e.g. the sink built by string concat) is
//    never confirmed. Pattern signatures should prefilter loosely and let anchors cut.
//  - Pattern signatures match against privemap candidate EVIDENCE (one sink line, ≤160
//    chars) — a shape spanning multiple lines needs a class signature + anchors instead.
//  - `plugin` is a path-shape heuristic: trees without wp-content/plugins/<slug>/ layout
//    report the first path segment, and one plugin's files split across roots attribute
//    separately.
