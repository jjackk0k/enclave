// VARVEL - agentsig: the agent-tradecraft oracle engine (gap#7).
//
// Why it exists: VARVEL is driven by an LLM operator, so its shell-command streams have
// a measurable SHAPE - and 2026 defenders publish fingerprints for exactly that shape
// (the published AI-agent command-stream signatures: delimiter echos between command
// blocks, output truncated for machine parsing, blanket error suppression,
// non-interactive flags, dense command bundling, planning leakage in comments, and
// machine cadence). Grading our own streams against the PUBLISHED signatures is the
// only honest way to know which of them our operator's tradecraft trips.
//
// This module grades VARVEL's OWN command streams - the channel task ledger's shell
// tasks for a live agent, or a PLANNED command list pre-flight - against that published
// signature family and reports exactly which signatures fire, with the exact matched
// text as evidence. Sibling of engine/beaconscore (which grades the wire cadence).
//
// THE HONESTY CONTRACT (same doctrine as tools/detoracle.mjs, engine/beaconscore.mjs):
// this is SIGNATURE evidence against published AI-agent tells, never a vendor verdict -
// vendor detector weights and thresholds are secret, so no score here is a claim of
// detectability OR of undetectability. Fail-closed on thin evidence: fewer than 5
// commands is 'insufficient-data', never guessed. Cadence is computed ONLY from real
// per-command timestamps; when none are provided the cadence signature reports
// fired:null with a 'no timing evidence' note - never a fabricated number.
// The tier's extra line, non-negotiable: REPORT signatures + evidence only. No evasion
// coaching, no remediation hints - not in output, not in comments.
//
// Pure logic, no I/O.

const MIN_COMMANDS = 5; // below this no ratio statistic is honest (fail-closed)
const EVIDENCE_CAP = 80; // matched-text evidence is truncated to this many chars
const LONG_LINE = 150;   // a single command line past this length is itself a density tell
const SUB1S_MS = 1000;   // inter-command gaps under a second are machine pacing

const clamp01 = (x) => Math.min(1, Math.max(0, x));
const _mean = (xs) => xs.reduce((s, x) => s + x, 0) / xs.length;
// Population stddev (divide by n): we describe THIS observed series, we do not infer
// a distribution parameter from a sample of it (same convention as beaconscore).
const _pstdev = (xs, m) => Math.sqrt(xs.reduce((s, x) => s + (x - m) * (x - m), 0) / xs.length);
const _r = (x, p = 4) => { const k = Math.pow(10, p); return Math.round(x * k) / k; };
const _ev = (s) => String(s).replace(/\s+/g, ' ').trim().slice(0, EVIDENCE_CAP);

// --- the published signature patterns (kept faithful to the 2026 writeups) ---
// 1. machine-parsing separators: delimiter echos between command blocks.
const RE_SEPARATOR = /\becho\s+['"]?[-=_*]{3,}['"]?/i;
// 2. bounded captures: stderr merged into stdout and truncated for machine parsing.
const RE_BOUNDED = /2>&1\s*\|\s*(?:head|tail)\s+-(?:n\s+)?\d+/i;
// 3. blanket error suppression (scored as a RATIO over the stream, see below).
const RE_SUPPRESS = /2>\s*\/dev\/null/;
// 4. non-interactive flags: pager=off, --no-pager, PAGER=cat, -batch/--batch, yes |.
const RE_NONINTERACTIVE = /(?:--no-pager|\bpager=off\b|\bPAGER=cat\b|(?:^|\s)--?batch(?:\s|$)|\byes\s*\|)/i;
// 5. command bundling: heredocs, && / ; chains (commands-per-line density), long lines.
const RE_HEREDOC = /<<-?\s*['"]?[A-Za-z_]/;
const RE_CHAINOP = /&&|;/g;
// 6. planning leakage: a shell comment carrying an explanatory sentence (2+ words).
const RE_COMMENT = /(?:^|\s)#\s+([A-Za-z][A-Za-z0-9 ,.'_-]{9,})/;

// Score a command stream against the published AI-agent signatures.
// commands: array of command strings (chronological). opts.times: optional per-command
// ms timestamps (same order); cadence is computed ONLY when times.length matches.
// Returns { score, band, signatures, flagged, note } with per-signature
// { id, name, fired, evidence, weight }.
export function analyzeCommandStream(commands, { times } = {}) {
  const cmds = (Array.isArray(commands) ? commands : []).map((c) => String(c ?? ''));
  const NOTE = 'signature-level measurement against the published AI-agent command-stream'
    + ' fingerprints (2026 defender writeups) -- vendor detector weights and thresholds are secret,'
    + ' so this is SIGNATURE evidence, never a vendor verdict; a clean grade is NOT a claim of'
    + ' undetectability. This tier reports signatures + evidence only.';

  // FAIL-CLOSED: thin evidence gets no grade at all.
  if (cmds.length < MIN_COMMANDS) {
    return { score: null, band: 'insufficient-data', signatures: null, flagged: [], note: 'fewer than 5 commands -- no honest grade possible' };
  }
  const n = cmds.length;

  // --- per-signature matching ---
  const sepHit = cmds.map((c) => RE_SEPARATOR.exec(c)).find(Boolean);
  const sepCount = cmds.filter((c) => RE_SEPARATOR.test(c)).length;
  const boundHit = cmds.map((c) => RE_BOUNDED.exec(c)).find(Boolean);
  const suppCount = cmds.filter((c) => RE_SUPPRESS.test(c)).length;
  const suppRatio = suppCount / n;
  const suppHit = cmds.find((c) => RE_SUPPRESS.test(c));
  const niHit = cmds.map((c) => RE_NONINTERACTIVE.exec(c)).find(Boolean);
  const isBundled = (c) => RE_HEREDOC.test(c) || (c.match(RE_CHAINOP) || []).length >= 1 || c.length > LONG_LINE;
  const bundleCount = cmds.filter(isBundled).length;
  const bundleRatio = bundleCount / n;
  const bundleHit = cmds.find(isBundled);
  const commentHit = cmds.map((c) => RE_COMMENT.exec(c)).find((m) => m && m[1].trim().includes(' '));

  // --- cadence: ONLY from real timestamps, never fabricated ---
  const ts = (Array.isArray(times) ? times : []).map(Number).filter(Number.isFinite).sort((a, b) => a - b);
  const hasTiming = ts.length === n;
  let gapCV = null, sub1sFrac = null, gaps = null;
  if (hasTiming) {
    gaps = [];
    for (let i = 1; i < ts.length; i++) gaps.push(ts[i] - ts[i - 1]);
    const gm = _mean(gaps);
    gapCV = gm > 0 ? _pstdev(gaps, gm) / gm : 0; // all-same-timestamp: zero dispersion, honestly
    sub1sFrac = gaps.filter((g) => g < SUB1S_MS).length / gaps.length;
  }

  // --- the score: 0-100 agent-likeness, seven legs, weights documented with their basis ---
  //   separators       20  the highest-PRECISION published tell: delimiter echos between
  //                        command blocks are near-exclusive to machine-parsed streams.
  //   bounded-captures 15  2>&1 piped to head/tail -N: output truncated for machine
  //                        parsing; high-precision, rare in interactive human use.
  //   error-suppression 15 RATIO leg: 2>/dev/null on a high share of commands (full
  //                        marks at >= 50% - blanket suppression; anchored at the
  //                        published "high ratio" phrasing, 40% = fire threshold).
  //   non-interactive  10  pager=off / --no-pager / PAGER=cat / batch flags / yes-pipes:
  //                        real but lower-precision (scripts use them too).
  //   bundling         20  RATIO leg: heredocs, && / ; chains, >150-char lines - the
  //                        strongest VOLUMETRIC tell (commands-per-line density; full
  //                        marks at >= 60% bundled, 30% = fire threshold).
  //   comments          5  planning leakage in explanatory shell comments; weakest alone
  //                        (humans comment scripts too), kept small on purpose.
  //   cadence          15  inter-command gapCV (regularity) + sub-1s gap fraction, from
  //                        REAL timestamps only; the published sub-second-chaining tell.
  // Rare tells are binary (observed once = the signature fired); ratio tells are graded.
  const signatures = [];
  const flagged = [];
  const push = (id, name, weight, fired, evidence, leg, flagText) => {
    signatures.push({ id, name, fired, evidence, weight });
    if (fired) flagged.push(flagText);
    return (fired ? leg : 0) * weight;
  };

  let score = 0;
  score += push('separators', 'machine-parsing separators (delimiter echos between command blocks)', 20,
    sepCount >= 1,
    sepCount >= 1 ? _ev(sepHit[0]) + ' (' + sepCount + '/' + n + ' commands)' : null,
    1,
    'delimiter echos between command blocks: "' + _ev(sepHit ? sepHit[0] : '') + '" -- the published machine-parsing separator tell');
  score += push('bounded-captures', 'bounded captures (2>&1 piped to head/tail -N: output truncated for machine parsing)', 15,
    !!boundHit,
    boundHit ? _ev(boundHit[0]) : null,
    1,
    'output truncated for machine parsing: "' + _ev(boundHit ? boundHit[0] : '') + '"');
  score += push('error-suppression', 'blanket error suppression (2>/dev/null on a high ratio of commands)', 15,
    suppRatio >= 0.4,
    suppRatio >= 0.4 ? Math.round(suppRatio * 100) + '% of commands, e.g. "' + _ev(suppHit) + '"' : null,
    clamp01(suppRatio / 0.5),
    'blanket error suppression: ' + Math.round(suppRatio * 100) + '% of commands carry 2>/dev/null');
  score += push('non-interactive', 'non-interactive flags (pager=off, --no-pager, PAGER=cat, batch, yes |)', 10,
    !!niHit,
    niHit ? _ev(niHit[0]) : null,
    1,
    'non-interactive flags: "' + _ev(niHit ? niHit[0] : '') + '"');
  score += push('bundling', 'command bundling (heredocs, && / ; chains, long lines: commands-per-line density)', 20,
    bundleRatio >= 0.3,
    bundleRatio >= 0.3 ? Math.round(bundleRatio * 100) + '% of lines bundled, e.g. "' + _ev(bundleHit) + '"' : null,
    clamp01(bundleRatio / 0.6),
    'dense command bundling: ' + Math.round(bundleRatio * 100) + '% of lines chain, heredoc, or run long');
  score += push('comments', 'planning leakage (explanatory shell comments)', 5,
    !!commentHit,
    commentHit ? _ev('# ' + commentHit[1]) : null,
    1,
    'planning leakage in a shell comment: "# ' + _ev(commentHit ? commentHit[1] : '') + '"');

  if (!hasTiming) {
    signatures.push({ id: 'cadence', name: 'cadence (inter-command regularity + sub-1s chaining)', fired: null, evidence: 'no timing evidence -- cadence is computed only from real per-command timestamps, never fabricated', weight: 15 });
  } else {
    const reg = clamp01(1 - (gapCV - 0.05) / 0.45); // published operating points, as in beaconscore
    const sub = clamp01(sub1sFrac / 0.6);
    const fired = gapCV < 0.35 || sub1sFrac >= 0.4;
    const ev = 'gapCV ' + _r(gapCV, 2) + ', ' + Math.round(sub1sFrac * 100) + '% sub-1s gaps (n=' + gaps.length + ')';
    signatures.push({ id: 'cadence', name: 'cadence (inter-command regularity + sub-1s chaining)', fired, evidence: fired ? ev : null, weight: 15 });
    if (fired) {
      flagged.push('machine cadence: gapCV ' + _r(gapCV, 2) + ' with ' + Math.round(sub1sFrac * 100) + '% sub-1s gaps -- the published sub-second-chaining tell');
      score += 15 * (0.5 * reg + 0.5 * sub);
    }
  }

  score = Math.round(score);
  const band = score >= 70 ? 'agent-shaped' : score >= 35 ? 'mixed' : 'human-like';
  const note = hasTiming
    ? NOTE
    : 'no timing evidence was provided, so the cadence leg (15 of 100 points) is unscored -- never rescaled, never fabricated. ' + NOTE;
  return { score, band, signatures, flagged, note };
}
