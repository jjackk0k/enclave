// VARVEL — tokenshape: the "computable-not-observable" detector class (scoped minimal).
//
// Research thread T2, build 3. Two halves, both PURE (no I/O — house rule):
//
//   1) TOKEN_SHAPES — the small library of known weak-token derivations a composer may
//      try when a target leaks token MATERIAL (a seed, a counter) but never the token
//      itself. Each shape is a hypothesis; execution is the oracle, so the library is
//      deliberately tiny and ordered most-common-first. Adding a shape is a research
//      act (hypothesis log entry), not a config tweak.
//
//   2) analyzeSamples(samples) — for endpoints that DO return tokens (invite links,
//      download URLs, API keys in responses): collect N samples and test for the
//      derivable patterns — sequential integers, timestamp-derived values, hex/base36
//      encodings of either. Returns an honest verdict with the evidence; 'none' is a
//      first-class result (random-looking tokens are a NEGATIVE finding worth logging,
//      per the failure-ledger doctrine).
//
// Scope discipline: this covers what the chainyard reset-token case needs plus the
// directly-adjacent observable case. It is NOT a general PRNG cryptanalysis kit.

// ——— shape library ———
// render(vars) produces the candidate token from extracted material.
// vars: { seed, user } at minimum (threaded by chainrun's {{var}} templates).
export const TOKEN_SHAPES = [
  { id: 'prefix-seed-user', label: '<prefix>-<seed>-<user>', render: ({ seed, user, prefix = 'rset' }) => `${prefix}-${seed}-${user}` },
  { id: 'seed-user', label: '<seed>-<user>', render: ({ seed, user }) => `${seed}-${user}` },
  { id: 'user-seed', label: '<user>-<seed>', render: ({ seed, user }) => `${user}-${seed}` },
  { id: 'seed-only', label: '<seed>', render: ({ seed }) => `${seed}` },
];

// The extract regexes a leak-primitive tries, most-specific first. The bare-hex
// fallback is intentionally absent: '[0-9a-f]{8}' matches timestamps and uptimes —
// a false seed is worse than no seed (it burns an execution candidate on garbage).
export const SEED_EXTRACT_REGEXES = [
  '(?:RNG_SEED|rng_seed|seed|SEED)["\\s:=]+([0-9a-fA-F]{6,32})',
  '(?:token[_-]?secret|signing[_-]?secret)["\\s:=]+([\\w-]{6,64})',
];

// ——— observable-sample analysis ———
const isHex = (s) => /^[0-9a-f]+$/i.test(s);
const isNum = (s) => /^\d+$/.test(s);

// Decode a sample to a candidate integer when it plausibly encodes one.
function toInt(s) {
  if (isNum(s)) return BigInt(s);
  if (isHex(s) && s.length >= 6) { try { return BigInt('0x' + s); } catch { return null; } }
  return null;
}

/**
 * @param {string[]} samples  token samples collected from ONE endpoint, in issue order
 * @returns {{predictable:boolean, pattern:'sequential'|'timestamp'|'none',
 *            detail:string, deltas?:string[]}}
 */
export function analyzeSamples(samples) {
  const list = (Array.isArray(samples) ? samples : []).map(String).filter(Boolean);
  if (list.length < 3) {
    return { predictable: false, pattern: 'none', detail: `need ≥3 samples to test derivability; got ${list.length} — inconclusive, honestly` };
  }
  const ints = list.map(toInt);
  if (ints.every((v) => v !== null)) {
    const deltas = ints.slice(1).map((v, i) => (v - ints[i]).toString());
    // sequential: CONSTANT stride across all gaps (a counter). Varying gaps are not a
    // counter — they fall through to the timestamp check.
    const seq = deltas.every((d) => d === deltas[0]);
    if (seq) return { predictable: true, pattern: 'sequential', deltas, detail: `constant delta ${deltas[0]} across ${list.length} samples` };
    // timestamp-derived: deltas cluster in a plausible ms-per-request band and grow
    const allPositive = deltas.every((d) => BigInt(d) > 0n);
    const tsLike = allPositive && ints.every((v) => v > 1_000_000_000_000n || (v > 1_000_000_000n && v < 4_000_000_000n));
    if (tsLike) return { predictable: true, pattern: 'timestamp', deltas, detail: 'monotonic values in a unix-epoch band — timestamp-derived' };
  }
  return { predictable: false, pattern: 'none', detail: `${list.length} samples show no sequential/timestamp structure (a negative result — log it, don't retry it)` };
}
