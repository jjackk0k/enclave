// VARVEL — fuzzseed: deterministic mutation fuzzing of pure parsers/codecs, with a
// crash/behavior oracle and found-case minimization.
//
// THE HONEST FIRST USE IS OURSELVES: the calibration targets are VARVEL's own wire
// codecs (engine/stegocodec.mjs, engine/dnscodec.mjs, engine/wsframe.mjs,
// engine/pipelink.mjs FrameParser) — parsers that face an untrusted peer on every
// transport. A crash found here is a real robustness finding in OUR attack surface:
// fix it and pin the repro as a regression test. That is the zero-day pipeline closing
// its own loop before it ever points at someone else's code.
//
// HARNESS CONTRACT:
//   target  = a PURE decode/parse function (Buffer -> anything). Parsers that reject
//             garbage by throwing their DECLARED typed error are healthy — declare
//             those classes in expectedErrors and they count as clean rejections.
//   oracle  = (a) CRASH: a throw that is NOT an expectedErrors instance (a TypeError
//             from an undefined deref, a RangeError from an oversized alloc — the
//             real-bug classes); (b) SLOW: wall-clock above slowMs (a hang CANDIDATE —
//             labeled environment-dependent, never asserted as proof); (c) INVARIANT:
//             the optional validate(output) callback throwing. DIFFERENTIAL mode
//             (fuzzDifferential) feeds the same input to two decoders and reports
//             accept/reject splits and output disagreements.
//   determinism = the case stream is a pure function of { seeds, seed, count, ... }:
//             same seed, same cases, byte for byte. Wall-clock touches NOTHING but the
//             SLOW label. runFuzz twice with the same seed must find the same things.
//   minimization = every crash/invariant finding is greedily shrunk (delta-debugging
//             lite: halves → quarters → … → single bytes) to the smallest input that
//             still reproduces the SAME failure signature. Deterministic, budget-capped.
//
// Pure: no fs, no network. The tool wrapper (tools/fuzz.mjs) owns corpus persistence.

import { performance } from 'node:perf_hooks';

// mulberry32 — the same seeded PRNG the stego scene renderer uses (local copy: engine
// modules stay standalone).
export function makePrng(seed) {
  let a = Number(seed) >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const STRATEGIES = Object.freeze(['bit-flip', 'byte-flip', 'truncate', 'duplicate', 'insert', 'delete-range', 'boundary-length', 'magic-swap']);

// Lengths that historically hurt parsers: off-by-ones around inline/extended length
// fields, u8/u16 boundaries, and the configured cap itself.
const BOUNDARY_BASES = [0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 62, 63, 64, 65, 124, 125, 126, 127, 128, 129, 255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097, 65535, 65536];

const toBuf = (v) => (Buffer.isBuffer(v) ? v : Buffer.from(String(v ?? ''), 'utf8'));

// Generate the deterministic case stream. Each case: { index, seed, strategy, base,
// input (Buffer, always ≤ maxLen) }. `dictionary` tokens feed insert/magic-swap.
export function generateCases({ seeds = [], seed = 1, count = 500, maxLen = 8192, dictionary = [], strategies = STRATEGIES } = {}) {
  const rnd = makePrng(seed);
  const baseSeeds = (Array.isArray(seeds) && seeds.length ? seeds : [Buffer.alloc(0)]).map(toBuf);
  const dict = (Array.isArray(dictionary) ? dictionary : []).map(toBuf).filter((d) => d.length);
  const strat = Array.isArray(strategies) && strategies.length ? strategies : STRATEGIES;
  const pick = (n) => Math.floor(rnd() * n);
  const cap = (b) => (b.length > maxLen ? b.subarray(0, maxLen) : b);

  const cases = [];
  for (let index = 0; index < Math.max(0, count | 0); index++) {
    const base = baseSeeds[pick(baseSeeds.length)];
    const strategy = strat[pick(strat.length)];
    let input;
    switch (strategy) {
      case 'bit-flip': {
        const b = Buffer.from(base);
        if (b.length) { const i = pick(b.length); b[i] ^= 1 << pick(8); }
        else { input = Buffer.from([1 << pick(8)]); break; }
        input = b;
        break;
      }
      case 'byte-flip': {
        if (!base.length) { input = Buffer.from([pick(256)]); break; }
        const b = Buffer.from(base);
        const n = 1 + pick(4);
        for (let k = 0; k < n; k++) b[pick(b.length)] = pick(256);
        input = b;
        break;
      }
      case 'truncate': {
        input = base.subarray(0, pick(base.length + 1));
        break;
      }
      case 'duplicate': {
        if (!base.length) { input = Buffer.alloc(0); break; }
        const a = pick(base.length), z = a + pick(base.length - a);
        const slice = base.subarray(a, z);
        const at = pick(base.length + 1);
        input = Buffer.concat([base.subarray(0, at), slice, slice, base.subarray(at)]);
        break;
      }
      case 'insert': {
        const token = dict.length && rnd() < 0.7 ? dict[pick(dict.length)] : Buffer.from(Array.from({ length: 1 + pick(8) }, () => pick(256)));
        const at = pick(base.length + 1);
        input = Buffer.concat([base.subarray(0, at), token, base.subarray(at)]);
        break;
      }
      case 'delete-range': {
        if (!base.length) { input = Buffer.alloc(0); break; }
        const a = pick(base.length), z = a + pick(base.length - a);
        input = Buffer.concat([base.subarray(0, a), base.subarray(z)]);
        break;
      }
      case 'boundary-length': {
        const want = BOUNDARY_BASES[pick(BOUNDARY_BASES.length)];
        if (base.length >= want) input = base.subarray(0, want);
        else {
          const pad = Buffer.alloc(want - base.length, base.length ? base[base.length - 1] : 0);
          input = Buffer.concat([base, pad]);
        }
        break;
      }
      case 'magic-swap': {
        // Replace a leading (or random) segment with a dictionary token — wrong-magic
        // and foreign-framing probes live here.
        const token = dict.length ? dict[pick(dict.length)] : Buffer.from([0x89, 0x50, 0x4e, 0x47]);
        const b = Buffer.from(base);
        const at = rnd() < 0.6 ? 0 : pick(b.length + 1);
        const kill = Math.min(token.length, Math.max(0, b.length - at));
        token.copy(b, at, 0, kill);
        input = at + token.length > b.length ? Buffer.concat([b, token.subarray(kill)]) : b;
        break;
      }
      default: {
        input = Buffer.from(base);
      }
    }
    cases.push({ index, seed, strategy, base: baseSeeds.indexOf(base), input: cap(Buffer.isBuffer(input) ? input : toBuf(input)) });
  }
  return cases;
}

// Delta-debugging lite: greedily delete segments (halves → quarters → … → bytes) while
// predicate(smaller) still reproduces. Deterministic; maxEvals-capped (exhaustion is
// reported, not hidden). Returns { input, originalLength, evaluations, exhausted }.
export function minimize(input, predicate, { maxEvals = 4000 } = {}) {
  let cur = toBuf(input);
  let evaluations = 0;
  const repro = (b) => {
    if (evaluations >= maxEvals) return false;
    evaluations++;
    try { return !!predicate(b); } catch { return false; }
  };
  let chunk = Math.max(1, Math.floor(cur.length / 2));
  while (cur.length > 1 && evaluations < maxEvals) {
    let reduced = false;
    for (let off = 0; off < cur.length && evaluations < maxEvals; off += chunk) {
      const smaller = Buffer.concat([cur.subarray(0, off), cur.subarray(Math.min(cur.length, off + chunk))]);
      if (smaller.length < cur.length && repro(smaller)) { cur = smaller; reduced = true; break; }
    }
    if (!reduced) {
      if (chunk === 1) break;
      chunk = Math.max(1, Math.floor(chunk / 2));
    }
  }
  return { input: cur, originalLength: toBuf(input).length, evaluations, exhausted: evaluations >= maxEvals };
}

function classifyError(e, expectedErrors) {
  for (const cls of expectedErrors || []) {
    if (cls && e instanceof cls) return null; // clean, declared rejection
  }
  const name = (e && e.name) || 'Error';
  const message = String((e && e.message) || e).slice(0, 200);
  const alloc = name === 'RangeError' && /invalid (?:array|string|typed ?array) length|allocation failed|out of memory|maximum call stack/i.test(message);
  return { errorName: name, errorMessage: message, alloc };
}

// Run the harness over the deterministic case stream.
//   target: Buffer -> any (pure). expectedErrors: typed error classes = clean rejects.
//   validate(output): optional invariant check — a throw = 'invariant' finding.
//   slowMs: wall-clock hang-candidate threshold (labeled, environment-dependent).
//   minimizeFindings: shrink crash/invariant repros (default true).
export function runFuzz(target, { seeds, seed = 1, count = 500, maxLen = 8192, dictionary = [], strategies, expectedErrors = [], validate = null, slowMs = 250, minimizeFindings = true, maxFindings = 50 } = {}) {
  if (typeof target !== 'function') throw new TypeError('runFuzz: target must be a pure decode/parse function');
  const findings = [];
  let casesRun = 0, cleanAccepts = 0, cleanRejects = 0;
  const seenSigs = new Set();

  for (const c of generateCases({ seeds, seed, count, maxLen, dictionary, strategies })) {
    casesRun++;
    const t0 = performance.now();
    let out, threw = null;
    try { out = target(c.input); } catch (e) { threw = e; }
    const dt = performance.now() - t0;

    if (threw) {
      const bad = classifyError(threw, expectedErrors);
      if (!bad) { cleanRejects++; continue; }
      const sig = `crash:${bad.errorName}:${bad.errorMessage.slice(0, 60)}`;
      if (seenSigs.has(sig)) continue;
      seenSigs.add(sig);
      const finding = {
        kind: bad.alloc ? 'crash:oversized-alloc' : 'crash',
        index: c.index, strategy: c.strategy, seed: c.seed,
        errorName: bad.errorName, errorMessage: bad.errorMessage,
        input: c.input,
      };
      if (minimizeFindings) {
        const min = minimize(c.input, (b) => {
          try { target(b); return false; } catch (e2) { const b2 = classifyError(e2, expectedErrors); return !!b2 && b2.errorName === bad.errorName; }
        });
        finding.minimized = min.input;
        finding.minimizedLength = min.input.length;
        finding.originalLength = c.input.length;
        finding.minimizeExhausted = min.exhausted;
      }
      findings.push(finding);
      continue;
    }
    cleanAccepts++;
    if (validate) {
      let vthrew = null;
      try { validate(out); } catch (e) { vthrew = e; }
      if (vthrew) {
        const sig = `invariant:${String((vthrew && vthrew.message) || vthrew).slice(0, 60)}`;
        if (!seenSigs.has(sig)) {
          seenSigs.add(sig);
          const finding = { kind: 'invariant', index: c.index, strategy: c.strategy, seed: c.seed, errorName: (vthrew && vthrew.name) || 'Error', errorMessage: String((vthrew && vthrew.message) || vthrew).slice(0, 200), input: c.input };
          if (minimizeFindings) {
            const min = minimize(c.input, (b) => {
              let o2;
              try { o2 = target(b); } catch { return false; }
              try { validate(o2); return false; } catch { return true; }
            });
            finding.minimized = min.input;
            finding.minimizedLength = min.input.length;
            finding.originalLength = c.input.length;
            finding.minimizeExhausted = min.exhausted;
          }
          findings.push(finding);
        }
        continue;
      }
    }
    if (dt > slowMs && findings.length < maxFindings) {
      findings.push({ kind: 'slow', index: c.index, strategy: c.strategy, seed: c.seed, ms: Math.round(dt * 10) / 10, input: c.input, note: 'hang CANDIDATE — wall-clock threshold, environment-dependent; rerun isolated before claiming' });
    }
    if (findings.length > maxFindings) break;
  }

  return {
    seed, casesRun, cleanAccepts, cleanRejects,
    crashed: findings.some((f) => f.kind.startsWith('crash')),
    findings: findings.slice(0, maxFindings),
    note: 'deterministic case stream (same seed ⇒ same cases); slow findings are wall-clock candidates, not proof',
  };
}

// Differential mode: the SAME generated cases through two decoders. Findings:
//   'accept-split'  — one rejects cleanly (expected error), the other accepts;
//   'crash-split'   — one crashes (unexpected error), the other doesn't;
//   'output-split'  — both accept, outputs disagree (Buffer.compare / JSON canonical).
export function fuzzDifferential(targetA, targetB, { seeds, seed = 1, count = 500, maxLen = 8192, dictionary = [], strategies, expectedErrorsA = [], expectedErrorsB = [], maxFindings = 50 } = {}) {
  if (typeof targetA !== 'function' || typeof targetB !== 'function') throw new TypeError('fuzzDifferential: two target functions required');
  const findings = [];
  let casesRun = 0, agreements = 0;
  // Output equality without stringifying giants: a 300MB accepted output must not crash
  // the ORACLE. Buffers compare byte-wise; anything unstringifiable degrades to a
  // labeled placeholder (documented: differential mode assumes decoder-sized outputs).
  const s = (v) => {
    if (Buffer.isBuffer(v)) return null; // handled by Buffer.equals below
    try { return JSON.stringify(v) ?? String(v); } catch { return `[unstringifiable ${typeof v}]`; }
  };
  const eqOut = (a, b) => {
    if (Buffer.isBuffer(a) || Buffer.isBuffer(b)) return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.equals(b);
    return s(a) === s(b);
  };

  for (const c of generateCases({ seeds, seed, count, maxLen, dictionary, strategies })) {
    casesRun++;
    let outA, errA = null, outB, errB = null;
    try { outA = targetA(c.input); } catch (e) { errA = e; }
    try { outB = targetB(c.input); } catch (e) { errB = e; }
    const crashA = errA && classifyError(errA, expectedErrorsA);
    const crashB = errB && classifyError(errB, expectedErrorsB);
    const rejA = errA && !crashA, rejB = errB && !crashB;

    let kind = null, detail = '';
    if (crashA || crashB) {
      kind = 'crash-split';
      const which = crashA ? { side: 'A', ...crashA } : { side: 'B', ...crashB };
      detail = `${which.side} crashed (${which.errorName}: ${which.errorMessage})`;
    } else if ((rejA && !errB) || (rejB && !errA)) {
      kind = 'accept-split';
      detail = rejA ? `A rejects (${String(errA.message).slice(0, 60)}), B accepts` : `B rejects (${String(errB.message).slice(0, 60)}), A accepts`;
    } else if (!errA && !errB) {
      if (!eqOut(outA, outB)) { kind = 'output-split'; detail = 'both accept, outputs differ'; }
    }
    if (!kind) { agreements++; continue; }
    findings.push({ kind, detail, index: c.index, strategy: c.strategy, seed: c.seed, input: c.input });
    if (findings.length >= maxFindings) break;
  }
  return { seed, casesRun, agreements, divergent: findings.length, findings, note: 'same deterministic stream through both decoders' };
}
