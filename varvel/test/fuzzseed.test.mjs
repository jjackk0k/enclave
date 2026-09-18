// VARVEL fuzzseed tests — the fuzz harness tier (engine/fuzzseed.mjs + the codec
// registry in tools/fuzz.mjs). Hermetic: pure in-memory fuzzing; found-case corpus
// artifacts persist ONLY under varvel/.tmp per the house rule.
//
// THE HONEST CALIBRATION: the four VARVEL wire codecs (stegocodec, dnscodec, wsframe,
// pipelink FrameParser) are fuzzed with the deterministic stream. Crash-free is the
// expected outcome — and it MEANS something only because the same harness is proven
// against a deliberately-fragile fixture parser in this file (oracle + minimizer +
// differential all demonstrated firing). If a calibration ever goes red, the finding
// is real: fix the codec and pin the minimized repro here.
//   node --test test/fuzzseed.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateCases, runFuzz, fuzzDifferential, minimize } from '../engine/fuzzseed.mjs';
import { fuzzCodec, CODEC_TARGETS } from '../tools/fuzz.mjs';
import { embedPayload, extractPayload, renderScene, StegError } from '../engine/stegocodec.mjs';

const TMP = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp', 'fuzzseed-test');
mkdirSync(TMP, { recursive: true });

const hexStream = (cases) => cases.map((c) => `${c.strategy}:${c.input.toString('hex')}`).join('|');

// A deliberately fragile parser: typed clean reject on a NUL first byte; TypeError
// deref when the bytes contain CRSH; RangeError 'Invalid array length' on a huge
// declared length. The oracle must classify all three behaviors correctly.
class FragileError extends Error { constructor(m) { super(m); this.name = 'FragileError'; } }
function fragile(buf) {
  if (!buf.length || buf[0] === 0x00) throw new FragileError('clean reject: bad magic');
  if (buf.includes(Buffer.from('CRSH'))) { const x = undefined; return x.boom; }
  if (buf.length >= 4) {
    const len = buf.readUInt32BE(0);
    if (len * 2 > 0xffffffff) return new Array(len * 2); // RangeError: Invalid array length
  }
  return { ok: true, len: buf.length };
}
const FRAGILE_SEEDS = [Buffer.from('AAAA CRSH BBBB'), Buffer.from([1, 2, 3, 4, 5])];
const FRAGILE_DICT = [Buffer.from('CRSH'), Buffer.from([0xff, 0xff, 0xff, 0xff])];

test('determinism: same seed ⇒ identical case stream; different seed ⇒ different stream', () => {
  const a = generateCases({ seeds: FRAGILE_SEEDS, seed: 42, count: 200 });
  const b = generateCases({ seeds: FRAGILE_SEEDS, seed: 42, count: 200 });
  const c = generateCases({ seeds: FRAGILE_SEEDS, seed: 43, count: 200 });
  assert.equal(hexStream(a), hexStream(b), 'same seed produced different cases');
  assert.notEqual(hexStream(a), hexStream(c), 'different seeds produced the same stream');
  assert.equal(a.length, 200);
  // Every strategy in the set actually fires over a modest stream.
  const used = new Set(a.map((x) => x.strategy));
  assert.ok(used.size >= 6, `strategy coverage thin: ${[...used].join(', ')}`);
});

test('oracle: unexpected throws are crashes; declared typed errors are clean rejects', () => {
  const r = runFuzz(fragile, { seeds: FRAGILE_SEEDS, seed: 7, count: 300, expectedErrors: [FragileError], dictionary: FRAGILE_DICT });
  assert.ok(r.crashed, 'the fragile parser must crash under the harness');
  assert.ok(r.cleanRejects > 0, 'FragileError instances counted as clean rejects');
  const typeErr = r.findings.find((f) => f.errorName === 'TypeError');
  assert.ok(typeErr, 'TypeError deref not detected');
  assert.equal(typeErr.kind, 'crash');
  // Deterministic findings: same seed, same crash signatures.
  const r2 = runFuzz(fragile, { seeds: FRAGILE_SEEDS, seed: 7, count: 300, expectedErrors: [FragileError], dictionary: FRAGILE_DICT });
  assert.deepEqual(r2.findings.map((f) => [f.kind, f.errorName, f.index]), r.findings.map((f) => [f.kind, f.errorName, f.index]));
});

test('oracle: oversized allocation is classified as its own crash subclass', () => {
  const r = runFuzz(fragile, { seeds: [Buffer.from([0xff, 0xff, 0xff, 0xff, 65])], seed: 5, count: 200, expectedErrors: [FragileError], dictionary: FRAGILE_DICT, strategies: ['byte-flip', 'magic-swap', 'insert', 'duplicate'] });
  const alloc = r.findings.find((f) => f.errorName === 'RangeError');
  assert.ok(alloc, 'the huge-length alloc was not reached');
  assert.equal(alloc.kind, 'crash:oversized-alloc', `RangeError should classify as oversized-alloc (message: ${alloc.errorMessage})`);
});

test('minimization: a found case shrinks to the smallest repro of the same failure', () => {
  const r = runFuzz(fragile, { seeds: FRAGILE_SEEDS, seed: 7, count: 300, expectedErrors: [FragileError], dictionary: FRAGILE_DICT });
  const typeErr = r.findings.find((f) => f.errorName === 'TypeError');
  assert.ok(typeErr && typeErr.minimized, 'finding carries a minimized repro');
  assert.ok(typeErr.minimizedLength <= 4, `minimized to ${typeErr.minimizedLength} bytes (want ≤4 — 'CRSH')`);
  assert.ok(typeErr.minimized.includes(Buffer.from('CRSH')), 'the trigger bytes survive minimization');
  // The minimized repro still crashes the target (the repro-pin loop).
  assert.throws(() => fragile(typeErr.minimized), (e) => e instanceof TypeError);

  // Standalone minimize(): deterministic, budget-honest.
  const m = minimize(Buffer.from('zz CRSH zz CRSH zz'), (b) => b.includes(Buffer.from('CRSH')));
  assert.equal(m.input.toString(), 'CRSH');
  assert.ok(m.evaluations > 0 && !m.exhausted);
});

test('differential mode: accept-split, crash-split and output-split are all surfaced', () => {
  // robust: same clean-reject contract, PLUS rejects the 'XX' marker fragile accepts,
  // and returns a different output shape — so all three split classes can occur.
  const robust = (buf) => {
    if (!buf.length || buf[0] === 0x00) throw new FragileError('clean reject');
    if (buf.includes(Buffer.from('XX'))) throw new FragileError('robust-only reject');
    return { ok: true, n: buf.length };
  };
  const d = fuzzDifferential(robust, fragile, {
    seeds: FRAGILE_SEEDS, seed: 3, count: 250,
    expectedErrorsA: [FragileError], expectedErrorsB: [FragileError],
    dictionary: [...FRAGILE_DICT, Buffer.from('XX')],
  });
  const kinds = new Set(d.findings.map((f) => f.kind));
  assert.ok(kinds.has('crash-split'), 'one side crashing must surface');
  assert.ok(kinds.has('accept-split'), 'one side rejecting what the other accepts must surface');
  assert.ok(kinds.has('output-split'), 'accept/accept disagreement must surface (different output shapes)');
  assert.ok(d.casesRun > 0 && d.divergent === d.findings.length, 'run accounting is honest');
});

// ——— the calibration battery: VARVEL's own codecs, fuzzed before anyone else's ———

test('calibration: dnscodec decodeQuery — never throws, null-or-object contract holds', async () => {
  const r = await fuzzCodec('dnscodec', { seed: 20260818, count: 600, persist: false });
  assert.ifError(r.error);
  assert.equal(r.crashed, false, 'REAL FINDING: dnscodec crashed — fix it and pin the repro here');
  assert.equal(r.casesRun, 600);
  assert.deepEqual(r.findings, []);
});

test('calibration: wsframe WsParser — only typed WsError rejects, no crashes', async () => {
  const r = await fuzzCodec('wsframe', { seed: 20260818, count: 600, persist: false });
  assert.ifError(r.error);
  assert.equal(r.crashed, false, 'REAL FINDING: wsframe crashed — fix it and pin the repro here');
  assert.ok(r.cleanRejects > 50, 'reject path exercised (protocol violations rejected typed)');
  assert.ok(r.cleanAccepts > 50, 'accept path exercised (valid-ish frames still parse)');
});

test('calibration: pipelink FrameParser — only typed PipeLinkError rejects, no crashes', async () => {
  const r = await fuzzCodec('pipelink', { seed: 20260818, count: 600, persist: false });
  assert.ifError(r.error);
  assert.equal(r.crashed, false, 'REAL FINDING: pipelink crashed — fix it and pin the repro here');
  assert.ok(r.cleanRejects > 50, 'reject path exercised');
});

test('calibration: stegocodec decodeStgPng — chunk layer fails closed, no crashes', async () => {
  const r = await fuzzCodec('stegocodec', { seed: 20260818, count: 400, persist: false });
  assert.ifError(r.error);
  assert.equal(r.crashed, false, 'REAL FINDING: stegocodec crashed — fix it and pin the repro here');
  // Mutations almost all die at signature/CRC — that IS the fail-closed contract; the
  // deep frame layer gets its own calibration below.
  assert.ok(r.cleanRejects > 300, 'PNG chunk guards reject mutated structures typed');
});

test('calibration: stegocodec LSB frame layer (extractPayload) — length/CRC guards hold', () => {
  const scene = renderScene({ width: 64, height: 64, profile: 'flat', seed: 11 });
  const seeds = [embedPayload(scene, '{"t":"x"}'), embedPayload(scene, ''), embedPayload(scene, 'y'.repeat(900))];
  const r = runFuzz((buf) => extractPayload(buf), {
    seeds, seed: 20260818, count: 600, expectedErrors: [StegError],
    dictionary: [Buffer.from('SG'), Buffer.from([0, 0, 0, 0]), Buffer.from([0xff, 0xff, 0xff, 0xff])],
  });
  assert.equal(r.crashed, false, 'REAL FINDING: extractPayload crashed — fix it and pin the repro here');
  assert.ok(r.cleanAccepts > 100, 'frame layer actually decoded mutated-but-valid streams');
  assert.ok(r.cleanRejects > 50, 'frame layer rejects corrupted frames typed');
});

// ——— the house-rule corpus path ———

test('found-case corpus persists minimized repros under varvel/.tmp (never os.tmpdir)', async () => {
  CODEC_TARGETS['fragile-fixture'] = {
    describe: 'test-only fragile parser',
    build: async () => ({ fn: fragile, expectedErrors: [FragileError], seeds: FRAGILE_SEEDS, dictionary: FRAGILE_DICT }),
  };
  const corpusDir = join(TMP, 'corpus');
  rmSync(corpusDir, { recursive: true, force: true });
  const r = await fuzzCodec('fragile-fixture', { seed: 7, count: 300, corpusDir });
  assert.ifError(r.error);
  assert.equal(r.crashed, true);
  assert.ok(r.corpus && r.corpus.length >= 1, 'crash findings persisted to the corpus');
  for (const f of r.corpus) {
    assert.ok(f.replace(/\\/g, '/').includes('/.tmp/'), `corpus file outside .tmp: ${f}`);
    assert.ok(existsSync(f));
    // The persisted bytes are the MINIMIZED repro and still crash the parser — with an
    // UNDECLARED error class (never the clean-reject FragileError).
    assert.throws(() => fragile(readFileSync(f)), (e) => !(e instanceof FragileError));
  }
  assert.ok(readdirSync(corpusDir).length >= 1);
  delete CODEC_TARGETS['fragile-fixture'];
});

test('unknown codec target is a structured error, never a throw (tool contract)', async () => {
  const r = await fuzzCodec('no-such-codec', {});
  assert.match(String(r.error), /unknown codec target/);
});
