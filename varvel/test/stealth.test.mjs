// VARVEL enforced operational-stealth tests — deterministic pacer math + real pacing.
//   node --test varvel/test/stealth.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { STEALTH_PROFILES, stealthProfile, makePacer, estimateDuration, asPacer } from '../engine/stealth.mjs';
import { webScan } from '../tools/webscan.mjs';

test('profiles are ordered loud→paranoid: concurrency falls, delay rises', () => {
  const order = ['loud', 'normal', 'quiet', 'paranoid'];
  for (let i = 1; i < order.length; i++) {
    const a = STEALTH_PROFILES[order[i - 1]], b = STEALTH_PROFILES[order[i]];
    assert.ok(b.concurrency <= a.concurrency, `${order[i]} concurrency <= ${order[i - 1]}`);
    assert.ok(b.delayMs >= a.delayMs, `${order[i]} delay >= ${order[i - 1]}`);
  }
});

test('stealthProfile: name lookup, object override, unknown→normal', () => {
  assert.equal(stealthProfile('quiet').label, 'quiet');
  assert.equal(stealthProfile('nope').label, 'normal'); // unknown falls back
  assert.equal(stealthProfile({ concurrency: 2, delayMs: 5 }).concurrency, 2); // object merges over normal
  assert.equal(stealthProfile({ concurrency: 2 }).jitterMs, STEALTH_PROFILES.normal.jitterMs); // keeps normal's rest
});

test('makePacer: concurrency clamped ≥1 and floored; nextDelay math is base ± jitter, floored at 0', () => {
  assert.equal(makePacer('paranoid').concurrency, 1);
  assert.equal(makePacer({ concurrency: 0 }).concurrency, 1); // clamp
  assert.equal(makePacer({ concurrency: 3.9 }).concurrency, 3); // floor
  const prof = { concurrency: 2, delayMs: 100, jitterMs: 40 };
  assert.equal(makePacer(prof, { rand: () => 0.5 }).nextDelay(), 100); // 0.5 → 0 jitter → base
  assert.equal(makePacer(prof, { rand: () => 1 }).nextDelay(), 140);   // +full jitter
  assert.equal(makePacer(prof, { rand: () => 0 }).nextDelay(), 60);    // -full jitter
  assert.equal(makePacer({ delayMs: 10, jitterMs: 100 }, { rand: () => 0 }).nextDelay(), 0); // floored, never negative
});

test('pace() spaces successive requests via the shared clock (first is free)', async () => {
  const p = makePacer({ concurrency: 1, delayMs: 30, jitterMs: 0 });
  await p.pace(); // first emission — no reason to wait
  const t0 = process.hrtime.bigint();
  await p.pace(); // next — spaced ~30ms after the first
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.ok(ms >= 25, `spaced ~30ms, got ${ms.toFixed(1)}ms`);
});

test('shared clock: even with concurrency>1, request STARTS are globally spaced (no bursts)', async () => {
  const p = makePacer({ concurrency: 4, delayMs: 25, jitterMs: 0 }); // 4 workers, but starts must serialize
  const starts = [];
  const t0 = process.hrtime.bigint();
  await Promise.all(Array.from({ length: 4 }, () => (async () => { await p.pace(); starts.push(Number(process.hrtime.bigint() - t0) / 1e6); })()));
  starts.sort((a, b) => a - b);
  assert.ok(starts[3] >= 60, `4th start spaced (~75ms), not a burst — got ${starts[3].toFixed(0)}ms`);
});

test('penalize widens the gap on target push-back (adaptive, quieter — not evasion)', () => {
  const p = makePacer({ concurrency: 1, delayMs: 100, jitterMs: 0 });
  assert.equal(p.currentDelay(), 100);
  p.penalize(2, 0); // e.g. saw a 429/503
  assert.equal(p.currentDelay(), 200, 'doubled after target push-back');
  assert.ok(p.nextDelay() >= 200);
});

test('makePacer clamps Infinity concurrency to 1; asPacer passes/builds', () => {
  assert.equal(makePacer({ concurrency: Infinity }).concurrency, 1);
  const p = makePacer('quiet');
  assert.equal(asPacer(p), p, 'existing pacer returned as-is');
  assert.equal(asPacer('quiet').profile.label, 'quiet', 'profile → pacer');
  assert.equal(asPacer(null), null);
});

test('estimateDuration ≈ count × delay (shared clock serializes emissions); Infinity-safe', () => {
  assert.equal(estimateDuration({ concurrency: 2, delayMs: 100 }, 10), 1000); // n × delay (concurrency hides latency, not spacing)
  assert.equal(estimateDuration('loud', 100), 0); // no delay → instant
  assert.equal(estimateDuration('quiet', Infinity), Infinity);
});

// ---- integration: the pacer is ENFORCED inside our native tools ----

async function serve() {
  const srv = http.createServer((req, res) => { res.writeHead(404); res.end('nope'); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { srv, base: `http://127.0.0.1:${srv.address().port}` };
}

test('webScan without stealth is unchanged (stealth: null, fast)', async () => {
  const { srv, base } = await serve();
  try {
    const res = await webScan(base, { paths: ['/a', '/b', '/c'], timeout: 500 });
    assert.equal(res.stealth, null);
  } finally { srv.close(); }
});

test('webScan with a stealth profile enforces pacing in code (label returned + measurable floor)', async () => {
  const { srv, base } = await serve();
  try {
    // concurrency 1, 20ms delay, no jitter → 6 paths each paced ≥20ms ⇒ ≥120ms floor.
    const t0 = process.hrtime.bigint();
    const res = await webScan(base, { paths: ['/a', '/b', '/c', '/d', '/e', '/f'], timeout: 500, stealth: { label: 'test-slow', concurrency: 1, delayMs: 20, jitterMs: 0 } });
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    assert.equal(res.stealth, 'test-slow', 'applied profile surfaced to the operator');
    assert.ok(ms >= 100, `low-and-slow enforced: expected ≥100ms of pacing, got ${ms.toFixed(0)}ms`);
  } finally { srv.close(); }
});

test('extraHeaders: program-required attestation headers ride every requestHeaders call; tool/UA overrides refused', () => {
  const p = makePacer('paranoid', { extraHeaders: { 'X-Hackerone': 'varvel', 'User-Agent': 'forged-attempt', 'x-varvel-tag': 'nope' } });
  const h = p.requestHeaders({ accept: '*/*' });
  assert.equal(h['x-hackerone'], 'varvel', 'attestation header present, key lowercased');
  assert.notEqual(h['user-agent'], 'forged-attempt', 'UA override refused — the persona/scrub own UA');
  assert.equal(h['x-varvel-tag'], undefined, 'x-varvel* refused — the scrub owns the toolset namespace');
  assert.equal(h.accept, '*/*', 'per-call accept override still honored');
  assert.ok(h['accept-language'], 'persona headers intact');
  assert.deepEqual(p.extraHeaders, { 'x-hackerone': 'varvel' }, 'declared on the pacer so the report states exactly what was sent');

  const plain = makePacer('paranoid');
  assert.equal(plain.extraHeaders, null);
  assert.equal(plain.requestHeaders()['x-hackerone'], undefined, 'no attestation without opt-in — never set globally');
});

// ---------- ghost-level traffic shaper (2026-09-01): the pacer is POLICED by the
// ghost shaper — a floor on timing plus coarse app-layer padding, honestly labelled.

test('normalizeShaperConfig: null/false/empty -> null (no fake shaping); garbage is LOUD', async () => {
  const { normalizeShaperConfig } = await import('../engine/stealth.mjs');
  assert.equal(normalizeShaperConfig(null), null);
  assert.equal(normalizeShaperConfig(false), null);
  assert.equal(normalizeShaperConfig({}), null, 'an empty shaper is no shaper — never pretend');
  assert.deepEqual(normalizeShaperConfig({ minDelayMs: 100, jitterMs: 50, padTo: 'mtu' }), { minDelayMs: 100, jitterMs: 50, padTo: 'mtu' });
  assert.throws(() => normalizeShaperConfig({ padTo: 'constant-rate' }), /padTo/);
  assert.throws(() => normalizeShaperConfig({ minDelayMs: -1 }), /minDelayMs/);
});

test('pacer + ghost shaper: nextDelay is FLOORED at the shaper gap — the policy can slow, never speed up', () => {
  const p = makePacer({ concurrency: 1, delayMs: 100, jitterMs: 0 }, { rand: () => 0.5, shaper: { minDelayMs: 900, jitterMs: 400 } });
  assert.ok(p.nextDelay() >= 900 && p.nextDelay() <= 1300, 'shaper floor wins over the profile');
  const fast = makePacer({ concurrency: 1, delayMs: 2000, jitterMs: 0 }, { rand: () => 0.5, shaper: { minDelayMs: 900, jitterMs: 400 } });
  assert.equal(fast.nextDelay(), 2000, 'a slower profile is NOT sped up to the shaper floor');
  const none = makePacer({ concurrency: 1, delayMs: 40, jitterMs: 30 }, { rand: () => 0.5 });
  assert.equal(none.shaper, null, 'no shaper configured — nothing policed (backward-compatible)');
  assert.equal(none.nextDelay(), 40);
});

test('pacer shaper padTo mtu: requestHeaders carries an ADMITTED x-pad sized toward the MTU envelope; padTo null -> no pad', () => {
  const p = makePacer({ concurrency: 1, delayMs: 0, jitterMs: 0 }, { shaper: { minDelayMs: 10, padTo: 'mtu' } });
  const h = p.requestHeaders();
  assert.ok(h['x-pad'], 'padding header present');
  assert.ok(h['x-pad'].length > 500 && h['x-pad'].length <= 4096, 'coarse MTU-ward padding, capped');
  const np = makePacer({ concurrency: 1, delayMs: 0, jitterMs: 0 }, { shaper: { minDelayMs: 10 } });
  assert.equal(np.requestHeaders()['x-pad'], undefined, 'no padTo -> no padding');
  assert.equal(p.requestHeaders()['user-agent'] !== undefined, true, 'persona headers untouched');
});
