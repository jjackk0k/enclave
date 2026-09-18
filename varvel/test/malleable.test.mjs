// VARVEL malleable C2 + DNS-codec tests.
//   node --test varvel/test/malleable.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { MALLEABLE_PROFILES, malleableProfile, nextGap } from '../engine/malleable.mjs';
import { b32encode, b32decode, encodeQuery, decodeQuery, encodeReply } from '../engine/dnscodec.mjs';
import { CallbackChannel } from '../engine/callback.mjs';
import { SimAgent } from '../agents/sim-agent.mjs';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SCOPE = { cidrs: ['127.0.0.0/8'] };
const hmac = (t, m) => crypto.createHmac('sha256', t).update(m).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test('profiles: named profiles resolve, custom is clamped sane, unknown → ops-tempo', () => {
  assert.equal(malleableProfile('web-browse').label, 'Web browsing');
  assert.equal(malleableProfile('nonexistent').label, 'Ops tempo');
  const c = malleableProfile({ intervalMs: 5, jitterMs: 10 });
  assert.equal(c.intervalMs, 200, 'clamped, never zero-wait');
  assert.equal(c.label, 'custom');
  assert.ok(Object.keys(MALLEABLE_PROFILES).length >= 4);
});

test('nextGap: baseline within interval±jitter; bursts fire quick cycles', () => {
  const p = { intervalMs: 1000, jitterMs: 100, burst: { chance: 0, minN: 0, maxN: 0, gapMs: 0 } };
  assert.equal(nextGap(p, { rand: () => 0.5 }).gapMs, 1000);
  assert.equal(nextGap(p, { rand: () => 1 }).gapMs, 1100);
  assert.equal(nextGap(p, { rand: () => 0 }).gapMs, 900);
  const b = { intervalMs: 5000, jitterMs: 0, burst: { chance: 1, minN: 2, maxN: 4, gapMs: 250 } };
  const g = nextGap(b, { rand: () => 0 });
  assert.equal(g.gapMs, 250);
  assert.ok(g.burst >= 2 && g.burst <= 4);
});

test('channel setProfile → delivered on check-in header → sim agent ADOPTS the new cadence', async () => {
  const ch = new CallbackChannel({ scope: SCOPE });
  const { port } = await ch.arm(0);
  const dir = mkdtempSync(join(tmpdir(), 'sim-prof-'));
  try {
    const { agentId, token } = ch.registerAgent({});
    const agent = new SimAgent({ url: `http://127.0.0.1:${port}`, agentId, token, dir, interval: 200, jitter: 0 });
    const run = agent.run();
    try {
      await sleep(400);
      assert.ok(!agent.profile, 'no profile before assignment');
      const p = ch.setProfile(agentId, 'streaming');
      assert.equal(p.label, 'Streaming app');
      assert.equal(ch.agentsView()[0].profile, 'Streaming app');
      await sleep(900); // let a check-in deliver the header
      assert.ok(agent.profile && agent.profile.intervalMs === 1200, 'agent adopted the delivered profile live');
    } finally { agent.stop(); await run; }
  } finally { await ch.disarm(); }
});

test('DNS codec: b32 round-trip, query pack/unpack, malformed fails closed', () => {
  const payload = { a: 'agent01', s: 7, h: 'deadbeef' };
  assert.deepEqual(JSON.parse(b32decode(b32encode(JSON.stringify(payload))).toString()), payload);
  const q = encodeQuery(payload, { domain: 'ax.sim' });
  assert.ok(q.endsWith('.ax.sim'));
  for (const label of q.split('.')) assert.ok(label.length <= 63, 'DNS label cap');
  assert.deepEqual(decodeQuery(q, { domain: 'ax.sim' }), payload);
  assert.equal(decodeQuery('evil.other.domain', { domain: 'ax.sim' }), null);
  assert.equal(decodeQuery('!!bad!!.ax.sim', { domain: 'ax.sim' }), null);
  assert.ok(encodeReply({ taskId: 't1' }).length > 0);
  assert.equal(encodeReply(null), '');
});

test('DNS-codec transport: governed pull end-to-end (task delivery, bad auth → empty)', async () => {
  const ch = new CallbackChannel({ scope: SCOPE });
  const { port } = await ch.arm(0);
  try {
    const { agentId, token } = ch.registerAgent({});
    const taskId = ch.task(agentId, 'shell', 'whoami');
    const q = encodeQuery({ a: agentId, s: 1, h: hmac(token, agentId + ':1:pull') });
    const r = await fetch(`http://127.0.0.1:${port}/d/${q}`);
    const enc = await r.text();
    const delivered = JSON.parse(b32decode(enc).toString());
    assert.equal(delivered.taskId, taskId);
    assert.equal(delivered.kind, 'shell');
    assert.equal(ch.tasksView(agentId)[0].status, 'delivered');
    // bad auth → uniform EMPTY response (the codec's 204)
    const bad = encodeQuery({ a: agentId, s: 2, h: 'wrong' });
    const r2 = await fetch(`http://127.0.0.1:${port}/d/${bad}`);
    assert.equal(await r2.text(), '');
  } finally { await ch.disarm(); }
});

test('teardown grace (win32)', async () => { await sleep(500); });
