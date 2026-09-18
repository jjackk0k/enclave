// stg.test.mjs — roadmap #4: the STEGANOGRAPHY CHANNEL (transport 'stg'). Hermetic:
// loopback only, ephemeral ports, and every payload-class artifact (PNGs with embedded
// envelopes) is written under varvel/.tmp/ per the house rule — NEVER os.tmpdir().
// Covers: the pure PNG/LSB codec (round-trip byte-exact, capacity, typed corruption
// errors), the full wire through the REAL callback intake (task down over an image,
// result up over an upload-shaped image, kill-list, uniformity), ghost threading, and
// the channel-assigned switch onto the image wire.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CallbackChannel } from '../engine/callback.mjs';
import { b32decode } from '../engine/dnscodec.mjs';
import { SimAgent } from '../agents/sim-agent.mjs';
import { StgTransport, STG_PUSH_CHUNK } from '../agents/stg-client.mjs';
import { encodeStgPng, decodeStgPng, encodePng, decodePng, renderScene, stgCapacity, StegError, STG_DEFAULTS } from '../engine/stegocodec.mjs';

const SCOPE = { engagement: 'test', signedBy: 'test', cidrs: ['127.0.0.0/8'] };
const hmac = (token, msg) => crypto.createHmac('sha256', token).update(msg).digest('hex');

// The repo-local scratch dir (gitignored + Defender-excluded — the house rule for
// payload-class artifacts). Settings JSON isolation rides the same dir.
const TMP = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp', 'stg-test');
mkdirSync(TMP, { recursive: true });
process.env.VARVEL_SETTINGS_FILE = join(TMP, 'settings.json');

async function armedStg(extra = {}) {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), stg: { profile: 'gradient' }, ...extra });
  await ch.arm(0);
  return { ch, events, port: ch.port, url: `http://127.0.0.1:${ch.port}` };
}

// Minimal GET helper for raw image pulls (query-envelope shape, no agent wrapper).
function getPng(port, path) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method: 'GET' }, (res) => {
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    req.end();
  });
}
const pullPath = (agentId, token, seq) => '/stg/i/hero-banner.png?d=' + Buffer.from(JSON.stringify({ a: agentId, s: seq, h: hmac(token, agentId + ':' + seq + ':pull') })).toString('base64url');

// ——— Codec: round-trip byte-exactness across payload classes and scene profiles ———
test('codec: PNG round-trip is byte-exact for empty / small / chunked-max payloads, all profiles', () => {
  const small = Buffer.from(JSON.stringify({ taskId: crypto.randomUUID(), kind: 'note', data: 'hello-stg' }));
  // The biggest envelope the agent leg ever embeds: a push chunk at STG_PUSH_CHUNK.
  const maxChunkEnv = Buffer.from(JSON.stringify({
    a: 'a1b2c3d4e5f6', s: 42, h: 'ab'.repeat(32), t: crypto.randomUUID(), k: 'push', i: 9, n: 10,
    d: Buffer.alloc(STG_PUSH_CHUNK, 0x61).toString('base64'),
  }));
  const sizes = { empty: 0, small: small.length, chunkedMax: maxChunkEnv.length };
  assert.ok(maxChunkEnv.length <= stgCapacity(STG_DEFAULTS), 'the agent\'s max push envelope fits the default frame (' + maxChunkEnv.length + ' <= ' + stgCapacity(STG_DEFAULTS) + ')');
  const stats = [];
  for (const profile of ['gradient', 'flat', 'noise']) {
    for (const [label, payload] of [['empty', Buffer.alloc(0)], ['small', small], ['chunkedMax', maxChunkEnv]]) {
      const t0 = performance.now();
      const png = encodeStgPng(payload, { profile });
      const encMs = performance.now() - t0;
      const t1 = performance.now();
      const back = decodeStgPng(png);
      const decMs = performance.now() - t1;
      assert.ok(back.equals(payload), profile + '/' + label + ' round-trips byte-exact');
      stats.push(`${profile}/${label}: png=${png.length}B payload=${payload.length}B enc=${encMs.toFixed(1)}ms dec=${decMs.toFixed(1)}ms`);
    }
  }
  // Bandwidth evidence for the docs (measured, not asserted-as-claim): the envelope
  // capacity per image and what the images cost on the wire.
  console.log('  [stg bandwidth] capacity=' + stgCapacity(STG_DEFAULTS) + 'B/image :: ' + stats.join(' | '));
});

test('codec: artifacts persist under varvel/.tmp and decode back from disk (house rule)', () => {
  const payload = Buffer.from('payload-class artifact, repo-local scratch only');
  for (const profile of ['gradient', 'flat', 'noise']) {
    const png = encodeStgPng(payload, { profile });
    const p = join(TMP, `sample-${profile}.png`);
    writeFileSync(p, png); // payload-class (image with embedded envelope) -> .tmp, NEVER os.tmpdir()
    assert.ok(decodeStgPng(readFileSync(p)).equals(payload), profile + ' decodes back from disk byte-exact');
  }
});

test('codec: identical envelopes never byte-repeat (fresh scene seed per encode)', () => {
  const env = Buffer.from('{"a":"x","s":1}');
  const a = encodeStgPng(env), b = encodeStgPng(env);
  assert.ok(!a.equals(b), 'same payload, different PNG bytes (seeded cover scene)');
  assert.ok(decodeStgPng(a).equals(env) && decodeStgPng(b).equals(env), 'both still decode to the same envelope');
  // pinned seeds are deterministic (the test/reproducibility seam)
  assert.ok(encodeStgPng(env, { seed: 7 }).equals(encodeStgPng(env, { seed: 7 })));
});

test('codec: capacity math is explicit and overflow refuses LOUDLY', () => {
  const cap = stgCapacity({ width: 128, height: 128 }); // floor(128*128*3/8) - 11
  assert.equal(cap, 6133, '1 LSB per RGB byte, 11-byte frame: 6144 - 11');
  const ok = encodeStgPng(Buffer.alloc(cap)); // exactly full fits
  assert.equal(decodeStgPng(ok).length, cap);
  assert.throws(() => encodeStgPng(Buffer.alloc(cap + 1)), (e) => {
    assert.ok(e instanceof StegError);
    assert.equal(e.code, 'CAPACITY');
    assert.match(e.message, /6133/); // the refusal names the numbers
    return true;
  });
});

test('codec: wrong magic / truncated / corrupt / foreign / bit-flipped all throw TYPED errors', () => {
  // wrong magic
  assert.throws(() => decodeStgPng(Buffer.from('GIF89a not a png at all')), (e) => e instanceof StegError && e.code === 'NOT_PNG');
  const png = encodeStgPng(Buffer.from('corruption targets'));
  // truncated (mid-IHDR: the declared chunk runs past the cut)
  assert.throws(() => decodeStgPng(png.subarray(0, 20)), (e) => e instanceof StegError && e.code === 'TRUNCATED');
  // corrupt IDAT bytes (deflate stream damage or pixel damage — typed, never garbage)
  const corrupt = Buffer.from(png);
  corrupt[60] ^= 0xff; // inside the IDAT data of every profile's layout
  assert.throws(() => decodeStgPng(corrupt), (e) => e instanceof StegError && ['BAD_CHUNK_CRC', 'CORRUPT', 'PAYLOAD_CRC'].includes(e.code));
  // a valid PNG that is not ours (clean scene, no frame): NO_PAYLOAD, not garbage
  const clean = encodePng({ width: 64, height: 64, rgb: renderScene({ width: 64, height: 64, profile: 'flat', seed: 1 }) });
  assert.throws(() => decodeStgPng(clean), (e) => e instanceof StegError && e.code === 'NO_PAYLOAD');
  // a single pixel LSB flipped inside the payload region: the frame CRC trips
  const { pixels } = decodePng(png);
  pixels[100] ^= 0x01; // stream byte 100 sits inside the payload span (frame offset 7+)
  const reflipped = encodePng({ width: 128, height: 128, rgb: pixels });
  assert.throws(() => decodeStgPng(reflipped), (e) => e instanceof StegError && e.code === 'PAYLOAD_CRC');
});

// ——— The full wire, through the REAL callback intake ———
test('wire e2e: task down over an image, multi-chunk result up over upload images, ledger completes', async () => {
  const { ch, events, url } = await armedStg();
  const dir = join(TMP, 'agent-e2e');
  try {
    const { agentId, token } = ch.registerAgent({ label: 'stg-e2e' });
    // 2.1 KB note -> 2,107-byte result -> 2 upload chunks over the image wire (the
    // down envelope is ~3.5 KB of b32 — inside the 6,133 B frame; bigger tasking is
    // what the loud stg.down-failed path is for, tested below).
    const taskId = ch.task(agentId, 'note', 'x'.repeat(2100));
    const agent = new SimAgent({ url, agentId, token, dir, transport: 'stg', interval: 200, jitter: 0 });
    assert.equal(await agent.tick(), true);
    const view = ch.tasksView(agentId).find((t) => t.taskId === taskId);
    assert.equal(view.status, 'resulted');
    const res = ch.results(agentId, { taskId });
    assert.equal(res.length, 1);
    assert.equal(res[0].data, 'noted: ' + 'x'.repeat(2100), 'the reassembled multi-chunk body is intact');
    // governance + tagging landed on the stg bucket for BOTH legs
    const av = ch.agentsView()[0];
    assert.equal(av.transportCheckins.stg, 3, '1 pull + 2 push chunks, all tagged stg');
    assert.equal(av.lastTransport, 'stg');
    assert.ok(events.some((e) => e.type === 'agent.checkin' && e.transport === 'stg'));
    assert.ok(events.some((e) => e.type === 'task.delivered' && e.transport === 'stg' && e.taskId === taskId));
    assert.ok(events.some((e) => e.type === 'task.resulted' && e.transport === 'stg' && e.taskId === taskId));
    assert.ok(events.some((e) => e.type === 'agent.push' && e.transport === 'stg' && e.chunk === 2 && e.of === 2));
    const st = ch.stgStatus();
    assert.equal(st.configured, true);
    assert.equal(st.served, 1);
    assert.equal(st.uploads, 2);
    assert.equal(st.capacityBytes, 6133);
    agent.stop();
  } finally { await ch.disarm(); rmSync(dir, { recursive: true, force: true }); }
});

test('wire: idle vs tasked uniformity — same asset shape, structurally identical images, empty vs task envelope', async () => {
  const { ch, events, port } = await armedStg();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'stg-uniform' });
    const bare = await getPng(port, '/stg/i/hero-banner.png'); // an observer's bare GET
    const idle = await getPng(port, pullPath(agentId, token, 1));
    ch.task(agentId, 'note', 'tasked-image');
    const tasked = await getPng(port, pullPath(agentId, token, 2));
    for (const [label, r] of [['bare', bare], ['idle', idle], ['tasked', tasked]]) {
      assert.equal(r.status, 200, label + ' -> 200');
      assert.equal(r.headers['content-type'], 'image/png', label + ' is an image asset');
      const img = decodePng(r.body); // parses as a real PNG
      assert.equal(img.width, 128);
      assert.equal(img.height, 128);
    }
    assert.equal(decodeStgPng(bare.body).length, 0, 'bare GET: empty envelope (clean image)');
    assert.equal(decodeStgPng(idle.body).length, 0, 'idle pull: empty envelope — SAME structure as tasked');
    const task = JSON.parse(b32decode(decodeStgPng(tasked.body).toString('utf8')).toString('utf8'));
    assert.equal(task.data, 'tasked-image');
    // HONEST SIDE-CHANNEL (documented, asserted as fact not as a claim of immunity):
    // idle and tasked images differ in BYTE SIZE — size correlates with payload length;
    // nothing pads it away. Both are valid framed PNGs; size is the leak.
    assert.ok(tasked.body.length !== idle.body.length, 'size side-channel exists and is documented');
    console.log(`  [stg uniformity] bare=${bare.body.length}B idle=${idle.body.length}B tasked=${tasked.body.length}B — content-uniform, size leaks (documented)`);
    assert.ok(!events.some((e) => e.type === 'checkin.rejected'), 'clean pulls reject nothing');
  } finally { await ch.disarm(); }
});

test('wire: kill-list + unknown agent + bad auth all serve the empty-envelope image (deny ≡ idle)', async () => {
  const { ch, events, port } = await armedStg();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'stg-kill' });
    ch.task(agentId, 'note', 'never-delivered');
    ch.kill(agentId);
    const killed = await getPng(port, pullPath(agentId, token, 1));
    assert.equal(killed.status, 200);
    assert.equal(killed.headers['content-type'], 'image/png');
    assert.equal(decodeStgPng(killed.body).length, 0, 'a killed agent\'s image is indistinguishable from idle');
    assert.ok(events.some((e) => e.type === 'checkin.rejected'), 'the denial is loud in the ledger only');
    const ghost = await getPng(port, pullPath('deadbeefcafe', 'ab'.repeat(16), 1));
    assert.equal(decodeStgPng(ghost.body).length, 0, 'unknown agent: same empty image');
    const badAuth = await getPng(port, '/stg/i/hero-banner.png?d=' + Buffer.from(JSON.stringify({ a: agentId, s: 5, h: 'wrong' })).toString('base64url'));
    assert.equal(decodeStgPng(badAuth.body).length, 0, 'bad auth: same empty image');
    const junk = await getPng(port, '/stg/i/hero-banner.png?d=!!!not-an-envelope!!!');
    assert.equal(junk.status, 200);
    assert.equal(decodeStgPng(junk.body).length, 0, 'a malformed envelope still gets the uniform image');
  } finally { await ch.disarm(); }
});

test('wire: a task bigger than the frame is a LOUD down-failure (stg.down-failed), never a silent loss', async () => {
  const { ch, events, port } = await armedStg();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'stg-oversize' });
    const taskId = ch.task(agentId, 'note', 'y'.repeat(8000)); // reply b32 ≈ 12.9 KB > 6,133 B capacity
    const r = await getPng(port, pullPath(agentId, token, 1));
    assert.equal(r.status, 200);
    assert.equal(decodeStgPng(r.body).length, 0, 'the agent sees the uniform empty image');
    const fail = events.find((e) => e.type === 'stg.down-failed');
    assert.ok(fail, 'the gap is audited loudly');
    assert.equal(fail.reason, 'capacity');
    assert.ok(fail.bytes > fail.capacity);
    assert.equal(ch.stgStatus().downFailed, 1);
    // the honest ledger window: dequeued (delivered) but never resulted — same doctrine
    // as ghc.down-failed and the UDP wire.
    assert.equal(ch.tasksView(agentId).find((t) => t.taskId === taskId).status, 'delivered');
  } finally { await ch.disarm(); }
});

test('wire: upload intake rejects non-images and foreign PNGs (204-uniform, ledger-loud)', async () => {
  const { ch, events, url, port } = await armedStg();
  try {
    const post = (body, ct) => new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, path: '/stg/u', method: 'POST', headers: { 'content-type': ct, 'content-length': body.length } }, (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode));
      });
      req.on('error', reject);
      req.end(body);
    });
    assert.equal(await post(Buffer.from('plain text, not an image'), 'image/png'), 204);
    assert.equal(await post(encodePng({ width: 64, height: 64, rgb: renderScene({ width: 64, height: 64, seed: 3 }) }), 'image/png'), 204);
    assert.equal(await post(encodeStgPng(Buffer.from('not json')), 'image/png'), 204);
    assert.equal(await post(encodeStgPng(Buffer.from('{}')), 'text/plain'), 204, 'wrong content-type: same 204');
    const rejects = events.filter((e) => e.type === 'checkin.rejected');
    assert.ok(rejects.some((e) => e.reason === 'stg-bad-image'), 'decode/parse failures are ledger-loud with the typed reason');
    assert.ok(rejects.some((e) => e.error === 'NO_PAYLOAD' || e.error === 'no-envelope'), 'the typed stego code rides the audit event');
    assert.equal(ch.stgStatus().rejected, 4);
    // and the channel is still serving real traffic afterwards
    const { agentId, token } = ch.registerAgent({});
    const r = await getPng(port, pullPath(agentId, token, 1));
    assert.equal(r.status, 200);
  } finally { await ch.disarm(); }
});

test('ghost threading: the agent leg rides an injected agent chain (the Ghost.agents() seam)', async () => {
  const { ch, url } = await armedStg();
  const dir = join(TMP, 'agent-ghost');
  try {
    // The seam Ghost.agents() plugs into: count requests at the http.Agent layer.
    class CountingAgent extends http.Agent {
      constructor() { super({ keepAlive: false }); this.requests = 0; }
      addRequest(...args) { this.requests++; return super.addRequest(...args); }
    }
    const counter = new CountingAgent();
    const { agentId, token } = ch.registerAgent({ label: 'stg-ghost' });
    ch.task(agentId, 'note', 'through-the-chain');
    const agent = new SimAgent({ url, agentId, token, dir, transport: 'stg', agents: { httpAgent: counter, httpsAgent: counter }, interval: 200, jitter: 0 });
    assert.equal(await agent.tick(), true);
    assert.ok(counter.requests >= 2, 'pull image + upload image both rode the injected agent (' + counter.requests + ' requests)');
    agent.stop();
  } finally { await ch.disarm(); rmSync(dir, { recursive: true, force: true }); }
});

test('channel-assigned switch onto stg: http agent adopts, next check-ins arrive on the image wire', async () => {
  const { ch, events, url } = await armedStg();
  const dir = join(TMP, 'agent-switch');
  try {
    const { agentId, token } = ch.registerAgent({ label: 'stg-switch' });
    const asg = ch.setTransport(agentId, 'stg');
    assert.equal(asg.transport, 'stg');
    assert.equal(asg.state, 'assigned');
    ch.task(agentId, 'note', 'switch-me');
    const agent = new SimAgent({ url, agentId, token, dir, transport: 'http', interval: 200, jitter: 0 });
    assert.equal(await agent.tick(), true); // http pull: the x-varvel-transport header assigns stg
    assert.equal(agent.transport, 'stg', 'the agent adopted the assigned wire');
    assert.equal(await agent.tick(), false); // idle pull ON THE IMAGE WIRE
    const av = ch.agentsView()[0];
    assert.equal(av.assignedTransport.state, 'active', 'observed stg traffic flips assigned -> active');
    assert.ok(av.transportCheckins.stg >= 1);
    assert.ok(events.some((e) => e.type === 'agent.transport-active' && e.transport === 'stg'));
    agent.stop();
  } finally { await ch.disarm(); rmSync(dir, { recursive: true, force: true }); }
});

test('stg leg padding: pad envelopes ride the image wire and audit as agent.pad', async () => {
  const { ch, events, url } = await armedStg();
  const dir = join(TMP, 'agent-pad');
  try {
    const { agentId, token } = ch.registerAgent({ label: 'stg-pad' });
    const agent = new SimAgent({ url, agentId, token, dir, transport: 'stg', interval: 200, jitter: 0 });
    assert.equal(await agent._pad(), true);
    const pad = events.find((e) => e.type === 'agent.pad');
    assert.ok(pad, 'the padding dummy is audited as itself');
    assert.equal(pad.transport, 'stg');
    assert.equal(pad.padding, true);
    agent.stop();
  } finally { await ch.disarm(); rmSync(dir, { recursive: true, force: true }); }
});

test('settings: stg.enabled defaults OFF (opt-in), stg.profile validates against the scene classes', async () => {
  const { Settings } = await import('../engine/settings.mjs?fresh-stg=' + Date.now());
  const s = Settings.for('stg-test-' + Date.now());
  assert.equal(s.get('stg.enabled'), false, 'default OFF — the engagement must opt in');
  assert.equal(s.get('stg.profile'), 'gradient');
  assert.equal(s.set('stg.enabled', true), true);
  assert.equal(s.set('stg.profile', 'noise'), 'noise');
  assert.throws(() => s.set('stg.profile', 'watercolor'), TypeError, 'unknown scene classes refuse');
});

test('stg transport grading: the wire joins the failover vocabulary honestly', async () => {
  const { rankTransports, gradeAgentTransports } = await import('../engine/transport-grade.mjs');
  const now = 1_000_000_000;
  const grades = gradeAgentTransports({ transportLastSeen: { http: now - 100, stg: now - 100 }, lastTransport: 'http' }, { now, expectedMs: 5000 });
  assert.equal(grades.perTransport.stg.health, 'healthy');
  const r = rankTransports({ grades, wireScores: {}, checkins: { http: 5, stg: 2 }, eligible: { ghc: false, smb: false, doh: false, icmp: false, stg: false }, current: 'http' });
  assert.ok(r.ineligible.some((x) => x.transport === 'stg' && /image channel armed/.test(x.reason)), 'unarmed stg is listed with its honest reason, never ranked');
});

// Teardown grace: on win32, --test-force-exit can fire while sockets are still closing
// (libuv UV_HANDLE_CLOSING assert). Same guard as doh/dnstransport/transportfail.
test('teardown grace for socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});
