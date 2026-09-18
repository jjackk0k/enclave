// envelope.test.mjs — PER-HOP ENVELOPE ENCRYPTION (engine/envelope + the intake/agent
// wiring). The stealth item: governed wire envelope CONTENT is AEAD-sealed end-to-end
// agent↔listener (chacha20-poly1305, HKDF key hierarchy), so a relay parent on the
// pivot mesh forwards OPAQUE CIPHERTEXT instead of reading every task/result.
//
// PROOF OBLIGATIONS (the tasking contract):
//   (a) round-trip through the REAL intake for encrypted envelopes — http + smb-link
//       (plus the codec/ws/stg/ghc inheritance proofs: one envelope layer, every wire).
//   (b) NEGATIVE: the relay parent's decoded view contains ONLY ciphertext — the
//       parent-side open attempt with the LINK keys it actually holds FAILS.
//   (c) tamper => AEAD open fails => typed EnvelopeError + audit, no plaintext oracle.
//   (d) mixed-mode negotiation: old (plaintext) agent on preferred works; on required
//       => loud refusal ('enc-required' in the ledger, 204-uniform on the wire).
//   (e) key-rotation-safe replay protection: seq semantics unchanged (the AEAD layer
//       holds no replay state; the HMAC-layer seq decides, rekey or not).
//   (f) token never derivable from envelopes: HKDF info separation, proven by failed
//       derivation/open attempts from everything a parent holds.
//
// Hermetic: real CallbackChannel on 127.0.0.1 (ephemeral), real named pipes (win32),
// real SimAgents. HOUSE RULE: everything written lives under repo-local .tmp — never
// os.tmpdir(). Settings discipline: VARVEL_SETTINGS_FILE points under .tmp, unique
// engagement names per test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtempSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ENV_VERSION, ENV_MAGIC, ENV_PREFIX, ENC_MODES, EnvelopeError, normalizeEncMode,
  deriveEncKey, sealBytes, openBytes, isSealedBytes, sealString, openString, isSealedString,
} from '../engine/envelope.mjs';
import { deriveVerifyKey } from '../engine/pipelink.mjs';
import { encodeQuery, b32decode, b32encode } from '../engine/dnscodec.mjs';
import { pullPayload, pushPayloads, decodeReplyEnc, downCommentBody } from '../engine/ghc2.mjs';
import { CallbackChannel } from '../engine/callback.mjs';
import { SimAgent } from '../agents/sim-agent.mjs';
import { DnsTransport } from '../agents/dns-client.mjs';
import { StgTransport } from '../agents/stg-client.mjs';
import { Settings } from '../engine/settings.mjs';

// HOUSE RULE: repo-local .tmp only (gitignored, Defender-excluded) — never os.tmpdir().
const TMP_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp');
mkdirSync(TMP_ROOT, { recursive: true });
const WORK = mkdtempSync(join(TMP_ROOT, 'envelope-test-'));
process.env.VARVEL_SETTINGS_FILE = join(WORK, 'settings.json');

const SCOPE = { engagement: 'test', signedBy: 'test', cidrs: ['127.0.0.0/8'] };
const hmac = (token, msg) => crypto.createHmac('sha256', token).update(msg).digest('hex');
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const tick = (ms = 15) => new Promise((r) => setTimeout(r, ms));
let engSeq = 0;
const freshEng = () => 'envelope-' + (engSeq++) + '-' + Date.now();

async function waitFor(fn, timeoutMs = 4000) {
  const start = Date.now();
  while (!fn()) {
    if (Date.now() - start > timeoutMs) return false;
    await new Promise((r) => setTimeout(r, 15));
  }
  return true;
}

async function armed(extra = {}, scope = SCOPE) {
  const events = [];
  const ch = new CallbackChannel({ scope, onEvent: (t, o) => events.push({ type: t, ...o }), ...extra });
  await ch.arm(0);
  return { ch, port: ch.port, events };
}

// ---------------- pure: key hierarchy + AEAD primitive ----------------
test('envelope keys: HKDF per-agent hierarchy, info separation from the link domain (proof f)', () => {
  const token = crypto.randomBytes(16).toString('hex');
  const k1 = deriveEncKey(token, 'agent01');
  assert.equal(k1.length, 32, 'a 32-byte AEAD key');
  // agent-scoped: same token, different agent id -> different key
  assert.notEqual(deriveEncKey(token, 'agent02').toString('hex'), k1.toString('hex'));
  // token-bound: same agent id, different token -> different key
  assert.notEqual(deriveEncKey(crypto.randomBytes(16).toString('hex'), 'agent01').toString('hex'), k1.toString('hex'));
  // deterministic: the listener (stored credential) and the agent (its token) derive the SAME key
  assert.equal(deriveEncKey(token, 'agent01').toString('hex'), k1.toString('hex'));
  // HKDF INFO SEPARATION vs the pipelink domain: the parent holds
  // verifyKey = HMAC(token, 'varvel-link:'+link); its sessions keys derive from THAT.
  // None of the parent's material stretches into the 'varvel-env:' domain:
  const linkId = 'ab12cd34';
  const verifyKey = deriveVerifyKey(token, linkId);
  const sessUp = hmac(verifyKey, 'sess-up:' + 'a'.repeat(16));
  // 1) the parent's best HKDF stretch (its verify key as IKM) != the envelope key
  assert.notEqual(deriveEncKey(verifyKey, 'agent01').toString('hex'), k1.toString('hex'));
  assert.notEqual(deriveEncKey(sessUp, 'agent01').toString('hex'), k1.toString('hex'));
  // 2) the raw domain outputs differ (HKDF('varvel-env:') vs HMAC('varvel-link:'))
  assert.notEqual(verifyKey, k1.toString('hex'));
  // 3) and the proof that matters operationally: a blob sealed for the agent does NOT
  //    open under anything the parent holds
  const blob = sealBytes(k1, Buffer.from('task: exfil the ledger'));
  for (const parentKeyMaterial of [verifyKey, sessUp]) {
    assert.throws(() => openBytes(deriveEncKey(parentKeyMaterial, 'agent01'), blob), EnvelopeError, 'parent-held key material cannot open the envelope');
    assert.throws(() => openBytes(Buffer.from(parentKeyMaterial, 'hex'), blob), EnvelopeError, 'the raw link key is not the envelope key either');
  }
  // input validation: typed, fail-closed
  assert.throws(() => deriveEncKey('', 'a'), (e) => e instanceof EnvelopeError && e.code === 'key');
  assert.throws(() => deriveEncKey(token, ''), (e) => e instanceof EnvelopeError && e.code === 'key');
});

test('envelope AEAD: seal/open round trip; tamper matrix fails typed + oracle-free (proof c, unit)', () => {
  const key = deriveEncKey(crypto.randomBytes(16).toString('hex'), 'agent01');
  const pt = Buffer.from('result body: CROWN-JEWELS-42');
  const blob = sealBytes(key, pt);
  // shape: MAGIC || nonce(12) || ct || tag(16); self-describing
  assert.ok(isSealedBytes(blob));
  assert.equal(blob.subarray(0, 3).toString('latin1'), 'VE' + String.fromCharCode(ENV_VERSION));
  assert.equal(blob.length, ENV_MAGIC.length + 12 + pt.length + 16);
  assert.deepEqual(openBytes(key, blob), pt);
  // random nonce per seal: identical plaintext never byte-repeats
  const blob2 = sealBytes(key, pt);
  assert.notEqual(blob.toString('hex'), blob2.toString('hex'));
  // empty plaintext is legal (an empty result body)
  assert.deepEqual(openBytes(key, sealBytes(key, Buffer.alloc(0))), Buffer.alloc(0));
  // TAMPER: flip one bit in the ciphertext, in the tag, in the nonce — all fail 'open'
  for (const at of [10, blob.length - 17, blob.length - 1]) {
    const bad = Buffer.from(blob);
    bad[at] ^= 0x01;
    assert.throws(() => openBytes(key, bad), (e) => e instanceof EnvelopeError && e.code === 'open' && !/CROWN/.test(e.message), 'bit-flip at ' + at + ' fails typed, leaking NO plaintext');
  }
  // wrong key / truncation / bad magic / non-buffer
  assert.throws(() => openBytes(deriveEncKey('deadbeef', 'agent01'), blob), (e) => e.code === 'open');
  assert.throws(() => openBytes(key, blob.subarray(0, blob.length - 8)), (e) => e.code === 'open' || e.code === 'shape');
  assert.throws(() => openBytes(key, Buffer.from('not-a-blob')), (e) => e.code === 'shape');
  assert.throws(() => openBytes(key, 'a string is not a blob'), (e) => e.code === 'shape');
  // seal input validation
  assert.throws(() => sealBytes(Buffer.alloc(16), pt), (e) => e.code === 'seal');
});

test('envelope strings: sealed-string form round trips; the token NEVER appears in an envelope (proof f, wire)', () => {
  const token = crypto.randomBytes(16).toString('hex');
  const key = deriveEncKey(token, 'agent01');
  const s = sealString(key, 'b32-task-reply-body');
  assert.ok(isSealedString(s));
  assert.ok(s.startsWith(ENV_PREFIX));
  assert.equal(openString(key, s), 'b32-task-reply-body');
  assert.throws(() => openString(key, 'plaintext-reply'), (e) => e.code === 'shape');
  assert.throws(() => openString(key, ENV_PREFIX + '!!!not-base64url!!!'), EnvelopeError);
  // a tampered sealed string fails typed
  const tampered = s.slice(0, -3) + (s.endsWith('AAA') ? 'BBB' : 'AAA');
  assert.throws(() => openString(key, tampered), (e) => e instanceof EnvelopeError && (e.code === 'open' || e.code === 'shape'));
  // TOKEN CONFIDENTIALITY: neither the binary blob nor the string form contains the
  // token (hex), its base64, or any 8-char substring of it — envelopes are AEAD output.
  const blob = sealBytes(key, Buffer.from('x'));
  assert.ok(!blob.toString('hex').includes(token));
  assert.ok(!blob.toString('base64').includes(Buffer.from(token).toString('base64')));
  assert.ok(!s.includes(token) && !s.includes(token.slice(0, 8)));
  // mode normalization: strict enum, typed refusal
  assert.deepEqual(ENC_MODES, ['off', 'preferred', 'required']);
  assert.equal(normalizeEncMode(' REQUIRED '), 'required');
  assert.throws(() => normalizeEncMode('sometimes'), (e) => e instanceof EnvelopeError && e.code === 'mode');
});

// ---------------- negotiation: settings + channel mode resolution ----------------
test('enc.mode: schema enum + channel resolution (constructor wins; settings floor; garbage throws)', () => {
  const s = Settings.for(freshEng());
  assert.equal(s.get('enc.mode'), 'preferred', 'schema default is the backward-compatible mode');
  assert.equal(s.set('enc.mode', 'required'), 'required');
  assert.throws(() => s.set('enc.mode', 'maybe'), TypeError);
  // channel resolution: explicit constructor option wins over the engagement setting
  const eng = freshEng();
  Settings.for(eng).set('enc.mode', 'required');
  const scope = { engagement: eng, signedBy: 'test', cidrs: ['127.0.0.0/8'] };
  const chSet = new CallbackChannel({ scope });
  assert.equal(chSet.encMode, 'required', 'the engagement setting is the floor');
  const chOpt = new CallbackChannel({ scope, enc: 'off' });
  assert.equal(chOpt.encMode, 'off', 'the constructor option wins');
  assert.throws(() => new CallbackChannel({ scope, enc: 'loud-ish' }), (e) => e instanceof EnvelopeError && e.code === 'mode');
  // default resolution with no setting anywhere: preferred
  const chDef = new CallbackChannel({ scope: { engagement: freshEng(), cidrs: ['127.0.0.0/8'] } });
  assert.equal(chDef.encMode, 'preferred');
  assert.equal(chDef.encStatus().mode, 'preferred');
});

// ---------------- (a) http round-trip through the REAL intake ----------------
test('enc http: sealed pull reply + sealed result body round-trip the REAL /c /r routes', async () => {
  const { ch, port, events } = await armed({ enc: 'required' });
  try {
    const { agentId, token } = ch.registerAgent({ label: 'enc-http' });
    const taskId = ch.task(agentId, 'note', 'enc-http-secret');
    // WIRE-SHAPE PROOF, manual pull: valid HMAC + capability header -> the body is sealed
    const r = await fetch(`http://127.0.0.1:${port}/c`, {
      headers: { 'x-agent': agentId, 'x-seq': '1', 'x-auth': hmac(token, agentId + ':1:pull'), 'x-varvel-enc': '1' },
    });
    assert.equal(r.status, 200);
    const body = await r.text();
    assert.ok(isSealedString(body), 'the task body left the listener sealed');
    assert.ok(!body.includes('enc-http-secret'), 'no plaintext on the wire');
    const task = JSON.parse(openString(deriveEncKey(token, agentId), body));
    assert.equal(task.taskId, taskId);
    assert.equal(task.data, 'enc-http-secret', 'the agent-side key opens it');
    assert.ok(events.some((e) => e.type === 'enc.negotiated' && e.via === 'capability' && e.transport === 'http'));
    // manual sealed push: seal the result, HMAC signs the CIPHERTEXT (encrypt-then-MAC)
    const sealedBody = sealBytes(deriveEncKey(token, agentId), Buffer.from('http-result-secret'));
    const pr = await fetch(`http://127.0.0.1:${port}/r`, {
      method: 'POST', body: sealedBody,
      headers: { 'x-agent': agentId, 'x-seq': '2', 'x-task': taskId, 'x-auth': hmac(token, agentId + ':2:' + taskId + ':' + sha256(sealedBody)) },
    });
    assert.equal(pr.status, 200);
    const rs = ch.results(agentId, { taskId });
    assert.equal(rs.length, 1);
    assert.equal(rs[0].data, 'http-result-secret', 'the listener opened the sealed body');
    assert.equal(ch.agentsView()[0].enc, true);
    assert.equal(ch.encStatus().agents.enc, 1);
  } finally { await ch.disarm(); }
});

test('enc http: a REAL enc SimAgent round-trips a task on a required-mode channel', async () => {
  const { ch, port, events } = await armed({ enc: 'required' });
  const cred = ch.registerAgent({ label: 'sim-enc' });
  const agent = new SimAgent({ url: 'http://127.0.0.1:' + port, agentId: cred.agentId, token: cred.token, interval: 250, jitter: 0, enc: true, dir: join(WORK, 'sim-http') });
  try {
    const taskId = ch.task(cred.agentId, 'note', 'sim-enc-roundtrip');
    const run = agent.run({ onTick: () => {} });
    let got = null; // results() DRAINS — capture inside the poll, never poll-then-read
    assert.ok(await waitFor(() => { const r = ch.results(cred.agentId, { taskId }); if (r.length) { got = r[0]; return true; } return false; }, 6000), 'the enc sim-agent pulled, executed, and pushed sealed');
    assert.equal(got.data, 'noted: sim-enc-roundtrip');
    agent.stop();
    await run.catch(() => {});
    assert.ok(events.some((e) => e.type === 'result.received' && e.transport === 'http'));
  } finally { agent.stop(); await ch.disarm(); }
});

// ---------------- inheritance: dns codec / stg / ghc / ws ride the same layer ----------------
test('enc dns-codec: /d wire carries sealed pull replies + sealed push chunks', async () => {
  const { ch, port, events } = await armed({ enc: 'preferred' });
  try {
    const { agentId, token } = ch.registerAgent({ label: 'enc-dns' });
    const taskId = ch.task(agentId, 'note', 'dns-secret');
    // wire shape on /d: the reply text is a sealed string
    const q = encodeQuery({ a: agentId, s: 1, h: hmac(token, agentId + ':1:pull'), ec: 1 });
    const r = await fetch(`http://127.0.0.1:${port}/d/${q}`);
    const text = await r.text();
    assert.ok(isSealedString(text), 'the /d reply is sealed');
    const task = JSON.parse(b32decode(openString(deriveEncKey(token, agentId), text)).toString('utf8'));
    assert.equal(task.taskId, taskId);
    // a REAL enc DnsTransport round trip through the same intake (the manual probe
    // above consumed seq 1 — the transport's first pull must start past it)
    const t = new DnsTransport({ url: 'http://127.0.0.1:' + port, agentId, token, enc: true });
    t.seq = 1;
    const taskId2 = ch.task(agentId, 'note', 'dns-secret-2');
    const got = await t.pull();
    assert.equal(got.taskId, taskId2);
    await t.push(taskId2, 'dns-result-secret');
    let got2 = null; // results() DRAINS — capture inside the poll
    assert.ok(await waitFor(() => { const r = ch.results(agentId, { taskId: taskId2 }); if (r.length) { got2 = r[0]; return true; } return false; }));
    assert.equal(got2.data, 'dns-result-secret');
    assert.ok(events.some((e) => e.type === 'task.resulted' && e.transport === 'dns-codec'), 'the push completed through the /d intake');
    t.close();
  } finally { await ch.disarm(); }
});

test('enc stg: image-carried envelopes seal end-to-end (content cover + content secrecy)', async () => {
  const { ch, port } = await armed({ enc: 'preferred', stg: {} });
  try {
    const { agentId, token } = ch.registerAgent({ label: 'enc-stg' });
    const t = new StgTransport({ url: 'http://127.0.0.1:' + port, agentId, token, enc: true, width: 64, height: 64 });
    const taskId = ch.task(agentId, 'note', 'stg-secret');
    const got = await t.pull();
    assert.equal(got.taskId, taskId, 'the sealed reply rode the PNG pixels and opened');
    await t.push(taskId, 'stg-result-secret');
    let rs = null; // results() DRAINS — capture inside the poll
    assert.ok(await waitFor(() => { const r = ch.results(agentId, { taskId }); if (r.length) { rs = r[0]; return true; } return false; }));
    assert.equal(rs.data, 'stg-result-secret');
  } finally { await ch.disarm(); }
});

test('enc ghc: mailbox payloads seal; the signed sealed down-reply opens agent-side', () => {
  const token = crypto.randomBytes(16).toString('hex');
  const agentId = 'ghcagent';
  // pull carries the capability flag
  const p = pullPayload({ agentId, token, seq: 7, enc: true });
  assert.equal(p.ec, 1);
  assert.equal(p.h, hmac(token, agentId + ':7:pull'), 'the HMAC discipline is unchanged');
  // push chunks are sealed BEFORE the per-chunk HMAC (encrypt-then-MAC)
  const parts = pushPayloads({ agentId, token, taskId: 't1', body: 'x'.repeat(9000), nextSeq: (() => { let s = 10; return () => ++s; })(), enc: true });
  assert.equal(parts.length, 3);
  for (const part of parts) {
    const blob = Buffer.from(part.d, 'base64');
    assert.ok(isSealedBytes(blob), 'every mailbox chunk is ciphertext');
    assert.ok(!blob.toString('utf8').includes('xxx'));
    assert.equal(part.h, hmac(token, [agentId, part.s, 't1', part.i, part.n, part.d].join(':')), 'HMAC over ciphertext, formula unchanged');
  }
  // the shared intake opens them (feed the exact payloads through _dnsPayload)
  return (async () => {
    const { ch } = await armed({ enc: 'preferred' });
    try {
      const reg = ch.registerAgent({ label: 'enc-ghc' });
      const taskId = ch.task(reg.agentId, 'note', 'ghc-secret');
      const ups = pushPayloads({ agentId: reg.agentId, token: reg.token, taskId, body: 'ghc-result-secret', nextSeq: (() => { let s = 0; return () => ++s; })(), enc: true });
      for (const up of ups) assert.equal(ch._dnsPayload(up, 'ghc-mailbox', 'ghc'), '');
      assert.equal(ch.results(reg.agentId, { taskId })[0].data, 'ghc-result-secret');
      // down direction: the channel's signed down-comment body carries the sealed reply
      const replyStr = ch._sealDown(ch.agents.get(reg.agentId), b32encode(Buffer.from(JSON.stringify({ taskId, kind: 'note', data: 'ghc-secret' }))));
      assert.ok(isSealedString(replyStr));
      const body = downCommentBody({ agentId: reg.agentId, replyStr, token: reg.token }); // signature rides the SEALED string
      assert.ok(typeof body === 'string' && body.includes('ghc1:'));
      const task = decodeReplyEnc(replyStr, { agentId: reg.agentId, token: reg.token });
      assert.equal(task.taskId, taskId);
      assert.equal(decodeReplyEnc('b32-plaintext', { agentId: reg.agentId, token: reg.token }), null, 'an unsealed reply is refused');
    } finally { await ch.disarm(); }
  })();
});

test('enc ws: sealed task FRAMES + sealed push frames on the push wire; required-mode refusal', async () => {
  const net = await import('node:net');
  const { WsParser, buildFrame } = await import('../engine/wsframe.mjs');
  const wsClient = (port, query) => {
    const messages = [];
    const parser = new WsParser();
    const sock = net.connect(port, '127.0.0.1');
    sock.on('error', () => {});
    let pre = Buffer.alloc(0), handshook = false;
    const ready = new Promise((resolve) => {
      const timer = setTimeout(() => resolve(0), 3000);
      const feed = (buf) => { try { for (const f of parser.feed(buf)) messages.push(f); } catch { /* test client */ } };
      sock.on('data', (d) => {
        if (!handshook) {
          pre = Buffer.concat([pre, d]);
          const idx = pre.indexOf('\r\n\r\n');
          if (idx < 0) return;
          const status = Number((pre.slice(0, idx).toString('latin1').split('\r\n')[0] || '').split(/\s+/)[1]) || 0;
          handshook = true; clearTimeout(timer); resolve(status);
          if (pre.length > idx + 4) feed(pre.slice(idx + 4));
          return;
        }
        feed(d);
      });
      sock.on('connect', () => sock.write('GET /ws?' + query + ' HTTP/1.1\r\nhost: 127.0.0.1\r\nupgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-key: ' + crypto.randomBytes(16).toString('base64') + '\r\nsec-websocket-version: 13\r\n\r\n'));
    });
    const send = (obj) => sock.write(buildFrame({ opcode: 1, payload: Buffer.from(JSON.stringify(obj), 'utf8'), mask: true }));
    const next = async (timeoutMs = 2000) => {
      const start = Date.now();
      while (!messages.length) { if (Date.now() - start > timeoutMs) return null; await tick(10); }
      return messages.shift();
    };
    return { ready, send, next, close: () => { try { sock.destroy(); } catch {} } };
  };

  // required mode: a capability-less upgrade is refused (observable 403 — the ws denial shape)
  {
    const { ch, port, events } = await armed({ enc: 'required' });
    try {
      const { agentId, token } = ch.registerAgent({ label: 'ws-plain' });
      const c = wsClient(port, `a=${agentId}&s=1&h=${hmac(token, agentId + ':1:ws')}`);
      assert.equal(await c.ready, 403);
      c.close();
      assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'enc-required'), 'plaintext ws upgrade refused loudly');
    } finally { await ch.disarm(); }
  }
  // preferred mode with ec=1: task frames arrive SEALED; sealed push frames land
  {
    const { ch, port } = await armed({ enc: 'preferred' });
    try {
      const { agentId, token } = ch.registerAgent({ label: 'ws-enc' });
      const taskId = ch.task(agentId, 'note', 'ws-secret');
      const key = deriveEncKey(token, agentId);
      const c = wsClient(port, `a=${agentId}&s=1&h=${hmac(token, agentId + ':1:ws')}&ec=1`);
      assert.equal(await c.ready, 101);
      const f = await c.next();
      const payload = f.payload.toString('utf8');
      assert.ok(isSealedString(payload), 'the pushed task frame is a sealed string');
      assert.ok(!payload.includes('ws-secret'));
      const task = JSON.parse(openString(key, payload));
      assert.equal(task.taskId, taskId);
      // sealed push frame back
      const d = sealBytes(key, Buffer.from('ws-result-secret')).toString('base64');
      c.send({ a: agentId, s: 2, h: hmac(token, [agentId, 2, taskId, 0, 1, d].join(':')), t: taskId, k: 'push', i: 0, n: 1, d });
      let rs = null; // results() DRAINS — capture inside the poll
      assert.ok(await waitFor(() => { const r = ch.results(agentId, { taskId }); if (r.length) { rs = r[0]; return true; } return false; }));
      assert.equal(rs.data, 'ws-result-secret');
      c.close();
    } finally { await ch.disarm(); }
  }
});

// ---------------- (d) mixed-mode negotiation ----------------
test('enc modes: preferred serves a mixed fleet honestly; required refuses plaintext loudly; off refuses sealed', async () => {
  // PREFERRED: a plaintext old agent and an enc new agent share one channel
  {
    const { ch, port, events } = await armed({ enc: 'preferred' });
    try {
      const oldCred = ch.registerAgent({ label: 'old-agent' });
      const newCred = ch.registerAgent({ label: 'new-agent' });
      const oldTask = ch.task(oldCred.agentId, 'note', 'old-plaintext');
      const newTask = ch.task(newCred.agentId, 'note', 'new-sealed');
      // old agent: today's exact plaintext wire, unchanged
      const r1 = await fetch(`http://127.0.0.1:${port}/c`, { headers: { 'x-agent': oldCred.agentId, 'x-seq': '1', 'x-auth': hmac(oldCred.token, oldCred.agentId + ':1:pull') } });
      assert.equal(r1.status, 200);
      const j = await r1.json();
      assert.equal(j.taskId, oldTask, 'plaintext agent works exactly as before');
      assert.equal(ch.agents.get(oldCred.agentId).enc, null, 'never ratcheted — an old agent stays what it is');
      // new agent: sealed
      const r2 = await fetch(`http://127.0.0.1:${port}/c`, { headers: { 'x-agent': newCred.agentId, 'x-seq': '1', 'x-auth': hmac(newCred.token, newCred.agentId + ':1:pull'), 'x-varvel-enc': '1' } });
      assert.ok(isSealedString(await r2.text()));
      assert.equal(ch.agents.get(newCred.agentId).enc, true);
      assert.ok(events.some((e) => e.type === 'enc.negotiated'));
      // DOWNGRADE RATCHET: once enc-proven, PLAINTEXT CONTENT from that agent is refused
      const d = Buffer.from('downgrade-attempt').toString('base64');
      const forged = { a: newCred.agentId, s: 2, h: hmac(newCred.token, [newCred.agentId, 2, newTask, 0, 1, d].join(':')), t: newTask, k: 'push', i: 0, n: 1, d };
      assert.equal(ch._dnsPayload(forged, '127.0.0.1', 'dns'), '', 'plaintext content from an enc agent gets the uniform deny');
      assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'enc-downgrade'), 'downgrade refused loudly');
      assert.equal(ch.results(newCred.agentId, { taskId: newTask }).length, 0, 'no cleartext landed');
    } finally { await ch.disarm(); }
  }
  // REQUIRED: plaintext pull (http header-less AND codec ec-less) refused loudly, uniform on the wire
  {
    const { ch, port, events } = await armed({ enc: 'required' });
    try {
      const { agentId, token } = ch.registerAgent({ label: 'old-on-required' });
      const r = await fetch(`http://127.0.0.1:${port}/c`, { headers: { 'x-agent': agentId, 'x-seq': '1', 'x-auth': hmac(token, agentId + ':1:pull') } });
      assert.equal(r.status, 204, 'the wire answer stays 204-uniform');
      assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'enc-required' && e.agentId === agentId), 'the ledger is the loud place');
      assert.equal(ch.agents.get(agentId).checkins, 0, 'a refused pull consumes nothing');
      const q = encodeQuery({ a: agentId, s: 1, h: hmac(token, agentId + ':1:pull') }); // codec pull, no ec
      const r2 = await fetch(`http://127.0.0.1:${port}/d/${q}`);
      assert.equal(await r2.text(), '', 'codec plaintext pull: the uniform empty answer');
      assert.ok(events.filter((e) => e.reason === 'enc-required').length >= 2);
      // and plaintext CONTENT is refused the same way
      const taskId = ch.task(agentId, 'note', 'will-not-ship');
      const d = Buffer.from('cleartext').toString('base64');
      const p = { a: agentId, s: 3, h: hmac(token, [agentId, 3, taskId, 0, 1, d].join(':')), t: taskId, k: 'push', i: 0, n: 1, d };
      assert.equal(ch._dnsPayload(p, '127.0.0.1', 'dns'), '');
      assert.ok(events.some((e) => e.reason === 'enc-required' && e.agentId === agentId));
      assert.equal(ch.results(agentId, { taskId }).length, 0);
    } finally { await ch.disarm(); }
  }
  // OFF: the layer is disabled — sealed content is refused loudly, plaintext flows
  {
    const { ch, events } = await armed({ enc: 'off' });
    try {
      const { agentId, token } = ch.registerAgent({ label: 'on-off' });
      const taskId = ch.task(agentId, 'note', 'off-mode');
      const d = sealBytes(deriveEncKey(token, agentId), Buffer.from('sealed')).toString('base64');
      const p = { a: agentId, s: 1, h: hmac(token, [agentId, 1, taskId, 0, 1, d].join(':')), t: taskId, k: 'push', i: 0, n: 1, d };
      assert.equal(ch._dnsPayload(p, '127.0.0.1', 'dns'), '');
      assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'enc-disabled'));
      const d2 = Buffer.from('plaintext-ok').toString('base64');
      const p2 = { a: agentId, s: 2, h: hmac(token, [agentId, 2, taskId, 0, 1, d2].join(':')), t: taskId, k: 'push', i: 0, n: 1, d: d2 };
      assert.equal(ch._dnsPayload(p2, '127.0.0.1', 'dns'), '');
      assert.equal(ch.results(agentId, { taskId })[0].data, 'plaintext-ok');
    } finally { await ch.disarm(); }
  }
});

// ---------------- (c) tamper at the REAL intake: typed error + audit, no oracle ----------------
test('enc tamper: HMAC-valid/wrong-key sealed push fails AEAD open -> typed audit, NOTHING stored', async () => {
  const { ch, events } = await armed({ enc: 'required' });
  try {
    const victim = ch.registerAgent({ label: 'victim' });
    const other = ch.registerAgent({ label: 'other' });
    const taskId = ch.task(victim.agentId, 'note', 'oracle-test');
    // A VALID HMAC over a blob sealed with the WRONG key (an insider/confusion case —
    // the HMAC gate alone cannot catch it): the AEAD open must fail, typed + audited.
    const d = sealBytes(deriveEncKey(other.token, other.agentId), Buffer.from('forged-content')).toString('base64');
    const p = { a: victim.agentId, s: 1, h: hmac(victim.token, [victim.agentId, 1, taskId, 0, 1, d].join(':')), t: taskId, k: 'push', i: 0, n: 1, d };
    assert.equal(ch._dnsPayload(p, '127.0.0.1', 'dns'), '', 'uniform deny — no decryption oracle');
    const evt = events.find((e) => e.type === 'enc.open-failed');
    assert.ok(evt, 'the AEAD failure is its own audit event');
    assert.equal(evt.agentId, victim.agentId);
    assert.equal(evt.code, 'open');
    assert.ok(!JSON.stringify(evt).includes('forged-content'), 'the audit carries NO plaintext');
    assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'enc-open-failed'));
    assert.equal(ch.results(victim.agentId, { taskId }).length, 0, 'nothing landed');
    assert.equal(ch.agents.get(victim.agentId).ledger.get(taskId).resultAt, null, 'the ledger task never resulted');
    assert.equal(ch.agents.get(victim.agentId).seq, 0, 'a refused envelope consumes no seq');
    // and the classic outsider tamper (no valid HMAC) dies at the HMAC gate first —
    // encrypt-then-MAC: the AEAD layer never even runs for a forgery
    const d2 = Buffer.from(sealBytes(deriveEncKey(victim.token, victim.agentId), Buffer.from('x')));
    d2[d2.length - 3] ^= 1;
    const d2s = d2.toString('base64');
    const p2 = { a: victim.agentId, s: 1, h: '0'.repeat(64), t: taskId, k: 'push', i: 0, n: 1, d: d2s };
    assert.equal(ch._dnsPayload(p2, '127.0.0.1', 'dns'), '');
    assert.ok(events.some((e) => e.reason === 'dns-push-reject'), 'forgery dies at the HMAC gate');
    assert.equal(events.filter((e) => e.type === 'enc.open-failed').length, 1, 'AEAD never ran for the forgery');
  } finally { await ch.disarm(); }
});

// ---------------- (e) replay protection unchanged under the envelope layer ----------------
test('enc replay: strict seq still decides (replay dies stale); key re-derivation opens NO replay window', async () => {
  const { ch, events } = await armed({ enc: 'required' });
  try {
    const { agentId, token } = ch.registerAgent({ label: 'replay-enc' });
    const key = deriveEncKey(token, agentId);
    const taskId = ch.task(agentId, 'note', 'replay-me');
    const mkPush = (s, body) => {
      const d = sealBytes(key, Buffer.from(body)).toString('base64');
      return { a: agentId, s, h: hmac(token, [agentId, s, taskId, 0, 1, d].join(':')), t: taskId, k: 'push', i: 0, n: 1, d };
    };
    // seq 1 accepted; the EXACT envelope replayed dies on the stale-seq gate.
    // (results() DRAINS — accumulate across the assertions.)
    let drained = 0;
    const p1 = mkPush(1, 'first');
    assert.equal(ch._dnsPayload(p1, '127.0.0.1', 'dns'), '');
    drained += ch.results(agentId, { taskId }).length;
    assert.equal(drained, 1);
    assert.equal(ch._dnsPayload(p1, '127.0.0.1', 'dns'), '');
    assert.ok(events.some((e) => e.reason === 'dns-reject'), 'replayed sealed envelope: stale-seq reject, unchanged semantics');
    drained += ch.results(agentId, { taskId }).length;
    assert.equal(drained, 1, 'exactly-once despite the replay');
    // forward jump still allowed (a lost envelope is not a desync — unchanged)
    const p5 = mkPush(5, 'fifth');
    assert.equal(ch._dnsPayload(p5, '127.0.0.1', 'dns'), '');
    drained += ch.results(agentId, { taskId }).length;
    assert.equal(drained, 2);
    // KEY-ROTATION SAFETY: a fresh key schedule (new agent instance / re-derived keys —
    // the AEAD layer holds NO replay state) cannot resurrect an old envelope: replay
    // protection lives at the HMAC seq layer, so a rekey opens no window.
    const keyRotated = deriveEncKey(token, agentId); // deterministic re-derivation = the rekey event for this hierarchy
    const oldReplay = mkPush(2, 'stale-content'); // a seq already consumed
    oldReplay.h = hmac(token, [agentId, 2, taskId, 0, 1, oldReplay.d].join(':'));
    assert.equal(ch._dnsPayload(oldReplay, '127.0.0.1', 'dns'), '');
    drained += ch.results(agentId, { taskId }).length;
    assert.equal(drained, 2, 'the rekeyed schedule replays nothing');
    void keyRotated;
  } finally { await ch.disarm(); }
});

// ---------------- (a)+(b) THE MESH PROOF: parent forwards ciphertext it cannot read ----------------
test('enc mesh e2e: the relay parent forwards OPAQUE ciphertext — its own link keys cannot open it', async (t2) => {
  if (process.platform !== 'win32') return t2.skip('named pipes are the Windows build target');
  const { ch, port, events } = await armed({ enc: 'required' });
  const pcred = ch.registerAgent({ label: 'parent' });
  const ccred = ch.registerLinkedAgent({ parentId: pcred.agentId, label: 'enc-child' });
  // required mode governs EVERY agent on the channel — the parent's own check-in leg
  // must be enc too, or its own pulls are refused and it never receives link-listen.
  const parent = new SimAgent({ url: 'http://127.0.0.1:' + port, agentId: pcred.agentId, token: pcred.token, interval: 300, jitter: 0, enc: true, label: 'parent', dir: join(WORK, 'sim-parent') });
  let child = null;
  // The parent's decoded view of the child's traffic: exactly what its PipeServer hands
  // relayUp AFTER the link layer is peeled (and the down string it wraps back).
  const parentView = [];
  try {
    const parentRun = parent.run({ onTick: () => {} });
    assert.ok(await waitFor(() => parent._link && parent._link._server), 'the pipe server is up inside the parent');
    const origRelay = parent._link._relayUp.bind(parent._link);
    parent._link._relayUp = async (p) => { const down = await origRelay(p); parentView.push({ up: p, down }); return down; };
    child = new SimAgent({ transport: 'smb', link: ccred.link.linkId, agentId: ccred.agentId, token: ccred.token, interval: 300, jitter: 0, enc: true, label: 'enc-child', dir: join(WORK, 'sim-child') });
    // A MULTI-CHUNK result: 9,014 bytes = three sealed push frames through the pipe —
    // the chunk-reassembly path is part of the proof, not just the single-frame one.
    const SECRET_BODY = 'MESH-SECRET-TASK-' + 'x'.repeat(9000);
    const taskId = ch.task(ccred.agentId, 'note', SECRET_BODY);
    const childRun = child.run({ onTick: () => {} });
    let meshGot = null; // results() DRAINS — capture inside the poll
    assert.ok(await waitFor(() => { const r = ch.results(ccred.agentId, { taskId }); if (r.length) { meshGot = r[0]; return true; } return false; }, 8000), 'the sealed round trip crossed the mesh');
    assert.equal(meshGot.data, 'noted: ' + SECRET_BODY, 'the LISTENER reads the full reassembled content fine');
    parent.stop(); child.stop();
    await Promise.allSettled([parentRun, childRun]);

    // ——— THE NEGATIVE ASSERTION (proof b): the parent's whole decoded view is ciphertext ———
    assert.ok(parentView.length >= 3, 'the parent relayed the pull and the push chunks');
    const pushes = parentView.filter((v) => v.up.k === 'push');
    assert.equal(pushes.length, 3, 'the multi-chunk result crossed as three opaque frames');
    const blobs = pushes.map((v) => Buffer.from(v.up.d, 'base64'));
    for (const b of blobs) {
      assert.ok(isSealedBytes(b), 'the parent sees sealed blobs, not result bytes');
      assert.ok(!b.toString('latin1').includes('MESH-SECRET') && !b.toString('latin1').includes('noted'), 'no plaintext in the parent view');
    }
    const blob = blobs[0];
    // the down string the parent wrapped into its link layer: sealed too
    const pullView = parentView.find((v) => !v.up.k);
    assert.ok(pullView && isSealedString(pullView.down), 'the task reply crossed the parent sealed');
    assert.ok(!pullView.down.includes('MESH-SECRET-TASK'));
    // the parent's ACTUAL key material — the link verify key from its link-listen task —
    // cannot open EITHER direction. This is the compromised-parent property, proven.
    const verifyKey = parent._link.hub._children.get(ccred.agentId);
    assert.ok(/^[0-9a-f]{64}$/.test(verifyKey), 'the parent holds a link verify key');
    assert.notEqual(verifyKey, ccred.token, 'the parent never held the child token');
    const sessKeys = { up: hmac(verifyKey, 'sess-up:' + 'x'.repeat(16)), down: hmac(verifyKey, 'sess-down:' + 'x'.repeat(16)) };
    for (const km of [verifyKey, sessKeys.up, sessKeys.down]) {
      assert.throws(() => openBytes(deriveEncKey(km, ccred.agentId), blob), EnvelopeError, 'parent key material cannot open the UP content');
      assert.throws(() => openString(deriveEncKey(km, ccred.agentId), pullView.down), EnvelopeError, 'parent key material cannot open the DOWN content');
      assert.throws(() => openBytes(Buffer.from(km, 'hex'), blob), EnvelopeError, 'even RAW, the link key is not an envelope key');
    }
    // governance evidence through the mesh with the envelope layer on
    assert.ok(events.some((e) => e.type === 'link.relay' && e.agentId === pcred.agentId));
    assert.ok(events.some((e) => e.type === 'agent.checkin' && e.agentId === ccred.agentId && e.transport === 'smb'));
    assert.ok(events.some((e) => e.type === 'enc.negotiated' && e.agentId === ccred.agentId), 'the child negotiated enc THROUGH the link');
    assert.equal(ch.agents.get(ccred.agentId).enc, true);
  } finally {
    try { if (child) await child._pipe?.close(); } catch {}
    try { if (parent._link) await parent._link.close(); } catch {}
    await ch.disarm();
  }
});

// ---------------- agent-side downgrade refusal (the child's half of (d)) ----------------
test('enc agent policy: an enc child REFUSES a plaintext task reply (loud note, never tasked from)', async () => {
  // A middlebox that strips the capability flag gets the channel to answer plaintext —
  // the enc agent's own policy is the second half of the anti-downgrade story.
  const { ch, port } = await armed({ enc: 'preferred' });
  try {
    const { agentId, token } = ch.registerAgent({ label: 'plain-server' });
    ch.task(agentId, 'note', 'plaintext-reply');
    const t = new DnsTransport({ url: 'http://127.0.0.1:' + port, agentId, token, enc: true });
    // The channel never saw ec (we lie by omission: enc transport, no flag sent) —
    // emulate by forcing the record back to unknown right before the reply is built.
    // Simplest honest emulation: pull against a channel whose agent record is not ratcheted.
    const q = encodeQuery({ a: agentId, s: 1, h: hmac(token, agentId + ':1:pull') }); // NO ec flag
    const r = await fetch(`http://127.0.0.1:${port}/d/${q}`);
    const text = await r.text();
    assert.ok(!isSealedString(text) && text.length > 0, 'the channel answered plaintext (no capability was proven)');
    assert.equal(t._decodeTaskReply(text), null, 'the enc transport refuses it');
    assert.equal(t.lastError, 'enc-plaintext-reply', 'loud, typed agent-side signal');
    t.close();
  } finally { await ch.disarm(); }
});

// Teardown grace: on win32, --test-force-exit can fire while sockets/pipes are still
// closing (libuv UV_HANDLE_CLOSING assert). Same guard as pipelink/ws/doh.
test('teardown grace for pipe/socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});
