// icmpcodec.test.mjs — ICMP fallback codec: round-trip, tamper rejection, chunking, honest capability.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inetChecksum, icmpPacket, parseIcmpPacket, chunkPayload, reassemble, icmpCapability } from '../engine/icmpcodec.mjs';

test('icmp packet round-trip: parse(encode(payload)) recovers everything, checksum valid', () => {
  const data = Buffer.from('governed payload bytes — HMAC lives above this layer');
  const p = icmpPacket({ type: 8, id: 0x5601, seq: 42, kind: 'push', idx: 2, cnt: 5, data });
  assert.equal(inetChecksum(p), 0);
  const q = parseIcmpPacket(p);
  assert.equal(q.type, 8);
  assert.equal(q.id, 0x5601);
  assert.equal(q.seq, 42);
  assert.equal(q.kind, 'push');
  assert.equal(q.idx, 2);
  assert.equal(q.cnt, 5);
  assert.deepEqual(q.data, data);
});

test('tamper rejection: any flipped byte fails the checksum; bad magic/type/shape rejected', () => {
  const p = icmpPacket({ type: 8, kind: 'pull', data: Buffer.from('abc') });
  const bad = Buffer.from(p);
  bad[20] ^= 0xff;
  assert.equal(parseIcmpPacket(bad), null);                       // checksum
  const badMagic = Buffer.from(p); badMagic[8] = 0x99;
  // recompute checksum so ONLY the magic is wrong
  badMagic.writeUInt16BE(0, 2);
  badMagic.writeUInt16BE(inetChecksum(badMagic), 2);
  assert.equal(parseIcmpPacket(badMagic), null);                  // magic
  const badType = Buffer.from(p); badType[0] = 13;
  badType.writeUInt16BE(0, 2); badType.writeUInt16BE(inetChecksum(badType), 2);
  assert.equal(parseIcmpPacket(badType), null);                   // type
  assert.equal(parseIcmpPacket(Buffer.from([1, 2, 3])), null);    // too short
  const badIdx = icmpPacket({ type: 8, kind: 'pull', idx: 0, cnt: 1, data: Buffer.alloc(0) });
  badIdx.writeUInt16BE(5, 15);                                    // idx corrupt: 5 >= cnt 1
  badIdx.writeUInt16BE(0, 2); badIdx.writeUInt16BE(inetChecksum(badIdx), 2);
  assert.equal(parseIcmpPacket(badIdx), null);
});

test('chunk + reassemble: a 2KB body survives fragmentation; incomplete stays null', () => {
  const body = Buffer.alloc(2048);
  for (let i = 0; i < body.length; i++) body[i] = i & 0xff;
  const frames = chunkPayload(body).map((c) => parseIcmpPacket(icmpPacket({ type: 8, kind: 'push', seq: 7, ...c })));
  assert.ok(frames.length >= 4);
  assert.deepEqual(reassemble(frames), body);
  assert.equal(reassemble(frames.slice(0, frames.length - 1)), null); // last chunk missing
  // empty body: one empty chunk, reassembles to empty
  const empty = chunkPayload(Buffer.alloc(0)).map((c) => parseIcmpPacket(icmpPacket({ type: 8, kind: 'push', ...c })));
  assert.deepEqual(reassemble(empty), Buffer.alloc(0));
});

test('oversized single payload refuses (must chunk); bad kind rejected', () => {
  assert.throws(() => icmpPacket({ type: 8, kind: 'push', data: Buffer.alloc(513) }), /chunk/);
  assert.throws(() => icmpPacket({ type: 8, kind: 'nope' }), /bad kind/);
});

test('capability is HONEST: unverified by default; flips ONLY on an observed live round trip', () => {
  const c = icmpCapability();
  assert.equal(c.supported, false);
  assert.match(c.reason, /no raw-ICMP/);
  assert.match(c.transport, /awaiting live verification/);
  // a configured-but-unverified bridge does NOT flip it
  assert.equal(icmpCapability({ configured: true, armed: true, liveVerified: false }).supported, false);
  // only an observed authenticated round trip does
  const v = icmpCapability({ configured: true, armed: true, liveVerified: true });
  assert.equal(v.supported, true);
  assert.match(v.transport, /live-verified/);
});
