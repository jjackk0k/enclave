// VARVEL — ICMP fallback codec for the governed channel (last-resort transport shape).
//
// Frames the same governed payloads into ICMP echo (type 8 request / type 0 reply) packets:
// a VARVEL magic header + kind + seq + chunk indexing, RFC 1071 checksum, chunk/reassembly
// for result bodies. Same contract as the DNS codec: governance lives ABOVE this layer
// (HMAC/seq/scope in the payload itself — the codec is just the envelope).
//
// HONESTY NOTICE (the line, applied to ourselves): Node has NO raw-ICMP socket access, so
// this process cannot terminate ICMP alone. The channel spawns agents/icmp-bridge.py (a
// privileged raw-socket byte pump, opt-in via VARVEL_ICMP=1) to terminate the transport
// for real — and icmpCapability() only reports supported:true when handed a channel
// status whose liveVerified flag was set by an OBSERVED authenticated round trip this
// session. No observation, no claim: the default stays supported:false.

const MAGIC = Buffer.from([0x56, 0x43]); // 'VC'
const MAX_PAYLOAD = 512;                 // conservative per-packet data (MTU-friendly)

// RFC 1071 internet checksum.
export function inetChecksum(buf) {
  let sum = 0;
  for (let i = 0; i < buf.length - 1; i += 2) sum = (sum + buf.readUInt16BE(i)) >>> 0;
  if (buf.length % 2) sum = (sum + (buf[buf.length - 1] << 8)) >>> 0;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}

// Build an ICMP echo packet. kind: 'pull' | 'push' | 'reply'. Frames carry (idx,cnt) for
// chunking; cnt=1 idx=0 for unchunked payloads.
export function icmpPacket({ type = 8, id = 0x5601, seq = 1, kind = 'pull', idx = 0, cnt = 1, data = Buffer.alloc(0) }) {
  const KIND = { pull: 1, push: 2, reply: 3 };
  const k = KIND[kind];
  if (!k) throw new TypeError('icmpPacket: bad kind ' + kind);
  const payload = Buffer.isBuffer(data) ? data : Buffer.from(String(data ?? ''));
  if (payload.length > MAX_PAYLOAD) throw new RangeError('icmpPacket: payload > ' + MAX_PAYLOAD + ' (chunk it)');
  const body = Buffer.alloc(2 + 1 + 4 + 2 + 2 + 2 + payload.length);
  MAGIC.copy(body, 0);
  body.writeUInt8(k, 2);
  body.writeUInt32BE(seq >>> 0, 3);
  body.writeUInt16BE(idx, 7);
  body.writeUInt16BE(cnt, 9);
  body.writeUInt16BE(payload.length, 11);
  payload.copy(body, 13);
  const head = Buffer.alloc(8);
  head.writeUInt8(type, 0);
  head.writeUInt8(0, 1);          // code 0
  head.writeUInt16BE(0, 2);       // checksum placeholder
  head.writeUInt16BE(id & 0xffff, 4);
  head.writeUInt16BE(seq & 0xffff, 6);
  const packet = Buffer.concat([head, body]);
  packet.writeUInt16BE(inetChecksum(packet), 2);
  return packet;
}

// Parse + validate. Returns { type, id, seq, kind, idx, cnt, data } or null (fail-closed).
export function parseIcmpPacket(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 8 + 13) return null;
  if (inetChecksum(buf) !== 0) return null;
  const type = buf.readUInt8(0);
  if (type !== 8 && type !== 0) return null;
  if (buf[1] !== 0) return null;
  if (!buf.subarray(8, 10).equals(MAGIC)) return null;
  const KIND = { 1: 'pull', 2: 'push', 3: 'reply' };
  const kind = KIND[buf.readUInt8(10)];
  if (!kind) return null;
  const seq = buf.readUInt32BE(11);
  const idx = buf.readUInt16BE(15);
  const cnt = buf.readUInt16BE(17);
  const dlen = buf.readUInt16BE(19);
  if (cnt < 1 || cnt > 5000 || idx >= cnt) return null;
  if (8 + 13 + dlen !== buf.length) return null;
  return { type, id: buf.readUInt16BE(4), seq, kind, idx, cnt, data: Buffer.from(buf.subarray(21)) };
}

// Split a body into chunk descriptors ready for icmpPacket().
export function chunkPayload(buf, max = MAX_PAYLOAD) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(String(buf ?? ''));
  const chunks = [];
  for (let i = 0; i < b.length; i += max) chunks.push(b.subarray(i, Math.min(i + max, b.length)));
  if (!chunks.length) chunks.push(Buffer.alloc(0));
  return chunks.map((data, i) => ({ idx: i, cnt: chunks.length, data }));
}

// Reassemble validated frames (parseIcmpPacket outputs). Returns the body when complete,
// null when incomplete; throws on shape conflict (n changed mid-stream).
export function reassemble(frames) {
  if (!frames.length) return null;
  const cnt = frames[0].cnt;
  if (frames.some((f) => f.cnt !== cnt)) throw new Error('icmp reassemble: cnt changed mid-stream');
  const have = new Set(frames.map((f) => f.idx));
  if (have.size < cnt) return null;
  const ordered = [];
  for (let i = 0; i < cnt; i++) ordered.push(frames.find((f) => f.idx === i).data);
  return Buffer.concat(ordered);
}

// The capability story, honest by construction. Node cannot open raw ICMP sockets; the
// native bridge (agents/icmp-bridge.py, opt-in) terminates the transport when the host
// allows it. Pass the channel's live icmpStatus() to get the observed truth: supported
// flips true ONLY after an authenticated ICMP round trip was actually seen this session.
export function icmpCapability(live = null) {
  if (live && live.configured && live.armed && live.liveVerified) {
    return {
      codec: 'proven (round-trip, tamper rejection, chunk/reassembly — unit-tested)',
      transport: 'live-verified · native bridge round trip observed',
      supported: true,
      reason: 'agents/icmp-bridge.py terminated a real authenticated ICMP frame exchange this session (channel liveVerified).',
    };
  }
  return {
    codec: 'proven (round-trip, tamper rejection, chunk/reassembly — unit-tested)',
    transport: 'bridge-available · awaiting live verification',
    supported: false,
    reason: 'the Node runtime has no raw-ICMP socket access; agents/icmp-bridge.py (opt-in VARVEL_ICMP=1) terminates the transport when the host permits raw sockets. Not claimed live until an authenticated round trip is observed.',
  };
}
