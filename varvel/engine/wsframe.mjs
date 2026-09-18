// VARVEL - RFC 6455 WebSocket frame codec (gap#4), pure node: stdlib, zero deps.
//
// The ws PUSH transport terminates on the channel's EXISTING http server (an 'upgrade'
// listener on /ws), so the framing layer must live here in-process. No npm ws package:
// the codec is ~150 lines, dependency-free, and fail-closed by construction.
//
// Fail-closed contract: every protocol violation throws a typed WsError; the caller
// (engine/callback) closes the socket. A malformed peer never gets a partial parse,
// never gets a second chance on the same parser, and never takes the channel down.
//
// Scope of the implementation (what the ws transport actually needs):
//   - buildFrame: one complete frame (server->client unmasked, client->client masked)
//   - WsParser: a STREAMING parser - feed(Buffer) -> [{ opcode, payload, fin }]
//     Handles partial frames across arbitrary TCP chunk boundaries, 126/127 extended
//     payload lengths, masked and unmasked frames, fragmentation reassembly by opcode
//     (continuation frames), and control frames (ping/pong/close) interleaved between
//     fragments of a data message (RFC 6455 5.4 - control frames may be injected
//     mid-message and are surfaced immediately, in order).

import crypto from 'node:crypto';

// The RFC 6455 1.3 magic GUID for the Sec-WebSocket-Accept handshake hash.
export const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export const OP_CONT = 0x0;
export const OP_TEXT = 0x1;
export const OP_BINARY = 0x2;
export const OP_CLOSE = 0x8;
export const OP_PING = 0x9;
export const OP_PONG = 0xa;

// Typed protocol violation. `code` is the RFC 6455 close status the caller should
// echo in its close frame (1002 = protocol error, 1009 = message too big).
export class WsError extends Error {
  constructor(reason, code = 1002) {
    super('ws protocol violation: ' + reason);
    this.name = 'WsError';
    this.code = code;
  }
}

// accept-key helper: base64(sha1(key + GUID)) - the server half of the handshake.
export function acceptKey(key) {
  return crypto.createHash('sha1').update(String(key || '') + WS_GUID).digest('base64');
}

// Build ONE complete frame. opcode: OP_* constant. payload: Buffer (or string, utf8).
// mask: client->server frames MUST be masked per the RFC (the channel's parser
// enforces this); server->client frames are never masked. fin: false only when the
// caller is hand-fragmenting a message (the channel never does - one frame per task).
export function buildFrame({ opcode = OP_TEXT, payload = Buffer.alloc(0), mask = false, fin = true } = {}) {
  const p = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8');
  const len = p.length;
  let headLen = 2;
  if (len > 65535) headLen += 8;
  else if (len > 125) headLen += 2;
  const maskLen = mask ? 4 : 0;
  const buf = Buffer.allocUnsafe(headLen + maskLen + len);
  buf[0] = (fin ? 0x80 : 0x00) | (opcode & 0x0f);
  let off;
  if (len > 65535) { buf[1] = 127; buf.writeBigUInt64BE(BigInt(len), 2); off = 10; }
  else if (len > 125) { buf[1] = 126; buf.writeUInt16BE(len, 2); off = 4; }
  else { buf[1] = len; off = 2; }
  if (mask) {
    buf[1] |= 0x80;
    const key = crypto.randomBytes(4);
    key.copy(buf, off);
    off += 4;
    for (let i = 0; i < len; i++) buf[off + i] = p[i] ^ key[i & 3];
  } else if (len) {
    p.copy(buf, off);
  }
  return buf;
}

// Streaming frame parser. feed() returns the COMPLETE items yielded by this chunk
// (zero or more): data messages reassembled across fragments, and control frames
// surfaced in arrival order. Incomplete trailing bytes stay buffered for the next
// feed. expectMask: server-side parsers set true (RFC: client frames MUST be masked -
// an unmasked client frame is a protocol violation). maxFrame caps one frame,
// maxMessage caps a reassembled fragmented message.
export class WsParser {
  constructor({ expectMask = false, maxFrame = 8 * 1024 * 1024, maxMessage = 16 * 1024 * 1024 } = {}) {
    this.expectMask = !!expectMask;
    this.maxFrame = maxFrame;
    this.maxMessage = maxMessage;
    this._buf = Buffer.alloc(0);
    this._frag = null; // { opcode, chunks: [Buffer], size } while a data message is open
  }

  feed(chunk) {
    if (chunk && chunk.length) this._buf = this._buf.length ? Buffer.concat([this._buf, chunk]) : chunk;
    const out = [];
    for (;;) {
      const f = this._frame();
      if (!f) break; // incomplete - wait for more bytes
      if (f.opcode >= 0x8) {
        // Control frame: never fragmented (enforced in _frame), surfaced immediately
        // even when it arrived BETWEEN fragments of a data message (RFC 5.4).
        out.push({ opcode: f.opcode, payload: f.payload, fin: true });
        continue;
      }
      if (f.opcode === OP_CONT) {
        if (!this._frag) throw new WsError('continuation frame without an open message');
        this._frag.chunks.push(f.payload);
        this._frag.size += f.payload.length;
        if (this._frag.size > this.maxMessage) throw new WsError('reassembled message exceeds the cap', 1009);
        if (!f.fin) continue;
        const msg = { opcode: this._frag.opcode, payload: Buffer.concat(this._frag.chunks), fin: true };
        this._frag = null;
        out.push(msg);
        continue;
      }
      // New data frame (text/binary): illegal while a fragmented message is still open.
      if (this._frag) throw new WsError('new data frame while a fragmented message is open');
      if (f.fin) { out.push({ opcode: f.opcode, payload: f.payload, fin: true }); continue; }
      this._frag = { opcode: f.opcode, chunks: [f.payload], size: f.payload.length };
    }
    return out;
  }

  // Parse ONE frame off the head of the buffer. Returns null when the buffer holds
  // only a partial frame (header or payload incomplete) - bytes stay buffered.
  _frame() {
    const b = this._buf;
    if (b.length < 2) return null;
    const b0 = b[0], b1 = b[1];
    const fin = !!(b0 & 0x80);
    if (b0 & 0x70) throw new WsError('RSV bits set (no extensions are negotiated)');
    const opcode = b0 & 0x0f;
    if (opcode !== OP_CONT && opcode !== OP_TEXT && opcode !== OP_BINARY && opcode !== OP_CLOSE && opcode !== OP_PING && opcode !== OP_PONG) {
      throw new WsError('reserved opcode 0x' + opcode.toString(16));
    }
    const masked = !!(b1 & 0x80);
    if (this.expectMask && !masked) throw new WsError('unmasked client frame');
    const len7 = b1 & 0x7f;
    let off = 2;
    let len;
    if (len7 === 126) {
      if (b.length < 4) return null;
      len = b.readUInt16BE(2);
      if (len < 126) throw new WsError('non-minimal length encoding (126 for <126)');
      off = 4;
    } else if (len7 === 127) {
      if (b.length < 10) return null;
      const big = b.readBigUInt64BE(2);
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new WsError('payload length overflows safe integer', 1009);
      len = Number(big);
      if (len < 65536) throw new WsError('non-minimal length encoding (127 for <65536)');
      off = 10;
    } else {
      len = len7;
    }
    if (len > this.maxFrame) throw new WsError('frame payload exceeds the cap', 1009);
    if (opcode >= 0x8) {
      if (!fin) throw new WsError('fragmented control frame');
      if (len > 125) throw new WsError('control frame payload > 125');
    }
    const total = off + (masked ? 4 : 0) + len;
    if (b.length < total) return null; // partial frame - wait for the rest
    let payload;
    if (masked) {
      const key = b.subarray(off, off + 4);
      payload = Buffer.allocUnsafe(len);
      for (let i = 0; i < len; i++) payload[i] = b[off + 4 + i] ^ key[i & 3];
    } else {
      payload = Buffer.from(b.subarray(off, off + len)); // copy - the buffer is reused
    }
    this._buf = this._buf.subarray(total);
    return { fin, opcode, payload };
  }
}
