// VARVEL — governed SOCKS5 server for the pivot mesh (gap #4b, stage 3).
//
// WHAT THIS IS: an RFC 1928 CONNECT server (IPv4 + IPv6 + DOMAIN forms; RFC 1929
// user/pass optional) intended to run INSIDE a landed agent process, so the operator's
// tools can pivot THROUGH that agent into the internal network — the classic
// Cobalt-Strike-class "socks" capability, built to VARVEL's governance bar.
//
// THE GOVERNANCE SEAM (the whole point): every CONNECT is decided by an injected
//   allow({ host, port, addressType, remoteIp }) -> boolean | { ok, reason? }
// callback — the Enclave seam's scope check. When `allow` is NOT SET the server REFUSES
// EVERYTHING (default-refuse: an ungoverned relay is a finding, not a feature). A refused
// destination gets the RFC reply 0x02 ("connection not allowed by ruleset"), is audited
// as socks.refused, and no dial is ever attempted. A pivot to an out-of-scope destination
// is refused exactly the way a direct connection would be.
//
// SCOPE (honest, documented):
//   · CONNECT only. BIND and UDP ASSOCIATE get 0x07 (command not supported).
//   · ATYP 0x01 (IPv4), 0x03 (DOMAIN), 0x04 (IPv6). v6 destinations are canonicalized
//     by the SHARED engine/ipaddr parser (compressed/mixed-case forms collapse), so the
//     seam's CIDR ring math sees the same text it sees everywhere else on the platform.
//     v4-mapped v6 (…00 00 ff ff + 4 v4 bytes) collapses to the v4 form — it IS v4.
//   · Domain destinations: the allow-check sees the DOMAIN STRING (the seam decides what
//     domains it governs); resolution happens at dial time by the stack.
//   · No-auth (0x00) by default; with auth:{user,pass} configured the server demands
//     method 0x02 and does RFC 1929 subnegotiation with a timing-safe compare.
//   · Every association and refusal is audited via onEvent; the relay is a dumb byte pump
//     with byte counters (socks.associated / socks.closed carry the totals).

import net from 'node:net';
import { timingSafeEqual } from 'node:crypto';
import { parseIp } from './ipaddr.mjs';

export const SOCKS_VERSION = 0x05;
export const REP = {
  SUCCEEDED: 0x00, GENERAL_FAILURE: 0x01, NOT_ALLOWED: 0x02, NETWORK_UNREACHABLE: 0x03,
  HOST_UNREACHABLE: 0x04, CONNECTION_REFUSED: 0x05, TTL_EXPIRED: 0x06,
  COMMAND_NOT_SUPPORTED: 0x07, ADDRESS_TYPE_NOT_SUPPORTED: 0x08,
};
const MAX_GREETING = 1 + 1 + 255;      // VER NMETHODS METHODS[255]
const MAX_REQUEST = 4 + 1 + 255 + 2;   // VER CMD RSV ATYP DOMAIN[255] PORT
const HANDSHAKE_MS = 10_000;

export class SocksError extends Error {
  constructor(message, rep = REP.GENERAL_FAILURE) {
    super(message);
    this.name = 'SocksError';
    this.rep = rep;
  }
}

// ——— pure wire helpers (unit-tested directly) ———
// Parse a client greeting. Returns the offered methods array, or throws SocksError.
export function parseGreeting(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 2) throw new SocksError('greeting too short');
  if (buf[0] !== SOCKS_VERSION) throw new SocksError('not SOCKS5 (ver ' + buf[0] + ')');
  const n = buf[1];
  if (n < 1) throw new SocksError('greeting offers no methods');
  if (buf.length < 2 + n) return null; // incomplete — caller waits for more bytes
  if (buf.length > MAX_GREETING) throw new SocksError('oversized greeting');
  return { methods: [...buf.subarray(2, 2 + n)], rest: buf.subarray(2 + n) };
}

// Parse a CONNECT request. Returns null when more bytes are needed; throws SocksError
// (carrying the RFC reply code) on anything malformed or unsupported.
export function parseRequest(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 4) return null;
  if (buf.length > MAX_REQUEST) throw new SocksError('oversized request');
  if (buf[0] !== SOCKS_VERSION) throw new SocksError('not SOCKS5 (ver ' + buf[0] + ')');
  const cmd = buf[1];
  if (buf[2] !== 0x00) throw new SocksError('RSV must be 0');
  const atyp = buf[3];
  let host, fam, need;
  if (atyp === 0x01) { // IPv4
    need = 4 + 4 + 2;
    if (buf.length < need) return null;
    host = [...buf.subarray(4, 8)].join('.');
    fam = 'ipv4';
  } else if (atyp === 0x03) { // DOMAIN
    const dlen = buf[4];
    if (dlen < 1) throw new SocksError('empty domain');
    need = 4 + 1 + dlen + 2;
    if (buf.length < need) return null;
    host = buf.subarray(5, 5 + dlen).toString('latin1');
    if (!/^[\w.-]+$/.test(host)) throw new SocksError('domain shape is not dialable');
    fam = 'domain';
  } else if (atyp === 0x04) { // IPv6 — 16 raw bytes, canonicalized by the shared parser
    need = 4 + 16 + 2;
    if (buf.length < need) return null;
    const groups = [];
    for (let i = 0; i < 8; i++) groups.push(buf.readUInt16BE(4 + i * 2).toString(16));
    const p = parseIp(groups.join(':'));
    if (!p) throw new SocksError('bad IPv6 destination', REP.GENERAL_FAILURE);
    host = p.text; // canonical: the seam's ring math sees the platform-wide form
    fam = p.fam === 4 ? 'ipv4' : 'ipv6'; // v4-mapped on the wire IS a v4 destination
  } else {
    throw new SocksError('unknown address type 0x' + atyp.toString(16), REP.ADDRESS_TYPE_NOT_SUPPORTED);
  }
  const port = buf.readUInt16BE(need - 2);
  if (cmd !== 0x01) throw new SocksError('only CONNECT (0x01) is supported', REP.COMMAND_NOT_SUPPORTED);
  if (port === 0) throw new SocksError('port 0 is not dialable');
  return { cmd, addressType: fam, host, port, rest: buf.subarray(need) };
}

// Parse an RFC 1929 user/pass subnegotiation. null = need more bytes.
export function parseAuth(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 2) return null;
  if (buf[0] !== 0x01) throw new SocksError('bad auth version ' + buf[0]);
  const ulen = buf[1];
  if (buf.length < 2 + ulen + 1) return null;
  const user = buf.subarray(2, 2 + ulen).toString('latin1');
  const plen = buf[2 + ulen];
  if (buf.length < 2 + ulen + 1 + plen) return null;
  const pass = buf.subarray(2 + ulen + 1, 2 + ulen + 1 + plen).toString('latin1');
  return { user, pass, rest: buf.subarray(2 + ulen + 1 + plen) };
}

// A CONNECT reply: VER REP RSV ATYP(IPv4) BND.ADDR BND.PORT. BND is 0.0.0.0:0 — the
// standard proxy shape (we do not leak the relay's bound address into the reply).
export function buildReply(rep) {
  return Buffer.from([SOCKS_VERSION, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
}

const safeEq = (a, b) => {
  const x = Buffer.from(String(a ?? ''), 'latin1');
  const y = Buffer.from(String(b ?? ''), 'latin1');
  return x.length === y.length && timingSafeEqual(x, y);
};

// ——— the server ———
export class SocksServer {
  // allow({ host, port, addressType, remoteIp }) — THE seam decision point (async ok).
  //   UNSET => default-refuse everything (a relay without governance is refused).
  // auth: { user, pass } => require RFC 1929; omitted => no-auth (method 0x00).
  // connectImpl(host, port) -> Promise<socket> — injectable dialer (tests, ghost chains).
  constructor({ allow, auth, onEvent, connectImpl, maxConns = 64, handshakeTimeoutMs = HANDSHAKE_MS } = {}) {
    this.allow = typeof allow === 'function' ? allow : null;
    this.auth = auth && typeof auth === 'object' ? { user: String(auth.user ?? ''), pass: String(auth.pass ?? '') } : null;
    this.onEvent = typeof onEvent === 'function' ? onEvent : () => {};
    this.connectImpl = connectImpl || ((host, port) => new Promise((resolve, reject) => {
      const s = net.connect(port, host);
      s.once('connect', () => resolve(s));
      s.once('error', reject);
    }));
    this.maxConns = Math.max(1, Number(maxConns) || 64);
    this.handshakeTimeoutMs = Math.max(500, Number(handshakeTimeoutMs) || HANDSHAKE_MS);
    this._server = null;
    this._conns = new Set();
    this.associations = 0;
    this.refusals = 0;
  }
  _emit(type, obj) { try { this.onEvent(type, obj); } catch { /* audit must never break the relay */ } }

  async listen(port = 0, host = '127.0.0.1') {
    if (this._server) return { port: this.port };
    this._server = net.createServer((sock) => this._onConn(sock));
    this._server.on('error', (e) => this._emit('socks.error', { error: (e && e.message) || String(e) }));
    await new Promise((resolve, reject) => {
      this._server.once('error', reject);
      this._server.listen(port, host, resolve);
    });
    this.port = this._server.address().port;
    this._emit('socks.listening', { port: this.port, governed: !!this.allow, auth: !!this.auth });
    return { port: this.port };
  }

  status() {
    return { listening: !!this._server, port: this.port || 0, governed: !!this.allow, auth: !!this.auth, associations: this.associations, refusals: this.refusals, connections: this._conns.size };
  }

  async close() {
    for (const s of this._conns) { try { s.destroy(); } catch {} }
    this._conns.clear();
    const srv = this._server;
    this._server = null;
    if (srv) await new Promise((r) => { try { srv.close(() => r()); } catch { r(); } });
  }

  _reply(sock, rep) { try { sock.write(buildReply(rep)); } catch {} }

  async _onConn(sock) {
    if (this._conns.size >= this.maxConns) { try { sock.destroy(); } catch {} return; }
    this._conns.add(sock);
    const remoteIp = sock.remoteAddress || '';
    let buf = Buffer.alloc(0);
    let stage = 'greeting'; // greeting -> auth -> request -> relay
    const timer = setTimeout(() => { if (stage !== 'relay') { this._emit('socks.malformed', { remoteIp, error: 'handshake timeout' }); try { sock.destroy(); } catch {} } }, this.handshakeTimeoutMs);
    sock.on('error', () => {});
    sock.on('close', () => { clearTimeout(timer); this._conns.delete(sock); });

    const fail = (rep, type, obj = {}) => {
      this.refusals++;
      this._emit(type, { remoteIp, ...obj });
      if (stage === 'request' || stage === 'deciding') this._reply(sock, rep);
      try { sock.end(); } catch {}
      setTimeout(() => { try { sock.destroy(); } catch {} }, 250).unref?.();
    };

    // Stage machine: greeting -> (auth) -> request -> relay. Loops over the buffer so
    // pipelined bytes (client sent greeting+request in one segment) are handled in one go.
    const step = async () => {
      if (stage === 'greeting') {
        const g = parseGreeting(buf);
        if (!g) return; // wait for the rest
        buf = g.rest;
        const want = this.auth ? 0x02 : 0x00;
        if (!g.methods.includes(want)) {
          try { sock.write(Buffer.from([SOCKS_VERSION, 0xff])); } catch {} // RFC 1928: no acceptable method
          return fail(REP.GENERAL_FAILURE, 'socks.auth-refused', { error: 'client did not offer method 0x0' + want });
        }
        try { sock.write(Buffer.from([SOCKS_VERSION, want])); } catch { return; }
        stage = this.auth ? 'auth' : 'request';
        return step();
      }
      if (stage === 'auth') {
        const a = parseAuth(buf);
        if (!a) return;
        buf = a.rest;
        if (!safeEq(a.user, this.auth.user) || !safeEq(a.pass, this.auth.pass)) {
          try { sock.write(Buffer.from([0x01, 0x01])); } catch {}
          return fail(REP.GENERAL_FAILURE, 'socks.auth-failed', { user: a.user.slice(0, 32) });
        }
        try { sock.write(Buffer.from([0x01, 0x00])); } catch { return; }
        stage = 'request';
        return step();
      }
      if (stage === 'request') {
        const req = parseRequest(buf); // throws SocksError with the right REP
        if (!req) return;
        buf = req.rest;
        stage = 'deciding'; // no more handshake parsing; not relaying yet either
        clearTimeout(timer);
        // THE SEAM: governed allow-check, default-refuse when unset.
        let decision = false, reason = 'no allow-check configured (default-refuse)';
        if (this.allow) {
          try {
            const d = await this.allow({ host: req.host, port: req.port, addressType: req.addressType, remoteIp });
            decision = !!(d && (d === true || d.ok));
            if (!decision && d && d.reason) reason = String(d.reason);
            if (decision) reason = '';
          } catch (e) { decision = false; reason = 'allow-check threw: ' + ((e && e.message) || e); }
        }
        if (!decision) return fail(REP.NOT_ALLOWED, 'socks.refused', { host: req.host, port: req.port, reason });
        // Governed connect
        let remote;
        try { remote = await this.connectImpl(req.host, req.port); }
        catch (e) { return fail(REP.CONNECTION_REFUSED, 'socks.unreachable', { host: req.host, port: req.port, error: (e && e.message) || String(e) }); }
        this._reply(sock, REP.SUCCEEDED);
        this.associations++;
        stage = 'relay'; // pipe() owns the stream from here
        this._emit('socks.associated', { host: req.host, port: req.port, addressType: req.addressType, remoteIp });
        this._relay(sock, remote, req);
        return;
      }
    };
    sock.on('data', (chunk) => {
      if (stage === 'relay') return; // pipe() owns the stream from here
      buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
      step().catch((e) => {
        const rep = e instanceof SocksError ? e.rep : REP.GENERAL_FAILURE;
        const type = e instanceof SocksError && (rep === REP.COMMAND_NOT_SUPPORTED || rep === REP.ADDRESS_TYPE_NOT_SUPPORTED) ? 'socks.unsupported' : 'socks.malformed';
        fail(rep, type, { error: (e && e.message) || String(e) });
      });
    });
  }

  // Dumb byte pump with counters. Either side ending closes the pair; errors destroy both.
  _relay(client, remote, req) {
    let up = 0, down = 0;
    client.on('data', (d) => { up += d.length; });
    remote.on('data', (d) => { down += d.length; });
    const done = () => {
      try { client.destroy(); } catch {}
      try { remote.destroy(); } catch {}
      this._emit('socks.closed', { host: req.host, port: req.port, bytesUp: up, bytesDown: down });
    };
    client.once('close', done);
    remote.once('close', done);
    remote.once('error', () => { try { client.destroy(); } catch {} });
    client.pipe(remote);
    remote.pipe(client);
  }
}
