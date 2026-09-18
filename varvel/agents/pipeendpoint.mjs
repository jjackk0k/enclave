// VARVEL — agent-side named-pipe endpoints for the pivot mesh (gap #4b, stage 2).
//
// The I/O half of engine/pipelink.mjs (which is pure). Two roles:
//
//   PipeServer  — runs INSIDE THE PARENT agent: listens on \\.\pipe\<pipeName> (the
//                 governed pipeNameFor(linkId) namespace), drives a ParentLinkHub, and
//                 relays each authenticated child's `up` payloads through an injected
//                 relayUp(payload) -> Promise<replyString> (the parent's own governed
//                 channel leg — sim-agent wires it to the channel's /l relay route).
//   PipeClient  — runs INSIDE THE CHILD agent: connects to the parent's pipe, performs
//                 the hello/welcome handshake, then round-trips governed payloads.
//
// WINDOWS PIPES FROM NODE: net.createServer/net.connect speak named pipes directly via
// the \\.\pipe\NAME (this host) and \\HOST\pipe\NAME (another host) paths. The REMOTE
// form is the SMB leg: the OS redirector carries it over SMB/IPC$ with the agent's own
// logon-session credentials — no new egress, indistinguishable from internal SMB chatter.
// (tools/smbv2.mjs additionally grows a raw-protocol IPC$ pipe call for environments
// without a usable redirector — operator-side tooling, not the mesh's agent path.)
//
// GOVERNANCE: every connect/handshake/relay/death is audited through onEvent; every
// protocol violation is fail-closed (destroy + audit), never a silent swallow. No
// evasion anywhere: the pipe name is the governed varvel_link_<linkId> namespace.

import net from 'node:net';
import { FrameParser, PipeLinkError, ParentLinkHub, ChildLink, encodeFrame, pipeNameFor, LINK_TIMEOUT_MS } from '../engine/pipelink.mjs';

const HANDSHAKE_MS = 10_000;   // a connection must complete hello/welcome inside this
const MAX_SESSIONS = 16;       // per pipe server — a parent links a handful of children

const safe = (fn) => { try { fn(); } catch { /* never throw into the agent */ } };

// ——— PARENT END ———
// new PipeServer({ linkId, children, relayUp, onEvent, linkTimeoutMs })
//   children: Map/obj childId -> verifyKey (from the channel's link-listen task)
//   relayUp(payloadObj) -> Promise<string>  — ONE payload to the channel, its reply string
export class PipeServer {
  constructor({ linkId, children, relayUp, onEvent, linkTimeoutMs = LINK_TIMEOUT_MS, pipeName } = {}) {
    if (typeof relayUp !== 'function') throw new TypeError('PipeServer: relayUp(payload) is required');
    this.onEvent = typeof onEvent === 'function' ? onEvent : () => {};
    this.hub = new ParentLinkHub({ linkId, children, onEvent: (t, o) => this._emit(t, o), linkTimeoutMs });
    this.linkId = this.hub.linkId;
    this.pipeName = pipeName || pipeNameFor(this.linkId);
    this.pipePath = '\\\\.\\pipe\\' + this.pipeName;
    this._relayUp = relayUp;
    this._server = null;
    this._conns = new Set();
    this.relayed = 0; // honest counter for status/tests
  }
  _emit(type, obj) { safe(() => this.onEvent(type, { pipe: this.pipeName, ...obj })); }

  async listen() {
    if (this._server) return { pipe: this.pipePath };
    this._server = net.createServer((sock) => this._onConn(sock));
    this._server.on('error', (e) => this._emit('link.error', { error: (e && e.message) || String(e) }));
    await new Promise((resolve, reject) => {
      this._server.once('error', reject);
      this._server.listen(this.pipePath, resolve);
    });
    this._emit('link.listening', { path: this.pipePath, children: this.hub.childCount() });
    return { pipe: this.pipePath };
  }

  _onConn(sock) {
    if (this._conns.size >= MAX_SESSIONS) { this._emit('link.refused', { reason: 'session-cap' }); safe(() => sock.destroy()); return; }
    this._conns.add(sock);
    const parser = new FrameParser();
    let session = null;
    let relayQ = Promise.resolve(); // serialize relay per connection: down order == up order
    const kill = (reason) => {
      if (session) this.hub.dropSession(session.agentId, reason);
      safe(() => sock.destroy());
    };
    const timer = setTimeout(() => { if (!session) { this._emit('link.hello-timeout', {}); kill('hello-timeout'); } }, HANDSHAKE_MS);
    sock.on('error', () => { /* close follows — never throws into the agent */ });
    sock.on('close', () => {
      clearTimeout(timer);
      this._conns.delete(sock);
      if (session) { this.hub.dropSession(session.agentId, 'pipe-closed'); session = null; }
    });
    sock.on('data', (chunk) => {
      let frames;
      try { frames = parser.feed(chunk); }
      catch (e) { this._emit('link.error', { error: (e && e.message) || String(e), code: e.code || 'frame' }); kill('protocol'); return; }
      for (const f of frames) {
        if (!session) {
          let hs;
          try { hs = this.hub.acceptHello(f); }
          catch (e) { this._emit('link.hello-denied', { error: e.message, child: String((f && f.a) || '') }); kill('hello-denied'); return; }
          session = hs.session;
          clearTimeout(timer);
          try { sock.write(encodeFrame(hs.welcome)); } catch { kill('write-failed'); return; }
          continue;
        }
        if (f.t === 'up') {
          let payload;
          try { payload = session.openUp(f); }
          catch (e) { this._emit('link.error', { child: session.agentId, error: e.message, code: e.code }); kill('chain-violation'); return; }
          const s = session;
          relayQ = relayQ.then(async () => {
            if (sock.destroyed) return;
            let reply = '';
            try {
              reply = await this._relayUp(payload);
              this.relayed++;
            } catch (e) { this._emit('link.relay-error', { child: s.agentId, error: (e && e.message) || String(e) }); reply = ''; }
            if (sock.destroyed) return;
            try { sock.write(encodeFrame(s.sealDown(String(reply ?? '')))); }
            catch (e) { this._emit('link.error', { child: s.agentId, error: (e && e.message) || String(e) }); kill('write-failed'); }
          });
          continue;
        }
        if (f.t === 'bye') {
          try { session.openBye(f); this._emit('link.bye', { child: session.agentId, reason: f.p }); }
          catch (e) { this._emit('link.error', { child: session.agentId, error: e.message, code: e.code }); }
          kill('bye');
          return;
        }
        this._emit('link.error', { child: session.agentId, error: 'unexpected frame type ' + String(f.t) });
        kill('protocol');
        return;
      }
    });
  }

  // Enroll an additional child on a RUNNING link (the channel queued a second link-listen).
  addChild(agentId, verifyKey) { return this.hub.addChild(agentId, verifyKey); }
  reapDead(opts) { return this.hub.reapDead(opts); }
  status() { return { pipe: this.pipePath, link: this.linkId, connections: this._conns.size, relayed: this.relayed, sessions: this.hub.sessionsView(), children: this.hub.childCount() }; }

  async close() {
    for (const sock of this._conns) safe(() => sock.destroy());
    this._conns.clear();
    const s = this._server;
    this._server = null;
    if (s) await new Promise((r) => { try { s.close(() => r()); } catch { r(); } });
    this._emit('link.closed', {});
  }
}

// ——— CHILD END ———
// new PipeClient({ pipePath, linkId, agentId, token, onEvent, timeout })
//   pipePath: '\\\\.\\pipe\\NAME' (parent on this host) or '\\\\HOST\\pipe\\NAME' (remote —
//   the SMB leg via the OS redirector). hello/welcome, then serialized roundTrips.
export class PipeClient {
  constructor({ pipePath, host, pipeName, linkId, agentId, token, onEvent, timeout = 8000 } = {}) {
    this.pipePath = pipePath || ('\\\\' + (host || '.') + '\\pipe\\' + (pipeName || pipeNameFor(linkId)));
    this.link = new ChildLink({ linkId, agentId, token });
    this.onEvent = typeof onEvent === 'function' ? onEvent : () => {};
    this.timeout = Math.max(500, Number(timeout) || 8000);
    this._sock = null;
    this._parser = new FrameParser();
    this._pending = null;   // { resolve, reject, timer } — roundTrips are serialized
    this._queue = Promise.resolve();
    this.dead = true;       // no wire until the handshake completes
  }
  _emit(type, obj) { safe(() => this.onEvent(type, obj)); }

  async connect() {
    const sock = net.connect(this.pipePath);
    sock.on('error', () => {});
    sock.on('close', () => this._onClose());
    sock.on('data', (chunk) => this._onData(chunk));
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new PipeLinkError('pipe connect timeout', 'state')), this.timeout);
      sock.once('connect', () => { clearTimeout(t); resolve(); });
      sock.once('error', (e) => { clearTimeout(t); reject(new PipeLinkError('pipe connect failed: ' + (e && e.message), 'state')); });
    });
    this._sock = sock;
    // handshake — a lying or refusing parent must not leave a half-open socket behind
    const welcomeP = this._awaitFrame();
    sock.write(encodeFrame(this.link.makeHello()));
    try {
      const welcome = await welcomeP;
      this.link.acceptWelcome(welcome); // throws PipeLinkError on a lying parent
    } catch (e) {
      this._die('handshake-failed');
      throw e;
    }
    this.dead = false;
    this._emit('link.connected', { pipe: this.pipePath });
    return this;
  }

  _awaitFrame() {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this._pending = null; reject(new PipeLinkError('pipe reply timeout', 'state')); }, this.timeout);
      this._pending = { resolve, reject, timer };
    });
  }

  _onData(chunk) {
    let frames;
    try { frames = this._parser.feed(chunk); }
    catch (e) { this._emit('link.error', { error: e.message }); this._die('protocol'); return; }
    for (const f of frames) {
      const p = this._pending;
      if (!p) { this._emit('link.error', { error: 'unsolicited frame ' + String(f && f.t) }); continue; }
      clearTimeout(p.timer);
      this._pending = null;
      p.resolve(f);
    }
  }

  _onClose() {
    this.dead = true;
    const p = this._pending;
    if (p) { clearTimeout(p.timer); this._pending = null; p.reject(new PipeLinkError('pipe closed mid-exchange', 'state')); }
    this._emit('link.closed', { pipe: this.pipePath });
  }

  _die(reason) { this.dead = true; try { if (this._sock) this._sock.destroy(); } catch {} this._sock = null; }

  // One governed payload up, its reply string down. Serialized: a second call queues
  // behind the in-flight one so the down-chain order always matches the up-chain.
  roundTrip(payload) {
    const run = async () => {
      if (this.dead || !this._sock || this._sock.destroyed) throw new PipeLinkError('link is dead', 'state');
      const frame = this.link.sealUp(payload);
      const replyP = this._awaitFrame();
      try { this._sock.write(encodeFrame(frame)); }
      catch (e) { this._die('write-failed'); throw new PipeLinkError('pipe write failed: ' + (e && e.message), 'state'); }
      const down = await replyP;
      try { return this.link.openDown(down); } // chain-verified
      catch (e) { this._die('chain-violation'); throw e; } // a desynced/forged link is a dead link
    };
    const out = this._queue.then(run, run);
    this._queue = out.catch(() => {});
    return out;
  }

  async close(reason = 'agent-done') {
    if (this._sock && !this._sock.destroyed && !this.dead) {
      try { this._sock.write(encodeFrame(this.link.sealBye(reason))); } catch {}
    }
    this._die('closed');
  }
}

// ——— the child agent's channel transport over the link (mirrors DnsTransport's pull/push) ———
// The payloads are EXACTLY the governed channel objects ({a,s,h} pull / chunked push with
// per-chunk HMAC); the parent's relay delivers the listener's reply strings verbatim.
// ENVELOPE LAYER (engine/envelope): with enc:true the CONTENT is AEAD-sealed end-to-end
// child↔listener — the parent relaying these frames holds only the 'varvel-link:' keys
// and sees opaque ciphertext (its link layer still re-encrypts per hop AROUND it).
import { createHmac } from 'node:crypto';
import { b32decode } from '../engine/dnscodec.mjs';
import { deriveEncKey, sealBytes, isSealedString, openString } from '../engine/envelope.mjs';

const hmacOf = (key, msg) => createHmac('sha256', String(key)).update(String(msg)).digest('hex');
// 4092 (not 4096): 3-ALIGNED so per-chunk base64 concatenates padding-free in the
// channel's reassembly — the dns/stg/ghc wires obey the same rule (a 4096 chunk pads
// mid-join and the intake's join()+base64-decode truncates the result there).
const PIPE_PUSH_CHUNK = 4092; // raw bytes per push frame — pipes are streams, no DNS-label cap

export class PipeTransport {
  constructor({ pipePath, host, pipeName, linkId, agentId, token, timeout = 8000, onEvent, enc = false } = {}) {
    if (!agentId || !token) throw new TypeError('PipeTransport needs agentId + token');
    if (!linkId) throw new TypeError('PipeTransport needs linkId (the link this pipe carries)');
    this.agentId = String(agentId);
    this.token = String(token);
    this.linkId = linkId;
    this.seq = 0;
    // Envelope encryption: seal push content end-to-end (the parent reads ciphertext),
    // require sealed task replies (a plaintext reply through the link is a downgrade).
    this.enc = enc === true;
    this._encKey = null;
    this.lastError = null;
    this.client = new PipeClient({ pipePath, host, pipeName, linkId, agentId: this.agentId, token: this.token, timeout, onEvent });
  }

  _key() { if (!this._encKey) this._encKey = deriveEncKey(this.token, this.agentId); return this._encKey; }

  async connect() { await this.client.connect(); return this; }

  // The pipe died (or was never opened): a FRESH handshake with a new nonce, preserving
  // the channel seq (the listener's strict per-agent seq survives relinks — it must).
  async ensureConnected() {
    if (!this.client.dead) return;
    const c = this.client;
    this.client = new PipeClient({ pipePath: c.pipePath, linkId: this.linkId, agentId: this.agentId, token: this.token, timeout: c.timeout, onEvent: c.onEvent });
    await this.client.connect();
  }

  // Check in through the parent; returns the task object or null (idle/denied — uniform).
  async pull() {
    const s = ++this.seq;
    const env = { a: this.agentId, s, h: hmacOf(this.token, this.agentId + ':' + s + ':pull') };
    if (this.enc) env.ec = 1; // capability flag — the listener seals the reply for us
    const reply = await this.client.roundTrip(env);
    if (!reply) return null;
    if (this.enc) {
      if (!isSealedString(reply)) { this.lastError = 'enc-plaintext-reply'; return null; } // downgrade through the link: refused
      let plain;
      try { plain = openString(this._key(), reply); } catch (e) { this.lastError = 'enc-open-failed:' + ((e && e.code) || 'open'); return null; }
      this.lastError = null;
      const buf = b32decode(plain);
      if (!buf) return null;
      try { return JSON.parse(buf.toString('utf8')); } catch { return null; }
    }
    const buf = b32decode(reply);
    if (!buf) return null;
    try { return JSON.parse(buf.toString('utf8')); } catch { return null; }
  }

  // Push a result body, chunked with per-chunk HMAC — identical semantics to the dns wire.
  // enc: each chunk is AEAD-SEALED first (encrypt-then-MAC; the HMAC formula is unchanged
  // and now authenticates ciphertext) — the relay parent forwards opaque ciphertext.
  async push(taskId, body) {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body ?? ''));
    const chunks = [];
    for (let i = 0; i < buf.length; i += PIPE_PUSH_CHUNK) chunks.push(buf.subarray(i, Math.min(i + PIPE_PUSH_CHUNK, buf.length)));
    if (!chunks.length) chunks.push(Buffer.alloc(0));
    const n = chunks.length;
    for (let i = 0; i < n; i++) {
      const s = ++this.seq;
      const d = (this.enc ? sealBytes(this._key(), chunks[i]) : chunks[i]).toString('base64');
      const h = hmacOf(this.token, [this.agentId, s, taskId, i, n, d].join(':'));
      await this.client.roundTrip({ a: this.agentId, s, h, t: taskId, k: 'push', i, n, d });
    }
    return true;
  }

  async close() { await this.client.close(); }
}
