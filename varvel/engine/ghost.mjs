// VARVEL — GHOST MODE: governed identity stealth for authorized offensive engagements.
//
// Jack's directive (2026-08-03): the operator's identity must be HIDDEN — and the platform
// must GUARANTEE it, not just advise on a footprint number. This is OFFENSIVE tradecraft,
// not defense-flavored caution: Cobalt's redirectors and a red team's proxy chain exist so
// the ATTACK can keep pressing without exposing its origin. Ghost Mode is that capability,
// native and governed — VARVEL is an offensive platform, and this is built to that bar.
//
// Two layers, both in code:
//
//   TRANSPORT — all ghost-covered egress routes through an operator-configured proxy chain
//   (http:// CONNECT and/or socks5://, N hops). DNS is resolved by the LAST proxy, never
//   locally (no DNS leak). Plain-HTTP targets use absolute-URI through the final hop;
//   HTTPS targets use iterative CONNECT; raw-TCP tools can borrow the same tunnel via
//   ghost.connect(). Headers go through scrubHeaders() (persona UA, no VARVEL-* markers).
//
//   GUARANTEE — ghost.mode 'required' is FAIL-CLOSED: egress to a PUBLIC destination is
//   refused (logged) until verify() proves the chain exits from an IP that is NOT the
//   operator's real one. 'on' is best-effort (watchdog warns when unverified). Private
//   destinations (RFC1918/loopback/link-local — the range) always go direct: lab traffic
//   can't leave the lab anyway, and a proxy would only break it.
//
// GOVERNANCE (unchanged, by design): the chain hides the operator from the TARGET and the
// network path — never from VARVEL itself or the Enclave's audit. Every ghost event is
// logged, status() is in getState()/the report (chain hosts, exit IP, verification state —
// no proxy credentials ever recorded). Scope checks still see the real destination; the
// proxy changes the path, not what is allowed.

import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { bracketHost, extractIp, isPrivate, parseIp } from './ipaddr.mjs';
import { runEgressCheck, normalizeExitSet } from './egresscheck.mjs';
import { normalizeShaperConfig } from './stealth.mjs';
import { probeTlsInspection } from '../tools/tlsinspect.mjs';

// ---------- chain parsing ----------
export function parseChain(str) {
  const raw = String(str || '').trim();
  if (!raw) return [];
  return raw.split(',').map((part, i) => {
    let u;
    try { u = new URL(part.trim()); } catch { throw new TypeError(`ghost chain hop ${i + 1}: not a URL: ${part}`); }
    const scheme = u.protocol.replace(':', '').toLowerCase();
    if (!['http', 'https', 'socks5', 'socks'].includes(scheme)) throw new TypeError(`ghost chain hop ${i + 1}: scheme must be http(s):// or socks5:// (got ${scheme})`);
    const port = Number(u.port) || (scheme === 'https' ? 443 : scheme === 'http' ? 80 : 1080);
    if (!u.hostname || !(port > 0 && port < 65536)) throw new TypeError(`ghost chain hop ${i + 1}: bad host/port`);
    return { scheme: scheme === 'socks' ? 'socks5' : scheme, host: u.hostname, port, user: decodeURIComponent(u.username || ''), pass: decodeURIComponent(u.password || '') };
  });
}

// The CANONICAL egress id of a chain: creds-stripped 'scheme://host:port' per hop,
// comma-joined -- EXACTLY the format status().chain reports, so every surface (console,
// audit, vault) names an egress the same way. The clearance vault keys minted cookies
// under this id: cf_clearance is IP-bound, so the MINT side and the RIDE side must agree
// on the egress id or the vault silently misses (the 2026-08-10 mint-direct/ride-chain
// split). Accepts a chain spec string or parsed hops; an empty chain is 'direct' (no
// app-level proxy). Throws TypeError on an unparseable spec (same contract as parseChain)
// -- callers that must never throw parse first and decide honestly.
export function chainEgressId(chain) {
  const hops = typeof chain === 'string' ? parseChain(chain) : (Array.isArray(chain) ? chain : []);
  if (!hops.length) return 'direct';
  return hops.map((h) => `${h.scheme}://${h.host}:${h.port}`).join(',');
}

// Private destinations always go direct: range traffic never leaves the lab; proxying it
// would break the sealed net AND leak lab topology to the proxy operator. Address-class
// math is shared (engine/ipaddr): RFC1918/loopback/link-local v4 + ULA/link-local/::1 v6.
export function isPrivateDest(host) {
  const h = String(host || '').toLowerCase();
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')) return true;
  return isPrivate(h);
}

// ---------- Tor auto-detect (the free chain) ----------
// Jack's directive (2026-08-04): a user without funds for a paid proxy must still be able
// to hide — so ghost treats a LOCAL Tor as the built-in free chain. Detection = a SOCKS5
// greeting answered on Tor's standard loopback ports (9050 daemon, 9150 Tor Browser).
// Honesty: a SOCKS5 answer on those ports is reported as "local Tor (or compatible
// SOCKS5)" — we never claim more than we observed, and verify() still has to PROVE the
// exit differs from the operator before 'required' lets anything out.
export function probeSocks5({ host = '127.0.0.1', port, timeout = 1500 } = {}) {
  return new Promise((resolve) => {
    let done = false;
    let s;
    const fin = (v) => { if (!done) { done = true; clearTimeout(t); try { s && s.destroy(); } catch {} resolve(v); } };
    const t = setTimeout(() => fin(false), timeout);
    try {
      s = net.connect({ host, port });
      s.once('connect', () => { try { s.write(Buffer.from([0x05, 0x01, 0x00])); } catch { fin(false); } });
      s.on('data', (d) => fin(d.length >= 2 && d[0] === 0x05 && d[1] !== 0xff));
      s.once('error', () => fin(false));
    } catch { fin(false); }
  });
}

// socks5GreetOn(socket, timeout) — the SAME greeting probe as probeSocks5, but on an
// ALREADY-OPEN socket (per-hop health through the chain: hop k's greeting rides the tunnel
// through hops 0..k-1). Never destroys the socket — the caller owns it. Never throws.
function socks5GreetOn(socket, timeout) {
  return new Promise((resolve) => {
    let done = false;
    const fin = (v) => { if (!done) { done = true; clearTimeout(t); resolve(v); } };
    const t = setTimeout(() => fin(false), timeout);
    try {
      socket.once('data', (d) => fin(d.length >= 2 && d[0] === 0x05 && d[1] !== 0xff));
      socket.once('error', () => fin(false));
      socket.write(Buffer.from([0x05, 0x01, 0x00]));
    } catch { fin(false); }
  });
}

export async function detectTor({ ports = [9050, 9150], timeout = 1500 } = {}) {
  for (const port of ports) {
    if (await probeSocks5({ port, timeout })) return { ok: true, port, chain: `socks5://127.0.0.1:${port}` };
  }
  return { ok: false, reason: 'no SOCKS5 listener on 127.0.0.1:9050/9150 (Tor not detected)' };
}

// The arm-time decision: configured chain wins; an empty chain in on/required falls back
// to a detected local Tor; otherwise fail with HONEST guidance (the free path named, no
// silent direct-egress). `detect` injectable for hermetic tests.
export async function resolveGhostChain({ mode, chain, detect = detectTor } = {}) {
  const hops = parseChain(chain);
  if (mode === 'off') return { hops: [], source: 'off' };
  if (hops.length) return { hops, source: 'configured' };
  const t = await detect();
  if (t.ok) return { hops: parseChain(t.chain), source: 'tor' };
  throw new TypeError(`ghost mode ${mode} needs a proxy chain — none configured and no local Tor detected (${(t && t.reason) || 'probe failed'}). Free path: install Tor (torproject.org) and retry, or enter any socks5:// or http(s):// proxy. Paid optional (Mullvad / own VPS); avoid free proxy lists — logged, flagged, often malicious.`);
}

// ---------- socket tunneling ----------
// CONNECT authority form brackets v6 literals ('CONNECT [fd00::1]:443') — a bare
// 'CONNECT fd00::1:443' is unparseable to a conforming proxy. v4/hostnames untouched.
function httpConnectFrame(host, port, hop) {
  const authority = `${bracketHost(host)}:${port}`;
  let f = `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n`;
  if (hop.user) f += `Proxy-Authorization: Basic ${Buffer.from(`${hop.user}:${hop.pass}`).toString('base64')}\r\n`;
  return f + '\r\n';
}

function readHttpHead(socket, deadlineMs, what) {
  return new Promise((resolve, reject) => {
    let buf = '';
    const t = setTimeout(() => { cleanup(); reject(new Error(`${what}: tunnel read timeout`)); }, deadlineMs);
    const onData = (d) => {
      buf += d.toString('latin1');
      const end = buf.indexOf('\r\n\r\n');
      if (end >= 0) { cleanup(); resolve(buf.slice(0, end)); }
    };
    const onErr = (e) => { cleanup(); reject(new Error(`${what}: ${e.message}`)); };
    const cleanup = () => { clearTimeout(t); socket.off('data', onData); socket.off('error', onErr); };
    socket.on('data', onData);
    socket.on('error', onErr);
  });
}

async function httpConnect(socket, hop, host, port, timeout) {
  socket.write(httpConnectFrame(host, port, hop));
  const head = await readHttpHead(socket, timeout, `proxy ${hop.host}`);
  const m = /^HTTP\/\d\.\d (\d{3})/.exec(head);
  if (!m || m[1][0] !== '2') throw new Error(`proxy ${hop.host}:${hop.port} refused CONNECT ${host}:${port} (${m ? m[1] : 'no status'})`);
}

async function socks5Connect(socket, hop, host, port, timeout) {
  const read = makeReader(socket, timeout, 'socks5');
  const methods = hop.user ? [0x00, 0x02] : [0x00];
  socket.write(Buffer.from([0x05, methods.length, ...methods]));
  const greet = await read(2);
  if (greet[0] !== 0x05 || greet[1] === 0xff) throw new Error(`socks5 ${hop.host}: no acceptable auth method`);
  if (greet[1] === 0x02) { // RFC1929 user/pass
    const u = Buffer.from(hop.user), p = Buffer.from(hop.pass);
    socket.write(Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([p.length]), p]));
    const auth = await read(2);
    if (auth[1] !== 0x00) throw new Error(`socks5 ${hop.host}: authentication failed`);
  }
  const h = Buffer.from(host);
  // ATYP by family: a v6 literal rides as 0x04 + 16 raw bytes (sending 'fd00::1' as a
  // DOMAIN would make the proxy try to RESOLVE it as a name). v4 literals keep the
  // historical DOMAIN form (3.x servers and Tor accept it) — zero v4 wire change.
  const pip = parseIp(host);
  const addr = pip && pip.fam === 6
    ? Buffer.concat([Buffer.from([0x04]), Buffer.from(pip.groups.flatMap((g) => [g >> 8, g & 0xff]))])
    : Buffer.concat([Buffer.from([0x03, h.length]), h]);
  socket.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), addr, Buffer.from([port >> 8, port & 0xff])]));
  const head = await read(4);
  if (head[1] !== 0x00) throw new Error(`socks5 ${hop.host} refused CONNECT ${host}:${port} (code ${head[1]})`);
  const atyp = head[3];
  const skip = atyp === 0x01 ? 4 : atyp === 0x04 ? 16 : atyp === 0x03 ? (await read(1))[0] : 0;
  await read(skip + 2); // bind address + port
}

// A per-handshake reader that KEEPS leftover bytes between reads (a server reply often
// arrives in one TCP segment; naive read-exactly-N drops the remainder and deadlocks).
function makeReader(socket, deadlineMs, what) {
  let buf = Buffer.alloc(0);
  const waiters = [];
  const onData = (d) => {
    buf = Buffer.concat([buf, d]);
    while (waiters.length && buf.length >= waiters[0].n) {
      const w = waiters.shift();
      const out = buf.subarray(0, w.n);
      buf = buf.subarray(w.n);
      clearTimeout(w.t);
      w.resolve(out);
    }
  };
  const onErr = (e) => { while (waiters.length) { const w = waiters.shift(); clearTimeout(w.t); w.reject(new Error(`${what}: ${e.message}`)); } };
  socket.on('data', onData);
  socket.on('error', onErr);
  return (n) => new Promise((resolve, reject) => {
    if (buf.length >= n) { const out = buf.subarray(0, n); buf = buf.subarray(n); return resolve(out); }
    const t = setTimeout(() => { const i = waiters.findIndex((w) => w.t === t); if (i >= 0) waiters.splice(i, 1); reject(new Error(`${what}: read timeout`)); }, deadlineMs);
    waiters.push({ n, t, resolve, reject });
  });
}

function tcpConnect(hop, timeout) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host: hop.host, port: hop.port });
    const t = setTimeout(() => { s.destroy(); reject(new Error(`ghost hop ${hop.host}:${hop.port} connect timeout`)); }, timeout);
    s.once('connect', () => { clearTimeout(t); resolve(s); });
    s.once('error', (e) => { clearTimeout(t); reject(new Error(`ghost hop ${hop.host}:${hop.port}: ${e.message}`)); });
  });
}

// Open a raw socket to host:port THROUGH the chain. DNS is resolved by the last proxy.
export async function openTunnel(chain, host, port, timeout = 15000) {
  if (!chain.length) throw new Error('openTunnel: empty chain');
  const socket = await tcpConnect(chain[0], timeout);
  try {
    for (let i = 1; i < chain.length; i++) {
      const via = chain[i - 1], hop = chain[i];
      if (via.scheme === 'socks5') await socks5Connect(socket, via, hop.host, hop.port, timeout);
      else await httpConnect(socket, via, hop.host, hop.port, timeout);
    }
    const last = chain[chain.length - 1];
    if (last.scheme === 'socks5') await socks5Connect(socket, last, host, port, timeout);
    else await httpConnect(socket, last, host, port, timeout);
    return socket;
  } catch (e) { try { socket.destroy(); } catch {} throw e; }
}

// ---------- agents ----------
// Plain-HTTP egress: with an HTTP proxy at the LAST hop, connect to the chain and speak
// absolute-URI at it (the proxy fetches + resolves DNS). With a SOCKS5 last hop there is no
// absolute-URI form — CONNECT the target through the tunnel and speak origin-form to it.
class GhostHttpAgent extends http.Agent {
  constructor(chain, opts) {
    super(opts);
    this._chain = chain;
    // alwaysProxy: for verify() ONLY — measuring the chain's exit REQUIRES riding the
    // chain even to a private check endpoint. Engagement traffic never sets this.
    this._alwaysProxy = !!(opts && opts.alwaysProxy);
    this._absoluteMode = chain[chain.length - 1].scheme !== 'socks5';
  }
  createConnection(opts, cb) {
    const chain = this._chain;
    // PRIVATE destinations go DIRECT, always — range traffic never leaves the lab, and
    // proxying it would leak lab topology to the proxy operator (isPrivateDest).
    if (!this._alwaysProxy && isPrivateDest(opts.host || opts.hostname)) return cb(null, net.connect({ host: opts.host || opts.hostname, port: Number(opts.port) || 80 }));
    if (!this._absoluteMode) {
      openTunnel(chain, opts.host || opts.hostname, Number(opts.port) || 80, 15000).then((s) => cb(null, s), cb);
      return;
    }
    tcpConnect(chain[0], 15000).then(async (socket) => {
      try {
        for (let i = 1; i < chain.length; i++) {
          const via = chain[i - 1], hop = chain[i];
          if (via.scheme === 'socks5') await socks5Connect(socket, via, hop.host, hop.port, 15000);
          else await httpConnect(socket, via, hop.host, hop.port, 15000);
        }
        cb(null, socket);
      } catch (e) { try { socket.destroy(); } catch {} cb(e); }
    }, cb);
  }
  addRequest(req, opts) {
    // absolute-form request-target (HTTP-proxy mode only): the final proxy resolves the host.
    // Private destinations skip the rewrite — they dial direct, and origin-form is correct there.
    if (this._absoluteMode && (this._alwaysProxy || !isPrivateDest(opts.host || opts.hostname)) && !/^https?:\/\//i.test(req.path)) {
      const port = opts.port && Number(opts.port) !== 80 ? `:${opts.port}` : '';
      req.path = `http://${bracketHost(opts.host || opts.hostname)}${port}${req.path}`; // v6 literals bracketed — a bare 'http://fd00::1/x' is not a URL
    }
    super.addRequest(req, opts);
  }
}

// HTTPS egress: full CONNECT tunnel to the target, then TLS over it (servername = target).
class GhostHttpsAgent extends https.Agent {
  constructor(chain, opts) { super(opts); this._chain = chain; this._alwaysProxy = !!(opts && opts.alwaysProxy); }
  createConnection(opts, cb) {
    const host = opts.host || opts.hostname;
    const port = opts.port || 443;
    // PRIVATE destinations go DIRECT (same rule as the HTTP agent): the lab is never
    // tunneled, and the proxy operator never learns the lab exists. alwaysProxy is
    // verify()-only: measuring the chain's exit REQUIRES riding the chain.
    if (!this._alwaysProxy && isPrivateDest(host)) {
      const direct = tls.connect({ host, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: opts.rejectUnauthorized !== false }, () => cb(null, direct));
      direct.once('error', (e) => cb(e));
      return;
    }
    openTunnel(this._chain, host, port, 15000).then((socket) => {
      const tlsSock = tls.connect({ socket, servername: host, rejectUnauthorized: opts.rejectUnauthorized !== false }, () => cb(null, tlsSock));
      tlsSock.once('error', (e) => cb(e));
    }, cb);
  }
}

// ---------- header scrub ----------
const PERSONA_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
// Strip anything that names the toolset; force a browser persona UA. The persona is also
// recorded in status() so the report states exactly what was sent — scrub hides from the
// target, never from the operator.
export function scrubHeaders(headers = {}, { ua = PERSONA_UA } = {}) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const lk = k.toLowerCase();
    if (lk.startsWith('x-varvel') || lk === 'x-powered-by' || lk === 'via') continue;
    if (lk === 'user-agent') continue;
    out[lk] = v;
  }
  out['user-agent'] = ua;
  return out;
}

// ---------- the Ghost engine ----------
export class Ghost {
  constructor({ onEvent, fetchImpl } = {}) {
    this.mode = 'off';            // off | on | required
    this.chain = [];
    this.checkUrl = 'https://api.ipify.org?format=json';
    this.shaper = null;           // ghost-level traffic shaper policy (engine/stealth normalizeShaperConfig) — pacer consults it
    this._exitSet = null;         // operator-declared rotation set (canonical IPs); null = no set policy
    this._exitSetDropped = [];    // set entries that failed to parse — kept visible, never silently narrower
    this._pin = null;             // { expectExit, exitSet, at } — the pin/set used by the LAST exitCheck (audit record)
    this._verified = null;        // { ok, baselineIp, exitIp, at, error? }
    this._lastExitCheck = null;   // last exitCheck() result (additive in status())
    this._lastTlsCheck = null;    // last tlsCheck() result (additive in status())
    this._hopHealth = null;       // last probeHops() result (additive in status(); 15s cache like refreshTor)
    this._agents = null;          // cached { httpAgent, httpsAgent }
    this.onEvent = typeof onEvent === 'function' ? onEvent : () => {};
    this._fetch = fetchImpl || ((...a) => fetch(...a));
  }

  _emit(type, obj) { try { this.onEvent(type, obj); } catch { /* audit tap must never break ghost */ } }

  configure({ mode, chain, checkUrl, shaper, exitSet } = {}) {
    const hops = typeof chain === 'string' ? parseChain(chain) : (chain || this.chain);
    const m = mode || this.mode;
    if (!['off', 'on', 'required'].includes(m)) throw new TypeError('ghost mode must be off | on | required');
    if (m !== 'off' && !hops.length) throw new TypeError('ghost mode ' + m + ' needs at least one proxy hop in the chain');
    this.mode = m;
    this.chain = hops;
    if (checkUrl) this.checkUrl = String(checkUrl);
    // Shaper resolution order: explicit option > VARVEL_GHOST_SHAPER env (JSON) > keep
    // current. A malformed env is LOUD (throws) — a silently-dropped shaping policy would
    // be a claimed control that isn't running.
    if (shaper !== undefined) this.setShaper(shaper);
    else if (process.env.VARVEL_GHOST_SHAPER !== undefined) {
      let parsed;
      try { parsed = JSON.parse(process.env.VARVEL_GHOST_SHAPER); }
      catch (e) { throw new TypeError('VARVEL_GHOST_SHAPER is not valid JSON (' + e.message + ') — fix or unset it; refusing to arm with a silently-dropped shaper'); }
      this.setShaper(parsed);
    }
    if (exitSet !== undefined) this.setExitSet(exitSet);
    this._verified = null;
    this._hopHealth = null; // chain changed — prior per-hop health is stale
    this._agents = null;
    this._vagents = null;
    this._emit('ghost.configure', { mode: this.mode, hops: hops.map((h) => `${h.scheme}://${h.host}:${h.port}`), shaper: this.shaper, exitSet: this._exitSet });
    return this.status();
  }

  // Arm/clear the ghost-level traffic shaper ({minDelayMs, jitterMs, padTo: null|'mtu'} —
  // semantics + the honest app-layer ceiling in engine/stealth.mjs). Campaign pacers consult
  // it. Throws LOUD on malformed config; null clears.
  setShaper(cfg) {
    this.shaper = normalizeShaperConfig(cfg);
    this._emit('ghost.shaper', { shaper: this.shaper });
    return this.shaper;
  }

  // Declare the ROTATION SET: the exits an engagement may use (array or comma-string).
  // Canonicalized; unparseable entries are dropped but KEPT VISIBLE in status(). An input
  // with entries but zero parseable IPs throws — an empty set would match nothing and
  // silently fail every strict check closed, which must be the operator's LOUD error, not
  // a surprise at engagement time.
  setExitSet(input) {
    if (input == null || input === '') { this._exitSet = null; this._exitSetDropped = []; this._emit('ghost.exitSet', { exitSet: null }); return null; }
    const { list, dropped } = normalizeExitSet(input);
    if (!list.length) throw new TypeError('ghost exit set has no parseable IP entries (got: ' + String(input).slice(0, 120) + ') — refused; an unmatchable set would fail every strict exit check closed');
    this._exitSet = list;
    this._exitSetDropped = dropped;
    this._emit('ghost.exitSet', { exitSet: list, dropped });
    return list;
  }

  agents() {
    if (this.mode === 'off' || !this.chain.length) return null;
    if (!this._agents) this._agents = { httpAgent: new GhostHttpAgent(this.chain), httpsAgent: new GhostHttpsAgent(this.chain) };
    return this._agents;
  }

  // verify()-only agents: the exit measurement MUST ride the chain, even to a private
  // check endpoint (riding the chain is the thing being measured). Engagement traffic
  // never touches these — it uses agents()/connect(), where private goes direct.
  _verifyAgents() {
    if (!this._vagents) this._vagents = { httpAgent: new GhostHttpAgent(this.chain, { alwaysProxy: true }), httpsAgent: new GhostHttpsAgent(this.chain, { alwaysProxy: true }) };
    return this._vagents;
  }

  // Raw tunnel for socket-level tools (SMB/LDAP tiers). Honors the same chain + DNS rule.
  // PRIVATE destinations dial DIRECT (range traffic never leaves the lab).
  async connect({ host, port, timeout = 15000 } = {}) {
    if (this.mode === 'off' || isPrivateDest(host)) return net.connect({ host, port });
    return openTunnel(this.chain, host, port, timeout);
  }

  async _ipOf(url, agents) {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    return new Promise((resolve) => {
      const req = lib.request({
        hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search,
        timeout: 12000, rejectUnauthorized: false,
        agent: agents ? (u.protocol === 'https:' ? agents.httpsAgent : agents.httpAgent) : undefined,
      }, (res) => {
        let b = '';
        res.on('data', (d) => { if (b.length < 4096) b += d; });
        res.on('end', () => {
          let ip = null;
          try { ip = JSON.parse(b).ip; } catch { ip = extractIp(b); }
          const p = parseIp(ip);
          resolve(p ? p.text : null); // canonical — v4 AND v6 exit IPs both validate
        });
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
      req.end();
    });
  }

  // Prove the chain exits from an IP that is NOT the operator's own egress. In 'required'
  // mode this is the gate: no proof, no public egress. Baseline = direct fetch (the
  // operator's real IP — recorded locally only, never sent anywhere but the check service,
  // and masking it in status is deliberate: the operator may see it, a casual reader may not).
  async verify() {
    if (this.mode === 'off') { this._verified = { ok: true, reason: 'ghost off' }; return this._verified; }
    const [baselineIp, exitIp] = [await this._ipOf(this.checkUrl, null), await this._ipOf(this.checkUrl, this._verifyAgents())];
    const ok = !!(baselineIp && exitIp && baselineIp !== exitIp);
    this._verified = { ok, baselineIp, exitIp, at: new Date().toISOString(), ...(ok ? {} : { error: !exitIp ? 'chain did not reach the check endpoint' : !baselineIp ? 'baseline (direct) check failed' : 'exit IP == operator IP — identity NOT hidden' }) };
    this._emit('ghost.verify', { ...this._verified, baselineIp: maskIp(baselineIp) });
    return this._verified;
  }

  verifiedOk() { return !!(this._verified && this._verified.ok); }

  // Pre-engagement EXIT measurement (engine/egresscheck.mjs): exit STABILITY (N samples
  // through the chain, ~1s apart: 'stable' | 'rotating' — rotating carries the
  // cf_clearance IP-binding warning + the one-Mullvad-server fix), best-effort egress
  // CLASS (ipinfo.io free feed THROUGH the chain, 3s cap, heuristic-labelled, silent
  // when offline), and exit PINNING (expected exit from opts, else the
  // VARVEL_GHOST_EXPECT_EXIT env; pinStrict => mismatch is fail-closed AND drops the
  // verified state, so required mode refuses public egress). Purely additive: verify()
  // and assertEgress() semantics are untouched except that a strict pin failure can
  // only ever CLOSE the gate, never open it. Never throws.
  async exitCheck({ samples = 3, spacingMs = 1000, sampler, sleep, expectExit, pinStrict, classify = true, fetchImpl, exitSet } = {}) {
    const expected = (expectExit != null && expectExit !== '') ? String(expectExit)
      : (process.env.VARVEL_GHOST_EXPECT_EXIT || null);
    // Rotation-set resolution order: explicit option > engine-declared set (setExitSet /
    // configure) > VARVEL_GHOST_EXIT_SET env. null = no set policy (single-pin doctrine as
    // before — fully backward-compatible).
    const setInput = exitSet != null ? exitSet
      : (this._exitSet && this._exitSet.length ? this._exitSet
        : (process.env.VARVEL_GHOST_EXIT_SET || null));
    // Default sampler: the same chain-riding measurement verify() uses.
    const sample = sampler || (() => this._ipOf(this.checkUrl, this._verifyAgents()));
    // Default classifier transport: ride the chain too, so org/ASN describe the EXIT,
    // not the operator's direct egress (fetchImpl overrides it in hermetic tests).
    const classFetch = fetchImpl || ((url) => new Promise((resolve) => {
      const u = new URL(url);
      const req = https.request({
        hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search,
        timeout: 3000, rejectUnauthorized: false, agent: this._verifyAgents().httpsAgent,
      }, (res) => {
        let b = '';
        res.on('data', (d) => { if (b.length < 16384) b += d; });
        res.on('end', () => resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, json: async () => JSON.parse(b) }));
      });
      req.on('error', () => resolve({ ok: false, status: 0, json: async () => ({}) }));
      req.on('timeout', () => { req.destroy(); resolve({ ok: false, status: 0, json: async () => ({}) }); });
      req.end();
    }));
    const result = await runEgressCheck({ sampler: sample, samples, spacingMs, sleep, expectExit: expected, expectExitSet: setInput, pinStrict, classify, fetchImpl: classFetch });
    // Audit record: WHICH pin/set policy this check ran under — the campaign constructor
    // logs it as ghost.engagement so the ledger always names the exit policy an engagement
    // rode (never the operator baseline; canonical exit IPs only).
    this._pin = { expectExit: result.expectExit || null, exitSet: result.expectExitSet || null, at: result.at };
    if (!result.ok && result.pinStrict) {
      // Strict pin failed: CLOSE the gate (strengthening only — this can never open it).
      this._verified = { ok: false, exitIp: result.distinct[0] || null, at: result.at, error: result.reason };
      this._emit('ghost.refused', { host: '(pinStrict)', reason: result.reason });
    }
    this._lastExitCheck = result;
    this._emit('ghost.exitCheck', { ok: result.ok, verdict: result.verdict, distinct: result.distinct, pinMatch: result.pinMatch, setMatch: result.setMatch, warnings: result.warnings.length });
    return result;
  }

  // PER-HOP HEALTH (multi-hop visibility, 2026-09-01): hop k is probed THROUGH hops
  // 0..k-1 — hop 0 by direct TCP (+socks5 greeting when it's a socks hop), hop k>0 by
  // opening a tunnel through the path so far to the hop's own address and speaking the
  // greeting there. This measures REACHABILITY THROUGH THE CHAIN, never exit identity
  // (verify()/exitCheck own that). A dead hop marks all downstream hops ok:null
  // 'unprobed' — downstream health is unmeasurable through a broken hop, never guessed.
  // Cached 15s like refreshTor (status surfaces poll constantly). Never throws per-hop;
  // failures are recorded in the result.
  async probeHops({ timeout = 4000, force = false } = {}) {
    const nowMs = Date.now();
    if (!force && this._hopHealth && nowMs - this._hopHealth.atMs < 15000) return this._hopHealth;
    const hops = [];
    if (this.mode !== 'off' && this.chain.length) {
      for (let i = 0; i < this.chain.length; i++) {
        const hop = this.chain[i];
        const rec = { hop: `${hop.scheme}://${hop.host}:${hop.port}`, ok: false, latencyMs: null, error: null, probe: hop.scheme === 'socks5' ? 'socks5-greeting' : 'tcp-connect-through-path' };
        const t0 = Date.now();
        let sock = null;
        try {
          sock = i === 0 ? await tcpConnect(hop, timeout) : await openTunnel(this.chain.slice(0, i), hop.host, hop.port, timeout);
          if (hop.scheme === 'socks5') {
            rec.ok = await socks5GreetOn(sock, timeout);
            if (!rec.ok) rec.error = 'connected, but the socks5 greeting was refused or garbage';
          } else {
            rec.ok = true; // TCP reachability through the path so far — no CONNECT issued (a probe, not a proxied request)
          }
          rec.latencyMs = Date.now() - t0;
        } catch (e) {
          rec.error = String((e && e.message) || e);
        }
        try { sock && sock.destroy(); } catch {}
        hops.push(rec);
        if (!rec.ok) break; // downstream hops are unreachable THROUGH a dead hop
      }
      for (let i = hops.length; i < this.chain.length; i++) {
        const hop = this.chain[i];
        hops.push({ hop: `${hop.scheme}://${hop.host}:${hop.port}`, ok: null, latencyMs: null, error: 'unprobed — an earlier hop failed; downstream health is unmeasurable through it', probe: null });
      }
    }
    this._hopHealth = {
      ok: hops.length ? hops.every((h) => h.ok === true) : null,
      hops, at: new Date(nowMs).toISOString(), atMs: nowMs,
      note: 'greeting/reachability per hop through the path so far — NOT an exit measurement (verify/exitCheck own that); a healthy hop says nothing about who operates it',
    };
    this._emit('ghost.hopHealth', { ok: this._hopHealth.ok, hops: hops.map((h) => ({ hop: h.hop, ok: h.ok, latencyMs: h.latencyMs })) });
    return this._hopHealth;
  }

  // TLS-INSPECTION CHECK (lose-point #5 — engine/tlsinspect + tools/tlsinspect): probe a
  // reference set (operator-configurable tlsinspect.refs — well-known SaaS domains; our
  // own listener when the operator includes it) and classify each handshake's chain for
  // SSL-bump evidence. PATH DOCTRINE matches verify(): when armed, PUBLIC references ride
  // the chain (the probe measures the path engagement traffic would take — including a
  // bump upstream of the exit); PRIVATE references always dial direct (the lab never
  // leaves the lab). Ghost off = the direct egress is measured, which is exactly where an
  // enterprise bump sits. `probe` is injectable for hermetic tests. Never throws.
  async tlsCheck({ refs = 'api.github.com,www.microsoft.com', timeout = 4000, probe = probeTlsInspection } = {}) {
    // The chain-riding dial: public hosts tunnel through the armed chain, private hosts
    // (the listener reference) dial direct — identical routing to engagement traffic.
    const dial = (this.mode === 'off' || !this.chain.length)
      ? undefined
      : async (host, port) => (isPrivateDest(host) ? net.connect({ host, port }) : openTunnel(this.chain, host, port, 15000));
    const result = await probe({ refs, dial, timeout });
    this._lastTlsCheck = {
      ...result,
      path: dial ? 'chain (public refs) + direct (private refs)' : 'direct',
      // The posture only; adaptation is DECIDED by tlsinspect.policy (engine/settings)
      // and applied by rankTransports — this check never claims the inspection away.
    };
    this._emit('ghost.tlsCheck', { posture: result.posture, refs: result.refs.map((r) => ({ ref: r.ref, verdict: r.verdict })) });
    return this._lastTlsCheck;
  }

  // Cached local-Tor probe for status surfaces (15s cache — /api/state polls status()
  // constantly; probing every poll would be silly). Returns { detected, port, at }.
  async refreshTor({ force = false } = {}) {
    const now = Date.now();
    if (!force && this._tor && now - this._tor.at < 15000) return this._tor;
    const t = await detectTor();
    this._tor = { detected: !!t.ok, port: t.ok ? t.port : null, at: now };
    return this._tor;
  }

  // Fail-closed gate for PUBLIC egress. Private/range destinations always allowed (direct).
  async assertEgress(dest) {
    if (this.mode !== 'required') return true;
    const host = typeof dest === 'string' && dest.includes('://') ? new URL(dest).hostname : String(dest || '');
    if (isPrivateDest(host)) return true;
    if (!this.verifiedOk()) {
      const err = new Error(`ghost: public egress REFUSED to ${host} — identity chain not verified (mode=required). Arm a working chain or stand down.`);
      err.ghostRefused = true;
      this._emit('ghost.refused', { host });
      throw err;
    }
    return true;
  }

  // CORRELATION-RESISTANCE SELF-REPORT (2026-09-01): grade the CURRENT chain against the
  // checklist that matters vs an ISP-level / national adversary (flow + traffic
  // correlation, not just target-side attribution). PURE over cached state — no network,
  // no new measurement; whatever was never measured is graded UNVERIFIED, and NOTHING here
  // is ever asserted. Grades: pass | warn | fail | unverified. Overall is conservative:
  // any fail => fail; else anything short of pass => warn. 'pass' overall means only that
  // every check passed — it is NOT a claim of national-adversary immunity (the residual
  // statement says why, in plain language).
  substatus() {
    const checks = [];
    const push = (id, grade, detail) => checks.push({ id, grade, detail });
    const armed = this.mode !== 'off';

    push('mode',
      this.mode === 'required' ? 'pass' : this.mode === 'on' ? 'warn' : 'fail',
      this.mode === 'required'
        ? 'fail-closed: public egress is refused until verify() proves the exit differs from the operator baseline'
        : this.mode === 'on'
          ? 'best-effort: unverified public egress is ALLOWED — raises no fail-closed guarantee'
          : 'ghost off — egress is direct; the operator source is exposed to targets and the path');

    push('verified',
      !armed ? 'fail' : !this._verified ? 'unverified' : this._verified.ok ? 'pass' : 'fail',
      !armed
        ? 'ghost off — nothing to verify'
        : !this._verified
          ? 'verify() has never run on this chain — required mode refuses public egress until it passes'
          : this._verified.ok
            ? `exit ${this._verified.exitIp || '?'} differs from the operator baseline (${maskIp(this._verified.baselineIp)}) as of ${this._verified.at}`
            : 'verification FAILED: ' + (this._verified.error || 'unknown'));

    if (armed) {
      const n = this.chain.length;
      push('hops',
        n >= 2 ? 'pass' : 'warn',
        n >= 2
          ? `${n}-hop chain plumbed. Honest ceiling: hop INDEPENDENCE (different providers/jurisdictions, no shared logging) is operator config — not measurable from the app layer`
          : 'single-hop VPN: the operator\'s ISP sees the VPN provider\'s metadata AND the full timing/shape of the operator→VPN flow, and the provider sees both ends. Entry↔exit timing correlation against this shape costs a national adversary little. Multi-hop = operator config (Mullvad Bridges / a second proxy in the chain string)');
      push('dns', 'pass', 'resolved by the LAST proxy — code-level, test-pinned (an unresolvable name still egresses; no local DNS of targets)');

      const ec = this._lastExitCheck;
      const cls = ec && ec.egress && ec.egress.ok ? ec.egress.class : null;
      push('exitClass',
        cls === 'vpn' || cls === 'datacenter' ? 'warn' : cls === 'residential-ish' ? 'pass' : 'unverified',
        cls === 'vpn'
          ? `exit ASN is a known VPN provider (${(ec.egress && ec.egress.org) || '?'} [free-feed heuristic]) — attributable to "a Mullvad-class customer", never to the operator; blends-as-residential NO`
          : cls === 'datacenter'
            ? `exit is datacenter-class (${(ec.egress && ec.egress.org) || '?'} [free-feed heuristic]) — low-reputation, flagged by classification feeds`
            : cls === 'residential-ish'
              ? `exit class residential-ish [free-feed heuristic — paid classification feeds NOT covered]`
              : 'exit class never measured (run exitCheck — the ipinfo leg is offline-skipped and honest)');

      const hasPolicy = !!(ec && (ec.expectExit || ec.expectExitSet));
      const pinOk = ec && (ec.pinMatch === true || ec.setMatch === true);
      const pinBad = ec && (ec.pinMatch === false || ec.setMatch === false);
      push('pin',
        pinOk ? 'pass' : pinBad ? 'fail' : hasPolicy ? 'unverified' : 'warn',
        pinOk
          ? 'observed exit(s) match the declared pin/rotation set'
          : pinBad
            ? 'observed exit VIOLATES the declared pin/rotation set — named loudly; fail-closed under pinStrict'
            : hasPolicy
              ? 'a pin/set is declared but unproven (no successful sample)'
              : 'no exit pin or rotation set declared — the operator has not said WHICH exits are expected; rotation can silently break IP-bound sessions (the cf_clearance lesson) and a hijacked/mis-set chain would go unnoticed');

      push('stability',
        !ec ? 'unverified' : ec.verdict === 'stable' ? 'pass' : ec.verdict === 'rotating' ? 'warn' : 'unverified',
        !ec
          ? 'exit stability never measured (run exitCheck)'
          : ec.verdict === 'stable'
            ? `${ec.sampled} samples, one exit`
            : ec.verdict === 'rotating'
              ? `exit ROTATES (${(ec.distinct || []).join(', ') || '?'}) — fine for non-CF ops, fatal for IP-bound sessions`
              : 'stability unmeasurable — no sample succeeded');

      push('shaping',
        this.shaper ? 'pass' : 'warn',
        this.shaper
          ? `ghost shaper armed (floor ${this.shaper.minDelayMs}ms + ${this.shaper.jitterMs}ms jitter${this.shaper.padTo === 'mtu' ? ' + MTU-ward request padding' : ''}) — governed HTTP is paced/policed. TRUE constant-rate padding is impossible at the app layer — VPN-layer shaping (Mullvad DAITA) is operator-side and UNVERIFIABLE from here`
          : 'no ghost-level shaper — the engagement pacer is the only shaping; the operator→first-hop timing pattern is whatever the workload happens to look like');

      push('coverTraffic', 'warn',
        'NONE at the app layer — idle windows are silent, so an ISP correlating entry/exit sees the engagement\'s activity windows. App-layer cover traffic would multiply request volume and is not implemented; DAITA pads flows but is not cover traffic either. Residual, stated, accepted');

      push('tlsFingerprint', 'unverified',
        'the TLS ClientHello of Node/undici governed HTTP is not a browser\'s (JA4-class distinguishability); not measured here — fporacle/shapegrade grade wire fingerprints on the C2 side, not this HTTP egress');

      push('ipv6', 'unverified',
        'governed VARVEL traffic is fail-closed inside the chain, but UNGOVERNED system traffic (other apps, OS, a browser outside the chain) bypasses ghost by design — split-tunnel and in-tunnel IPv6 are operator-side settings (Mullvad app), not observable from here');

      const factors = [];
      if (this.chain.length < 2) factors.push('single-hop');
      if (!this.shaper) factors.push('no shaper');
      factors.push('no cover traffic');
      push('flowCorrelation', 'warn',
        `resistance to ISP-level entry↔exit flow correlation: LOW (${factors.join(', ')}). Multi-hop + VPN-layer padding (DAITA) raise the cost; NOTHING at the app layer defeats a national adversary holding both ends of the flow — and this platform never claims otherwise`);
    } else {
      for (const id of ['hops', 'dns', 'exitClass', 'pin', 'stability', 'shaping', 'coverTraffic', 'tlsFingerprint', 'ipv6', 'flowCorrelation']) {
        push(id, 'unverified', 'ghost off — check not applicable');
      }
    }

    const overall = checks.some((c) => c.grade === 'fail') ? 'fail'
      : checks.every((c) => c.grade === 'pass') ? 'pass' : 'warn';
    return {
      at: new Date().toISOString(),
      mode: this.mode,
      versus: 'ISP-level / national flow+traffic correlation (beyond target-side attribution)',
      overall,
      checks,
      residual: 'Even fully armed, this chain is ONE governed HTTP egress layer: it beats target-side attribution and raises ISP-correlation cost, but a national adversary with both path ends + classification feeds retains the advantage. The operator-side residua are named in docs/EGRESS.md (multi-hop Bridges, DAITA, dedicated proxies, split-tunnel/IPv6). Anything UNVERIFIED above was never measured — it is not claimed.',
    };
  }

  status() {
    return {
      mode: this.mode,
      chain: this.chain.map((h) => `${h.scheme}://${h.host}:${h.port}`), // never credentials
      hops: this.chain.length,
      checkUrl: this.mode === 'off' ? null : this.checkUrl,
      verified: this._verified ? { ...this._verified, baselineIp: maskIp(this._verified.baselineIp) } : null,
      dns: this.mode === 'off' ? 'direct' : 'resolved-by-last-proxy (no local DNS leak)',
      privateDestinations: 'always direct (range traffic never leaves the lab)',
      exitCheck: this._lastExitCheck || null, // additive: last pre-engagement egress check (engine/egresscheck)
      tlsInspect: this._lastTlsCheck || null, // additive: last TLS-inspection probe (engine/tlsinspect posture + per-reference evidence)
      tor: this._tor ? { detected: this._tor.detected, port: this._tor.port } : null,
      shaper: this.shaper, // additive: ghost-level shaping policy the campaign pacer is policed by (null = none)
      exitSet: this._exitSet ? [...this._exitSet] : null, // additive: operator-declared rotation set (canonical)
      exitSetDropped: [...this._exitSetDropped], // additive: set entries that failed to parse — kept visible, never silently narrower
      hopHealth: this._hopHealth ? { ok: this._hopHealth.ok, hops: this._hopHealth.hops, at: this._hopHealth.at, note: this._hopHealth.note } : null, // additive: last per-hop probe (probeHops, 15s cache)
      pin: this._pin, // additive: the pin/set policy the last exitCheck ran under (the campaign ghost.engagement audit reads it)
      substatus: this.substatus(), // additive: correlation-resistance self-report (pure over cached state, no network)
    };
  }
}

function maskIp(ip) {
  const p = parseIp(ip);
  if (!p) return ip;
  if (p.fam === 4) { const o = p.text.split('.'); return `${o[0]}.${o[1]}.x.x`; }
  return `${p.groups[0].toString(16)}:${p.groups[1].toString(16)}::…`;
}
