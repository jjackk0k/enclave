// VARVEL — ghostfetch: the ghost-chain transport for the hunt's external traffic.
//
// WHY IT EXISTS (production bug, first live hunt 2026-09-09): the console's ghost
// gate VERIFIED the chain (socks5://10.64.0.1:1080, the Mullvad in-tunnel up-link)
// and then the hunt loop's watcher talked to the H1 API DIRECT — one ESTABLISHED
// idle connection to Cloudflare, identity exposed, and (worse) a stalled body the
// old h1Get timeout could not cover. From here on, ALL external hunt traffic rides
// the chain the settings arm. The brain stays direct (127.0.0.1:8080 is local).
//
// HARD RULES:
//   1. FAIL CLOSED: a chain that is configured but unreachable is a NAMED error
//      ('ghost-chain-down') — the caller must refuse loudly; there is NO silent
//      fall-back to direct egress. (No chain configured at all = direct, and the
//      caller says so — the console's ghost gate is what requires a chain.)
//   2. REMOTE DNS: the SOCKS5 CONNECT goes out with ATYP=domain — the resolver is
//      the proxy's, never the local one (the DNS-leak posture, by construction).
//   3. ZERO-DEP + AUDITED: node:net + node:tls only (the repo has no socks dep —
//      this file IS the small audited transport: no eval, strict parsing, bounded
//      reads, every byte accounted for). A proxy answer in ANY other shape is a
//      hard error, never a guess.
//   4. LOCAL STAYS LOCAL: 127.0.0.1 / localhost / ::1 targets ALWAYS go direct
//      (mock servers in tests, the brain lane) — named, never hidden.
//   5. TIMEOUTS ARE WHOLE-OPERATION: the deadline covers connect, handshake, TLS,
//      request AND the full body read (the h1Get-stall lesson: a headers-then-
//      silence response must die at the deadline, not park forever).
//
// Chain resolution (mirror of the console's ghost gate, spark_code/opsmenu.py):
//   1. env VARVEL_GHOST_CHAIN (explicit override — wins)
//   2. the VARVEL_ENGAGEMENT bucket's ghost.chain in data/settings.json
//   3. the first bucket with ghost.mode on|required AND a chain
//   4. the first bucket carrying any ghost.chain
//   The source bucket is named in the result — never a silent guess.

import net from 'node:net';
import tls from 'node:tls';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dir = dirname(fileURLToPath(import.meta.url));
const SETTINGS_FILE = () => process.env.VARVEL_SETTINGS_FILE || join(__dir, '..', 'data', 'settings.json');

export const LOCAL_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

// SOCKS5 reply codes → meanings (never reported bare).
export const SOCKS5_REPS = {
  0x01: 'general SOCKS server failure',
  0x02: 'connection not allowed by ruleset',
  0x03: 'network unreachable',
  0x04: 'host unreachable',
  0x05: 'connection refused',
  0x06: 'TTL expired',
  0x07: 'command not supported',
  0x08: 'address type not supported',
};

export class GhostError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

// resolveGhostChain({ env, settingsFile }) -> { chain, source, mode } | null.
// Reads the settings store DIRECTLY (the same file the console's gate reads) —
// no Settings registry import, so a watcher process never caches a stale chain.
export function resolveGhostChain({ env = process.env, settingsFile } = {}) {
  if (env.VARVEL_GHOST_CHAIN) {
    return { chain: String(env.VARVEL_GHOST_CHAIN).split(',')[0].trim(), source: 'env VARVEL_GHOST_CHAIN', mode: 'explicit' };
  }
  const file = settingsFile || SETTINGS_FILE();
  let doc = null;
  try { doc = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : null; } catch { doc = null; }
  if (!doc || typeof doc !== 'object') return null;
  const pick = (eng) => {
    const e = doc[eng];
    if (!e || typeof e !== 'object' || !e['ghost.chain']) return null;
    return {
      chain: String(e['ghost.chain']).split(',')[0].trim(),
      source: `settings.json bucket '${eng}'`,
      mode: String(e['ghost.mode'] || 'off'),
      expectExit: e['ghost.expectExit'] || null,
      pinStrict: e['ghost.pinStrict'] === true,
    };
  };
  if (env.VARVEL_ENGAGEMENT) {
    const named = pick(env.VARVEL_ENGAGEMENT);
    if (named) return named;
  }
  for (const eng of Object.keys(doc)) {
    const c = pick(eng);
    if (c && (c.mode === 'on' || c.mode === 'required')) return c;
  }
  for (const eng of Object.keys(doc)) {
    const c = pick(eng);
    if (c) return c;
  }
  return null;
}

export function parseProxy(chainUrl) {
  let u;
  try { u = new URL(chainUrl); } catch { throw new GhostError('ghost-chain-invalid', `unparseable ghost chain URL: ${chainUrl}`); }
  const scheme = (u.protocol || '').replace(':', '').toLowerCase();
  if (scheme !== 'socks5' && scheme !== 'socks5h') {
    throw new GhostError('ghost-chain-invalid', `ghost chain scheme '${scheme}' is not supported (socks5 only — refused loudly, no silent downgrade)`);
  }
  if (!u.hostname) throw new GhostError('ghost-chain-invalid', `ghost chain carries no host: ${chainUrl}`);
  return { scheme, host: u.hostname, port: Number(u.port) || 1080 };
}

// A per-socket buffered reader: recvExact(n) returns exactly n bytes and KEEPS
// any surplus for the next read (the first version dropped it — a reply that
// arrived in one segment wedged the handshake; proven by the debug trace).
function makeReader(sock) {
  let buf = Buffer.alloc(0);
  const read = (n) => new Promise((resolve, reject) => {
    if (buf.length >= n) {
      const out = buf.subarray(0, n);
      buf = buf.subarray(n);
      return resolve(out);
    }
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= n) {
        cleanup();
        const out = buf.subarray(0, n);
        buf = buf.subarray(n);
        resolve(out);
      }
    };
    const onErr = (e) => { cleanup(); reject(e || new Error('socket closed mid-reply')); };
    const cleanup = () => { sock.off('data', onData); sock.off('error', onErr); sock.off('close', onErr); };
    sock.on('data', onData);
    sock.on('error', onErr);
    sock.on('close', onErr); // a destroyed socket (deadline/abort) closes — never hang
  });
  read.leftover = () => buf; // bytes already read past the handshake — handed to the HTTP reader
  return read;
}

// A whole-operation deadline: rejects via the given promise AND destroys the socket.
// HARD RULE (the 2026-09-10 'ghost-timeout' process crash): destroy() takes NO error
// argument here — destroy(err) manufactures an 'error' EVENT that can land in a
// listener-less microtask gap and kill the process. The rejection channel below is
// the only path the error takes.
function makeDeadline(sock, timeoutMs, what, signal) {
  let timer = null;
  const onAbort = () => fire(new GhostError('ghost-timeout', `${what} aborted by the caller's signal`));
  const fire = (err) => { try { sock.destroy(); } catch { /* already gone */ } };
  const p = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const err = new GhostError('ghost-timeout', `${what} exceeded the ${timeoutMs}ms whole-operation deadline (headers-then-silence is a stall, not a wait — the 2026-09-09 lesson)`);
      fire(err);
      reject(err);
    }, timeoutMs);
    if (signal) {
      if (signal.aborted) onAbort();
      else signal.addEventListener('abort', () => { const e = new GhostError('ghost-timeout', `${what} aborted`); fire(e); reject(e); }, { once: true });
    }
  });
  p.catch(() => {}); // the loser of a race must never be an unhandled rejection
  return {
    race: (q) => {
      const tracked = Promise.resolve(q);
      tracked.catch(() => {}); // if the deadline wins, q's later rejection is handled
      return Promise.race([tracked, p]);
    },
    done: () => clearTimeout(timer),
  };
}

// socks5Connect({ proxy, destHost, destPort, timeoutMs, signal }) -> net.Socket
// through the chain. ATYP=domain: the destination NAME goes to the proxy —
// remote resolution, by construction.
export async function socks5Connect({ proxy, destHost, destPort, timeoutMs = 20000, signal }) {
  const sock = net.connect({ host: proxy.host, port: proxy.port });
  // Durable error sink: a socket error event with no attached listener crashes the
  // process outright (the 2026-09-10 'ghost-timeout' kill). From birth to death the
  // socket keeps this handler; phase-level once('error') listeners still fire too.
  sock.on('error', () => {});
  const read = makeReader(sock);
  const dead = makeDeadline(sock, timeoutMs, `SOCKS5 dial ${proxy.host}:${proxy.port} -> ${destHost}:${destPort}`, signal);
  try {
    await dead.race(new Promise((resolve, reject) => {
      sock.once('connect', resolve);
      sock.once('error', reject);
    }));
  } catch (e) {
    dead.done();
    if (e && e.code && String(e.code).startsWith('ghost')) throw e;
    throw new GhostError('ghost-chain-down', `the ghost proxy ${proxy.host}:${proxy.port} is not dialable (${(e && e.code) || (e && e.message) || e}) — FAIL CLOSED, no direct fall-back`);
  }
  try {
    sock.write(Buffer.from([0x05, 0x01, 0x00])); // VER 5, 1 method, no-auth
    const method = await dead.race(read(2));
    if (method[0] !== 0x05 || method[1] !== 0x00) {
      throw new GhostError('ghost-chain-down', `proxy refused no-auth SOCKS5 (method 0x${method[1].toString(16)}) — it demands authentication`);
    }
    const hb = Buffer.from(destHost, 'utf8');
    const req = Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, hb.length]), hb]);
    const portBuf = Buffer.alloc(2);
    portBuf.writeUInt16BE(destPort, 0);
    sock.write(Buffer.concat([req, portBuf]));
    const hdr = await dead.race(read(4));
    if (hdr[0] !== 0x05) throw new GhostError('ghost-chain-down', `proxy answered the CONNECT with a non-SOCKS5 byte 0x${hdr[0].toString(16)}`);
    if (hdr[1] !== 0x00) {
      throw new GhostError('ghost-connect-refused', `proxy CONNECT to ${destHost}:${destPort} refused: ${SOCKS5_REPS[hdr[1]] || `REP 0x${hdr[1].toString(16)}`}`);
    }
    const atyp = hdr[3]; // drain BND.ADDR
    if (atyp === 0x01) await dead.race(read(4));
    else if (atyp === 0x03) { const ln = await dead.race(read(1)); await dead.race(read(ln[0])); }
    else if (atyp === 0x04) await dead.race(read(16));
    else throw new GhostError('ghost-chain-down', `proxy returned an unknown BND.ATYP 0x${atyp.toString(16)}`);
    await dead.race(read(2)); // BND.PORT
    dead.done();
    sock._ghostLeftover = read.leftover(); // handshake surplus belongs to the HTTP reader
    return sock;
  } catch (e) {
    dead.done();
    try { sock.destroy(); } catch { /* already gone */ }
    if (e && e.code && String(e.code).startsWith('ghost')) throw e;
    throw new GhostError('ghost-chain-down', `SOCKS5 handshake with ${proxy.host}:${proxy.port} failed: ${(e && e.message) || e} — FAIL CLOSED`);
  }
}

// --- the minimal audited HTTP/1.1 reader -------------------------------------------------
// Enough of the protocol for JSON:API GETs: status line, headers, a body framed by
// content-length OR chunked (read to connection close otherwise). Response MUST be
// identity-encoded — we never offer accept-encoding, and a content-encoding that
// still arrives is a hard error (never gunzip blindly, never guess).
const MAX_HEADER_BYTES = 16384;
const MAX_BODY_BYTES = 8 * 1024 * 1024;

async function readHttpResponse(sock, dead, seed, { bodyless = false } = {}) {
  let buf = seed && seed.length ? Buffer.from(seed) : Buffer.alloc(0);
  const take = async () => {
    const chunk = await dead.race(new Promise((resolve, reject) => {
      sock.once('data', resolve);
      sock.once('error', reject);
      sock.once('end', () => resolve(null));
      sock.once('close', () => resolve(null)); // a destroyed socket ends the read
    }));
    if (chunk === null) return false;
    buf = Buffer.concat([buf, chunk]);
    if (buf.length > MAX_BODY_BYTES) throw new GhostError('ghost-bad-response', `response exceeded the ${MAX_BODY_BYTES}-byte read bound`);
    return true;
  };
  const idxOf = (needle) => buf.indexOf(needle);
  while (idxOf('\r\n\r\n') === -1) {
    if (!(await take()) || buf.length > MAX_HEADER_BYTES) {
      throw new GhostError('ghost-bad-response', 'response headers never completed (bounded read)');
    }
  }
  const headEnd = idxOf('\r\n\r\n') + 4;
  const head = buf.subarray(0, headEnd).toString('latin1');
  buf = buf.subarray(headEnd); // buf stays THE live body accumulator — every take() appends to it
  const lines = head.split('\r\n');
  const m = /^HTTP\/\d\.\d (\d{3})(?: (.*))?$/.exec(lines[0]);
  if (!m) throw new GhostError('ghost-bad-response', `unparseable status line: ${lines[0].slice(0, 80)}`);
  const status = Number(m[1]);
  const headers = {};
  for (const line of lines.slice(1)) {
    const ix = line.indexOf(':');
    if (ix > 0) headers[line.slice(0, ix).trim().toLowerCase()] = line.slice(ix + 1).trim();
  }
  if (headers['content-encoding'] && headers['content-encoding'] !== 'identity') {
    throw new GhostError('ghost-bad-response', `response arrived content-encoding '${headers['content-encoding']}' — we never offered it; refusing to guess`);
  }
  let body;
  if (bodyless) {
    // HEAD: the response carries NO body by definition (RFC 9110 §9.3.2) — its
    // framing headers describe the hypothetical GET and are never read as bytes.
    body = Buffer.alloc(0);
  } else if (headers['transfer-encoding'] && /chunked/i.test(headers['transfer-encoding'])) {
    // strict chunked reader: every chunk length line + exactly that many bytes + CRLF
    const out = [];
    for (;;) {
      let ix = buf.indexOf('\r\n');
      while (ix === -1) { if (!(await take())) throw new GhostError('ghost-bad-response', 'chunked body truncated mid chunk-size'); ix = buf.indexOf('\r\n'); }
      const size = parseInt(buf.subarray(0, ix).toString('latin1').split(';')[0], 16);
      if (!Number.isFinite(size)) throw new GhostError('ghost-bad-response', 'unparseable chunk size');
      const need = ix + 2 + size + 2;
      while (buf.length < need) { if (!(await take())) throw new GhostError('ghost-bad-response', 'chunked body truncated mid chunk'); }
      if (size === 0) { buf = buf.subarray(need); break; }
      out.push(buf.subarray(ix + 2, ix + 2 + size));
      buf = buf.subarray(need);
    }
    body = Buffer.concat(out);
  } else if (headers['content-length'] !== undefined) {
    const len = Number(headers['content-length']);
    if (!Number.isFinite(len) || len < 0) throw new GhostError('ghost-bad-response', `bad content-length '${headers['content-length']}'`);
    while (buf.length < len) { if (!(await take())) throw new GhostError('ghost-bad-response', `body truncated: ${buf.length} of ${len} bytes`); }
    body = buf.subarray(0, len);
  } else {
    // no framing: read to connection close (we send Connection: close)
    while (await take()) { /* accumulate */ }
    body = buf;
  }
  return { status, headers, body: body.toString('utf8') };
}

// ghostFetch(chainUrl, { timeoutMs }) -> a fetch-shaped async (url, { headers, signal })
// covering h1Get's whole contract: { ok, status, json() } (+ text()). Non-local
// targets ride the chain; local targets go DIRECT (rule 4) via the global fetch.
//
// THE READ-ONLY METHOD EXTENSION (the poc-forge's probe path): the returned fn
// also accepts { method, body } — GET (default), HEAD, POST only, a body rides
// POST alone (16KB cap). Any other verb, or a body on GET/HEAD, is refused
// BEFORE a byte leaves ('ghost-method-refused') — the transport's read-only
// posture is enforced here, at the one place the bytes are written.
export function ghostFetch(chainUrl, { timeoutMs = 20000 } = {}) {
  const proxy = parseProxy(chainUrl);
  return async function proxiedGet(url, { headers = {}, signal, method = 'GET', body } = {}) {
    const verb = String(method || 'GET').toUpperCase();
    if (!/^(GET|HEAD|POST)$/.test(verb)) {
      throw new GhostError('ghost-method-refused', `the audited transport speaks GET/HEAD/POST only — '${method}' refused (the read-only posture, fail-closed)`);
    }
    if (body !== undefined && body !== null && verb !== 'POST') {
      throw new GhostError('ghost-method-refused', `a request body rides POST only — ${verb} carries none (the read-only posture)`);
    }
    const bodyBuf = body === undefined || body === null ? null : Buffer.from(String(body), 'utf8');
    if (bodyBuf && bodyBuf.length > 16384) {
      throw new GhostError('ghost-body-too-large', `the probe body exceeded the 16KB transport bound (${bodyBuf.length} bytes)`);
    }
    const u = new URL(url);
    const host = u.hostname.replace(/^\[|\]$/g, '');
    if (LOCAL_HOSTS.has(host) || LOCAL_HOSTS.has(u.hostname)) {
      return fetch(url, { headers, signal, method: verb, ...(bodyBuf ? { body: bodyBuf } : {}) }); // local stays local — mock servers, the brain
    }
    const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
    const sock = await socks5Connect({ proxy, destHost: host, destPort: port, timeoutMs, signal });
    // Bytes read past the socks handshake (an eager server's early bytes) are NEVER
    // dropped: TLS gets them unshifted back onto the wire; plain HTTP gets them as
    // the reader's seed.
    const leftover = sock._ghostLeftover && sock._ghostLeftover.length ? sock._ghostLeftover : null;
    let transport = sock;
    let seed = leftover;
    if (u.protocol === 'https:') {
      if (leftover) { try { sock.unshift(leftover); } catch { /* stream state refuses — the handshake deadline names it honestly */ } }
      seed = null; // the tls layer consumes the wire, leftovers included
      transport = tls.connect({ socket: sock, servername: host });
      transport.on('error', () => {}); // durable sink — same crash-guard as the raw socket
      const tdead = makeDeadline(transport, timeoutMs, `TLS handshake ${host}:${port} via the chain`, signal);
      await tdead.race(new Promise((resolve, reject) => {
        transport.once('secureConnect', resolve);
        transport.once('error', reject);
      }));
      tdead.done();
    }
    const dead = makeDeadline(transport, timeoutMs, `GET ${host}${u.pathname} via the chain`, signal);
    try {
      const path = (u.pathname || '/') + (u.search || '');
      const lines = [
        `${verb} ${path} HTTP/1.1`,
        `Host: ${u.host}`,
        'Connection: close',
      ];
      for (const [k, v] of Object.entries(headers)) {
        const hk = String(k).toLowerCase();
        // Framing + hop-by-hop + identity-negotiation headers are owned by the
        // transport — a caller-supplied one is DROPPED, never honored (one
        // writer of the framing, always: the request-smuggling posture).
        if (hk === 'accept-encoding' || hk === 'host' || hk === 'connection' || hk === 'content-length' || hk === 'transfer-encoding') continue;
        lines.push(`${k}: ${v}`);
      }
      if (bodyBuf) lines.push(`content-length: ${bodyBuf.length}`);
      transport.write(Buffer.concat([Buffer.from(lines.join('\r\n') + '\r\n\r\n', 'latin1'), bodyBuf || Buffer.alloc(0)]));
      const res = await dead.race(readHttpResponse(transport, dead, seed, { bodyless: verb === 'HEAD' }));
      dead.done();
      return {
        ok: res.status >= 200 && res.status < 300,
        status: res.status,
        headers: res.headers,
        json: async () => JSON.parse(res.body),
        text: async () => res.body,
      };
    } finally {
      dead.done();
      try { transport.destroy(); } catch { /* already closed */ }
    }
  };
}

// ghostPreflight(chainUrl, { timeoutMs }) — the loop's own fail-closed check:
// dial the proxy and CONNECT the H1 API host through it. ok:true means the
// chain is VERIFIED USABLE (the event the console's GHOST card shows).
export async function ghostPreflight(chainUrl, { host = 'api.hackerone.com', port = 443, timeoutMs = 12000, signal } = {}) {
  try {
    const proxy = parseProxy(chainUrl);
    const sock = await socks5Connect({ proxy, destHost: host, destPort: port, timeoutMs, signal });
    try { sock.destroy(); } catch { /* already gone */ }
    return { ok: true, detail: `chain dials and CONNECTs ${host}:${port} (remote DNS)` };
  } catch (e) {
    return { ok: false, error: (e && e.code) || 'ghost-chain-down', detail: (e && e.message) || String(e) };
  }
}
