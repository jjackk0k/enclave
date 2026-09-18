// VARVEL -- fporacle: the fingerprint self-awareness oracle (the live side).
//
// Why it exists: same doctrine as detoracle, one layer down. A nation-grade offensive
// platform must MEASURE exactly what it looks like on the wire, never assert it. detoracle
// answers "did the defender log it?"; fporacle answers "what would the defender's JA4/JA4S/
// JA4H stack see?" -- our own ClientHello, a server's ServerHello, and every request that
// reaches the governed channel, rendered into the industry's standard fingerprints plus
// the raw shape facts. All fingerprint math lives in engine/fingerprint.mjs (pure); this
// file is the I/O shell.
//
// THE HONESTY CONTRACT (non-negotiable): a fingerprint is a MEASUREMENT, never a verdict.
// fporacle REPORTS fingerprints, shape facts, and mismatch flags. It NEVER claims
// undetectability ("matches Chrome's published JA4" is only ever string equality, not
// indistinguishability), and it builds/suggests NO evasion internals. Live paths never
// throw: failures come back as { ok: false, error }.

import net from 'node:net';
import { parseClientHello, ja4, parseServerHello, ja4s, ja4h, httpShape, fingerprintFindings } from '../engine/fingerprint.mjs';

const hex4 = (v) => v.toString(16).padStart(4, '0');

// One FIXED probe ClientHello, byte-deterministic: same hello out every time, so JA4S
// responses are comparable run over run. TLS1.2 record, supported_versions 1.3+1.2, SNI,
// ALPN h2+http/1.1, 15 common ciphers, 12 common extensions -- including a fixed (dummy)
// x25519 key_share so TLS1.3 servers answer with a full ServerHello. We only ever read
// the FIRST record back; the handshake is never completed (that is the point of a probe).
export function buildProbeClientHello(servername) {
  const u16 = (...vs) => Buffer.from(vs.flatMap((v) => [(v >> 8) & 0xff, v & 0xff]));
  const ext = (type, data) => Buffer.concat([u16(type, data.length), data]);
  const exts = [];

  const sni = Buffer.from(String(servername || ''), 'utf8');
  if (sni.length) exts.push(ext(0x0000, Buffer.concat([u16(3 + sni.length), Buffer.from([0x00]), u16(sni.length), sni]))); // server_name
  exts.push(ext(0x0010, Buffer.concat([u16(12), Buffer.from([2]), Buffer.from('h2', 'latin1'), Buffer.from([8]), Buffer.from('http/1.1', 'latin1')]))); // ALPN
  exts.push(ext(0x002b, Buffer.concat([Buffer.from([4]), u16(0x0304, 0x0303)])));                    // supported_versions: 1.3, 1.2
  exts.push(ext(0x000d, Buffer.concat([u16(16), u16(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)]))); // signature_algorithms
  exts.push(ext(0x000a, Buffer.concat([u16(8), u16(0x001d, 0x0017, 0x0018, 0x0019)])));              // supported_groups
  exts.push(ext(0x000b, Buffer.from([1, 0])));                                                       // ec_point_formats: uncompressed
  exts.push(ext(0x0033, Buffer.concat([u16(36), u16(0x001d, 32), Buffer.alloc(32, 0x56)])));         // key_share: x25519 dummy
  exts.push(ext(0x002d, Buffer.from([1, 1])));                                                       // psk_key_exchange_modes: psk_dhe_ke
  exts.push(ext(0x0017, Buffer.alloc(0)));                                                           // extended_master_secret
  exts.push(ext(0xff01, Buffer.from([0])));                                                          // renegotiation_info
  exts.push(ext(0x0005, Buffer.from([1, 0, 0, 0, 0])));                                              // status_request: ocsp
  exts.push(ext(0x0023, Buffer.alloc(0)));                                                           // session_ticket

  const cipherBytes = u16(0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035);
  const extBytes = Buffer.concat(exts);
  const body = Buffer.concat([
    u16(0x0303),                  // legacy_version: TLS1.2 (real version rides 0x002b)
    Buffer.alloc(32, 0x56),       // random (fixed -- deterministic probe bytes)
    Buffer.from([0]),             // legacy_session_id: empty
    u16(cipherBytes.length), cipherBytes,
    Buffer.from([1, 0]),          // compression_methods: null only
    u16(extBytes.length), extBytes,
  ]);
  const hs = Buffer.concat([Buffer.from([1]), Buffer.from([(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff]), body]);
  return Buffer.concat([Buffer.from([22, 3, 1]), u16(hs.length), hs]);
}

// Active JA4S: send the fixed probe hello, read one record back, fingerprint it.
// Never throws: { ok:false, error } on refusal/timeout/alert/garbage.
export async function probeJa4s(host, port, { servername, timeout = 3000 } = {}) {
  try {
    const p = Number(port);
    if (!host || !Number.isInteger(p) || p <= 0 || p > 65535) return { ok: false, error: 'probeJa4s needs a host and a valid port' };
    const hello = buildProbeClientHello(servername || host);
    return await new Promise((resolve) => {
      let done = false, buf = Buffer.alloc(0);
      const sock = net.connect({ host: String(host), port: p });
      const finish = (out) => { if (!done) { done = true; try { sock.destroy(); } catch {} resolve(out); } };
      sock.setTimeout(timeout);
      sock.once('connect', () => { try { sock.write(hello); } catch (e) { finish({ ok: false, error: String((e && e.message) || e) }); } });
      sock.on('data', (d) => {
        buf = Buffer.concat([buf, d]);
        if (buf.length < 5 || buf.length < 5 + buf.readUInt16BE(3)) return; // wait for the full first record
        const sh = parseServerHello(buf);
        if (!sh) return finish({ ok: false, error: 'response was not a parseable TLS ServerHello (alert, plaintext, or garbage)' });
        finish({ ok: true, ja4s: ja4s(sh), version: hex4(sh.version), cipher: hex4(sh.cipher), alpn: sh.alpn });
      });
      sock.on('timeout', () => finish({ ok: false, error: 'timeout waiting for ServerHello' }));
      sock.on('error', (e) => finish({ ok: false, error: String((e && e.message) || e) }));
      sock.on('close', () => finish({ ok: false, error: 'connection closed before a full ServerHello' }));
    });
  } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
}

// Passive JA4: accept ONE connection on a temporary listener, capture the first TLS
// record (the ClientHello), close. `connect(port)` is INJECTED -- it triggers the client
// (tests inject node tls.connect; live callers can inject any client driver). Never throws.
export async function captureJa4({ listen = '127.0.0.1', port = 0, connect, timeout = 3000 } = {}) {
  try {
    if (typeof connect !== 'function') return { ok: false, error: 'captureJa4 needs an injected connect(port) that triggers the client' };
    return await new Promise((resolve) => {
      let done = false, timer = null;
      const server = net.createServer((sock) => {
        let buf = Buffer.alloc(0);
        sock.on('data', (d) => {
          buf = Buffer.concat([buf, d]);
          if (buf.length < 5 || buf.length < 5 + buf.readUInt16BE(3)) return;
          try { sock.end(); } catch {}
          const parsed = parseClientHello(buf);
          if (!parsed) return finish({ ok: false, error: 'first record was not a parseable TLS ClientHello' });
          finish({
            ok: true,
            ja4: ja4(parsed),
            parsed: {
              version: hex4(parsed.version),
              ciphers: parsed.ciphers.map(hex4),
              extensions: parsed.extensions.map(hex4),
              sni: parsed.sni,
              alpn: parsed.alpn,
              sigalgs: parsed.sigalgs.map(hex4),
            },
          });
        });
        sock.on('error', () => { /* the client gives up once we close -- expected */ });
      });
      const finish = (out) => {
        if (done) return;
        done = true;
        if (timer) clearTimeout(timer);
        try { server.close(); } catch {}
        resolve(out);
      };
      server.on('error', (e) => finish({ ok: false, error: String((e && e.message) || e) }));
      server.listen(Number(port) || 0, String(listen), () => {
        timer = setTimeout(() => finish({ ok: false, error: 'timeout waiting for the ClientHello' }), timeout);
        if (timer.unref) timer.unref();
        try { connect(server.address().port); } catch (e) { finish({ ok: false, error: 'connect() threw: ' + String((e && e.message) || e) }); }
      });
    });
  } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
}

// Ordered [name, value] pairs out of a node req (rawHeaders preserves order + case).
function pairsFromReq(req) {
  const raw = req && Array.isArray(req.rawHeaders) ? req.rawHeaders : [];
  const pairs = [];
  for (let i = 0; i + 1 < raw.length; i += 2) pairs.push([String(raw[i]), String(raw[i + 1])]);
  return pairs;
}

// The passive HTTP observer: every request that reaches the channel is fingerprinted into
// a bounded ring. Passive by contract -- observe() NEVER throws and NEVER touches the
// response path.
export function createHttpObserver({ ringSize = 50 } = {}) {
  const ring = [];
  const cap = Math.max(1, Number(ringSize) || 50);
  const observe = (req) => {
    try {
      const headers = pairsFromReq(req);
      const fp = ja4h({ method: req.method, httpVersion: req.httpVersion, headers });
      if (!fp) return;
      const shape = httpShape(headers);
      ring.push({
        at: new Date().toISOString(),
        route: String(req.url || '').split('?')[0],
        remoteIp: (req.socket && req.socket.remoteAddress) || '',
        agent: (req.headers && req.headers['x-agent']) || null, // shaping pack: per-agent attribution for the shapegrade loop (null on non-channel requests)
        ja4h: fp,
        shapeSummary: {
          count: shape.count,
          hasUA: shape.hasUA,
          hasAccept: shape.hasAccept,
          hasAcceptLanguage: shape.hasAcceptLanguage,
          hasExpect: shape.hasExpect,
          customXHeaders: shape.customXHeaders,
        },
      });
      while (ring.length > cap) ring.shift();
    } catch { /* passive observer: never breaks the request path */ }
  };
  const status = () => ({ observations: ring.slice(), distinctJa4h: new Set(ring.map((o) => o.ja4h)).size });
  return { observe, status };
}

// One-shot composition: fingerprint + shape + findings for a single request.
export function assessHttp(req, { claimedUA } = {}) {
  try {
    const headers = pairsFromReq(req);
    const shape = httpShape(headers);
    return {
      ja4h: ja4h({ method: req && req.method, httpVersion: req && req.httpVersion, headers }),
      shape,
      findings: fingerprintFindings({ shape, claimedUA }),
    };
  } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
}
