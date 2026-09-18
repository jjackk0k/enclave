// VARVEL — DNS-style check-in codec (alternate transport for the range).
//
// Cobalt-grade malleability includes transports beyond plain HTTP. This codec encodes the
// EXACT same governed payloads (agent id, seq, HMAC, task pull/result) as DNS-lookalike
// label chains — the agent's check-in becomes something shaped like a domain query, and
// the channel's reply is an encoded answer body. Same governance as /c /r: HMAC-authed,
// replay-protected, scope-enforced, audited. A true UDP DNS listener is an infra piece for
// later; the range speaks this codec over the /d route so the transport shape is real and
// testable end-to-end today.

const B32 = '0123456789abcdefghijklmnopqrstuv'; // base32hex — DNS-label-safe, lowercase

export function b32encode(buf) {
  const bytes = Buffer.isBuffer(buf) ? buf : Buffer.from(String(buf));
  let bits = 0, value = 0, out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function b32decode(str) {
  const s = String(str || '').toLowerCase();
  const bytes = [];
  let bits = 0, value = 0;
  for (const ch of s) {
    const idx = B32.indexOf(ch);
    if (idx < 0) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(bytes);
}

// Pack a JSON payload into DNS-lookalike labels (63 chars max each). Real-DNS wires
// enforce their own name-length limits at the wire; decode-side accepts up to 2048
// (see decodeQuery) because chunked pushes legitimately exceed DNS-realistic sizes.
export function encodeQuery(payloadObj, { domain = 'ax.sim' } = {}) {
  const enc = b32encode(Buffer.from(JSON.stringify(payloadObj)));
  const labels = [];
  for (let i = 0; i < enc.length; i += 63) labels.push(enc.slice(i, i + 63));
  return [...labels, domain].join('.');
}

// Unpack. Returns the payload object, or null on any malformed shape (fail-closed).
export function decodeQuery(qname, { domain = 'ax.sim' } = {}) {
  const q = String(qname || '').toLowerCase().replace(/\.+$/, '');
  const suffix = '.' + domain;
  if (!q.endsWith(suffix)) return null;
  const enc = q.slice(0, q.length - suffix.length).replace(/\./g, '');
  // The 480 cap was a DNS-realism nod (names ≤253) — but the agent's chunked pushes
  // legitimately reach ~482 chars once i/n/s go two-digit (a 1400B result = 15 chunks),
  // and those tail chunks were silently rejected (range-proven: 4-chunk pushes landed,
  // 15-chunk pushes died at chunk 10 with zero error anywhere). 2048 keeps the shape
  // check without eating real traffic; the real-DNS wire still enforces its own limits.
  if (!enc || enc.length > 2048 || !/^[0-9a-v]+$/.test(enc)) return null;
  const buf = b32decode(enc);
  if (!buf || !buf.length) return null;
  try { const obj = JSON.parse(buf.toString('utf8')); return obj && typeof obj === 'object' ? obj : null; }
  catch { return null; }
}

// Encode a reply body (task JSON, or '' for the idle case).
export function encodeReply(payloadObj) {
  if (payloadObj == null) return '';
  return b32encode(Buffer.from(JSON.stringify(payloadObj)));
}
