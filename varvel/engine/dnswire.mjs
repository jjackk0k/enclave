// VARVEL — minimal DNS wire codec (RFC 1035) for the governed channel's UDP transport.
//
// This is what makes the DNS transport REAL, not HTTP-carried: actual query packets on a
// UDP socket. A query for <b32-labels>.ax.sim TXT carries the governed payload in its
// labels; the response carries the encoded reply as TXT character-strings (or zero answers
// for the uniform idle/deny case). Fail-closed on any malformed packet.

// Parse a DNS query packet. Returns { id, qname, qtype, rd } or null on any malformed shape.
export function parseDnsQuery(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 13) return null;
  const id = buf.readUInt16BE(0);
  const flags = buf.readUInt16BE(2);
  if (flags & 0x8000) return null;                    // QR must be 0 (a query)
  if (((flags >> 11) & 0xf) !== 0) return null;       // OPCODE must be 0 (standard query)
  const qd = buf.readUInt16BE(4);
  if (qd !== 1) return null;                          // exactly one question
  const labels = [];
  let off = 12, total = 0;
  while (true) {
    if (off >= buf.length) return null;
    const len = buf[off++];
    if (len === 0) break;
    if (len > 63 || off + len > buf.length || (len & 0xc0) !== 0) return null; // no compression in queries
    const label = buf.subarray(off, off + len).toString('latin1');
    if (!/^[0-9a-zA-Z_-]+$/.test(label)) return null;
    labels.push(label.toLowerCase());
    total += len;
    if (total > 480) return null; // codec cap (matches decodeQuery). NOTE: >255 violates the
    // RFC qname limit and won't traverse real recursive resolvers — accepted here because
    // range transport is agent→channel direct, and governance beats spec-purity.
    off += len;
  }
  if (!labels.length || off + 4 > buf.length) return null;
  const qtype = buf.readUInt16BE(off);
  const qclass = buf.readUInt16BE(off + 2);
  if (qclass !== 1) return null;                      // IN only
  return { id, qname: labels.join('.'), qtype, rd: !!(flags & 0x0100) };
}

// Craft a DNS response. txt=null/'' → NOERROR with zero answers (uniform idle/deny).
// Otherwise one TXT answer; long strings split into ≤255-byte character-strings per RFC.
export function craftDnsResponse({ id, qname, qtype, rd }, txt) {
  const q = encodeQName(qname);
  const hasAnswer = !!(txt && txt.length);
  const flags = 0x8000 | 0x0400 | (rd ? 0x0100 : 0) | 0x0080; // QR + AA + RD + RA, RCODE 0
  const head = Buffer.alloc(12);
  head.writeUInt16BE(id & 0xffff, 0);
  head.writeUInt16BE(flags, 2);
  head.writeUInt16BE(1, 4);                            // QDCOUNT
  head.writeUInt16BE(hasAnswer ? 1 : 0, 6);            // ANCOUNT
  head.writeUInt16BE(0, 8);
  head.writeUInt16BE(0, 10);
  const question = Buffer.concat([q, u16(qtype), u16(1)]);
  if (!hasAnswer) return Buffer.concat([head, question]);
  const chunks = [];
  const data = Buffer.from(String(txt), 'latin1');
  for (let i = 0; i < data.length; i += 255) {
    const c = data.subarray(i, Math.min(i + 255, data.length));
    chunks.push(Buffer.concat([Buffer.from([c.length]), c]));
  }
  const rdata = Buffer.concat(chunks);
  const answer = Buffer.concat([Buffer.from([0xc0, 0x0c]), u16(16), u16(1), u32(60), u16(rdata.length), rdata]);
  return Buffer.concat([head, question, answer]);
}

function encodeQName(qname) {
  const parts = String(qname || '').toLowerCase().split('.').filter(Boolean);
  const out = [];
  for (const p of parts) { const b = Buffer.from(p, 'latin1'); out.push(Buffer.from([b.length]), b); }
  out.push(Buffer.from([0]));
  return Buffer.concat(out);
}
const u16 = (v) => { const b = Buffer.alloc(2); b.writeUInt16BE(v & 0xffff); return b; };
const u32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32BE(v >>> 0); return b; };

// Decode the TXT character-strings from a response crafted above (client side).
export function decodeTxtAnswer(buf) {
  try {
    const an = buf.readUInt16BE(6);
    if (!an) return '';
    let off = 12;
    while (buf[off] !== 0) off += 1 + buf[off];
    off += 5; // terminating 0 + qtype + qclass
    // answer: name pointer(2) type(2) class(2) ttl(4) rdlen(2)
    const rdlen = buf.readUInt16BE(off + 10);
    let p = off + 12;
    const end = p + rdlen;
    let out = '';
    while (p < end) { const l = buf[p++]; out += buf.subarray(p, p + l).toString('latin1'); p += l; }
    return out;
  } catch { return null; }
}
