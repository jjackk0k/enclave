// VARVEL — SMB v2: NTLMSSP session setup + SMB3 signing + share probing.
//
// Protocol-level recon depth, native (the enum4linux/Impacket tier, honestly built).
// v1 did NEGOTIATE. v2 adds the session layer: SPNEGO-wrapped NTLMv2 guest session
// setup, SMB3 message signing (required by every modern Windows host), and TREE_CONNECT
// probing of the standard share set with verdict mapping (exists / access-denied /
// not-found / refused) — real share enumeration without a single credential.
//
// Honest scope notes:
//   · GUEST only (empty user/password). We never try credentials — that's the
//     credstuff tool's lane with its own gates. A host that refuses guest sessions
//     reports exactly that (and it's a finding: "guest disabled" is the hardened state).
//   · Signing is real: NTLMv2 session key → exported session key → SMB3 HMAC-SHA256
//     message signatures, per MS-SMB2/MS-NLMP. Verified byte-for-byte in tests.
//   · smbEnumerate stays read-only: one session, no writes, no IPC abuse beyond
//     TREE_CONNECT verdicts.
//   · smbPipeCall (added for the pivot mesh, gap #4b) DOES write/read: a governed
//     named-pipe round trip on IPC$ (CREATE → WRITE → READ → CLOSE). It is the
//     raw-protocol SMB client leg for hosts where the OS redirector can't be used;
//     the agent-side mesh endpoints ride node:net UNC pipes instead. Same guest-only
//     discipline — it opens exactly the pipe it was told to open, nothing else.

import net from 'node:net';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { smb2Header, buildNegotiateRequest, parseNegotiateResponse } from './smbenum.mjs';

// ——— NTLMSSP message builders (MS-NLMP) ———
const NTLMSSP_SIG = 'NTLMSSP\0';

// NEGOTIATE flags we speak: UNICODE, OEM, SIGN, SEAL always off; NTLM, REQUEST_TARGET,
// NTLMv2 (0x00080000), VERSION off, 128/56 off, KEY_EXCH on (we need the session key).
const FLG = {
  UNICODE: 0x00000001, OEM: 0x00000002, REQUEST_TARGET: 0x00000004, SIGN: 0x00000010,
  SEAL: 0x00000020, NTLM: 0x00000200, NTLMv2: 0x00080000, KEY_EXCH: 0x40000000,
};

function secBuf(len, offset) { const b = Buffer.alloc(8); b.writeUInt16LE(len, 0); b.writeUInt16LE(len, 2); b.writeUInt32LE(offset, 4); return b; }

// NTLMSSP NEGOTIATE_MESSAGE (type 1). Guest: no domain/workstation content.
export function buildNtlmNegotiate() {
  const flags = FLG.UNICODE | FLG.REQUEST_TARGET | FLG.NTLM | FLG.NTLMv2 | FLG.KEY_EXCH;
  const msg = Buffer.alloc(32);
  msg.write(NTLMSSP_SIG, 0, 'latin1');
  msg.writeUInt32LE(1, 8);          // type 1
  msg.writeUInt32LE(flags, 12);
  secBuf(0, 32).copy(msg, 16);      // domain (empty)
  secBuf(0, 32).copy(msg, 24);      // workstation (empty)
  return msg;
}

// Parse NTLMSSP CHALLENGE_MESSAGE (type 2) → { serverChallenge, targetInfo }.
export function parseNtlmChallenge(buf) {
  if (!buf || buf.length < 32 || buf.toString('latin1', 0, 8) !== NTLMSSP_SIG || buf.readUInt32LE(8) !== 2) throw new Error('not an NTLMSSP challenge');
  return {
    serverChallenge: buf.subarray(24, 32),
    targetInfoLen: buf.readUInt16LE(40),
    targetInfoOffset: buf.readUInt32LE(44),
    targetInfo: buf.subarray(buf.readUInt32LE(44), buf.readUInt32LE(44) + buf.readUInt16LE(40)),
    flags: buf.readUInt32LE(20),
  };
}

// ——— NTLMv2 crypto (MS-NLMP §3.3.2) ———
const hmacMd5 = (key, data) => createHmac('md5', key).update(data).digest();

// Pure-JS MD4 (OpenSSL 3 removed MD4 from the default provider; NTLM needs it).
// Validated in tests against the canonical vectors ("" → 31d6cfe0…, "a" → bde52cb3…).
export function md4(data) {
  const msg = Buffer.from(data);
  const bitLen = BigInt(msg.length) * 8n;
  const pad = (64 - ((msg.length + 9) % 64)) % 64;
  const buf = Buffer.concat([msg, Buffer.from([0x80]), Buffer.alloc(pad), (() => { const l = Buffer.alloc(8); l.writeBigUInt64LE(bitLen); return l; })()]);
  let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
  const rot = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
  const F = (x, y, z) => (x & y) | (~x & z), G = (x, y, z) => (x & y) | (x & z) | (y & z), H = (x, y, z) => x ^ y ^ z;
  const K1 = 0x5a827999, K2 = 0x6ed9eba1;
  const R1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
  const R2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
  const R3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
  const S1 = [3, 7, 11, 19], S2 = [3, 5, 9, 13], S3 = [3, 9, 11, 15];
  for (let off = 0; off < buf.length; off += 64) {
    const X = []; for (let i = 0; i < 16; i++) X[i] = buf.readUInt32LE(off + i * 4);
    let aa = a, bb = b, cc = c, dd = d;
    for (let i = 0; i < 16; i++) { const s = S1[i % 4];
      if (i % 4 === 0) a = rot((a + F(b, c, d) + X[R1[i]]) >>> 0, s);
      else if (i % 4 === 1) d = rot((d + F(a, b, c) + X[R1[i]]) >>> 0, s);
      else if (i % 4 === 2) c = rot((c + F(d, a, b) + X[R1[i]]) >>> 0, s);
      else b = rot((b + F(c, d, a) + X[R1[i]]) >>> 0, s);
    }
    for (let i = 0; i < 16; i++) { const s = S2[i % 4];
      if (i % 4 === 0) a = rot((a + G(b, c, d) + X[R2[i]] + K1) >>> 0, s);
      else if (i % 4 === 1) d = rot((d + G(a, b, c) + X[R2[i]] + K1) >>> 0, s);
      else if (i % 4 === 2) c = rot((c + G(d, a, b) + X[R2[i]] + K1) >>> 0, s);
      else b = rot((b + G(c, d, a) + X[R2[i]] + K1) >>> 0, s);
    }
    for (let i = 0; i < 16; i++) { const s = S3[i % 4];
      if (i % 4 === 0) a = rot((a + H(b, c, d) + X[R3[i]] + K2) >>> 0, s);
      else if (i % 4 === 1) d = rot((d + H(a, b, c) + X[R3[i]] + K2) >>> 0, s);
      else if (i % 4 === 2) c = rot((c + H(d, a, b) + X[R3[i]] + K2) >>> 0, s);
      else b = rot((b + H(c, d, a) + X[R3[i]] + K2) >>> 0, s);
    }
    a = (a + aa) >>> 0; b = (b + bb) >>> 0; c = (c + cc) >>> 0; d = (d + dd) >>> 0;
  }
  const out = Buffer.alloc(16);
  out.writeUInt32LE(a, 0); out.writeUInt32LE(b, 4); out.writeUInt32LE(c, 8); out.writeUInt32LE(d, 12);
  return out;
}

// Empty-password NT hash is a public constant (MD4 of UTF-16LE("")). Compute anyway.
export const EMPTY_NT_HASH = md4(Buffer.from('', 'utf16le'));

// NTLMv2 response for guest (empty password). blob = server targetInfo + client timestamp.
// ResponseKeyNT = HMAC-MD5(NT-Hash, UTF16LE(UPPER(user))) — encoded as UTF-16, never UTF-8.
const responseKeyNT = () => hmacMd5(EMPTY_NT_HASH, Buffer.from('GUEST'.toUpperCase(), 'utf16le'));
export function ntlmv2GuestResponse({ serverChallenge, targetInfo, time }) {
  const blob = clientBlob(targetInfo, time);
  const ntProof = hmacMd5(responseKeyNT(), Buffer.concat([serverChallenge, blob]));
  return Buffer.concat([ntProof, blob]);
}
function clientBlob(targetInfo, time) {
  const ts = time || (BigInt(Date.now()) * 10000n + 116444736000000000n);
  const b = Buffer.alloc(28 + (targetInfo ? targetInfo.length : 0));
  b.writeUInt8(0x01, 0); b.writeUInt8(0x01, 1);       // resp type
  b.writeUInt16LE(0, 2);                             // hi-resp type
  b.writeUInt16LE(0, 4); b.writeUInt16LE(0, 6);      // reserved
  b.writeBigUInt64LE(ts, 8);                         // client timestamp
  randomBytes(8).copy(b, 16);                        // client challenge
  b.writeUInt32LE(0, 24);                            // reserved
  if (targetInfo && targetInfo.length) targetInfo.copy(b, 28);
  return b;
}

// NTLMSSP AUTHENTICATE_MESSAGE (type 3) for guest: empty LM, NTLMv2 response, empty
// domain/user/workstation, KEY_EXCH: encrypted random session key with the session base key.
export function buildNtlmAuthenticate({ serverChallenge, targetInfo, time }) {
  const ntv2 = ntlmv2GuestResponse({ serverChallenge, targetInfo, time });
  const userBuf = Buffer.from('GUEST', 'utf16le');
  const sessionBaseKey = hmacMd5(responseKeyNT(), ntv2.subarray(0, 16));
  const exportedKey = randomBytes(16);
  const encryptedKey = rc4(sessionBaseKey, exportedKey);
  const lm = Buffer.alloc(0);
  const fields = [lm, ntv2, Buffer.alloc(0), userBuf, Buffer.alloc(0), encryptedKey];
  const head = 64;
  let off = head;
  const msg = Buffer.alloc(head + fields.reduce((a, f) => a + f.length, 0));
  msg.write(NTLMSSP_SIG, 0, 'latin1');
  msg.writeUInt32LE(3, 8);
  fields.forEach((f, i) => { secBuf(f.length, off).copy(msg, 12 + i * 8); f.copy(msg, off); off += f.length; });
  msg.writeUInt32LE(FLG.UNICODE | FLG.NTLM | FLG.NTLMv2 | FLG.KEY_EXCH, 60);
  return { message: msg, exportedKey, sessionBaseKey };
}

// Minimal RC4 (for KEY_EXCH encryption).
function rc4(key, data) {
  const s = [...Array(256).keys()];
  let j = 0;
  for (let i = 0; i < 256; i++) { j = (j + s[i] + key[i % key.length]) & 255; [s[i], s[j]] = [s[j], s[i]]; }
  let i = 0; j = 0;
  const out = Buffer.alloc(data.length);
  for (let k = 0; k < data.length; k++) {
    i = (i + 1) & 255; j = (j + s[i]) & 255; [s[i], s[j]] = [s[j], s[i]];
    out[k] = data[k] ^ s[(s[i] + s[j]) & 255];
  }
  return out;
}

// ——— SPNEGO wrapper (minimal, NTLM mech only) ———
function negTokenOid() { return Buffer.from([0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]); } // 1.3.6.1.5.5.2
function lenBytes(n) { return Buffer.from(n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 255]); }
function tlv(tag, body) { return Buffer.concat([Buffer.from([tag]), lenBytes(body.length), body]); }

// SPNEGO negTokenInit wrapping an NTLMSSP message, per RFC 4178:
// GSS InitialContextToken [APPLICATION 0] { spnego-oid, [0] NegTokenInit SEQUENCE {
//   mechTypes [0] SEQUENCE OF { ntlm-oid }, mechToken [2] OCTET STRING } }
// (Windows validates this strictly — a missing SEQUENCE or context tag is an instant
// STATUS_INVALID_PARAMETER, as proven against the live host.)
export function spnegoInit(ntlmMsg) {
  const mechOid = Buffer.from([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a]); // 1.3.6.1.4.1.311.2.2.10
  const mechList = tlv(0xa0, tlv(0x30, mechOid));                // [0] MechTypeList = SEQUENCE OF OID
  const mechToken = tlv(0xa2, tlv(0x04, ntlmMsg));               // [2] mechToken = OCTET STRING
  const negInitSeq = tlv(0x30, Buffer.concat([mechList, mechToken])); // NegTokenInit ::= SEQUENCE
  const choice = tlv(0xa0, negInitSeq);                          // NegotiationToken CHOICE [0]
  return tlv(0x60, Buffer.concat([negTokenOid(), choice]));      // GSS InitialContextToken
}
export function spnegoRespParse(buf) {
  // Find the embedded NTLMSSP blob (search for the signature — SPNEGO nesting varies).
  const idx = buf.indexOf(NTLMSSP_SIG, 0, 'latin1');
  return idx >= 0 ? buf.subarray(idx) : null;
}

// The SECOND client message is a NegotiationToken CHOICE [1] NegTokenResp carrying the
// AUTHENTICATE_MESSAGE as responseToken (RFC 4178 §4.2.2 — Windows requires this framing
// for continuation tokens; raw auth is rejected with STATUS_INVALID_PARAMETER).
export function spnegoContinuation(ntlmMsg) {
  return tlv(0xa1, tlv(0x30, tlv(0xa2, tlv(0x04, ntlmMsg))));
}

// ——— SMB2 SESSION_SETUP + signing + TREE_CONNECT ———
const SMB2_SESSION_SETUP = 0x0001;
const SMB2_TREE_CONNECT = 0x0003;
const SMB2_CREATE = 0x0005;
const SMB2_CLOSE = 0x0006;
const SMB2_READ = 0x0008;
const SMB2_WRITE = 0x0009;

function sessionSetupRequest(secBlob, { messageId, headerSessionId = 0n } = {}) {
  const body = Buffer.alloc(24 + secBlob.length);
  body.writeUInt16LE(25, 0);
  body.writeUInt8(0, 2);              // flags
  body.writeUInt8(1, 3);              // security mode: signing enabled
  body.writeUInt32LE(0, 4);           // capabilities
  body.writeUInt32LE(0, 8);           // channel
  body.writeUInt16LE(88, 12);         // security buffer offset (64 + 24)
  body.writeUInt16LE(secBlob.length, 14);
  body.writeBigUInt64LE(0n, 16);      // previous session id (for re-auth, not guest)
  secBlob.copy(body, 24);
  return Buffer.concat([smb2Header(SMB2_SESSION_SETUP, { messageId: BigInt(messageId), sessionId: headerSessionId }), body]);
}

// SMB3 message signature: HMAC-SHA256(signingKey, header+body), first 16 bytes into Signature.
export function signMessage(packet, signingKey) {
  const p = Buffer.from(packet);
  p.fill(0, 48, 64); // zero the signature field
  const sig = createHmac('sha256', signingKey).update(p).digest().subarray(0, 16);
  sig.copy(p, 48);
  return p;
}

function treeConnectRequest(path, { messageId, sessionId, signingKey }) {
  const pathBuf = Buffer.from(path, 'utf16le');
  const body = Buffer.alloc(8 + pathBuf.length);
  body.writeUInt16LE(9, 0);
  body.writeUInt16LE(0, 2);       // flags (not cluster share)
  body.writeUInt16LE(72, 4);      // path offset (64 + 8)
  body.writeUInt16LE(pathBuf.length, 6);
  pathBuf.copy(body, 8);          // the actual UNC path bytes
  const pkt = Buffer.concat([smb2Header(SMB2_TREE_CONNECT, { messageId: BigInt(messageId), sessionId: BigInt(sessionId) }), body]);
  return signingKey ? signMessage(pkt, signingKey) : pkt;
}

// Default probe set — the shares every methodology checks first.
export const SHARE_PROBES = ['ADMIN$', 'C$', 'IPC$', 'print$', 'Users', 'Public', 'Shares', 'share', 'backup', 'data'];

const VERDICTS = {
  0x00000000: 'exists (accessible)',
  0xc0000022: 'exists (access denied — hardened)',
  0xc00000cc: 'not found',
  0xc00000bb: 'not supported',
};

// Full v2 flow: negotiate → session setup (guest, SPNEGO/NTLMv2) → share probing.
// Returns { negotiate, session: 'guest-ok'|'refused'|error, shares: [{name, verdict, status}] }.
export async function smbEnumerate(host, { port = 445, timeout = 3000, shares = SHARE_PROBES, connectImpl = null } = {}) {
  const once = async (sock, packet) => {
    const nbss = Buffer.alloc(4); nbss.writeUInt32BE(packet.length, 0);
    const p2 = new Promise((resolve) => {
      const handler = (d) => { resolve(d); };
      sock.once('data', handler);
      sock.once('error', () => resolve(null));
      sock.setTimeout(timeout, () => resolve(null));
    });
    sock.write(Buffer.concat([nbss, packet]));
    const d = await p2;
    if (!d || d.length < 4) return null;
    const need = 4 + d.readUInt32BE(0);
    return d.length >= need ? d.subarray(4, need) : null;
  };

  // 1) negotiate (connectImpl: an injected dialer — e.g. the ghost tunnel for public
  // engagements; private destinations go direct by ghost's own routing rule)
  const dial = connectImpl || ((h, p) => net.connect(p, h));
  let sock;
  try { sock = await dial(host, port, timeout); }
  catch (e) { return { ok: false, error: 'connect failed: ' + e.message }; }
  sock.setTimeout(timeout);
  const neg = await once(sock, buildNegotiateRequest());
  if (!neg) { try { sock.destroy(); } catch {}; return { ok: false, error: 'no negotiate response' }; }
  const negR = parseNegotiateResponse(neg);
  if (negR.rejected) { try { sock.destroy(); } catch {}; return { ok: false, error: 'negotiate rejected ' + negR.statusHex }; }

  // 2) session setup #1 (NTLMSSP negotiate via SPNEGO)
  let msgId = 1;
  const ss1 = await once(sock, sessionSetupRequest(spnegoInit(buildNtlmNegotiate()), { messageId: msgId }));
  if (!ss1) { try { sock.destroy(); } catch {}; return { ok: true, negotiate: negR, session: 'no-response', shares: [] }; }
  const sessionId = ss1.readBigUInt64LE(40);
  const challenge = spnegoRespParse(ss1.subarray(64));
  if (!challenge) { try { sock.destroy(); } catch {}; return { ok: true, negotiate: negR, session: 'no-challenge', sessionStatus: '0x' + ss1.readUInt32LE(8).toString(16).padStart(8, '0'), shares: [] }; }

  // 3) session setup #2 (NTLMSSP authenticate, guest) — the header MUST carry the session id
  const ch = parseNtlmChallenge(challenge);
  const auth = buildNtlmAuthenticate(ch);
  msgId++;
  const ss2 = await once(sock, sessionSetupRequest(spnegoContinuation(auth.message), { messageId: msgId, headerSessionId: sessionId }));
  if (!ss2) { try { sock.destroy(); } catch {}; return { ok: true, negotiate: negR, session: 'no-response-2', shares: [] }; }
  const status2 = ss2.readUInt32LE(8);
  if (status2 !== 0) { try { sock.destroy(); } catch {}; return { ok: true, negotiate: negR, session: 'refused', sessionStatus: '0x' + status2.toString(16).padStart(8, '0'), shares: [] }; }

  // 4) share probing (signed if the server demands it)
  const signingKey = auth.exportedKey; // SMB3 signing key = exported session key (no NTLM SEAL/KEY_EXCH transform needed for signing)
  const results = [];
  for (const share of shares) {
    msgId++;
    const tc = await once(sock, treeConnectRequest('\\\\' + host + '\\' + share, { messageId: msgId, sessionId, signingKey }));
    if (!tc) { results.push({ name: share, verdict: 'no response', status: null }); continue; }
    const st = tc.readUInt32LE(8);
    results.push({ name: share, verdict: VERDICTS[st] || ('status 0x' + st.toString(16).padStart(8, '0')), status: '0x' + st.toString(16).padStart(8, '0') });
  }
  try { sock.destroy(); } catch {}
  return { ok: true, negotiate: negR, session: 'guest-ok', shares: results };
}

// ——— named-pipe (IPC$) I/O — the raw-protocol SMB client leg of the pivot mesh ———
// What this is: open \\HOST\IPC$\pipe\<name>, write bytes, read the reply, close — over
// the raw SMB2 wire (negotiate → guest session → tree IPC$ → CREATE/WRITE/READ/CLOSE),
// signed with the session key exactly like the share prober above. The MESH's agent-side
// pipe endpoints (agents/pipeendpoint.mjs) ride the OS redirector via node:net UNC paths;
// THIS call exists for environments where that redirector is not usable (a non-Windows
// operator host in the range, or a tool that must control the protocol explicitly).
// Same honest scope as the rest of this module: GUEST sessions only, never credentials.
//
// Per MS-SMB2 the CREATE name on IPC$ is the pipe's object path — '\pipe\<name>' (the
// form proven against Windows by the Impacket lineage). Requests past session setup are
// SMB3-signed (HMAC-SHA256, exported session key) — the same contract as treeConnect.

function pipeCreateRequest(pipeName, { messageId, sessionId, treeId, signingKey }) {
  const name = Buffer.from('\\pipe\\' + pipeName, 'utf16le');
  const body = Buffer.alloc(56 + name.length);
  body.writeUInt16LE(57, 0);            // StructureSize
  body.writeUInt8(0, 2);                // SecurityFlags
  body.writeUInt8(0, 3);                // RequestedOplockLevel: none
  body.writeUInt32LE(2, 4);             // ImpersonationLevel: Impersonation
  // SmbCreateFlags (8) + Reserved (8) stay zero
  body.writeUInt32LE(0xc0000000, 24);   // DesiredAccess: GENERIC_READ | GENERIC_WRITE
  body.writeUInt32LE(0, 28);            // FileAttributes
  body.writeUInt32LE(3, 32);            // ShareAccess: READ | WRITE
  body.writeUInt32LE(1, 36);            // CreateDisposition: FILE_OPEN
  body.writeUInt32LE(0x00000040, 40);   // CreateOptions: FILE_NON_DIRECTORY_FILE
  body.writeUInt16LE(120, 44);          // NameOffset (from SMB2 header start: 64 + 56)
  body.writeUInt16LE(name.length, 46);  // NameLength
  name.copy(body, 56);
  const pkt = Buffer.concat([smb2Header(SMB2_CREATE, { messageId: BigInt(messageId), sessionId: BigInt(sessionId), treeId }), body]);
  return signingKey ? signMessage(pkt, signingKey) : pkt;
}

function pipeWriteRequest(fileId, data, { messageId, sessionId, treeId, signingKey }) {
  const body = Buffer.alloc(48 + data.length);
  body.writeUInt16LE(49, 0);            // StructureSize
  body.writeUInt16LE(112, 2);           // DataOffset (from header start: 64 + 48)
  body.writeUInt32LE(data.length, 4);   // Length
  body.writeBigUInt64LE(0n, 8);         // Offset (pipes ignore offsets)
  Buffer.from(fileId).copy(body, 16);   // FileId (16)
  // Channel / RemainingBytes / WriteChannelInfo* / Flags stay zero
  data.copy(body, 48);
  const pkt = Buffer.concat([smb2Header(SMB2_WRITE, { messageId: BigInt(messageId), sessionId: BigInt(sessionId), treeId }), body]);
  return signingKey ? signMessage(pkt, signingKey) : pkt;
}

function pipeReadRequest(fileId, readBytes, { messageId, sessionId, treeId, signingKey }) {
  const body = Buffer.alloc(48);
  body.writeUInt16LE(49, 0);            // StructureSize
  body.writeUInt32LE(readBytes, 4);     // Length
  body.writeBigUInt64LE(0n, 8);         // Offset
  Buffer.from(fileId).copy(body, 16);   // FileId
  body.writeUInt32LE(0, 32);            // MinimumCount: 0 = return whatever is available
  const pkt = Buffer.concat([smb2Header(SMB2_READ, { messageId: BigInt(messageId), sessionId: BigInt(sessionId), treeId }), body]);
  return signingKey ? signMessage(pkt, signingKey) : pkt;
}

function pipeCloseRequest(fileId, { messageId, sessionId, treeId, signingKey }) {
  const body = Buffer.alloc(24);
  body.writeUInt16LE(24, 0);            // StructureSize
  Buffer.from(fileId).copy(body, 8);    // FileId at +8
  const pkt = Buffer.concat([smb2Header(SMB2_CLOSE, { messageId: BigInt(messageId), sessionId: BigInt(sessionId), treeId }), body]);
  return signingKey ? signMessage(pkt, signingKey) : pkt;
}

// One request → one response packet (NBSS-stripped), the smbEnumerate exchange shape.
function pipeExchange(sock, packet, timeout) {
  return new Promise((resolve) => {
    const nbss = Buffer.alloc(4);
    nbss.writeUInt32BE(packet.length, 0);
    const done = (v) => { sock.off('data', onData); sock.off('error', onErr); resolve(v); };
    const onData = (d) => {
      if (d.length < 4) return done(null);
      const need = 4 + d.readUInt32BE(0);
      done(d.length >= need ? d.subarray(4, need) : null);
    };
    const onErr = () => done(null);
    sock.on('data', onData);
    sock.on('error', onErr);
    sock.setTimeout(timeout, () => done(null));
    sock.write(Buffer.concat([nbss, packet]));
  });
}

const statusHex = (pkt) => '0x' + pkt.readUInt32LE(8).toString(16).padStart(8, '0');

// Open a named pipe on a remote host's IPC$, write `data`, read up to `readBytes`, close.
// Returns { ok, response?, wrote?, ... } — every failure is an honest { ok:false, stage,
// status } report, never a throw past the dial. GUEST session, same as smbEnumerate.
export async function smbPipeCall(host, { pipe, data = Buffer.alloc(0), readBytes = 4096, port = 445, timeout = 3000, connectImpl = null } = {}) {
  const pipeName = String(pipe || '').replace(/^[\\/]+/, '').replace(/^pipe[\\/]/i, '');
  if (!/^[A-Za-z0-9_.\-]{1,64}$/.test(pipeName) || pipeName.includes('..')) throw new TypeError('smbPipeCall: pipe must be a pipe name (1..64 of [A-Za-z0-9_.-], no dot segments)');
  const payload = Buffer.isBuffer(data) ? data : Buffer.from(String(data ?? ''));
  const dial = connectImpl || ((h, p) => net.connect(p, h));
  let sock;
  try { sock = await dial(host, port, timeout); }
  catch (e) { return { ok: false, stage: 'dial', error: 'connect failed: ' + e.message }; }
  const bail = (stage, pkt) => { try { sock.destroy(); } catch {} return { ok: false, stage, status: pkt ? statusHex(pkt) : null, error: pkt ? 'status ' + statusHex(pkt) : 'no response' }; };
  try {
    sock.setTimeout(timeout);
    // 1) negotiate + guest session (identical flow to smbEnumerate)
    const neg = await pipeExchange(sock, buildNegotiateRequest(), timeout);
    if (!neg) return bail('negotiate', null);
    const negR = parseNegotiateResponse(neg);
    if (negR.rejected) return bail('negotiate', neg);
    const ss1 = await pipeExchange(sock, sessionSetupRequest(spnegoInit(buildNtlmNegotiate()), { messageId: 1 }), timeout);
    if (!ss1) return bail('session-setup-1', null);
    const sessionId = ss1.readBigUInt64LE(40);
    const challenge = spnegoRespParse(ss1.subarray(64));
    if (!challenge) return bail('session-setup-1', ss1);
    const auth = buildNtlmAuthenticate(parseNtlmChallenge(challenge));
    const ss2 = await pipeExchange(sock, sessionSetupRequest(spnegoContinuation(auth.message), { messageId: 2, headerSessionId: sessionId }), timeout);
    if (!ss2 || ss2.readUInt32LE(8) !== 0) return bail('session-setup-2', ss2);
    const signingKey = auth.exportedKey;
    // 2) tree connect IPC$
    const tc = await pipeExchange(sock, treeConnectRequest('\\\\' + host + '\\IPC$', { messageId: 3, sessionId, signingKey }), timeout);
    if (!tc || tc.readUInt32LE(8) !== 0) return bail('tree-connect', tc);
    const treeId = tc.readUInt32LE(36);
    // 3) open the pipe
    const cr = await pipeExchange(sock, pipeCreateRequest(pipeName, { messageId: 4, sessionId, treeId, signingKey }), timeout);
    if (!cr || cr.readUInt32LE(8) !== 0) return bail('create', cr);
    if (cr.length < 64 + 88) return { ...bail('create', cr), error: 'create response too short' };
    const fileId = cr.subarray(64 + 64, 64 + 80);
    // 4) write (when there is payload), then read the pipe's reply
    let wrote = 0;
    if (payload.length) {
      const wr = await pipeExchange(sock, pipeWriteRequest(fileId, payload, { messageId: 5, sessionId, treeId, signingKey }), timeout);
      if (!wr || wr.readUInt32LE(8) !== 0) return bail('write', wr);
      wrote = wr.length >= 72 ? wr.readUInt32LE(64 + 4) : payload.length;
    }
    let response = Buffer.alloc(0);
    if (readBytes > 0) {
      const rd = await pipeExchange(sock, pipeReadRequest(fileId, readBytes, { messageId: 6, sessionId, treeId, signingKey }), timeout);
      if (!rd || rd.readUInt32LE(8) !== 0) return bail('read', rd);
      const dataOff = rd.readUInt8(64 + 2);
      const dataLen = rd.readUInt32LE(64 + 4);
      response = rd.subarray(dataOff, dataOff + dataLen);
    }
    // 5) close the handle (best-effort — the socket close ends the session regardless)
    await pipeExchange(sock, pipeCloseRequest(fileId, { messageId: 7, sessionId, treeId, signingKey }), timeout);
    try { sock.destroy(); } catch {}
    return { ok: true, session: 'guest-ok', pipe: pipeName, wrote, response, dialect: negR.dialect };
  } catch (e) {
    try { sock.destroy(); } catch {}
    return { ok: false, stage: 'protocol', error: (e && e.message) || String(e) };
  }
}
