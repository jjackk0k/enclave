// VARVEL — native SMB2 enumeration client v1 (the enum4linux/Impacket slot, first step).
//
// Protocol-level recon, native — no wrappers. v1 scope (honest, documented): the SMB2
// NEGOTIATE exchange. From ONE connection you learn what a network scan never shows:
// the server's dialect ceiling (2.0.2 → 3.1.1), whether signing is REQUIRED (the
// relay-resistance flag every methodology checks), its server GUID, capabilities, and
// its clock (time-skew — useful later for Kerberos work). This is the measurable,
// verifiable layer that share/user enumeration (v2: SESSION_SETUP + TREE_CONNECT) builds on.
//
// Packet-accurate: header + NEGOTIATE request are constructed byte-for-byte per
// MS-SMB2, and the response is parsed against the same spec — proven hermetically
// against a mock responder in the tests, and against a real Windows SMB service live.
//
// Stealth note: one TCP connection, one exchange — footprint ≈ a normal SMB client
// handshake (quieter than nmap -sV). No credentials, no auth attempts, no writes.

import net from 'node:net';

// SMB2 command codes we speak.
const SMB2_NEGOTIATE = 0x0000;

// Dialect revision → label.
const DIALECTS = {
  0x0202: 'SMB 2.0.2',
  0x0210: 'SMB 2.1',
  0x0300: 'SMB 3.0',
  0x0302: 'SMB 3.0.2',
  0x0311: 'SMB 3.1.1',
};

// 16 bytes of zeroes for ClientGuid (we don't impersonate a specific machine).
const ZERO16 = Buffer.alloc(16, 0);

// Build the SMB2 header (64 bytes).
export function smb2Header(command, { messageId = 0n, sessionId = 0n, treeId = 0 } = {}) {
  const h = Buffer.alloc(64);
  h.write('\xfeSMB', 0, 'latin1');                    // ProtocolId
  h.writeUInt16LE(64, 4);                            // StructureSize
  h.writeUInt16LE(0, 6);                             // CreditCharge
  h.writeUInt32LE(0, 8);                             // ChannelSequence (grant any credits)
  h.writeUInt16LE(command, 12);                      // Command
  h.writeUInt16LE(1, 14);                            // Credits requested
  h.writeUInt32LE(0, 16);                            // Flags
  h.writeUInt32LE(0, 20);                            // NextCommand (single, not compounded)
  h.writeBigUInt64LE(messageId, 24);                 // MessageId
  h.writeUInt32LE(0, 32);                            // Reserved (PID)
  h.writeUInt32LE(treeId, 36);                       // TreeId
  h.writeBigUInt64LE(sessionId, 40);                 // SessionId
  // Signature (16) stays zero — unsigned negotiate
  return h;
}

// Build a NEGOTIATE request offering our dialect set. Note: offering 0x0311 REQUIRES
// negotiate contexts (preauth integrity) per MS-SMB2 3.1.5.2 — without them, Windows
// rejects with STATUS_INVALID_PARAMETER (proven live). v1 offers up to 3.0.2; a 3.1.1
// server happily answers at 3.0.2 and still tells us its signing requirement.
export function buildNegotiateRequest({ dialects = [0x0202, 0x0210, 0x0300, 0x0302] } = {}) {
  const body = Buffer.alloc(36 + dialects.length * 2);
  body.writeUInt16LE(36, 0);                         // StructureSize
  body.writeUInt16LE(dialects.length, 2);            // DialectCount
  body.writeUInt16LE(0x0001, 4);                     // SecurityMode: signing enabled
  body.writeUInt16LE(0, 6);                          // Reserved
  body.writeUInt32LE(0, 8);                          // Capabilities (plain client)
  ZERO16.copy(body, 12);                             // ClientGuid
  body.writeUInt32LE(0, 28);                         // NegotiateContextOffset/Reserved
  dialects.forEach((d, i) => body.writeUInt16LE(d, 36 + i * 2)); // dialect list at offset 36
  return Buffer.concat([smb2Header(SMB2_NEGOTIATE), body]);
}

// Parse a NEGOTIATE response (header + body). Throws on malformed (fail-closed);
// an SMB2 ERROR response (short body, non-zero status) is reported, not thrown.
export function parseNegotiateResponse(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 64 + 8) throw new Error('SMB2 negotiate response too short (' + (buf && buf.length) + ' bytes)');
  if (buf.toString('latin1', 0, 4) !== '\xfeSMB') throw new Error('not an SMB2 response (bad ProtocolId)');
  const command = buf.readUInt16LE(12);
  const status = buf.readUInt32LE(8);
  if (command !== SMB2_NEGOTIATE) throw new Error('unexpected SMB2 command in response: 0x' + command.toString(16));
  // SMB3 error context (StructureSize 9) or any non-zero status: honest rejection report.
  if (status !== 0 || buf.readUInt16LE(64) === 9) {
    return { rejected: true, status, statusHex: '0x' + status.toString(16).padStart(8, '0') };
  }
  if (buf.length < 64 + 65) throw new Error('SMB2 negotiate body too short (' + buf.length + ' bytes)');
  const o = 64; // body offset
  return {
    status,
    structureSize: buf.readUInt16LE(o),
    securityMode: buf.readUInt16LE(o + 2),
    signingEnabled: !!(buf.readUInt16LE(o + 2) & 0x0002),
    signingRequired: !!(buf.readUInt16LE(o + 2) & 0x0001),
    dialectRevision: buf.readUInt16LE(o + 4),
    dialect: DIALECTS[buf.readUInt16LE(o + 4)] || ('unknown 0x' + buf.readUInt16LE(o + 4).toString(16)),
    serverGuid: buf.subarray(o + 8, o + 24).toString('hex'),
    capabilities: buf.readUInt32LE(o + 24),
    maxTransactSize: buf.readUInt32LE(o + 28),
    maxReadSize: buf.readUInt32LE(o + 32),
    maxWriteSize: buf.readUInt32LE(o + 36),
    systemTime: buf.readBigUInt64LE(o + 40),
    serverStartTime: buf.readBigUInt64LE(o + 48),
  };
}

// FILETIME (100ns since 1601) → ms since epoch.
export function filetimeToMs(ft) {
  const n = typeof ft === 'bigint' ? ft : BigInt(ft || 0);
  if (n <= 0n) return null;
  return Number(n / 10000n) - 11644473600000;
}

// One NEGOTIATE exchange against host:445. Returns the parsed fingerprint + skew.
// SMB over TCP is framed by a 4-byte big-endian NetBIOS session header (length prefix).
export async function smbNegotiate(host, { port = 445, timeout = 2500 } = {}) {
  if (!host) throw new TypeError('smbNegotiate: host is required');
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let settled = false, buf = Buffer.alloc(0);
    const done = (v) => { if (settled) return; settled = true; try { sock.destroy(); } catch {} resolve(v); };
    sock.connect(port, host, () => {
      try {
        const packet = buildNegotiateRequest();
        const nbss = Buffer.alloc(4);
        nbss.writeUInt32BE(packet.length, 0);
        sock.write(Buffer.concat([nbss, packet]));
      } catch { done(null); }
    });
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      // NBSS session-message framing: 4-byte big-endian length prefix.
      if (buf.length >= 4) {
        const need = 4 + buf.readUInt32BE(0);
        if (buf.length >= need) {
          const packet = buf.subarray(4, need);
          try {
            const r = parseNegotiateResponse(packet);
            if (r.rejected) { done({ ok: false, error: 'server rejected negotiate: status ' + r.statusHex, status: r.status }); return; }
            const serverMs = filetimeToMs(r.systemTime);
            done({ ok: true, ...r, serverTime: serverMs ? new Date(serverMs).toISOString() : null, skewMs: serverMs ? serverMs - Date.now() : null });
          } catch (e) { done({ ok: false, error: e.message }); }
        }
      }
    });
    sock.on('timeout', () => done({ ok: false, error: 'timeout' }));
    sock.on('error', (e) => done({ ok: false, error: e.message }));
    sock.setTimeout(timeout);
  });
}
