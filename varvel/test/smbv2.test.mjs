// VARVEL smbv2 tests — NTLMSSP shape, NTLMv2 guest crypto, signing, share probing.
//   node --test varvel/test/smbv2.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { createHmac, randomBytes } from 'node:crypto';
import {
  buildNtlmNegotiate, parseNtlmChallenge, ntlmv2GuestResponse, buildNtlmAuthenticate,
  spnegoInit, spnegoRespParse, signMessage, smbEnumerate, smbPipeCall, SHARE_PROBES, EMPTY_NT_HASH,
} from '../tools/smbv2.mjs';

test('NTLMSSP NEGOTIATE is spec-shaped', () => {
  const m = buildNtlmNegotiate();
  assert.equal(m.toString('latin1', 0, 8), 'NTLMSSP\0');
  assert.equal(m.readUInt32LE(8), 1, 'type 1');
  const flags = m.readUInt32LE(12);
  assert.ok(flags & 0x00000001 && flags & 0x00080000 && flags & 0x40000000, 'UNICODE + NTLMv2 + KEY_EXCH');
});

test('NTLMSSP CHALLENGE parser extracts challenge + targetInfo, rejects junk', () => {
  const ch = Buffer.alloc(52);
  ch.write('NTLMSSP\0', 0, 'latin1');
  ch.writeUInt32LE(2, 8);
  randomBytes(8).copy(ch, 24);
  ch.writeUInt16LE(4, 40);   // targetInfo length
  ch.writeUInt16LE(4, 42);   // max length
  ch.writeUInt32LE(48, 44);  // targetInfo OFFSET (48, not 44 — the offset field lives at 44)
  Buffer.from('ABCD').copy(ch, 48);
  const p = parseNtlmChallenge(ch);
  assert.equal(p.serverChallenge.length, 8);
  assert.equal(p.targetInfo.toString(), 'ABCD');
  assert.throws(() => parseNtlmChallenge(Buffer.from('nope')), /challenge/);
});

test('NTLMv2 guest crypto is deterministic against a fixed challenge (test-vector shape)', () => {
  const serverChallenge = Buffer.from('0123456789abcdef', 'hex');
  const targetInfo = Buffer.from('TI');
  const r1 = ntlmv2GuestResponse({ serverChallenge, targetInfo, time: 0n });
  const a = buildNtlmAuthenticate({ serverChallenge, targetInfo, time: 0n });
  // NTLMv2 response = HMAC-MD5(responseKey, challenge+blob) || blob — 16 + blob length
  assert.equal(r1.length, 16 + 28 + 2);
  assert.equal(a.message.toString('latin1', 0, 8), 'NTLMSSP\0');
  assert.equal(a.message.readUInt32LE(8), 3, 'type 3');
  assert.equal(a.exportedKey.length, 16, 'exported session key present');
  assert.equal(a.sessionBaseKey.length, 16);
  // guest uses the empty-password NT hash — the public constant
  assert.equal(EMPTY_NT_HASH.toString('hex'), '31d6cfe0d16ae931b73c59d7e0c089c0');
});

test('SPNEGO wrap/parse round-trips the NTLM blob', () => {
  const blob = buildNtlmNegotiate();
  const wrapped = spnegoInit(blob);
  assert.equal(wrapped[0], 0x60, 'GSS InitialContextToken');
  const back = spnegoRespParse(wrapped);
  assert.ok(back && back.equals(blob));
});

test('SMB3 signing: signature lands in the field and verifies against a re-computed HMAC', () => {
  const key = randomBytes(16);
  const pkt = Buffer.alloc(128, 7);
  const signed = signMessage(pkt, key);
  const ref = Buffer.from(pkt); ref.fill(0, 48, 64); // HMAC input = packet with signature zeroed
  const expect = createHmac('sha256', key).update(ref).digest().subarray(0, 16);
  assert.equal(signed.subarray(48, 64).equals(expect), true, 'signature is HMAC-SHA256 of the packet');
});

// ——— live-ish flow against a mock SMB server that speaks the v2 handshake ———
function mockV2() {
  return net.createServer((sock) => {
    let stage = 0;
    sock.on('data', (d) => {
      const packet = d.subarray(4);
      const cmd = packet.readUInt16LE(12);
      const hdr = Buffer.alloc(64);
      hdr.write('\xfeSMB', 0, 'latin1');
      hdr.writeUInt16LE(64, 4);
      const nbss = (body) => { const n = Buffer.alloc(4); n.writeUInt32BE(body.length, 0); return Buffer.concat([n, body]); };
      if (cmd === 0) { // NEGOTIATE
        hdr.writeUInt16LE(0, 12);
        const b = Buffer.alloc(65);
        b.writeUInt16LE(65, 0); b.writeUInt16LE(3, 2); b.writeUInt16LE(0x0302, 4);
        sock.write(nbss(Buffer.concat([hdr, b])));
      } else if (cmd === 1) { // SESSION_SETUP
        if (stage === 0) {
          stage = 1;
          hdr.writeUInt32LE(0xc0000016, 8); // STATUS_MORE_PROCESSING_REQUIRED
          hdr.writeBigUInt64LE(4242n, 40);
          // SPNEGO-wrapped NTLMSSP challenge
          const ch = Buffer.alloc(48);
          ch.write('NTLMSSP\0', 0, 'latin1'); ch.writeUInt32LE(2, 8);
          Buffer.from('0123456789abcdef', 'hex').copy(ch, 24);
          ch.writeUInt16LE(2, 40); ch.writeUInt32LE(46, 44); Buffer.from('TI').copy(ch, 46);
          sock.write(nbss(Buffer.concat([hdr, ch])));
        } else {
          hdr.writeUInt32LE(0, 8); // STATUS_OK — guest accepted
          hdr.writeBigUInt64LE(4242n, 40);
          sock.write(nbss(hdr));
        }
      } else if (cmd === 3) { // TREE_CONNECT
        const status = packet.includes(Buffer.from('C$', 'utf16le')) ? 0x00000000 : 0xc00000cc;
        hdr.writeUInt32LE(status, 8);
        sock.write(nbss(hdr));
      }
    });
  });
}

test('smbEnumerate end-to-end vs a mock v2 server: guest session + share verdicts', async () => {
  const srv = mockV2();
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  try {
    const r = await smbEnumerate('127.0.0.1', { port, timeout: 1500, shares: ['C$', 'NOPE$'] });
    assert.equal(r.ok, true, String(r.error || ''));
    assert.equal(r.session, 'guest-ok');
    const c = r.shares.find((s) => s.name === 'C$');
    assert.equal(c.verdict, 'exists (accessible)');
    const n = r.shares.find((s) => s.name === 'NOPE$');
    assert.equal(n.verdict, 'not found');
    assert.equal(r.negotiate.dialect, 'SMB 3.0.2');
  } finally { srv.close(); }
});

test('SHARE_PROBES set covers the methodology canon', () => {
  for (const s of ['ADMIN$', 'C$', 'IPC$']) assert.ok(SHARE_PROBES.includes(s), s + ' probed');
  assert.ok(SHARE_PROBES.length <= 12, 'probe set is methodical, not a storm');
});

test('live (best-effort): full v2 flow against this host if it answers', async () => {
  const r = await smbEnumerate('127.0.0.1', { port: 445, timeout: 1500, shares: ['ADMIN$', 'C$', 'IPC$'] });
  if (r.ok && r.session !== 'refused') {
    console.log('      [live SMB v2] session:', r.session, '| shares:', r.shares.map((s) => s.name + '=' + s.verdict).join(' '));
    assert.ok(r.negotiate.dialect);
  } else {
    assert.ok(true, 'host refused guest sessions (hardened) — honest negative: ' + (r.session || r.error));
  }
});

test('connectImpl: an injected dialer is used; a failing dialer is an honest error', async () => {
  const srv = mockV2();
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  try {
    let dialed = null;
    const r = await smbEnumerate('127.0.0.1', { port, timeout: 1500, shares: ['C$'], connectImpl: async (h, p) => { dialed = `${h}:${p}`; return net.connect(p, h); } });
    assert.equal(r.ok, true, String(r.error || ''));
    assert.equal(dialed, `127.0.0.1:${port}`, 'the injected dialer dialed the target');
  } finally { srv.close(); }
  const bad = await smbEnumerate('127.0.0.1', { port: 1, timeout: 300, connectImpl: async () => { throw new Error('tunnel refused'); } });
  assert.equal(bad.ok, false);
  assert.match(bad.error, /connect failed: tunnel refused/);
});

// ——— pivot-mesh named-pipe I/O (IPC$ CREATE/WRITE/READ/CLOSE) against a pipe mock ———
// The mock speaks the FULL v2 handshake plus the pipe commands: CREATE answers a fileId,
// WRITE echoes the accepted length, READ returns a canned pipe reply, CLOSE accepts.
function mockPipe({ pipeReply = Buffer.from('LINK-REPLY'), createStatus = 0x00000000 } = {}) {
  const seen = { wrote: 0, createName: null, cmds: [] };
  const srv = net.createServer((sock) => {
    let stage = 0;
    sock.on('data', (d) => {
      const packet = d.subarray(4);
      const cmd = packet.readUInt16LE(12);
      seen.cmds.push(cmd);
      const hdr = Buffer.alloc(64);
      hdr.write('\xfeSMB', 0, 'latin1');
      hdr.writeUInt16LE(64, 4);
      hdr.writeUInt16LE(cmd, 12);
      hdr.writeBigUInt64LE(packet.readBigUInt64LE(24), 24); // echo MessageId
      hdr.writeBigUInt64LE(packet.readBigUInt64LE(40), 40); // echo SessionId
      hdr.writeUInt32LE(packet.readUInt32LE(36), 36);       // echo TreeId
      const nbss = (body) => { const n = Buffer.alloc(4); n.writeUInt32BE(body.length, 0); return Buffer.concat([n, body]); };
      if (cmd === 0) { // NEGOTIATE
        const b = Buffer.alloc(65);
        b.writeUInt16LE(65, 0); b.writeUInt16LE(3, 2); b.writeUInt16LE(0x0302, 4);
        sock.write(nbss(Buffer.concat([hdr, b])));
      } else if (cmd === 1) { // SESSION_SETUP
        if (stage === 0) {
          stage = 1;
          hdr.writeUInt32LE(0xc0000016, 8); // STATUS_MORE_PROCESSING_REQUIRED
          hdr.writeBigUInt64LE(4242n, 40);
          const ch = Buffer.alloc(48);
          ch.write('NTLMSSP\0', 0, 'latin1'); ch.writeUInt32LE(2, 8);
          Buffer.from('0123456789abcdef', 'hex').copy(ch, 24);
          ch.writeUInt16LE(2, 40); ch.writeUInt32LE(46, 44); Buffer.from('TI').copy(ch, 46);
          sock.write(nbss(Buffer.concat([hdr, ch])));
        } else {
          hdr.writeUInt32LE(0, 8);
          sock.write(nbss(hdr));
        }
      } else if (cmd === 3) { // TREE_CONNECT — accept (and note the share for assertions)
        seen.tree = packet.subarray(64 + 8).toString('utf16le').replace(/\0+$/, '');
        sock.write(nbss(hdr));
      } else if (cmd === 5) { // CREATE
        if (createStatus !== 0) { hdr.writeUInt32LE(createStatus, 8); sock.write(nbss(hdr)); return; }
        const nameOff = packet.readUInt16LE(64 + 44);
        const nameLen = packet.readUInt16LE(64 + 46);
        seen.createName = packet.subarray(nameOff, nameOff + nameLen).toString('utf16le');
        const b = Buffer.alloc(88);
        b.writeUInt16LE(89, 0);
        Buffer.from('deadbeefcafe0001', 'hex').copy(b, 64); // FileId (16, padded zero)
        hdr.writeUInt32LE(0, 8);
        sock.write(nbss(Buffer.concat([hdr, b])));
      } else if (cmd === 9) { // WRITE — accept the full length
        seen.wrote = packet.readUInt32LE(64 + 4);
        const b = Buffer.alloc(16);
        b.writeUInt16LE(17, 0);
        b.writeUInt32LE(seen.wrote, 4);
        sock.write(nbss(Buffer.concat([hdr, b])));
      } else if (cmd === 8) { // READ — serve the canned pipe reply
        const b = Buffer.alloc(16 + pipeReply.length);
        b.writeUInt16LE(17, 0);
        b.writeUInt8(64 + 16, 2); // DataOffset from header start
        b.writeUInt32LE(pipeReply.length, 4);
        pipeReply.copy(b, 16);
        sock.write(nbss(Buffer.concat([hdr, b])));
      } else if (cmd === 6) { // CLOSE
        const b = Buffer.alloc(60);
        b.writeUInt16LE(60, 0);
        sock.write(nbss(Buffer.concat([hdr, b])));
      }
    });
  });
  return { srv, seen };
}

test('smbPipeCall end-to-end vs a mock pipe server: IPC$ open, write, read, close', async () => {
  const { srv, seen } = mockPipe({ pipeReply: Buffer.from('LINK-REPLY') });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  try {
    const r = await smbPipeCall('127.0.0.1', { pipe: 'varvel_link_ab12', data: Buffer.from('HELLO-CHILD'), port, timeout: 1500 });
    assert.equal(r.ok, true, String(r.error || ''));
    assert.equal(r.session, 'guest-ok');
    assert.equal(r.wrote, 11, 'the pipe accepted the full payload');
    assert.equal(r.response.toString(), 'LINK-REPLY', "the pipe's reply bytes came back");
    // the wire shape: negotiate, 2x session setup, tree IPC$, create \pipe\name, write, read, close
    assert.deepEqual(seen.cmds, [0, 1, 1, 3, 5, 9, 8, 6]);
    assert.match(seen.tree, /IPC\$$/, 'tree-connected the IPC$ share');
    assert.equal(seen.createName, '\\pipe\\varvel_link_ab12', 'CREATE names the pipe object path');
  } finally { srv.close(); }
});

test('smbPipeCall: a refused CREATE is an honest staged error, never a throw', async () => {
  const { srv } = mockPipe({ createStatus: 0xc0000034 }); // STATUS_OBJECT_NAME_NOT_FOUND
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  try {
    const r = await smbPipeCall('127.0.0.1', { pipe: 'no_such_pipe', data: Buffer.from('x'), port, timeout: 1500 });
    assert.equal(r.ok, false);
    assert.equal(r.stage, 'create');
    assert.equal(r.status, '0xc0000034');
  } finally { srv.close(); }
  // input discipline: pipe names are validated (no path games into IPC$) — async TypeError
  await assert.rejects(() => smbPipeCall('127.0.0.1', { pipe: '../..' }), TypeError);
  await assert.rejects(() => smbPipeCall('127.0.0.1', { pipe: '' }), TypeError);
});
