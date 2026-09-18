// VARVEL smbenum tests — mock SMB responder (packet-accurate) + live loopback check.
//   node --test varvel/test/smbenum.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { buildNegotiateRequest, parseNegotiateResponse, smbNegotiate, filetimeToMs } from '../tools/smbenum.mjs';

// A mock SMB2 server that answers NEGOTIATE with a spec-shaped response.
function mockSmb({ dialect = 0x0311, securityMode = 0x0003, capabilities = 0x00000007 } = {}) {
  return net.createServer((sock) => {
    let buf = Buffer.alloc(0);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length < 4) return;
      const need = 4 + buf.readUInt32BE(0);
      if (buf.length < need) return;
      const req = buf.subarray(4, need);
      // sanity: it really is an SMB2 NEGOTIATE from our builder
      const isSmb2 = req.toString('latin1', 0, 4) === '\xfeSMB' && req.readUInt16LE(12) === 0;
      const body = Buffer.alloc(65);
      body.writeUInt16LE(65, 0);
      body.writeUInt16LE(securityMode, 2);
      body.writeUInt16LE(dialect, 4);
      body.writeUInt16LE(0, 6);
      Buffer.from('0123456789abcdef0123456789abcdef', 'hex').copy(body, 8);
      body.writeUInt32LE(capabilities, 24);
      body.writeUInt32LE(65536, 28);
      body.writeUInt32LE(65536, 32);
      body.writeUInt32LE(65536, 36);
      const ft = BigInt(Date.now()) * 10000n + 116444736000000000n;
      body.writeBigUInt64LE(ft, 40);
      body.writeBigUInt64LE(ft, 48);
      body.writeUInt16LE(0, 56); body.writeUInt16LE(0, 58);
      const hdr = Buffer.alloc(64);
      hdr.write('\xfeSMB', 0, 'latin1');
      hdr.writeUInt16LE(64, 4);
      hdr.writeUInt32LE(isSmb2 ? 0 : 0xc0000016, 8); // STATUS_MORE_PROCESSING_REQUIRED if not SMB2-shaped
      hdr.writeUInt16LE(0, 12);
      hdr.writeBigUInt64LE(0n, 24);
      const packet = Buffer.concat([hdr, body]);
      const nbss = Buffer.alloc(4);
      nbss.writeUInt32BE(packet.length, 0);
      sock.end(Buffer.concat([nbss, packet]));
    });
  });
}

async function listen(srv) { await new Promise((r) => srv.listen(0, '127.0.0.1', r)); return srv.address().port; }

test('packet build: a NEGOTIATE request is spec-shaped (header + body + dialects)', () => {
  const req = buildNegotiateRequest();
  assert.equal(req.toString('latin1', 0, 4), '\xfeSMB');
  assert.equal(req.readUInt16LE(4), 64, 'header StructureSize');
  assert.equal(req.readUInt16LE(12), 0, 'command NEGOTIATE');
  const body = req.subarray(64);
  assert.equal(body.readUInt16LE(0), 36, 'negotiate StructureSize');
  assert.equal(body.readUInt16LE(2), 4, 'four dialects offered (3.1.1 needs negotiate contexts — v2)');
  assert.equal(body.readUInt16LE(4) & 1, 1, 'signing enabled flag set');
  assert.equal(body.readUInt16LE(36), 0x0202, 'first dialect 2.0.2');
  assert.equal(body.readUInt16LE(36 + 6), 0x0302, 'last dialect 3.0.2');
});

test('parseNegotiateResponse: full field extraction + malformed inputs fail closed', () => {
  const buf = Buffer.alloc(64 + 65);
  buf.write('\xfeSMB', 0, 'latin1');
  buf.writeUInt16LE(64, 4);
  buf.writeUInt16LE(0, 12);
  buf.writeUInt16LE(65, 64);
  buf.writeUInt16LE(0x0003, 66); // signing required + enabled
  buf.writeUInt16LE(0x0311, 68);
  Buffer.from('aabbccddeeff00112233445566778899', 'hex').copy(buf, 72);
  buf.writeUInt32LE(7, 88);
  buf.writeBigUInt64LE(133444000000000000n, 104);
  const r = parseNegotiateResponse(buf);
  assert.equal(r.dialect, 'SMB 3.1.1');
  assert.equal(r.signingRequired, true);
  assert.equal(r.signingEnabled, true);
  assert.equal(r.serverGuid, 'aabbccddeeff00112233445566778899');
  assert.equal(r.capabilities, 7);
  assert.throws(() => parseNegotiateResponse(Buffer.from('x')), /too short/);
  assert.throws(() => parseNegotiateResponse(Buffer.alloc(129, 0)), /ProtocolId/);
});

test('smbNegotiate against a mock responder: dialect + signing + skew, one exchange', async () => {
  const srv = mockSmb({ dialect: 0x0311, securityMode: 0x0003 });
  const port = await listen(srv);
  try {
    const r = await smbNegotiate('127.0.0.1', { port, timeout: 1500 });
    assert.equal(r.ok, true, 'negotiate failed: ' + String(r.error || ''));
    assert.equal(r.dialect, 'SMB 3.1.1');
    assert.equal(r.signingRequired, true);
    assert.ok(r.serverTime, 'server clock decoded');
    assert.ok(Math.abs(r.skewMs) < 5000, 'skew sane on loopback');
  } finally { srv.close(); }
});

test('smbNegotiate: dead host resolves an error object, never throws', async () => {
  const r = await smbNegotiate('127.0.0.1', { port: 1, timeout: 500 });
  assert.equal(r.ok, false);
  assert.ok(r.error);
});

test('filetimeToMs: FILETIME↔ms conversion sanity', () => {
  const ms = Date.now();
  const ft = BigInt(ms) * 10000n + 116444736000000000n;
  assert.equal(filetimeToMs(ft), ms);
  assert.equal(filetimeToMs(0n), null);
});

test('live (best-effort): negotiate against this host\'s real SMB service if present', async () => {
  const r = await smbNegotiate('127.0.0.1', { port: 445, timeout: 1200 });
  if (r.ok) {
    assert.ok(r.dialect, 'a real Windows SMB service answered with a dialect: ' + r.dialect);
    console.log('      [live SMB] dialect:', r.dialect, '| signingRequired:', r.signingRequired, '| skew:', r.skewMs, 'ms');
  } else {
    assert.ok(true, 'no SMB service on 445 here — skipping live assertion (' + r.error + ')');
  }
});
