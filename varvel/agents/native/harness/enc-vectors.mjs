// enc-vectors.mjs — WIRE PARITY VECTORS for the envelope layer (engine/envelope.mjs),
// extracted from the NODE engine itself so the native Go agent (agents/native/
// envelope.go) is proven a full peer BY CROSS-DECRYPTION, not by re-implementation
// claims. Both directions run inside `go test` (envelope_test.go):
//
//   node agents/native/harness/enc-vectors.mjs emit
//     → JSON on stdout: { token, agentId, keyHex, vectors[], plaintext[] }
//     vectors[]:   { name, plainHex, blobHex, string } — REAL sealed output of the
//                  Node engine over the fixed payload set (random nonce per seal —
//                  parity is proven by OPENING, never by reproducing ciphertext).
//     plaintext[]: { name, hex?, utf8?, isSealedBytes?, isSealedString? } — the
//                  detection verdicts the Go side must agree with.
//   node agents/native/harness/enc-vectors.mjs open <goVectors.json>
//     → derives the SAME key, opens every Go-sealed blob/string in the file, compares
//       against the declared plaintext, and checks the Go side's detection verdicts.
//       Exit 0 + JSON report on success; exit 1 with the failure list on any mismatch.
//
// The fixed token/agentId are the wire_test.go vector constants — test material, not
// live credentials.
import { readFileSync } from 'node:fs';
import {
  deriveEncKey, sealBytes, openBytes, isSealedBytes, sealString, openString, isSealedString,
} from '../../../engine/envelope.mjs';

const TOKEN = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
const AGENT_ID = 'f00ba7cafe01';

// The fixed payload set: a task-reply JSON shape, a result string, unicode, an empty
// plaintext, and a binary blob (string form is utf8-only by contract, so the binary
// one exercises the blob form only).
const PAYLOADS = [
  { name: 'task-reply', utf8: '{"taskId":"9f1c2ab3-44aa-4e7c-9d01-112233445566","kind":"echo","data":"wire-parity"}' },
  { name: 'result-echo', utf8: 'wire-parity' },
  { name: 'unicode', utf8: 'snowman ☃ — ümläut — 漢字' },
  { name: 'empty', utf8: '' },
  { name: 'binary', hex: Buffer.from(Array.from({ length: 256 }, (_, i) => i)).toString('hex'), blobOnly: true },
];

function emit() {
  const key = deriveEncKey(TOKEN, AGENT_ID);
  const vectors = PAYLOADS.map((p) => {
    const plain = p.hex ? Buffer.from(p.hex, 'hex') : Buffer.from(p.utf8, 'utf8');
    const v = { name: p.name, plainHex: plain.toString('hex'), blobHex: sealBytes(key, plain).toString('hex') };
    if (!p.blobOnly) v.string = sealString(key, plain.toString('utf8'));
    return v;
  });
  // Detection parity set: buffers/strings that must read as NOT sealed on BOTH sides
  // (a plaintext task body, a bare 'enc1' without colon, a 'VE'-magic buffer too short
  // to be a blob, and the empty string the 204-uniform doctrine never seals).
  const plaintext = [
    { name: 'task-json', utf8: '{"taskId":"t","kind":"note","data":"hi"}', isSealedBytes: false, isSealedString: false },
    { name: 'enc1-no-colon', utf8: 'enc1-not-a-prefix', isSealedBytes: false, isSealedString: false },
    { name: 'short-ve-magic', hex: Buffer.from([0x56, 0x45, 0x01, 0x00, 0x01]).toString('hex'), isSealedBytes: false },
    { name: 'empty-string', utf8: '', isSealedString: false },
  ];
  // Self-check the claims before emitting (the generator must not lie).
  for (const p of plaintext) {
    if (p.hex) assertEq(isSealedBytes(Buffer.from(p.hex, 'hex')), p.isSealedBytes, p.name + ' isSealedBytes');
    if (p.utf8 != null) {
      assertEq(isSealedBytes(Buffer.from(p.utf8, 'utf8')), p.isSealedBytes ?? false, p.name + ' isSealedBytes');
      assertEq(isSealedString(p.utf8), p.isSealedString ?? false, p.name + ' isSealedString');
    }
  }
  console.log(JSON.stringify({ token: TOKEN, agentId: AGENT_ID, keyHex: key.toString('hex'), vectors, plaintext }, null, 1));
}

function assertEq(got, want, what) {
  if (got !== want) throw new Error(what + ': got ' + got + ' want ' + want);
}

// open <file>: the REVERSE direction — the Go side sealed; Node must open. The file
// shape mirrors emit() output (vectors[] with plainHex + blobHex/string, plaintext[]
// with the Go side's detection verdicts to be checked against the Node engine's).
function open(file) {
  const doc = JSON.parse(readFileSync(file, 'utf8'));
  if (doc.token !== TOKEN || doc.agentId !== AGENT_ID) {
    console.error('open: vector doc token/agentId mismatch (this harness owns the fixed set)');
    process.exit(1);
  }
  const key = deriveEncKey(TOKEN, AGENT_ID);
  const failures = [];
  const opened = [];
  for (const v of doc.vectors || []) {
    const want = Buffer.from(v.plainHex, 'hex');
    try {
      const got = openBytes(key, Buffer.from(v.blobHex, 'hex'));
      if (!got.equals(want)) throw new Error('plaintext mismatch');
      opened.push(v.name + ':blob');
    } catch (e) { failures.push(v.name + ':blob: ' + (e.code || e.message)); }
    if (v.string != null) {
      try {
        const got = openString(key, v.string);
        if (Buffer.from(got, 'utf8').equals(want) === false) throw new Error('plaintext mismatch');
        opened.push(v.name + ':string');
      } catch (e) { failures.push(v.name + ':string: ' + (e.code || e.message)); }
    }
  }
  for (const p of doc.plaintext || []) {
    if (p.hex && isSealedBytes(Buffer.from(p.hex, 'hex')) !== p.isSealedBytes) failures.push(p.name + ': isSealedBytes disagreement');
    if (p.utf8 != null && isSealedString(p.utf8) !== p.isSealedString) failures.push(p.name + ': isSealedString disagreement');
  }
  if (failures.length) {
    console.error(JSON.stringify({ ok: false, failures }, null, 1));
    process.exit(1);
  }
  console.log(JSON.stringify({ ok: true, opened, plaintextChecked: (doc.plaintext || []).length }, null, 1));
}

const mode = process.argv[2] || 'emit';
if (mode === 'emit') emit();
else if (mode === 'open') open(process.argv[3]);
else { console.error('usage: enc-vectors.mjs [emit] | open <goVectors.json>'); process.exit(2); }
