// demo.mjs — externally-verifiable tamper-evidence for the audit ledger.
// The hash-chained ledger (poc/enforcement-seam) proves *internal* consistency.
// This adds the layer that makes it verifiable WITHOUT trusting Enclave: a Merkle
// root over the ledger, signed by an INDEPENDENT authority and published to an
// external transparency log. Anyone with the authority's public key can then prove
// whether a ledger state is the one that was anchored.

import { createHash } from 'node:crypto';
import { existsSync, unlinkSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { buildTree, inclusionProof, verifyInclusion } from './merkle.mjs';
import { makeAuthority, anchorRoot, verifyAnchor } from './anchor.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const EXT_LOG = join(HERE, 'external-transparency-log.jsonl');
const C = { g: s => `\x1b[32m${s}\x1b[0m`, r: s => `\x1b[31m${s}\x1b[0m`, dim: s => `\x1b[90m${s}\x1b[0m`, b: s => `\x1b[1m${s}\x1b[0m` };

// representative audit entries, hash-chained the way the real ledger is
function makeEntries() {
  const base = [
    { event: 'auth.session_verified', principal: 'dana', clearance: 3 },
    { event: 'pretooluse.decision', principal: 'dana', action: 'readCode', decision: 'allow' },
    { event: 'pretooluse.decision', principal: 'sam', action: 'deleteFiles', decision: 'deny' },
    { event: 'egress.block', host: 'pastebin.com' },
    { event: 'pretooluse.decision', principal: 'marcus', action: 'networkScan', decision: 'allow' },
    { event: 'pretooluse.decision', principal: 'marcus', action: 'exploit', decision: 'deny' },
    { event: 'sandbox.teardown', principal: 'dana', wiped: true },
    { event: 'ledger.export', principal: 'priya' },
  ];
  let prev = 'GENESIS';
  return base.map((e, i) => {
    const rec = { ...e, seq: i, prev_hash: prev };
    const entry_hash = createHash('sha256').update(prev + JSON.stringify(rec)).digest('hex');
    prev = entry_hash;
    return { ...rec, entry_hash };
  });
}

(async () => {
  if (existsSync(EXT_LOG)) unlinkSync(EXT_LOG);
  const entries = makeEntries();
  const authority = makeAuthority();               // external notary — Enclave does NOT hold this private key
  const ts = new Date().toISOString();

  const { root, levels } = buildTree(entries);
  const anchor = anchorRoot({ rootHex: root.toString('hex'), count: entries.length, tsIso: ts, privateKey: authority.privateKey });
  writeFileSync(EXT_LOG, JSON.stringify(anchor) + '\n'); // "published" outside Enclave's control

  console.log('\n' + C.b('  ENCLAVE — audit anchoring') + C.dim('   externally-verifiable tamper-evidence\n'));
  console.log(`  ${entries.length} hash-chained entries → Merkle root ${C.dim(anchor.root.slice(0, 16) + '…')}`);
  console.log(`  signed by the external authority + published to the transparency log ${C.g('✓')}\n`);

  // 1) inclusion proof against the anchored root
  const k = 4;
  const proof = inclusionProof(levels, k);
  const included = verifyInclusion(entries[k], proof, anchor.root);
  console.log('  ' + C.b(`1) inclusion proof`) + `  entry #${k} "${entries[k].event} · ${entries[k].principal || ''}"`);
  console.log(`       proven in the anchored ledger: ${included ? C.g('yes ✓') : C.r('no ✗')}  ${C.dim(`(audit path: ${proof.length} hashes, not the whole log)`)}\n`);

  // 2) tamper detection — change one entry, recompute
  const tampered = entries.map((e, i) => (i === k ? { ...e, decision: 'allow_TAMPERED' } : e));
  const root2 = buildTree(tampered).root.toString('hex');
  const stillMatches = root2 === anchor.root;
  console.log('  ' + C.b('2) tamper detection') + `  flip entry #${k}'s decision to "allow" and recompute`);
  console.log(`       recomputed root ${root2.slice(0, 16)}… ${root2 !== anchor.root ? C.r('≠ anchored root') : C.g('= anchored')}`);
  console.log(`       ledger still matches its external anchor: ${stillMatches ? C.r('yes') : C.g('NO ✗')}  ${C.dim('← tampering is provable to anyone holding the authority key')}\n`);

  // 3) insider forgery — rewrite everything AND forge a new anchor
  const insiderKeys = makeAuthority(); // an insider signing their own anchor
  const forged = anchorRoot({ rootHex: root2, count: tampered.length, tsIso: ts, privateKey: insiderKeys.privateKey });
  const forgedValid = verifyAnchor(forged, authority.publicKey); // checked against the REAL authority key
  const realValid = verifyAnchor(anchor, authority.publicKey);
  console.log('  ' + C.b('3) insider forgery') + `  rewrite the whole ledger + hash-chain AND forge a fresh anchor`);
  console.log(`       forged anchor verifies against the authority's public key: ${forgedValid ? C.r('yes ✗') : C.g('NO ✓')}  ${C.dim("← insider can't sign as the external authority")}`);
  console.log(`       the originally-published anchor still verifies: ${realValid ? C.g('yes ✓') : C.r('no ✗')}\n`);

  const pass = included && !stillMatches && !forgedValid && realValid;
  console.log(C.b('  ── summary ──'));
  console.log('  The ledger\'s integrity does not rest on trusting Enclave: it rests on a Merkle root');
  console.log('  signed by an independent authority and published externally. Any change is detectable');
  console.log('  by a third party, and Enclave cannot forge the authority\'s signature.');
  console.log('  ' + (pass ? C.g(C.b('AUDIT-ANCHOR: PASS ✓')) : C.r(C.b('AUDIT-ANCHOR: FAIL ✗'))) + '\n');
  process.exit(pass ? 0 : 1);
})();
