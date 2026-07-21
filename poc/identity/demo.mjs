// demo.mjs — identity hardening: SD-JWT clearances · DPoP · SPIFFE. Real node:crypto.
import { createHash } from 'node:crypto';
import { genKey, jwkOf, thumbprint, b64url } from './jws.mjs';
import * as sdjwt from './sd-jwt.mjs';
import * as dpop from './dpop.mjs';
import * as spiffe from './spiffe.mjs';

const C = { g: s => `\x1b[32m${s}\x1b[0m`, r: s => `\x1b[31m${s}\x1b[0m`, y: s => `\x1b[33m${s}\x1b[0m`, dim: s => `\x1b[90m${s}\x1b[0m`, b: s => `\x1b[1m${s}\x1b[0m` };
const ok = v => (v ? C.g('✓') : C.r('✗'));
const now = Math.floor(Date.now() / 1000);
let pass = true;
const check = (cond, label) => { if (!cond) pass = false; return `${ok(cond)} ${label}`; };

console.log('\n' + C.b('  ENCLAVE — identity hardening') + C.dim('   SD-JWT clearances · DPoP · SPIFFE  (real crypto, no deps)\n'));

// ── Part 1 — SD-JWT selective-disclosure clearances (RFC 9901) + holder key binding ──
console.log('  ' + C.b('1) SD-JWT clearance credential') + C.dim('  — reveal the minimum, prove you hold it'));
const idp = genKey();          // Acme IdP (issuer)
const dana = genKey();         // Dana's holder key
const cred = sdjwt.issue({
  issuerKey: idp, subject: 'spiffe://acme/user/dana', holderPubKey: dana.publicKey,
  disclosable: { name: 'Dana Okoye', role: 'IR-Analyst', clearance: 'L3', clearance_l3_plus: true, licenses: ['GCIH', 'GCFA'] },
  alwaysVisible: { iss: 'https://acme-security.io', vct: 'https://enclave/credential/operator' },
});

// (A) prove "clearance ≥ L3" WITHOUT revealing the exact level, name, or licenses — key-bound
const presA = sdjwt.present({ sdjwt: cred.sdjwt, disclosures: cred.disclosures, reveal: ['clearance_l3_plus'],
  kb: { holderKey: dana, aud: 'enclave-pdp', nonce: 'nonce-abc', iatSec: now } });
const vA = sdjwt.verify({ presentation: presA, issuerPubKey: idp.publicKey,
  kb: { expectedAud: 'enclave-pdp', expectedNonce: 'nonce-abc', nowSec: now } });
console.log('     ' + check(vA.valid && vA.revealed.clearance_l3_plus === true && vA.revealed.clearance === undefined && vA.revealed.name === undefined,
  `verifier learns clearance≥L3=${vA.revealed?.clearance_l3_plus}, and NOT the exact level / name / licenses ${C.dim(`(${vA.hiddenCount} claims stay hidden)`)}`));

// (B) a different verifier that needs the exact level + certs
const presB = sdjwt.present({ sdjwt: cred.sdjwt, disclosures: cred.disclosures, reveal: ['clearance', 'licenses'],
  kb: { holderKey: dana, aud: 'enclave-audit', nonce: 'nonce-xyz', iatSec: now } });
const vB = sdjwt.verify({ presentation: presB, issuerPubKey: idp.publicKey, kb: { expectedAud: 'enclave-audit', expectedNonce: 'nonce-xyz', nowSec: now } });
console.log('     ' + check(vB.valid && vB.revealed.clearance === 'L3' && Array.isArray(vB.revealed.licenses), `another verifier selectively gets exact clearance=${vB.revealed?.clearance} + licenses`));

// (C) replay presentation A at a verifier expecting a different nonce → key binding fails
const vReplay = sdjwt.verify({ presentation: presA, issuerPubKey: idp.publicKey, kb: { expectedAud: 'enclave-pdp', expectedNonce: 'DIFFERENT-nonce', nowSec: now } });
console.log('     ' + check(!vReplay.valid, `replayed presentation rejected ${C.dim(`(${vReplay.reason})`)}`));

// (D) forged disclosure not in _sd
const forged = presB.replace(/~[^~]+~[^~]+~/, '~' + b64url(Buffer.from(JSON.stringify(['salt', 'clearance', 'L5']))) + '~');
const vForge = sdjwt.verify({ presentation: forged.endsWith('~') ? forged : forged + '~', issuerPubKey: idp.publicKey });
console.log('     ' + check(!vForge.valid, `forged "clearance=L5" disclosure rejected ${C.dim(`(${vForge.reason})`)}\n`));

// ── Part 2 — DPoP sender-constrained tokens (RFC 9449) ──
console.log('  ' + C.b('2) DPoP-bound access token') + C.dim('  — a stolen token is useless without the key'));
const clientKey = genKey();
const tokenJkt = dpop.keyThumbprint(clientKey);   // the AS stamps cnf.jkt = this into the token
const htm = 'POST', htu = 'https://api.enclave.example/exec';
const seen = new Set();
const proof1 = dpop.makeProof({ key: clientKey, htm, htu, iatSec: now });
const rs1 = dpop.verifyProof(proof1, { htm, htu, expectedJkt: tokenJkt, nowSec: now, seenJtis: seen });
console.log('     ' + check(rs1.valid, `legit request: proof key matches token binding (jkt) ${C.dim('→ allowed')}`));
const rs2 = dpop.verifyProof(proof1, { htm, htu, expectedJkt: tokenJkt, nowSec: now, seenJtis: seen });
console.log('     ' + check(!rs2.valid, `same proof replayed → rejected ${C.dim(`(${rs2.reason})`)}`));
const attackerKey = genKey();
const stolen = dpop.makeProof({ key: attackerKey, htm, htu, iatSec: now });
const rs3 = dpop.verifyProof(stolen, { htm, htu, expectedJkt: tokenJkt, nowSec: now, seenJtis: seen });
console.log('     ' + check(!rs3.valid, `stolen token used with attacker's key → rejected ${C.dim(`(${rs3.reason})`)}\n`));

// ── Part 3 — SPIFFE workload identity between components ──
console.log('  ' + C.b('3) SPIFFE workload identity') + C.dim('  — the broker proves who it is to the PDP'));
const trustDomain = genKey(); // SPIRE server / trust bundle
const brokerSVID = spiffe.issueSVID({ trustDomainKey: trustDomain, spiffeId: 'spiffe://enclave.example/broker', audience: 'spiffe://enclave.example/pdp', iatSec: now });
const authz = { expectedAudience: 'spiffe://enclave.example/pdp', authorizedIds: ['spiffe://enclave.example/broker'], nowSec: now };
const pdpCheck = spiffe.verifySVID(brokerSVID, trustDomain.publicKey, authz);
console.log('     ' + check(pdpCheck.valid && pdpCheck.spiffeId === 'spiffe://enclave.example/broker', `PDP authenticates the broker's SVID ${C.dim('(signed by trust domain, authorized ID)')}`));
const rogue = genKey();
const forgedSVID = spiffe.issueSVID({ trustDomainKey: rogue, spiffeId: 'spiffe://enclave.example/broker', audience: 'spiffe://enclave.example/pdp', iatSec: now });
const rogueCheck = spiffe.verifySVID(forgedSVID, trustDomain.publicKey, authz);
console.log('     ' + check(!rogueCheck.valid, `attacker self-signs the same SPIFFE ID → rejected ${C.dim(`(${rogueCheck.reason})`)}`));
const wrongSvcSVID = spiffe.issueSVID({ trustDomainKey: trustDomain, spiffeId: 'spiffe://enclave.example/sandbox', audience: 'spiffe://enclave.example/pdp', iatSec: now });
const wrongSvc = spiffe.verifySVID(wrongSvcSVID, trustDomain.publicKey, authz);
console.log('     ' + check(!wrongSvc.valid, `an unauthorized component (sandbox → PDP) → rejected ${C.dim(`(${wrongSvc.reason})`)}\n`));

console.log(C.b('  ── summary ──'));
console.log('  Clearances/licenses are verifiable credentials with selective disclosure + holder key binding;');
console.log('  access tokens are bound to a client key (stolen ≠ usable); components authenticate by SPIFFE ID.');
console.log('  ' + (pass ? C.g(C.b('IDENTITY: PASS ✓')) : C.r(C.b('IDENTITY: FAIL ✗'))) + '\n');
process.exit(pass ? 0 : 1);
