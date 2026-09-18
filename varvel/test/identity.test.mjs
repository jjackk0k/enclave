// VARVEL identity tests — the Enclave console handoff.
// Verifies VARVEL reads the SIGNED operator identity the same way the hook does:
// trusts a valid signature, rejects a forged one, and never authorizes on its own.
//
// Sessions come from CHECKED-IN fixtures (test/fixtures/identity-*.json), signed
// with the seam's own demo key via poc/enforcement-seam/util.mjs signSession —
// decoupled from the LIVE session dir (poc/enforcement-seam/session/*.json is
// mutable engagement state; a re-scoped live session must never fail this suite —
// the 2026-08-26 semrush/marcus failure). Verification still runs through the
// seam's real verifySession + entities directory, so the test proves the seam
// contract, not a reimplementation.
//   node --test varvel/test/identity.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readOperator, scopeForCampaign, informBlock, publicIdentity } from '../engine/identity.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
const SESSION = (p) => join(__dir, 'fixtures', `identity-${p}`);

test('no ENCLAVE_SESSION -> standalone, no fabricated operator', async () => {
  const op = await readOperator({});
  assert.equal(op.bound, false);
  assert.equal(op.verified, false);
  assert.equal(op.source, 'standalone');
  assert.equal(op.principal, null);
  assert.equal(op.cidrs.length, 0);
  assert.equal(scopeForCampaign(op), null, 'no scope without an operator');
});

test('a valid SIGNED session (marcus) binds with real attrs from the directory', async () => {
  const op = await readOperator({ ENCLAVE_SESSION: SESSION('marcus.json') });
  assert.equal(op.bound, true);
  assert.equal(op.verified, true, 'the real demo-signed token verifies');
  assert.equal(op.principal, 'marcus');
  assert.equal(op.role, 'Red-Team-Lead');
  assert.equal(op.clearance, 4);
  assert.deepEqual(op.licenses, ['OSCP', 'OSEP', 'CRTO']);
  assert.equal(op.workspace, 'pentest-northwind');
  assert.deepEqual(op.cidrs, ['10.10.0.0/16', '192.168.50.0/24']);
});

test('scopeForCampaign derives the campaign scope from the SIGNED engagementScope', async () => {
  const op = await readOperator({ ENCLAVE_SESSION: SESSION('marcus.json') });
  const scope = scopeForCampaign(op);
  assert.ok(scope, 'a verified operator with a scope yields a campaign scope');
  assert.equal(scope.engagement, 'pentest-northwind');
  assert.match(scope.signedBy, /marcus/);
  assert.match(scope.signedBy, /L4/);
  assert.deepEqual(scope.cidrs, ['10.10.0.0/16', '192.168.50.0/24']);
  assert.equal(scope.fromIdentity, true);
});

test('a non-offensive persona (sam) binds but has NO offensive scope', async () => {
  const op = await readOperator({ ENCLAVE_SESSION: SESSION('sam.json') });
  assert.equal(op.verified, true);
  assert.equal(op.principal, 'sam');
  assert.equal(op.clearance, 1);
  assert.equal(op.cidrs.length, 0, 'sam has no engagementScope');
  assert.equal(scopeForCampaign(op), null, 'no signed scope -> nothing to target (VARVEL still opens)');
});

test('a FORGED session (bad signature) is not trusted — attrs withheld', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'varvel-id-'));
  const forged = join(dir, 'forged.json');
  // claims to be alex (clearance 5) but the signature is garbage
  writeFileSync(forged, JSON.stringify({ session_id: 'sess-x', principal: 'alex', workspace: 'command-deck', engagementScope: '0.0.0.0/0', sig: 'hmac-sha256:deadbeef' }));
  const op = await readOperator({ ENCLAVE_SESSION: forged });
  assert.equal(op.verified, false, 'bad signature does not verify');
  assert.equal(op.clearance, null, 'attrs are withheld for an unverified binding');
  assert.equal(op.role, null);
  assert.equal(scopeForCampaign(op), null, 'a forged session grants no scope');
});

test('informBlock states the inform-not-authorize rule; publicIdentity omits the signature', async () => {
  const op = await readOperator({ ENCLAVE_SESSION: SESSION('marcus.json') });
  const block = informBlock(op);
  assert.match(block, /NOT authorization/);
  assert.match(block, /checked[\s\S]*server-side/);
  assert.match(block, /marcus/);
  const pub = publicIdentity(op);
  assert.equal(pub.principal, 'marcus');
  assert.equal(pub.clearance, 4);
  assert.ok(!('sig' in pub) && !('engagementScope' in pub), 'no signature/raw-scope leak in the public view');

  const standalone = informBlock(await readOperator({}));
  assert.match(standalone, /standalone/);
});
