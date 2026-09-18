// VARVEL program tests — bug-bounty scope intake (tools/program.mjs). Hermetic: local
// fixtures only, zero network, and the pinned marcus.json is proven UNTOUCHED by the
// sign path (identity.test.mjs owns its baseline).
//   node --test test/program.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { normalizeProgram, normalizeEntries, signScope, PLATFORMS } from '../tools/program.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
const FIX = (n) => JSON.parse(readFileSync(join(__dir, 'fixtures', n), 'utf8'));
const SEAM = join(__dir, '..', '..', 'poc', 'enforcement-seam');
const MARCUS = join(SEAM, 'session', 'marcus.json');
const CLI = join(__dir, '..', 'tools', 'cli.mjs');
const run = (args) => {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 30000 });
  let out = null;
  try { out = JSON.parse(r.stdout); } catch { out = { parseError: r.stdout.slice(0, 300), stderr: r.stderr.slice(0, 300) }; }
  return { status: r.status, out };
};
const tmpFile = (name) => join(tmpdir(), `varvel-program-${process.pid}-${name}`);

// --- adapters -> ONE normalizer -------------------------------------------------------

test('hackerone: structured-scope export normalizes; every asset class lands honestly', () => {
  const n = normalizeProgram(FIX('h1-program.json'), { platform: 'hackerone' });
  assert.equal(n.ok, true);
  assert.equal(n.program.handle, 'acme-bbp');
  assert.equal(n.program.url, 'https://hackerone.com/acme-bbp');
  // CIDRs canonical; the bare IP became a host route; the URL's host became a domain
  // with the path honestly named as inexpressible.
  assert.deepEqual(n.inScope.cidrs.map((c) => c.asset), ['203.0.113.0/24', '198.51.100.7/32']);
  assert.deepEqual(n.inScope.domains.map((d) => d.asset), ['example.com', 'app.example.com']);
  assert.match(n.inScope.domains[1].note, /path \(\/admin\) is not expressible/);
  assert.deepEqual(n.inScope.wildcards.map((w) => w.asset), ['*.api.example.com']);
  assert.equal(n.inScope.other.length, 1);
  assert.equal(n.inScope.other[0].bounty, false, 'eligible_for_bounty:false rides through');
  // eligible_for_submission:false = out-of-scope, verbatim, never dropped
  assert.deepEqual(n.outOfScope.domains.map((d) => d.asset), ['status.example.com', 'api.example.com']);
  assert.deepEqual(n.outOfScope.cidrs.map((c) => c.asset), ['203.0.113.99/32']);
  // the signed CSV is CIDRs only — exactly the strings the hook's inAnyCidr parses
  assert.equal(n.engagementScope, '203.0.113.0/24,198.51.100.7/32');
  assert.equal(n.signable, true);
  // metadata carry-through: the program's own words + the reward table
  assert.match(n.policy, /safe harbor/i);
  assert.equal(n.rewards.length, 3);
  // gaps: the adapter assumption, the wildcard honesty, the domain-resolution step,
  // and BOTH overlap warnings (out-CIDR inside in-CIDR; out-domain under in-wildcard)
  assert.ok(n.gaps.some((g) => /modeled on the documented structured-scope/.test(g)));
  assert.ok(n.gaps.some((g) => /\*\.api\.example\.com NOT expanded/.test(g)));
  assert.ok(n.gaps.some((g) => /2 in-scope domain\(s\) are NOT in the signed CIDR scope/.test(g)));
  assert.ok(n.gaps.some((g) => /203\.0\.113\.99\/32 overlaps in-scope 203\.0\.113\.0\/24/.test(g)), 'the signed-scope-covers-exclusion warning is loud');
  assert.ok(n.gaps.some((g) => /api\.example\.com falls under in-scope wildcard/.test(g)));
});

test('bugcrowd: target-groups classify by in_scope/name; an ambiguous group falls OUT with a named gap', () => {
  const n = normalizeProgram(FIX('bc-program.json'), { platform: 'bugcrowd' });
  assert.equal(n.ok, true);
  assert.equal(n.program.name, 'Globex Public Bounty');
  assert.deepEqual(n.inScope.cidrs.map((c) => c.asset), ['10.20.30.0/24']);
  assert.deepEqual(n.inScope.domains.map((d) => d.asset), ['www.globex.example'], 'uri wins over name; URL scoped to host');
  assert.deepEqual(n.outOfScope.domains.map((d) => d.asset).sort(), ['com.globex.app', 'status.globex.example']);
  assert.ok(n.gaps.some((g) => /target group 'Mobile'/.test(g) && /OUT-of-scope/.test(g)), 'ambiguous group named in a gap, treated out (safe direction)');
  assert.ok(n.gaps.some((g) => /no rewards table/.test(g)));
});

test('generic: out-of-scope ALWAYS wins — exact domain + contained CIDR exclusions recorded, in-scope shrinks', () => {
  const n = normalizeProgram(FIX('generic-program.json'), { platform: 'generic' });
  assert.equal(n.ok, true);
  assert.equal(n.engagementScope, '2001:db8::/32', 'only the unexcluded CIDR remains');
  assert.deepEqual(n.inScope.domains, [], 'the exact-matched domain is excluded');
  assert.deepEqual(n.inScope.wildcards.map((w) => w.asset), ['*.initech.example']);
  const kinds = n.overlaps.map((o) => o.direction).sort();
  assert.deepEqual(kinds, ['in-scope CIDR excluded', 'in-scope domain excluded']);
  assert.ok(n.overlaps.every((o) => o.rule === 'out-of-scope wins'));
  // the exclusion is never silent: the excluded entries carry the reason in outOfScope
  assert.ok(n.outOfScope.domains.some((d) => d.asset === 'initech.example' && /EXCLUDED by/.test(d.note || '')));
  assert.ok(n.outOfScope.cidrs.some((c) => c.asset === '192.0.2.10/32' && /EXCLUDED by/.test(c.note || '')));
});

test('empty in-scope after precedence is REFUSED with a named reason', () => {
  const n = normalizeProgram(FIX('program-empty.json'), { platform: 'generic' });
  assert.equal(n.ok, false);
  assert.equal(n.error, 'scope-resolves-empty');
  assert.match(n.reason, /EMPTY after out-of-scope precedence/);
  assert.equal(n.overlaps.length, 1, 'the exclusion that emptied it is on record');
});

test('the normalizer is adapter-agnostic: raw entries with no metadata still apply every hard rule', () => {
  const n = normalizeEntries([
    { asset: '10.0.0.0/8', inScope: true },
    { asset: '10.1.0.0/16', inScope: false },
  ]);
  assert.equal(n.ok, true);
  assert.deepEqual(n.inScope.cidrs.map((c) => c.asset), ['10.0.0.0/8']);
  assert.ok(n.gaps.some((g) => /10\.1\.0\.0\/16 overlaps in-scope 10\.0\.0\.0\/8/.test(g)), 'partial coverage is a loud gap, never silent');
  const bad = normalizeEntries([{ asset: '', inScope: true }]);
  assert.equal(bad.ok, false, 'an empty entry cannot arm a scope');
  const unknown = normalizeProgram({}, { platform: 'nope' });
  assert.equal(unknown.error, 'unknown-platform');
  assert.deepEqual(PLATFORMS, ['hackerone', 'bugcrowd', 'generic']);
});

// --- the signing path (reuse of the seam's own signSession) ----------------------------

test('signScope refuses a scope with zero CIDRs (domains await operator resolution)', async () => {
  const only = normalizeEntries([{ asset: 'only-domains.example', inScope: true }]);
  const s = await signScope(only, {});
  assert.equal(s.ok, false);
  assert.equal(s.error, 'no-cidrs-to-sign');
  assert.match(s.reason, /ZERO CIDRs/);
  const notImportable = await signScope({ ok: false, error: 'scope-resolves-empty' }, {});
  assert.equal(notImportable.error, 'not-importable');
});

test('signScope produces a fixture the SEAM verifies and identity.mjs consumes — and never touches marcus.json', async () => {
  const before = readFileSync(MARCUS, 'utf8'); // the pinned baseline identity.test.mjs owns
  const n = normalizeProgram(FIX('generic-program.json'), { platform: 'generic' });
  const s = await signScope(n, {}); // defaults: principal marcus, workspace <- program handle
  assert.equal(s.ok, true);
  assert.equal(s.fixture.principal, 'marcus');
  assert.equal(s.fixture.workspace, 'initech', 'workspace defaults to the program handle');
  assert.equal(s.fixture.engagementScope, '2001:db8::/32');
  assert.match(s.fixture.sig, /^hmac-sha256:[0-9a-f]{64}$/);
  assert.equal(s.carriedIdentity, true, 'session continuity carried from the existing marcus fixture');

  // the fixture verifies under the seam's OWN verifySession (the hook's code)…
  const util = await import(pathToFileURL(join(SEAM, 'util.mjs')).href);
  assert.equal(util.verifySession(s.fixture), true);
  // …and is consumed by engine/identity.mjs exactly like the pinned marcus.json
  const file = tmpFile('signed-scope.json');
  try {
    writeFileSync(file, JSON.stringify(s.fixture, null, 2) + '\n');
    const { readOperator, scopeForCampaign } = await import('../engine/identity.mjs');
    const op = await readOperator({ ENCLAVE_SESSION: file });
    assert.equal(op.verified, true);
    assert.deepEqual(op.cidrs, ['2001:db8::/32']);
    const scope = scopeForCampaign(op);
    assert.equal(scope.engagement, 'initech');
    assert.deepEqual(scope.cidrs, ['2001:db8::/32']);
  } finally { rmSync(file, { force: true }); }

  // explicit overrides win over every default
  const o = await signScope(n, { principal: 'ravi', workspace: 'explicit-eng', sessionId: 'sess-x' });
  assert.equal(o.fixture.workspace, 'explicit-eng');
  assert.equal(o.fixture.session_id, 'sess-x');
  assert.equal(o.fixture.principal, 'ravi');

  assert.equal(readFileSync(MARCUS, 'utf8'), before, 'the pinned marcus.json is byte-identical — the sign path never writes it');
});

// --- the CLI surface -------------------------------------------------------------------

test('cli program import prints the normalized scope + gaps; unknown platform and junk file are data, not crashes', () => {
  const ok = run(['program', 'import', join(__dir, 'fixtures', 'h1-program.json'), '--platform', 'hackerone']);
  assert.equal(ok.status, 0);
  assert.equal(ok.out.ok, true);
  assert.equal(ok.out.engagementScope, '203.0.113.0/24,198.51.100.7/32');
  assert.ok(Array.isArray(ok.out.gaps) && ok.out.gaps.length >= 4);
  const bad = run(['program', 'import', join(__dir, 'fixtures', 'h1-program.json'), '--platform', 'nope']);
  assert.equal(bad.out.error, 'unknown-platform');
  const junk = run(['program', 'import', join(__dir, 'fixtures', 'no-such-file.json'), '--platform', 'generic']);
  assert.equal(junk.out.error, 'unreadable-fixture');
  const empty = run(['program', 'import', join(__dir, 'fixtures', 'program-empty.json'), '--platform', 'generic']);
  assert.equal(empty.out.error, 'scope-resolves-empty');
});

test('cli program import --sign --out writes a verifying fixture; without --out it prints, never writes', () => {
  const file = tmpFile('cli-scope.json');
  try {
    const signed = run(['program', 'import', join(__dir, 'fixtures', 'generic-program.json'), '--platform', 'generic', '--sign', '--out', file]);
    assert.equal(signed.status, 0);
    assert.equal(signed.out.signing.ok, true);
    assert.equal(signed.out.wrote, file);
    const fixture = JSON.parse(readFileSync(file, 'utf8'));
    assert.deepEqual(Object.keys(fixture).sort(), ['engagementScope', 'principal', 'session_id', 'sig', 'workspace'], 'the file is EXACTLY the consumed session-fixture shape');
    assert.equal(fixture.engagementScope, '2001:db8::/32');
    // no --out: the signed fixture is printed into the result, nothing written
    const printed = run(['program', 'import', join(__dir, 'fixtures', 'generic-program.json'), '--platform', 'generic', '--sign']);
    assert.equal(printed.out.signing.ok, true);
    assert.ok(printed.out.signedFixture && printed.out.signedFixture.sig);
    assert.equal(printed.out.wrote, undefined);
    assert.equal(existsSync(tmpFile('never-written.json')), false);
  } finally { rmSync(file, { force: true }); }
});
