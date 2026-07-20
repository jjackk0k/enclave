#!/usr/bin/env node
// test-all.mjs — one command to verify every runnable proof in Enclave is green.
// Run before a demo / test session:   node test-all.mjs   (or: npm test)
//
// It installs the one dependency that needs it (Cedar for the enforcement seam),
// runs each PoC's self-checking demo, and asserts the success markers.

import { spawnSync } from 'node:child_process';
import { existsSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = dirname(fileURLToPath(import.meta.url));
const strip = s => (s || '').replace(/\x1b\[[0-9;]*m/g, '');
const C = { g: s => `\x1b[32m${s}\x1b[0m`, r: s => `\x1b[31m${s}\x1b[0m`, dim: s => `\x1b[90m${s}\x1b[0m`, b: s => `\x1b[1m${s}\x1b[0m` };

function run(cwd, cmd, args, timeout = 120000) {
  const r = spawnSync(cmd, args, { cwd: join(ROOT, cwd), encoding: 'utf8', timeout,
    env: { ...process.env, NODE_NO_WARNINGS: '1' } });
  return { code: r.status, out: strip((r.stdout || '') + (r.stderr || '')) };
}

console.log('\n' + C.b('  Enclave — test-all') + C.dim('   verifying every runnable proof\n'));

// 0) ensure the enforcement seam has Cedar installed (the isolation + egress demos use it too)
const SEAM = 'poc/enforcement-seam';
if (!existsSync(join(ROOT, SEAM, 'node_modules', '@cedar-policy'))) {
  process.stdout.write('  · installing Cedar for the enforcement seam … ');
  const i = run(SEAM, 'npm', ['install', '--no-audit', '--no-fund'], 240000);
  console.log(i.code === 0 ? C.g('done') : C.r('FAILED'));
  if (i.code !== 0) { console.log(i.out.split('\n').slice(-8).join('\n')); process.exit(1); }
}

const NODE = process.execPath;
const checks = [
  { name: 'enforcement seam · identity + clearance + qualification', cwd: SEAM, cmd: NODE, args: ['demo.mjs'],
    want: [/scenarios behaved exactly as policy requires ✓/, /integrity verified ✓/], needZeroExit: true },
  { name: 'isolation layer · provision → PEP gate → isolated run → teardown', cwd: 'poc/isolation', cmd: NODE, args: ['demo.mjs'],
    want: [/state wiped: yes/, /integrity verified ✓/, /scrubbed ✓/] },
  { name: 'egress broker · deny-all + BYO-key injection', cwd: 'poc/egress-broker', cmd: NODE, args: ['demo.mjs'],
    want: [/key ever inside the sandbox: no ✓/, /audit log: none ✓/, /integrity verified ✓/] },
  { name: 'presets · scaffold a governed, pre-filled workspace', cwd: 'presets', cmd: NODE,
    args: ['scaffold.mjs', '--preset', 'red-team', '--name', '_selftest', '--client', 'Acme', '--scope', '10.0.0.0/8', '--lead', 'QA', '--force'],
    want: [/Scaffolded "_selftest"/, /clearance ≥ L4/], notWant: [/«FILL/] },
];

let failed = 0;
for (const c of checks) {
  const r = run(c.cwd, c.cmd, c.args);
  const missing = (c.want || []).filter(re => !re.test(r.out));
  const bad = (c.notWant || []).filter(re => re.test(r.out));
  const exitOk = c.needZeroExit ? r.code === 0 : true;
  const ok = missing.length === 0 && bad.length === 0 && exitOk;
  if (!ok) failed++;
  console.log(`  ${ok ? C.g('PASS') : C.r('FAIL')}  ${c.name}`);
  if (!ok) {
    if (!exitOk) console.log(C.dim(`         non-zero exit (${r.code})`));
    for (const m of missing) console.log(C.dim(`         missing marker: ${m}`));
    for (const m of bad) console.log(C.dim(`         unexpected: ${m}`));
    console.log(C.dim('         --- tail ---\n' + r.out.split('\n').filter(Boolean).slice(-6).map(l => '         ' + l).join('\n')));
  }
}

// cleanup the scaffold self-test output
try { rmSync(join(ROOT, 'presets', 'workspaces', '_selftest'), { recursive: true, force: true }); } catch {}

console.log('');
if (failed === 0) { console.log(C.g(C.b(`  ✓ all ${checks.length} proofs green — ready to test/demo.`)) + '\n'); process.exit(0); }
console.log(C.r(C.b(`  ✗ ${failed}/${checks.length} failed — see tails above.`)) + '\n');
process.exit(1);
