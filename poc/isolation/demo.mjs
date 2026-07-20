// demo.mjs — the Phase-1 spine, end to end, runnable today:
//   provision an isolated sandbox -> gate a tool call at the real PEP ->
//   run allowed work INSIDE the sandbox -> deny disallowed work before it runs ->
//   tear down (wipe) -> everything audited.
// Runs on whatever isolation tier is available (process today; Docker/Firecracker
// when present) and reports what that tier enforces vs. the production target.

import { readFileSync, existsSync, unlinkSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { SandboxManager, LEDGER } from './sandbox-manager.mjs';
import { verifyLedger } from '../enforcement-seam/util.mjs';
import firecracker from './providers/firecracker.mjs';
import docker from './providers/docker.mjs';
import local from './providers/local-process.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SESS = join(HERE, '..', 'enforcement-seam', 'session');
const C = { g: s => `\x1b[32m${s}\x1b[0m`, r: s => `\x1b[31m${s}\x1b[0m`, y: s => `\x1b[33m${s}\x1b[0m`,
  dim: s => `\x1b[90m${s}\x1b[0m`, b: s => `\x1b[1m${s}\x1b[0m` };
const yn = v => (v === true ? C.g('yes') : v === false ? C.r('no ') : C.y(String(v)));

// Program run INSIDE the sandbox: proves ephemeral cwd, working fs, and NO secrets.
const PROBE = "const fs=require('fs');fs.writeFileSync('proof.txt','ok');" +
  "console.log(JSON.stringify({cwd:process.cwd(),wroteFile:fs.existsSync('proof.txt')," +
  "seesAnthropicKey:!!process.env.ANTHROPIC_API_KEY,seesAwsKey:!!process.env.AWS_SECRET_ACCESS_KEY," +
  "envCount:Object.keys(process.env).length}))";

function matrix(active) {
  const rows = [['ephemeral filesystem', 'ephemeralFs'], ['secrets scrubbed', 'secretsScrubbed'],
    ['egress denied (kernel)', 'egressDenied'], ['isolation', 'kernelIsolation']];
  console.log('  ' + C.b('what each tier enforces') + C.dim('   (★ = the tier running now)'));
  console.log('  ' + 'property'.padEnd(24) + ['local-process', 'docker', 'firecracker'].map((n, i) =>
    (active.name === [local, docker, firecracker][i].name ? '★ ' : '  ') + n).join('   '));
  for (const [label, key] of rows) {
    const cells = [local, docker, firecracker].map(p => String(p.enforces[key]));
    console.log('  ' + C.dim(label.padEnd(24)) + cells.map((c, i) => c.padEnd(i === 0 ? 13 : i === 1 ? 6 : 0)).join('   '));
  }
  console.log('');
}

(async () => {
  if (existsSync(LEDGER)) unlinkSync(LEDGER);
  // Plant a fake credential in the PARENT env; the sandbox must never see it.
  process.env.ANTHROPIC_API_KEY = 'sk-demo-MUST-NOT-appear-in-sandbox';

  const mgr = new SandboxManager();
  console.log('\n' + C.b('  ENCLAVE — isolation layer') + C.dim(`   active tier: ${mgr.provider.tier}`));
  console.log(C.dim('  provision → PEP-gated exec → isolated run → teardown → audit\n'));
  matrix(mgr.provider);

  // ── Act 1 — provision an isolated sandbox for the operator's session ──
  const danaFile = join(SESS, 'dana.json');
  const dana = JSON.parse(readFileSync(danaFile, 'utf8'));
  const box = mgr.provision(dana);
  console.log('  ' + C.b('1) provisioned') + `  session ${box.id}  ·  ${box.workdir || box.container}  ·  ${mgr.provider.name}\n`);

  // ── Act 2a — an ALLOWED tool call runs INSIDE the sandbox ──
  const okCall = { tool_name: 'Bash', tool_input: { command: 'ls -la ./evidence' }, cwd: '/work/incident-2231', hook_event_name: 'PreToolUse' };
  const a = await mgr.exec(box, dana, danaFile, okCall, PROBE);
  console.log('  ' + C.b('2a) allowed work') + `  dana (L3) · "${okCall.tool_input.command}"  →  ${a.decision === 'allow' ? C.g('ALLOW → ran in sandbox') : C.r(a.decision)}`);
  if (a.ran) {
    const p = JSON.parse(a.result.stdout || '{}');
    console.log('       ' + C.dim(`in-sandbox cwd: ${p.cwd}`));
    console.log('       ' + `wrote a file in the ephemeral dir: ${yn(p.wroteFile)}   ` +
      `sandbox can see the ANTHROPIC key: ${yn(p.seesAnthropicKey)} ${p.seesAnthropicKey === false ? C.dim('(scrubbed ✓)') : ''}`);
  }
  console.log('');

  // ── Act 2b — a DISALLOWED tool call is blocked BEFORE it can run ──
  const badCall = { tool_name: 'Bash', tool_input: { command: 'nmap -sS 10.10.5.20' }, cwd: '/work/incident-2231', hook_event_name: 'PreToolUse' };
  const b = await mgr.exec(box, dana, danaFile, badCall, "console.log('THIS MUST NEVER RUN')");
  console.log('  ' + C.b('2b) disallowed work') + `  dana (L3) · "${badCall.tool_input.command}"  →  ${b.decision === 'deny' ? C.r('DENY') : C.y(b.decision)}`);
  console.log('       ' + `executed in sandbox: ${yn(b.ran)} ${b.ran === false ? C.dim('(gate precedes execution ✓)') : ''}`);
  console.log('       ' + C.dim(b.reason || ''));
  console.log('');

  // ── Act 3 — teardown wipes the sandbox ──
  const wiped = mgr.teardown(box, dana);
  const gone = box.workdir ? !existsSync(box.workdir) : wiped;
  console.log('  ' + C.b('3) teardown') + `  sandbox destroyed, state wiped: ${yn(gone)}\n`);

  const led = verifyLedger(LEDGER);
  console.log(C.b('  ── summary ──'));
  console.log(`  spine ran on the ${C.b(mgr.provider.tier)} tier; allowed work executed in isolation, disallowed work never did.`);
  console.log(`  audit ledger: ${led.count} hash-chained entries, integrity ${led.ok ? C.g('verified ✓') : C.r('BROKEN ✗')}`);
  if (mgr.provider.name === 'local-process')
    console.log(C.dim('  (start Docker Desktop to auto-run on the container tier with kernel-enforced --network none egress deny.)'));
  console.log('');
})();
