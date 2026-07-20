// demo.mjs — build a security tool for Linux AND Windows inside a sealed, no-network
// container. Proves the tool-dev workload: an operator can develop and cross-compile
// tooling in isolation, offline, from one source tree — the Linux enclave produces
// both an ELF (Linux) and a PE (Windows) binary.

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const C = { g: s => `\x1b[32m${s}\x1b[0m`, r: s => `\x1b[31m${s}\x1b[0m`, y: s => `\x1b[33m${s}\x1b[0m`, dim: s => `\x1b[90m${s}\x1b[0m`, b: s => `\x1b[1m${s}\x1b[0m` };
const IMG = 'enclave-tool-forge';
const d = (args, t = 180000) => spawnSync('docker', args, { encoding: 'utf8', timeout: t });
const dockerUp = () => { const r = d(['info', '--format', '{{.ServerVersion}}'], 8000); return r.status === 0 && !!(r.stdout || '').trim(); };

(async () => {
  console.log('\n' + C.b('  ENCLAVE — tool-forge') + C.dim('   build a tool for Linux + Windows, isolated\n'));
  if (!dockerUp()) { console.log(C.y('  SKIPPED') + ' — requires Docker.\n  TOOL-FORGE: SKIP\n'); process.exit(0); }

  process.stdout.write('  · building toolchain image ' + C.dim('(first run pulls golang:alpine)') + ' … ');
  const build = d(['build', '-q', '-t', IMG, HERE], 300000);
  if (build.status !== 0) { console.log(C.r('failed')); console.log(build.stderr); process.exit(1); }
  console.log(C.g('ready'));

  // Build INSIDE a sealed container: no network, read-only root, no caps, scratch on tmpfs.
  const run = d(['run', '--rm', '--network', 'none', '--read-only',
    '--tmpfs', '/out:rw', '--tmpfs', '/tmp:rw,size=256m', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    IMG], 120000);
  const m = (run.stdout || '').match(/RESULT:(\{.*\})/);
  if (!m) { console.log(C.r('\n  build produced no result')); console.log((run.stdout || '') + (run.stderr || '')); console.log('  TOOL-FORGE: FAIL\n'); process.exit(1); }
  const R = JSON.parse(m[1]);

  const linuxOk = R.linuxMagic === '7f454c46';   // ELF
  const winOk = R.windowsMagic === '4d5a';        // MZ (PE)

  console.log('\n  built inside a ' + C.b('sealed --network none container') + C.dim(' (offline, GOPROXY=off, read-only root)') + ':');
  console.log(`     Linux target    → portcheck-linux         ${String(R.linuxBytes).padStart(8)} bytes · magic ${R.linuxMagic} ${linuxOk ? C.g('(ELF ✓)') : C.r('✗')}`);
  console.log(`     Windows target  → portcheck-windows.exe   ${String(R.windowsBytes).padStart(8)} bytes · magic ${R.windowsMagic} ${winOk ? C.g('(PE / MZ ✓)') : C.r('✗')}`);

  const pass = linuxOk && winOk;
  console.log('\n' + C.b('  ── summary ──'));
  console.log('  One source tree, two OS targets, produced offline in isolation — the tool-dev workload.');
  console.log('  (Run/test the Windows binary in the Windows isolation tier; offensive USE stays gated at runtime.)');
  console.log('  ' + (pass ? C.g(C.b('TOOL-FORGE: PASS ✓')) : C.r(C.b('TOOL-FORGE: FAIL ✗'))) + '\n');
  process.exit(pass ? 0 : 1);
})();
