// demo.mjs — the full-stack join, on real Docker isolation:
//
//   [sandbox]───internal net (NO internet)───[broker]───upstream net───[mock api]
//   no key, no NIC out                    holds+injects key      confirms key arrived
//
// Proves in ONE run: the sandbox can reach nothing but the broker; the broker is
// the only path out and injects the key the sandbox never had; off-allowlist is
// denied; a smuggled sandbox key is stripped. "No data leaves, key never enters."

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const C = { g: s => `\x1b[32m${s}\x1b[0m`, r: s => `\x1b[31m${s}\x1b[0m`, y: s => `\x1b[33m${s}\x1b[0m`, dim: s => `\x1b[90m${s}\x1b[0m`, b: s => `\x1b[1m${s}\x1b[0m` };
const IMG = 'enclave-fullstack';
const NET_INT = 'enclave-fs-net-internal', NET_UP = 'enclave-fs-net-upstream';
const MOCK = 'enclave-fs-upstream', BROKER = 'enclave-fs-broker', SANDBOX = 'enclave-fs-sandbox';

const d = (args, t = 30000, input) => spawnSync('docker', args, { encoding: 'utf8', timeout: t, input });
const dockerUp = () => { const r = d(['info', '--format', '{{.ServerVersion}}'], 8000); return r.status === 0 && !!(r.stdout || '').trim(); };
function cleanup() { d(['rm', '-f', MOCK, BROKER, SANDBOX]); d(['network', 'rm', NET_INT]); d(['network', 'rm', NET_UP]); }

(async () => {
  console.log('\n' + C.b('  ENCLAVE — full-stack join') + C.dim('   sandbox + isolation + egress broker + key injection\n'));

  if (!dockerUp()) {
    console.log(C.y('  SKIPPED') + ' — requires Docker (start Docker Desktop and re-run).');
    console.log('  FULL-STACK: SKIP\n');
    process.exit(0);
  }

  cleanup(); // clear any leftovers
  process.stdout.write('  · building image, networks, containers … ');
  const build = d(['build', '-q', '-t', IMG, HERE], 180000);
  if (build.status !== 0) { console.log(C.r('build failed')); console.log(build.stderr); cleanup(); process.exit(1); }

  // two internal networks — neither has an internet gateway
  d(['network', 'create', '--internal', NET_INT]);
  d(['network', 'create', '--internal', NET_UP]);

  // mock upstream: only on the upstream net (sandbox can never reach it)
  d(['run', '-d', '--rm', '--name', MOCK, '--network', NET_UP, IMG, 'node', 'upstream-mock.mjs']);

  // broker: on the internal net (faces the sandbox), then also connected to the
  // upstream net (faces the mock). Holds the key. Dual-homed = the only bridge.
  const b = d(['run', '-d', '--rm', '--name', BROKER, '--network', NET_INT,
    '-e', 'ENCLAVE_KEY=sk-ant-BROKER-HELD-secret', '-e', `UPSTREAM_URL=http://${MOCK}:9090`,
    IMG, 'node', 'broker-server.mjs']);
  if (b.status !== 0) { console.log(C.r('broker failed')); console.log(b.stderr); cleanup(); process.exit(1); }
  d(['network', 'connect', NET_UP, BROKER]);
  console.log(C.g('ready'));

  await new Promise(x => setTimeout(x, 1500)); // let the servers bind

  // sandbox: on the internal net ONLY, no key, hardened. Reaches only the broker.
  const s = d(['run', '--rm', '--name', SANDBOX, '--network', NET_INT,
    '--read-only', '--tmpfs', '/tmp:rw,mode=1777', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '65534',
    '-e', `BROKER_URL=http://${BROKER}:8080`, IMG, 'node', 'sandbox-agent.mjs'], 60000);
  cleanup();

  const m = (s.stdout || '').match(/RESULT:(\{.*\})/);
  if (!m) { console.log(C.r('\n  no result from sandbox agent')); console.log((s.stdout || '') + (s.stderr || '')); console.log('  FULL-STACK: FAIL\n'); process.exit(1); }
  const R = JSON.parse(m[1]);

  const a = R.viaBrokerAnthropic || {}, aj = a.json || {}, ups = aj.upstream || {};
  const smUp = (R.smuggle && R.smuggle.json && R.smuggle.json.upstream) || {};
  const blocked = v => typeof v === 'string' && v.startsWith('blocked');

  console.log('');
  console.log(`  sandbox holds a credential of its own: ${R.sandboxHasKey ? C.r('yes ✗') : C.g('no ✓')}\n`);
  console.log('  ' + C.b('A) reach Claude — through the broker') + C.dim('  (sandbox sends no key)'));
  console.log(`       ${aj.allowed ? C.g('200 allowed') : C.r('blocked')} · broker injected ${C.dim(aj.keyPrefix || '?')} · upstream received a key: ${ups.upstreamSawApiKey ? C.g('yes ✓') : C.r('no ✗')}`);
  console.log('  ' + C.b('B) exfil to pastebin — through the broker'));
  console.log(`       ${R.viaBrokerExfil && R.viaBrokerExfil.allowed === false ? C.r('DENY') : C.y('?')} · ${(R.viaBrokerExfil && R.viaBrokerExfil.reason) || ''}`);
  console.log('  ' + C.b('C) reach Claude — directly, bypassing the broker'));
  console.log(`       ${blocked(R.directAnthropic) ? C.g(`BLOCKED (${R.directAnthropic}) ✓`) : C.r(R.directAnthropic)} ${C.dim('← sandbox has no route; only the broker does')}`);
  console.log('  ' + C.b('D) reach the open internet — directly'));
  console.log(`       ${blocked(R.directInternet) ? C.g(`BLOCKED (${R.directInternet}) ✓`) : C.r(R.directInternet)} ${C.dim('← no NIC to the outside at all')}`);
  console.log('  ' + C.b('E) smuggle its own stolen key — through the broker'));
  console.log(`       upstream saw the sandbox's stolen key: ${(smUp.keyPrefix || '').startsWith('sk-SAND') ? C.r('yes ✗') : C.g('no ✓')} ${C.dim('← broker stripped it, used its own')}`);

  const pass = !R.sandboxHasKey && aj.allowed && ups.upstreamSawApiKey &&
    R.viaBrokerExfil && R.viaBrokerExfil.allowed === false &&
    blocked(R.directAnthropic) && blocked(R.directInternet) &&
    !(smUp.keyPrefix || '').startsWith('sk-SAND');

  console.log('\n' + C.b('  ── summary ──'));
  console.log('  No client data can leave the sandbox except through the audited broker; the API key');
  console.log('  lives in the broker and is injected on the way out — it never enters the sandbox.');
  console.log('  ' + (pass ? C.g(C.b('FULL-STACK: PASS ✓')) : C.r(C.b('FULL-STACK: FAIL ✗'))) + '\n');
  process.exit(pass ? 0 : 1);
})();
