// docker provider — the tier-2 isolation. Auto-activates when the Docker daemon
// is reachable. Each session is a disposable container with REAL kernel-enforced
// isolation: no network at all (--network none), read-only root, all capabilities
// dropped, non-root, resource-capped. Secrets never enter (host env isn't passed in).

import { spawnSync } from 'node:child_process';

const IMAGE = 'node:20-alpine'; // has node, so `run` is identical to the local tier
function docker(args, timeout = 30000) {
  return spawnSync('docker', args, { encoding: 'utf8', timeout });
}

export default {
  name: 'docker',
  tier: 'container (docker --network none)',
  enforces: { ephemeralFs: true, secretsScrubbed: true, egressDenied: true, kernelIsolation: 'namespaces + seccomp' },

  available() {
    const r = docker(['info', '--format', '{{.ServerVersion}}'], 8000);
    return r.status === 0 && !!(r.stdout || '').trim();
  },

  create(session) {
    const name = 'enclave-' + session.session_id;
    const r = docker(['run', '-d', '--rm', '--name', name,
      '--network', 'none',              // deny-all egress, kernel-enforced
      '--read-only',                    // immutable rootfs
      '--tmpfs', '/work:rw,size=256m,mode=1777',  // ephemeral scratch (world-writable so the non-root user can write), gone on stop
      '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges',
      '--user', '65534',                // nobody
      '--pids-limit', '128', '--memory', '512m',
      '-w', '/work',
      IMAGE, 'sleep', '3600']);
    if (r.status !== 0) throw new Error('docker create failed: ' + (r.stderr || r.stdout));
    return { id: session.session_id, container: name, provider: 'docker' };
  },

  run(sandbox, code) {
    // Pipe the program to `node` over stdin (via `docker exec -i`) rather than as a
    // `-e` argument — avoids cross-platform arg-escaping mangling the code string.
    const r = spawnSync('docker', ['exec', '-i', sandbox.container, 'node'],
      { input: code, encoding: 'utf8', timeout: 15000 });
    return { code: r.status, stdout: (r.stdout || '').trim(), stderr: (r.stderr || '').trim() };
  },

  destroy(sandbox) { docker(['rm', '-f', sandbox.container], 15000); return true; },
};
