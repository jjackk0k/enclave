// local-process provider — the DEV tier. Runs today on any OS (incl. Windows).
// Isolation is a per-session ephemeral working directory + a scrubbed environment
// (no secrets reach the sandbox). It does NOT provide kernel-level network/FS
// isolation — that's the Docker and Firecracker tiers. Use for local development.

import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

// Anything that looks like a credential is stripped before the sandbox runs.
const SECRET_RE = /(ANTHROPIC|AWS|AZURE|GCP|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|APIKEY|_KEY)$|API_KEY|ACCESS_KEY/i;
function scrubEnv(env) {
  const out = {};
  for (const [k, v] of Object.entries(env)) if (!SECRET_RE.test(k)) out[k] = v;
  out.ENCLAVE_SANDBOX = '1';
  return out;
}

export default {
  name: 'local-process',
  tier: 'process + ephemeral dir (dev only)',
  enforces: { ephemeralFs: true, secretsScrubbed: true, egressDenied: false, kernelIsolation: 'none (shared kernel)' },

  available() { return true; },

  create(session) {
    const workdir = mkdtempSync(join(tmpdir(), 'enclave-' + session.session_id + '-'));
    return { id: session.session_id, workdir, provider: 'local-process' };
  },

  // `code` is a JS program string, executed by node INSIDE the sandbox (portable).
  run(sandbox, code) {
    const r = spawnSync(process.execPath, ['-e', code], {
      cwd: sandbox.workdir, env: scrubEnv(process.env), encoding: 'utf8', timeout: 10000,
    });
    return { code: r.status, stdout: (r.stdout || '').trim(), stderr: (r.stderr || '').trim() };
  },

  destroy(sandbox) {
    if (existsSync(sandbox.workdir)) rmSync(sandbox.workdir, { recursive: true, force: true });
    return !existsSync(sandbox.workdir);
  },
};
