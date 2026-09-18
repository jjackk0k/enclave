// capture-hello.mjs — the JA4 OBSERVER leg for the native agent, Node side.
//
// Spawns the compiled varvel-agent against a one-shot loopback listener, captures the
// raw ClientHello off the wire (the first TLS record is cleartext — no server half is
// needed), and fingerprints it with the PLATFORM'S OWN oracle
// (varvel/engine/fingerprint.mjs parseClientHello + ja4 — the same math the fporacle
// and the channel's passive observer use). The same bytes are independently
// fingerprinted in Go (agents/native/ja4) — cross-implementation parity is asserted
// in test/native-agent.test.mjs.
//
// CLI:  node agents/native/harness/capture-hello.mjs <path-to-varvel-agent.exe> <profile>
// LIB:  import { captureAgentHello } from './capture-hello.mjs'
//
// HONESTY: a JA4 string is a MEASUREMENT. Matching a published Chrome JA4 is string
// equality with a reference, never a claim of indistinguishability.

import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { captureJa4 } from '../../../tools/fporacle.mjs';

// captureAgentHello runs the agent binary once (-once) at the given TLS profile and
// returns { ok, ja4, parsed, stderr } — the oracle's verdict on the bytes the binary
// actually emitted. SNI is a NAME (localhost), never an IP literal: real clients omit
// SNI for IPs, and the JA4 d/i flag would measure the wrong thing.
export async function captureAgentHello(binary, profile, { timeout = 15000 } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'varvel-native-'));
  let stderr = '';
  const connect = (port) => {
    const child = spawn(binary, [
      '-url', `https://localhost:${port}/c`, // the listener closes after one record — the pull "fails", the hello is already captured
      '-id', 'ja4probe', '-token', 'capture-leg-only',
      '-tls-profile', profile, '-tls-insecure', '-once', '-dir', dir,
    ], { windowsHide: true });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', () => {});
  };
  const r = await captureJa4({ connect, timeout });
  return { ...r, stderr: stderr.trim() };
}

// CLI
if (process.argv[1] && import.meta.url === new URL('file://' + process.argv[1].replace(/\\/g, '/')).href) {
  const [binary, profile = 'chrome'] = process.argv.slice(2);
  if (!binary) { console.error('usage: node capture-hello.mjs <varvel-agent.exe> [chrome|go-native]'); process.exit(2); }
  const r = await captureAgentHello(binary, profile);
  console.log(JSON.stringify(r, null, 2));
  process.exit(r.ok ? 0 : 1);
}
