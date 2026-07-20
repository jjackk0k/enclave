#!/usr/bin/env node
// print-context.mjs — emit the read-only session context for injection into a
// headless Claude Code session.
//
//   Raw (for --append-system-prompt):
//     ENCLAVE_SESSION=./session/dana.json node print-context.mjs
//
//   As a SessionStart hook (emits additionalContext JSON):
//     ENCLAVE_SESSION=./session/dana.json node print-context.mjs --hook
//
// Like the PEP, it TRUSTS ONLY THE SIGNED SESSION: an unverifiable identity
// yields no context (fail-closed), so the model is never told a clearance that
// wasn't cryptographically bound.

import { readFileSync } from 'node:fs';
import { verifySession } from './util.mjs';
import { buildContext } from './session-context.mjs';

let session;
try { session = JSON.parse(readFileSync(process.env.ENCLAVE_SESSION, 'utf8')); }
catch { process.stderr.write('print-context: no ENCLAVE_SESSION file — refusing (fail-closed)\n'); process.exit(1); }

if (!verifySession(session)) {
  process.stderr.write('print-context: session signature invalid — refusing to build context\n');
  process.exit(2);
}

const ctx = buildContext(session);
if (!ctx) { process.stderr.write('print-context: unknown principal\n'); process.exit(3); }

if (process.argv.includes('--hook')) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: ctx },
  }));
} else {
  process.stdout.write(ctx + '\n');
}
