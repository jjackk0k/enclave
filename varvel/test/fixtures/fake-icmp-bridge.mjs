// fake-icmp-bridge.mjs — a node shim masquerading as agents/icmp-bridge.py for hermetic
// tests: a REAL child process with REAL stdio pipes, no raw sockets, no admin. Speaks
// the exact bridge protocol (JSON lines, capability first). Mode via FAKE_BRIDGE_MODE:
//   echo   (default) capability supported:true, then every send gets a 'sent' ack and the
//          packet looped back as a recv from 127.0.0.1 (a loopback wire simulator).
//   stub   the WindowsApps store stub: nag on stderr, exit 49, NO capability line.
//   silent launches cleanly and never emits anything (capability-window honesty probe).
import { stdin, stdout, stderr, env, exit } from 'node:process';

const mode = env.FAKE_BRIDGE_MODE || 'echo';
const say = (obj) => stdout.write(JSON.stringify(obj) + '\n');

if (mode === 'stub') {
  stderr.write('Python was not found; run without arguments to install from the Microsoft Store, or disable this shortcut from Settings > Apps > Advanced app settings > App execution aliases.\n');
  exit(49);
}
if (mode === 'silent') {
  stdin.resume(); // stay alive, say nothing — the parent's honesty window must catch this
} else {
  say({ op: 'capability', supported: true, reason: 'fake bridge: stdio echo shim (no raw sockets)' });
  let buf = '';
  stdin.on('data', (d) => {
    buf += d.toString('utf8');
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { say({ op: 'error', error: 'bad json line' }); continue; }
      if (msg.op !== 'send') { say({ id: msg.id ?? null, op: 'error', error: 'unknown op' }); continue; }
      const len = Buffer.from(String(msg.packetB64 || ''), 'base64').length;
      say({ id: msg.id ?? null, op: 'sent', bytes: len });
      say({ op: 'recv', src: '127.0.0.1', packetB64: msg.packetB64 }); // loopback echo
    }
  });
}
