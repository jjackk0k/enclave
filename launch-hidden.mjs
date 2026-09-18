// launch-hidden.mjs — start a server detached with NO console window (Jack's rule:
// never spawn visible console windows for servers). Logs go to a file.
//   node launch-hidden.mjs <entry.mjs> <cwd> <logfile>
import { spawn } from 'node:child_process';
import { openSync } from 'node:fs';
import { resolve } from 'node:path';

const [entry, cwd, logfile] = process.argv.slice(2);
if (!entry || !cwd || !logfile) { console.error('usage: node launch-hidden.mjs <entry.mjs> <cwd> <logfile>'); process.exit(2); }
const out = openSync(resolve(logfile), 'a');
const child = spawn(process.execPath, [resolve(entry)], {
  cwd: resolve(cwd),
  detached: true,
  stdio: ['ignore', out, out],
  windowsHide: true,   // the whole point: no console window appears
});
child.unref();
console.log('launched hidden: ' + entry + ' (pid ' + child.pid + ', log ' + logfile + ')');
