// kali.mjs — one-shot helper: run a bash command inside the Kali attacker VM
// via vm-lab.mjs guest-ops and print its output. Usage: node kali.mjs "<cmd>"
import { runInKali } from './vm-lab.mjs';
const cmd = process.argv.slice(2).join(' ');
if (!cmd) { console.error('usage: node kali.mjs "<cmd>"'); process.exit(2); }
console.log(await runInKali(cmd, Number(process.env.KALI_TIMEOUT || 150000)));
