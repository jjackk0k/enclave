// scope-sign.mjs — re-issue a signed Enclave session with a new engagementScope.
// Running this is the operator's authorization act: the signature binds the principal
// to exactly these CIDRs, and VARVEL reads its scope from this file at spawn.
// usage: node scripts/scope-sign.mjs <principal> "<cidr,cidr,..."
import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const [principal, scope] = process.argv.slice(2);
if (!principal || !scope) {
  console.error('usage: node scope-sign.mjs <principal> "<cidr,cidr,...>"');
  process.exit(2);
}
const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'poc', 'enforcement-seam');
const util = await import(pathToFileURL(join(dir, 'util.mjs')).href);
const file = join(dir, 'session', principal + '.json');
const s = JSON.parse(readFileSync(file, 'utf8'));
delete s.sig;                       // re-sign from the canonical fields, never trust the old sig
s.engagementScope = scope;
const signed = { ...s, sig: util.signSession(s) };
if (!util.verifySession(signed)) { console.error('self-verify failed — not writing'); process.exit(1); }
writeFileSync(file, JSON.stringify(signed, null, 2) + '\n');
console.log(`re-signed ${principal}.json  engagementScope: ${scope}`);
