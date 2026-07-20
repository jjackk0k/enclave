// mksessions.mjs — issues the demo session tokens (run once).
// Stands in for the IdP / session broker: it binds a principal to a session and
// signs it. The hook later verifies this signature and trusts NOTHING else.
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { signSession } from './util.mjs';

const dir = join(dirname(fileURLToPath(import.meta.url)), 'session');
const issue = (s) => { const signed = { ...s, sig: signSession(s) };
  writeFileSync(join(dir, s.principal + '.json'), JSON.stringify(signed, null, 2) + '\n'); return signed; };

issue({ session_id: 'sess-1001', principal: 'sam',    workspace: 'triage-queue' });
issue({ session_id: 'sess-1002', principal: 'priya',  workspace: 'soc2-evidence-q3' });
issue({ session_id: 'sess-1003', principal: 'dana',   workspace: 'incident-2231' });
issue({ session_id: 'sess-1004', principal: 'marcus', workspace: 'pentest-northwind', engagementScope: '10.10.0.0/16' });

// A FORGED session: Sam's token edited to claim a higher-value workspace, WITHOUT
// re-signing. The hook must reject it (signature no longer matches) — you cannot
// self-elevate by editing the token.
const forged = issue({ session_id: 'sess-1001', principal: 'sam', workspace: 'triage-queue' });
forged.workspace = 'incident-2231';           // tamper AFTER signing
writeFileSync(join(dir, 'sam-forged.json'), JSON.stringify(forged, null, 2) + '\n');

console.log('issued 4 signed sessions + 1 forged (tampered) session');
