// oauth-refresh-test.mjs — verify the kimi-code OAuth refresh flow end to end.
// On 200: writes the fresh pair back to the credentials file (same as the CLI does).
// Prints status + field names only — never token values.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const FILE = join(homedir(), '.kimi-code', 'credentials', 'kimi-code.json');
const CLIENT_ID = '17e5f671-d194-4dfb-9706-5516cb48c098';
const cred = JSON.parse(readFileSync(FILE, 'utf8'));

const hosts = ['https://auth.kimi.com/api/oauth/token', 'https://api.kimi.com/api/oauth/token'];
const PATHS = null;
let done = false;
for (const h of hosts) {
  try {
    const res = await fetch(h, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: CLIENT_ID, grant_type: 'refresh_token', refresh_token: cred.refresh_token }),
    });
    console.log(h, '-> HTTP', res.status);
    if (res.status !== 200) { console.log('  body:', (await res.text()).slice(0, 200)); continue; }
    const j = await res.json();
    console.log('  fields:', Object.keys(j).join(','));
    const next = {
      access_token: j.access_token,
      refresh_token: j.refresh_token || cred.refresh_token,
      expires_at: Math.floor(Date.now() / 1000) + (j.expires_in || 900),
      expires_in: j.expires_in || 900,
      scope: j.scope || cred.scope,
      token_type: j.token_type || cred.token_type,
    };
    writeFileSync(FILE, JSON.stringify(next, null, 2) + '\n');
    console.log('  WROTE fresh pair back (expires_in', next.expires_in, 's)');
    done = true;
    break;
  } catch (e) { console.log(h, 'ERR', e.message); }
}
if (!done) process.exit(1);
