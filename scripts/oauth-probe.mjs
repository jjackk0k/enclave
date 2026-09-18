// oauth-probe.mjs — does the current Kimi OAuth access_token work as Bearer on the
// coding endpoint the way VARVEL calls it? Prints status + a short snippet only.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const cred = JSON.parse(readFileSync(join(homedir(), '.kimi-code', 'credentials', 'kimi-code.json'), 'utf8'));
const nowSec = Math.floor(Date.now() / 1000);
console.log('token expires_in:', cred.expires_in, 's · expires_at - now =', (cred.expires_at - nowSec), 's (negative = already expired)');
const res = await fetch('https://api.kimi.com/coding/v1/messages', {
  method: 'POST',
  headers: { 'content-type': 'application/json', authorization: 'Bearer ' + cred.access_token, 'x-api-key': cred.access_token, 'anthropic-version': '2023-06-01' },
  body: JSON.stringify({ model: 'k3', max_tokens: 16, messages: [{ role: 'user', content: 'reply with the word ok' }], stream: false }),
});
console.log('HTTP', res.status);
const t = await res.text();
console.log(t.slice(0, 300));
