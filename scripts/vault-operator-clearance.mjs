// vault-operator-clearance.mjs — write OPERATOR-PROVIDED clearance into the vaults.
// The operator reads cf_clearance out of their OWN consented browser session and hands it
// over explicitly — no profile scraping, ever. usage:
//   node scripts/vault-operator-clearance.mjs <domain> <ua> <cfClearanceValue> [minutes]
import { pathToFileURL } from 'node:url';

const [domain, ua, value, minutes] = process.argv.slice(2);
if (!domain || !ua || !value) { console.error('usage: node scripts/vault-operator-clearance.mjs <domain> <ua> <cfClearanceValue> [minutes]'); process.exit(2); }
const broker = await import(pathToFileURL('C:/Users/Jack/Downloads/enclave/varvel/tools/clearance/broker.mjs').href);

const zone = domain.replace(/^www\./, '');
const ttl = (Number(minutes) || 45) * 60000;
const entry = {
  cookies: [{ name: 'cf_clearance', value, domain: '.' + zone, path: '/', secure: true, httpOnly: true, sameSite: 'None' }],
  ua,
  mintedAt: new Date().toISOString(),
  expiresAt: new Date(Date.now() + ttl).toISOString(),
  engine: 'operator-provided',
};
const key = broker.vaultKey(zone, 'direct', ua);

const vaults = [
  'C:/Users/Jack/Downloads/enclave/varvel/data/clearance-vault.json',
  'C:/Users/Jack/.enclave-workspaces/varvel-chat/varvel-tools/data/clearance-vault.json',
];
for (const vaultPath of vaults) {
  const cur = broker.readVault({ vaultPath });
  const entries = cur.ok ? cur.entries : {};
  entries[key] = entry;
  const w = broker.writeVault(entries, { vaultPath });
  console.log(w.ok ? `vaulted -> ${vaultPath}` : `FAILED ${vaultPath}: ${w.error}`);
}
console.log('zone:', zone, '| engine: operator-provided | expires:', entry.expiresAt);
