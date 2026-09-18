// mullvad-check.mjs — is Mullvad's in-tunnel SOCKS5 answering? (one-shot)
import { pathToFileURL } from 'node:url';
const { probeSocks5 } = await import(pathToFileURL('C:/Users/Jack/Downloads/enclave/varvel/engine/ghost.mjs').href);
const r = await probeSocks5({ host: '10.64.0.1', port: 1080, timeout: 2500 });
console.log('mullvad socks5 10.64.0.1:1080 ->', r ? 'ANSWERING (tunnel connected)' : 'no answer (app not connected, or different local port)');
