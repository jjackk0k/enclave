// doh-ja4s.mjs — fporacle JA4S probe of the live DoH endpoint (one-shot).
import { pathToFileURL } from 'node:url';
const { probeJa4s } = await import(pathToFileURL('C:/Users/Jack/Downloads/enclave/varvel/tools/fporacle.mjs').href);
const fp = await probeJa4s('192.168.50.1', 4453, { servername: 'varvel-doh-lab.local' });
console.log('JA4S: ' + JSON.stringify(fp));
