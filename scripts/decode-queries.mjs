// decode-queries.mjs — offline decode of %TEMP%\push-queries.txt: which of the
// agent-produced push queries fail to decode, and what do the good ones carry.
import { readFileSync } from 'node:fs';
import { decodeQuery } from '../varvel/engine/dnscodec.mjs';

const lines = readFileSync(process.env.TEMP + '\\push-queries.txt', 'utf8').trim().split(/\r?\n/);
lines.forEach((q, idx) => {
  const p = decodeQuery(q, { domain: 'ax.sim' });
  if (!p) { console.log(idx, 'DECODE-FAIL qlen=' + q.length); return; }
  console.log(idx, 's=' + p.s, 'i=' + p.i, 'n=' + p.n, 'dlen=' + String(p.d || '').length, 'hlen=' + String(p.h || '').length, 'qlen=' + q.length);
});
