// VARVEL http-methods/CORS tests — pure classifier + hermetic live checks.
//   node --test varvel/test/httpmethods.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { httpFindings, analyzeHttp } from '../tools/httpmethods.mjs';

const has = (f, ref) => f.some((x) => x.ref === ref);
async function serve(handler) {
  const srv = http.createServer(handler);
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { srv, base: `http://127.0.0.1:${srv.address().port}` };
}

test('httpFindings: dangerous methods + TRACE (and untrimmed/mixed-case)', () => {
  const f = httpFindings({ methods: [' put ', 'GET', 'Trace', 'DELETE'] });
  assert.ok(has(f, 'HTTP-METHODS') && f.find((x) => x.ref === 'HTTP-METHODS').sev === 'high');
  assert.ok(has(f, 'HTTP-TRACE'), 'trimmed + case-folded before matching');
});

test('httpFindings: CORS misconfigurations by severity', () => {
  assert.equal(httpFindings({ cors: { reflects: true, credentials: true } }).find((x) => x.ref === 'CORS-REFLECT').sev, 'high');
  assert.equal(httpFindings({ cors: { acao: '*', credentials: true } }).find((x) => x.ref === 'CORS-WILD-CRED').sev, 'high');
  assert.equal(httpFindings({ cors: { acao: '*' } }).find((x) => x.ref === 'CORS-WILD').sev, 'low');
  assert.equal(httpFindings({ cors: { reflects: true } }).find((x) => x.ref === 'CORS-REFLECT-NC').sev, 'med');
});

test('httpFindings: header findings only when header data present; no-args -> []', () => {
  const f = httpFindings({ headers: { hsts: false, csp: false, xfo: false } });
  assert.ok(has(f, 'HDR-HSTS') && has(f, 'HDR-CSP') && has(f, 'HDR-XFO'));
  assert.deepEqual(httpFindings({ methods: ['GET'], headers: { hsts: true, csp: true, xfo: true }, cors: {} }), []);
  assert.deepEqual(httpFindings(), [], 'no data -> no fabricated findings');
});

test('analyzeHttp: live OPTIONS + reflected-origin-with-credentials (verbatim)', async () => {
  const { srv, base } = await serve((req, res) => {
    if (req.method === 'OPTIONS') { res.writeHead(200, { allow: 'GET, POST, PUT, TRACE' }); return res.end(); }
    const o = req.headers.origin, h = {};
    if (o) { h['access-control-allow-origin'] = o; h['access-control-allow-credentials'] = 'true'; }
    res.writeHead(200, h); res.end('ok');
  });
  try {
    const r = await analyzeHttp(base, { timeout: 800 });
    assert.ok(r.methods.includes('PUT') && r.methods.includes('TRACE'));
    assert.equal(r.findings.find((x) => x.ref === 'CORS-REFLECT')?.sev, 'high');
    assert.ok(has(r.findings, 'HTTP-METHODS'));
  } finally { srv.close(); }
});

test('analyzeHttp: reflection detected even when the origin is normalized (trailing slash)', async () => {
  const { srv, base } = await serve((req, res) => {
    const o = req.headers.origin, h = {};
    if (o) { h['access-control-allow-origin'] = o + '/'; h['access-control-allow-credentials'] = 'true'; } // normalized echo
    res.writeHead(200, h); res.end('ok');
  });
  try {
    const r = await analyzeHttp(base, { timeout: 800 });
    assert.equal(r.findings.find((x) => x.ref === 'CORS-REFLECT')?.sev, 'high', 'normalized reflection still caught');
  } finally { srv.close(); }
});

test('analyzeHttp: HSTS is NOT flagged over plain http (noise); CSP/XFO still are', async () => {
  const { srv, base } = await serve((req, res) => { res.writeHead(200); res.end('ok'); }); // no security headers
  try {
    const r = await analyzeHttp(base, { timeout: 800 });
    assert.ok(!has(r.findings, 'HDR-HSTS'), 'no HSTS finding over http');
    assert.ok(has(r.findings, 'HDR-CSP') && has(r.findings, 'HDR-XFO'), 'CSP/XFO still checked over http');
  } finally { srv.close(); }
});

test('analyzeHttp: unreachable host does NOT fabricate missing-header findings', async () => {
  const r = await analyzeHttp('http://127.0.0.1:1', { timeout: 300 });
  assert.equal(r.ok, false, 'unreachable -> ok:false');
  assert.equal(r.findings, undefined, 'no findings fabricated for a host never reached');
});
