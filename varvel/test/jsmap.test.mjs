// VARVEL jsmap tests — hermetic fixtures for the Node/JS impact-primitive miner
// (engine/jsmap.mjs + tools/jsmap.mjs). Mirrors the privemap test doctrine: a
// deliberately vulnerable express app, a deliberately safe one, mitigation/ranking
// assertions, and never-throw robustness (minified/binary/huge/garbage inputs).
// Tool-level fixtures are written under varvel/.tmp per the house rule.
//   node --test test/jsmap.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mineJs } from '../engine/jsmap.mjs';
import { jsmap } from '../tools/jsmap.mjs';

// Repo-local scratch dir (gitignored, Defender-excluded) — the house rule.
const TMP = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp', 'jsmap-test');
mkdirSync(TMP, { recursive: true });

// (a) The vulnerable express app: every required detection class in one file.
const VULN_APP = `
import express from 'express';
import { exec } from 'child_process';
import jwt from 'jsonwebtoken';
import fetch from 'node-fetch';
import path from 'node:path';

const app = express();
app.use(express.json());

function authRequired(req, res, next) {
  if (!req.headers.authorization) return res.status(401).end();
  next();
}

// unauth + exec with template-interpolated req.query → rce-exec, direct
app.get('/ping-host', (req, res) => {
  const host = req.query.host;
  exec(\`ping \${host}\`, (err, out) => res.send(out || String(err)));
});

// same sink behind auth — must rank strictly BELOW the unauth one
app.post('/admin/backup', authRequired, (req, res) => {
  const file = req.body.file;
  exec('tar czf /backups/x.tgz ' + file, () => res.send('ok'));
});

app.get('/profile', authRequired, (req, res) => res.send('p'));
app.get('/settings', authRequired, (req, res) => res.send('s'));

// unauth prototype-polluting merge; also a differential middleware gap
app.post('/merge', (req, res) => {
  const cfg = {};
  Object.assign(cfg, req.body);
  res.json(cfg);
});

app.get('/read', (req, res) => {
  res.sendFile(path.join('/srv/files', req.query.name));
});

app.get('/token', (req, res) => {
  const claims = jwt.verify(req.query.t, process.env.SECRET);
  res.json(claims);
});

app.post('/fetch', (req, res) => {
  fetch(req.body.url).then((r) => r.text()).then((t) => res.send(t));
});

app.post('/hook', (req, res) => {
  if (req.headers['x-hook-secret'] === process.env.HOOK_SECRET) {
    res.send('verified');
  } else {
    res.status(403).end();
  }
});
`;

// (b) The safe app: constant-arg execFile, pinned jwt, timingSafeEqual, allowlisted
// path lookup, auth middleware everywhere. Nothing here may rank high/crit.
const SAFE_APP = `
import express from 'express';
import { execFile } from 'node:child_process';
import jwt from 'jsonwebtoken';
import { timingSafeEqual } from 'node:crypto';
import path from 'node:path';

const app = express();
app.use(express.json());

function authRequired(req, res, next) {
  const token = req.headers.authorization || '';
  const expect = process.env.API_TOKEN || '';
  const a = Buffer.from(token);
  const b = Buffer.from(expect);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return res.status(401).end();
  next();
}

app.get('/git-status', authRequired, (req, res) => {
  execFile('git', ['status', '--short'], (err, out) => res.send(out || 'clean'));
});

app.get('/doc', authRequired, (req, res) => {
  const ALLOWED = { readme: 'README.md', license: 'LICENSE' };
  const key = String(req.query.name || '');
  if (!Object.prototype.hasOwnProperty.call(ALLOWED, key)) return res.status(404).end();
  const p = path.join(__dirname, ALLOWED[key]);
  if (!p.startsWith(__dirname)) return res.status(400).end();
  res.sendFile(p);
});

app.get('/claims', authRequired, (req, res) => {
  const claims = jwt.verify(req.query.t, process.env.SECRET, { algorithms: ['HS256'] });
  res.json(claims);
});
`;

// (c) Named-handler + helper-descent fixture: the sink lives in a helper the handler
// calls (the privemap transitive shape).
const HELPER_APP = `
const express = require('express');
const { execSync } = require('child_process');
const router = express.Router();

function runReport(name) {
  return execSync('report-gen --name ' + name);
}

function reportHandler(req, res) {
  const name = req.query.name;
  const out = runReport(name);
  res.send(out);
}

router.get('/report', reportHandler);
`;

// (d) Raw createServer fixture (the VARVEL server.mjs shape).
const RAW_APP = `
const { createServer } = require('node:http');
const { readFileSync } = require('node:fs');

const requestHandler = async (req, res) => {
  const q = new URL(req.url, 'http://x').searchParams.get('f') || '';
  const body = readFileSync(q);
  res.end(body);
};

createServer(requestHandler).listen(8080, '127.0.0.1');
`;

const rec = (name, content) => ({ path: `fixtures/${name}`, content });

test('vulnerable fixture: every detection class fires with route-registered unauth reachability', () => {
  const r = mineJs([rec('vuln-app.js', VULN_APP)]);
  const classes = new Set(r.candidates.map((c) => c.impactClass));
  for (const want of ['rce-exec', 'proto-pollution', 'path-traversal', 'ssrf', 'jwt-alg-unpinned', 'secret-compare', 'middleware-gap']) {
    assert.ok(classes.has(want), `missing class ${want}; got ${[...classes].join(', ')}`);
  }
  // privemap candidate shape
  for (const c of r.candidates) {
    for (const k of ['rank', 'sev', 'title', 'ref', 'reachability', 'impactClass', 'evidence', 'confidence', 'probe']) {
      assert.ok(k in c, `candidate missing ${k}`);
    }
    assert.match(c.probe, /READ-ONLY|read-only|MEASURE/i, 'probes stay read-only/differential');
    assert.doesNotMatch(c.probe, /;cat \/etc\/passwd|DROP TABLE|rm -rf/i, 'probes never carry payloads');
  }
});

test('ranking: unauth rce-exec outranks its authed twin; reachability model holds', () => {
  const r = mineJs([rec('vuln-app.js', VULN_APP)]);
  const rce = r.candidates.filter((c) => c.impactClass === 'rce-exec');
  assert.equal(rce.length, 2, 'both the unauth and the authed exec are reported');
  const [unauth, authed] = rce.sort((a, b) => a.rank - b.rank);
  assert.equal(unauth.reachability, 'unauth');
  assert.equal(unauth.sev, 'crit');
  assert.equal(r.candidates[0].impactClass, 'rce-exec', 'unauth rce-exec is rank 1');
  assert.equal(authed.reachability, 'authed');
  assert.ok(authed.score < unauth.score, 'authed ranks below unauth (same class)');
  assert.ok(authed.mitigations.some((m) => /authRequired/.test(m)), 'auth middleware is named in mitigations');
});

test('differential middleware-gap: fires per unauth route with authed siblings, cites the asymmetry', () => {
  const r = mineJs([rec('vuln-app.js', VULN_APP)]);
  const gapsFound = r.candidates.filter((c) => c.impactClass === 'middleware-gap');
  assert.ok(gapsFound.length >= 4, `expected ≥4 gap findings, got ${gapsFound.length}`);
  for (const g of gapsFound) {
    assert.equal(g.reachability, 'unauth');
    assert.match(g.evidence, /sibling route\(s\).*enforce/i);
    assert.equal(g.confidence, 'medium');
  }
  // The authed routes themselves are never gap findings.
  assert.ok(!gapsFound.some((g) => g.route === '/admin/backup'));
});

test('safe fixture: zero high/crit; sanitizers suppress or downgrade every class', () => {
  const r = mineJs([rec('safe-app.js', SAFE_APP)]);
  assert.ok(!r.candidates.some((c) => c.sev === 'crit' || c.sev === 'high'),
    'safe app produced a high/crit: ' + JSON.stringify(r.candidates.map((c) => [c.sev, c.impactClass, c.evidence])));
  // The pinned jwt.verify, timingSafeEqual, and constant-arg execFile stay silent.
  assert.ok(!r.candidates.some((c) => c.impactClass === 'jwt-alg-unpinned'));
  assert.ok(!r.candidates.some((c) => c.impactClass === 'secret-compare'));
  assert.ok(!r.candidates.some((c) => c.impactClass === 'rce-exec'));
  // The allowlisted+guarded path lookup may remain as a downgraded residual — with
  // mitigations attached and confidence no higher than medium (ranks, not convicts).
  for (const c of r.candidates.filter((x) => x.impactClass === 'path-traversal')) {
    assert.ok(c.mitigations.length >= 1, 'guard not credited in mitigations');
    assert.ok(['medium', 'low'].includes(c.confidence));
  }
});

test('named handlers resolve; helper descent carries chain + low confidence', () => {
  const r = mineJs([rec('helper-app.js', HELPER_APP)]);
  assert.equal(r.stats.routes, 1);
  const hit = r.candidates.find((c) => c.impactClass === 'rce-exec');
  assert.ok(hit, 'the helper-resident exec was not found');
  assert.match(hit.evidence, /via reportHandler -> runReport/, 'descent chain is documented');
  assert.equal(hit.confidence, 'low', 'cross-function hits stay low confidence');
  assert.equal(hit.reachability, 'unauth');
});

test('raw http.createServer handlers are mined (the server.mjs shape)', () => {
  const r = mineJs([rec('raw-app.js', RAW_APP)]);
  assert.equal(r.stats.routes, 1);
  const hit = r.candidates.find((c) => c.impactClass === 'path-traversal');
  assert.ok(hit, 'readFileSync on a query param was not found');
  assert.equal(hit.reachability, 'unauth');
  assert.equal(hit.taint, 'tainted-var', 'q is assigned from req.url one line up');
});

test('never-throw: minified, binary-ish, huge, CRLF and garbage inputs degrade to gaps/nothing', () => {
  const minified = 'const a=1;' + 'function f(){return "x".repeat(9)};'.repeat(3000) + 'app.get("/x",(q,s)=>{s.end("y")});';
  const hugeLine = 'app.post("/y",(req,res)=>{' + 'const z=' + '"ab".repeat(120000);' + 'res.end(z)});';
  const garbage = '���\x00\x01 binary \x7f stuff {{{ }}} ((';
  const crlf = VULN_APP.replace(/\n/g, '\r\n');
  for (const [name, content] of [['min.js', minified], ['huge.js', hugeLine], ['garbage.js', garbage], ['crlf.js', crlf], ['empty.js', ''], ['nullish.js', null]]) {
    assert.doesNotThrow(() => mineJs([rec(name, content)]), `threw on ${name}`);
  }
  const crlfR = mineJs([rec('crlf.js', crlf)]);
  assert.ok(crlfR.candidates.some((c) => c.impactClass === 'rce-exec'), 'CRLF sources are normalized and mined');
  const junk = mineJs([rec('garbage.js', garbage)]);
  assert.ok(Array.isArray(junk.candidates) && Array.isArray(junk.gaps));
});

test('tool wrapper: walks a tree, skips binary/oversized/node_modules, root-relative refs, never throws', () => {
  const tree = join(TMP, 'tree');
  mkdirSync(join(tree, 'routes'), { recursive: true });
  mkdirSync(join(tree, 'node_modules', 'leftpad'), { recursive: true });
  writeFileSync(join(tree, 'index.js'), VULN_APP);
  writeFileSync(join(tree, 'routes', 'helper.js'), HELPER_APP);
  writeFileSync(join(tree, 'node_modules', 'leftpad', 'index.js'), 'eval(req.body.x)'); // must NOT be scanned
  writeFileSync(join(tree, 'blob.js'), Buffer.from([0x89, 0x50, 0x00, 0x0d, 0x65, 0x76, 0x61, 0x6c])); // NUL bytes → binary skip
  writeFileSync(join(tree, 'big.js'), 'const x = "' + 'A'.repeat(900 * 1024) + '";\n'); // oversized skip

  const r = jsmap(tree);
  assert.ok(r.scannedFiles >= 2);
  assert.ok(r.candidates.some((c) => c.impactClass === 'rce-exec'));
  assert.ok(!r.candidates.some((c) => /node_modules/.test(c.ref)), 'node_modules stayed out');
  assert.ok(!r.candidates.some((c) => c.ref.startsWith(tree) || c.ref.startsWith(tree.replace(/\\/g, '/'))), 'refs are root-relative');
  assert.ok(r.skipped.some((s) => /blob\.js$/.test(s.path) && /binary/.test(s.reason)), 'binary file reported skipped');
  assert.ok(r.skipped.some((s) => /big\.js$/.test(s.path) && /oversized/.test(s.reason)), 'oversized file reported skipped');
  assert.ok(r.stats.routes >= 2);

  // Never-throw on bad roots.
  for (const bad of [join(TMP, 'does-not-exist'), '', join(tree, 'index.js')]) {
    const out = jsmap(bad);
    assert.ok(Array.isArray(out.candidates) && Array.isArray(out.skipped), `tool threw or malformed on root '${bad}'`);
  }
});
