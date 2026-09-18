// impersonate.test.mjs -- hermetic: NO live network, NO real curl-impersonate binary.
// Detection is exercised against fake binaries planted in temp dirs via the paths
// override; the non-zero-exit path uses the node binary itself as a stand-in process
// that rejects curl's argv (exit != 0); arg construction and header-dump parsing are
// tested as the pure functions they are.
//   node --test varvel/test/impersonate.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { detectImpersonate, fetchImpersonated, buildArgs, parseHeaderDump, browserFromName, HONEST_NOTE, INSTALL_CMD } from '../tools/impersonate.mjs';

const mk = () => fs.mkdtempSync(path.join(os.tmpdir(), 'varvel-imp-test-'));
const plant = (dir, name) => { const p = path.join(dir, name); fs.writeFileSync(p, 'fake'); return p; };

test('detect: exact curl-impersonate-chrome.exe found via paths.binDir override', () => {
  const dir = mk();
  const p = plant(dir, 'curl-impersonate-chrome.exe');
  const d = detectImpersonate({ env: {}, paths: { binDir: dir, pathDirs: [] } });
  assert.equal(d.available, true);
  assert.equal(d.path, p);
  assert.equal(d.browser, 'chrome');
  assert.equal(d.note, HONEST_NOTE);
});

test('detect: wrapper prefix curl_ff*.exe resolves to firefox', () => {
  const dir = mk();
  plant(dir, 'curl_ff116.exe');
  const d = detectImpersonate({ env: {}, paths: { binDir: dir, pathDirs: [] } });
  assert.equal(d.available, true);
  assert.equal(d.browser, 'firefox');
});

test('detect: PATH override dirs are searched (pathDirs)', () => {
  const binDir = mk();
  const pathDir = mk();
  const p = plant(pathDir, 'curl-impersonate-ff.exe');
  const d = detectImpersonate({ env: {}, paths: { binDir, pathDirs: [pathDir] } });
  assert.equal(d.available, true);
  assert.equal(d.path, p);
  assert.equal(d.browser, 'firefox');
});

test('detect: CURL_IMPERSONATE wins over binDir', () => {
  const dir = mk();
  plant(dir, 'curl-impersonate-chrome.exe');
  const explicit = plant(mk(), 'curl-impersonate-ff.exe');
  const d = detectImpersonate({ env: { CURL_IMPERSONATE: explicit }, paths: { binDir: dir, pathDirs: [] } });
  assert.equal(d.available, true);
  assert.equal(d.path, explicit);
  assert.equal(d.browser, 'firefox');
});

test('detect: unsupported honesty when nothing exists (note names installer + upstream truth)', () => {
  const dir = mk();
  const d = detectImpersonate({ env: {}, paths: { binDir: dir, pathDirs: [] } });
  assert.equal(d.available, false);
  assert.equal(d.path, null);
  assert.equal(d.browser, null);
  assert.match(d.note, /no curl-impersonate binary found/);
  assert.match(d.note, /NO Windows binary/);
  assert.ok(d.note.includes(INSTALL_CMD), 'note points at the installer');
});

test('detect: CURL_IMPERSONATE pointing at a missing file is reported, not trusted', () => {
  const dir = mk();
  const ghost = path.join(dir, 'nope.exe');
  const d = detectImpersonate({ env: { CURL_IMPERSONATE: ghost }, paths: { binDir: dir, pathDirs: [] } });
  assert.equal(d.available, false);
  assert.match(d.note, /points at a missing file/);
});

test('buildArgs: proxy, headers and timeout land as their own argv tokens, url last', () => {
  const args = buildArgs('https://t.example/path', {
    proxy: 'http://127.0.0.1:8080',
    headers: { 'x-a': '1', accept: 'text/html' },
    timeoutMs: 2500,
    bodyPath: 'BODY',
    headerPath: 'HEAD',
  });
  assert.deepEqual(args, [
    '-sS', '-o', 'BODY', '-D', 'HEAD', '-w', '%{http_code}',
    '--max-time', '2.5',
    '--proxy', 'http://127.0.0.1:8080',
    '-H', 'x-a: 1', '-H', 'accept: text/html',
    'https://t.example/path',
  ]);
});

test('buildArgs: defaults (no proxy, 20s timeout) and caller-bug TypeErrors', () => {
  const args = buildArgs('https://t.example/', { bodyPath: 'B', headerPath: 'H' });
  assert.deepEqual(args, ['-sS', '-o', 'B', '-D', 'H', '-w', '%{http_code}', '--max-time', '20', 'https://t.example/']);
  assert.throws(() => buildArgs('', { bodyPath: 'B', headerPath: 'H' }), TypeError);
  assert.throws(() => buildArgs('https://t.example/'), TypeError); // missing capture files
  assert.throws(() => buildArgs('https://t.example/', { bodyPath: 'B', headerPath: 'H', headers: { 'x-evil': 'a\r\ninjected: 1' } }), TypeError);
  assert.throws(() => buildArgs('https://t.example/', { bodyPath: 'B', headerPath: 'H', proxy: 'http://p\nbad' }), TypeError);
});

test('parseHeaderDump: last block wins, HTTP/2 status line, repeated keys become arrays', () => {
  const dump = 'HTTP/1.1 200 Connection established\r\n\r\n' +
    'HTTP/2 200 \r\nserver: cloudflare\r\ncontent-type: text/html; charset=utf-8\r\nset-cookie: a=1\r\nset-cookie: b=2\r\n\r\n';
  const h = parseHeaderDump(dump);
  assert.equal(h.statusLine, 'HTTP/2 200');
  assert.equal(h.headers.server, 'cloudflare');
  assert.equal(h.headers['content-type'], 'text/html; charset=utf-8');
  assert.deepEqual(h.headers['set-cookie'], ['a=1', 'b=2']);
});

test('browserFromName: chrome / ff / firefox / unknown', () => {
  assert.equal(browserFromName('C:\\bin\\curl-impersonate-chrome.exe'), 'chrome');
  assert.equal(browserFromName('/opt/curl_ff116'), 'firefox');
  assert.equal(browserFromName('curl-impersonate-ff.exe'), 'firefox');
  assert.equal(browserFromName('plain-curl.exe'), null);
});

test('fetch: explicit binary that does not exist -> supported:false with install, never throws', async () => {
  const ghost = path.join(mk(), 'curl-impersonate-chrome.exe');
  const r = await fetchImpersonated('https://t.example/', { binary: ghost });
  assert.equal(r.supported, false);
  assert.match(r.reason, /not found at/);
  assert.match(r.reason, /NO Windows binary/);
  assert.equal(r.install, INSTALL_CMD);
});

test('fetch: non-zero exit resolves an honest error object, never throws', async () => {
  // process.execPath (node) rejects curl's argv ("bad option") and exits non-zero --
  // a hermetic stand-in for a failing binary; no network, no real impersonate binary.
  const r = await fetchImpersonated('https://t.example/', { binary: process.execPath, timeoutMs: 8000 });
  assert.equal(r.supported, false);
  assert.notEqual(r.exit, 0);
  assert.match(r.reason, /exited/);
  assert.equal(r.install, undefined); // binary exists -- this is a runtime failure, not a missing tool
});
