// VARVEL -- fetch-curl-impersonate: the honest installer for the curl-impersonate
// baseline used by tools/impersonate.mjs.
//
// WHAT THIS DOES: reads the pinned upstream release of lwthiker/curl-impersonate from
// the live GitHub API, looks for a win64 asset carrying curl-impersonate-chrome, and --
// IF one exists -- downloads it into varvel/bin/, computes the sha256 at install time,
// PRINTS that hash for the operator to record, and prints exactly what was installed.
//
// WHAT IT FOUND (verified live 2026-08-05): NO Windows binary has ever shipped
// upstream. Latest release v0.6.1 carries Linux (x86_64/aarch64/arm) + macOS (x86_64)
// assets only. On that reality this script says so plainly and exits 1 with
// build-from-source guidance. It never fakes availability -- and neither does
// tools/impersonate.mjs, whose unsupported reason tells the same story.
//
//   node scripts/fetch-curl-impersonate.mjs

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const REPO = 'lwthiker/curl-impersonate';
const PINNED_VERSION = 'v0.6.1'; // pinned 2026-08-05 after reading releases/latest live -- re-pin when upstream ships a newer tag
const PINNED_SHA256 = null; // expected sha256 of the win64 asset; null until one exists -- record the printed hash here after a verified install
const BIN_DIR = fileURLToPath(new URL('../bin/', import.meta.url));
const API = 'https://api.github.com/repos/' + REPO + '/releases/latest';
const FETCH_TIMEOUT = 15000;

const say = (s) => process.stdout.write(s + '\n');

async function getJson(url) {
  const ctl = new AbortController();
  const t = setTimeout(() => { try { ctl.abort(); } catch {} }, FETCH_TIMEOUT);
  try {
    const r = await fetch(url, { headers: { 'user-agent': 'varvel-curl-impersonate-installer', accept: 'application/vnd.github+json' }, signal: ctl.signal });
    if (!r.ok) throw new Error('GitHub API answered HTTP ' + r.status);
    return await r.json();
  } finally {
    clearTimeout(t);
  }
}

async function download(url, dest) {
  const ctl = new AbortController();
  const t = setTimeout(() => { try { ctl.abort(); } catch {} }, 10 * 60 * 1000);
  try {
    const r = await fetch(url, { headers: { 'user-agent': 'varvel-curl-impersonate-installer' }, redirect: 'follow', signal: ctl.signal });
    if (!r.ok || !r.body) throw new Error('download answered HTTP ' + r.status);
    fs.writeFileSync(dest, Buffer.from(await r.arrayBuffer()));
  } finally {
    clearTimeout(t);
  }
}

// A win64 curl-impersonate-chrome asset: chrome flavour, a Windows name, and not the
// libcurl library tarball.
function isWinChromeAsset(name) {
  return /curl-impersonate/i.test(name) && /chrome/i.test(name) && /(win64|win32|windows)/i.test(name) && !/^libcurl/i.test(name);
}

function findExe(dir) {
  const out = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (/^curl-impersonate-chrome.*\.exe$/i.test(e.name) || /^curl_chrome.*\.exe$/i.test(e.name)) out.push(p);
    }
  };
  walk(dir);
  return out.sort();
}

function printGuidance(tag) {
  say('');
  say('RESULT: NO win64 curl-impersonate-chrome asset exists in upstream release ' + tag + '.');
  say('VARVEL will NOT pretend otherwise: tools/impersonate.mjs reports the same fact as');
  say('{ supported:false } until a real binary is present. Nothing was installed.');
  say('');
  say('Honest routes to a working binary on this Windows host:');
  say('  1. WSL2 -- download the x86_64-linux-gnu tarball above inside WSL and call the');
  say('     Linux binary there; point CURL_IMPERSONATE at it from the Linux side.');
  say('  2. Docker -- run the published lwthiker/curl-impersonate container image and');
  say('     route requests through it (the image is Linux-based).');
  say('  3. Build from source -- https://github.com/' + REPO + ' documents Linux/macOS');
  say('     builds only; a mingw-w64 cross-compile for Windows is community-reported,');
  say('     NOT officially supported. If you produce curl-impersonate-chrome.exe, drop');
  say('     it in ' + BIN_DIR + ' or set CURL_IMPERSONATE to its full path.');
  say('');
  say('Reminder of the locked label: browser TLS/H2 fingerprint parity at the transport');
  say('layer is NOT a challenge bypass -- passage depends on zone config + egress');
  say('reputation.');
}

async function main() {
  say('VARVEL curl-impersonate installer');
  say('upstream: ' + REPO + ' (pinned ' + PINNED_VERSION + (PINNED_SHA256 ? ', sha256 pinned' : ', no asset hash pinned yet') + ')');
  say('target:   ' + BIN_DIR);
  say('');

  let rel;
  try {
    rel = await getJson(API);
  } catch (e) {
    say('ERROR: could not reach the GitHub API (' + String((e && e.message) || e) + ').');
    say('No claim made either way -- re-run with network access.');
    process.exitCode = 1;
    return;
  }

  const tag = String(rel.tag_name || 'unknown');
  if (tag !== PINNED_VERSION) {
    say('NOTE: latest upstream release is ' + tag + ' but this script is pinned to ' + PINNED_VERSION + '.');
    say('      Evaluating ' + tag + ' anyway; re-pin PINNED_VERSION after reviewing the result.');
  }
  const assets = Array.isArray(rel.assets) ? rel.assets : [];
  say('release ' + tag + ' publishes ' + assets.length + ' assets:');
  for (const a of assets) say('  - ' + a.name);

  const win = assets.filter((a) => isWinChromeAsset(String(a.name || '')));
  if (!win.length) {
    printGuidance(tag);
    process.exitCode = 1;
    return;
  }

  // A Windows asset exists: download, hash, verify against the pin when one is set.
  const asset = win[0];
  fs.mkdirSync(BIN_DIR, { recursive: true });
  const staging = path.join(BIN_DIR, '.staging-' + asset.name);
  say('');
  say('downloading ' + asset.name + ' (' + asset.size + ' bytes)...');
  try {
    await download(asset.browser_download_url, staging);
  } catch (e) {
    try { fs.rmSync(staging, { force: true }); } catch {}
    say('ERROR: download failed (' + String((e && e.message) || e) + '). Nothing installed.');
    process.exitCode = 1;
    return;
  }

  const sha256 = crypto.createHash('sha256').update(fs.readFileSync(staging)).digest('hex');
  say('sha256 (computed at install time -- RECORD THIS): ' + sha256);
  if (PINNED_SHA256 && sha256 !== PINNED_SHA256) {
    try { fs.rmSync(staging, { force: true }); } catch {}
    say('ERROR: hash mismatch against PINNED_SHA256 ' + PINNED_SHA256 + ' -- refusing to install.');
    process.exitCode = 1;
    return;
  }
  if (!PINNED_SHA256) say('no PINNED_SHA256 is set in this script yet; verify this hash independently, then pin it.');

  const extractDir = fs.mkdtempSync(path.join(BIN_DIR, '.extract-'));
  try {
    execFileSync('tar', ['-xf', staging, '-C', extractDir], { stdio: ['ignore', 'ignore', 'inherit'] }); // bsdtar (ships with Windows) handles .tar.gz and .zip
  } catch (e) {
    say('ERROR: could not extract ' + asset.name + ' (' + String((e && e.message) || e) + '). Nothing installed.');
    process.exitCode = 1;
    return;
  }
  const exes = findExe(extractDir);
  if (!exes.length) {
    say('ERROR: archive held no curl-impersonate-chrome*.exe -- refusing to guess. Nothing installed.');
    process.exitCode = 1;
    return;
  }
  const dest = path.join(BIN_DIR, 'curl-impersonate-chrome.exe');
  fs.copyFileSync(exes[0], dest);
  const size = fs.statSync(dest).size;

  say('');
  say('INSTALLED:');
  say('  version: ' + tag);
  say('  binary:  ' + dest + ' (' + size + ' bytes)');
  say('  sha256:  ' + sha256 + ' (of archive ' + asset.name + ')');
  say('  detect:  tools/impersonate.mjs will now report available:true, browser chrome');
  say('  honesty: TLS/H2 parity only -- NOT a challenge bypass (zone config + egress reputation decide passage)');

  try { fs.rmSync(staging, { force: true }); } catch {}
  try { fs.rmSync(extractDir, { recursive: true, force: true }); } catch {}
}

main().catch((e) => {
  say('ERROR: installer crashed (' + String((e && e.message) || e) + '). Nothing installed.');
  process.exitCode = 1;
});
