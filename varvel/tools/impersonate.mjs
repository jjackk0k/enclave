// VARVEL -- impersonate: the curl-impersonate transport shell (browser TLS/H2 parity).
//
// Why it exists (2026 research verdict): lwthiker/curl-impersonate reproduces a real
// browser's TLS ClientHello AND HTTP/2 frame profile at the socket level. That is the
// necessary BASELINE for talking to Cloudflare-fronted targets -- but it is NEVER
// sufficient alone: a managed challenge serves a JS bundle no forged fingerprint can
// execute. Every successful fetch therefore carries the locked honesty label verbatim
// (HONEST_NOTE below); nothing here is a challenge bypass.
//
// THE HONESTY CONTRACT (same doctrine as tools/detoracle.mjs, tools/preflight.mjs):
// NEVER throws on live paths -- a missing binary, a failed launch, a non-zero exit, or
// a timeout resolve { supported:false, reason } and the gap is REPORTED, never hidden.
// Upstream reality (verified live 2026-08-05): lwthiker/curl-impersonate has never
// shipped a Windows binary -- latest release v0.6.1 carries Linux/macOS assets only.
// detectImpersonate()'s absent note and fetchImpersonated()'s unsupported reason say
// exactly that and point at the installer (scripts/fetch-curl-impersonate.mjs), which
// re-verifies the claim against the live API and prints build-from-source guidance.
// Availability is never faked.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// The locked label. Carried verbatim in every supported result as honestNote.
export const HONEST_NOTE = 'browser TLS/H2 fingerprint parity at the transport layer — NOT a challenge bypass; passage depends on zone config + egress reputation.';

export const INSTALL_CMD = 'node scripts/fetch-curl-impersonate.mjs';

// One sentence of verified upstream truth, shared by the absent note and the
// unsupported reason so both tell the same story as the installer.
export const UPSTREAM_TRUTH = 'upstream lwthiker/curl-impersonate publishes NO Windows binary (latest release v0.6.1, verified 2026-08-05: Linux/macOS assets only)';

const BIN_DIR = fileURLToPath(new URL('../bin/', import.meta.url));
const EXACT = ['curl-impersonate-chrome', 'curl-impersonate-ff']; // preference order: chrome first
const PREFIX = ['curl_chrome', 'curl_ff']; // wrapper-style binary names

// browserFromName(p) -> 'chrome' | 'firefox' | null, derived from the binary's file
// name alone (that is what determines which fingerprint profile the process speaks).
export function browserFromName(p) {
  const base = String(p || '').split(/[\\/]/).pop().toLowerCase().replace(/\.exe$/, '');
  if (base.includes('chrome')) return 'chrome';
  if (base.includes('firefox') || /(?:^|[_-])ff(?:[_-]|\d|$)/.test(base)) return 'firefox';
  return null;
}

// scanDir(dir) -> full path of the first impersonate binary in dir, or null. Exact
// names win over wrapper prefixes; prefix hits are alphabetical for determinism.
function scanDir(dir) {
  let entries;
  try { entries = fs.readdirSync(dir); } catch { return null; }
  const wins = process.platform === 'win32';
  const low = entries.map((e) => e.toLowerCase());
  for (const base of EXACT) {
    const i = low.indexOf(wins ? base + '.exe' : base);
    if (i !== -1) return path.join(dir, entries[i]);
  }
  const hits = entries.filter((e) => {
    const l = e.toLowerCase();
    if (wins && !l.endsWith('.exe')) return false;
    return PREFIX.some((p) => l.startsWith(p));
  }).sort();
  return hits.length ? path.join(dir, hits[0]) : null;
}

// findOnPath(env) -> first impersonate binary on the operator's PATH, or null. Uses
// where/which for the exact names, then falls back to a direct PATH-directory scan
// (equivalent to what where/which does, but synchronous -- and it also catches the
// curl_chrome*/curl_ff* wrapper names that `which` cannot glob).
function findOnPath(env) {
  const wins = process.platform === 'win32';
  for (const base of EXACT) {
    try {
      const out = execFileSync(wins ? 'where' : 'which', [wins ? base + '.exe' : base], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true });
      const first = out.split(/\r?\n/).map((s) => s.trim()).find(Boolean);
      if (first && fs.existsSync(first)) return first;
    } catch { /* not on PATH under this name */ }
  }
  for (const d of String((env && env.PATH) || '').split(path.delimiter).filter(Boolean)) {
    const hit = scanDir(d);
    if (hit) return hit;
  }
  return null;
}

// detectImpersonate({ env, paths }) -> { available, path, browser, note }. Search
// order: CURL_IMPERSONATE env, then varvel/bin/, then PATH. `paths` ({ binDir,
// pathDirs }) overrides the filesystem roots so tests stay hermetic. Never throws.
export function detectImpersonate({ env = process.env, paths } = {}) {
  const checked = [];
  let envMiss = null;

  const envBin = env && env.CURL_IMPERSONATE;
  if (envBin) {
    checked.push('CURL_IMPERSONATE');
    if (fs.existsSync(envBin)) return { available: true, path: envBin, browser: browserFromName(envBin), note: HONEST_NOTE };
    envMiss = 'CURL_IMPERSONATE is set but points at a missing file (' + envBin + ')';
  }

  const binDir = (paths && paths.binDir) || BIN_DIR;
  checked.push(binDir);
  const inBin = scanDir(binDir);
  if (inBin) return { available: true, path: inBin, browser: browserFromName(inBin), note: HONEST_NOTE };

  if (paths && paths.pathDirs) {
    checked.push('PATH (override dirs)');
    for (const d of paths.pathDirs) {
      const hit = scanDir(d);
      if (hit) return { available: true, path: hit, browser: browserFromName(hit), note: HONEST_NOTE };
    }
  } else {
    checked.push('PATH');
    const onPath = findOnPath(env);
    if (onPath) return { available: true, path: onPath, browser: browserFromName(onPath), note: HONEST_NOTE };
  }

  return {
    available: false,
    path: null,
    browser: null,
    note: 'no curl-impersonate binary found (checked ' + checked.join(', ') + ') -- ' + UPSTREAM_TRUTH +
      (envMiss ? '; ' + envMiss : '') +
      '; run ' + INSTALL_CMD + ' for the live re-check and build-from-source guidance',
  };
}

// buildArgs(url, opts) -> the deterministic argv for the impersonate binary. Pure.
// Discipline: body -> -o file, response headers -> -D file, and stdout carries ONLY
// the numeric status (-w '%{http_code}'), so the caller parses digits, not streams.
// Every variable lands as its own argv token -- spawn args array, never a shell.
export function buildArgs(url, { proxy, headers = {}, timeoutMs = 20000, bodyPath, headerPath } = {}) {
  if (typeof url !== 'string' || !url.trim()) throw new TypeError('impersonate.buildArgs needs a url');
  if (!bodyPath || !headerPath) throw new TypeError('impersonate.buildArgs needs bodyPath and headerPath (the -o/-D capture files)');
  const args = ['-sS', '-o', String(bodyPath), '-D', String(headerPath), '-w', '%{http_code}', '--max-time', String(Number(timeoutMs) / 1000)];
  if (proxy) {
    if (/[\r\n]/.test(String(proxy))) throw new TypeError('impersonate.buildArgs: unsafe proxy uri');
    args.push('--proxy', String(proxy));
  }
  for (const [k, v] of Object.entries(headers || {})) {
    if (!k || /[\r\n]/.test(k) || /[\r\n]/.test(String(v))) throw new TypeError('impersonate.buildArgs: unsafe header ' + JSON.stringify(k));
    args.push('-H', k + ': ' + String(v));
  }
  args.push(String(url));
  return args;
}

// parseHeaderDump(text) -> { statusLine, headers } from a curl -D capture. Multi-block
// dumps (proxy CONNECT, 100-continue, redirects) resolve to the LAST block -- the
// final response. Header keys lowercase; repeated keys become arrays. Pure.
export function parseHeaderDump(text) {
  const blocks = String(text || '').split(/\r?\n\r?\n/).map((b) => b.trim()).filter(Boolean);
  const lines = (blocks[blocks.length - 1] || '').split(/\r?\n/).filter(Boolean);
  const statusLine = (lines.shift() || '').trim(); // 'HTTP/2 200 ' carries a trailing pad space in -D captures
  const headers = {};
  for (const line of lines) {
    const i = line.indexOf(':');
    if (i <= 0) continue;
    const k = line.slice(0, i).trim().toLowerCase();
    const v = line.slice(i + 1).trim();
    if (headers[k] === undefined) headers[k] = v;
    else if (Array.isArray(headers[k])) headers[k].push(v);
    else headers[k] = [headers[k], v];
  }
  return { statusLine, headers };
}

// runCurl(bin, args, timeoutMs) -> { code, stdout, stderr } | { error } | timeout.
// curl's own --max-time fires first; the watchdog (timeoutMs + 1s) kills stragglers.
// Never throws: spawn ENOENT/EPERM resolve as { error }.
function runCurl(bin, args, timeoutMs) {
  return new Promise((resolve) => {
    let child;
    try { child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true }); }
    catch (e) { return resolve({ error: String((e && e.message) || e) }); }
    const out = [], err = [];
    let timedOut = false, settled = false;
    const done = (r) => { if (!settled) { settled = true; clearTimeout(timer); resolve(r); } };
    const timer = setTimeout(() => { timedOut = true; try { child.kill(); } catch {} }, timeoutMs + 1000);
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', (e) => done({ error: (e && e.code) || String((e && e.message) || e) }));
    child.on('close', (code) => done({ code, timedOut, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') }));
  });
}

// fetchImpersonated(url, { binary, proxy, timeoutMs, headers }) -> on success
//   { supported:true, status, headers, body, parity, honestNote }
// where parity is the browser id from the binary name ('chrome'|'firefox'|null) and
// honestNote is HONEST_NOTE verbatim. On any failure: { supported:false, reason, ... }
// with `install` attached when the cause is a missing binary. NEVER throws on live
// paths; TypeError from buildArgs (a caller bug) still propagates.
export async function fetchImpersonated(url, { binary, proxy, timeoutMs = 20000, headers = {} } = {}) {
  let bin = binary ? String(binary) : null;
  let browser = bin ? browserFromName(bin) : null;
  if (!bin) {
    const d = detectImpersonate();
    if (!d.available) {
      return { supported: false, reason: 'no curl-impersonate binary available -- ' + UPSTREAM_TRUTH + '; build from source or run under WSL/Docker, then point CURL_IMPERSONATE at it', install: INSTALL_CMD };
    }
    bin = d.path;
    browser = d.browser;
  } else if (!fs.existsSync(bin)) {
    return { supported: false, reason: 'curl-impersonate binary not found at ' + bin + ' -- ' + UPSTREAM_TRUTH, install: INSTALL_CMD };
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'varvel-imp-'));
  const bodyPath = path.join(dir, 'body.bin');
  const headerPath = path.join(dir, 'headers.txt');
  const args = buildArgs(url, { proxy, timeoutMs, headers, bodyPath, headerPath }); // throws TypeError on caller bugs only
  try {
    const r = await runCurl(bin, args, timeoutMs);
    if (r.error) {
      const missing = r.error === 'ENOENT';
      const out = { supported: false, reason: 'curl-impersonate at ' + bin + (missing ? ' is not launchable (ENOENT -- missing or not an executable)' : ' failed to launch: ' + r.error) };
      if (missing) out.install = INSTALL_CMD;
      return out;
    }
    if (r.timedOut) return { supported: false, reason: 'curl-impersonate timed out after ' + timeoutMs + 'ms fetching ' + url, timeout: true };
    if (r.code !== 0) {
      const line = (r.stderr || '').trim().split(/\r?\n/).find(Boolean) || 'no stderr';
      return { supported: false, reason: 'curl-impersonate exited ' + r.code + ' (' + line + ')', exit: r.code };
    }
    const status = Number((r.stdout || '').trim());
    if (!Number.isInteger(status) || status < 100 || status > 999) {
      return { supported: false, reason: 'curl-impersonate exited 0 but printed an unparsable status ' + JSON.stringify((r.stdout || '').trim()) + ' -- refusing to guess' };
    }
    const head = parseHeaderDump(fs.existsSync(headerPath) ? fs.readFileSync(headerPath, 'utf8') : '');
    const body = fs.existsSync(bodyPath) ? fs.readFileSync(bodyPath, 'utf8') : '';
    return { supported: true, status, headers: head.headers, body, parity: browser, honestNote: HONEST_NOTE };
  } catch (e) {
    return { supported: false, reason: 'impersonated fetch failed: ' + String((e && e.message) || e) };
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* temp cleanup is best-effort */ }
  }
}
