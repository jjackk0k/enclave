// VARVEL — native OS fingerprinting (the `nmap -O` slot).
//
// Correlates every OS signal pure Node can actually observe, confidence-weighted and
// honest about its ceiling. Material reviewed: HYDRA OsFingerprinter (TCP stack TTL /
// window / DF / options-ordering + SMB negotiate + banner grab). The honest difference:
// raw-socket signals (TTL/window/options from the SYN-ACK) are NOT observable from Node —
// so this tool reports only signals it can verify, each labeled, and never claims the
// nmap-style packet-level certainty it cannot see. What it can see is strong:
//
//   SMB dialect   — the single best Windows signal: one SMB2 NEGOTIATE (rides smbenum)
//                   pins the OS to a version band. 55 weight.
//   SSH banner    — OpenSSH version strings frequently carry the distro tag
//                   ("OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" → Ubuntu 22.04). 35 weight.
//   TTL estimate  — ICMP echo reply TTL → family only (128 Windows, 64 Linux/Unix,
//                   255 network device). Optional, via the OS ping (1 packet, parsed,
//                   failure tolerated). 25 weight, family-level only.
//   HTTP Server   — IIS versions pin Windows bands; distro-tagged Apache pins Linux. 15.
//   FTP/SMTP      — "Microsoft FTP Service" etc. 15.
//
// Correlation: agreeing weights sum; a family CONFLICT between signals halves the total
// and is reported as a caveat (never silently averaged). Confidence caps at 95 — remote
// inference is never certain. Non-destructive: TCP connects + banner reads + ≤1 ICMP.
// Stealth: ≈4 connections + 1 ping, quieter than `nmap -O` (which sends ~16 probes).
// Noise kind 'os-fingerprint' (loudness 2). Hermetic: every signal is injectable.

import net from 'node:net';
import { execFile } from 'node:child_process';
import { smbNegotiate } from './smbenum.mjs';

export const SIGNAL_WEIGHTS = { smb: 55, ssh: 35, ttl: 25, http: 15, 'ftp/smtp': 15 };
const CONFIDENCE_CAP = 95;

// SMB dialect revision → Windows version band (MS-SMB2 + observed server behavior).
const DIALECT_OS = {
  0x0202: 'Windows Vista / Server 2008',
  0x0210: 'Windows 7 / Server 2008 R2',
  0x0300: 'Windows 8 / Server 2012',
  0x0302: 'Windows 8.1 / Server 2012 R2 or later (answered at the client dialect ceiling)',
  0x0311: 'Windows 10/11 / Server 2016+',
};

// ---- individual signals (each returns { ok, family?, version?, evidence } ) ----

async function smbSignal(host, { timeout, smbImpl }) {
  const fn = smbImpl || smbNegotiate;
  try {
    const r = await fn(host, { timeout });
    if (!r || r.dialectRevision == null) return { ok: false, reason: 'no SMB negotiate response' };
    const rev = typeof r.dialectRevision === 'string' ? parseInt(r.dialectRevision, 16) : r.dialectRevision;
    return {
      ok: true, family: 'windows',
      version: DIALECT_OS[rev] || `Windows (SMB dialect 0x${rev.toString(16)})`,
      evidence: `SMB negotiate: dialect 0x${rev.toString(16)}${r.signingRequired ? ', signing required' : ''}`,
    };
  } catch (e) { return { ok: false, reason: `smb: ${e.message}` }; }
}

function parseSshBanner(line) {
  // e.g. SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6 / SSH-2.0-OpenSSH_for_Windows_8.1
  const m = /^SSH-[\d.]+-(.+)$/.exec(line.trim());
  if (!m) return null;
  const id = m[1];
  if (/OpenSSH_for_Windows/i.test(id)) return { family: 'windows', version: id.replace(/^OpenSSH_for_Windows_/, 'Windows (OpenSSH ') + ')' };
  const distro = /(Ubuntu|Debian|Fedora|CentOS|RHEL|Alpine|Arch|FreeBSD|NetBSD)/i.exec(id);
  if (distro) {
    const d = distro[1].toLowerCase();
    if (d === 'freebsd' || d === 'netbsd') return { family: 'unix', version: `${distro[1]} (${id.split(' ')[0]})` };
    let version = `Linux (${distro[1]})`;
    if (/ubuntu/i.test(id)) {
      const v = { '8.9': '22.04', '9.0': '22.10', '9.3': '23.10', '9.6': '24.04', '7.6': '18.04', '8.2': '20.04' }[/OpenSSH_(\d+\.\d+)/.exec(id)?.[1]];
      if (v) version = `Ubuntu ${v.class ? '' : v} (OpenSSH ${/OpenSSH_(\S+)/.exec(id)[1]})`;
    }
    return { family: 'linux', version };
  }
  if (/OpenSSH/i.test(id)) return { family: 'unix', version: `Unix-like (${id.split(' ')[0]})` };
  return null;
}

function parseHttpServer(line) {
  const m = /microsoft-iis\/([\d.]+)/i.exec(line);
  if (m) {
    const band = { '10.0': 'Windows Server 2016+ / Windows 10+', '8.5': 'Windows Server 2012 R2', '8.0': 'Windows Server 2012', '7.5': 'Windows Server 2008 R2' }[m[1]];
    return { family: 'windows', version: band ? `${band} (IIS ${m[1]})` : `Windows (IIS ${m[1]})` };
  }
  const distro = /(?:apache|nginx)\/?[\d.]*\s*\((\w+)\)/i.exec(line);
  if (distro && /ubuntu|debian|centos|fedora|red\s?hat|alpine/i.test(distro[1])) {
    return { family: 'linux', version: `Linux (${distro[1]}, per Server header)` };
  }
  return null;
}

async function bannerSignal(host, { timeout, bannerImpl }) {
  const grab = bannerImpl || defaultBannerGrab;
  try {
    const banners = await grab(host, timeout);
    for (const b of banners) {
      const ssh = b.port === 22 && parseSshBanner(b.text);
      if (ssh) return { ok: true, ...ssh, evidence: `SSH banner: ${b.text.trim().slice(0, 80)}` };
      const http = (b.port === 80 || b.port === 443) && /^Server:/im.test(b.text) && parseHttpServer(/Server:\s*(.+)/i.exec(b.text)?.[1] || '');
      if (http) return { ok: true, ...http, evidence: `HTTP Server header on :${b.port}` };
      if ((b.port === 21 || b.port === 25) && /microsoft/i.test(b.text)) {
        return { ok: true, family: 'windows', version: `Windows (${b.port === 21 ? 'FTP' : 'SMTP'} service)`, evidence: `banner :${b.port}: ${b.text.trim().slice(0, 60)}` };
      }
    }
    return { ok: false, reason: 'banners carried no OS-identifying string' };
  } catch (e) { return { ok: false, reason: `banners: ${e.message}` }; }
}

async function defaultBannerGrab(host, timeout) {
  const out = [];
  const read = (port, send) => new Promise((resolve) => {
    const sock = net.connect({ host, port, timeout: timeout || 2000 });
    let buf = '';
    const done = () => { try { sock.destroy(); } catch {} resolve(buf); };
    sock.on('connect', () => { if (send) sock.write(send); });
    sock.on('data', (d) => { buf += d.toString('latin1'); if (buf.length > 2048) done(); });
    sock.on('timeout', done); sock.on('error', done); sock.on('end', done);
    setTimeout(done, (timeout || 2000) + 500);
  });
  for (const [port, send] of [[22, null], [80, 'HEAD / HTTP/1.0\r\nHost: x\r\n\r\n'], [21, null], [25, null]]) {
    const text = await read(port, send);
    if (text) out.push({ port, text });
  }
  return out;
}

function familyFromTtl(ttl) {
  // Round up to the nearest plausible initial TTL (32/64/128/255).
  const init = [32, 64, 128, 255].find((t) => ttl <= t);
  if (init == null) return null;
  if (init === 128) return { family: 'windows', evidence: `TTL ${ttl} → initial ~128 (Windows)` };
  if (init === 64) return { family: 'linux', evidence: `TTL ${ttl} → initial ~64 (Linux/Unix)` };
  if (init === 255) return { family: 'network-device', evidence: `TTL ${ttl} → initial ~255 (network device/Solaris)` };
  return { family: 'windows', evidence: `TTL ${ttl} → initial ~32 (legacy Windows)` };
}

async function ttlSignal(host, { timeout, execImpl }) {
  const run = execImpl || defaultPing;
  try {
    const ttl = await run(host, timeout);
    if (!ttl) return { ok: false, reason: 'no ICMP echo reply (or unparsable)' };
    const f = familyFromTtl(ttl);
    return f ? { ok: true, ...f } : { ok: false, reason: `implausible TTL ${ttl}` };
  } catch (e) { return { ok: false, reason: `ttl: ${e.message}` }; }
}

function defaultPing(host, timeout = 2000) {
  const win = process.platform === 'win32';
  const args = win ? ['-n', '1', '-w', String(timeout), host] : ['-c', '1', '-W', String(Math.ceil(timeout / 1000)), host];
  return new Promise((resolve) => {
    execFile('ping', args, { windowsHide: true, timeout: timeout + 1500 }, (err, stdout) => {
      const m = /ttl=(\d+)/i.exec(stdout || '');
      resolve(m ? Number(m[1]) : null);
    });
  });
}

// ---- correlation ----

/**
 * Fingerprint a host's OS. Never throws for signal failures — honest degradation.
 * @param {string} host
 * @param {object} [opts] { signals=['smb','ttl','banner'], timeout, smbImpl, execImpl, bannerImpl }
 * @returns {Promise<{host, family, version, confidence, signals: Array, caveats: string[]}>}
 */
export async function osFingerprint(host, opts = {}) {
  if (!host || typeof host !== 'string') throw new Error('osFingerprint: host is required');
  const wanted = opts.signals || ['smb', 'ttl', 'banner'];
  const timeout = opts.timeout ?? 2500;
  const results = [];
  if (wanted.includes('smb')) results.push({ name: 'smb', ...(await smbSignal(host, { timeout, smbImpl: opts.smbImpl })) });
  if (wanted.includes('ttl')) results.push({ name: 'ttl', ...(await ttlSignal(host, { timeout, execImpl: opts.execImpl })) });
  if (wanted.includes('banner')) results.push({ name: 'banner', ...(await bannerSignal(host, { timeout, bannerImpl: opts.bannerImpl })) });

  const good = results.filter((r) => r.ok && r.family);
  const families = new Map();
  for (const r of good) {
    const weightKey = r.name === 'banner' ? (r.evidence?.startsWith('SSH') ? 'ssh' : r.evidence?.startsWith('HTTP') ? 'http' : 'ftp/smtp') : r.name;
    const w = SIGNAL_WEIGHTS[weightKey] ?? 10;
    const cur = families.get(r.family) || { weight: 0, version: null, signals: [] };
    cur.weight += w;
    if (r.version && (!cur.version || w >= (SIGNAL_WEIGHTS[cur.versionFrom] ?? 0))) { cur.version = r.version; cur.versionFrom = weightKey; }
    cur.signals.push(r.name);
    families.set(r.family, cur);
  }

  const caveats = [];
  let family = 'unknown', version = null, confidence = 0;
  if (families.size > 0) {
    const ranked = [...families.entries()].sort((a, b) => b[1].weight - a[1].weight);
    const [winner, info] = ranked[0];
    family = winner; version = info.version; confidence = Math.min(CONFIDENCE_CAP, info.weight);
    if (ranked.length > 1) {
      confidence = Math.floor(confidence / 2);
      caveats.push(`conflicting signals: ${ranked.map(([f, i]) => `${f} (${i.signals.join('+')}, w${i.weight})`).join(' vs ')} — confidence halved, reported as majority vote`);
    }
    if (info.weight < 30) caveats.push('weak evidence — family-level answer only');
  } else {
    caveats.push('no OS signal observable — host may filter all probed services');
  }
  for (const r of results.filter((r) => !r.ok)) caveats.push(`${r.name}: ${r.reason}`);

  return { host, family, version, confidence, signals: results, caveats };
}

export const __internals = { parseSshBanner, parseHttpServer, familyFromTtl, DIALECT_OS };
