// VARVEL — structured parameter fuzzer (the Burp-grade slot, honest edition).
//
// Web attack depth, native. Given an endpoint with a {FUZZ} placeholder, fire a small
// METHODICAL payload set (not a wordlist storm) and read the target's responses against
// TWO references: a baseline (ordinary value) and a control (a value that should behave
// like the baseline). What makes a finding: a crash-class response (5xx/error text the
// baseline doesn't produce) or a STRONG differential vs both references. "Maybe" is
// not reported — every finding carries the exact evidence.
//
// Payloads are DETECTION classes, not exploitation strings: type confusions, boundary
// numbers, format-string probes (%x — the classic info-leak DETECTOR), error-triggering
// quotes and traversal tokens. We observe; we do not exfiltrate.
//
// Budget-capped, stealth-pacer honored, adaptive back-off, same-origin enforced.

import http from 'node:http';
import https from 'node:https';
import { makePacer, asPacer } from '../engine/stealth.mjs';

const BODY_CAP = 128 * 1024;

// The methodical set: each [id, value, class]. Detection-shaped, never destructive.
export const FUZZ_VALUES = [
  { id: 'int-zero',    value: '0',                  class: 'type-numeric' },
  { id: 'int-neg',     value: '-1',                 class: 'type-numeric' },
  { id: 'int-max',     value: '2147483647',         class: 'type-numeric' },
  { id: 'int-over',    value: '99999999999999999999', class: 'type-numeric' },
  { id: 'str-long',    value: 'A'.repeat(512),      class: 'type-string' },
  { id: 'str-empty',   value: '',                   class: 'type-string' },
  { id: 'str-quote',   value: "'",                  class: 'error-trigger' },
  { id: 'str-dquote',  value: '"',                  class: 'error-trigger' },
  { id: 'fmt-x',       value: '%x%x%x',             class: 'format-string' },
  { id: 'fmt-s',       value: '%s%s%s%s',           class: 'format-string' },
  { id: 'trav-basic',  value: '../../../../etc/passwd', class: 'traversal-detect' },
  { id: 'trav-enc',    value: '..%2f..%2fetc%2fpasswd', class: 'traversal-detect' },
  { id: 'bool-true',   value: 'true',               class: 'type-confuse' },
  { id: 'arr-json',    value: '[]',                 class: 'type-confuse' },
  { id: 'obj-json',    value: '{}',                 class: 'type-confuse' },
  { id: 'null-lit',    value: 'null',               class: 'type-confuse' },
];

const ERROR_RE = /(stack trace|traceback|exception|error in your SQL|ORA-\d{4,5}|PostgreSQL.*ERROR|warning.*on line|format string|%!x|0x[0-9a-f]{8,})/i;

function raw(u, { timeout = 1500, hdrs, agents } = {}) {
  return new Promise((resolve) => {
    const lib = u.protocol === 'https:' ? https : http;
    let text = '', settled = false;
    const done = (v) => { if (settled) return; settled = true; clearTimeout(deadline); resolve(v); };
    const req = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method: 'GET', timeout, rejectUnauthorized: false,
      agent: agents ? (u.protocol === 'https:' ? agents.httpsAgent : agents.httpAgent) : undefined,
      headers: hdrs || { 'user-agent': 'VARVEL-fuzz', accept: '*/*' },
    }, (r) => {
      r.on('data', (d) => {
        if (settled) return;
        if (text.length < BODY_CAP) text += d.toString('utf8', 0, Math.max(0, BODY_CAP - text.length));
        if (text.length >= BODY_CAP) { done({ status: r.statusCode, body: text }); try { req.destroy(); } catch {} }
      });
      r.on('end', () => done({ status: r.statusCode, body: text }));
    });
    const deadline = setTimeout(() => { try { req.destroy(); } catch {} done(null); }, Math.max(timeout * 3, 3000));
    req.on('timeout', () => { try { req.destroy(); } catch {} done(null); });
    req.on('error', () => done(null));
    req.end();
  });
}

const sigOf = (r) => (r ? { status: r.status, len: r.body.length, err: ERROR_RE.test(r.body) } : null);

// endpoint: full URL with the {FUZZ} placeholder where the value goes.
export async function fuzz(endpoint, { values = FUZZ_VALUES, timeout = 1500, maxProbes = 24, stealth, pacer, agents = null } = {}) {
  if (!/\{FUZZ\}/.test(String(endpoint || ''))) throw new TypeError('fuzz: endpoint must contain the {FUZZ} placeholder');
  let origin;
  try { origin = new URL(String(endpoint).replace('{FUZZ}', 'x')).origin; } catch { throw new TypeError('fuzz: bad endpoint URL'); }

  pacer = asPacer(pacer) || (stealth ? makePacer(stealth) : null);
  const budget = Math.max(4, Math.floor(maxProbes) || 24);
  let used = 0;
  const fire = async (value) => {
    if (used >= budget) return null;
    let u;
    try { u = new URL(String(endpoint).replace('{FUZZ}', encodeURIComponent(value))); } catch { return null; }
    if (u.origin !== origin) return null; // same-origin, always
    used++;
    if (pacer) await pacer.pace();
    const r = await raw(u, { timeout, hdrs: pacer && pacer.requestHeaders ? pacer.requestHeaders({ accept: '*/*' }) : undefined, agents });
    if (pacer && r && (r.status === 429 || r.status === 503)) pacer.penalize(2, 0);
    return r;
  };

  // Baseline (an ordinary value) + control (another ordinary value) — honesty anchors.
  const baseline = sigOf(await fire('1'));
  const control = sigOf(await fire('2'));
  const findings = [];

  for (const v of values) {
    if (used >= budget) break;
    const r = await fire(v.value);
    if (!r) continue;
    const s = sigOf(r);
    // WAF block is a finding about the DEFENDER, labeled honestly as such.
    if (r.status === 403 && baseline && baseline.status !== 403) {
      findings.push({ id: v.id, value: v.value.slice(0, 24), kind: 'waf-block', sev: 'info', evidence: `payload class ${v.class} is WAF-blocked (403; baseline is ${baseline.status})`, confidence: 'firm' });
      continue;
    }
    // Crash class: 5xx or an error signature the references don't show.
    const crash = r.status >= 500 || (s.err && !(baseline && baseline.err));
    if (crash) {
      const ev = r.status >= 500 ? `HTTP ${r.status} (baseline ${baseline && baseline.status}, control ${control && control.status})` : 'error text: ' + (r.body.match(ERROR_RE) || [''])[0].slice(0, 60);
      findings.push({ id: v.id, value: v.value.slice(0, 24), kind: 'crash-class', sev: 'medium', evidence: `${v.class}: ${ev}`, confidence: 'firm' });
      continue;
    }
    // Strong differential vs BOTH references (not just noise).
    if (baseline && control && baseline.status === control.status) {
      const statusDiff = r.status !== baseline.status;
      const sizeDiff = Math.abs(r.body.length - baseline.len) > Math.max(300, baseline.len * 0.4) && Math.abs(r.body.length - control.len) > Math.max(300, control.len * 0.4);
      if (statusDiff || sizeDiff) {
        findings.push({ id: v.id, value: v.value.slice(0, 24), kind: 'differential', sev: 'low', evidence: `${v.class}: probe ${r.status}/${r.body.length}b vs references ${baseline.status}/${baseline.len}b`, confidence: 'firm' });
      }
    }
  }

  return {
    endpoint: origin + new URL(String(endpoint).replace('{FUZZ}', 'x')).pathname,
    probed: used - 2, // minus baseline + control
    findings: findings.sort((a, b) => ({ medium: 2, low: 1, info: 0 }[b.sev] - { medium: 2, low: 1, info: 0 }[a.sev])),
    requests: used,
    stealth: pacer ? pacer.profile.label : null,
  };
}

// ---------------------------------------------------------------------------
// CODEC FUZZ HARNESS (the zero-day pipeline's fuzz tier — alongside the network
// fuzzer above, which stays untouched). Mutation-fuzz a PURE decode/parse function
// through engine/fuzzseed.mjs. The honest first use is OURSELVES: the registry below
// is VARVEL's own wire codecs, the parsers that face an untrusted peer on every
// transport. A crash here is a real robustness finding in our own attack surface.
//
// HOUSE RULE: found-case corpus artifacts (minimized repros — payload-carrying bytes)
// persist under repo-local varvel/.tmp/fuzz-corpus/<target>/ — NEVER os.tmpdir().
// Tool contract holds: never throws; a bad target name or a harness failure is a
// structured { error }, not an exception.

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runFuzz } from '../engine/fuzzseed.mjs';

// Each target: load() the module, then build { fn, expectedErrors, seeds, dictionary }.
// fn closes over per-case parser STATE (a streaming parser is fresh per case — feeding
// one mutated stream into a reused parser would fuzz parser state, not the frame
// grammar). Seeds are VALID exemplars the mutations degrade.
export const CODEC_TARGETS = {
  stegocodec: {
    describe: 'engine/stegocodec decodeStgPng (PNG chunks + LSB frame)',
    build: async () => {
      const m = await import('../engine/stegocodec.mjs');
      const seeds = [
        m.encodeStgPng('{"t":"task","id":"a1"}', { seed: 7 }),
        m.encodeStgPng('', { seed: 8, profile: 'flat' }),
        m.encodeStgPng('x'.repeat(400), { seed: 9, profile: 'noise' }),
      ];
      const dictionary = [Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from('IHDR'), Buffer.from('IDAT'), Buffer.from('IEND'), Buffer.from('SG')];
      return { fn: (buf) => m.decodeStgPng(buf), expectedErrors: [m.StegError], seeds, dictionary };
    },
  },
  dnscodec: {
    describe: 'engine/dnscodec decodeQuery (b32 label chain -> JSON)',
    build: async () => {
      const m = await import('../engine/dnscodec.mjs');
      const seeds = [
        m.encodeQuery({ a: 'agent-1', s: 1, h: 'ab'.repeat(32) }),
        m.encodeQuery({ a: 'agent-2', s: 14, h: 'cd'.repeat(32), t: 'r', k: 'k', i: 10, n: 15, d: 'x'.repeat(300) }),
        'plain-not-a-query.ax.sim',
      ];
      const dictionary = [Buffer.from('.ax.sim'), Buffer.from('.'), Buffer.from('0123456789abcdefghijklmnopqrstuv')];
      return {
        fn: (buf) => m.decodeQuery(buf.toString('utf8')),
        expectedErrors: [], // contract: null on anything malformed — ANY throw is a finding
        validate: (out) => { if (out !== null && (typeof out !== 'object')) throw new Error('decodeQuery returned a non-object/non-null: ' + typeof out); },
        seeds,
        dictionary,
      };
    },
  },
  wsframe: {
    describe: 'engine/wsframe WsParser.feed (RFC 6455 streaming frames)',
    build: async () => {
      const m = await import('../engine/wsframe.mjs');
      const seeds = [
        m.buildFrame({ opcode: m.OP_TEXT, payload: '{"t":"ping"}' }),
        m.buildFrame({ opcode: m.OP_BINARY, payload: Buffer.alloc(300, 0x41), mask: true }),
        Buffer.concat([m.buildFrame({ opcode: m.OP_TEXT, payload: 'frag1', fin: false }), m.buildFrame({ opcode: m.OP_CONT, payload: 'frag2' })]),
        Buffer.concat([m.buildFrame({ opcode: m.OP_PING, payload: 'hb' }), m.buildFrame({ opcode: m.OP_TEXT, payload: 'after-ping' })]),
      ];
      const dictionary = [Buffer.from([0x81]), Buffer.from([0x82]), Buffer.from([0x88]), Buffer.from([0x7f]), Buffer.from([0x7e]), Buffer.from([0xff, 0xff])];
      return { fn: (buf) => new m.WsParser().feed(buf), expectedErrors: [m.WsError], seeds, dictionary };
    },
  },
  pipelink: {
    describe: 'engine/pipelink FrameParser.feed (u32le length-prefixed JSON frames)',
    build: async () => {
      const m = await import('../engine/pipelink.mjs');
      const seeds = [
        m.encodeFrame({ t: 'hello', v: 1, link: 'link01', a: 'agent-1', n: 'ab'.repeat(8), h: 'cd'.repeat(32) }),
        m.encodeFrame({ t: 'up', v: 1, s: 1, m: 'ef'.repeat(32), p: { a: 'agent-1', s: 1, h: '00'.repeat(32) } }),
        Buffer.concat([m.encodeFrame({ t: 'bye', v: 1, s: 2, m: '11'.repeat(32), p: 'done' }), m.encodeFrame({ t: 'down', v: 1, s: 1, m: '22'.repeat(32), p: '' })]),
      ];
      const dictionary = [Buffer.from([0xff, 0xff, 0xff, 0xff]), Buffer.from([0x00, 0x00, 0x00, 0x00]), Buffer.from('{"t":"'), Buffer.from('}{')];
      return { fn: (buf) => new m.FrameParser().feed(buf), expectedErrors: [m.PipeLinkError], seeds, dictionary };
    },
  },
};

const CORPUS_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp', 'fuzz-corpus');

// fuzzCodec('stegocodec', { seed, count, ... }) → JSON-safe report. Findings carry
// minimized repros as hex AND are persisted to .tmp/fuzz-corpus/<target>/ (house rule).
export async function fuzzCodec(targetName, { seed = 1, count = 500, maxLen = 8192, slowMs = 250, persist = true, corpusDir = CORPUS_ROOT } = {}) {
  const spec = CODEC_TARGETS[String(targetName || '')];
  if (!spec) return { error: `unknown codec target '${targetName}' — known: ${Object.keys(CODEC_TARGETS).join(', ')}` };
  try {
    const { fn, expectedErrors, seeds, dictionary, validate } = await spec.build();
    const r = runFuzz(fn, { seeds, dictionary, expectedErrors, validate, seed, count, maxLen, slowMs });
    const findings = r.findings.map((f) => ({
      kind: f.kind, index: f.index, strategy: f.strategy,
      errorName: f.errorName, errorMessage: f.errorMessage,
      inputHex: f.input.toString('hex').slice(0, 512),
      ...(f.minimized ? { minimizedHex: f.minimized.toString('hex'), originalLength: f.originalLength, minimizedLength: f.minimizedLength } : {}),
      ...(f.ms != null ? { ms: f.ms, note: f.note } : {}),
    }));
    let persisted = null;
    if (persist && r.crashed) {
      // Payload-class artifacts → repo-local .tmp ONLY (gitignored, Defender-excluded).
      const dir = join(corpusDir, String(targetName));
      mkdirSync(dir, { recursive: true });
      persisted = [];
      for (const f of r.findings) {
        if (!f.kind.startsWith('crash') && f.kind !== 'invariant') continue;
        const file = join(dir, `case-${f.index}-${f.kind.replace(/[^\w-]/g, '_')}.bin`);
        writeFileSync(file, f.minimized || f.input);
        persisted.push(file);
      }
    }
    return {
      target: targetName, describe: spec.describe,
      seed: r.seed, casesRun: r.casesRun, cleanAccepts: r.cleanAccepts, cleanRejects: r.cleanRejects,
      crashed: r.crashed, findings, corpus: persisted,
      note: r.note,
    };
  } catch (e) {
    return { target: targetName, error: 'harness failed: ' + ((e && e.message) || e) };
  }
}
