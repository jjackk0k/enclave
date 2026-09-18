// VARVEL — soft-404 baselining (the noise-flood killer).
//
// SPA apps answer HTTP 200 + the login shell for ANY unknown path, so a status-only
// (or even status+length) check on a sensitive-path probe files a fake "exposed"
// finding on every catch-all app. The fix is a per-web-base BASELINE fingerprint:
// probe 2-3 random garbage paths (/varvel-<rand>-<rand>) that cannot exist, fingerprint
// the responses (status + length bucket + 64-bit simhash of the normalized body text),
// and any later probe response matching that fingerprint is the fallback, NOT a
// finding — logged honestly as a soft404.match, never silently dropped.
//
// Pure functions, no I/O — the tools (webscan/vulncheck) fetch and pass responses in.

// 64-bit FNV-1a over a string, returned as a BigInt.
function fnv1a64(s) {
  let h = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  const mask = 0xffffffffffffffffn;
  for (let i = 0; i < s.length; i++) {
    h ^= BigInt(s.charCodeAt(i) & 0xff);
    h = (h * prime) & mask;
  }
  return h;
}

// Normalize a body into stable word tokens: tags collapse to their names, runs of
// whitespace/punctuation separate tokens, everything lowercased. The SPA shell's text
// shape is what we fingerprint — not its exact bytes (nonces/timestamps may vary).
function tokens(body) {
  const t = String(body || '').toLowerCase()
    .replace(/<script[\s\S]*?<\/script>/g, ' <script> ')   // script bodies vary (bundles); the tag shape stays
    .replace(/<style[\s\S]*?<\/style>/g, ' <style> ')
    .replace(/<!--[\s\S]*?-->/g, ' ');
  return t.split(/[^a-z0-9<>/._-]+/).filter((w) => w.length > 1).slice(0, 4096);
}

// 64-bit simhash over the normalized token stream.
export function simhash64(body) {
  const bits = new Array(64).fill(0);
  const counts = new Map();
  for (const w of tokens(body)) counts.set(w, (counts.get(w) || 0) + 1);
  for (const [w, n] of counts) {
    const h = fnv1a64(w);
    for (let i = 0; i < 64; i++) bits[i] += ((h >> BigInt(i)) & 1n) ? n : -n;
  }
  let out = 0n;
  for (let i = 0; i < 64; i++) if (bits[i] > 0) out |= (1n << BigInt(i));
  return out;
}

export function hamming64(a, b) {
  let x = a ^ b, n = 0;
  while (x) { n += Number(x & 1n); x >>= 1n; }
  return n;
}

// Length bucket: powers of two, so a 7.6KB shell and a 7.9KB shell share a bucket
// while a 200-byte artifact does not.
export function lenBucket(len) {
  const n = Math.max(0, Number(len) || 0);
  if (n < 256) return 0;
  return Math.floor(Math.log2(n));
}

// Fingerprint one raw response { status, len?, body }.
export function fingerprint(r) {
  const len = r && (typeof r.len === 'number' ? r.len : (r.body ? r.body.length : 0));
  return { status: r && r.status, len: len || 0, lenBucket: lenBucket(len), hash: simhash64(r && r.body) };
}

// Build a baseline from garbage-path responses. `soft` only when at least two junk
// probes answered 2xx — one random hit proves nothing.
export function makeBaseline(responses) {
  const rs = (responses || []).filter(Boolean);
  if (rs.length < 2 || !rs.every((r) => r.status >= 200 && r.status < 300)) return { soft: false, probes: rs.length, status: rs.length ? rs[0].status : null };
  const fps = rs.map(fingerprint);
  return {
    soft: true,
    probes: rs.length,
    status: fps[0].status,
    len: fps[0].len,
    lenBucket: fps[0].lenBucket,
    hashes: fps.map((f) => f.hash),
  };
}

// A probe response matches the baseline when the status matches AND the body is the
// same page: simhash-close to ANY baseline hash (≤10 of 64 bits) or same length bucket
// with length within 10%/48B (the fallback for near-empty bodies).
export function matchesBaseline(r, bl, { threshold = 10 } = {}) {
  if (!bl || !bl.soft || !r || r.status !== bl.status) return false;
  const fp = fingerprint(r);
  const close = (bl.hashes || []).some((h) => hamming64(fp.hash, h) <= threshold);
  if (close) return true;
  return fp.lenBucket === bl.lenBucket && Math.abs(fp.len - (bl.len || 0)) <= Math.max(48, (bl.len || 0) * 0.1);
}
