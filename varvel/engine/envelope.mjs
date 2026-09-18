// VARVEL — per-hop ENVELOPE ENCRYPTION for the governed wire (the 'multi-layer
// encryption, per-hop re-encryption' stealth item). PURE module: node:crypto only,
// no I/O — the wire integration lives in engine/callback.mjs (shared intake) and the
// agent-side transports (agents/dns-client, stg-client, ghc2-client, pipeendpoint,
// sim-agent).
//
// THE GAP THIS CLOSES: the governed envelopes ({a,s,h} pull / {a,s,h,t,k,i,n,d} push)
// were HMAC-authenticated but CLEARTEXT — and on the pivot mesh (engine/pipelink) a
// relay parent could READ every task/result payload it forwarded. A compromised parent
// was content exposure. With this layer the CONTENT is AEAD-sealed end-to-end
// child↔listener; the relay parent forwards OPAQUE CIPHERTEXT (its pipe link layer,
// keyed from the link-scoped verify key, still decrypts/re-encrypts per hop AROUND the
// envelope — true per-hop re-encryption with the envelope opaque through it).
//
// CIPHER: chacha20-poly1305 (native in node:crypto on every supported Node — verified;
// no fallback needed). AEAD = confidentiality + integrity in one primitive.
//
// KEY HIERARCHY (HKDF info separation):
//   encKey = HKDF-SHA256(ikm = agentToken, salt = 'varvel-envelope-v1',
//                        info = 'varvel-env:' + agentId, 32 bytes)
//   · The LISTENER derives it from the STORED credential (agents.get(id).token).
//   · The AGENT derives it from its own token (issued at enrollment).
//   · A relay PARENT has NEITHER: it holds only verifyKey = HMAC(token,
//     'varvel-link:'+linkId) and the per-session link keys HMAC(verifyKey, ...). HMAC
//     is one-way (the token is unreachable from the verify key) and the HKDF info
//     domains are disjoint ('varvel-link:' vs 'varvel-env:'), so no derivation path
//     exists from anything the parent holds to the envelope key. The tests prove it:
//     a parent-side open with every link-domain key it holds FAILS.
//
// SEAL/MAC ORDER — ENCRYPT-THEN-MAC, deliberately: the existing HMAC envelope
// discipline is UNCHANGED and now authenticates the CIPHERTEXT (the push HMAC covers
// `d`, which is the sealed blob; the http /r HMAC covers sha256 of the sealed body).
// The receiver verifies the HMAC BEFORE any decryption runs, so a forgery never
// reaches the AEAD layer — no decryption oracle. MAC-then-seal would decrypt-then-
// verify (oracle-prone) and would force HMAC-formula changes for zero gain.
//   · UP direction (agent→listener): HMAC over ciphertext, exactly as today.
//   · DOWN direction (listener→agent): the task reply had NO MAC at all before (the
//     agent just parsed whatever came back). The AEAD tag now provides BOTH secrecy
//     and authentication there — the down direction GAINS tamper-evidence it never had
//     (a tampered sealed reply fails open() with a typed EnvelopeError, loudly).
//
// NONCE DISCIPLINE: a fresh random 12-byte nonce per seal, prepended to the blob.
// Replay/ordering stays entirely at the HMAC layer's per-agent strictly-increasing
// seq — the AEAD layer deliberately carries NO sequence state of its own (no
// double-counting), so replay protection is key-rotation-safe: re-deriving or
// rotating keys never resets a cipher-level counter that a replayed blob could
// desync; the seq gate decides, exactly as before.
//
// WIRE SHAPES:
//   · Binary blob:  'VE' || 0x01 || nonce(12) || ciphertext || tag(16)  — self-
//     describing (isSealedBytes), base64'd into the push chunk field `d` or carried
//     raw as the http /r body.
//   · Sealed string: 'enc1:' + base64url(blob) — for the codec wires' reply STRINGS
//     (the /d body, the ws frame, the smb down payload, the ghc down-comment, the stg
//     embedded payload) and the sealed http /c body. The empty reply '' (idle/deny,
//     the 204-uniform doctrine) is NEVER sealed — denial stays indistinguishable.
//
// MODES (engine/settings 'enc.mode', or the CallbackChannel `enc` constructor option):
//   off       — the layer is disabled: plaintext flows as before; sealed CONTENT is
//               refused loudly ('enc-disabled').
//   preferred — (default, the backward-compat mode) plaintext agents keep working;
//               an agent proves capability via the `ec:1` envelope flag (or simply by
//               a sealed chunk that opens) and its record ratchets enc:true — from
//               then on its replies are sealed and PLAINTEXT CONTENT from it is
//               refused as a downgrade ('enc-downgrade'). Ratchet only moves up.
//   required  — plaintext is refused loudly ('enc-required'): unsealed content AND
//               capability-less pulls alike. The wire answer stays 204-uniform — the
//               ledger is the loud place, exactly like every other refusal here.
export const ENV_VERSION = 1;
export const ENV_MAGIC = Buffer.from([0x56, 0x45, ENV_VERSION]); // 'VE' + version byte
export const ENV_PREFIX = 'enc1:';
export const ENC_MODES = Object.freeze(['off', 'preferred', 'required']);

import { createCipheriv, createDecipheriv, randomBytes, hkdfSync } from 'node:crypto';

const KEY_LEN = 32;
const NONCE_LEN = 12;   // chacha20-poly1305 nonce
const TAG_LEN = 16;     // poly1305 tag
const KEY_SALT = 'varvel-envelope-v1'; // HKDF salt (domain pin, not a secret)
const KEY_INFO = 'varvel-env:';        // HKDF info prefix — DISJOINT from 'varvel-link:'

// Typed failure — callers catch EnvelopeError, audit e.code, and fail closed. Codes:
// 'key' (derivation inputs), 'shape' (malformed blob/string), 'open' (tag mismatch —
// tamper or wrong key), 'mode' (bad enc.mode value), 'seal' (seal inputs).
export class EnvelopeError extends Error {
  constructor(message, code = 'open') {
    super(message);
    this.name = 'EnvelopeError';
    this.code = code;
  }
}

// Validate an enc.mode value ('off' | 'preferred' | 'required'). Throws on garbage —
// a misspelled mode must never silently disable encryption policy.
export function normalizeEncMode(v) {
  const s = String(v == null ? '' : v).trim().toLowerCase();
  if (!ENC_MODES.includes(s)) throw new EnvelopeError('enc.mode must be one of ' + ENC_MODES.join(', ') + ' (got ' + String(v) + ')', 'mode');
  return s;
}

// The envelope key: HKDF-SHA256 keyed by the agent TOKEN, info-separated per agent id.
// One-way: envelopes carry only nonce||ct||tag — no token material is recoverable from
// them, and no link-domain key (the parent's verify/session keys) derives this.
export function deriveEncKey(token, agentId) {
  if (typeof token !== 'string' || !token) throw new EnvelopeError('deriveEncKey: token required', 'key');
  if (typeof agentId !== 'string' || !agentId) throw new EnvelopeError('deriveEncKey: agent id required', 'key');
  return Buffer.from(hkdfSync('sha256', token, KEY_SALT, KEY_INFO + agentId, KEY_LEN));
}

// Self-description check on DECODED content bytes (a push chunk / an http /r body).
export function isSealedBytes(buf) {
  return Buffer.isBuffer(buf) && buf.length >= ENV_MAGIC.length + NONCE_LEN + TAG_LEN && buf.subarray(0, ENV_MAGIC.length).equals(ENV_MAGIC);
}

// AEAD-seal plaintext bytes. Random 12B nonce per call; output = MAGIC||nonce||ct||tag.
export function sealBytes(key, plaintext) {
  if (!Buffer.isBuffer(key) || key.length !== KEY_LEN) throw new EnvelopeError('sealBytes: a 32-byte encKey is required (deriveEncKey)', 'seal');
  const pt = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext ?? ''), 'utf8');
  const nonce = randomBytes(NONCE_LEN);
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: TAG_LEN });
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  return Buffer.concat([ENV_MAGIC, nonce, ct, cipher.getAuthTag()]);
}

// AEAD-open a sealed blob. Throws EnvelopeError: 'shape' on a malformed blob, 'open'
// on a tag mismatch (tamper / wrong key) — the caller audits and fails closed; NO
// plaintext or partial detail ever leaves this function on failure (no oracle).
export function openBytes(key, blob) {
  if (!Buffer.isBuffer(key) || key.length !== KEY_LEN) throw new EnvelopeError('openBytes: a 32-byte encKey is required (deriveEncKey)', 'key');
  if (!Buffer.isBuffer(blob) || !isSealedBytes(blob)) throw new EnvelopeError('openBytes: not a sealed envelope blob', 'shape');
  const nonce = blob.subarray(ENV_MAGIC.length, ENV_MAGIC.length + NONCE_LEN);
  const tag = blob.subarray(blob.length - TAG_LEN);
  const ct = blob.subarray(ENV_MAGIC.length + NONCE_LEN, blob.length - TAG_LEN);
  try {
    const d = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: TAG_LEN });
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]);
  } catch {
    throw new EnvelopeError('envelope open failed (tamper or wrong key)', 'open');
  }
}

// ——— sealed STRING form (the codec wires' reply strings + sealed http bodies) ———
export function isSealedString(s) {
  return typeof s === 'string' && s.startsWith(ENV_PREFIX);
}

export function sealString(key, str) {
  return ENV_PREFIX + sealBytes(key, Buffer.from(String(str ?? ''), 'utf8')).toString('base64url');
}

export function openString(key, str) {
  if (!isSealedString(str)) throw new EnvelopeError('openString: not a sealed envelope string', 'shape');
  const blob = Buffer.from(str.slice(ENV_PREFIX.length), 'base64url');
  return openBytes(key, blob).toString('utf8');
}
