// VARVEL — steganography codec (transport 'stg'): governed envelopes inside innocuous PNGs.
//
// The last-resort covert wire: task/result envelopes ride INSIDE ordinary-looking PNG
// images fetched over plain HTTP from the channel listener. The covertness is that the
// content IS the channel — to a watcher each request is an image asset, not an API call.
// This module is the PURE codec half (zero npm deps — node:zlib for deflate, a local
// CRC32): PNG encode/decode + LSB payload framing. The transport attachment lives in
// engine/callback.mjs (routes) and agents/stg-client.mjs (agent leg).
//
// HONESTY CONTRACT (same doctrine as engine/transport-grade): this is a LOW-BANDWIDTH,
// HIGH-LATENCY fallback wire. It claims CONTENT cover only (the bytes on the wire are a
// valid image). It does NOT claim traffic-analysis immunity: image byte size correlates
// with payload length (documented, not padded), and the agent's poll cadence/timing is
// fully visible. Same governance as every wire — the embedded payload is the EXACT
// governed envelope object the dns/ws wires carry (per-agent HMAC, strict seq, kill-list,
// chunk reassembly), fed verbatim into the channel's shared intake (_dnsPayload).
//
// EMBEDDING CHOICE (the brief offered LSB or a tEXt-adjacent ancillary chunk): classic
// LSB of the pixel data. Justification: an ancillary chunk is TRIVIALLY visible — any
// PNG inspector (`pngcheck`, an EDR's file carve, `strings`) lists foreign chunks, so the
// envelope would be a labeled anomaly in an otherwise plain asset. LSB hides in the pixel
// noise floor where nothing structural announces it; our seeded scenes carry per-pixel
// jitter by construction, so modified LSBs are indistinguishable from the scene's own
// grain (a statistical detector is out of scope — see the honesty contract).
//
// WIRE FRAME (embedded MSB-first into the LSB of each successive pixel-stream byte):
//   'SG' (2 magic) | version u8 (0x01) | length u32BE | payload bytes | crc32(payload) u32BE
// Overhead 11 bytes. The payload for the DOWN wire is the channel's reply string (the
// b32 task JSON, EMPTY when idle/denied — an empty-envelope image, so idle vs tasked are
// structurally identical and differ only in size); for the UP wire it is the governed
// envelope JSON object (same shape the ws wire posts). The crc is the stego layer's own
// corruption tripwire — envelope authenticity stays the HMAC's job, one layer up.

import zlib from 'node:zlib';
import { randomBytes } from 'node:crypto';

// Typed failure, always loud: corrupt/foreign input is NEVER decoded into silent garbage.
export class StegError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'StegError';
    this.code = code; // NOT_PNG | TRUNCATED | BAD_CHUNK_CRC | UNSUPPORTED | CORRUPT | NO_PAYLOAD | BAD_LENGTH | PAYLOAD_CRC | CAPACITY
  }
}

// ——— CRC32 (PNG/zlib polynomial 0xEDB88320, reflected) — implemented locally: the PNG
// chunk CRCs and the payload frame CRC both ride this one table.
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
export function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const CHANNELS = { 0: 1, 2: 3, 4: 2, 6: 4 }; // grayscale / RGB / gray+alpha / RGBA (8-bit only)

function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td), 0);
  return Buffer.concat([len, td, crc]);
}

// Minimal valid PNG encoder: 8-bit RGB (color type 2), filter 0 scanlines, zlib deflate.
// That is all a cover scene needs — the DECODER below is the general one.
export function encodePng({ width, height, rgb }) {
  const w = Number(width) | 0, h = Number(height) | 0;
  if (!(w >= 1 && h >= 1)) throw new StegError('BAD_LENGTH', 'encodePng: width/height must be >= 1');
  if (!Buffer.isBuffer(rgb) || rgb.length !== w * h * 3) throw new StegError('BAD_LENGTH', 'encodePng: rgb buffer must be exactly width*height*3 bytes');
  const stride = w * 3;
  const raw = Buffer.alloc((stride + 1) * h);
  for (let y = 0; y < h; y++) {
    raw[y * (stride + 1)] = 0; // filter: none
    rgb.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 2;  // color type: truecolor RGB
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter method
  ihdr[12] = 0; // no interlace
  return Buffer.concat([PNG_SIG, pngChunk('IHDR', ihdr), pngChunk('IDAT', zlib.deflateSync(raw, { level: 9 })), pngChunk('IEND', Buffer.alloc(0))]);
}

// Paeth predictor (PNG spec 6.3).
function paeth(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
  return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
}

// General PNG decoder: any non-interlaced 8-bit grayscale/RGB/gray+alpha/RGBA image,
// all five scanline filters, multiple IDATs. Returns { width, height, channels, pixels }
// where pixels is the raw pixel byte stream the LSB framing rides. Foreign-but-valid
// PNGs decode cleanly here and then fail LOUDLY at the framing layer (NO_PAYLOAD) —
// never silent garbage.
export function decodePng(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 8 || !buf.subarray(0, 8).equals(PNG_SIG)) {
    throw new StegError('NOT_PNG', 'not a PNG: bad 8-byte signature');
  }
  let pos = 8, width = 0, height = 0, bitDepth = 0, colorType = 0, interlace = 0;
  const idats = [];
  let sawIhdr = false, sawIend = false;
  while (pos < buf.length) {
    if (pos + 8 > buf.length) throw new StegError('TRUNCATED', 'chunk header cut off at byte ' + pos);
    const len = buf.readUInt32BE(pos);
    const type = buf.toString('ascii', pos + 4, pos + 8);
    if (pos + 12 + len > buf.length) throw new StegError('TRUNCATED', type + ' chunk (' + len + ' bytes) runs past end of file');
    const data = buf.subarray(pos + 8, pos + 8 + len);
    if (buf.readUInt32BE(pos + 8 + len) !== crc32(buf.subarray(pos + 4, pos + 8 + len))) {
      throw new StegError('BAD_CHUNK_CRC', type + ' chunk CRC mismatch (corrupt image)');
    }
    if (type === 'IHDR') {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      bitDepth = data[8];
      colorType = data[9];
      interlace = data[12];
      sawIhdr = true;
    } else if (type === 'IDAT') {
      idats.push(Buffer.from(data)); // copy: subarray views into a caller buffer must not leak
    } else if (type === 'IEND') {
      sawIend = true;
      break;
    }
    pos += 12 + len;
  }
  if (!sawIhdr) throw new StegError('TRUNCATED', 'no IHDR chunk');
  if (!sawIend) throw new StegError('TRUNCATED', 'no IEND chunk (file cut short)');
  if (bitDepth !== 8) throw new StegError('UNSUPPORTED', 'bit depth ' + bitDepth + ' (only 8-bit images decode)');
  const channels = CHANNELS[colorType];
  if (!channels) throw new StegError('UNSUPPORTED', 'color type ' + colorType + ' (palette/16-bit images are not a stego carrier here)');
  if (interlace !== 0) throw new StegError('UNSUPPORTED', 'interlaced PNG (Adam7) is not a stego carrier here');
  if (!(width >= 1 && height >= 1)) throw new StegError('CORRUPT', 'IHDR declares a zero-sized image');
  const bpp = channels; // 8-bit: bytes per pixel == channel count
  const stride = width * bpp;
  let raw;
  try { raw = zlib.inflateSync(Buffer.concat(idats)); } catch (e) { throw new StegError('CORRUPT', 'IDAT inflate failed: ' + ((e && e.message) || e)); }
  if (raw.length !== (stride + 1) * height) throw new StegError('CORRUPT', 'inflated pixel data is ' + raw.length + ' bytes, expected ' + (stride + 1) * height);
  const pixels = Buffer.alloc(stride * height);
  for (let y = 0; y < height; y++) {
    const filt = raw[y * (stride + 1)];
    const rowIn = y * (stride + 1) + 1;
    const rowOut = y * stride;
    if (filt > 4) throw new StegError('CORRUPT', 'unknown scanline filter ' + filt + ' on row ' + y);
    for (let x = 0; x < stride; x++) {
      const v = raw[rowIn + x];
      const left = x >= bpp ? pixels[rowOut + x - bpp] : 0;
      const up = y > 0 ? pixels[rowOut - stride + x] : 0;
      const upLeft = y > 0 && x >= bpp ? pixels[rowOut - stride + x - bpp] : 0;
      let r;
      if (filt === 0) r = v;
      else if (filt === 1) r = v + left;
      else if (filt === 2) r = v + up;
      else if (filt === 3) r = v + ((left + up) >> 1);
      else r = v + paeth(left, up, upLeft);
      pixels[rowOut + x] = r & 0xff;
    }
  }
  return { width, height, channels, pixels };
}

// ——— Seeded cover scenes ———
// Deterministic given a seed; the DEFAULT seed is fresh randomness per encode, so two
// encodes of the SAME envelope never byte-repeat (the scene is pure cover — the decoder
// only reads LSBs and never needs the seed). stg.profile picks the scene class:
//   'gradient' — smooth two-color diagonal wash + grain   (plausible web "background" asset)
//   'flat'     — one seeded base color + grain            (logo-card / placeholder class)
//   'noise'    — per-pixel grain around a seeded midtone  (photographic-ish texture)
export const STG_PROFILES = ['gradient', 'flat', 'noise'];

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function renderScene({ width, height, profile = 'gradient', seed } = {}) {
  const w = Number(width) | 0, h = Number(height) | 0;
  const p = STG_PROFILES.includes(profile) ? profile : 'gradient';
  const s = seed == null ? randomBytes(4).readUInt32BE(0) : Number(seed) >>> 0;
  const rnd = mulberry32(s);
  const c1 = [rnd() * 256 | 0, rnd() * 256 | 0, rnd() * 256 | 0];
  const c2 = [rnd() * 256 | 0, rnd() * 256 | 0, rnd() * 256 | 0];
  const rgb = Buffer.alloc(w * h * 3);
  const span = Math.max(1, w + h - 2);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const o = (y * w + x) * 3;
      const grain = () => (rnd() * 9 - 4) | 0; // ±4 LSB grain: the scene's own noise floor
      if (p === 'noise') {
        for (let k = 0; k < 3; k++) rgb[o + k] = Math.max(0, Math.min(255, c1[k] + ((rnd() * 41 - 20) | 0)));
      } else if (p === 'flat') {
        for (let k = 0; k < 3; k++) rgb[o + k] = Math.max(0, Math.min(255, c1[k] + grain()));
      } else {
        const t = (x + y) / span;
        for (let k = 0; k < 3; k++) rgb[o + k] = Math.max(0, Math.min(255, Math.round(c1[k] + (c2[k] - c1[k]) * t) + grain()));
      }
    }
  }
  return rgb;
}

// ——— LSB framing ———
const FRAME_MAGIC = Buffer.from('SG', 'ascii');
const FRAME_VERSION = 1;
const FRAME_OVERHEAD = 2 + 1 + 4 + 4; // magic + version + length + crc

// Payload capacity in bytes for an image's pixel stream (1 LSB per stream byte).
export function stgCapacity({ width, height, channels = 3 } = {}) {
  const bits = (Number(width) | 0) * (Number(height) | 0) * (Number(channels) | 0);
  return Math.max(0, Math.floor(bits / 8) - FRAME_OVERHEAD);
}

function writeBits(pixels, frame) {
  for (let i = 0; i < frame.length * 8; i++) {
    const bit = (frame[i >> 3] >>> (7 - (i & 7))) & 1;
    pixels[i] = (pixels[i] & 0xfe) | bit;
  }
}
function readBits(pixels, byteOff, nBytes) {
  const out = Buffer.alloc(nBytes);
  const base = byteOff * 8;
  for (let i = 0; i < nBytes * 8; i++) out[i >> 3] = (out[i >> 3] << 1) | (pixels[base + i] & 1);
  return out;
}

// Embed a framed payload into a COPY of the pixel stream. Loud CAPACITY refusal.
export function embedPayload(pixels, payload) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload ?? ''), 'utf8');
  const need = FRAME_OVERHEAD + body.length;
  if (need * 8 > pixels.length) {
    throw new StegError('CAPACITY', 'payload ' + body.length + ' bytes + ' + FRAME_OVERHEAD + ' frame exceeds this image\'s ' + (Math.floor(pixels.length / 8) - FRAME_OVERHEAD) + '-byte capacity');
  }
  const out = Buffer.from(pixels); // never mutate the caller's scene
  const frame = Buffer.alloc(FRAME_OVERHEAD + body.length);
  FRAME_MAGIC.copy(frame, 0);
  frame[2] = FRAME_VERSION;
  frame.writeUInt32BE(body.length, 3);
  body.copy(frame, 7);
  frame.writeUInt32BE(crc32(body), 7 + body.length);
  writeBits(out, frame);
  return out;
}

// Extract the framed payload. Typed errors, fail-closed: a foreign image (valid PNG,
// no SG frame) is NO_PAYLOAD; a damaged frame is TRUNCATED/BAD_LENGTH/PAYLOAD_CRC.
export function extractPayload(pixels) {
  if (!Buffer.isBuffer(pixels) || pixels.length < 7 * 8) throw new StegError('TRUNCATED', 'pixel stream too small to hold a frame header');
  const head = readBits(pixels, 0, 7);
  if (head[0] !== FRAME_MAGIC[0] || head[1] !== FRAME_MAGIC[1]) throw new StegError('NO_PAYLOAD', 'no VARVEL frame in this image (foreign or clean PNG)');
  if (head[2] !== FRAME_VERSION) throw new StegError('NO_PAYLOAD', 'unknown frame version ' + head[2]);
  const len = head.readUInt32BE(3);
  if ((7 + len + 4) * 8 > pixels.length) throw new StegError('BAD_LENGTH', 'frame claims ' + len + ' payload bytes but the image holds at most ' + (Math.floor(pixels.length / 8) - FRAME_OVERHEAD));
  const body = readBits(pixels, 7, len);
  const crcRead = readBits(pixels, 7 + len, 4).readUInt32BE(0);
  if (crcRead !== crc32(body)) throw new StegError('PAYLOAD_CRC', 'payload CRC mismatch (corrupt or tampered image)');
  return body; // Buffer.alloc(0) for the uniform empty-envelope (idle/deny) image
}

// ——— The one-call codec ———
export const STG_DEFAULTS = Object.freeze({ width: 128, height: 128, profile: 'gradient' });

// payload bytes -> PNG bytes (seeded scene + LSB frame). seed is optional: pinned seeds
// are for tests/reproducibility; the default fresh-random seed keeps identical envelopes
// from byte-repeating on the wire.
export function encodeStgPng(payload, { width = STG_DEFAULTS.width, height = STG_DEFAULTS.height, profile = STG_DEFAULTS.profile, seed = null } = {}) {
  const w = Math.max(16, Math.min(1024, Number(width) | 0));
  const h = Math.max(16, Math.min(1024, Number(height) | 0));
  const scene = renderScene({ width: w, height: h, profile, seed });
  return encodePng({ width: w, height: h, rgb: embedPayload(scene, payload) });
}

// PNG bytes -> payload bytes (empty Buffer = the idle/deny empty envelope). Throws
// StegError (typed) on anything corrupt or foreign.
export function decodeStgPng(buf) {
  const { pixels } = decodePng(buf);
  return extractPayload(pixels);
}
