// VARVEL -- clearance: the cf_clearance MINT-and-RIDE broker (the honest pattern).
//
// Why it exists: Cloudflare's managed challenge ships a JS bundle (Turnstile-family
// proof-of-work + environment probes) that must execute in a REAL browser engine before
// the zone hands out cf_clearance. Cheap HTTP cannot mint it; a stealth browser can. So
// the browser mints ONCE here, then cheap HTTP requests RIDE the minted cookies. Engine:
// patchright-core (Apache-2.0, same license as upstream Playwright -- the stealth
// Playwright fork with a Node SDK) driving the REAL Chrome binary; 2026 independent
// benchmarks put that pair at the front of the Node-native pack. puppeteer-extra-plugin-
// stealth, undetected-chromedriver and FlareSolverr are BURNED and are never used here.
// The dependency is isolated to tools/clearance/node_modules -- VARVEL core stays
// dependency-free.
//
// SECOND MINT ENGINE (2026-08-05): after THREE Patchright mints failed the honest proof
// gate against a managed-challenge zone (cf_clearance issued but the zone re-challenged;
// the zone served interactive ticks to a HUMAN session, never to the automation window --
// the challenge-flavor differential IS the detection), a structurally different control
// plane was added: nodriver (Python; drives the SAME real Chrome over a raw CDP WebSocket
// -- no Playwright/CDP-session layer at all). 2026 independent benchmarks found it the
// ONLY zero-blocked automation tool. LICENSE NOTE: nodriver is AGPL-3.0 -- it is NEVER
// linked or bundled; it runs as an isolated subprocess sidecar (tools/clearance/py/
// ndmint.py inside its own .venv) communicating over ONE stdout JSON object. Engine
// selection: opts.engine 'nodriver' | 'patchright' | 'auto' (default auto = nodriver when
// detectNodriver() finds the sidecar healthy, else patchright). Every result/reason names
// the engine that ran, and vault entries record it.
//
// STICKY EGRESS IS MANDATORY: cf_clearance is bound to the source IP + User-Agent seen
// at mint time and lives ~30-60 min (vault TTL defaults to 45). Rotating the exit IP
// invalidates it instantly, so the vault keys every entry zone|egressId|sha256(ua)[:12]
// and prunes expired entries on read.
//
// OS-LEVEL AUTO-TICK (2026-08-11): when the sidecar's poll sees a Turnstile checkbox,
// the tick is a real OS input event on the VISIBLE window (ctypes user32 SetCursorPos/
// mouse_event from the sidecar process -- NEVER a CDP-synthesized click, which
// Cloudflare catches via a screenX/screenY differential inside the cross-domain
// iframe). Humanized: cursor drift + 300-900ms dwell. Up to 3 attempts (initial + 2
// retries, fresh locate each), then it falls back to the passive operator-tick wait --
// as it does from the start under VARVEL_CF_MANUAL_TICK=1 (surfaced to the sidecar as
// --manual-tick), in headless mode, or off Windows. Every mint result carries the
// honest provenance: tick.path = auto-os-click | operator-manual | not-required |
// unattended-headless | unresolved (detectability accounting), and the vault entry
// records it. The tick phase never extends the mint timeout.
//
// THE MINT RIDES THE SAME EGRESS THE GOVERNED TOOLS RIDE (2026-08-10, live-proven on the
// manhuaus rematch): a DIRECT mint (egressId 'direct') binds cf_clearance to the operator
// egress, but ghost-governed tools (wafbypass/cfmap/cfride...) ride the ghost SOCKS chain
// -- the cookie was challenged at the edge on every ghost-ridden probe (24/24 wasted).
// So when ghost mode is armed the mint browser launches THROUGH the chain: opts.proxy is
// the chain's canonical single-hop URL (applied as --proxy-server to the nodriver
// sidecar's Chrome, and as the context proxy option to patchright), and the egressId
// recorded is the chain's canonical id (engine/ghost chainEgressId) -- resolveMintEgress
// is the one decision function for this, shared by the CLI so mint-side and lookup-side
// can never drift apart.
//
// THE HONESTY CONTRACT (non-negotiable): NEVER throws -- every failure resolves
// { minted:false, reason } (no real Chrome found, launch failed, challenge never
// resolved, budget exhausted). A mint is PROVEN, not assumed: after cookie extraction we
// run ONE confirmation fetch of the zone root inside the same browser context (same
// cookies, same UA) and classify it with engine/challenge.mjs -- minted:true ONLY when
// that response carries no challenge evidence. A cookie that does not clear the gate is
// reported as exactly that, and is never vaulted.
//
// OPERATOR NOTE: headless:false (the default) means browser windows ARE VISIBLE on the
// operator's machine -- that is intended. headless:true is allowed but measurably
// weaker against 2026 bot gates.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync as cpSpawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { detectChallenge } from '../../engine/challenge.mjs';
import { Ghost, parseChain, chainEgressId, isPrivateDest } from '../../engine/ghost.mjs';
import { Settings } from '../../engine/settings.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(HERE, '..', '..', 'data');
const VAULT_PATH = path.join(DATA_DIR, 'clearance-vault.json');
const PROFILE_DIR = path.join(DATA_DIR, 'clearance-profile'); // persistent real profile: stronger trust than a throwaway context
const ND_PROFILE_DIR = path.join(DATA_DIR, 'clearance-profile-nd'); // separate persistent profile for the nodriver sidecar: sharing one profile dir with a live Patchright context would deadlock on Chrome's profile lock
const PY_DIR = path.join(HERE, 'py');
const NDMINT_PY = path.join(PY_DIR, 'ndmint.py');
const ND_ENGINE = 'nodriver (raw-CDP sidecar)';
const PR_ENGINE = 'patchright (stealth Playwright + real Chrome)';
const DEFAULT_TTL_MS = 45 * 60 * 1000; // real cf_clearance lives ~30-60min; 45 is the safe midpoint
const POLL_MS = 1000;

const msg = (e) => String((e && e.message) || e);

function zoneOf(url) {
  try {
    const u = new URL(String(url));
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u.host || null;
  } catch { return null; }
}

function originOf(url) {
  try { return new URL(String(url)).origin; } catch { return null; }
}

// Real-Chrome detection, in order: opts.chromePath, env CHROME_PATH, then the two
// well-known Chrome install paths, then Microsoft Edge (Chromium-class) as a declared
// fallback. The REAL binary matters as much as the Patchright patches (the
// channel:'chrome' doctrine) -- a bundled Chromium is a different, weaker fingerprint.
// Edge is Chromium and drives identically, but its stealth parity with real Chrome is
// UNVERIFIED (2026 benchmarks tested Chrome) — the via-string carries that label into
// every result/error so an Edge mint is never silently treated as proven-equivalent.
// env/exists are injectable so the not-found path stays hermetic in tests.
export function resolveChrome({ chromePath, env = process.env, exists = fs.existsSync } = {}) {
  const EDGE_NOTE = 'Edge (Chromium-class) — stealth parity with real Chrome UNVERIFIED until live-tested';
  const candidates = [
    chromePath ? { via: 'opts.chromePath', p: String(chromePath) } : null,
    env && env.CHROME_PATH ? { via: 'env CHROME_PATH', p: String(env.CHROME_PATH) } : null,
    { via: 'well-known path (Chrome)', p: 'C:/Program Files/Google/Chrome/Application/chrome.exe' },
    { via: 'well-known path (Chrome)', p: 'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe' },
    { via: 'well-known path (' + EDGE_NOTE + ')', p: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe' },
    { via: 'well-known path (' + EDGE_NOTE + ')', p: 'C:/Program Files/Microsoft/Edge/Application/msedge.exe' },
  ].filter(Boolean);
  for (const c of candidates) { try { if (exists(c.p)) return c; } catch {} }
  return null;
}

// Sticky-egress vault key: same zone through a different egress (or under a different
// UA) is a DIFFERENT clearance -- Cloudflare binds the cookie to source IP + UA.
export function vaultKey(zone, egressId, ua) {
  const digest = crypto.createHash('sha256').update(String(ua)).digest('hex').slice(0, 12);
  return String(zone) + '|' + String(egressId) + '|' + digest;
}

// readVault({ vaultPath, now }) -> { ok, entries, pruned }. Expired (and malformed)
// entries are pruned on read, in memory; the file is compacted on the next writeVault.
// A missing vault is an empty vault, not an error; a corrupt one is an honest error.
// Never throws.
export function readVault({ vaultPath = VAULT_PATH, now = () => Date.now() } = {}) {
  try {
    let raw;
    try { raw = fs.readFileSync(vaultPath, 'utf8'); }
    catch (e) { if (e && e.code === 'ENOENT') return { ok: true, entries: {}, pruned: 0 }; throw e; }
    const parsed = JSON.parse(raw);
    const table = (parsed && typeof parsed === 'object' && parsed.entries && typeof parsed.entries === 'object') ? parsed.entries : {};
    const t = now();
    const entries = {};
    let pruned = 0;
    for (const [k, e] of Object.entries(table)) {
      const exp = e && typeof e === 'object' ? Date.parse(e.expiresAt || '') : NaN;
      if (!e || typeof e !== 'object' || !Array.isArray(e.cookies) || !Number.isFinite(exp) || exp <= t) { pruned++; continue; }
      entries[k] = e;
    }
    return { ok: true, entries, pruned };
  } catch (e) { return { ok: false, error: 'clearance vault unreadable (' + msg(e) + ')', entries: {}, pruned: 0 }; }
}

// writeVault(entries, { vaultPath }) -> { ok, count }. Atomic (tmp + rename); the data/
// dir is created on first use. Never throws.
export function writeVault(entries, { vaultPath = VAULT_PATH } = {}) {
  try {
    fs.mkdirSync(path.dirname(vaultPath), { recursive: true });
    const tmp = vaultPath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({ version: 1, entries: entries || {} }, null, 2));
    fs.renameSync(tmp, vaultPath);
    return { ok: true, count: Object.keys(entries || {}).length };
  } catch (e) { return { ok: false, error: 'clearance vault write failed (' + msg(e) + ')' }; }
}

// clearanceFor(url, { egressId, ua }) -> { cookies, ua, expiresAt, mintedAt } for a
// VALID, unexpired entry matching exactly this zone + egress + UA, else null. The UA is
// part of the key: the ride must name the exact UA string it will send. Never throws.
export async function clearanceFor(url, { egressId = 'direct', ua, vaultPath = VAULT_PATH, now } = {}) {
  try {
    const zone = zoneOf(url);
    if (!zone) return null;
    const v = readVault(now ? { vaultPath, now } : { vaultPath });
    if (!v.ok) return null;
    if (ua) {
      // Exact-UA ride (the minted-identity binding): precise key only.
      const e = v.entries[vaultKey(zone, egressId, ua)];
      return e ? { cookies: e.cookies, ua: e.ua, expiresAt: e.expiresAt, engine: e.engine, tick: e.tick || null, mintedAt: e.mintedAt || null } : null;
    }
    // No UA given: any unexpired entry for this zone+egress qualifies (readVault already
    // pruned expired) — the natural query for status/rides; most recently minted wins.
    const prefix = zone + '|' + egressId + '|';
    let best = null;
    for (const [k, e] of Object.entries(v.entries)) {
      if (!k.startsWith(prefix)) continue;
      if (!best || String(e.mintedAt || '') > String(best.mintedAt || '')) best = e;
    }
    return best ? { cookies: best.cookies, ua: best.ua, expiresAt: best.expiresAt, engine: best.engine, tick: best.tick || null, mintedAt: best.mintedAt || null } : null;
  } catch { return null; }
}

// proofGate(response) -- THE HONEST MINT PROOF, pure and injectable-testable. The one
// confirmation fetch of the zone root is classified with engine/challenge: passage is
// PROVEN only when that response carries no challenge evidence. A minted cf_clearance
// that does not clear the gate is honestly minted:false.
export function proofGate({ status = 0, headers = {}, body = '' } = {}) {
  const detection = detectChallenge({ status, headers, body });
  if (detection.present) {
    return { minted: false, detection, reason: 'cf_clearance minted but zone still challenges — unproven passage, honestly reported' };
  }
  return { minted: true, detection };
}

// resolveMintEgress({ ghostMode, ghostChain, directEgress }) -> the ghost-aware mint
// egress decision (PURE, never throws -- the CLI feeds it the same Settings source the
// ghost engine arms from). The rule, from the 2026-08-10 live failure: the mint must
// ride the SAME egress the ghost-governed tools ride, or the IP-bound cookie burns at
// the edge. Decisions:
//   ghost off                          -> direct mint, egressId 'direct' (unchanged)
//   ghost on|required + chain          -> mint THROUGH the chain; proxy = the chain's
//                                         canonical single-hop URL, egressId = the
//                                         chain's canonical id (chainEgressId)
//   ghost required + NO chain          -> REFUSED, fail-closed: never mint direct into a
//                                         required-ghost engagement by default
//   ghost on + no chain                -> direct mint WITH a loud warning (best-effort
//                                         mode stays best-effort, honestly labeled)
//   directEgress: true                 -> explicit operator override: direct mint WITH a
//                                         loud warning (legitimate direct-mint cases exist)
//   multi-hop chain                    -> REFUSED, fail-closed: a browser can ride exactly
//                                         ONE proxy hop; minting through only the first
//                                         hop would bind the cookie to the WRONG exit
//                                         (the chain exits at the LAST hop) -- the exact
//                                         mint/ride split this decision exists to kill
// Credentials never ride the proxy id or the vault key: they are handed to the launcher
// separately as proxyAuth.
export function resolveMintEgress({ ghostMode = 'off', ghostChain = '', directEgress = false } = {}) {
  const DIRECT_BASE = { ok: true, proxy: null, proxyAuth: null, egressId: 'direct' };
  if (directEgress) {
    return {
      ...DIRECT_BASE,
      warning: 'WARNING: --direct-egress given -- minting DIRECT (egressId "direct"): cf_clearance will bind to the OPERATOR egress, NOT the ghost chain exit. Ghost-governed tools riding the chain will NOT match this clearance (IP-bound) -- ride it only from direct-egress tooling.',
    };
  }
  if (ghostMode !== 'on' && ghostMode !== 'required') return { ...DIRECT_BASE };
  const spec = String(ghostChain || '').trim();
  if (!spec) {
    if (ghostMode === 'required') {
      return {
        ok: false, proxy: null, proxyAuth: null, egressId: null,
        reason: 'ghost mode is REQUIRED but no proxy chain is configured -- mint REFUSED (fail-closed): a direct mint would bind cf_clearance to the operator egress while ghost-governed tools ride the chain exit, so the cookie would be challenged at the edge. Configure ghost.chain (e.g. Mullvad socks5://10.64.0.1:1080) or pass --direct-egress for an explicit direct mint.',
      };
    }
    return {
      ...DIRECT_BASE,
      warning: 'WARNING: ghost mode is ON but no proxy chain is configured -- minting DIRECT (egressId "direct"): cf_clearance will bind to the operator egress. Ghost-governed tools riding a chain will NOT match this clearance (IP-bound).',
    };
  }
  let hops;
  try { hops = parseChain(spec); } catch (e) {
    return {
      ok: false, proxy: null, proxyAuth: null, egressId: null,
      reason: 'ghost chain could not be parsed (' + msg(e) + ') -- mint REFUSED (fail-closed): the egress the mint would ride is unknowable, and an unverified egress is how IP-bound cookies get burned.',
    };
  }
  if (hops.length > 1) {
    return {
      ok: false, proxy: null, proxyAuth: null, egressId: null,
      reason: 'ghost chain has ' + hops.length + ' hops but a browser mint can ride exactly ONE proxy hop (Chrome accepts a single --proxy-server) -- minting through only the first hop would bind cf_clearance to the WRONG exit IP (the chain exits at the LAST hop). Mint REFUSED (fail-closed); configure a single-hop chain or pass --direct-egress.',
    };
  }
  return {
    ok: true,
    proxy: hops[0].scheme + '://' + hops[0].host + ':' + hops[0].port,
    proxyAuth: hops[0].user ? { username: hops[0].user, password: hops[0].pass } : null,
    egressId: chainEgressId(hops),
  };
}

// rideEgressId({ ghostMode, ghostChain }) -> the egressId the RIDE side (cfride /
// cfbrowser / clearance status) uses for vault lookups: the chain's canonical id when
// ghost is armed with a parseable chain, else 'direct'. NEVER throws -- a bad chain
// yields 'direct' (the vault simply misses honestly; the ghost-governed tools would have
// refused the ride first). THE parity rule: mint through a chain under resolveMintEgress
// and look up under rideEgressId with the same settings -- both land on chainEgressId.
export function rideEgressId({ ghostMode = 'off', ghostChain = '' } = {}) {
  try {
    if (ghostMode !== 'on' && ghostMode !== 'required') return 'direct';
    const spec = String(ghostChain || '').trim();
    if (!spec) return 'direct';
    return chainEgressId(spec);
  } catch { return 'direct'; }
}

// --- the RIDE-side transport gate (2026-08-10, live-proven gap) -----------------------
// resolveMintEgress + rideEgressId aligned the VAULT KEY; this aligns the WIRE. cfride's
// default fetcher was plain global fetch and cfbrowser's launcher took no proxy, so a
// chain-minted (IP-bound) clearance was looked up under the chain's canonical id and
// then ridden DIRECT -- the edge saw the wrong source IP and challenged every request.
// The vault entry's egressId is the binding contract: the ride's transport MUST match it.
//
// resolveRideTransport({ ghost, ghostMode, egressId, hostname }) -> the decision:
//   private/range destination                -> direct, always (ghost doctrine: lab
//                                               traffic never leaves the lab)
//   chain-keyed entry (egressId != 'direct') -> the armed ghost chain, and ONLY a chain
//                                               whose canonical id EQUALS the entry's id
//                                               (a different exit IP burns the cookie);
//                                               ghost required + unverified: one verify()
//                                               attempt, then refuse (wafbypass's
//                                               ensureGhost posture, mirrored)
//   chain-keyed + ghost off / no chain       -> REFUSED, fail-closed (a direct ride would
//                                               present the wrong IP and burn the cookie)
//   'direct' entry + ghost required + public -> REFUSED, fail-closed (required mode
//                                               forbids operator-IP egress to public
//                                               targets -- re-mint through the chain)
//   'direct' entry + ghost off | on          -> direct (the operator-clearance pattern;
//                                               'on' is best-effort and the transport
//                                               string says so)
// Result: { ok, direct, agents, proxy, proxyAuth, multiHop, transport } or
// { ok:false, reason }. `agents` feeds node http(s) requesters (cfride's fetcher + the
// crawl/apisurface/vulncheck `agents` seam); `proxy`/`proxyAuth` feed a browser context
// (cfbrowser -- a browser rides exactly ONE hop, the same constraint the mint leg
// enforces, so multiHop is flagged for that caller to refuse). Never throws.
export async function resolveRideTransport({ ghost, ghostMode, egressId = 'direct', hostname } = {}) {
  const mode = ghostMode || (ghost && ghost.mode) || 'off';
  try {
    if (isPrivateDest(hostname)) {
      return { ok: true, direct: true, agents: null, proxy: null, proxyAuth: null, multiHop: false, transport: 'direct (private/range destination -- ghost doctrine: lab traffic never leaves the lab)' };
    }
    if (egressId && egressId !== 'direct') {
      if (!ghost || mode === 'off' || !ghost.chain || !ghost.chain.length) {
        return { ok: false, reason: 'the vaulted clearance is bound to ghost-chain egress "' + egressId + '" but ghost is not armed with a chain -- riding DIRECT would present the wrong source IP and burn the IP-bound cookie at the edge. Arm ghost (mode + the mint-time chain) or re-mint with --direct-egress. Ride REFUSED (fail-closed).' };
      }
      let armedId = null;
      try { armedId = chainEgressId(ghost.chain); } catch { /* an unparseable armed chain can never equal the entry id */ }
      if (armedId !== egressId) {
        return { ok: false, reason: 'the vaulted clearance is bound to egress "' + egressId + '" but the armed ghost chain is "' + (armedId || 'unparseable') + '" -- a different exit IP invalidates the IP-bound cookie instantly. Re-mint through the armed chain or restore the mint-time chain. Ride REFUSED (fail-closed).' };
      }
      if (mode === 'required' && !ghost.verifiedOk()) {
        try { await ghost.verify(); } catch { /* verify failure is handled below */ }
        if (!ghost.verifiedOk()) {
          return { ok: false, reason: 'ghost mode is required but the chain exit is NOT verified (exit != operator IP unproven) -- public egress REFUSED (fail-closed). Run the ghost self-check first.' };
        }
      }
      const single = ghost.chain.length === 1;
      const hop = single ? ghost.chain[0] : null;
      return {
        ok: true,
        direct: false,
        agents: ghost.agents(),
        proxy: hop ? hop.scheme + '://' + hop.host + ':' + hop.port : null,
        proxyAuth: hop && hop.user ? { username: hop.user, password: hop.pass } : null,
        multiHop: !single,
        transport: 'ghost chain (' + ghost.chain.length + ' hop(s), egressId "' + egressId + '")',
      };
    }
    if (mode === 'required') {
      return { ok: false, reason: 'the vaulted clearance is direct-bound (egressId "direct") but ghost mode is REQUIRED -- a direct ride to a public target exposes the operator egress, exactly what required mode forbids. Re-mint through the chain (clearance mint) so the ride matches the armed egress. Ride REFUSED (fail-closed).' };
    }
    return { ok: true, direct: true, agents: null, proxy: null, proxyAuth: null, multiHop: false, transport: 'direct (egressId "direct" -- the vault entry binds the operator egress' + (mode === 'on' ? '; ghost mode ON is best-effort, a direct-bound ride stays direct' : '') + ')' };
  } catch (e) {
    return { ok: false, reason: 'ride transport resolution failed (' + msg(e) + ') -- refusing (fail-closed)' };
  }
}

// ghostRideState(engagement) -> { ghost, ghostMode }: the ride tools' ghost, armed from
// the SAME per-engagement Settings source the mint/lookup sides read (cli ghostSettings),
// so transport and vault key can never drift. Never throws: an unreadable store reads as
// ghost off; an unarmable spec (e.g. required with NO chain -- Ghost.configure throws)
// leaves the Ghost off while ghostMode keeps the RAW configured value, so 'required'
// still fails closed for public targets in resolveRideTransport.
export function ghostRideState(engagement) {
  let ghostMode = 'off', ghostChain = '', checkUrl;
  try {
    const s = Settings.for(engagement);
    ghostMode = s.get('ghost.mode') || 'off';
    ghostChain = s.get('ghost.chain') || '';
    checkUrl = s.get('ghost.checkUrl') || undefined;
  } catch { /* an unreadable settings store reads as ghost off */ }
  const ghost = new Ghost();
  try { if (ghostMode !== 'off') ghost.configure({ mode: ghostMode, chain: ghostChain, checkUrl }); }
  catch { /* unarmable: the Ghost stays off; the raw ghostMode still fails closed */ }
  return { ghost, ghostMode };
}

// --- nodriver sidecar (SECOND mint engine; AGPL-3.0 -- subprocess only, never linked) ---

let ndProbeCache = null; // per-process cache of the DEFAULT (non-injected) probe

// detectNodriver({ env, exists, spawnSync } injectable) -> { available, pythonPath,
// version, reason? }. The sidecar is available only when the venv python EXISTS at
// tools/clearance/py/.venv AND `import nodriver` runs cleanly under it. env/exists/
// spawnSync are injectable so both the absent and present paths stay hermetic in tests;
// the default (non-injected) probe result is cached per process. Never throws.
export function detectNodriver(opts = {}) {
  const injected = !!(opts && (opts.env !== undefined || opts.exists !== undefined || opts.spawnSync !== undefined));
  if (!injected && ndProbeCache) return ndProbeCache;
  const { env = process.env, exists = fs.existsSync, spawnSync = cpSpawnSync } = opts || {};
  const candidates = [
    path.join(PY_DIR, '.venv', 'Scripts', 'python.exe'), // Windows venv
    path.join(PY_DIR, '.venv', 'Scripts', 'python'),
    path.join(PY_DIR, '.venv', 'bin', 'python'), // POSIX venv, for completeness
  ];
  let pythonPath = null;
  for (const p of candidates) { try { if (exists(p)) { pythonPath = p; break; } } catch {} }
  const install = 'python -m venv tools/clearance/py/.venv && tools/clearance/py/.venv/Scripts/python -m pip install nodriver';
  let result;
  if (!pythonPath) {
    result = { available: false, pythonPath: null, version: null, reason: 'no nodriver sidecar venv at tools/clearance/py/.venv (checked Scripts/python.exe, Scripts/python, bin/python) -- install: ' + install };
  } else {
    let probe = null;
    try { probe = spawnSync(pythonPath, ['-c', 'from importlib.metadata import version; print(version("nodriver"))'], { encoding: 'utf8', timeout: 30000, env }); }
    catch (e) { probe = { error: e }; }
    if (probe && !probe.error && probe.status === 0) {
      const version = String(probe.stdout || '').trim().split(/\r?\n/).filter(Boolean).pop() || 'unknown';
      result = { available: true, pythonPath, version };
    } else {
      const detail = probe && probe.error ? msg(probe.error) : String((probe && probe.stderr) || ('exit ' + (probe && probe.status))).trim().slice(0, 300);
      result = { available: false, pythonPath, version: null, reason: 'venv python found at ' + pythonPath + ' but "import nodriver" failed (' + detail + ') -- install: ' + install };
    }
  }
  if (!injected) ndProbeCache = result;
  return result;
}

// parseSidecarJson(stdout) -> { ok, facts? }. The sidecar prints EXACTLY ONE JSON object,
// but the contract is tolerant: browser/nodriver log lines may precede it on stdout, so
// the LAST line that parses as a JSON object wins. No parseable line = honest not-ok.
export function parseSidecarJson(stdout) {
  const lines = String(stdout == null ? '' : stdout).split(/\r?\n/);
  for (let i = lines.length - 1; i >= 0; i--) {
    const t = lines[i].trim();
    if (!t || t[0] !== '{') continue;
    try {
      const v = JSON.parse(t);
      if (v && typeof v === 'object') return { ok: true, facts: v };
    } catch {}
  }
  return { ok: false };
}

// Default sidecar spawn: the venv python + ndmint.py as an ARGS ARRAY (never a shell
// string), stdout/stderr collected to strings. A hard kill fires at timeoutMs so the
// Node side can never hang past the sidecar's own budget + grace. Never rejects.
function defaultSidecarRun(pythonPath, args, { timeoutMs } = {}) {
  return new Promise((resolve) => {
    let stdout = '', stderr = '', settled = false;
    const done = (r) => { if (!settled) { settled = true; resolve(r); } };
    let child;
    try { child = spawn(pythonPath, args); } catch (e) { done({ ok: false, error: msg(e), stdout, stderr }); return; }
    const killer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch {}
      done({ ok: false, timedOut: true, error: 'sidecar exceeded its hard kill budget (' + timeoutMs + 'ms) and was force-killed', stdout, stderr });
    }, Math.max(1000, timeoutMs || 60000));
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (e) => { clearTimeout(killer); done({ ok: false, error: msg(e), stdout, stderr }); });
    child.on('close', (code) => { clearTimeout(killer); done({ ok: true, status: code, stdout, stderr }); });
  });
}

// normalizeTick(raw) -> the tick-path PROVENANCE record, or null when the sidecar
// reported none (an old sidecar, or a run that never reached the poll). The mint
// report must state honestly which path passed the challenge -- auto-os-click (the
// OS-level ctypes user32 click) vs operator-manual (the human ticked the visible
// window) vs not-required (no interactive checkbox ever appeared) -- because that
// provenance feeds detectability accounting. Raw facts pass through verbatim in
// shape, coerced to the known fields.
export function normalizeTick(raw) {
  if (!raw || typeof raw !== 'object') return null;
  return {
    path: typeof raw.path === 'string' && raw.path ? raw.path : 'unknown',
    attempts: Number.isFinite(raw.attempts) ? raw.attempts : 0,
    clicks: Number.isFinite(raw.clicks) ? raw.clicks : 0,
    sawCheckbox: raw.sawCheckbox === true,
    auto: raw.auto === true,
    manual: raw.manual === true,
  };
}

// manualTickRequested(env) -> true when the operator pinned the manual tick path
// (VARVEL_CF_MANUAL_TICK=1|true). The broker translates it into an explicit
// --manual-tick sidecar arg so the override is visible on the wire contract, not
// just inherited process env.
export function manualTickRequested(env = process.env) {
  return /^(1|true)$/i.test(String((env && env.VARVEL_CF_MANUAL_TICK) || '').trim());
}

// The nodriver mint leg: spawn the sidecar, parse its raw facts, run the SAME proofGate
// as the Patchright path. minted:true ONLY when the sidecar solved the challenge AND the
// proof response is challenge-free; unproven cookies are never vaulted. Never throws.
// opts.sidecarRun is an injectable seam (tests): async (pythonPath, args, { timeoutMs })
// -> { ok, status?, stdout, stderr, error? }.
async function mintViaNodriver(url, { zone, origin, chrome, headless, timeoutMs, userDataDir, egressId, ttlMs, vaultPath, now, nd, sidecarRun, proxy, env }) {
  const profileDir = userDataDir || ND_PROFILE_DIR;
  try { fs.mkdirSync(profileDir, { recursive: true }); } catch {}
  const secs = Math.max(5, Math.ceil(timeoutMs / 1000));
  const args = [NDMINT_PY, String(url), '--chrome', chrome.p, '--profile', profileDir, '--timeout-s', String(secs)];
  if (headless) args.push('--headless');
  if (proxy) args.push('--proxy', proxy); // the mint rides the ghost chain: Chrome --proxy-server (applied by the sidecar)
  // Operator override (2026-08-11): VARVEL_CF_MANUAL_TICK=1 disables the OS-level
  // auto-tick -- the sidecar then keeps the pre-auto-tick passive operator-tick wait.
  if (manualTickRequested(env)) args.push('--manual-tick');
  const run = sidecarRun || defaultSidecarRun;
  const res = await run(nd.pythonPath, args, { timeoutMs: timeoutMs + 45000 }).catch((e) => ({ ok: false, error: msg(e), stdout: '', stderr: '' }));
  const stderrTail = String((res && res.stderr) || '').trim().split(/\r?\n/).filter(Boolean).slice(-3).join(' | ').slice(0, 300);
  if (!res || res.ok !== true) {
    return { minted: false, engine: ND_ENGINE, reason: 'nodriver sidecar did not complete (' + ((res && (res.error || ('exit ' + res.status))) || 'spawn failed') + (stderrTail ? '; stderr tail: ' + stderrTail : '') + ') -- unproven passage, honestly reported' };
  }
  const parsed = parseSidecarJson(res.stdout);
  if (!parsed.ok) {
    return { minted: false, engine: ND_ENGINE, reason: 'nodriver sidecar produced no parseable JSON verdict on stdout (exit ' + res.status + (stderrTail ? '; stderr tail: ' + stderrTail : '') + ') -- unproven passage, honestly reported' };
  }
  const facts = parsed.facts;
  if (facts.ok !== true) {
    return { minted: false, engine: ND_ENGINE, reason: 'nodriver sidecar failed: ' + String(facts.reason || 'unknown sidecar error') };
  }
  const tick = normalizeTick(facts.tick);
  if (facts.solved !== true) {
    return {
      minted: false,
      engine: ND_ENGINE,
      reason: String(facts.reason || 'managed challenge did not resolve before the sidecar time budget ran out'),
      tick, // provenance even on failure: which tick path was tried, how many OS clicks landed
    };
  }
  const ua = typeof facts.ua === 'string' && facts.ua ? facts.ua : null;
  if (!ua) {
    return { minted: false, engine: ND_ENGINE, reason: 'challenge resolved but the exact User-Agent string could not be read back by the sidecar -- the vault key embeds sha256(ua), so an unreadable UA is an honest mint failure' };
  }
  const cookies = Array.isArray(facts.cookies) ? facts.cookies : [];
  // HONEST MINT PROOF: the sidecar's ONE confirmation navigation of the zone root,
  // classified by the SAME engine/challenge gate as the Patchright path.
  const proofStatus = Number.isFinite(facts.proofStatus) ? facts.proofStatus : 0;
  const gate = proofGate({ status: proofStatus, headers: (facts.proofHeaders && typeof facts.proofHeaders === 'object') ? facts.proofHeaders : {}, body: typeof facts.proofBody === 'string' ? facts.proofBody : '' });
  if (!gate.minted) return { minted: false, engine: ND_ENGINE, reason: gate.reason, postStatus: proofStatus, postKind: gate.detection.kind, tick };
  const mintedMs = now();
  const mintedAt = new Date(mintedMs).toISOString();
  const expiresAt = new Date(mintedMs + ttlMs).toISOString();
  const cur = readVault({ vaultPath, now });
  const entries = cur.ok ? cur.entries : {};
  entries[vaultKey(zone, egressId, ua)] = { cookies, ua, mintedAt, expiresAt, engine: ND_ENGINE, ...(tick ? { tick } : {}) };
  const w = writeVault(entries, { vaultPath });
  return {
    minted: true,
    engine: ND_ENGINE,
    zone,
    egressId,
    cookies,
    ua,
    mintedAt,
    expiresAt,
    postStatus: proofStatus,
    browserVia: chrome.via,
    sidecar: { python: nd.pythonPath, nodriver: nd.version || 'unknown' },
    tick, // honest provenance: auto-os-click vs operator-manual vs not-required (detectability accounting)
    egressNote: 'cf_clearance is bound to source IP + User-Agent: these cookies were minted through egressId "' + egressId + '" under UA sha256[:12] ' + vaultKey(zone, egressId, ua).split('|')[2] + '. Riding them from another exit IP invalidates them instantly -- sticky egress is mandatory. Vault TTL ' + Math.round(ttlMs / 60000) + 'min (real cf_clearance lives ~30-60min).',
    vault: w.ok ? { ok: true, path: vaultPath } : { ok: false, error: w.error },
  };
}

// Default launcher: patchright-core (dynamically imported so this module still loads
// without the isolated node_modules -- hermetic tests never touch it) driving REAL
// Chrome through a persistent context. executablePath is the binary we resolved
// ourselves -- the channel:'chrome' effect, but with a not-found path we control.
// proxy (optional): the chain's canonical single-hop URL, applied as the context proxy
// so the MINT rides the same egress the ghost-governed tools ride.
async function defaultLauncher({ chromePath: exe, headless, userDataDir, proxy, proxyAuth }) {
  let chromium;
  try {
    ({ chromium } = await import('patchright-core'));
  } catch (e) {
    throw new Error('patchright-core is missing at tools/clearance/node_modules -- run: cd tools/clearance && npm install --omit=dev (' + msg(e) + ')');
  }
  const dir = userDataDir || PROFILE_DIR;
  fs.mkdirSync(dir, { recursive: true });
  return chromium.launchPersistentContext(dir, {
    headless,
    executablePath: exe,
    viewport: null, // real window size, not the fixed automation-viewport tell
    ...(proxy ? { proxy: { server: proxy, ...(proxyAuth || {}) } } : {}),
  });
}

// Poll until the document no longer looks like a challenge AND/OR cf_clearance appears.
// A page mid-navigation (evaluate throws) counts as STILL challenged -- we never call a
// navigation artifact "resolved". A BLANK/loading document (about:blank, redirect
// interstitials, an empty DOM) also counts as still challenged: 'no challenge markers in
// an empty page' is a loading state, not a resolution — the 2026-08-05 manhuaus attempt 3
// flash-closed the window on exactly this, robbing the operator's tick. Never throws.
export async function waitForResolution(page, context, origin, deadline) {
  let sawClearance = false;
  let lastKind = 'unknown';
  while (Date.now() < deadline) {
    const cookies = await context.cookies(origin).catch(() => []);
    sawClearance = (Array.isArray(cookies) ? cookies : []).some((c) => c && c.name === 'cf_clearance');
    const html = await page.evaluate(() => document.title + '\n' + (document.documentElement ? document.documentElement.innerHTML : '')).catch(() => null);
    let pageUrl = ''; try { pageUrl = String(page.url() || ''); } catch {}
    const blank = html == null || /^about:(blank|srcdoc)/i.test(pageUrl) || html.replace(/<[^>]+>|\s+/g, '').length < 40;
    const det = html == null ? { present: true, kind: 'navigation-in-flight' }
      : blank ? { present: true, kind: 'document-loading' }
      : detectChallenge({ status: 200, headers: {}, body: html });
    lastKind = det.kind;
    // 2026-08-10 (Jack's catch, manhuaus rematch): cf_clearance can arrive a tick EARLY --
    // the cookie appears while the challenge page is still up (a second tick pending). The
    // old '|| sawClearance' clause declared resolution on the cookie alone, so the proof
    // fetch ran against a still-challenged session (403) and the window closed under the
    // operator's mouse. Resolution is decided by the PAGE STATE alone; the cookie rides.
    if (!det.present && !blank) return { ok: true, sawClearance, domKind: det.kind };
    await new Promise((r) => setTimeout(r, Math.max(1, Math.min(POLL_MS, deadline - Date.now()))));
  }
  return {
    ok: false,
    sawClearance,
    reason: 'managed challenge did not resolve before the time budget ran out (last DOM classification: ' + lastKind + '; ' + (sawClearance ? 'cf_clearance appeared but the page still looks challenged' : 'no cf_clearance observed') + ')',
  };
}

// mintClearance(url, opts) -> the mint result. Headed by default: a browser window IS
// VISIBLE on the operator's machine. Never throws -- see the honesty contract above.
// opts.engine: 'nodriver' | 'patchright' | 'auto' (DEFAULT 'auto' = nodriver when
// detectNodriver() finds the sidecar healthy, else patchright). Every result/reason names
// the engine that ran. opts.launcher is an injectable seam (tests) for the patchright
// path: async ({ chromePath, chromeVia, headless, userDataDir, proxy, proxyAuth }) -> a
// BrowserContext-like object -- in 'auto' mode an injected launcher PINS the engine to
// patchright (the seam is the driver; see the cascade note below); opts.sidecarRun is the
// same for the nodriver path (see mintViaNodriver); opts.spawnSync is passed through to
// detectNodriver for hermetic engine-cascade tests.
// opts.proxy: the chain's canonical single-hop proxy URL (e.g. socks5://10.64.0.1:1080)
// -- the mint browser rides it so cf_clearance binds to the CHAIN exit the governed
// tools ride (2026-08-10 mint-direct/ride-chain split). When proxy is set and no
// explicit opts.egressId is given, the egressId recorded defaults to the chain's
// canonical id (chainEgressId) -- mint-side and ride-side agree by construction.
// opts.proxyAuth: { username, password } for credentialed hops (never keyed/logged).
export async function mintClearance(url, {
  engine = 'auto',
  headless = false, // default = VISIBLE window on the operator's machine; headless:true is allowed but measurably weaker against 2026 bot gates
  timeoutMs = 90000,
  chromePath,
  userDataDir,
  egressId: egressOpt,
  proxy,
  proxyAuth,
  ttlMs = DEFAULT_TTL_MS,
  vaultPath = VAULT_PATH,
  launcher,
  sidecarRun,
  now = () => Date.now(),
  env,
  exists,
  spawnSync: injectedSpawnSync,
} = {}) {
  try {
    const zone = zoneOf(url);
    const origin = originOf(url);
    if (!zone || !origin) return { minted: false, reason: 'mintClearance needs an absolute http(s) URL -- got ' + JSON.stringify(String(url)) };
    if (engine !== 'auto' && engine !== 'nodriver' && engine !== 'patchright') {
      return { minted: false, reason: 'unknown engine ' + JSON.stringify(String(engine)) + ' -- expected nodriver | patchright | auto' };
    }
    // Proxy sanity, fail-closed: a bad or multi-hop spec here means the mint egress is
    // NOT the egress the caller believes -- refusing is how we never burn an IP-bound
    // cookie again. (resolveMintEgress already enforces this on the CLI path; this is
    // the same gate for direct API callers.)
    if (proxy != null) {
      let ph;
      try { ph = parseChain(String(proxy)); } catch (e) {
        return { minted: false, reason: 'mint proxy could not be parsed (' + msg(e) + ') -- mint REFUSED (fail-closed): the mint egress must be knowable exactly, cf_clearance is IP-bound' };
      }
      if (ph.length !== 1) {
        return { minted: false, reason: 'mint proxy must be exactly ONE hop (a browser rides a single --proxy-server) -- got ' + ph.length + ' -- mint REFUSED (fail-closed): minting through only the first hop would bind cf_clearance to the wrong exit IP' };
      }
    }
    const egressId = egressOpt || (proxy ? chainEgressId(String(proxy)) : 'direct');
    const chrome = resolveChrome(env !== undefined || exists !== undefined ? { chromePath, env, exists } : { chromePath });
    if (!chrome) {
      return { minted: false, reason: 'no REAL Chrome/Edge binary found (checked opts.chromePath, env CHROME_PATH, both well-known Chrome paths, both well-known Edge paths) -- cf_clearance minting needs a real browser, not a bundled Chromium; install Chrome or pass chromePath' };
    }
    // Engine cascade. An injected opts.launcher IS the patchright driver -- in 'auto'
    // mode the seam pins the engine to patchright (otherwise an injected context would be
    // silently bypassed whenever the sidecar venv is healthy on the host). 'nodriver'
    // requested-but-absent is an honest failure (never a silent fallback to the WEAKER
    // engine -- the operator asked for the strong one by name); 'auto' degrades to
    // patchright and says so through the engine label on the result.
    const pinned = (engine === 'auto' && launcher) ? 'patchright' : engine;
    if (pinned !== 'patchright') {
      const ndOpts = (env !== undefined || exists !== undefined || injectedSpawnSync !== undefined) ? { env, exists, spawnSync: injectedSpawnSync } : undefined;
      const nd = detectNodriver(ndOpts);
      if (pinned === 'nodriver' && !nd.available) {
        return { minted: false, engine: ND_ENGINE, reason: 'engine "nodriver" requested but the sidecar is unavailable: ' + (nd.reason || 'probe failed') };
      }
      if (nd.available) {
        return await mintViaNodriver(url, { zone, origin, chrome, headless, timeoutMs, userDataDir, egressId, ttlMs, vaultPath, now, nd, sidecarRun, proxy, env });
      }
    }
    const launch = launcher || defaultLauncher;
    let context;
    try {
      context = await launch({ chromePath: chrome.p, chromeVia: chrome.via, headless, userDataDir, proxy, proxyAuth });
    } catch (e) {
      return { minted: false, engine: PR_ENGINE, reason: 'browser launch failed via ' + chrome.via + ' (' + chrome.p + '): ' + msg(e) };
    }
    try {
      const page = (context.pages && context.pages()[0]) || await context.newPage();
      const deadline = Date.now() + timeoutMs;
      // A rejected goto is NOT fatal here: challenge pages redirect/reload under us;
      // the poll below is the arbiter of resolution.
      await page.goto(String(url), { waitUntil: 'domcontentloaded', timeout: Math.max(1, deadline - Date.now()) }).catch(() => null);
      const wait = await waitForResolution(page, context, origin, deadline);
      if (!wait.ok) return { minted: false, engine: PR_ENGINE, reason: wait.reason };
      const ua = await page.evaluate(() => navigator.userAgent).catch(() => null);
      if (!ua) return { minted: false, engine: PR_ENGINE, reason: 'challenge resolved but the exact User-Agent string could not be read back -- the vault key embeds sha256(ua), so an unreadable UA is an honest mint failure' };
      const cookies = await context.cookies(origin).catch(() => []);
      // HONEST MINT PROOF: ONE confirmation fetch of the zone root, inside this same
      // browser context (same cookies, same UA). minted:true ONLY if it is clean.
      const remaining = deadline - Date.now();
      if (remaining <= 0) return { minted: false, engine: PR_ENGINE, reason: 'challenge resolved but the time budget was exhausted before the confirmation fetch could run -- unproven passage, honestly reported' };
      const proofRes = await page.goto(origin + '/', { waitUntil: 'domcontentloaded', timeout: remaining }).catch(() => null);
      if (!proofRes) return { minted: false, engine: PR_ENGINE, reason: 'confirmation fetch of the zone root failed inside the minting context -- unproven passage, honestly reported', postStatus: 0 };
      const postStatus = proofRes.status();
      const gate = proofGate({ status: postStatus, headers: proofRes.headers(), body: await proofRes.text().catch(() => '') });
      if (!gate.minted) return { minted: false, engine: PR_ENGINE, reason: gate.reason, postStatus, postKind: gate.detection.kind };
      const mintedMs = now();
      const mintedAt = new Date(mintedMs).toISOString();
      const expiresAt = new Date(mintedMs + ttlMs).toISOString();
      const cur = readVault({ vaultPath, now });
      const entries = cur.ok ? cur.entries : {};
      entries[vaultKey(zone, egressId, ua)] = { cookies, ua, mintedAt, expiresAt, engine: PR_ENGINE };
      const w = writeVault(entries, { vaultPath });
      return {
        minted: true,
        engine: PR_ENGINE,
        zone,
        egressId,
        cookies,
        ua,
        mintedAt,
        expiresAt,
        postStatus,
        browserVia: chrome.via,
        egressNote: 'cf_clearance is bound to source IP + User-Agent: these cookies were minted through egressId "' + egressId + '" under UA sha256[:12] ' + vaultKey(zone, egressId, ua).split('|')[2] + '. Riding them from another exit IP invalidates them instantly -- sticky egress is mandatory. Vault TTL ' + Math.round(ttlMs / 60000) + 'min (real cf_clearance lives ~30-60min).',
        vault: w.ok ? { ok: true, path: vaultPath } : { ok: false, error: w.error },
      };
    } finally {
      await Promise.resolve(context.close && context.close()).catch(() => {});
    }
  } catch (e) {
    return { minted: false, reason: 'mintClearance failed: ' + msg(e) };
  }
}
