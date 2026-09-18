// AXIOM SOC — the deterministic blue-team core (advisory AI voice lives elsewhere).
//
// The next realism tier for the Axiom practice target: a mini security team. The RULES
// are code, not a model — an attacker's input can never talk this core into blinding
// itself. What it does (the human-SOC playbook, deterministic):
//
//   · burst behavior  → TEMP-BAN the source (lockout page + Retry-After)
//   · repeated WAF blocks from one source → STRICT mode (their rate limit tightens)
//   · admin-action anomaly (an admin-class write with a token the server never issued —
//     the exact shape of a FORGED session) → ALERT, investigate… and on the third strike
//     ROTATE THE SIGNING KEY — every previously-leaked/forged token dies on the spot.
//
// The leak-trap is deliberate: the legacy bundle still serves the OLD key, so an attacker
// mid-chain suddenly finds their forgeries rejected and must figure out why. Speed now
// matters, and VARVEL's watchdog can see the defender adapting — the honest next tier.
//
// All thresholds injectable; `now` injectable for hermetic tests. Emits every decision
// to onEvent (the SOC console / audit). Holds NO secrets (rotation events carry the new
// key VERSION, never the key).

export function makeSoc({
  onEvent,
  rotateKey,
  now = () => Date.now(),
  banThreshold = 3,        // rate-limit trips within the window → temp-ban
  strictThreshold = 3,     // WAF blocks within the window → strict mode
  rotateThreshold = 2,     // anomalous admin strikes → key rotation (v2: a real SOC doesn't wait for 3)
  rotationLagMs = 30_000,  // the SOC's response lag — a FAST attacker still escapes inside it
  windowMs = 5 * 60_000,
  banMs = 120_000,
  strictMs = 10 * 60_000,
} = {}) {
  const events = []; // ring buffer, capped
  const emit = (type, obj = {}) => {
    const ev = { type, at: new Date(now()).toISOString(), ...obj };
    events.push(ev);
    if (events.length > 200) events.shift();
    try { onEvent && onEvent(type, ev); } catch {}
    return ev;
  };

  const rateTrips = new Map();  // ip -> [ts]
  const wafBlocks = new Map();  // ip -> [ts]
  const banned = new Map();     // ip -> untilTs
  const strict = new Map();     // ip -> untilTs
  const interactiveLogins = new Set(); // ips with a REAL interactive login this instance
  let anomalies = 0;
  let rotations = 0;
  let pendingRotation = 0;     // ts at which a triggered rotation actually takes effect (response lag)

  const prune = (arr, t) => arr.filter((x) => t - x < windowMs);

  // Called when the target rate-limits an IP (429).
  function observeRateLimited(ip) {
    const t = now();
    const arr = prune(rateTrips.get(ip) || [], t);
    arr.push(t);
    rateTrips.set(ip, arr);
    if (arr.length >= banThreshold && !(banned.get(ip) > t)) {
      banned.set(ip, t + banMs);
      emit('ban', { ip, until: new Date(t + banMs).toISOString(), reason: 'repeated rate-limit violations' });
    }
  }

  // Called when the WAF signature-blocks an IP (403).
  function observeWafBlock(ip) {
    const t = now();
    const arr = prune(wafBlocks.get(ip) || [], t);
    arr.push(t);
    wafBlocks.set(ip, arr);
    if (arr.length >= strictThreshold && !(strict.get(ip) > t)) {
      strict.set(ip, t + strictMs);
      emit('strict', { ip, until: new Date(t + strictMs).toISOString(), reason: 'repeated hostile signatures' });
    }
  }

  // Interactive logins: an IP with a real login this instance. The IMPOSSIBLE-SESSION signal
  // (v2): an admin-class action from an IP that NEVER logged in = a confirmed forgery shape.
  function observeLogin(ip) { if (ip) interactiveLogins.add(ip); }
  function hasInteractiveLogin(ip) { return interactiveLogins.has(ip); }

  // Called on an admin-class action. `registered` = the token is one the server issued.
  // A valid-signature token the server never minted = a FORGED session — the SOC's cue.
  // v2: no-interactive-login adds a second strike on the spot; rotation triggers at the
  // threshold and takes effect AFTER the response lag (the SOC responds on its own clock).
  function observeAdminAnomaly({ ip, registered } = {}) {
    if (registered) return null;
    const t = now();
    tick(); // fire any pending rotation whose lag expired
    anomalies++;
    const impossible = !interactiveLogins.has(ip);
    if (impossible) anomalies++;
    const etype = impossible ? 'anomaly.impossible-session' : 'anomaly';

    if (anomalies >= rotateThreshold && !pendingRotation && typeof rotateKey === 'function') {
      pendingRotation = t + rotationLagMs;
      emit('rotate.pending', { ip, anomalies, impossible, effectiveAt: new Date(pendingRotation).toISOString(), note: 'forged-session pattern confirmed — rotating the signing key in ' + Math.round(rotationLagMs / 1000) + 's (SOC response time)' });
      return { rotated: false, pending: true };
    }
    emit(etype, { ip, anomaly: anomalies, impossible, status: pendingRotation ? 'rotation pending' : 'investigating', note: impossible ? 'admin-class action from an IP with NO interactive login — forgery shape confirmed' : 'admin-class action with a non-issued token (forgery shape)' });
    return { rotated: false };
  }

  // The SOC's clock: fires a triggered rotation once its lag has expired. Called on every
  // request + observe — deterministic, no timers.
  function tick() {
    const t = now();
    if (pendingRotation && t >= pendingRotation && typeof rotateKey === 'function') {
      pendingRotation = 0;
      rotations++;
      const version = rotateKey();
      emit('rotate', { anomalies, keyVersion: version, note: 'signing key rotated — previously leaked/forged credentials are now dead' });
      return true;
    }
    return false;
  }

  // Request-entry gate: banned → short-circuit; strict → tighten their budget.
  function check(ip) {
    const t = now();
    if ((banned.get(ip) || 0) > t) return { action: 'ban', retryAfter: Math.ceil((banned.get(ip) - t) / 1000) };
    return null;
  }
  function rateLimitFor(ip, base) {
    const t = now();
    return (strict.get(ip) || 0) > t ? Math.max(5, Math.floor(base / 3)) : base;
  }

  // Deterministic incident summary — the analyst's baseline voice, no model required.
  function summary() {
    if (!events.length) return 'SOC: quiet — no alerts this window.';
    const by = {};
    for (const e of events) by[e.type] = (by[e.type] || 0) + 1;
    const parts = Object.entries(by).map(([k, n]) => `${n} ${k}`).join(', ');
    const last = events[events.length - 1];
    const posture = rotations ? 'KEY ROTATED — previously leaked credentials are dead'
      : (banned.size || strict.size) ? 'active countermeasures in effect' : 'investigating';
    return `SOC: ${events.length} alert(s) (${parts}). Latest: ${last.type} @ ${last.at}. Posture: ${posture}.`;
  }

  return {
    observeRateLimited, observeWafBlock, observeAdminAnomaly, observeLogin, hasInteractiveLogin, check, rateLimitFor, tick,
    alerts: () => events.slice(),
    summary,
    state: () => ({ anomalies, rotations, rotationPending: pendingRotation > now() ? new Date(pendingRotation).toISOString() : false, bannedNow: [...banned.keys()].filter((ip) => banned.get(ip) > now()), strictNow: [...strict.keys()].filter((ip) => strict.get(ip) > now()) }),
  };
}
