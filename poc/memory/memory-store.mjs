// memory-store.mjs — GOVERNED AI memory. Persistent memory is valuable (the AI
// remembers the engagement) but, done naively, it moves sensitive data across the
// isolation boundary and invites memory-poisoning. So this store enforces:
//   • scope     — a memory is tagged (workspace, clearance); recall only returns
//                 memories in YOUR workspace, at or below YOUR clearance.
//   • DLP       — writes that look like secrets or raw dumps are refused (memory is
//                 for notes/summaries, not exfiltrated source or credentials).
//   • audit     — every write is hash-chained + tamper-evident.
//   • inert     — memory is DATA. It never enters an authorization decision, so a
//                 poisoned "grant admin" note can't escalate anything.
// node:crypto only.

import { createHash } from 'node:crypto';

const SECRET_RE = /(sk-[a-z0-9-]{6,}|-----BEGIN|AKIA[0-9A-Z]{16}|(?:api[_-]?key|password|secret|token)\s*[:=]\s*\S|[A-Za-z0-9+/]{200,})/i;
const MAX_LEN = 2000;

export class GovernedMemory {
  constructor() { this.entries = []; this._tip = 'GENESIS'; }

  /** who = { clearance }, session = { principal, workspace }. Returns {ok, reason?}. */
  remember({ session, who, text, tags = [], ts = '' }) {
    if (SECRET_RE.test(text)) return { ok: false, reason: 'DLP: looks like a secret/credential — memory is for notes, not raw sensitive data' };
    if (text.length > MAX_LEN) return { ok: false, reason: 'DLP: too large — memory is for summaries, not raw dumps' };
    const body = { seq: this.entries.length, workspace: session.workspace, clearance: who.clearance, principal: session.principal, text, tags, ts };
    const hash = createHash('sha256').update(this._tip + JSON.stringify(body)).digest('hex');
    this.entries.push({ ...body, prev: this._tip, hash });
    this._tip = hash;
    return { ok: true, hash };
  }

  /** Scope-enforced recall. Never returns another workspace's or a higher clearance's memory. */
  recall({ session, who, query = '' }) {
    const q = query.toLowerCase();
    return this.entries.filter(e =>
      e.workspace === session.workspace &&
      who.clearance >= e.clearance &&
      (!q || e.text.toLowerCase().includes(q) || e.tags.some(t => String(t).toLowerCase().includes(q))));
  }

  /** Hash-chain integrity (detects any edit/reorder/deletion). */
  verifyIntegrity() {
    let prev = 'GENESIS';
    for (const e of this.entries) {
      const { hash, prev: p, ...body } = e;
      const h = createHash('sha256').update(prev + JSON.stringify(body)).digest('hex');
      if (h !== hash || p !== prev) return false;
      prev = hash;
    }
    return true;
  }
}
