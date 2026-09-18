// VARVEL — the EXTERNAL STATE STORE: structured, provenance-tracked engagement knowledge.
// The governed agent's conversation memory fades past a handful of steps, and everything it
// "knows" past that lives only in prose history — which is exactly how false-positive claims
// once survived a whole engagement. This store is the fix: hosts / creds / sessions /
// findings as QUERYABLE entities with provenance on every write, file-backed per engagement
// (same VARVEL_DATA_DIR discipline + hash-disambiguated keys as engine/store.mjs — this
// module complements that ledger, it does not replace it), and SELECTIVELY INJECTED into
// the agent's brief via briefSlice() so the model trusts structured state over its memory.
//
// OPSEC (absolute): cred.secret and session token/cookie values NEVER appear in briefSlice
// output, in reports, or in any API response — redact() is the only shape that leaves this
// module toward anything external-facing. The ONE reveal path is the operator-side CLI
// (`state cred <key> --reveal`), which prints to stdout once.
//
// Validation vocabulary is the validator gate's (engine/validator.mjs): a finding is
// 'claimed' (default — asserted, not yet reproduced), 'validated', 'refuted', or
// 'untestable'. REFUTED findings stay OUT of the brief (disproven is the gate's point);
// they remain queryable here.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { dataDir } from './store.mjs';

// store.mjs keeps these two helpers private — duplicated here, byte-for-byte in behavior.
const ensure = () => { const DIR = dataDir(); if (!existsSync(DIR)) mkdirSync(DIR, { recursive: true }); return DIR; };
const key = (s) => String(s || 'engagement').replace(/[^a-z0-9._-]/gi, '_').slice(0, 40) + '-' + createHash('sha1').update(String(s || 'engagement')).digest('hex').slice(0, 8);
const readJson = (p, fb) => { try { return existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : fb; } catch { return fb; } };

export const KINDS = ['hosts', 'creds', 'sessions', 'findings'];
export const ACTORS = ['ai', 'operator', 'tool'];
// Validation states, per engine/validator.mjs ('claimed' = asserted, not yet put through the gate).
export const VALIDATION_STATES = ['claimed', 'validated', 'refuted', 'untestable'];
// Field names that redact() blanks on EVERY external-facing shape — reserved vocabulary.
export const SECRET_FIELDS = ['secret', 'token', 'cookie'];
export const REDACTED = '[REDACTED]';

const emptyState = () => ({ hosts: [], creds: [], sessions: [], findings: [], notes: [] });
const stateFile = (engagement) => join(dataDir(), key(engagement) + '.state.json');

export function loadState(engagement) {
  const st = readJson(stateFile(engagement), null);
  return st && typeof st === 'object' ? { ...emptyState(), ...st } : null;
}

function saveState(engagement, st) {
  ensure();
  writeFileSync(stateFile(engagement), JSON.stringify(st, null, 2));
}

const norm = (s) => String(s == null ? '' : s).trim().toLowerCase();

// Deterministic dedup keys per kind (no prefixes — collections are already separate, and a
// typable key is what the operator passes to `state cred <key> --reveal`).
export function dedupKey(kind, e) {
  switch (kind) {
    case 'hosts': return norm(e.ip) || norm(e.label);
    case 'creds': return norm(e.kind) + '|' + norm(e.principal);
    case 'sessions': return norm(e.kind) + '|' + norm(e.subject);
    case 'findings': return norm(e.ref) || norm(e.title) + '|' + norm(e.host);
    default: throw new TypeError('unknown state kind: ' + kind);
  }
}

const assertKind = (kind) => { if (!KINDS.includes(kind)) throw new TypeError('unknown state kind: ' + kind); };
// Host lists ACCUMULATE across scans (a re-scan adds a service, it doesn't erase the rest).
const UNION_FIELDS = new Set(['hosts.services', 'hosts.tech', 'hosts.notes']);

// Upsert with deterministic dedup: a repeat key UPDATES in place — firstSeen is preserved,
// lastSeen moves to the latest sighting, and provenance records the LATEST writer.
// prov = { sourceTool, actor: 'ai'|'operator'|'tool', ts }; ts doubles as the sighting time
// (defaults to now), so a writer that observed something earlier can say so honestly.
export function upsert(engagement, kind, entity, prov = {}) {
  assertKind(kind);
  if (!entity || typeof entity !== 'object') throw new TypeError(kind + ' upsert needs an entity object');
  if (kind === 'findings' && entity.validation != null && !VALIDATION_STATES.includes(entity.validation)) {
    throw new TypeError('finding validation must be one of ' + VALIDATION_STATES.join(', '));
  }
  const st = loadState(engagement) || emptyState();
  const coll = st[kind];
  const k = dedupKey(kind, entity);
  if (!k || k === '|') throw new TypeError(kind + ' upsert needs its dedup fields (host: ip; cred: kind+principal; session: kind+subject; finding: ref or title+host)');
  const now = new Date().toISOString();
  const ts = prov.ts || now;
  const provenance = { engagement, sourceTool: prov.sourceTool || null, ts, actor: ACTORS.includes(prov.actor) ? prov.actor : 'ai' };
  const ix = coll.findIndex((e) => e.key === k);
  if (ix === -1) {
    const fresh = { ...entity, key: k, firstSeen: ts, lastSeen: ts, provenance };
    if (kind === 'findings' && fresh.validation == null) fresh.validation = 'claimed'; // asserted, not yet through the gate
    coll.push(fresh);
    saveState(engagement, st);
    return fresh;
  }
  const prev = coll[ix];
  const merged = { ...prev };
  for (const [f, v] of Object.entries(entity)) {
    if (v === undefined) continue;
    merged[f] = UNION_FIELDS.has(kind + '.' + f)
      ? [...new Set([...(Array.isArray(prev[f]) ? prev[f] : []), ...(Array.isArray(v) ? v : [v])])]
      : v;
  }
  merged.key = k;
  merged.firstSeen = prev.firstSeen || ts;
  merged.lastSeen = ts;
  merged.provenance = provenance;
  coll[ix] = merged;
  saveState(engagement, st);
  return merged;
}

// One entity by dedup key, FULL record (secrets included — this is the store's internal
// read; anything external-facing goes through redact()).
export function get(engagement, kind, entityKey) {
  assertKind(kind);
  const st = loadState(engagement);
  if (!st) return null;
  const k = norm(entityKey);
  return st[kind].find((e) => norm(e.key) === k) || null;
}

// Simple filters: a plain object is top-level field equality; a function is a predicate.
export function query(engagement, kind, filter) {
  assertKind(kind);
  const st = loadState(engagement);
  if (!st) return [];
  const items = st[kind];
  if (!filter) return items;
  if (typeof filter === 'function') return items.filter(filter);
  return items.filter((e) => Object.entries(filter).every(([f, v]) => e[f] === v));
}

export function stateCounts(engagement) {
  const st = loadState(engagement);
  const zero = { hosts: 0, creds: 0, sessions: 0, findings: 0, notes: 0 };
  if (!st) return zero;
  return { hosts: st.hosts.length, creds: st.creds.length, sessions: st.sessions.length, findings: st.findings.length, notes: st.notes.length };
}

// Operator/AI note into the engagement's bounded notes list (not part of the brief tiers).
export function addNote(engagement, text, prov = {}) {
  const st = loadState(engagement) || emptyState();
  const now = new Date().toISOString();
  const note = {
    text: String(text || '').slice(0, 1000),
    ts: prov.ts || now,
    provenance: { engagement, sourceTool: prov.sourceTool || null, ts: prov.ts || now, actor: ACTORS.includes(prov.actor) ? prov.actor : 'operator' },
  };
  st.notes = [...st.notes, note].slice(-200); // bounded, like the failure ledger
  saveState(engagement, st);
  return note;
}

// The ONLY shape allowed toward anything external-facing (brief lines are built from meta
// directly; API/report payloads must use this). Secrets become the REDACTED mark — visible
// withholding, never the value.
export function redact(entity) {
  if (!entity || typeof entity !== 'object') return entity;
  const out = { ...entity };
  for (const f of SECRET_FIELDS) if (out[f] != null) out[f] = REDACTED;
  return out;
}

export function redactState(st) {
  if (!st) return null;
  return {
    hosts: st.hosts.map(redact),
    creds: st.creds.map(redact),
    sessions: st.sessions.map(redact),
    findings: st.findings.map(redact),
    notes: st.notes,
  };
}

const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1, informational: 1 };
const sevRank = (s) => SEV_RANK[String(s || '').toLowerCase()] || 0;
const newest = (a, b) => String(b.lastSeen || '').localeCompare(String(a.lastSeen || ''));
const srcOf = (e) => (e.provenance && (e.provenance.sourceTool || e.provenance.actor)) || 'unknown';
const isLive = (s) => s.alive !== false && !(s.expiresAt && Number.isFinite(Date.parse(s.expiresAt)) && Date.parse(s.expiresAt) <= Date.now());

// The selective injector: what the agent's brief gets, in strict priority order —
//   (1) live sessions, (2) creds (META ONLY), (3) validated findings,
//   (4) claimed findings still needing the validator gate, (5) hosts summary.
// Highest-severity / newest first within a tier; HARD stop at charBudget with a
// '+N more (use: state <kind>)' trailer naming the first omitted tier. Provenance tags on
// every line ([validated]/[claimed], [source:cfride]). Secrets NEVER appear.
export function briefSlice(engagement, charBudget = 1200) {
  const budget = Math.max(0, Number(charBudget) || 0);
  const st = loadState(engagement);
  if (!st) return '';

  const tiers = []; // [{ kind, lines: [string] }] in priority order
  const sessions = st.sessions.filter(isLive).sort(newest);
  if (sessions.length) {
    tiers.push({
      kind: 'sessions',
      lines: sessions.map((s) => `session ${s.kind || 'session'} -> ${s.subject || '?'}${s.egress ? ` (egress ${s.egress})` : ''}${s.expiresAt ? `, expires ${s.expiresAt}` : ''} [source:${srcOf(s)}]`),
    });
  }
  const creds = [...st.creds].sort(newest);
  if (creds.length) {
    tiers.push({
      kind: 'creds',
      lines: [
        ...creds.map((c) => `cred ${c.kind || 'cred'}/${c.principal || '?'}${c.scope ? ` (scope: ${c.scope})` : ''} [source:${srcOf(c)}]`),
        'cred secrets are withheld from this brief — the operator retrieves one with: state cred <kind|principal> --reveal',
      ],
    });
  }
  const findings = [...st.findings].sort((a, b) => sevRank(b.sev) - sevRank(a.sev) || newest(a, b));
  const fline = (f, tag) => `finding [${tag}]${f.sev ? ` [${String(f.sev).toLowerCase()}]` : ''} ${f.title || '(untitled)'}${f.host ? ` @ ${f.host}` : ''}${f.ref ? ` (${f.ref})` : ''} [source:${srcOf(f)}]`;
  const validated = findings.filter((f) => f.validation === 'validated');
  if (validated.length) tiers.push({ kind: 'findings', lines: validated.map((f) => fline(f, 'validated')) });
  // Refuted/untestable findings are deliberately NOT in the brief: refuted is disproven
  // (the gate's whole point), untestable honestly can't be confirmed — both stay queryable.
  const claimed = findings.filter((f) => !f.validation || f.validation === 'claimed');
  if (claimed.length) tiers.push({ kind: 'findings', lines: claimed.map((f) => fline(f, 'claimed')) });
  const hosts = [...st.hosts].sort(newest);
  if (hosts.length) {
    tiers.push({
      kind: 'hosts',
      lines: hosts.map((h) => `host ${h.ip || h.label || '?'}${h.ip && h.label && h.label !== h.ip ? ` (${h.label})` : ''} — ${(h.services || []).length ? h.services.slice(0, 6).join(', ') : 'no services recorded'}${(h.tech || []).length ? `; tech: ${h.tech.slice(0, 4).join(', ')}` : ''} [source:${srcOf(h)}]`),
    });
  }

  const flat = [];
  for (const t of tiers) for (const line of t.lines) flat.push({ kind: t.kind, line });
  if (!flat.length) return '';

  const picked = [];
  let used = 0;
  for (const { line } of flat) {
    const add = (picked.length ? 1 : 0) + line.length; // +1 for the joining newline
    if (used + add > budget) break;
    picked.push(line);
    used += add;
  }
  if (picked.length === flat.length) return picked.join('\n');

  const trailer = () => `+${flat.length - picked.length} more (use: state ${flat[picked.length].kind})`;
  let t = trailer();
  while (picked.length && used + 1 + t.length > budget) { used -= picked.pop().length + 1; t = trailer(); }
  const out = picked.length ? picked.join('\n') + '\n' + t : t;
  return out.length <= budget ? out : out.slice(0, budget); // a budget smaller than the trailer itself still holds the cap
}
