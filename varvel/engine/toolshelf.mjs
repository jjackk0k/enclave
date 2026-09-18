// VARVEL — the tool shelf: persistence for tools the AI writes on the fly.
//
// Jack's ask: a governed agent writes genuinely useful tooling mid-engagement (the k2.7
// breach run wrote six Python scripts: recon, token forgers, admin fetchers) — and all of
// it used to VANISH with the session workspace. The shelf keeps them: cataloged,
// attributed, and promotable into VARVEL's native toolset.
//
// GOVERNANCE (load-bearing, do not soften):
//   · Shelf entries are DATA, never code VARVEL executes. Nothing on the shelf is
//     auto-run, auto-imported, or auto-wired into a campaign — ever.
//   · Status lifecycle: QUARANTINED (as written by the agent) → PROMOTED (a human said
//     this one is worth review) → native (a manual, reviewed port into tools/ — done by
//     Jack or Kimi with tests, not by the shelf).
//   · Promotion is a logged OPERATOR action (who/when), never an agent action.
//   · Content is capped + stored verbatim (no eval, no transform) with a sha256 so the
//     reviewed bytes are provably the bytes the agent wrote.

import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_SHELF = join(dirname(fileURLToPath(import.meta.url)), '..', 'tools', 'shelf');
// Resolved LAZILY per call — tests set VARVEL_SHELF_DIR to a temp dir, and ESM import
// hoisting means a module-load-time constant would capture the env before the test sets it.
const shelfDir = () => process.env.VARVEL_SHELF_DIR || DEFAULT_SHELF;
const INDEX = () => join(shelfDir(), 'index.json');
const MAX_FILE_BYTES = 256 * 1024;
const MAX_FILES = 20;
const KINDS = ['recon', 'offensive', 'utility', 'exploit-aid', 'analysis'];
// Exported so the campaign's auto-shelve (engine/campaign.mjs _shelveScratchTools) can
// coerce agent-declared kinds to the shelf's own vocabulary instead of guessing it.
export const SHELF_KINDS = KINDS;

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

function loadIndex() {
  try { return JSON.parse(readFileSync(INDEX(), 'utf8')); } catch { return { entries: [] }; }
}
function saveIndex(idx) {
  mkdirSync(shelfDir(), { recursive: true });
  writeFileSync(INDEX(), JSON.stringify(idx, null, 2));
}

// Shelve an AI-written tool. `entry`: { name, kind, description, files: [{name, content}],
// origin: { agent, session } }. Returns the stored entry (with id + sha256s), or throws.
export function shelveTool({ name, kind = 'utility', description = '', files = [], origin = {} } = {}) {
  if (!name || !/^[\w][\w ().-]{0,60}$/.test(String(name))) throw new TypeError('shelveTool: a safe short name is required');
  if (!KINDS.includes(kind)) throw new TypeError('shelveTool: kind must be one of ' + KINDS.join(', '));
  if (!Array.isArray(files) || !files.length) throw new TypeError('shelveTool: at least one file is required');
  if (files.length > MAX_FILES) throw new TypeError('shelveTool: too many files (max ' + MAX_FILES + ')');

  const idx = loadIndex();
  const id = String(name).toLowerCase().replace(/[^\w]+/g, '-').replace(/^-+|-+$/g, '') + '-' + Date.now().toString(36);
  const dir = join(shelfDir(), id);
  mkdirSync(dir, { recursive: true });

  const stored = [];
  for (const f of files) {
    const fname = String((f && f.name) || '');
    if (!/^[\w.-]+$/.test(fname)) throw new TypeError('shelveTool: unsafe file name ' + JSON.stringify(fname));
    const content = String((f && f.content) ?? '');
    if (Buffer.byteLength(content) > MAX_FILE_BYTES) throw new TypeError('shelveTool: file too large: ' + fname);
    writeFileSync(join(dir, fname), content);
    stored.push({ name: fname, bytes: Buffer.byteLength(content), sha256: sha256(content) });
  }

  const entry = {
    id, name: String(name), kind, description: String(description).slice(0, 500),
    status: 'quarantined', // DATA ONLY — never executed by VARVEL
    origin: { agent: origin.agent || 'unknown', session: origin.session || null, at: origin.at || new Date().toISOString() },
    files: stored,
    promoted: null,
  };
  idx.entries.push(entry);
  saveIndex(idx);
  return entry;
}

// List shelf entries (metadata only — file bytes stay on disk).
export function shelfList() {
  return loadIndex().entries.map((e) => ({ ...e, dir: 'tools/shelf/' + e.id }));
}

// Read one shelved file's content back (for review or a manual native port).
export function shelfRead(id, fileName) {
  if (!/^[\w.-]+$/.test(String(fileName || ''))) throw new TypeError('shelfRead: unsafe file name');
  const p = join(shelfDir(), String(id || ''), fileName);
  if (!existsSync(p)) return null;
  return readFileSync(p, 'utf8');
}

// Promote an entry: a HUMAN decision, logged with who/when. Promotion means "worth a
// reviewed native port" — it never makes VARVEL execute the shelved bytes.
export function promoteTool(id, { by = 'operator', note = '' } = {}) {
  const idx = loadIndex();
  const e = idx.entries.find((x) => x.id === id);
  if (!e) return null;
  e.status = 'promoted';
  e.promoted = { by: String(by).slice(0, 80), note: String(note).slice(0, 300), at: new Date().toISOString() };
  saveIndex(idx);
  return e;
}
