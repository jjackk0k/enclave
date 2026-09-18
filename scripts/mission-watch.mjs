// mission-watch.mjs — polls VARVEL /api/state and appends NEW activity events to
// scripts/mission-feed.jsonl so Kimi can read the mission ledger without hammering
// the console. Dedupes by seq. Also snapshots opsec + status transitions.
import { appendFileSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = dirname(fileURLToPath(import.meta.url));
const FEED = join(dir, 'mission-feed.jsonl');
const CURSOR = join(dir, 'mission-cursor.json');
const API = 'http://127.0.0.1:8971/api/state';

let last = { seq: 0, status: '' };
if (existsSync(CURSOR)) { try { last = JSON.parse(readFileSync(CURSOR, 'utf8')); } catch {} }

async function tick() {
  try {
    const r = await fetch(API, { signal: AbortSignal.timeout(5000) });
    const j = await r.json();
    const acts = Array.isArray(j.activity) ? j.activity : [];
    const fresh = acts.filter((a) => (a.seq || 0) > last.seq);
    for (const a of fresh) {
      appendFileSync(FEED, JSON.stringify({ t: a.at, seq: a.seq, kind: a.kind, data: a.data }) + '\n');
      last.seq = Math.max(last.seq, a.seq || 0);
    }
    if (j.status && j.status !== last.status) {
      appendFileSync(FEED, JSON.stringify({ t: new Date().toISOString(), seq: -1, kind: 'watch.status', data: { status: j.status } }) + '\n');
      last.status = j.status;
    }
    if (fresh.length || j.status !== last.status) writeFileSync(CURSOR, JSON.stringify(last));
  } catch (e) {
    appendFileSync(FEED, JSON.stringify({ t: new Date().toISOString(), seq: -2, kind: 'watch.error', data: String(e && e.message || e) }) + '\n');
  }
}
writeFileSync(FEED, ''); // fresh feed for this mission
setInterval(tick, 15000);
tick();
console.log('mission-watch polling every 15s ->', FEED);
