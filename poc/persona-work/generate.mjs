// generate.mjs — produce a deliverable BEFITTING a persona.
// Loads the operator's signed session, builds the same read-only context the model
// gets, and generates a role- and clearance-appropriate deliverable — offline by
// default, or via a live Claude call (through the broker pattern) when a key is set.
//
//   node generate.mjs --persona dana
//   node generate.mjs --persona marcus --task "plan week one of the engagement"
//   ANTHROPIC_API_KEY=… node generate.mjs --persona dana --live

import { readFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { DIRECTORY } from '../enforcement-seam/policy-engine.mjs';
import { capabilities, buildContext } from '../enforcement-seam/session-context.mjs';
import { verifySession } from '../enforcement-seam/util.mjs';
import { generate as generateOffline } from './templates.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SESS = join(HERE, '..', 'enforcement-seam', 'session');
const NAMES = { sam: 'Sam Reeve', priya: 'Priya Nair', dana: 'Dana Okoye', marcus: 'Marcus Vale', ravi: 'Ravi Shah', alex: 'Alex Chen' };

function whoFor(principal) {
  const e = DIRECTORY.find(x => x.uid.type === 'User' && x.uid.id === principal);
  return e ? { ...e.attrs, name: NAMES[principal] || principal } : null;
}

export async function produce(personaId, { task, live } = {}) {
  let session;
  try { session = JSON.parse(readFileSync(join(SESS, personaId + '.json'), 'utf8')); }
  catch { throw new Error(`no session for persona "${personaId}"`); }
  if (!verifySession(session)) throw new Error('session signature invalid — fail-closed');
  const who = whoFor(session.principal);
  if (!who) throw new Error('unknown principal');

  const caps = capabilities(session);
  const context = buildContext(session);
  const t = task || 'Produce your first deliverable for this workspace.';
  const key = process.env.ANTHROPIC_API_KEY;

  let deliverable, source;
  if (live && key) {
    const { generateLive } = await import('./live.mjs');
    deliverable = await generateLive({ context, task: t, key });
    source = 'live-claude';
  } else {
    deliverable = generateOffline({ who, session, caps, task: t });
    source = live ? 'offline (no ANTHROPIC_API_KEY — set it + --live for a live model)' : 'offline-generator';
  }
  return { who, session, caps, context, deliverable, source, keyPresent: !!key };
}

// ---- CLI ----
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = {};
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) if (argv[i].startsWith('--')) { const k = argv[i].slice(2); const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true'; args[k] = v; }
  if (!args.persona) { console.error('usage: node generate.mjs --persona <sam|dana|marcus|priya|ravi|alex> [--task "…"] [--live]'); process.exit(1); }

  produce(args.persona, { task: args.task, live: 'live' in args })
    .then(r => {
      const outDir = mkdtempSync(join(tmpdir(), `enclave-work-${args.persona}-`));
      const outFile = join(outDir, r.deliverable.filename);
      writeFileSync(outFile, r.deliverable.markdown);
      console.log(`\n[${r.source}]  ${r.who.name} · L${r.who.clearance} ${r.who.role}  →  "${r.deliverable.title}"`);
      console.log(`written: ${outFile}\n`);
      console.log(r.deliverable.markdown);
    })
    .catch(e => { console.error('generate: ' + e.message); process.exit(1); });
}
