#!/usr/bin/env node
// scaffold.mjs — spin up a ready-to-work Enclave workspace from a preset.
//
// Instead of configuring egress, clearance, and writing scope/checklist docs by
// hand, an operator picks a preset and passes their project info; this generates
// the workspace config the platform enforces PLUS the starter docs, pre-filled.
//
//   node scaffold.mjs --preset red-team --name northwind-q3 \
//       --client "Northwind Traders" --scope "10.10.0.0/16,10.20.0.0/24" --lead "M. Vale"
//
//   node scaffold.mjs --list          # show available presets
//
// Pure Node, no dependencies.

import { mkdirSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const TEMPLATES = join(HERE, 'templates');

function parseArgs(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      const k = argv[i].slice(2);
      const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true';
      a[k] = v;
    }
  }
  return a;
}
const args = parseArgs(process.argv.slice(2));
const fail = m => { console.error('scaffold: ' + m); process.exit(1); };

const available = readdirSync(TEMPLATES).filter(f => f.endsWith('.mjs')).map(f => f.replace('.mjs', ''));
if (args.list || (!args.preset && !args.name)) {
  console.log('\n  Available presets:');
  for (const id of available) {
    const p = (await import(pathToFileURL(join(TEMPLATES, id + '.mjs')).href)).default;
    console.log(`    • ${id.padEnd(20)} ${p.title}`);
  }
  console.log('\n  Usage: node scaffold.mjs --preset <id> --name <workspace> [--<param> <value> ...]\n');
  process.exit(0);
}

if (!args.preset) fail(`need --preset <id>  (one of: ${available.join(', ')})`);
if (!args.name) fail('need --name <workspace-name>');

let preset;
try { preset = (await import(pathToFileURL(join(TEMPLATES, args.preset + '.mjs')).href)).default; }
catch (e) { fail(`unknown preset "${args.preset}" (${e.message})`); }

// Build the fill context: name/date/workload + preset params (with defaults).
const ctx = { name: args.name, date: new Date().toISOString().slice(0, 10), workload: preset.workload, title: preset.title };
for (const p of preset.params || []) {
  const v = args[p.key] ?? p.default;
  if (v === undefined && p.required) fail(`preset "${preset.id}" needs --${p.key}  (${p.prompt})`);
  ctx[p.key] = v ?? '';
}
if (ctx.scope !== undefined)
  ctx.scopeJsonArray = JSON.stringify(String(ctx.scope).split(',').map(s => s.trim()).filter(Boolean));

const fill = tpl => tpl.replace(/\{\{(\w+)\}\}/g, (_, k) => (k in ctx ? String(ctx[k]) : `«FILL:${k}»`));

const outDir = args.out || join(HERE, 'workspaces', args.name);
if (existsSync(outDir) && args.force !== 'true') fail(`output ${outDir} already exists (pass --force to overwrite)`);
mkdirSync(outDir, { recursive: true });

const written = [];
for (const [fname, tpl] of Object.entries(preset.docs)) {
  writeFileSync(join(outDir, fname), fill(tpl));
  written.push(fname);
}

// workspace.json — the environment config the platform ENFORCES (clearance/cert
// gate, egress policy, tool shelf). This is what the enforcement seam reads.
const workspace = {
  name: args.name,
  preset: preset.id,
  workload: preset.workload,
  createdAt: ctx.date,
  requires: preset.requires,
  egress: { ...preset.egress },
  tools: preset.tools,
  project: Object.fromEntries((preset.params || []).map(p => [p.key, ctx[p.key]])),
};
if (ctx.scope) workspace.egress.scope = String(ctx.scope).split(',').map(s => s.trim()).filter(Boolean);
writeFileSync(join(outDir, 'workspace.json'), JSON.stringify(workspace, null, 2) + '\n');
written.push('workspace.json');

console.log(`\n  ✓ Scaffolded "${args.name}" from preset "${preset.title}"`);
console.log(`  → ${outDir}`);
for (const f of written) console.log(`     • ${f}`);
const cert = preset.requires.anyCert ? `, cert ∈ {${preset.requires.anyCert.join(', ')}}` : '';
console.log(`\n  Enforced environment: workload=${preset.workload}, clearance ≥ L${preset.requires.clearance}${cert},`);
console.log(`  egress=deny-all (+${(preset.egress.allow || []).length} allowlisted).  Docs are pre-filled — start work now.\n`);
