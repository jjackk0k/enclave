#!/usr/bin/env node
/**
 * pocvid — VARVEL's scriptable PoC video recorder.
 *
 * Bounty forms keep demanding a reproduction video (Patchstack: zipped; Wordfence:
 * attached). Hand-recording every PoC doesn't scale — this records a DETERMINISTIC
 * run: a JSON step file drives a headless Firefox through the exact reproduction
 * (login as the low-priv user, fire the request, show the effect), and the run is
 * saved as .tmp/<name>.webm (+ optional .zip for Patchstack's archive-only uploads).
 * Re-runnable at review time: the same steps always produce the same video.
 *
 * Usage:
 *   node tools/pocvid.mjs <steps.json> [--out name] [--zip]
 *
 * Steps JSON:
 *   { "startUrl": "http://127.0.0.1:8081/", "viewport": [1280, 800],
 *     "steps": [ { "goto": "http://..." }, { "fill": ["#user", "subscriber"] },
 *                { "click": "#wp-submit" }, { "wait": 1500 }, { "waitFor": "selector" },
 *                { "eval": "window.scrollTo(0,0)" }, { "note": "what the viewer should see now" } ] }
 *
 * Doctrine: the recorder captures exactly what the steps do — nothing is staged,
 * cropped, or edited after the fact; a falsified PoC video is a fabricated finding
 * with extra pixels. Sandbox/local targets are the normal subject; the operator
 * REVIEWS the .webm before it attaches to any payload. --zip shells out to
 * PowerShell Compress-Archive (Windows host, same as past Patchstack packs).
 */
import { firefox } from 'playwright-core';
import { readFileSync, mkdirSync, readdirSync, renameSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const OUT = join(ROOT, '.tmp');

const args = process.argv.slice(2);
const positional = args.filter(a => !a.startsWith('--'));
const flag = (n) => { const i = args.indexOf('--' + n); return i >= 0 ? args[i + 1] : undefined; };
const stepsFile = positional[0];
if (!stepsFile) { console.error('usage: node tools/pocvid.mjs <steps.json> [--out name] [--zip]'); process.exit(1); }
const wantZip = args.includes('--zip');

const spec = JSON.parse(readFileSync(resolve(stepsFile), 'utf8'));
if (!spec.startUrl || !Array.isArray(spec.steps)) { console.error('[pocvid] steps JSON needs { startUrl, steps[] }'); process.exit(1); }
const name = (flag('out') || 'poc').replace(/[^a-z0-9-]/gi, '_');
const [vw, vh] = Array.isArray(spec.viewport) ? spec.viewport : [1280, 800];

const browser = await firefox.launch({ headless: true });
const ctx = await browser.newContext({
  viewport: { width: vw, height: vh },
  recordVideo: { dir: join(OUT, 'pocvid-raw'), size: { width: vw, height: vh } },
  ignoreHTTPSErrors: true, // sandbox self-signed certs are the normal case
});
const page = await ctx.newPage();
page.setDefaultTimeout(15000);

const fail = async (msg) => { console.error('[pocvid] FAILED:', msg); try { await ctx.close(); } catch {} await browser.close(); process.exit(2); };

await page.goto(spec.startUrl, { waitUntil: 'domcontentloaded' }).catch(e => fail('startUrl: ' + e.message));
let n = 0;
for (const s of spec.steps) {
  n++;
  try {
    if (s.goto) await page.goto(s.goto, { waitUntil: 'domcontentloaded' });
    else if (s.fill) await page.fill(s.fill[0], String(s.fill[1]));
    else if (s.click) await page.click(s.click);
    else if (s.wait) await page.waitForTimeout(Number(s.wait));
    else if (s.waitFor) await page.waitForSelector(s.waitFor);
    else if (s.eval) await page.evaluate(s.eval);
    else if (s.note) { await page.waitForTimeout(1200); console.log('[pocvid] step', n, 'note:', s.note); }
    else console.log('[pocvid] step', n, 'unknown op — skipped (honestly logged):', JSON.stringify(s).slice(0, 80));
  } catch (e) { await fail(`step ${n} (${JSON.stringify(s).slice(0, 80)}): ${e.message}`); }
}
await page.waitForTimeout(1500); // settle tail — last effect must be visibly on screen

mkdirSync(OUT, { recursive: true });
const video = page.video();
await ctx.close(); // close FLUSHES the recording
await browser.close();

const rawPath = await video.path().catch(() => null);
if (!rawPath || !existsSync(rawPath)) { console.error('[pocvid] no video produced — recordVideo unsupported in this build?'); process.exit(2); }
const finalPath = join(OUT, name + '.webm');
renameSync(rawPath, finalPath);
console.log('[pocvid] recorded', spec.steps.length, 'steps ->', finalPath);

if (wantZip) {
  const zipPath = join(OUT, name + '.zip');
  try {
    execFileSync('powershell', ['-NoProfile', '-Command', `Compress-Archive -LiteralPath '${finalPath}' -DestinationPath '${zipPath}' -Force`], { stdio: 'pipe' });
    console.log('[pocvid] zipped for Patchstack ->', zipPath);
  } catch (e) { console.error('[pocvid] zip failed (video still saved):', String((e && e.message) || e).slice(0, 120)); }
}
console.log('[pocvid] REVIEW the video before it attaches to any payload.');
