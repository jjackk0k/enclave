#!/usr/bin/env node
/**
 * submit-drive — VARVEL's submission driver.
 *
 * Launches a PERSISTENT Firefox profile (data/submit-profile-ff) — Playwright's
 * own Firefox build, installed via `node node_modules/playwright-core/cli.js
 * install firefox` — opens a bug-bounty submission form already authenticated
 * (after a one-time `login` per site, when a site needs one), fills every field
 * from a submission payload JSON, attaches payload files, screenshots the
 * filled form for operator review — and NEVER clicks submit. The operator's
 * hand submits; that rule is load-bearing.
 *
 * Usage:
 *   node tools/submit-drive.mjs login [wordfence|patchstack] [--edge]    # one-time per site
 *   node tools/submit-drive.mjs fill <payload.json> [--edge]             # fill + attach + screenshot, leave open
 *   node tools/submit-drive.mjs scout <form-url> [--edge]                # dump a form's field structure to .tmp
 *   node tools/submit-drive.mjs sync-firefox <host-substring> [--edge]   # import cookies from real Firefox
 *   node tools/submit-drive.mjs payload <draft.md> [--site patchstack]   # draft markdown -> payload JSON + desktop launcher
 *   node tools/submit-drive.mjs scopecheck <slug> <authlevel> <vulntype> # Patchstack June-2026 scope gate (fetches only patchstack.com)
 *   node tools/submit-drive.mjs h1sync <handle[,handle...]|all> [--edge]  # snapshot+diff H1 program policy/scope pages (through the bot-wall)
 *
 * Payload JSON shape: see .tmp/payloads/givewp-patchstack.json. Keys:
 *   site, startUrl, title, software, slug, vendor, version, vulntype, cwe,
 *   cvss, vector, description, poc, references, disclosureYes,
 *   fieldMap   { "<input name>": "value" }        — exact by-name sets, applied first
 *   selects    [ { "label": "pre-requisite", "option": "subscriber" } ]
 *   selectText { vulntype: "...", swtype: "..." } — legacy Wordfence fallback
 *   attach     [ ".tmp/givewp-poc.webm" ]          — files into the form's file input
 *   acceptTerms true                               — ticks the guidelines/terms checkbox
 *
 * --edge falls back to system Edge (channel msedge, profile data/submit-profile).
 *
 * Doctrine: if the form's DOM shape is not what the matchers expect, fields
 * land in the MISSED report — never guessed into the wrong box. The driver
 * touches only the submission site's own pages; no other hosts, no target
 * contact.
 */
import { chromium, firefox } from 'playwright-core';
import { readFileSync, mkdirSync, writeFileSync, copyFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import readline from 'node:readline';
import { DatabaseSync } from 'node:sqlite';

const FIREFOX_PROFILES = join(process.env.APPDATA || '', 'Mozilla', 'Firefox', 'Profiles');

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const SHOTS = join(ROOT, '.tmp');

const SITES = {
  wordfence: {
    home: 'https://www.wordfence.com/',
    dashboard: 'https://www.wordfence.com/researcher-dashboard/',
    cookieHost: '%wordfence.com%',
  },
  patchstack: {
    home: 'https://patchstack.com/',
    dashboard: 'https://patchstack.com/',
    cookieHost: '%patchstack.com%',
  },
  hackerone: {
    home: 'https://hackerone.com/',
    dashboard: 'https://hackerone.com/',
    cookieHost: '%hackerone.com%',
  },
};

const args = process.argv.slice(2);
const useEdge = args.includes('--edge');
const positional = args.filter(a => a !== '--edge');
const cmd = positional[0];
const arg1 = positional[1];

const ask = async q => {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(r => rl.question(q, a => { rl.close(); r(a); }));
};

async function launch() {
  if (useEdge) {
    const PROFILE = join(ROOT, 'data', 'submit-profile');
    mkdirSync(PROFILE, { recursive: true });
    return chromium.launchPersistentContext(PROFILE, {
      channel: 'msedge',
      headless: false,
      args: ['--no-first-run', '--no-default-browser-check', '--disable-session-crashed-bubble', '--start-maximized'],
      viewport: null,
    });
  }
  const PROFILE = join(ROOT, 'data', 'submit-profile-ff');
  mkdirSync(PROFILE, { recursive: true });
  return firefox.launchPersistentContext(PROFILE, {
    headless: false,
    viewport: null,
    firefoxUserPrefs: {
      'browser.shell.checkDefaultBrowser': false,
      'browser.startup.homepage': 'about:blank',
      'datareporting.policy.dataSubmissionEnabled': false,
      'app.shield.optoutstudies.enabled': false,
      'browser.discovery.enabled': false,
      'signon.rememberSignons': true,
    },
  });
}

/** Page-side helpers shared by fillEngine and the scout dump. */
function pageHelpers() {
  const norm = s => (s || '').toLowerCase().replace(/[^a-z0-9 ]/g, ' ').replace(/\s+/g, ' ').trim();
  const labelFor = el => {
    let t = '';
    if (el.id) { const l = document.querySelector(`label[for="${CSS.escape(el.id)}"]`); if (l) t += ' ' + l.textContent; }
    const p = el.closest('label'); if (p) t += ' ' + p.textContent;
    let n = el;
    for (let i = 0; i < 5 && n; i++) { n = n.parentElement; if (!n) break;
      const lab = n.querySelector(':scope > label, :scope > .label, :scope > legend, :scope > th, :scope > .form-label, :scope > [class*="label"]');
      if (lab) { t += ' ' + lab.textContent; break; } }
    t += ' ' + (el.getAttribute('placeholder') || '') + ' ' + (el.getAttribute('aria-label') || '') + ' ' + (el.name || '') + ' ' + (el.id || '');
    return norm(t);
  };
  const setVal = (el, val) => {
    const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, val);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    el.dispatchEvent(new Event('blur', { bubbles: true }));
  };
  return { norm, labelFor, setVal };
}

/** The fill engine, run INSIDE the page. Same doctrine as the bookmarklet:
 *  fieldMap by exact name first, then label-text matching, never guess.
 *  MUST stay fully self-contained — playwright serializes this function and
 *  closures do not cross into the page. */
function fillEngine() {
  const PAYLOAD = globalThis.__VARVEL_PAYLOAD;
  const norm = s => (s || '').toLowerCase().replace(/[^a-z0-9 ]/g, ' ').replace(/\s+/g, ' ').trim();
  const labelFor = el => {
    let t = '';
    if (el.id) { const l = document.querySelector(`label[for="${CSS.escape(el.id)}"]`); if (l) t += ' ' + l.textContent; }
    const p = el.closest('label'); if (p) t += ' ' + p.textContent;
    let n = el;
    for (let i = 0; i < 5 && n; i++) { n = n.parentElement; if (!n) break;
      const lab = n.querySelector(':scope > label, :scope > .label, :scope > legend, :scope > th, :scope > .form-label, :scope > [class*="label"]');
      if (lab) { t += ' ' + lab.textContent; break; } }
    t += ' ' + (el.getAttribute('placeholder') || '') + ' ' + (el.getAttribute('aria-label') || '') + ' ' + (el.name || '') + ' ' + (el.id || '');
    return norm(t);
  };
  const setVal = (el, val) => {
    const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, val);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    el.dispatchEvent(new Event('blur', { bubbles: true }));
  };
  const MATCH = [
    { key: 'title',     labels: ['vulnerability title', 'vulnerability name', 'report title', 'headline', 'title'] },
    { key: 'software',  labels: ['affected component', 'affected software', 'software name', 'plugin name', 'theme name', 'software', 'plugin', 'product'] },
    { key: 'slug',      labels: ['component slug', 'slug'] },
    { key: 'vendor',    labels: ['vendor', 'author', 'developer'] },
    { key: 'version',   labels: ['affected version', 'affected software version', 'version'] },
    { key: 'submitterName',  labels: ['submitter name', 'name or alias', 'alias', 'your name', 'researcher name', 'name'] },
    { key: 'submitterEmail', labels: ['contact e mail', 'contact email', 'e mail', 'email'] },
    { key: 'website',   labels: ['website', 'web site', 'homepage'] },
    { key: 'cwe',       labels: ['cwe'] },
    { key: 'cvss',      labels: ['cvss score', 'cvss', 'severity score', 'severity'] },
    { key: 'vector',    labels: ['vector', 'cvss vector'] },
    { key: 'references', labels: ['component link', 'reference', 'affected code', 'source', 'url'] },
    { key: 'additionalInfo', labels: ['additional information', 'additional info', 'notes', 'anything else'] },
    { key: 'description', labels: ['vulnerability description', 'description', 'details', 'summary'] },
    { key: 'poc',       labels: ['how to reproduce', 'proof of concept', 'poc', 'steps to reproduce', 'reproduction', 'reproduce', 'exploit'] },
  ];
  const filled = [], missed = [];
  const used = new Set();
  const inputs = [...document.querySelectorAll('input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=checkbox]):not([type=radio]):not([type=file]), textarea')]
    .filter(el => el.offsetParent !== null);

  // 1) Exact by-name sets from the payload's fieldMap — highest confidence.
  for (const [name, val] of Object.entries(PAYLOAD.fieldMap || {})) {
    if (!val) continue;
    const el = [...document.querySelectorAll(`[name="${CSS.escape(name)}"]`)]
      .find(e => e.offsetParent !== null && e.type !== 'hidden');
    if (!el) { missed.push('fieldMap:' + name + ' (no visible element)'); continue; }
    if (el.tagName === 'SELECT') {
      let ok = false;
      for (const opt of el.options) {
        if (norm(opt.textContent).includes(norm(val)) || norm(opt.value).includes(norm(val))) {
          el.value = opt.value; el.dispatchEvent(new Event('change', { bubbles: true })); ok = true;
          filled.push('fieldMap:' + name + ' (select) -> "' + opt.textContent.trim() + '"'); break;
        }
      }
      if (!ok) missed.push('fieldMap:' + name + ' (no matching option)');
    } else {
      try { setVal(el, val); filled.push('fieldMap:' + name); } catch (e) { missed.push('fieldMap:' + name + ' (set failed)'); }
    }
    used.add(el);
  }

  // 2) Label-text matching for everything else.
  for (const m of MATCH) {
    const val = PAYLOAD[m.key]; if (!val) continue;
    let hit = null, hitScore = 0;
    for (const el of inputs) {
      if (used.has(el)) continue;
      const lt = labelFor(el);
      for (const lab of m.labels) { if (lt.includes(lab) && lab.length > hitScore) { hit = el; hitScore = lab.length; } }
    }
    if (hit) { try { setVal(hit, val); used.add(hit); filled.push(m.key + ' -> ' + (hit.name || hit.id || hit.placeholder || hit.tagName)); } catch (e) { missed.push(m.key + ' (set failed)'); } }
    else missed.push(m.key);
  }

  // 3) Selects: payload.selects [{label, option}] — then legacy selectText map.
  const selectWants = [];
  for (const s of PAYLOAD.selects || []) selectWants.push({ key: s.label, want: s.option, guard: null });
  const SELECTTEXT = PAYLOAD.selectText || ((PAYLOAD.selects || PAYLOAD.combos) ? {} : { vulntype: 'Missing Authorization', swtype: 'Plugin' });
  for (const [key, want] of Object.entries(SELECTTEXT)) {
    selectWants.push({
      key, want,
      guard: lt => key === 'vulntype' ? (lt.includes('type') || lt.includes('weakness') || lt.includes('vulnerab'))
             : key === 'swtype' ? (lt.includes('software') || lt.includes('type')) : true,
    });
  }
  for (const s of selectWants) {
    let done = false;
    for (const sel of document.querySelectorAll('select')) {
      if (used.has(sel) || sel.offsetParent === null) continue;
      const lt = labelFor(sel);
      if (!lt.includes(norm(s.key))) continue;
      if (s.guard && !s.guard(lt)) continue;
      for (const opt of sel.options) {
        if (norm(opt.textContent).includes(norm(s.want)) || norm(opt.value).includes(norm(s.want))) {
          sel.value = opt.value; sel.dispatchEvent(new Event('change', { bubbles: true }));
          used.add(sel); filled.push('select ' + s.key + ' -> "' + opt.textContent.trim() + '"'); done = true; break;
        }
      }
      if (done) break;
    }
    if (!done) missed.push('select:' + s.key);
  }

  // 4) Wordfence disclosure radio (only when the payload asks for it).
  if (PAYLOAD.disclosureYes) {
    let done = false;
    for (const r of document.querySelectorAll('input[type=radio], input[type=checkbox]')) {
      const lt = labelFor(r);
      if ((lt.includes('disclosure') || lt.includes('responsible')) && (lt.includes('yes') || String(r.value).toLowerCase() === 'yes' || r.value === '1')) {
        r.click(); filled.push('disclosure -> Yes'); done = true; break;
      }
    }
    if (!done) missed.push('disclosure (radio)');
  }

  // 5) Guidelines/terms checkbox — the operator still reads + clicks submit.
  if (PAYLOAD.acceptTerms) {
    let done = false;
    for (const c of document.querySelectorAll('input[type=checkbox]')) {
      if (c.offsetParent === null) continue;
      const lt = labelFor(c);
      if (lt.includes('guideline') || lt.includes('terms') || lt.includes('privacy')) {
        if (!c.checked) c.click();
        filled.push('terms checkbox'); done = true; break;
      }
    }
    if (!done) missed.push('terms checkbox');
  }

  return { filled, missed, url: location.href, title: document.title };
}

async function findSubmissionForm(page) {
  // Discover the submit-form link from the Wordfence dashboard — never guessed blind.
  const links = await page.$$eval('a[href]', as => as.map(a => ({ href: a.href, text: (a.textContent || '').trim() })));
  const hit = links.find(l => /submit/i.test(l.text) && /vulnerab/i.test(l.text))
    || links.find(l => /submit/i.test(l.href) && /vulnerab/i.test(l.href))
    || links.find(l => /submit/i.test(l.text));
  if (hit) { await page.goto(hit.href, { waitUntil: 'domcontentloaded' }); return hit.href; }
  return null;
}

async function findReportEntry(page) {
  // Patchstack mVDP: the security-policy page carries a report entry point
  // (link or embedded form). Navigate to the link if present; otherwise the
  // form is assumed on-page and the caller runs the fill engine as-is.
  const links = await page.$$eval('a[href]', as => as.map(a => ({ href: a.href, text: (a.textContent || '').trim() })));
  const hit = links.find(l => /report/i.test(l.text) && /vulnerab|secur|bug/i.test(l.text))
    || links.find(l => /patchstack\.com\/report/i.test(l.href))
    || links.find(l => /\/report/i.test(l.href) && /report/i.test(l.text));
  if (hit) { await page.goto(hit.href, { waitUntil: 'domcontentloaded' }); return hit.href; }
  return null;
}

/** Custom comboboxes (role=combobox widgets, e.g. Patchstack's dropdowns) —
 *  driver-side: open by label, pick the option by text, log options on miss. */
async function fillCombos(page, combos, report) {
  for (const c of combos || []) {
    try {
      const idx = await page.evaluate(({ label }) => {
        const norm = s => (s || '').toLowerCase().replace(/[^a-z0-9 ]/g, ' ').replace(/\s+/g, ' ').trim();
        const boxes = [...document.querySelectorAll('[role=combobox]')];
        for (let i = 0; i < boxes.length; i++) {
          let t = '';
          let n = boxes[i];
          for (let k = 0; k < 4 && n; k++) { n = n.parentElement; if (!n) break;
            const lab = n.querySelector(':scope > label, :scope > .label, :scope > [class*="label"], :scope > span, :scope > p');
            if (lab) { t += ' ' + lab.textContent; break; } }
          t += ' ' + (boxes[i].getAttribute('aria-label') || '') + ' ' + (boxes[i].id || '');
          if (norm(t).includes(norm(label))) return i;
        }
        return -1;
      }, { label: c.label });
      if (idx < 0) { report.missed.push('combo:' + c.label + ' (widget not found)'); continue; }
      const box = page.locator('[role=combobox]').nth(idx);
      await box.scrollIntoViewIfNeeded();
      await box.click();
      await page.waitForTimeout(700);
      const opts = page.locator('[role=option]');
      const opt = opts.filter({ hasText: new RegExp(c.option.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i') }).first();
      if ((await opts.count()) === 0 || (await opt.count()) === 0) {
        const seen = (await opts.allTextContents()).map(t => t.trim()).filter(Boolean).slice(0, 30);
        report.missed.push('combo:' + c.label + ' (option "' + c.option + '" not found; seen: ' + (seen.join(' | ') || 'none — list did not open') + ')');
        await page.keyboard.press('Escape');
        continue;
      }
      const chosen = (await opt.textContent()).trim();
      await opt.click();
      report.filled.push('combo ' + c.label + ' -> "' + chosen + '"');
      await page.waitForTimeout(300);
    } catch (e) { report.missed.push('combo:' + c.label + ' (' + String(e.message || e).slice(0, 80) + ')'); }
  }
}

/* ------------------------------------------------------------------ */
/* Pure functions — draft parsing, mapping tables, June-2026 scope     */
/* rules. Exported for tests (test/submit-drive-payload.test.mjs);     */
/* none of these touch the network, the filesystem, or the browser.    */
/* ------------------------------------------------------------------ */

const ROLE_WORDS = /(unauthenticated|unauth|subscriber|customer|contributor|author|editor|administrator|admin)\b/i;
const normRole = w => {
  const r = String(w || '').toLowerCase();
  if (r === 'unauth' || r === 'unauthenticated') return 'unauthenticated';
  if (r === 'admin' || r === 'administrator') return 'administrator';
  return ['subscriber', 'customer', 'contributor', 'author', 'editor'].includes(r) ? r : null;
};

/** The draft's required auth level, with the evidence it was read from.
 *  Priority: PoC heading parens, title parens, an "Authentication required:"
 *  line, the first role word in the body (blockquote scope stamps excluded —
 *  they discuss scope, not the vector), then the CVSS PR: value as a heuristic. */
export function detectAuth(md) {
  const text = String(md || '');
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  const title = lines.find(l => /^#\s+/.test(l)) || '';
  const pocHead = lines.find(l => /^##\s+Proof of Concept/i.test(l)) || '';
  for (const src of [pocHead, title]) {
    for (const m of src.matchAll(/\(([^)]*)\)/g)) {
      const r = ROLE_WORDS.exec(m[1]);
      const role = r && normRole(r[1]);
      if (role) return { auth: role, evidence: `heading "${src.trim().slice(0, 90)}"` };
    }
  }
  const req = /authentication required[^a-z]*([a-z]+)/i.exec(text);
  if (req && normRole(req[1])) return { auth: normRole(req[1]), evidence: 'the "Authentication required" line' };
  const body = lines.filter(l => !l.startsWith('>')).join('\n');
  const m = /(unauthenticated|subscriber|customer|contributor|author|editor|administrator)\b/i.exec(body);
  const role = m && normRole(m[1]);
  if (role) return { auth: role, evidence: `first role word in the draft body ("${m[0]}")` };
  const pr = /PR:([NLH])/.exec(text);
  if (pr) return {
    auth: pr[1] === 'N' ? 'unauthenticated' : pr[1] === 'L' ? 'subscriber' : 'editor',
    evidence: `CVSS PR:${pr[1]} (heuristic — verify by hand)`,
  };
  return { auth: null, evidence: null };
}

/** Parse a submission draft markdown (see .tmp/wordfence-*-submission.md) into
 *  the facts the payload generator needs. Sections keep their headings verbatim. */
export function parseDraft(md) {
  const text = String(md || '').replace(/\r\n/g, '\n');
  const lines = text.split('\n');
  const titleLine = lines.find(l => /^#\s+/.test(l));
  const title = titleLine ? titleLine.replace(/^#\s+/, '').trim() : '';

  const sections = [];
  let cur = null;
  for (const l of lines) {
    const m = /^##\s+(.*)$/.exec(l);
    if (m) { cur = { heading: m[1].trim(), body: [] }; sections.push(cur); }
    else if (cur) cur.body.push(l);
  }
  const find = re => sections.find(s => re.test(s.heading));
  const render = s => ('## ' + s.heading + '\n' + s.body.join('\n')).trim();

  const bullets = {};
  const sw = find(/^Software\b/i);
  if (sw) for (const l of sw.body) {
    const b = /^[-*]\s+\*\*([^:*]+):\*\*\s*(.*)$/.exec(l.trim());
    if (b) bullets[b[1].trim().toLowerCase()] = b[2].trim();
  }
  let softwareName = bullets['name'] || '';
  let slug = '';
  const nm = /^(.*?)\s*\(([^()]*)\)\s*$/.exec(softwareName);
  if (nm) { softwareName = nm[1].trim(); slug = nm[2].trim(); }
  if (!slug && softwareName) slug = softwareName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');

  const stripMd = s => String(s || '').replace(/\*\*/g, '').replace(/`/g, '').trim();
  const vulnVersion = stripMd(bullets['affected versions']).split(' (')[0].trim();

  // shortDescription: ## Summary through ## Suggested remediation inclusive,
  // canonical section order (the PoC section may sit mid-document).
  const SHORTDESC = [/^Summary\b/i, /^Evidence\b/i, /^Impact\b/i, /^Honest bounds\b/i, /^Suggested remediation\b/i];
  const shortDescription = SHORTDESC.map(re => find(re)).filter(Boolean).map(render).join('\n\n');
  const pocSec = find(/^Proof of Concept\b/i);
  const poc = pocSec ? render(pocSec) : '';

  const affectedCode = lines
    .map(l => l.trim())
    .filter(l => /affected code|code[ -]reference/i.test(l))
    .map(l => l.replace(/^[-*]\s*/, '').replace(/\*\*/g, ''))
    .join('\n');

  const { auth, evidence } = detectAuth(text);
  return {
    title, softwareName, slug,
    vendor: bullets['vendor'] || '',
    softwareType: bullets['software type'] || '',
    affectedVersions: bullets['affected versions'] || '',
    vulnVersion,
    vulnType: stripMd(bullets['vulnerability type']),
    cwe: bullets['cwe'] || '',
    cvss: bullets['proposed cvss 3.1'] || '',
    auth, authEvidence: evidence,
    shortDescription, poc, affectedCode,
  };
}

/** The Patchstack "Pre-requisite" combo. Only Subscriber/Contributor/Editor are
 *  banked as verified option strings (data/submit-sites/patchstack.json); every
 *  other mapping returns a note so the guess is never silent. */
export function mapPrereq(auth) {
  const a = String(auth || '').toLowerCase().trim();
  const banked = { subscriber: 'Subscriber', contributor: 'Contributor', editor: 'Editor' };
  if (banked[a]) return { option: banked[a], note: null };
  if (a === 'unauthenticated') return { option: 'Unauthenticated', note: 'no banked option string for unauthenticated — trying "Unauthenticated"; if the driver MISSED-reports it, it lists the options it saw' };
  if (a === 'customer') return { option: 'Subscriber', note: 'no banked "customer" option — mapped to the closest low-privilege option "Subscriber"; verify by hand' };
  if (a === 'author') return { option: 'Author', note: '"Author" is not among the banked options — the driver will MISSED-report it if absent' };
  if (a === 'administrator') return { option: 'Administrator', note: '"Administrator" is not among the banked options — the driver will MISSED-report it if absent' };
  return { option: 'TODO(choose-prereq)', note: `auth level ${a ? `"${a}"` : 'not detected'} has no mapping — choose the Pre-requisite by hand` };
}

/** OWASP 2021 class: banked only for missing-authorization-shaped findings. */
export function mapVulnClass(vulnType) {
  const t = String(vulnType || '').toLowerCase();
  if (/missing authori|broken access|idor|insecure direct object/.test(t))
    return { option: 'A1: Broken Access Control', note: null };
  return { option: 'TODO(choose-owasp-class)', note: `no banked OWASP 2021 class mapping for "${vulnType || 'unknown'}" — choose the class by hand` };
}

/* Vulnerability type -> exact Patchstack OWASP-type option string. Order is
 * load-bearing: first match wins (e.g. "Missing Authorization / Privilege
 * Escalation" maps to Bypass Vulnerability, matching the banked doctrine). */
const TYPE_MAP = [
  [/missing authori|broken access|missing capability|missing nonce/, 'Bypass Vulnerability'],
  [/idor|insecure direct object/, 'Insecure Direct Object References (IDOR)'],
  [/stored[\s-]*xss|cross[\s-]*site scripting|\bxss\b/, 'Cross Site Scripting (XSS)'],
  [/\bsql\b|sql injection|\bsqli\b/, 'SQL Injection'],
  [/csrf|cross[\s-]*site request forgery/, 'Cross Site Request Forgery (CSRF)'],
  [/privilege escalation|privesc/, 'Privilege Escalation'],
  [/remote code execution|\brce\b/, 'Remote Code Execution (RCE)'],
  [/arbitrary code execution|\bace\b/, 'Arbitrary Code Execution'],
  [/file upload/, 'Arbitrary File Upload'],
  [/file download/, 'Arbitrary File Download'],
  [/local file inclusion|\blfi\b/, 'Local File Inclusion'],
  [/remote file inclusion|\brfi\b/, 'Remote File Inclusion'],
  [/ssrf|server[\s-]*side request forgery/, 'Server Side Request Forgery (SSRF)'],
  [/xxe|xml external/, 'XML External Entity (XXE)'],
  [/object injection/, 'PHP Object Injection'],
  [/deseriali/, 'Deserialization of untrusted data'],
  [/directory traversal|path traversal/, 'Directory Traversal'],
  [/full path disclosure|\bfpd\b/, 'Full Path Disclosure (FPD)'],
  [/open redirect|unvalidated redirect/, 'Open Redirection'],
  [/sensitive data|information disclosure|data exposure/, 'Sensitive Data Exposure'],
  [/denial of service|\bdos\b/, 'Denial of Service Attack'],
  [/crlf/, 'CRLF Injection'],
  [/csv injection/, 'CSV Injection'],
  [/session hijacking/, 'Session Hijacking'],
  [/broken authentication/, 'Broken Authentication'],
];

export function mapVulnType(vulnType, options = []) {
  const t = String(vulnType || '').toLowerCase();
  for (const [re, option] of TYPE_MAP) {
    if (re.test(t)) {
      if (options.length && !options.includes(option))
        return { option: 'TODO(choose-type)', note: `mapped "${vulnType}" -> "${option}" but that string is not in the banked option list — choose by hand` };
      return { option, note: null };
    }
  }
  return { option: 'TODO(choose-type)', note: `no OWASP type mapping for "${vulnType || 'unknown'}" — choose by hand from the banked list` };
}

/** Draft + banked site config -> Patchstack payload JSON. attach is resolved by
 *  the caller (fs); everything unmappable comes back in warnings and carries a
 *  TODO marker in the JSON — never guessed silently. */
export function buildPayload(draftInput, cfg, { attach = [] } = {}) {
  const d = typeof draftInput === 'string' ? parseDraft(draftInput) : draftInput;
  const mappings = [], warnings = [];
  const slug = d.slug;

  const fm = {
    name: cfg.identity.name,
    email: cfg.identity.email,
    comp_link: `https://wordpress.org/plugins/${slug}/`,
    vuln_version: d.vulnVersion || 'TODO(affected-versions)',
    shortDescription: d.shortDescription || 'TODO(summary)',
    reproduce: d.poc || 'TODO(poc)',
    additional_info: d.affectedCode || '',
  };
  mappings.push(`fieldMap.name/email <- config identity defaults (${fm.name} <${fm.email}>)`);
  mappings.push(`fieldMap.comp_link = ${fm.comp_link} (derived from slug "${slug}")`);
  if (d.vulnVersion) mappings.push(`fieldMap.vuln_version = "${fm.vuln_version}" (from the **Affected versions:** bullet)`);
  else warnings.push('vuln_version: no **Affected versions:** bullet found — TODO marker left in the payload');
  mappings.push(`fieldMap.shortDescription = ## Summary .. ## Suggested remediation (${fm.shortDescription.length} chars, markdown preserved)`);
  const descLimit = cfg.limits?.shortDescription;
  if (descLimit && fm.shortDescription.length > descLimit) {
    warnings.push(`shortDescription is ${fm.shortDescription.length} chars — OVER the ${descLimit}-char Patchstack limit (the form rejects it on submit). Trim the draft's Summary..Remediation sections to ~${descLimit - 150} chars and regenerate.`);
  }
  mappings.push(`fieldMap.reproduce = ## Proof of Concept (${fm.reproduce.length} chars)`);
  if (d.affectedCode) mappings.push('fieldMap.additional_info = Affected-code/code-reference line(s) from the draft');
  else mappings.push('fieldMap.additional_info = "" (no Affected-code line in the draft)');

  const prereq = mapPrereq(d.auth);
  if (prereq.note) warnings.push(`Pre-requisite: ${prereq.note}`);
  mappings.push(`combo "${cfg.combos.prereq.label}": auth ${d.auth ? `"${d.auth}"` : 'NOT DETECTED'}${d.authEvidence ? ` (${d.authEvidence})` : ''} -> "${prereq.option}"`);

  const cls = mapVulnClass(d.vulnType);
  if (cls.note) warnings.push(`OWASP class: ${cls.note}`);
  mappings.push(`combo "${cfg.combos.owaspClass.label}": "${d.vulnType || 'unknown'}" -> "${cls.option}"`);

  const typ = mapVulnType(d.vulnType, cfg.combos.owaspType.options);
  if (typ.note) warnings.push(`OWASP type: ${typ.note}`);
  mappings.push(`combo "${cfg.combos.owaspType.label}": "${d.vulnType || 'unknown'}" -> "${typ.option}"`);

  if (attach.length) mappings.push(`attach: ${attach.join(', ')}`);
  else warnings.push(`attach: no .tmp/*poc*.zip matching "${slug}" — attach by hand if a recording exists (the form takes .zip only)`);

  const payload = {
    site: 'patchstack',
    startUrl: cfg.entryUrl.replace('{slug}', slug),
    slug,
    fieldMap: fm,
    combos: [
      { label: cfg.combos.prereq.matchLabel, option: prereq.option },
      { label: cfg.combos.owaspClass.matchLabel, option: cls.option },
      { label: cfg.combos.owaspType.matchLabel, option: typ.option },
    ],
    attach,
    acceptTerms: true,
  };
  return { payload, mappings, warnings };
}

export const BAN_REMINDER = 'reports that clearly break the program rules trigger an automatic one-week ban.';

/** Patchstack scope rules (June 2026) as a pure function.
 *  In:  { mVDP: boolean, auth: 'unauthenticated'|'subscriber'|'customer'|'contributor'|'author'|'editor'|..., type: free text,
 *         impact: ''|'minor'|'significant'|'high', ac: ''|'low'|'high' }
 *  Out: { verdict: 'FILE (standard)'|'FILE (mVDP)'|'PARK'|'NO-FILE', rule: the exact rule cited }
 *  PARK = real finding, but a qualifier the rules demand is not yet demonstrated —
 *  do not file as-is. NO-FILE = clearly out of scope (ban-risk if filed).
 *  Tightened 2026-08-27 after the GiveWP rejection (§4.2 minor-impact subscriber +
 *  §4.2 cron/scheduled-task + §3.9 sensitive-objects bar) — the kill clauses below
 *  are program-wide and fire at ANY auth level. */
export function evaluateScope({ mVDP = false, auth = '', type = '', impact = '', ac = '' } = {}) {
  // VOCABULARY SEAM (2026-09-18 regression): engine/lanes.mjs speaks hyphen-form
  // class tokens ('broken-access-control') and operators type the WP jargon
  // ('unauth', 'nopriv'); this gate spoke space-form and literal 'unauthenticated'
  // only. A legitimate finding got a FALSE NO-FILE ("unauth is out of scope" —
  // self-contradictory, since the standard band INCLUDES unauthenticated) and a
  // FALSE PARK (the hyphen type fell through every bucket regex to 'unknown').
  // Normalize both to the space-form here; the accepted-type list and every
  // qualifier bar are UNCHANGED — this only fixes which bucket the text reaches.
  const normA = String(auth || '').toLowerCase().trim().replace(/[-_]+/g, '');
  const a = ({ unauth: 'unauthenticated', nopriv: 'unauthenticated', nonauthenticated: 'unauthenticated' })[normA] || normA;
  const t = String(type || '').toLowerCase().replace(/[-_]+/g, ' ');
  const im = String(impact || '').toLowerCase().trim();
  const R = (verdict, rule) => ({ verdict, rule });
  const is = re => re.test(t);

  if (String(ac).toLowerCase().trim() === 'high')
    return R('NO-FILE', 'any report involving Attack Complexity: High is OUT (June 2026 §4.2).');

  // Program-wide kill clauses (June 2026 §4.x) — detected from the type text, ANY auth level.
  if (is(/cron|scheduled task|cache clear|clear(ing)? cache|re-?order|notice dismiss/))
    return R('NO-FILE', 're-ordering data, clearing cache, or manipulating cronjobs / scheduled tasks is explicitly OUT (June 2026 §4.2) — this is the clause that killed the GiveWP pause-migration report.');
  if (is(/open redirect/))
    return R('NO-FILE', 'open redirect is inherently out of scope (June 2026 §4.9).');
  if (is(/full path disclosure|\bfpd\b|username enumerat|enumeration-only/))
    return R('NO-FILE', 'full path disclosure and enumeration-only findings are OUT (June 2026 §4.4).');
  if (is(/rate[\s-]*limit|brute[\s-]*force|captcha|ip spoof|2fa|two[\s-]*factor/))
    return R('NO-FILE', 'rate-limit/brute-force absence, CAPTCHA bypass, IP spoofing, and 2FA issues are OUT (June 2026 §4.6).');
  if (is(/\bssrf\b/))
    return R('NO-FILE', 'blind SSRF is OUT without demonstrated concrete impact (June 2026 §4.10).');
  if (is(/csv injection|css injection|clickjack/))
    return R('NO-FILE', 'CSV injection, CSS injection, and clickjacking are OUT (June 2026 §4.3/§4.5).');
  if (is(/private post|draft post|pending post|password[\s-]*protected post/))
    return R('NO-FILE', 'private/draft/pending/password-protected post disclosure is OUT (June 2026 §4.4).');
  if (is(/ai feature token|token exhaustion/))
    return R('NO-FILE', 'AI feature token exhaustion is OUT (June 2026 §4.10).');

  // Minor-impact gates (June 2026 §4.2) — apply program-wide, mVDP included.
  if ((a === 'subscriber' || a === 'customer') && im === 'minor')
    return R('NO-FILE', 'subscriber/customer findings whose impact is minor (insignificant leakage/modification/availability — the Low-CIA band, CVSS 4.3-6.3 territory) are explicitly OUT (June 2026 §4.2) — this killed the GiveWP report; a subscriber finding needs significant impact or sensitive objects.');
  if (a === 'unauthenticated' && im === 'minor')
    return R('NO-FILE', 'unauthenticated findings with a single Low CIA impact (CVSS ~5.3) are OUT (June 2026 §4.2) — evidence a bigger impact or do not file.');

  let bucket = 'unknown';
  if (is(/idor|insecure direct object/)) bucket = 'idor';
  else if (is(/\bsql\b|sql injection|\bsqli\b/)) bucket = 'sqli';
  else if (is(/missing authori|broken access|missing capability|missing nonce/)) bucket = 'bac';
  else if (is(/xss|cross[\s-]*site scripting/)) bucket = 'xss';
  else if (is(/csrf|cross[\s-]*site request forgery/)) bucket = 'csrf';
  else if (is(/privilege escalation|privesc/)) bucket = 'privesc';
  else if (is(/file upload/)) bucket = 'file-upload';
  else if (is(/file deletion|file download/)) bucket = 'file-dl-del';
  else if (is(/remote code execution|arbitrary code execution|\brce\b|\bace\b/)) bucket = 'rce';
  else if (is(/object injection|deseriali/)) bucket = 'object-injection';
  else if (is(/settings|option overwrite|config(uration)? change/)) bucket = 'settings';
  else if (is(/local file inclusion|remote file inclusion|\blfi\b|\brfi\b/)) bucket = 'lfi-rfi';
  else if (is(/denial of service|\bdos\b|deface|crash/)) bucket = 'dos';

  // Type variants that are out at ANY auth level.
  if (bucket === 'xss' && ((is(/stored/) && is(/contributor|author|editor/)) || is(/html[\s-]*only/) || (is(/reflected/) && is(/nonce/))))
    return R('NO-FILE', 'XSS is accepted only when site-wide stored or reflected with proven JS execution — contributor-stored, HTML-only, and reflected-with-nonces variants are explicitly OUT (June 2026).');

  // Auth gate: standard = unauthenticated/subscriber/customer; mVDP adds contributor.
  const stdOK = ['unauthenticated', 'subscriber', 'customer'].includes(a);
  const mvdpOK = stdOK || a === 'contributor';
  if (mVDP ? !mvdpOK : !stdOK) {
    if (!mVDP && a === 'contributor')
      return R('NO-FILE', 'standard programs accept unauthenticated/subscriber/customer findings only — contributor+ is OUT (June 2026); contributor findings file only against mVDP software.');
    return R('NO-FILE', `${mVDP ? 'mVDP reports keep contributor in scope, but' : 'standard programs accept unauthenticated/subscriber/customer only;'} "${a || 'unknown'}" is out of scope (June 2026) — findings that require this access go to direct vendor disclosure, not the bounty form.`);
  }

  // A QUALIFIER IS ONLY PRESENT IF THE TEXT DOES NOT DISCLAIM IT (2026-09-17). The bare
  // keyword tests below (`is(/full|path|extension|arbitrary/)`) matched a sentence that
  // described the qualifier as ABSENT — "file upload, whitelisted extension, fixed
  // destination path, signed-token constraints" satisfied `path` + `extension` and returned
  // FILE, when the honest reading is that the accepted qualifier ("full path+extension
  // control") is missing. A gate that can be talked into a FILE verdict by wording is a
  // fabrication enabler; the disclaimer list is checked FIRST and always wins.
  const disclaimsControl = /whitelist|allow[\s-]?list|fixed\s+(?:path|dir|directory|destination|location)|hardened|sanitiz|restrict(?:ed|s)?\s+(?:extension|type|path)|no\s+(?:path|extension|control)|lacks?\s+(?:path|extension|control)|not\s+arbitrary|cannot\s+(?:control|choose)|server[\s-]?chosen|safe[\s_-]?name/i.test(`${t} ${im}`);

  const lane = mVDP ? 'FILE (mVDP)' : 'FILE (standard)';
  switch (bucket) {
    case 'sqli': return R(lane, 'SQLi is an accepted type (June 2026).');
    case 'rce': return R(lane, 'RCE/ACE is an accepted type (June 2026).');
    case 'object-injection': return R(lane, 'PHP Object Injection is an accepted type (June 2026).');
    case 'bac': {
      const sensitive = is(/api[\s-]*key|secret|hash|backup|sql file|sensitive|significant|token|credential/);
      if (!mVDP && !sensitive)
        return R('PARK', 'broken access control in the standard program is accepted ONLY when it reaches significant/sensitive objects (API keys/secrets with demonstrated impact, password hashes, backup/SQL files — June 2026 §3.9). The GiveWP report died on this bar: name the significant object/impact in the type or do not file.');
      return R(lane, 'broken access control is an accepted type where significant/sensitive objects are affected (June 2026) — keep the impact statement prominent in the report.');
    }
    case 'idor': {
      const mvdpObjects = is(/pii|attachment|ticket|event|order|appointment/);
      if (mvdpObjects && !mVDP)
        return R('NO-FILE', 'IDOR over PII-leakage/attachments/tickets/events/orders/appointments is in scope ONLY for mVDP software (June 2026).');
      return R(lane, `IDOR is an accepted type when the impact is significant (June 2026)${mVDP ? ' — PII-leakage/attachments/tickets/events/orders/appointments qualify via the mVDP lane.' : '.'}`);
    }
    case 'file-upload':
      return !disclaimsControl && is(/full|path|extension|arbitrary/)
        ? R(lane, 'arbitrary file upload is an accepted type given full path+extension control (June 2026).')
        : R('PARK', 'arbitrary file upload is accepted ONLY with full path+extension control (June 2026) — demonstrate that control before filing. The claim is not met when the path is fixed/hardened, the extension is whitelisted, or the name is sanitized.');
    case 'file-dl-del':
      return !disclaimsControl && is(/full|path|extension|arbitrary/)
        ? R(lane, 'arbitrary file deletion/download is an accepted type given full path+extension control (June 2026).')
        : R('PARK', 'arbitrary file deletion/download is accepted ONLY with full path+extension control (June 2026) — demonstrate that control before filing. A constrained path (temp dir, fixed directory, sanitized name) does not meet it.');
    case 'settings':
      return !disclaimsControl && is(/significant|site[\s-]*wide|arbitrary/)
        ? R(lane, 'arbitrary settings change is an accepted type given significant impact (June 2026).')
        : R('PARK', 'arbitrary settings change is accepted ONLY with significant impact (June 2026) — evidence the impact before filing.');
    case 'privesc':
      return !disclaimsControl && is(/contributor|author|editor|admin/)
        ? R(lane, 'privilege escalation is an accepted type when it leads to contributor+ capabilities (June 2026).')
        : R('PARK', 'privilege escalation is accepted ONLY when it leads to contributor+ capabilities (June 2026) — state the gained role before filing.');
    case 'lfi-rfi':
      return !disclaimsControl && is(/full|arbitrary|control/)
        ? R(lane, 'LFI/RFI is an accepted type given full control over the included file (June 2026).')
        : R('PARK', 'LFI/RFI is accepted ONLY with full control over the included file (June 2026) — demonstrate that control before filing. An allow-list, a fixed suffix, or a path built server-side does not meet it.');
    case 'csrf':
      return is(/chain|settings|option|write|upload/)
        ? R(lane, 'CSRF is an accepted type when chained to an accepted write action (June 2026).')
        : R('PARK', 'CSRF is accepted ONLY when chained to an accepted write action (June 2026) — demonstrate the chain before filing.');
    case 'xss': {
      const qualified = (is(/site[\s-]*wide/) && is(/stored/)) || (is(/reflected/) && is(/js|javascript|execution/));
      return qualified
        ? R(lane, 'XSS is an accepted type when site-wide stored or reflected with proven JS execution (June 2026).')
        : R('PARK', 'XSS is accepted ONLY when site-wide stored or reflected with proven JS execution (June 2026) — qualify the variant before filing.');
    }
    case 'dos':
      return is(/whole[\s-]*site|crash|deface/)
        ? R(lane, 'DoS is an accepted type for whole-site crash/deface only (June 2026).')
        : R('PARK', 'DoS is accepted ONLY for whole-site crash/deface (June 2026) — anything narrower is out.');
    default:
      return R('PARK', `"${type}" is not recognised as an accepted scope type (June 2026 list: SQLi, arbitrary file up/del/download, RCE/ACE, PHP Object Injection, significant settings change, privesc to contributor+, full-control LFI/RFI, broken access control, significant IDOR, chained CSRF, qualifying XSS, whole-site DoS) — reframe to an accepted type before filing.`);
  }
}

/** Banked per-site form facts (data/submit-sites/<site>.json). */
function loadSiteConfig(site) {
  const p = join(ROOT, 'data', 'submit-sites', `${site}.json`);
  if (!existsSync(p)) { console.error(`[submit-drive] no banked site config at data/submit-sites/${site}.json`); process.exit(1); }
  return JSON.parse(readFileSync(p, 'utf8'));
}

/** Desktop launcher, same shape as VARVEL-2-submit-GiveWP-PATCHSTACK.bat. */
function launcherBat(title, payloadRel) {
  return [
    '@echo off',
    `title VARVEL submit-drive — ${title} submission on PATCHSTACK (Firefox)`,
    `cd /d "${ROOT}"`,
    'echo.',
    'echo  Firefox will open the Patchstack report form PRE-FILLED.',
    'echo  1. Read the filled form in Firefox.',
    'echo  2. Click Submit in Firefox when you are happy.',
    'echo  3. Come back here and press Enter to close the driver.',
    'echo.',
    `"C:\\Program Files\\nodejs\\node.exe" tools\\submit-drive.mjs fill ${payloadRel.replace(/\//g, '\\')}`,
    'echo.',
    'pause',
    '',
  ].join('\r\n');
}

/* Run the command dispatch only when executed directly — the pure functions
 * above are imported by tests, and an import must not fire the CLI. */
const IS_MAIN = !!process.argv[1] && resolve(process.argv[1]).toLowerCase() === fileURLToPath(import.meta.url).toLowerCase();

if (IS_MAIN && cmd === 'payload') {
  // Draft markdown -> Patchstack payload JSON + desktop launcher, wired to the
  // banked site config. Every mapping is printed; anything unmappable gets a
  // loud TODO marker in the JSON — never guessed silently.
  if (!arg1) { console.error('[submit-drive] payload needs a draft markdown path'); process.exit(1); }
  const siteIdx = positional.indexOf('--site');
  const siteName = siteIdx >= 0 ? positional[siteIdx + 1] : 'patchstack';
  const cfg = loadSiteConfig(siteName);
  const draft = parseDraft(readFileSync(resolve(arg1), 'utf8'));
  if (!draft.slug) { console.error('[submit-drive] could not parse a component slug from the draft (**Name:** line) — aborting'); process.exit(1); }
  const squash = s => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const nameSq = squash((draft.softwareName || '').split(' ')[0]);
  const zips = readdirSync(SHOTS).filter(f => /poc/i.test(f) && /\.zip$/i.test(f)
    && (squash(f).includes(squash(draft.slug)) || (nameSq.length >= 4 && squash(f).includes(nameSq))));
  const { payload, mappings, warnings } = buildPayload(draft, cfg, { attach: zips.map(f => '.tmp/' + f) });
  mkdirSync(join(SHOTS, 'payloads'), { recursive: true });
  const out = join(SHOTS, 'payloads', `${draft.slug}-patchstack.json`);
  writeFileSync(out, JSON.stringify(payload, null, 2) + '\n');
  const batPath = join(process.env.USERPROFILE || ROOT, 'Desktop', `VARVEL-submit-${draft.slug}.bat`);
  writeFileSync(batPath, launcherBat(draft.softwareName || draft.slug, `.tmp/payloads/${draft.slug}-patchstack.json`));
  console.log(`[submit-drive] draft: ${arg1}  (software: ${draft.softwareName || '?'}, slug: ${draft.slug})`);
  console.log(`[submit-drive] payload  -> ${out}`);
  console.log(`[submit-drive] launcher -> ${batPath}`);
  console.log('[submit-drive] MAPPINGS:');
  mappings.forEach(m => console.log('   ✓', m));
  if (warnings.length) {
    console.log(`[submit-drive] NEEDS A HUMAN (${warnings.length}):`);
    warnings.forEach(w => console.log('   ✗', w));
  }
  console.log(`[submit-drive] next: double-click the launcher (or: node tools/submit-drive.mjs fill .tmp/payloads/${draft.slug}-patchstack.json). The driver fills but NEVER submits.`);
} else if (IS_MAIN && cmd === 'scopecheck') {
  // Offline-decidable scope gate: the only network touch is fetching the
  // software's own patchstack.com policy page to detect mVDP membership.
  // Usage: scopecheck <slug> <authlevel> <vulntype> [--impact minor|significant|high] [--ac low|high]
  const flagVal = f => { const i = positional.indexOf(f); return i >= 0 ? positional[i + 1] : ''; };
  const impact = flagVal('--impact'), ac = flagVal('--ac');
  const bare = positional.filter((p, i) => p !== '--impact' && p !== '--ac' && positional[i - 1] !== '--impact' && positional[i - 1] !== '--ac');
  const slug = bare[1], auth = bare[2], type = bare.slice(3).join(' ');
  if (!slug || !auth || !type) { console.error('[submit-drive] scopecheck needs <slug> <authlevel> <vulntype> [--impact minor|significant|high] [--ac low|high]'); process.exit(1); }
  if (!/^[a-z0-9][a-z0-9-]*$/i.test(slug)) { console.error('[submit-drive] bad slug:', slug); process.exit(1); }
  const cfg = loadSiteConfig('patchstack');
  let mVDP = false, source = null;
  for (const u of [cfg.securityPolicyUrl, cfg.vdpUrl].map(u => u.replace('{slug}', slug))) {
    try {
      const res = await fetch(u, { headers: { 'user-agent': 'varvel-submit-drive scopecheck' } });
      if (!res.ok) { console.log(`[submit-drive] ${u} -> HTTP ${res.status}`); continue; }
      const body = (await res.text()).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').toLowerCase();
      mVDP = body.includes('official vulnerability disclosure program');
      source = u;
      break;
    } catch (e) { console.log(`[submit-drive] fetch failed: ${u} (${String(e.message || e).slice(0, 80)})`); }
  }
  if (!source) console.log('[submit-drive] could not reach patchstack.com — assuming NOT mVDP (conservative; re-run when online to confirm)');
  const r = evaluateScope({ mVDP, auth, type, impact, ac });
  console.log(`[submit-drive] scopecheck: ${slug} | auth=${auth} | type="${type}"${impact ? ` | impact=${impact}` : ''}${ac ? ` | ac=${ac}` : ''}`);
  console.log(`[submit-drive] mVDP membership: ${mVDP ? 'YES' : 'NO'}${source ? ` (per ${source})` : ' (assumed)'}`);
  console.log(`[submit-drive] VERDICT: ${r.verdict}`);
  console.log(`[submit-drive] rule: ${r.rule}`);
  console.log('[submit-drive] reminder:', BAN_REMINDER);
} else if (IS_MAIN && cmd === 'scout') {
  // Dump a form's structure (fields, labels, select options, custom widgets)
  // so payload fieldMaps/selects can be built from facts, not guesses.
  if (!arg1) { console.error('[submit-drive] scout needs a form URL'); process.exit(1); }
  const ctx = await launch();
  const page = ctx.pages()[0] || await ctx.newPage();
  await page.goto(arg1, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(2500);
  const dump = await page.evaluate(ph => {
    const { norm, labelFor } = eval(`(${ph})`)();
    const fields = [];
    for (const el of document.querySelectorAll('input, textarea, select')) {
      if (el.type === 'hidden') continue;
      fields.push({
        tag: el.tagName.toLowerCase(), type: el.type || null, name: el.name || null, id: el.id || null,
        placeholder: el.getAttribute('placeholder'), label: labelFor(el), visible: el.offsetParent !== null,
        value: el.tagName === 'SELECT' ? undefined : (el.value || '').slice(0, 80),
        options: el.tagName === 'SELECT' ? [...el.options].map(o => o.textContent.trim()) : undefined,
      });
    }
    const custom = [...document.querySelectorAll('[role=combobox], [role=listbox], [role=button], [contenteditable=true]')]
      .map(el => ({ role: el.getAttribute('role') || (el.contentEditable === 'true' ? 'contenteditable' : null), text: (el.textContent || '').trim().slice(0, 100), cls: String(el.className).slice(0, 80) }));
    return { url: location.href, title: document.title, fields, custom };
  }, pageHelpers.toString());
  mkdirSync(SHOTS, { recursive: true });
  writeFileSync(join(SHOTS, 'submit-drive-scout.json'), JSON.stringify(dump, null, 2));
  await page.screenshot({ path: join(SHOTS, 'submit-drive-scout.png'), fullPage: true });
  console.log('[submit-drive] scout dump -> .tmp/submit-drive-scout.json (+ .png)');
  console.log('[submit-drive] fields:', dump.fields.length, '| custom widgets:', dump.custom.length, '|', dump.url);
  await ctx.close();
} else if (IS_MAIN && cmd === 'sync-firefox') {
  // Pull a site's session cookies out of the operator's REAL Firefox profile
  // into the driver profile — can replace the manual login step. Local-only:
  // the cookie DB is copied to temp first (Firefox holds a lock), read, and
  // only cookie NAMES are ever logged — values never leave the machine.
  const hostSub = arg1 || 'wordfence.com';
  const cookieHost = `%${hostSub.replace(/%/g, '')}%`;
  const profiles = readdirSync(FIREFOX_PROFILES)
    .map(d => join(FIREFOX_PROFILES, d, 'cookies.sqlite'))
    .filter(p => existsSync(p));
  if (!profiles.length) { console.error('[submit-drive] no Firefox profile with cookies.sqlite found under', FIREFOX_PROFILES); process.exit(1); }
  const pick = profiles.find(p => p.includes('default-release')) || profiles[profiles.length - 1];
  const tmp = join(tmpdir(), 'varvel-ff-cookies-copy.sqlite');
  copyFileSync(pick, tmp);
  const db = new DatabaseSync(tmp, { readOnly: true });
  const rows = db.prepare("SELECT host, name, value, path, expiry, isSecure, isHttpOnly, sameSite FROM moz_cookies WHERE host LIKE ?").all(cookieHost);
  db.close();
  if (!rows.length) { console.error(`[submit-drive] no ${hostSub} cookies in Firefox profile — log into ${hostSub} in Firefox first, then re-run sync-firefox`); process.exit(1); }
  const sameSite = v => (v === 1 ? 'Lax' : v === 2 ? 'Strict' : undefined);
  const cookies = rows.map(r => ({
    name: r.name, value: r.value, domain: r.host, path: r.path || '/',
    expires: (r.expiry > 0 ? Math.round(r.expiry / (r.expiry > 1e11 ? 1000 : 1)) : -1), secure: !!r.isSecure, httpOnly: !!r.isHttpOnly,
    ...(sameSite(r.sameSite) ? { sameSite: sameSite(r.sameSite) } : {}),
  }));
  const ctx = await launch();
  await ctx.addCookies(cookies);
  const page = ctx.pages()[0] || await ctx.newPage();
  await page.goto(`https://${hostSub.replace(/^\.?/, '')}/`, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(2500);
  const title = await page.title();
  const shot = join(SHOTS, 'submit-drive-sync-check.png');
  mkdirSync(SHOTS, { recursive: true });
  await page.screenshot({ path: shot });
  const loggedIn = rows.some(r => /^(wordpress_logged_in|wordfence_central_api_session|wfwaf-authcookie|patchstack)/i.test(r.name));
  console.log('[submit-drive] imported', cookies.length, hostSub, 'cookies from Firefox (', pick, ')');
  console.log('[submit-drive] cookie names:', rows.map(r => r.name).join(', '));
  console.log('[submit-drive] session-looking cookie present:', loggedIn ? 'YES' : 'LIKELY NO — verify in the screenshot');
  console.log('[submit-drive] page title after sync:', JSON.stringify(title), '| screenshot:', shot);
  await ctx.close();
  if (!loggedIn) process.exit(1);
} else if (IS_MAIN && cmd === 'login') {
  const site = SITES[arg1] || SITES.wordfence;
  const ctx = await launch();
  const page = ctx.pages()[0] || await ctx.newPage();
  await page.goto(site.home, { waitUntil: 'domcontentloaded' });
  console.log(`[submit-drive] ${useEdge ? 'Edge' : 'Firefox'} is open on ${site.home} — register/log in there (researcher account).`);
  await ask('[submit-drive] Press Enter here once you are logged in... ');
  await page.goto(site.dashboard, { waitUntil: 'domcontentloaded' }).catch(() => {});
  const shot = join(SHOTS, 'submit-drive-login-check.png');
  mkdirSync(SHOTS, { recursive: true });
  await page.screenshot({ path: shot, fullPage: false });
  console.log(`[submit-drive] session saved to ${useEdge ? 'data/submit-profile' : 'data/submit-profile-ff'}. Login check screenshot:`, shot);
  console.log('[submit-drive] page title now:', await page.title());
  await ctx.close();
} else if (IS_MAIN && cmd === 'fill') {
  if (!arg1) { console.error('[submit-drive] fill needs a payload JSON path'); process.exit(1); }
  const payload = JSON.parse(readFileSync(resolve(arg1), 'utf8'));
  // IDENTIFIER GUARD (house rule 2026-08-29 — a submitted report leaked the string
  // "varvel" twice: once in prose, once via a reflected probe origin in the evidence
  // attachment). Outbound prose AND text attachments must never contain it.
  const IDENT_RE = /\bvarvel\b/i;
  const outbound = [payload.h1Title, payload.title, payload.description, payload.impact,
    ...Object.values(payload.fieldMap || {}), ...Object.values(payload.selectText || {})]
    .filter(v => typeof v === 'string');
  for (const p of payload.attach || []) {
    const ap = resolve(ROOT, p);
    if (/\.(txt|md|log|json|csv)$/i.test(p) && existsSync(ap)) outbound.push(readFileSync(ap, 'utf8'));
  }
  const leak = outbound.find(v => IDENT_RE.test(v));
  if (leak) {
    const i = leak.search(IDENT_RE);
    console.error('[submit-drive] REFUSED: submission material names the identifier "varvel" (house rule — scrub before filling). Context: ' + JSON.stringify(leak.slice(Math.max(0, i - 50), i + 50)));
    process.exit(1);
  }
  const site = SITES[payload.site] || SITES.wordfence;
  const ctx = await launch();
  const page = ctx.pages()[0] || await ctx.newPage();
  let formUrl;
  if (payload.site === 'patchstack') {
    await page.goto(payload.startUrl || site.home, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(1500);
    formUrl = await findReportEntry(page);
    if (!formUrl) formUrl = page.url(); // form may be embedded on the policy page
  } else if (payload.startUrl) {
    // Direct form URL (e.g. HackerOne report assistant) — the payload says where.
    await page.goto(payload.startUrl, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2500);
    formUrl = page.url();
  } else {
    await page.goto(site.dashboard, { waitUntil: 'domcontentloaded' });
    formUrl = await findSubmissionForm(page);
  }
  if (!formUrl) {
    const shot = join(SHOTS, 'submit-drive-noform.png');
    await page.screenshot({ path: shot });
    console.error('[submit-drive] could not find the submission form — screenshot:', shot);
    console.error('[submit-drive] page title:', await page.title(), '| url:', page.url());
    await ctx.close();
    process.exit(2);
  }
  await page.waitForTimeout(1500);
  await page.evaluate(p => { globalThis.__VARVEL_PAYLOAD = p; }, payload);
  const report = await page.evaluate(`(${fillEngine.toString()})()`);
  // Custom combobox dropdowns (role=combobox) are handled driver-side.
  await fillCombos(page, payload.combos, report);
  // HackerOne report-assistant title: a borderless, nameless textarea — set by
  // exclusion (named description/impact fields and the Hai chat box skipped).
  if (payload.h1Title) {
    const titleOk = await page.evaluate(t => {
      const skip = el => el.name === 'report-intent-description' || el.name === 'report-intent-impact'
        || /ask a question/i.test(el.getAttribute('placeholder') || '');
      const el = [...document.querySelectorAll('textarea')].find(e => e.offsetParent !== null && !skip(e));
      if (!el) return false;
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(el, t);
      for (const ev of ['input', 'change', 'blur']) el.dispatchEvent(new Event(ev, { bubbles: true }));
      return true;
    }, payload.h1Title);
    (titleOk ? report.filled : report.missed).push('h1Title' + (titleOk ? '' : ' (no title textarea found)'));
  }
  // File attachments happen on the driver side (setInputFiles works even on
  // visually-hidden inputs). Never attempted inside the page.
  if (payload.attach && payload.attach.length) {
    const fi = await page.$('input[type=file]');
    if (fi) {
      const paths = payload.attach.map(p => resolve(ROOT, p));
      for (const p of paths) { if (!existsSync(p)) { report.missed.push('attach (missing file): ' + p); } }
      const existing = paths.filter(p => existsSync(p));
      if (existing.length) { await fi.setInputFiles(existing); report.filled.push('attach -> ' + existing.map(p => p.split(/[\\/]/).pop()).join(', ')); }
    } else report.missed.push('attach (no file input on form)');
  }
  const stamp = (payload.slug || 'submission').replace(/[^a-z0-9-]/gi, '_');
  const shot = join(SHOTS, `submit-drive-${stamp}-filled.png`);
  await page.screenshot({ path: shot, fullPage: true });
  writeFileSync(join(SHOTS, `submit-drive-${stamp}-report.json`), JSON.stringify(report, null, 2));
  console.log('[submit-drive] form:', formUrl);
  console.log('[submit-drive] FILLED (' + report.filled.length + '):'); report.filled.forEach(x => console.log('   ✓', x));
  console.log('[submit-drive] MISSED (' + report.missed.length + '):'); report.missed.forEach(x => console.log('   ✗', x, ' <- fill by hand'));
  console.log('[submit-drive] screenshot:', shot);
  if (payload.site === 'hackerone') console.log('[submit-drive] H1: click "Run checks" (Hai) before Submit and reconcile its severity/weakness suggestions — score the AFFECTED SURFACE + victim pool (CVSS), not what was demonstrated pre-auth; honesty lives in the scope-of-proof section, never in a deflated score.');
  console.log('[submit-drive] REVIEW IN THE BROWSER, then click Submit yourself. The driver never submits. Browser stays open.');
  if (process.env.VARVEL_FILL_NO_WAIT) {
    // Hidden/detached launch (no console to answer a prompt in): stay up until the
    // operator closes the browser window — that close IS the signal.
    console.log('[submit-drive] VARVEL_FILL_NO_WAIT set — driver stays up until the browser window is closed.');
    await new Promise(r => ctx.on('close', r));
  } else {
    await ask('[submit-drive] Press Enter here after you have submitted (or abandoned) to close the driver... ');
  }
  await ctx.close();
} else if (IS_MAIN && cmd === 'h1sync') {
  // h1sync — see THROUGH the Cloudflare wall with the same persistent Firefox the
  // submission lanes use: snapshot each HackerOne program's PUBLIC policy+scope page
  // and diff against the previous snapshot. Up-to-date program intel without the API
  // token (public pages need no login). Navigation only — never interacts, never
  // submits; human cadence between programs. A challenge/blocked page is reported
  // honestly as blocked and NEVER overwrites the last good snapshot.
  const SNAPDIR = join(ROOT, 'data', 'bountyline', 'h1sync');
  mkdirSync(SNAPDIR, { recursive: true });
  let handles = (arg1 || '').split(',').map(s => s.trim()).filter(Boolean);
  if (arg1 === 'all' || !handles.length) {
    try {
      const roster = JSON.parse(readFileSync(join(ROOT, 'data', 'bountyline', 'roster.json'), 'utf8'));
      handles = (roster.programs || []).map(p => p.handle).filter(h => h && h !== 'wordfence-madara'); // the madara lane is not an H1 program
    } catch { handles = []; }
    if (!handles.length) { console.error('[submit-drive] h1sync needs <handle[,handle...]> or a populated bountyline roster'); process.exit(1); }
  }
  const ctx = await launch();
  // Cloudflare's managed challenge keys on automation tells — scrub the one flag
  // Playwright can't hide otherwise. (No deeper shims: over-spoofing breaks CF's
  // attestation MORE than it helps.)
  await ctx.addInitScript(() => { Object.defineProperty(navigator, 'webdriver', { get: () => undefined }); });
  const page = ctx.pages()[0] || await ctx.newPage();
  const loadCleared = async (url, handle) => {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 45000 });
    // Challenge handling: poll up to ~150s. The interstitial often auto-passes on
    // its own; if it does not, the visible window lets the OPERATOR solve it once —
    // the cf_clearance cookie then persists in the driver profile (IP-bound: a VPN
    // exit change invalidates it, re-solve is one click). `sync-firefox hackerone.com`
    // seeds the profile from the operator's real browser — the proven path.
    let announced = false;
    for (let waited = 0; waited < 150000; waited += 5000) {
      await page.waitForTimeout(5000);
      const t = await page.title().catch(() => '');
      if (!/just a moment|attention required/i.test(t)) return t;
      if (!announced) { console.log('[h1sync] Cloudflare challenge on screen for ' + handle + ' — auto-waiting up to 150s; the operator may solve it in the open window (one click, saved to the profile)'); announced = true; }
    }
    return page.title().catch(() => '');
  };
  const bodyText = () => page.evaluate(() => ((document.body && document.body.innerText) || '').replace(/\s+/g, ' ').trim().slice(0, 40000));
  for (const handle of handles) {
    // H1's canonical URLs (the security.txt convention): the program ROOT carries the
    // scope table, ?view_policy=true the policy text. /policy 404s (found 2026-08-27).
    // Text-level diffing is honest but over-signals: page chrome (nav, activity feed)
    // churns between runs — treat CHANGED as "look closer", not as proof of a scope edit.
    const url = `https://hackerone.com/${handle}`;
    const priorPath = join(SNAPDIR, `${handle}.json`);
    let prior = null;
    try { prior = JSON.parse(readFileSync(priorPath, 'utf8')); } catch {}
    let snap = { handle, url, fetchedAt: new Date().toISOString(), blocked: false };
    try {
      snap.title = await loadCleared(url, handle);
      snap.scopeText = await bodyText();
      await page.waitForTimeout(1500);
      await loadCleared(`${url}?view_policy=true`, handle);
      snap.policyText = await bodyText();
      const txt = (snap.policyText || '') + '\n' + (snap.scopeText || '');
      snap.idGate = /identity verification|id[- ]verified|verify your identity/i.test(txt) ? 'mentioned-in-policy' : 'not-mentioned';
      if (/page not found|evaded detection/i.test(txt)) snap.blocked = true;
      if (/just a moment|attention required/i.test(snap.title || '')) snap.blocked = true;
    } catch (e) {
      snap.blocked = true; snap.error = String((e && e.message) || e).slice(0, 200);
    }
    const diff = { policyChanged: null, scopeChanged: null };
    if (prior && !snap.blocked) {
      if (prior.policyText) diff.policyChanged = prior.policyText !== snap.policyText;
      if (prior.scopeText) diff.scopeChanged = prior.scopeText !== snap.scopeText;
    }
    snap.diff = diff;
    if (!snap.blocked) writeFileSync(priorPath, JSON.stringify(snap, null, 2));
    console.log(`[h1sync] ${handle}: ${snap.blocked ? 'BLOCKED (' + (snap.error || snap.title) + ') — last good snapshot kept' : `id-gate ${snap.idGate}, policy ${diff.policyChanged === null ? 'first-snapshot' : diff.policyChanged ? 'CHANGED' : 'unchanged'}, scope ${diff.scopeChanged === null ? 'first-snapshot' : diff.scopeChanged ? 'CHANGED' : 'unchanged'}`}`);
    await page.waitForTimeout(2500); // human cadence between programs
  }
  console.log('[h1sync] snapshots ->', SNAPDIR);
  await ctx.close();
} else if (IS_MAIN) {
  console.log('usage: node tools/submit-drive.mjs login [wordfence|patchstack] [--edge] | fill <payload.json> [--edge] | scout <form-url> [--edge] | sync-firefox <host> [--edge] | payload <draft.md> [--site patchstack] | scopecheck <slug> <authlevel> <vulntype> | h1sync <handle[,handle...]|all> [--edge]');
  process.exit(1);
}
