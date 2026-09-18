// VARVEL — novelgate: the pre-submission NOVELTY GATE (the network half).
// Born 2026-08-31 from HackerOne semrush #2666357 closed DUPLICATE: we filed CORS
// origin-reflection + ACAO:credentials on admin.semrush.net, but the behavior was the
// Google IAP edge gate's own unauthenticated challenge (x-goog-iap-generated-response:
// true on a 302), no authenticated data was ever read cross-origin, and the program
// already knew. This tool makes that class of wasted submission structurally hard:
//
//   node tools/novelgate.mjs check --program semrush --host admin.semrush.net \
//        --weakness "cors" --draft .tmp/<draft>.md [--status 302 --headers hdrs.json] \
//        [--signature "google iap cors reflect"] [--annotate] [--json]
//
// WHAT IT DOES (in order):
//   1. HACKTIVITY DUPLICATE SEARCH — queries HackerOne's PUBLIC disclosed-reports surface
//      (the hacktivity GraphQL search, unauthenticated — shape verified live 2026-08-31)
//      twice: program-scoped (handle + hostname keyword + weakness class) and
//      behavior-signature (e.g. "google iap access-control-allow-origin"). Candidates are
//      ranked by signature-token overlap and written into the verdict.
//   2. EDGE-GENERATED-BEHAVIOR DETECTOR + PER-CLASS IMPACT BAR — the offline core
//      (engine/novelcore.mjs) runs on the draft text and any captured status/headers.
//   3. INTERNAL DEDUP — SimHash against our own prior submission drafts and reports
//      (.tmp/*submission*.md, data/exports/*report* — READ-ONLY, the corpus is never
//      modified).
//   4. --annotate rewrites the draft's "## Novelty check (novelgate)" section IN PLACE
//      (creating it if absent). REFUSED for paths under varvel/data/ or varvel/.data/ —
//      bountyline-drafted reports get their novelty section embedded by draftReports
//      itself; for those, run `check` without --annotate and act on the verdict.
//
// EGRESS DOCTRINE (hard):
//   * EVERY outbound request rides the ghost chain — default socks5://10.64.0.1:1080
//     (VARVEL_NOVELGATE_CHAIN overrides) via engine/ghost.mjs agents — and carries the
//     research header `X-HackerOne: varvel`. Queries to hackerone.com ride the same chain.
//   * FAIL-CLOSED: unreachable / non-2xx / Cloudflare-blocked / unparsable =>
//     a loud NAMED error ('hacktivity-unreachable' | 'hacktivity-http-error' |
//     'hacktivity-blocked' | 'hacktivity-bad-response') and verdict UNVERIFIABLE.
//     A failed search is NEVER a silent skip and NEVER a fabricated CLEAR.
//   * Candidate reports are read from the response only — never invented (the reader's
//     gaps are carried into the output).
//
// ASSUMED H1 SHAPE (verified live 2026-08-31; a live disagreement changes H1_GRAPHQL,
// not the gate): POST https://hackerone.com/graphql { query, variables:{ q } } with
//   search(index: CompleteHacktivityReportIndex, query_string: $q, first: N) →
//   nodes[] HacktivityDocument { _id, cwe, disclosed_at, severity_rating,
//   report { id, title, url, weakness { name }, team { handle } } }.
// IndexEnum confirmed by introspection: CompleteHacktivityReportIndex is the PUBLIC one.

import { readFileSync, writeFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import https from 'node:https';
import { Ghost } from '../engine/ghost.mjs';
import {
  classifyWeakness, impactEvidence, detectEdgeGenerated, parseHttpEvidence,
  assess, renderNoveltySection, parseNoveltySection,
  parseHacktivitySearch, rankCandidates, signatureTerms, dedupScan,
} from '../engine/novelcore.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
const VARVEL_ROOT = join(__dir, '..');

export const H1_GRAPHQL = {
  URL: 'https://hackerone.com/graphql',
  INDEX: 'CompleteHacktivityReportIndex', // the PUBLIC hacktivity index (IndexEnum, introspected 2026-08-31)
  FIRST: 25,
  QUERY: `query NoveltySearch($q: String!, $first: Int!) {
  search(index: CompleteHacktivityReportIndex, query_string: $q, first: $first) {
    total_count
    nodes {
      __typename
      ... on HacktivityDocument {
        _id cwe disclosed_at submitted_at severity_rating
        report { id title url weakness { name } team { handle name } }
      }
    }
  }
}`,
};
export const RESEARCH_HEADER = { 'x-hackerone': 'varvel' }; // program rule: research traffic is identified
export const GHOST_CHAIN = () => process.env.VARVEL_NOVELGATE_CHAIN || 'socks5://10.64.0.1:1080';
const BODY_CAP = 512 * 1024;

// --- ghost-riding transport (never throws; named errors; the vulncheck raw() discipline) ---
function ghostAgents(chainStr) {
  const g = new Ghost();
  g.configure({ mode: 'on', chain: chainStr });
  return g.agents(); // { httpAgent, httpsAgent }
}

// postJson(url, body, { agents, timeoutMs, reqImpl }) → { ok, status, body } — NEVER throws.
// reqImpl injectable for hermetic tests: (url, { method, headers, body, agent }) => Promise<{status, headers, body}|null>
export async function postJson(url, jsonBody, { agents, timeoutMs = 30000, reqImpl } = {}) {
  if (reqImpl) {
    try {
      const r = await reqImpl(url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json', ...RESEARCH_HEADER }, body: jsonBody });
      if (!r) return { ok: false, error: 'hacktivity-unreachable', reason: 'transport returned null (timeout/refused/reset) — no candidates were fabricated' };
      return { ok: true, status: r.status, body: typeof r.body === 'string' ? r.body : JSON.stringify(r.body) };
    } catch (e) {
      return { ok: false, error: 'hacktivity-unreachable', reason: `transport threw: ${String((e && e.message) || e).slice(0, 160)}` };
    }
  }
  const u = new URL(url);
  const lib = u.protocol === 'https:' ? https : http;
  const agent = agents ? (u.protocol === 'https:' ? agents.httpsAgent : agents.httpAgent) : undefined;
  return await new Promise((resolvePromise) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolvePromise(v); } };
    const req = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method: 'POST', agent, timeout: timeoutMs,
      headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0', ...RESEARCH_HEADER },
    }, (res) => {
      let text = '';
      res.on('data', (d) => { if (text.length < BODY_CAP) text += d.toString('utf8', 0, Math.max(0, BODY_CAP - text.length)); });
      res.on('end', () => done({ ok: true, status: res.statusCode, body: text }));
      res.on('error', (e) => done({ ok: false, error: 'hacktivity-unreachable', reason: `response stream error: ${String(e.message || e).slice(0, 160)}` }));
    });
    req.on('timeout', () => { try { req.destroy(); } catch {} done({ ok: false, error: 'hacktivity-unreachable', reason: `timeout after ${timeoutMs}ms — the search is UNVERIFIABLE, never silently skipped` }); });
    req.on('error', (e) => done({ ok: false, error: 'hacktivity-unreachable', reason: `${String(e.message || e).slice(0, 160)} — is the ghost chain (${GHOST_CHAIN()}) up?` }));
    req.end(typeof jsonBody === 'string' ? jsonBody : JSON.stringify(jsonBody));
  });
}

// hacktivitySearch(query, opts) → { ok:true, query, candidates, gaps } | { ok:false, error, reason, query }
export async function hacktivitySearch(q, { agents, reqImpl, timeoutMs, first = H1_GRAPHQL.FIRST } = {}) {
  const r = await postJson(H1_GRAPHQL.URL, { query: H1_GRAPHQL.QUERY, variables: { q, first } }, { agents, reqImpl, timeoutMs });
  if (!r.ok) return { ok: false, query: q, error: r.error, reason: r.reason };
  if (r.status === 403 || r.status === 401 || /just a moment|attention required|cf-chl/i.test(r.body || '')) {
    return { ok: false, query: q, error: 'hacktivity-blocked', reason: `H1/Cloudflare refused the search (HTTP ${r.status}) — run submit-drive h1sync's browser path to warm a cf_clearance, or retry later; the verdict is UNVERIFIABLE` };
  }
  if (r.status !== 200) return { ok: false, query: q, error: 'hacktivity-http-error', reason: `POST graphql answered HTTP ${r.status} — no candidates were fabricated` };
  const gaps = [];
  const candidates = parseHacktivitySearch(r.body, gaps);
  if (!candidates.length && gaps.length) return { ok: false, query: q, error: 'hacktivity-bad-response', reason: gaps.join('; ') };
  return { ok: true, query: q, candidates, gaps };
}

// --- internal corpus (READ-ONLY) ------------------------------------------------------------
export const CORPUS_DIRS = () => [
  { dir: join(VARVEL_ROOT, '.tmp'), re: /(submission|report).*\.md$/i },
  { dir: join(VARVEL_ROOT, 'data', 'exports'), re: /report/i },
];
export function collectCorpus(dirs = CORPUS_DIRS()) {
  const corpus = [];
  for (const { dir, re } of dirs) {
    if (!existsSync(dir)) continue;
    for (const name of readdirSync(dir)) {
      if (!re.test(name)) continue;
      const p = join(dir, name);
      try { if (!statSync(p).isFile()) continue; corpus.push({ name: p, text: readFileSync(p, 'utf8') }); } catch { /* unreadable corpus entry — skipped, never fatal */ }
    }
  }
  return corpus;
}

// --- the gate -------------------------------------------------------------------------------
// novelgateCheck({ program, platform, host, weakness, signature, draftPath, draftText,
//                  status, headers, corpusDirs, agents, reqImpl, offline }) → full result.
export async function novelgateCheck({ program, platform = 'hackerone', host, weakness, signature, draftPath, draftText, status, headers, corpusDirs, agents, reqImpl, timeoutMs, offline = false } = {}) {
  const text = draftText !== undefined ? String(draftText) : (draftPath && existsSync(draftPath) ? readFileSync(draftPath, 'utf8') : '');
  if (!text.trim()) return { ok: false, error: 'no-draft', reason: 'the gate needs the submission draft (--draft <path> or draftText) — a novelty verdict over nothing is fiction' };
  const klass = classifyWeakness([weakness, host, text.split('\n')[0]].filter(Boolean).join(' '));

  // Edge evidence: explicit --status/--headers win; else parse the draft's own HTTP blocks.
  let edgeInput = null;
  if (status !== undefined || headers) edgeInput = { status, headers };
  else {
    const blocks = parseHttpEvidence(text);
    edgeInput = blocks.find((b) => [302, 401, 403].includes(b.status)) || blocks[0] || null;
  }
  const edge = edgeInput ? detectEdgeGenerated(edgeInput) : { edge: false, unauthStatus: false, flagged: false, signals: [], reason: 'no response status/headers captured — the edge detector could not run (stated, not skipped)' };

  // Internal dedup (read-only corpus).
  const corpus = collectCorpus(corpusDirs).filter((d) => !draftPath || resolve(d.name) !== resolve(draftPath));
  const dedup = dedupScan(text, corpus);

  // Hacktivity duplicate search — TWO queries (program-scoped + behavior signature).
  const terms = signatureTerms({ host, klass, signature: signature || [program, host, weakness].filter(Boolean).join(' ') });
  let hacktivity;
  if (offline) {
    hacktivity = null; // PENDING — stated as such in the section
  } else {
    const queries = [];
    queries.push([program, host, klass !== 'other' ? klass : (weakness || '')].filter(Boolean).join(' '));
    if (signature) queries.push(signature);
    const all = [];
    const gapsAll = [];
    for (const q of [...new Set(queries)]) {
      const r = await hacktivitySearch(q, { agents, reqImpl, timeoutMs });
      if (!r.ok) { hacktivity = { ok: false, error: r.error, reason: r.reason, query: r.query }; break; }
      all.push(...r.candidates);
      gapsAll.push(...(r.gaps || []));
    }
    if (!hacktivity) {
      const seen = new Set();
      const uniq = all.filter((c) => { const k = c.id || c.url || c.title; if (seen.has(k)) return false; seen.add(k); return true; });
      hacktivity = { ok: true, candidates: rankCandidates(terms, uniq), gaps: gapsAll };
    }
  }

  const a = assess({ klass, platform, draftText: text, status: edgeInput && edgeInput.status, headers: edgeInput && edgeInput.headers, hacktivity, dedupMatches: dedup.matches });
  const command = `node tools/novelgate.mjs check --program ${program || '<handle>'} --host ${host || '<host>'} --weakness ${klass} --draft ${draftPath || '<draft.md>'}${status !== undefined ? ` --status ${status}` : ''} --annotate`;
  const section = renderNoveltySection(a, { program, host, signature, corpusSize: corpus.length, command });
  return { ok: true, verdict: a.verdict, assessment: a, section, command, corpusSize: corpus.length, dedupNote: dedup.note || null };
}

// annotateDraft(path, section) — rewrite/create the novelty section IN PLACE.
// REFUSES anything under varvel/data/ or varvel/.data/ (the owner's no-edit zones).
export function annotateDraft(path, section) {
  const abs = resolve(path);
  const forbidden = [join(VARVEL_ROOT, 'data'), join(VARVEL_ROOT, '.data')];
  for (const f of forbidden) {
    if (abs === f || abs.startsWith(f + sep)) {
      return { ok: false, error: 'annotate-refused', reason: `${path} is under ${f} — never edited by tooling. Bountyline-drafted reports get their novelty section from draftReports itself; run check without --annotate and act on the verdict.` };
    }
  }
  if (!existsSync(abs)) return { ok: false, error: 'draft-missing', reason: `no draft at ${path}` };
  let md = readFileSync(abs, 'utf8');
  const prior = parseNoveltySection(md);
  if (prior.present) {
    // Replace the prior section (from the marker's heading to the next '---' or EOF block end).
    const start = md.indexOf('## Novelty check (novelgate)');
    let end = md.length;
    const rest = md.slice(start);
    const m = rest.match(/\n---\n(?!['\n]*## Novelty check)/);
    if (m && m.index > 10) end = start + m.index;
    md = md.slice(0, start).replace(/[\s-]*$/, '\n') + section.trim() + '\n' + md.slice(end);
  } else {
    md = md.replace(/\s*$/, '') + '\n' + section;
  }
  writeFileSync(abs, md);
  return { ok: true, path: abs, replaced: prior.present };
}

// --- CLI ------------------------------------------------------------------------------------
const IS_MAIN = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (IS_MAIN) {
  const args = process.argv.slice(2);
  const opt = (name) => { const i = args.indexOf(name); return i === -1 ? undefined : args[i + 1]; };
  const has = (name) => args.includes(name);
  try {
    if (args[0] === 'check') {
      let headers = opt('--headers');
      if (headers) { try { headers = existsSync(headers) ? JSON.parse(readFileSync(headers, 'utf8')) : JSON.parse(headers); } catch (e) { throw new Error(`--headers must be a JSON object or a path to one (${e.message})`); } }
      const r = await novelgateCheck({
        program: opt('--program'), platform: opt('--platform') || 'hackerone',
        host: opt('--host'), weakness: opt('--weakness'), signature: opt('--signature'),
        draftPath: opt('--draft'),
        status: opt('--status') !== undefined ? Number(opt('--status')) : undefined,
        headers, offline: has('--offline'),
        agents: has('--offline') ? null : ghostAgents(GHOST_CHAIN()),
      });
      if (!r.ok) { console.error(`[novelgate] REFUSED: ${r.error} — ${r.reason}`); process.exit(1); }
      if (has('--annotate')) {
        if (!opt('--draft')) throw new Error('--annotate needs --draft <path>');
        const an = annotateDraft(opt('--draft'), r.section);
        if (!an.ok) { console.error(`[novelgate] ANNOTATE REFUSED: ${an.error} — ${an.reason}`); process.exit(1); }
        console.log(`[novelgate] draft annotated: ${an.path} (${an.replaced ? 'section replaced' : 'section added'})`);
      }
      console.log(r.section);
      if (has('--json')) console.log('\n```json\n' + JSON.stringify({ verdict: r.verdict, assessment: r.assessment, corpusSize: r.corpusSize }, null, 2) + '\n```');
      // Exit code carries the verdict for scripting: 0 CLEAR, 2 REVIEW-NEEDED, 3 UNVERIFIABLE, 4 BLOCKED.
      process.exit({ CLEAR: 0, 'REVIEW-NEEDED': 2, UNVERIFIABLE: 3, BLOCKED: 4 }[r.verdict]);
    } else {
      console.log('usage: node tools/novelgate.mjs check --program <handle> --host <host> --weakness <class> --draft <draft.md> [--signature "…"] [--status N --headers h.json] [--offline] [--annotate] [--json]');
      process.exit(1);
    }
  } catch (e) {
    console.error(`[novelgate] FATAL: ${String((e && e.message) || e)}`);
    process.exit(1);
  }
}
