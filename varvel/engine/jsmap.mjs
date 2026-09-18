// VARVEL — jsmap: static impact-primitive miner for Node/JS application source.
//
// The privemap METHOD (engine/privemap.mjs) applied to JavaScript/Node trees: given
// [{ path, content }] source records, rank the routes/handlers an operator should look
// at FIRST instead of reading the whole app by hand. privemap produced two
// verified-novel CVE candidates on a real engagement; this rung ports the method to the
// stack most of our targets' custom code actually runs on.
//
// LINE-BASED HEURISTICS, NOT AN AST (zero-dep rule). Precision is stated per candidate
// via `confidence` — this miner ranks, it does not convict. Known blind spots are
// documented at the bottom of this file and surface in the report's gaps[].
//
// MODEL: reachability comes from route registrations (express/koa-style
// app|router.METHOD(path, …middleware, handler), plus raw http.createServer handlers as
// a catch-all). Impact comes from sink calls inside the handler body (with bounded
// same-tree transitive descent, ≤2 hops, because the real sink often lives in a helper
// the handler calls). RANK = impact class weight × effective reachability ×
// attacker-control (taint) factor, decayed 0.75 per descent hop. The differential
// middleware class: a route carrying NO auth-looking middleware where its siblings in
// the same file do — that asymmetry is itself the finding (CWE-862 shaped).
//
// Pure: no fs, no network, no import-time side effects.

// --- tuning tables -----------------------------------------------------------

const REACH_W = { unauth: 1.0, authed: 0.55, internal: 0.15 };
const REACH_TITLE = {
  unauth: 'route-registered unauthenticated',
  authed: 'authenticated-route',
  internal: 'internal (no route registration seen)',
};

// Attacker-control multiplier: a sink whose arguments the caller cannot steer is a
// lesser primitive. `direct` = req.* on the sink line; `tainted-var` = a variable
// assigned from req.*; `ambient` = req.* elsewhere in the body; `none` = no req flow
// seen (structural classes still report; taint-needing classes skip).
const TAINT_FACTOR = { direct: 1, 'tainted-var': 0.9, ambient: 0.65, none: 0.45 };

// req-derived data: the express/koa request surface, plus req.url/originalUrl for raw
// http.createServer handlers (the only request input a bare node server has).
// req.user/req.session are deliberately NOT here — middleware-established identity,
// not raw attacker bytes.
const REQ_RE = /\breq\s*(?:\.\s*(?:body|query|params|headers|cookies|files?|ips?\b|hostname|url|originalUrl|get|header|param)\b|\s*\[)/;
const KOA_CTX_RE = /\bctx\s*\.\s*(?:request\s*\.\s*(?:body|query|headers)|query\b|params\b|headers\b)/;

// Impact classes, most-severe first by weight. `taintedOnly` classes are skipped when
// no req flow reaches the sink line (constant-argument execFile/spawn is the safe-app
// idiom — reporting it would be noise). Structural classes (jwt/secret/middleware-gap)
// stand on the code shape alone. Probes are read-only/differential suggestions, NEVER
// payloads; destructive or state-changing proof is operator sign-off territory.
const SINK_DEFS = [
  { id: 'rce-exec', weight: 100, taintedOnly: true,
    label: 'OS command execution (child_process with interpolated input)',
    re: /(?:^|[^\w$.])((?:child_process|childProcess|cp)\s*\.\s*)?(execSync|execFileSync|spawnSync|exec|execFile|spawn)\s*\(/,
    probe: 'READ-ONLY differential: send an intentionally INVALID value for the interpolated argument (an illegal flag, an overlong token) and grade the rejection vs baseline — proves the input reaches the shell/spawn boundary without executing anything. Any real command injection is operator sign-off territory, never fired by the miner.' },
  { id: 'code-eval', weight: 88, taintedOnly: true,
    label: 'dynamic code evaluation (eval / new Function on request data)',
    re: /(?:^|[^\w$.])(eval\s*\(|new\s+Function\s*\()/,
    probe: 'READ-ONLY differential: submit a well-formed no-op expression vs a syntax-error fragment; an eval reach shows a DIFFERENT error class for the two. No expressions with side effects.' },
  { id: 'deser-unsafe', weight: 84, taintedOnly: true,
    label: 'unsafe deserialization (node-serialize / eval-adjacent deserialize)',
    re: /(?:^|[^\w$.])(unserialize|deserialize)\s*\(/,
    probe: 'READ-ONLY differential: a MALFORMED serialized blob vs a well-formed innocent object — the parse-error split proves the deserialize boundary. The classic IIFE payload is change territory, never fired by the miner.' },
  { id: 'proto-pollution', weight: 82, taintedOnly: true,
    label: 'prototype-pollution-prone merge (unfiltered request body merge / __proto__ write)',
    re: /(?:^|[^\w$.])(Object\s*\.\s*assign|_?\$?\s*\.\s*(?:extend|merge|defaultsDeep)|merge|defaultsDeep)\s*\(|\b__proto__\b|\[\s*["\']__proto__["\']\s*\]/,
    probe: 'READ-ONLY: POST a body whose __proto__ key carries an INERT marker field (never isAdmin/role/auth flags), then read a subsequent response for marker leakage. Detection by observation; behavior-changing keys are operator sign-off territory.' },
  { id: 'path-traversal', weight: 76, taintedOnly: true,
    label: 'path traversal (path.join/resolve or fs read/write on request-derived segments)',
    re: /(?:^|[^\w$.])(path\s*\.\s*(?:join|resolve|normalize)|readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync|readdir|readdirSync|sendFile)\s*\(/,
    probe: 'READ-ONLY: request a path KNOWN to exist and benign inside the served root (the app\'s own package.json/README) vs a guaranteed-absent name — the existence differential proves reachability. No /etc/passwd or credential-store pulls without explicit scope sign-off.' },
  { id: 'ssrf', weight: 72, taintedOnly: true,
    label: 'SSRF (fetch/axios/request on a request-derived URL)',
    re: /(?:^|[^\w$.])(fetch|got|needle|request|superagent)\s*\(|(?:^|[^\w$.])axios\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(|(?:^|[^\w$.])https?\s*\.\s*(?:get|request)\s*\(/,
    probe: 'READ-ONLY: aim the URL parameter at an endpoint YOU control that only logs (a canary token / request bin), or at the target\'s OWN public page, and grade the fetch differential. No cloud-metadata (169.254.169.254) or internal port sweeps without explicit scope.' },
  { id: 'jwt-alg-unpinned', weight: 64, structural: true,
    label: 'jwt.verify without an algorithms pin (alg-confusion surface)',
    re: /(?:^|[^\w$.])jwt\s*\.\s*verify\s*\(/,
    probe: 'READ-ONLY: the finding stands on the code — confirm the jsonwebtoken version and the verify() options. Token FORGERY (alg=none / RS256→HS256 confusion) is a crypto-test annex decision, never fired by the miner.' },
  { id: 'secret-compare', weight: 58, structural: true,
    label: 'secret/token compared with === instead of crypto.timingSafeEqual',
    re: /(?:^|[^\w$.])(?:timingSafeEqual)\s*\(/, // presence of the SAFE call suppresses per-line (see scan)
    probe: 'READ-ONLY: timing side channel — MEASURE, do not exploit: collect N timing samples of correct-prefix vs wrong-prefix compares and report the distributions. No credential guessing.' },
];

// Middleware whose name reads as an authentication/authorization gate. The differential
// class (middleware-gap) fires on asymmetry: no such middleware HERE where siblings
// have it. Listed separately from sinks — the registration line is the evidence.
const AUTH_MW_RE = /auth|login|session|jwt|guard|passport|permission|require.?user|ensure.?user|is.?authenticated|verify.?(?:user|token|session)|acl|rbac|csrf/i;

const MW_GAP_WEIGHT = 60;
const MW_GAP = { id: 'middleware-gap', weight: MW_GAP_WEIGHT,
  label: 'route lacks auth middleware where sibling routes enforce it (differential)',
  probe: 'READ-ONLY: request the gap route AND its authed siblings unauthenticated with empty bodies and compare status/shape — a reachability differential only. No state-changing verb with a real body.' };

// Sanitizer/guard idioms that downgrade (not erase) confidence on the tainted classes.
const MITIGATION_RES = [
  { id: 'path-normalize-guard', re: /\bnormalize\s*\(|startsWith\s*\(|resolve\s*\([^)]*\)\s*\.{0,3}\s*startsWith/, classes: ['path-traversal'] },
  { id: 'allowlist/validator', re: /allowlist|whitelist|\bsanitize|escapeShell|shellQuote|validator\s*\.\s*|\.parse\s*\(\s*req\b|zod|Joi/, classes: ['rce-exec', 'path-traversal', 'ssrf', 'code-eval'] },
  { id: 'timingSafeEqual', re: /timingSafeEqual\s*\(/, classes: ['secret-compare'] },
  { id: 'helmet/rate-limit', re: /helmet\s*\(|rateLimit\s*\(/, classes: [] }, // recorded, no downgrade
];

// Names we never descend into (language/stdlib/framework noise).
const NO_DESCEND = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'return', 'function', 'new', 'typeof', 'await', 'else', 'do', 'try', 'throw',
  'require', 'import', 'export', 'console', 'JSON', 'Object', 'Array', 'String', 'Number', 'Boolean', 'Buffer', 'Promise', 'Math', 'Date', 'Error', 'Map', 'Set', 'RegExp', 'Symbol', 'BigInt', 'parseInt', 'parseFloat', 'isNaN', 'encodeURIComponent', 'decodeURIComponent',
  'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval', 'setImmediate', 'queueMicrotask', 'process', 'module',
  'then', 'catch', 'finally', 'map', 'filter', 'forEach', 'reduce', 'find', 'some', 'every', 'includes', 'indexOf', 'push', 'concat', 'slice', 'join', 'split', 'trim', 'replace', 'toString', 'valueOf', 'keys', 'values', 'entries', 'assign', 'stringify', 'parse',
  'use', 'get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'all', 'listen', 'status', 'json', 'send', 'end', 'redirect', 'render', 'set', 'type',
]);

// --- structural parsing (line-based; comments/strings blanked for brace math) --------

// Blank comments and string CONTENTS (single, double, template literals) so brace
// counting and call detection are not fooled by '{', '}' or 'function(' inside a string
// literal or comment. LENGTH-PRESERVING: every blanked char becomes one space, so the
// sanitized text aligns offset-for-offset with the original (the scanner joins both
// views and maps offsets between them — a collapsing blanker would misalign everything
// after the first string). Template-literal ${} interiors are blanked with the rest of
// the template (documented blind spot: nested templates can unbalance the blanking).
function structureLines(src) {
  const out = [];
  let inBlock = false;
  let inTemplate = false; // backtick templates legitimately span lines — carried
  for (const raw of String(src).split('\n')) {
    let s = '';
    let i = 0;
    while (i < raw.length) {
      if (inBlock) {
        const e = raw.indexOf('*/', i);
        if (e === -1) { s += ' '.repeat(raw.length - i); i = raw.length; }
        else { s += ' '.repeat(e + 2 - i); inBlock = false; i = e + 2; }
        continue;
      }
      if (inTemplate) {
        let j = i;
        while (j < raw.length && raw[j] !== '`') { if (raw[j] === '\\') j++; j++; }
        if (j >= raw.length) { s += ' '.repeat(raw.length - i); i = raw.length; }
        else { s += ' '.repeat(j + 1 - i); inTemplate = false; i = j + 1; }
        continue;
      }
      const two = raw.slice(i, i + 2);
      if (two === '/*') {
        const e = raw.indexOf('*/', i + 2);
        if (e === -1) { s += ' '.repeat(raw.length - i); inBlock = true; i = raw.length; }
        else { s += ' '.repeat(e + 2 - i); i = e + 2; }
        continue;
      }
      if (two === '//') { s += ' '.repeat(raw.length - i); break; }
      const ch = raw[i];
      if (ch === "'" || ch === '"' || ch === '`') {
        const q = ch;
        let j = i + 1;
        while (j < raw.length && raw[j] !== q) { if (raw[j] === '\\') j++; j++; }
        if (j >= raw.length) {
          // Unterminated on this line: a backtick template CARRIES to the next line
          // (multi-line templates are idiomatic); a single/double quote does not
          // (unterminated = syntax error, or a regex literal like /'/ — line-local).
          if (q === '`') inTemplate = true;
          s += ' '.repeat(raw.length - i);
          i = raw.length;
          continue;
        }
        s += ' '.repeat(j + 1 - i);
        i = j + 1;
        continue;
      }
      s += ch;
      i++;
    }
    out.push(s);
  }
  return out;
}

// Offset-based scanner over the whole file: regexes stay line-shaped, but brace/paren
// matching and line-number mapping ride a joined view (orig and san stay line-aligned,
// so offsets convert exactly).
function makeScanner(origLines, sanLines) {
  const orig = origLines.join('\n');
  const san = sanLines.join('\n');
  const lineStarts = [0];
  for (let i = 0; i < san.length; i++) if (san[i] === '\n') lineStarts.push(i + 1);
  const lineOf = (off) => {
    let lo = 0, hi = lineStarts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (lineStarts[mid] <= off) lo = mid; else hi = mid - 1; }
    return lo; // 0-based
  };
  // Match the bracket opened at openOff on the SANITIZED text (strings/comments already
  // blank). Returns the close offset, or -1 when unbalanced.
  const matchBracket = (openOff) => {
    const open = san[openOff];
    const close = open === '(' ? ')' : open === '{' ? '}' : open === '[' ? ']' : null;
    if (!close) return -1;
    let depth = 0;
    for (let i = openOff; i < san.length; i++) {
      const c = san[i];
      if (c === open) depth++;
      else if (c === close) { depth--; if (!depth) return i; }
    }
    return -1;
  };
  // Split [startOff,endOff) at top-level commas (all bracket types tracked together).
  const topLevelSplit = (startOff, endOff) => {
    const parts = [];
    let depth = 0, last = startOff;
    for (let i = startOff; i < endOff; i++) {
      const c = san[i];
      if (c === '(' || c === '{' || c === '[') depth++;
      else if (c === ')' || c === '}' || c === ']') depth--;
      else if (c === ',' && depth === 0) { parts.push([last, i]); last = i + 1; }
    }
    parts.push([last, endOff]);
    return parts;
  };
  return { orig, san, lineOf, matchBracket, topLevelSplit };
}

const FN_DECL_RE = /\b(?:export\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(/g;
const FN_ARROW_PAREN_RE = /\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=(?![=>])\s*(?:async\s*)?(?:function\s*\*?\s*)?\(/g;
const FN_ARROW_1ARG_RE = /\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=(?![=>])\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*=>/g;

// Extract named functions (declarations, const arrows, const function-expressions)
// with brace-matched bodies. Arrow expression-bodies (no '{') are skipped — no body to
// scan. Unbalanced files degrade to EOF bodies with a gap note (heuristic, never fatal).
function extractFunctions(path, sc, gaps) {
  const fns = [];
  const seen = new Set();
  const collect = (name, sigEnd, isArrow) => {
    let i = sigEnd;
    while (i < sc.san.length && /\s/.test(sc.san[i])) i++;
    if (isArrow && sc.san.slice(i, i + 2) === '=>') { i += 2; while (i < sc.san.length && /\s/.test(sc.san[i])) i++; }
    if (sc.san[i] !== '{') return; // expression body or unparseable — nothing to scan
    const close = sc.matchBracket(i);
    const startLine = sc.lineOf(i);
    const endLine = close === -1 ? sc.lineOf(sc.san.length - 1) : sc.lineOf(close);
    if (close === -1 && gaps.length < 60) gaps.push({ ref: `${path}:${startLine + 1}`, reason: `unbalanced braces in function ${name} — body taken to EOF (heuristic)` });
    const key = `${name}@${startLine}`;
    if (seen.has(key)) return;
    seen.add(key);
    fns.push({ name, path, line: startLine + 1, end: endLine + 1, body: sc.orig.split('\n').slice(startLine, endLine + 1), san: sc.san.split('\n').slice(startLine, endLine + 1) });
  };
  for (const re of [FN_DECL_RE, FN_ARROW_PAREN_RE, FN_ARROW_1ARG_RE]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(sc.san))) {
      if (re === FN_DECL_RE || re === FN_ARROW_PAREN_RE) {
        // Find the close paren of the signature, then the body.
        const parenOpen = sc.san.indexOf('(', m.index + m[0].length - 1);
        if (parenOpen === -1) continue;
        const parenClose = sc.matchBracket(parenOpen);
        if (parenClose === -1) continue;
        collect(m[1], parenClose + 1, re === FN_ARROW_PAREN_RE);
      } else {
        collect(m[1], m.index + m[0].length - 2, true); // before '=>'
      }
    }
  }
  return fns;
}

const ROUTE_RE = /\b(?:app|router|routes|api|server)\s*\.\s*(get|post|put|delete|patch|head|options|all|use)\s*\(/g;
const CREATESERVER_RE = /\bcreateServer\s*\(/g;
const STR_LIT_RE = /^\s*['"`]/;

// Extract route registrations. The statement may span lines (balanced-paren join via
// the scanner). Args after the path: trailing arg = handler (inline arrow/function or a
// named reference); middle args = middleware (identifiers, dotted names, call results,
// or [array] lists). app.use(mw) without a path registers global middleware (line-ordered).
function extractRoutes(path, sc, gaps) {
  const routes = [];
  const globals = []; // { name, line } global middleware from app.use
  const parseArgs = (stmtStart, parenClose, baseLineOff) => {
    const args = [];
    for (const [a0, a1] of sc.topLevelSplit(stmtStart, parenClose)) {
      const sanTxt = sc.san.slice(a0, a1).trim();
      const origTxt = sc.orig.slice(a0, a1).trim();
      if (!sanTxt && !origTxt) continue;
      args.push({ san: sanTxt, orig: origTxt, off: a0, line: sc.lineOf(a0) + 1 });
    }
    return args;
  };
  const inlineBody = (arg) => {
    // An arrow/function arg: find its '{' after '=>' (or after the params paren).
    const rel = sc.san.slice(arg.off, arg.off + arg.san.length + 400);
    const arrowAt = rel.indexOf('=>');
    let braceRel = -1;
    if (arrowAt !== -1) braceRel = rel.indexOf('{', arrowAt);
    else if (/^\s*(?:async\s+)?function\b/.test(arg.orig)) braceRel = rel.indexOf('{');
    if (braceRel === -1) return null;
    const braceOff = arg.off + braceRel;
    const close = sc.matchBracket(braceOff);
    if (close === -1) return null;
    const startLine = sc.lineOf(braceOff);
    const endLine = sc.lineOf(close);
    return { line: startLine + 1, end: endLine + 1, body: sc.orig.split('\n').slice(startLine, endLine + 1), san: sc.san.split('\n').slice(startLine, endLine + 1) };
  };
  const middlewareOf = (args) => {
    const mws = [];
    for (const a of args) {
      if (/=>|^\s*(?:async\s+)?function\b/.test(a.orig)) continue; // the handler, not middleware
      const names = a.san.startsWith('[')
        ? (a.san.match(/[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*/g) || [])
        : [a.san.replace(/\s+/g, '')];
      for (const n of names) if (n && !/^['"`]/.test(a.orig)) mws.push(n);
    }
    return mws;
  };

  for (const re of [ROUTE_RE, CREATESERVER_RE]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(sc.san))) {
      const isRaw = re === CREATESERVER_RE;
      const line = sc.lineOf(m.index) + 1;
      const parenOpen = sc.san.indexOf('(', m.index + m[0].length - 1);
      if (parenOpen === -1) continue;
      const parenClose = sc.matchBracket(parenOpen);
      if (parenClose === -1) {
        if (gaps.length < 60) gaps.push({ ref: `${path}:${line}`, reason: 'unbalanced route registration — skipped' });
        continue;
      }
      if (sc.lineOf(parenClose) - sc.lineOf(parenOpen) > 40) continue; // pathological join — not a route call
      const args = parseArgs(parenOpen + 1, parenClose);
      if (!args.length) continue;

      let method = isRaw ? 'ALL' : m[1].toLowerCase();
      let routePath = '(all)';
      let rest = args;
      if (!isRaw) {
        if (STR_LIT_RE.test(args[0].orig)) {
          routePath = args[0].orig.trim().replace(/^['"`]|['"`].*$/g, '');
          rest = args.slice(1);
          // koa-router named route: router.get('name', '/path', …)
          if (rest.length && STR_LIT_RE.test(rest[0].orig)) { routePath = rest[0].orig.trim().replace(/^['"`]|['"`].*$/g, ''); rest = rest.slice(1); }
        } else if (method === 'use') {
          // app.use(middleware) — global, line-ordered.
          for (const n of middlewareOf(args)) globals.push({ name: n, line });
          continue;
        } else {
          continue; // app.METHOD(<non-literal>) — dynamic path, blind spot (documented)
        }
      }
      if (!rest.length) continue;

      const handlerArg = rest[rest.length - 1];
      const mwNames = middlewareOf(rest.slice(0, -1));
      let handler = null, handlerName = null, closure = false;
      if (/=>|^\s*(?:async\s+)?function\b/.test(handlerArg.orig)) {
        closure = true;
        handler = inlineBody(handlerArg);
        if (!handler && gaps.length < 60) gaps.push({ ref: `${path}:${line}`, reason: 'inline handler body not brace-matched (expression body?) — not analyzed' });
      } else {
        handlerName = handlerArg.san.replace(/\s+/g, '');
      }
      routes.push({ path, line, method, route: routePath, kind: isRaw ? 'raw-http' : 'route', mw: mwNames, handler, handlerName, closure });
    }
  }
  return { routes, globals };
}

// --- body analysis -----------------------------------------------------------

// Taint: req.* reads, destructuring from req.*, plain re-assignments, plus one
// propagation pass through `const y = … x …` where x is already tainted.
function bodyTaint(body) {
  const vars = new Set();
  const hasReq = (expr) => REQ_RE.test(expr) || KOA_CTX_RE.test(expr);
  const DECL_RE = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=(?![=>])\s*(.+)/;
  const PLAIN_RE = /^\s*([A-Za-z_$][\w$]*)\s*=(?![=>])\s*(.+)/;
  const DESTRUCT_RE = /\b(?:const|let|var)\s*\{([^}]*)\}\s*=(?![=>])\s*(.+)/;
  const destructureNames = (inner) => (inner.match(/[A-Za-z_$][\w$]*/g) || []).filter((n) => !/^(?:const|let|var)$/.test(n));
  // Single-letter vars (q, x) carry taint too — real handlers use them; a shadowed
  // short name in a nested scope is accepted heuristic noise (confidence labels hold).
  const referencesTainted = (expr) => [...vars].some((v) => new RegExp(`\\b${v}\\b`).test(expr));
  for (const line of body) {
    const dm = line.match(DESTRUCT_RE);
    if (dm && hasReq(dm[2])) for (const n of destructureNames(dm[1])) vars.add(n);
    const m = line.match(DECL_RE) || line.match(PLAIN_RE);
    if (m && hasReq(m[2])) vars.add(m[1]);
  }
  for (const line of body) {
    const m = line.match(DECL_RE) || line.match(PLAIN_RE);
    if (m && !vars.has(m[1]) && referencesTainted(m[2])) vars.add(m[1]);
    const dm = line.match(DESTRUCT_RE);
    if (dm && referencesTainted(dm[2])) for (const n of destructureNames(dm[1])) vars.add(n);
  }
  return vars;
}

function lineTaint(line, taintVars, bodyHasReq) {
  if (REQ_RE.test(line) || KOA_CTX_RE.test(line)) return 'direct';
  for (const v of taintVars) if (new RegExp(`\\b${v}\\b`).test(line)) return 'tainted-var';
  return bodyHasReq ? 'ambient' : 'none';
}

// A function's parameter names, from the declaration line (heuristic: single-line
// signatures; multi-line signatures read as no params — documented blind spot).
function paramsOf(fn) {
  const first = (fn.body && fn.body[0]) || '';
  const m = first.match(/\(([^)]*)\)\s*=>/) || first.match(/\bfunction\s*\w*\s*\(([^)]*)\)/) || first.match(/=\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*=>/);
  if (!m) return [];
  return m[1].split(',').map((s) => s.trim().replace(/=.*$/, '').replace(/[[\]{}.]/g, '').trim()).filter((s) => /^[A-Za-z_$][\w$]*$/.test(s));
}

// Scan one function body for impact sinks. Returns raw hits. ambientFloor: at descent
// hops > 0 where the call site passed tainted arguments, 'none' taint floors to
// 'ambient' (cross-function dataflow past the params is unproven, never assumed absent).
function scanSinks(fn, taintVars, fileCtx, ambientFloor = false) {
  const hits = [];
  const bodyJoined = fn.body.join('\n');
  const sanJoined = fn.san.join('\n');
  const bodyHasReq = REQ_RE.test(bodyJoined) || KOA_CTX_RE.test(bodyJoined);
  const mitigations = [];
  for (const mit of MITIGATION_RES) {
    if (mit.re.test(bodyJoined) || mit.re.test(fileCtx.fileHead)) mitigations.push(mit.id);
  }
  for (let k = 0; k < fn.body.length; k++) {
    const orig = fn.body[k];
    const san = fn.san[k];
    if (/\bfunction\b/.test(san) && !/=>/.test(san)) { /* a nested declaration line; sinks on it are still real — keep scanning */ }
    for (const def of SINK_DEFS) {
      let m = orig.match(def.re);
      // secret-compare is inverted: the DEF regex matches the SAFE call; the finding is a
      // === / !== compare of a secret-ish, req-derived value WITHOUT timingSafeEqual.
      if (def.id === 'secret-compare') {
        if (!/(===|!==)/.test(orig)) continue;
        if (!/(token|secret|signature|api[-_]?key|password|passwd|hmac)/i.test(orig)) continue;
        if (/timingSafeEqual\s*\(/.test(orig)) continue;
        m = [orig.match(/(===|!==)/)[0]];
      } else if (!m) {
        continue;
      }
      const token = (def.id === 'secret-compare' ? '===' : (m[2] || m[1] || m[0])).replace(/[^\w$]*$/, '').slice(0, 24);
      if (def.id !== 'secret-compare' && !san.includes(token.replace(/^[^A-Za-z_$]+/, '').slice(0, 8) || '')) continue; // commented-out/string-only match
      let taint = lineTaint(orig, taintVars, bodyHasReq);
      if (taint === 'none' && ambientFloor) taint = 'ambient';
      if (def.taintedOnly && taint === 'none') continue; // constant-arg sinks are the safe idiom
      if (def.id === 'jwt-alg-unpinned') {
        // The options object may span lines: look at this line + the next three.
        const win = fn.body.slice(k, k + 4).join('\n');
        if (/\balgorithms\s*:/.test(win)) continue; // pinned — the safe idiom
        taint = 'none'; // structural class: stands on the code shape
      }
      if (def.id === 'secret-compare') taint = taint === 'none' ? 'ambient' : taint;
      const hit = { def, line: fn.line + k, text: orig.trim().slice(0, 160), taint };
      // rce-exec without any child_process import in the file is likely a same-named
      // local — keep, but cap confidence via a flag.
      if (def.id === 'rce-exec' && !m[1] && !fileCtx.importsChildProcess) hit.noImport = true;
      hits.push(hit);
    }
  }
  return { hits, mitigations };
}

// Callees worth descending into: bare calls and this.-calls (object identity of
// `obj.method()` is unknown to line heuristics — documented blind spot).
function calleesOf(fn) {
  const names = new Set();
  for (const line of fn.san) {
    for (const m of line.matchAll(/\bthis\s*\.\s*([A-Za-z_$][\w$]*)\s*\(/g)) names.add(m[1]);
    for (const m of line.matchAll(/(?<![\w$.])([a-z_$][\w$]*)\s*\(/g)) {
      if (!NO_DESCEND.has(m[1]) && !/^[A-Z]/.test(m[1])) names.add(m[1]);
    }
  }
  return names;
}

// --- the miner ----------------------------------------------------------------

// records: [{ path, content }]. Pure: no fs, no network, no import-time side effects.
export function mineJs(records, { maxDepth = 2, maxCallees = 30 } = {}) {
  const gaps = [];
  const fns = [];
  const allRoutes = [];
  const fileGlobals = new Map(); // path -> [{ name, line }]
  const fileCtxs = new Map();    // path -> { importsChildProcess, fileHead }

  for (const rec of Array.isArray(records) ? records : []) {
    try {
      const content = String(rec && rec.content != null ? rec.content : '').replace(/\r\n?/g, '\n');
      const path = String(rec && rec.path != null ? rec.path : '?').replace(/\\/g, '/');
      if (!content.trim()) continue;
      const orig = content.split('\n');
      const san = structureLines(content);
      const sc = makeScanner(orig, san);
      const head = orig.slice(0, 40).join('\n');
      fileCtxs.set(path, {
        importsChildProcess: /require\s*\(\s*['"]child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]/.test(head) || /child_process/.test(content.slice(0, 4000)),
        fileHead: head,
      });
      fns.push(...extractFunctions(path, sc, gaps));
      const { routes, globals } = extractRoutes(path, sc, gaps);
      allRoutes.push(...routes);
      fileGlobals.set(path, globals);
    } catch (e) {
      gaps.push({ ref: String(rec && rec.path), reason: 'parse failed: ' + ((e && e.message) || e) });
    }
  }

  const byName = new Map();
  for (const f of fns) {
    if (!byName.has(f.name)) byName.set(f.name, []);
    byName.get(f.name).push(f);
  }
  const dirOf = (p) => { const i = p.lastIndexOf('/'); return i === -1 ? '' : p.slice(0, i + 1); };
  const resolve = (name, fromPath) => {
    const cands = byName.get(name) || [];
    return cands.find((f) => f.path === fromPath) || cands.find((f) => dirOf(f.path) === dirOf(fromPath)) || cands[0] || null;
  };

  const candidates = [];
  const handlerFns = new Set(); // functions reached as route handlers (excluded from internal scan)
  const routeAuthed = new Map(); // route -> bool

  for (const route of allRoutes) {
    const regRef = `${route.path}:${route.line}`;
    // Reachability: auth-looking middleware on the route, or a global app.use(auth) that
    // precedes it in the same file (express line-order semantics, heuristic).
    const globals = fileGlobals.get(route.path) || [];
    const globalAuth = globals.find((g) => AUTH_MW_RE.test(g.name) && g.line <= route.line);
    const routeAuth = route.mw.find((n) => AUTH_MW_RE.test(n));
    const reach = (routeAuth || globalAuth) ? 'authed' : 'unauth';
    routeAuthed.set(route, reach === 'authed');
    const reachNote = !routeAuth && globalAuth ? `via global app.use(${globalAuth.name}) at line ${globalAuth.line}` : null;

    let handlerFn = null;
    if (route.handler) {
      // Inline handlers are named by their registration (route+line) — without that,
      // every '(inline)' handler in a file shares one dedupe key and same-class
      // findings across DIFFERENT routes collapse into each other.
      handlerFn = { name: `(inline ${route.method.toUpperCase()} ${route.route}@${route.line})`, path: route.path, line: route.handler.line, end: route.handler.end, body: route.handler.body, san: route.handler.san };
    } else if (route.handlerName) {
      if (/^(?:router|Router)$|Router$/.test(route.handlerName)) continue; // app.use('/x', router) mount — not a handler
      handlerFn = resolve(route.handlerName, route.path);
      if (!handlerFn) {
        gaps.push({ ref: regRef, reason: `handler '${route.handlerName}' not found in scanned sources (imported from outside the tree, or dynamic)` });
        continue;
      }
    } else {
      continue;
    }
    handlerFns.add(handlerFn);

    // BFS descent: handler body (hop 0) → callees (≤ maxDepth). Cross-file resolution is
    // name-based (same file, then same dir, then anywhere) — confidence stays 'low'
    // past hop 0 for that reason. Call-site taint is SEEDED into the callee: an argument
    // that is req-derived at the call site taints the callee's parameter at that
    // position (and floors its body's untainted sink lines to 'ambient').
    const seen = new Set();
    const chainOf = new Map([[handlerFn, [handlerFn.name]]]);
    const queue = [{ fn: handlerFn, hops: 0, seedTaint: null, floor: false }];
    const fileCtx = fileCtxs.get(handlerFn.path) || { importsChildProcess: false, fileHead: '' };
    const hits = [];
    let mitigations = [];
    while (queue.length) {
      const { fn, hops, seedTaint, floor } = queue.shift();
      if (seen.has(fn)) continue;
      seen.add(fn);
      const chain = chainOf.get(fn);
      const taintVars = bodyTaint(fn.body);
      if (seedTaint) for (const v of seedTaint) taintVars.add(v);
      const scanned = scanSinks(fn, taintVars, fileCtxs.get(fn.path) || fileCtx, floor);
      if (hops === 0) mitigations = scanned.mitigations;
      for (const h of scanned.hits) hits.push({ ...h, hops, chain, fnPath: fn.path });
      if (hops < maxDepth && seen.size < maxCallees) {
        for (const calleeName of calleesOf(fn)) {
          const callee = resolve(calleeName, fn.path);
          if (callee && !seen.has(callee) && !chainOf.has(callee)) {
            chainOf.set(callee, [...chain, calleeName]);
            // Call-site arg taint → callee params (positional, first matching call).
            let seed = null, callTainted = false;
            const callRe = new RegExp(`(?<![\\w$.])${calleeName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\(([^)]*)\\)`);
            for (const line of fn.san) {
              const cm = line.match(callRe);
              if (!cm) continue;
              const args = cm[1].split(',');
              const taintedIdx = new Set();
              args.forEach((a, i) => {
                if (REQ_RE.test(a) || KOA_CTX_RE.test(a) || [...taintVars].some((v) => new RegExp(`\\b${v}\\b`).test(a))) taintedIdx.add(i);
              });
              if (taintedIdx.size) {
                callTainted = true;
                const params = paramsOf(callee);
                seed = new Set([...taintedIdx].map((i) => params[i]).filter(Boolean));
              }
              break;
            }
            queue.push({ fn: callee, hops: hops + 1, seedTaint: seed, floor: callTainted });
          }
        }
      }
    }

    for (const h of hits) {
      const effTaint = h.hops > 0 && h.taint === 'none' ? 'ambient' : h.taint;
      let score = h.def.weight * (REACH_W[reach] ?? REACH_W.internal) * Math.pow(0.75, h.hops) * (TAINT_FACTOR[effTaint] ?? TAINT_FACTOR.none);
      let confidence;
      if (h.hops > 0) confidence = 'low';
      else if (h.def.structural) confidence = 'medium';
      else confidence = h.taint === 'direct' || h.taint === 'tainted-var' ? 'high' : (h.taint === 'ambient' ? 'medium' : 'low');
      if (h.noImport) { score *= 0.6; confidence = 'low'; }
      const appliedMit = mitigations.filter((id) => (MITIGATION_RES.find((x) => x.id === id) || { classes: [] }).classes.includes(h.def.id));
      if (appliedMit.length) { score *= 0.8; if (confidence === 'high') confidence = 'medium'; else if (confidence === 'medium') confidence = 'low'; }
      score = Math.round(score * 100) / 100;
      candidates.push({
        sev: score >= 80 ? 'crit' : score >= 50 ? 'high' : score >= 25 ? 'med' : score >= 10 ? 'low' : 'info',
        title: `${REACH_TITLE[reach]} ${h.def.label} — ${handlerFn.name} (${route.method.toUpperCase()} ${route.route})`,
        ref: `${h.fnPath || handlerFn.path}:${h.line}`,
        reachability: reach,
        mitigations: [...(routeAuth ? [`auth middleware: ${routeAuth}`] : []), ...(reachNote ? [reachNote] : []), ...mitigations],
        impactClass: h.def.id,
        evidence: h.hops > 0 ? `${h.text}  [via ${h.chain.join(' -> ')}]` : h.text,
        confidence,
        taint: h.taint,
        probe: h.def.probe,
        method: route.method.toUpperCase(),
        route: route.route,
        handler: handlerFn.name,
        score,
      });
    }

    // Differential middleware gap: this route is unauth while ≥2 sibling routes in the
    // same file enforce auth — the asymmetry is the finding (CWE-862 shaped).
    // (Emitted after sinks; dedupe keeps one per route.)
    if (reach === 'unauth') {
      const siblings = allRoutes.filter((r) => r.path === route.path && r !== route);
      const authedSiblings = siblings.filter((r) => routeAuthed.get(r));
      if (authedSiblings.length >= 2) {
        const score = MW_GAP.weight * REACH_W.unauth;
        const example = authedSiblings.slice(0, 3).map((r) => `${r.method.toUpperCase()} ${r.route}`).join(', ');
        candidates.push({
          sev: 'high',
          title: `route-registered unauthenticated ${MW_GAP.label} — ${handlerFn.name} (${route.method.toUpperCase()} ${route.route})`,
          ref: regRef,
          reachability: 'unauth',
          mitigations: authedSiblings.length ? [`sibling auth examples: ${example}`] : [],
          impactClass: 'middleware-gap',
          evidence: `${route.method.toUpperCase()} ${route.route} registers no auth middleware; ${authedSiblings.length} sibling route(s) in this file enforce it (${example})`,
          confidence: 'medium',
          taint: 'none',
          probe: MW_GAP.probe,
          method: route.method.toUpperCase(),
          route: route.route,
          handler: handlerFn.name,
          score,
        });
      }
    }
  }

  // Internal scan: functions never reached as route handlers. Taint-needing classes
  // require actual req flow (rare inside non-handlers but possible via closures);
  // structural classes always report — a latent primitive is still worth ranking LAST.
  for (const fn of fns) {
    if (handlerFns.has(fn)) continue;
    const fileCtx = fileCtxs.get(fn.path) || { importsChildProcess: false, fileHead: '' };
    const taintVars = bodyTaint(fn.body);
    const { hits, mitigations } = scanSinks(fn, taintVars, fileCtx);
    for (const h of hits) {
      if (!h.def.structural && h.taint === 'none') continue;
      const effTaint = h.taint;
      let score = h.def.weight * REACH_W.internal * (TAINT_FACTOR[effTaint] ?? TAINT_FACTOR.none);
      let confidence = h.def.structural ? 'medium' : 'low';
      if (h.noImport) { score *= 0.6; confidence = 'low'; }
      score = Math.round(score * 100) / 100;
      candidates.push({
        sev: score >= 80 ? 'crit' : score >= 50 ? 'high' : score >= 25 ? 'med' : score >= 10 ? 'low' : 'info',
        title: `${REACH_TITLE.internal} ${h.def.label} — ${fn.name}`,
        ref: `${fn.path}:${h.line}`,
        reachability: 'internal',
        mitigations,
        impactClass: h.def.id,
        evidence: h.text,
        confidence,
        taint: h.taint,
        probe: h.def.probe,
        handler: fn.name,
        score,
      });
    }
  }

  // Dedupe: one candidate per handler+class, then one per sink ref+class (the same
  // helper reached from two routes is ONE finding, kept at its best score).
  const dedupe = (list, keyFn) => {
    const best = new Map();
    for (const c of list) {
      const k = keyFn(c);
      const cur = best.get(k);
      if (!cur || c.score > cur.score) best.set(k, c);
    }
    return [...best.values()];
  };
  let out = dedupe(candidates, (c) => `${c.handler}::${c.impactClass}`);
  out = dedupe(out, (c) => `${c.ref}::${c.impactClass}`);

  const reachOrder = Object.keys(REACH_W);
  const weightOf = (id) => id === 'middleware-gap' ? MW_GAP_WEIGHT : (SINK_DEFS.find((s) => s.id === id) || { weight: 0 }).weight;
  out.sort((a, b) => b.score - a.score || weightOf(b.impactClass) - weightOf(a.impactClass) ||
    reachOrder.indexOf(a.reachability) - reachOrder.indexOf(b.reachability) || (a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0));
  out.forEach((c, i) => { c.rank = i + 1; });

  return {
    candidates: out,
    gaps: gaps.slice(0, 60),
    stats: {
      functions: fns.length,
      routes: allRoutes.length,
      unresolvedHandlers: gaps.filter((g) => /not found in scanned sources/.test(g.reason)).length,
    },
  };
}

// DOCUMENTED BLIND SPOTS (precision honesty — this miner ranks, it does not convict):
//  - Method-chained registration (`app.route('/x').get(handler)`), dynamic path
//    arguments, and routers re-exported through barrel files are not modeled.
//  - Middleware is read from the registration statement only; auth enforced INSIDE the
//    handler (an early `if (!req.user) return 401`) is not credited — such routes read
//    as 'unauth' and the differential class may over-fire (confidence stays 'medium').
//  - Taint is single-function, one propagation pass; cross-module dataflow and
//    obj.method() descent (object identity unknown to line heuristics) are out of
//    scope. Callee descent is NAME-based; collisions resolve same-file → same-dir →
//    first scanned. Confidence is 'low' past hop 0 for that reason.
//  - Template literals are blanked whole for brace math (carried across lines — they
//    legitimately span lines): `${}` interiors containing braces, nested templates, or
//    an unescaped backtick inside `${}` can unbalance a body match (degrades to an EOF
//    body with a gap note, never a crash). Regex literals are NOT understood: a quote
//    char inside /.../ (e.g. /'/) blanks to end-of-line only — never carried — so the
//    blast radius stays line-local.
//  - jwt-alg-unpinned checks a 4-line window for `algorithms:`; an options object
//    built further away (or shared from a config module) reads as unpinned.
//  - CRLF/CR sources are normalized to LF at ingestion; line numbers refer to the
//    normalized text (same numbering for well-formed files).

