// VARVEL — path-prefix scope guard (2026-08-31, the agoda-class constraint).
//
// A signed engagement scope may confine testing to URL PATH PREFIXES on a host
// (H1 agoda-public: ONLY https://www.agoda.com/book/ — the rest of the host is
// OUT OF SCOPE even though its IPs are signed). The IP/CIDR ring alone cannot
// express that, so when scope.pathPrefixes is present every outbound request to
// a scoped host must ALSO match a prefix. Fail-closed at every choke point:
//   - tools (webscan / crawl / apisurface / vulncheck) refuse before the wire
//   - chainrun refuses an out-of-prefix step before it fires
//   - campaign validateFinding refuses an out-of-prefix re-read
// Refusals are always recorded honestly (scopeRefusals / scope.path.refused),
// never silent.
//
// Semantics:
//   pathPrefixes absent/empty  → no path constraint (backward-compatible)
//   pathPrefixes contains '/'  → no path constraint (the whole host is in scope)
//   otherwise                  → request path must startWith one of the prefixes
//   (anchored: '/book/' does NOT admit '/booking'; the root '/' is OUT unless '/' is listed)

// sanitizePathPrefixes(x) → normalized array of '/'-anchored prefix strings, or
// null when the input carries no usable constraint. Exported for the campaign
// constructor and the server launch path.
export function sanitizePathPrefixes(x) {
  if (!Array.isArray(x)) return null;
  const out = x.filter((p) => typeof p === 'string' && p.startsWith('/'));
  return out.length ? out : null;
}

// pathPrefixAllowed(pathname, prefixes) → bool. `prefixes` is raw scope data
// (sanitized inside); `pathname` is a URL pathname (query already stripped by
// the caller, or a path+query string — the query never affects the match since
// prefixes end at a path boundary and we match on the path head).
export function pathPrefixAllowed(pathname, prefixes) {
  const px = sanitizePathPrefixes(prefixes);
  if (!px) return true;                    // no path constraint
  if (px.includes('/')) return true;       // whole host in scope
  const p = String(pathname || '/');
  return px.some((pre) => p.startsWith(pre));
}

// confinePaths(paths, prefixes) → { allowed, refused } — split a candidate path
// list honestly, so tools can report what the scope kept OFF the wire.
export function confinePaths(paths, prefixes) {
  const allowed = [], refused = [];
  for (const p of paths || []) {
    const pathname = String(p || '').split('?')[0] || '/';
    (pathPrefixAllowed(pathname, prefixes) ? allowed : refused).push(p);
  }
  return { allowed, refused };
}
