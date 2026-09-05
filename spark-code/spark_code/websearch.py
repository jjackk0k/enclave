"""Multi-provider web search, ported from the Spark cockpit's proven chain
(~/chatui/proxy.py): stdlib-only, no API keys, DuckDuckGo lite/html -> Bing
-> Mojeek with per-provider retries, a total time budget, result-quality
validation (degraded/junk pages never reach the model), redirect unwrapping,
and a 5-minute in-memory cache. Runs from this PC over the public internet.

The cockpit's optional API-key seam (brave/tavily via SEARCH_API_PROVIDER)
was intentionally NOT ported - no keys on this box, chain stays as proven.

HARD RULE carried over from the cockpit: search is pure text-in/text-out.
Nothing returned here is ever executed, written, or passed to a shell.
"""

from __future__ import annotations

import base64
import re
import time
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import List, Optional, Tuple

from . import config

SEARCH_UA = ("Mozilla/5.0 (X11; Linux x86_64; rv:124.0) "
             "Gecko/20100101 Firefox/124.0")
SEARCH_HEADERS = {"User-Agent": SEARCH_UA, "Accept-Language": "en-US,en;q=0.9"}

# Provider endpoints as module constants so tests can point the chain at a
# local mock server instead of the public internet.
DDG_LITE_URL = "https://lite.duckduckgo.com/lite/?q="
DDG_HTML_URL = "https://html.duckduckgo.com/html/?q="
BING_URL = "https://www.bing.com/search?q="
MOJEEK_URL = "https://www.mojeek.com/search?q="

# Per provider: initial try + 2 retries (1.5s / 4s backoff), as in the
# cockpit. Tests patch this to zeros to keep the suite fast.
RETRY_WAITS = (0, 1.5, 4)

_SNIPPET_CHARS = 240  # 1-2 lines per result in the formatted output


def _http_get(url: str, timeout: int = 10) -> str:
    req = urllib.request.Request(url, headers=SEARCH_HEADERS)
    return urllib.request.urlopen(req, timeout=timeout).read() \
        .decode("utf-8", "replace")


class _DDGLite(HTMLParser):
    """Small robust parser for lite.duckduckgo.com result pages."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.results = []
        self._cur = None
        self._in_a = False
        self._snippet = False
        self._snippet_text = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        cls = a.get("class", "")
        if tag == "a" and "result-link" in cls:
            self._in_a = True
            self._cur = {"title": "", "url": a.get("href", ""), "snippet": ""}
        elif tag == "td" and "result-snippet" in cls:
            self._snippet = True
            self._snippet_text = []

    def handle_endtag(self, tag):
        if tag == "a" and self._in_a:
            self._in_a = False
            if self._cur:
                self.results.append(self._cur)
                self._cur = None
        elif tag == "td" and self._snippet:
            self._snippet = False
            if self.results:
                self.results[-1]["snippet"] = \
                    " ".join("".join(self._snippet_text).split())

    def handle_data(self, data):
        if self._in_a and self._cur is not None:
            self._cur["title"] += data
        if self._snippet:
            self._snippet_text.append(data)
        if "Sponsored link" in data and self.results:
            self.results[-1]["sponsored"] = True


class _DDGHtml(HTMLParser):
    """Parser for html.duckduckgo.com/html/ result pages."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.results = []
        self._cur = None
        self._in_a = False
        self._snippet = False
        self._snippet_text = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        cls = a.get("class", "")
        if tag == "a" and "result__a" in cls:
            self._in_a = True
            self._cur = {"title": "", "url": a.get("href", ""), "snippet": ""}
        elif "result__snippet" in cls and not self._snippet:
            self._snippet = True
            self._snippet_text = []

    def handle_endtag(self, tag):
        if tag == "a" and self._in_a:
            self._in_a = False
            if self._cur:
                self.results.append(self._cur)
                self._cur = None
        if self._snippet and tag in ("a", "td", "div"):
            self._snippet = False
            if self.results:
                self.results[-1]["snippet"] = \
                    " ".join("".join(self._snippet_text).split())

    def handle_data(self, data):
        if self._in_a and self._cur is not None:
            self._cur["title"] += data
        if self._snippet:
            self._snippet_text.append(data)


class _BingParser(HTMLParser):
    """Parser for www.bing.com/search result pages (li.b_algo blocks)."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.results = []
        self._cur = None
        self._in_h2 = False
        self._in_a = False
        self._in_p = False
        self._p_text = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        cls = a.get("class", "")
        if tag == "li" and "b_algo" in cls:
            self._cur = {"title": "", "url": "", "snippet": ""}
        elif self._cur is not None:
            if tag == "h2":
                self._in_h2 = True
            elif tag == "a" and self._in_h2 and not self._cur["url"]:
                self._in_a = True
                self._cur["url"] = a.get("href", "")
            elif tag == "p" and "b_lineclamp" in cls and not self._cur["snippet"]:
                self._in_p = True
                self._p_text = []

    def handle_endtag(self, tag):
        if tag == "h2":
            self._in_h2 = False
        elif tag == "a" and self._in_a:
            self._in_a = False
        elif tag == "p" and self._in_p:
            self._in_p = False
            if self._cur is not None:
                self._cur["snippet"] = " ".join("".join(self._p_text).split())
        elif tag == "li" and self._cur is not None:
            if self._cur["url"]:
                self.results.append(self._cur)
            self._cur = None

    def handle_data(self, data):
        if self._in_a and self._cur is not None:
            self._cur["title"] += data
        if self._in_p:
            self._p_text.append(data)


class _MojeekParser(HTMLParser):
    """Tolerant parser for www.mojeek.com result pages."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.results = []
        self._cur = None
        self._in_a = False
        self._in_p = False
        self._p_text = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        cls = a.get("class", "")
        if tag == "a" and ("ob" in cls.split() or "title" in cls.split()
                           or "result-title" in cls):
            self._in_a = True
            self._cur = {"title": "", "url": a.get("href", ""), "snippet": ""}
        elif tag == "p" and ("s" == cls.strip() or "result-desc" in cls):
            self._in_p = True
            self._p_text = []

    def handle_endtag(self, tag):
        if tag == "a" and self._in_a:
            self._in_a = False
            if self._cur and self._cur["url"]:
                self.results.append(self._cur)
            self._cur = None
        elif tag == "p" and self._in_p:
            self._in_p = False
            if self.results:
                self.results[-1]["snippet"] = \
                    " ".join("".join(self._p_text).split())

    def handle_data(self, data):
        if self._in_a and self._cur is not None:
            self._cur["title"] += data
        if self._in_p:
            self._p_text.append(data)


def _unwrap_url(u: str) -> str:
    """Unwrap DDG/Bing redirect URLs to their real targets."""
    if "duckduckgo.com/l/?" in u:
        full = u if u.startswith("http") else "https:" + u
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(full).query)
        return (qs.get("uddg") or [""])[0]
    if "bing.com/ck/a" in u:
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(u).query)
        enc = (qs.get("u") or [""])[0]
        if enc.startswith("a1"):
            s = enc[2:] + "=" * (-len(enc[2:]) % 4)
            try:
                return base64.urlsafe_b64decode(s).decode("utf-8", "replace")
            except Exception:
                return ""
    return u


def _clean_results(raw, provider_host: str) -> List[dict]:
    out = []
    for r in raw:
        u = _unwrap_url(r["url"])
        if not u.startswith(("http://", "https://")) or provider_host in u:
            continue
        if r.get("sponsored"):
            continue
        out.append({"title": " ".join(r["title"].split())[:200],
                    "url": u,
                    "snippet": r.get("snippet", "")[:500]})
        if len(out) >= config.SEARCH_RESULTS:
            break
    return out


# ---------------- result-quality validation ----------------
# Junk (news-rail/homepage links on degraded pages) must NEVER be presented
# as results. A provider only "succeeds" when its results actually overlap
# the query's significant terms.
_STOPWORDS = frozenset((
    "a an and are as at be best by can could for from has have how i in is "
    "it its of on or s should that the their them this to was what when "
    "where which who why will with you your latest new vs into using use "
    "does do did not no yes over under more most much many any all some").split())


def _sig_terms(query: str) -> List[str]:
    terms = []
    for t in re.split(r"[^a-zA-Z0-9+#]+", query.lower()):
        if len(t) < 3 or t in _STOPWORDS or t.isdigit():
            continue
        terms.append(t)
    return terms


def _domain(u: str) -> str:
    try:
        return urllib.parse.urlparse(u).hostname or ""
    except Exception:
        return ""


def _hit(t: str, hay: str, substring_ok: bool) -> bool:
    """Term match: word-boundary everywhere (so 'gui' does NOT match
    'guide'); in domains, terms >=4 chars may also match glued text like
    'qtforpython'."""
    if substring_ok and len(t) >= 4 and t in hay:
        return True
    return re.search(r"\b" + re.escape(t) + r"\b", hay) is not None


def _relevant(r: dict, terms: List[str]) -> bool:
    title = r["title"].lower()
    dom = _domain(r["url"]).lower()
    snip = r.get("snippet", "").lower()
    strong = sum(1 for t in terms
                 if _hit(t, title, False) or _hit(t, dom, True))
    if strong >= 1:
        return True
    weak = sum(1 for t in terms
               if _hit(t, title + " " + snip, False) or _hit(t, dom, True))
    return weak >= 2


def validate_results(res, query: str):
    """Provider-level quality gate. Returns validated results (possibly
    empty), or None when the provider page was degraded/blocked:
    - fewer than 3 extracted organic results -> degraded page
    - fewer than 2 results overlapping significant query terms -> junk
    Otherwise the relevant subset (may be [] = genuine no-results)."""
    if res is None:
        return None
    if len(res) < 3:
        return None
    terms = _sig_terms(query)
    if not terms:
        return res  # nothing meaningful to check against
    relevant = [r for r in res if _relevant(r, terms)]
    if len(relevant) < 2:
        return None
    return relevant


# ---------------- providers ----------------
def _prov_ddg_lite(q: str):
    html = _http_get(DDG_LITE_URL + urllib.parse.quote(q))
    if "anomaly" in html.lower() or "challenge" in html.lower():
        return None  # challenge/rate-limit page, not a real result page
    p = _DDGLite()
    p.feed(html)
    return _clean_results(p.results, "duckduckgo.com")


def _prov_ddg_html(q: str):
    html = _http_get(DDG_HTML_URL + urllib.parse.quote(q))
    if "anomaly" in html.lower() or "challenge" in html.lower():
        return None
    p = _DDGHtml()
    p.feed(html)
    return _clean_results(p.results, "duckduckgo.com")


def _prov_bing(q: str):
    html = _http_get(BING_URL + urllib.parse.quote(q))
    low = html.lower()
    if "b_algo" not in html:
        if "captcha" in low or "unusual traffic" in low:
            return None
        return []  # plausible genuine "no results" page
    p = _BingParser()
    p.feed(html)
    return _clean_results(p.results, "bing.com")


def _prov_mojeek(q: str):
    html = _http_get(MOJEEK_URL + urllib.parse.quote(q))
    if "captcha" in html.lower():
        return None
    p = _MojeekParser()
    p.feed(html)
    return _clean_results(p.results, "mojeek.com")


PROVIDERS = (("ddg-lite", _prov_ddg_lite), ("ddg-html", _prov_ddg_html),
             ("bing", _prov_bing), ("mojeek", _prov_mojeek))


def format_results(query: str, results: List[dict], provider: str) -> str:
    """Compact numbered list for the model: title + URL + 1-2 line snippet.
    Five short results stay well under config.TOOL_RESULT_CHAR_CAP."""
    lines = [f"{len(results)} result(s) for {query!r} (via {provider})"]
    for i, r in enumerate(results, 1):
        lines.append(f"{i}. {r['title']}")
        lines.append(f"   {r['url']}")
        snip = " ".join(r.get("snippet", "").split())[:_SNIPPET_CHARS]
        if snip:
            lines.append(f"   {snip}")
    return "\n".join(lines)


class WebSearch:
    """Provider chain + 5-min cache + per-turn cap. One per ToolExecutor;
    the agent loop calls begin_turn() at the start of each user turn."""

    def __init__(self) -> None:
        self._cache = {}      # normalized query -> (ts, results, provider)
        self._turn_used = 0

    def begin_turn(self) -> None:
        self._turn_used = 0

    @property
    def turn_used(self) -> int:
        return self._turn_used

    def search(self, query: str) -> Tuple[str, Optional[List[dict]], Optional[str]]:
        """Returns (status, results, provider):
          ("results", [...], name)  - validated results; [] = genuine no-results
          ("limited", None, None)   - every provider failed / was degraded /
                                      rate-limited / returned junk
          ("capped",  None, None)   - per-turn cap already reached, no fetch
        Cache hits and fetches both count against the per-turn cap."""
        if self._turn_used >= config.SEARCH_MAX_PER_TURN:
            return ("capped", None, None)
        self._turn_used += 1
        key = " ".join(query.lower().split())
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < config.SEARCH_CACHE_TTL:
            return ("results", hit[1], hit[2] + " (cache)")
        start = time.time()
        for name, fn in PROVIDERS:
            for wait in RETRY_WAITS:
                if time.time() - start > config.SEARCH_TOTAL_BUDGET:
                    break
                if wait:
                    time.sleep(wait)
                try:
                    res = validate_results(fn(query), query)
                except Exception:
                    res = None
                if res is None:
                    continue
                self._cache[key] = (time.time(), res, name)
                return ("results", res, name)
        return ("limited", None, None)
