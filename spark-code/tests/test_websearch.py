"""Web search tests: provider chain against a scripted in-process HTTP
server (mock_server.py style - the provider endpoint constants are pointed
at 127.0.0.1, so no public internet is touched). Covers result formatting,
provider fallback, redirect unwrapping, sponsored filtering, the per-turn
cap, the cache, and the executor wiring (no approval prompt)."""

import contextlib
import io
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from spark_code import config, websearch
from spark_code.agent import Agent
from spark_code.client import SparkClient
from spark_code.session import SessionStore
from spark_code.tools import ToolExecutor
from spark_code.ui import UI
from tests.mock_server import MockSparkServer

QUERY = "python asyncio docs"  # sig terms: python, asyncio, docs

GOOD_RESULTS = [
    ("asyncio - Asynchronous I/O - Python 3 docs",
     "https://docs.python.org/3/library/asyncio.html",
     "The asyncio module provides infrastructure for writing concurrent "
     "Python code using the async/await syntax."),
    ("Async IO in Python: A Complete Walkthrough",
     "https://realpython.com/async-io-python/",
     "Learn how Python asyncio works with this complete async IO walkthrough."),
    ("asyncio docs - Python Developer's Guide",
     "https://devguide.python.org/asyncio/",
     "Notes on developing the asyncio package in CPython."),
    ("Python asyncio: a practical guide",
     "https://example.com/asyncio-guide",
     "A practical asyncio guide for Python developers: event loops and tasks."),
    ("Coroutines and Tasks - Python asyncio docs",
     "https://docs.python.org/3/library/asyncio-task.html",
     "Declaring coroutines and running asyncio tasks in Python."),
]

CHALLENGE_PAGE = "<html><body>Anomaly detection challenge</body></html>"


def ddg_lite_page(results):
    rows = []
    for title, url, snip in results:
        rows.append(f'<tr><td><a class="result-link" href="{url}">{title}</a></td></tr>')
        rows.append(f'<tr><td class="result-snippet">{snip}</td></tr>')
    return "<html><body><table>" + "".join(rows) + "</table></body></html>"


def ddg_html_page(results):
    out = []
    for title, url, snip in results:
        out.append(f'<div class="result"><a class="result__a" href="{url}">{title}</a>'
                   f'<a class="result__snippet">{snip}</a></div>')
    return "<html><body>" + "".join(out) + "</body></html>"


def bing_page(results):
    out = []
    for title, url, snip in results:
        out.append(f'<li class="b_algo"><h2><a href="{url}">{title}</a></h2>'
                   f'<p class="b_lineclamp2">{snip}</p></li>')
    return "<html><body><ol>" + "".join(out) + "</ol></body></html>"


def mojeek_page(results):
    out = []
    for title, url, snip in results:
        out.append(f'<a class="ob" href="{url}">{title}</a>'
                   f'<p class="s">{snip}</p>')
    return "<html><body><ul>" + "".join(out) + "</ul></body></html>"


class _SearchHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        server = self.server  # type: ignore[assignment]
        for prefix, page in server.pages.items():
            if self.path.startswith(prefix):
                server.requests.append(self.path)
                if page is None:  # provider down: drop the connection
                    self.close_connection = True
                    return
                body = page.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


class MockSearchServer:
    """Serves scripted result pages per path prefix; None drops the
    connection (provider down / rate-limited)."""

    ENDPOINTS = ("DDG_LITE_URL", "DDG_HTML_URL", "BING_URL", "MOJEEK_URL")

    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _SearchHandler)
        self.httpd.pages = {}      # path prefix -> html, or None = drop connection
        self.httpd.requests = []   # requested paths, for assertions
        # dropped sockets would otherwise spew handler tracebacks into output
        self.httpd.handle_error = lambda *a, **k: None
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    @property
    def requests(self) -> list:
        return self.httpd.requests

    def point_chain_at_mock(self):
        """Redirect every provider endpoint + zero the retry backoff."""
        self._saved = {name: getattr(websearch, name)
                       for name in self.ENDPOINTS + ("RETRY_WAITS",)}
        websearch.DDG_LITE_URL = self.base_url + "/lite/?q="
        websearch.DDG_HTML_URL = self.base_url + "/html/?q="
        websearch.BING_URL = self.base_url + "/bing?q="
        websearch.MOJEEK_URL = self.base_url + "/mojeek?q="
        websearch.RETRY_WAITS = (0, 0, 0)

    def restore_chain(self):
        for name, val in self._saved.items():
            setattr(websearch, name, val)

    def __enter__(self):
        self.thread.start()
        self.point_chain_at_mock()
        return self

    def __exit__(self, *exc):
        self.restore_chain()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


class TestWebSearch(unittest.TestCase):
    def setUp(self):
        self.ws = websearch.WebSearch()

    def _search_ok(self, srv, query=QUERY):
        status, results, provider = self.ws.search(query)
        self.assertEqual(status, "results")
        self.assertIsNotNone(results)
        return results, provider

    # -- success + formatting -------------------------------------------------
    def test_success_formatting(self):
        with MockSearchServer() as srv:
            srv.httpd.pages = {"/lite/": ddg_lite_page(GOOD_RESULTS)}
            results, provider = self._search_ok(srv)
            self.assertEqual(provider, "ddg-lite")
            self.assertEqual(len(results), config.SEARCH_RESULTS)
            text = websearch.format_results(QUERY, results, provider)
            self.assertIn("5 result(s) for 'python asyncio docs' (via ddg-lite)", text)
            self.assertIn("1. asyncio - Asynchronous I/O - Python 3 docs", text)
            self.assertIn("   https://docs.python.org/3/library/asyncio.html", text)
            self.assertIn("5. Coroutines and Tasks", text)
            self.assertLess(len(text), config.TOOL_RESULT_CHAR_CAP)

    def test_snippet_trimmed_to_two_lines(self):
        long_snip = ("word " * 100).strip()  # 499 chars
        results = [GOOD_RESULTS[0], GOOD_RESULTS[1], GOOD_RESULTS[2],
                   ("Python asyncio verbose docs", "https://example.com/v", long_snip)]
        with MockSearchServer() as srv:
            srv.httpd.pages = {"/lite/": ddg_lite_page(results)}
            text = websearch.format_results(QUERY, self._search_ok(srv)[0], "ddg-lite")
            self.assertNotIn(long_snip, text)
            self.assertLess(len(text), config.TOOL_RESULT_CHAR_CAP)

    # -- provider fallback ------------------------------------------------------
    def test_fallback_when_first_provider_challenged(self):
        with MockSearchServer() as srv:
            srv.httpd.pages = {"/lite/": CHALLENGE_PAGE,
                               "/html/": ddg_html_page(GOOD_RESULTS)}
            results, provider = self._search_ok(srv)
            self.assertEqual(provider, "ddg-html")
            self.assertEqual(len(results), config.SEARCH_RESULTS)
            # ddg-lite got its 3 tries (initial + 2 retries), then ddg-html 1
            lite = [r for r in srv.requests if r.startswith("/lite/")]
            html = [r for r in srv.requests if r.startswith("/html/")]
            self.assertEqual(len(lite), 3)
            self.assertEqual(len(html), 1)

    def test_fallback_to_bing_and_mojeek_parsers(self):
        with MockSearchServer() as srv:
            srv.httpd.pages = {"/lite/": CHALLENGE_PAGE, "/html/": CHALLENGE_PAGE,
                               "/bing": bing_page(GOOD_RESULTS)}
            results, provider = self._search_ok(srv)
            self.assertEqual(provider, "bing")
            self.assertIn("realpython.com", results[1]["url"])

            self.ws.begin_turn()
            srv.httpd.pages = {"/lite/": CHALLENGE_PAGE, "/html/": CHALLENGE_PAGE,
                               "/bing": CHALLENGE_PAGE,
                               "/mojeek": mojeek_page(GOOD_RESULTS)}
            results, provider = self._search_ok(srv, "python asyncio docs reference")
            self.assertEqual(provider, "mojeek")
            self.assertEqual(results[0]["title"], GOOD_RESULTS[0][0])

    def test_all_providers_down_is_limited(self):
        with MockSearchServer() as srv:
            srv.httpd.pages = {"/lite/": None, "/html/": None,
                               "/bing": None, "/mojeek": None}
            status, results, provider = self.ws.search(QUERY)
            self.assertEqual(status, "limited")
            self.assertIsNone(results)
            # 4 providers x 3 attempts each
            self.assertEqual(len(srv.requests), 12)

    def test_degraded_or_junk_page_never_reaches_the_model(self):
        as_dicts = [{"title": t, "url": u, "snippet": s}
                    for t, u, s in GOOD_RESULTS]
        # fewer than 3 organic results -> degraded page -> provider "fails"
        self.assertIsNone(websearch.validate_results(as_dicts[:2], QUERY))
        # junk: 5 results with no overlap with the query's significant terms
        junk = [{"title": "Breaking celebrity news",
                 "url": f"https://gossip.example.com/{i}",
                 "snippet": "entertainment homepage rail links"}
                for i in range(5)]
        self.assertIsNone(websearch.validate_results(junk, QUERY))
        # sane results pass validation unchanged
        self.assertEqual(websearch.validate_results(as_dicts, QUERY), as_dicts)
        # an empty page is treated as degraded too (falls to next provider)
        self.assertIsNone(websearch.validate_results([], QUERY))

    # -- redirect unwrapping / sponsored filtering -------------------------------
    def test_ddg_redirect_unwrapped_and_sponsored_dropped(self):
        wrapped = ("//duckduckgo.com/l/?uddg="
                   + "https%3A%2F%2Frealpython.com%2Fasync-io-python%2F")
        page = ddg_lite_page([GOOD_RESULTS[0], GOOD_RESULTS[2], GOOD_RESULTS[3],
                              GOOD_RESULTS[4]])
        sponsored = ('<tr><td><a class="result-link" '
                     'href="https://ad.example.com/python-asyncio-docs">'
                     'Buy python asyncio docs</a></td></tr>'
                     '<tr><td>Sponsored link</td></tr>')
        wrapped_row = ('<tr><td><a class="result-link" href="' + wrapped + '">'
                       + GOOD_RESULTS[1][0] + '</a></td></tr>')
        page = page.replace("</table>", wrapped_row + sponsored + "</table>")
        with MockSearchServer() as srv:
            srv.httpd.pages = {"/lite/": page}
            results, _ = self._search_ok(srv)
            urls = [r["url"] for r in results]
            self.assertIn("https://realpython.com/async-io-python/", urls)
            self.assertNotIn("https://ad.example.com/python-asyncio-docs", urls)
            self.assertFalse(any("duckduckgo.com" in u for u in urls))

    # -- per-turn cap ---------------------------------------------------------------
    def test_per_turn_cap(self):
        with MockSearchServer() as srv:
            srv.httpd.pages = {"/lite/": ddg_lite_page(GOOD_RESULTS)}
            for i in range(config.SEARCH_MAX_PER_TURN):
                status, _, _ = self.ws.search(f"{QUERY} {i}")  # unique: no cache
                self.assertEqual(status, "results")
            status, results, _ = self.ws.search(f"{QUERY} overflow")
            self.assertEqual(status, "capped")
            self.assertIsNone(results)
            self.assertEqual(len(srv.requests), config.SEARCH_MAX_PER_TURN)
            self.ws.begin_turn()
            status, _, _ = self.ws.search(f"{QUERY} after-reset")
            self.assertEqual(status, "results")

    # -- cache -------------------------------------------------------------------------
    def test_cache_hit_skips_the_network(self):
        with MockSearchServer() as srv:
            srv.httpd.pages = {"/lite/": ddg_lite_page(GOOD_RESULTS)}
            results1, provider1 = self._search_ok(srv)
            self.assertEqual(len(srv.requests), 1)
            # messy casing/spacing normalizes to the same cache key
            results2, provider2 = self._search_ok(srv, "  Python   ASYNCIO docs ")
            self.assertEqual(provider2, "ddg-lite (cache)")
            self.assertEqual(results2, results1)
            self.assertEqual(len(srv.requests), 1)  # no second fetch

    def test_cache_entry_expires(self):
        with MockSearchServer() as srv:
            srv.httpd.pages = {"/lite/": ddg_lite_page(GOOD_RESULTS)}
            self._search_ok(srv)
            key = " ".join(QUERY.lower().split())
            ts, res, name = self.ws._cache[key]
            self.ws._cache[key] = (ts - config.SEARCH_CACHE_TTL - 5, res, name)
            _, provider = self._search_ok(srv)
            self.assertEqual(provider, "ddg-lite")  # fresh fetch, not "(cache)"
            self.assertEqual(len(srv.requests), 2)

    # -- executor + agent wiring ---------------------------------------------------
    def test_executor_tool_no_approval(self):
        approvals = []

        def approve(action, summary, detail):
            approvals.append(action)
            return True

        with tempfile.TemporaryDirectory() as tmp, MockSearchServer() as srv:
            srv.httpd.pages = {"/lite/": ddg_lite_page(GOOD_RESULTS)}
            ex = ToolExecutor(cwd=tmp, approve=approve)
            r = ex.execute("web_search", {"query": QUERY})
            self.assertTrue(r.ok, r.text)
            self.assertIn("1. asyncio", r.text)
            self.assertEqual(approvals, [])  # read-only: never prompts
            self.assertIn("web_search", ToolExecutor.TOOL_NAMES)

    def test_executor_empty_query_and_limited_text(self):
        with tempfile.TemporaryDirectory() as tmp, MockSearchServer() as srv:
            ex = ToolExecutor(cwd=tmp, approve=lambda a, s, d: True)
            r = ex.execute("web_search", {"query": "   "})
            self.assertFalse(r.ok)
            self.assertIn("non-empty", r.text)
            srv.httpd.pages = {"/lite/": None, "/html/": None,
                               "/bing": None, "/mojeek": None}
            r = ex.execute("web_search", {"query": QUERY})
            self.assertFalse(r.ok)
            self.assertIn("unavailable", r.text)

    def test_agent_turn_resets_search_cap(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            store = SessionStore(Path(tmp) / "sessions")
            session = store.create(cwd=tmp, model="mock-heretic-27b")
            client = SparkClient(base_url=srv.base_url, model="mock-heretic-27b")
            executor = ToolExecutor(cwd=tmp, approve=lambda a, s, d: True)
            ui = UI(yolo=True, color=False)
            agent = Agent(client, session, executor, ui)
            executor.websearch._turn_used = 7  # pretend a previous turn searched
            srv.scripts.append({
                "deltas": ["plain answer."],  # terminator: keeps auto-continue silent
                "usage": {"prompt_tokens": 10, "completion_tokens": 2},
            })
            with contextlib.redirect_stdout(io.StringIO()):
                agent.run_turn("hi")
            self.assertEqual(executor.websearch.turn_used, 0)


if __name__ == "__main__":
    unittest.main()
