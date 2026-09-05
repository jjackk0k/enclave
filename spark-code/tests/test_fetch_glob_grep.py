"""fetch_url / glob / grep tools: readable-text extraction (script/style/nav
stripped), honest errors (status, content-type, too-large, unreachable),
redirect following, login-wall note, glob/grep behavior over the shared
SKIP_DIRS walker, and executor roundtrips (read-only: never prompt)."""

import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from spark_code import tools
from spark_code.tools import ToolExecutor

HTML_PAGE = """<html><head><title>Async Howto</title>
<style>body { color: red }</style>
<script>tracker.beacon("x")</script></head>
<body><nav>Home | Products | Sign in</nav>
<article><h1>Async IO in Python</h1>
<p>Asyncio  provides   infrastructure for
concurrent code.</p><p>Second paragraph here.</p></article>
<footer>copyright 2026</footer></body></html>"""


class _PageHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        page = self.server.pages.get(self.path)  # type: ignore[assignment]
        if page is None:
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if page[0] == "redirect":
            self.send_response(302)
            self.send_header("Location", page[1])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        _, ctype, body = page
        if isinstance(body, str):
            body = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class MockPageServer:
    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _PageHandler)
        self.httpd.pages = {}
        self.httpd.handle_error = lambda *a, **k: None
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


class TestFetchUrl(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ex = ToolExecutor(cwd=self.tmp.name, approve=lambda a, s, d: True)

    def tearDown(self):
        self.tmp.cleanup()

    def fetch(self, url):
        return self.ex.execute("fetch_url", {"url": url})

    def test_html_extraction_strips_chrome(self):
        with MockPageServer() as srv:
            srv.httpd.pages = {"/page": ("ok", "text/html; charset=utf-8", HTML_PAGE)}
            r = self.fetch(srv.base_url + "/page")
        self.assertTrue(r.ok, r.text)
        self.assertIn("Async IO in Python", r.text)
        self.assertIn("Asyncio provides infrastructure for concurrent code.", r.text)
        self.assertIn("Second paragraph here.", r.text)
        self.assertIn("[text/html", r.text)
        # chrome stripped
        self.assertNotIn("tracker.beacon", r.text)
        self.assertNotIn("color: red", r.text)
        self.assertNotIn("Home | Products", r.text)
        self.assertNotIn("copyright 2026", r.text)

    def test_redirect_followed_and_noted(self):
        with MockPageServer() as srv:
            srv.httpd.pages = {"/old": ("redirect", "/new"),
                               "/new": ("ok", "text/plain", "landing text")}
            r = self.fetch(srv.base_url + "/old")
        self.assertTrue(r.ok)
        self.assertIn("landing text", r.text)
        self.assertIn("redirected from", r.text)

    def test_404_is_honest(self):
        with MockPageServer() as srv:
            r = self.fetch(srv.base_url + "/missing")
        self.assertFalse(r.ok)
        self.assertIn("HTTP 404", r.text)

    def test_binary_content_type_refused(self):
        with MockPageServer() as srv:
            srv.httpd.pages = {"/bin": ("ok", "application/octet-stream", "x" * 100)}
            r = self.fetch(srv.base_url + "/bin")
        self.assertFalse(r.ok)
        self.assertIn("content-type", r.text)
        self.assertIn("discarded", r.text)

    def test_bad_scheme_refused(self):
        for bad in ("ftp://example.com/x", "file:///C:/x.txt", "example.com"):
            r = self.fetch(bad)
            self.assertFalse(r.ok, bad)
            self.assertIn("http/https", r.text)

    def test_unreachable_is_honest(self):
        r = self.fetch("http://127.0.0.1:9/nope")
        self.assertFalse(r.ok)
        self.assertIn("could not reach", r.text)

    def test_raw_cap_and_text_cap_notes(self):
        big = "word " * 60_000  # 300KB of text
        with MockPageServer() as srv:
            srv.httpd.pages = {"/big": ("ok", "text/plain", big)}
            r = self.fetch(srv.base_url + "/big")
        self.assertTrue(r.ok)
        self.assertIn("200KB", r.text)          # raw read cap noted
        self.assertIn("truncated to 8,000 chars", r.text)  # return cap noted
        self.assertLess(len(r.text), 9_000)

    def test_login_wall_noted(self):
        login = ("<html><body><form>Sign in <input type='password'>"
                 "<button>Log in</button></form></body></html>")
        with MockPageServer() as srv:
            srv.httpd.pages = {"/wall": ("ok", "text/html", login)}
            r = self.fetch(srv.base_url + "/wall")
        self.assertTrue(r.ok)
        self.assertIn("login wall", r.text)

    def test_read_only_never_prompts(self):
        approvals = []
        ex = ToolExecutor(cwd=self.tmp.name,
                          approve=lambda a, s, d: approvals.append(a) or True)
        with MockPageServer() as srv:
            srv.httpd.pages = {"/p": ("ok", "text/html", HTML_PAGE)}
            r = ex.execute("fetch_url", {"url": srv.base_url + "/p"})
        self.assertTrue(r.ok)
        self.assertEqual(approvals, [])
        self.assertIn("fetch_url", ToolExecutor.TOOL_NAMES)


class TestGlobAndGrep(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / "sub").mkdir()
        (root / ".git").mkdir()
        (root / "node_modules").mkdir()
        (root / "a.py").write_text("import os\nalpha = 1\n", encoding="utf-8")
        (root / "sub" / "b.py").write_text("beta = 2\nalpha again\n",
                                           encoding="utf-8")
        (root / "sub" / "c.txt").write_text("alpha in text\n", encoding="utf-8")
        (root / ".git" / "config").write_text("alpha hidden\n", encoding="utf-8")
        (root / "node_modules" / "x.py").write_text("alpha hidden too\n",
                                                    encoding="utf-8")
        self.ex = ToolExecutor(cwd=str(root), approve=lambda a, s, d: True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_glob_matches_basename_at_any_depth_and_skips_dirs(self):
        r = self.ex.execute("glob", {"pattern": "*.py"})
        self.assertTrue(r.ok, r.text)
        self.assertIn("a.py", r.text)
        self.assertIn(str(Path("sub") / "b.py"), r.text)
        self.assertNotIn("node_modules", r.text)  # walker skips them
        self.assertNotIn("config", r.text)        # .git never walked

    def test_glob_path_pattern(self):
        r = self.ex.execute("glob", {"pattern": "sub/*.txt"})
        self.assertIn("c.txt", r.text)
        self.assertNotIn("a.py", r.text)

    def test_glob_refuses_missing_dir(self):
        r = self.ex.execute("glob", {"pattern": "*.py", "path": "nope"})
        self.assertFalse(r.ok)
        self.assertIn("Not a directory", r.text)

    def test_grep_returns_path_line_matches(self):
        r = self.ex.execute("grep", {"regex": "alpha"})
        self.assertTrue(r.ok, r.text)
        self.assertIn("a.py:2: alpha = 1", r.text)
        self.assertIn("alpha again", r.text)       # second file
        self.assertIn("c.txt:1:", r.text)          # and .txt
        self.assertIn("3 line(s)", r.text)         # every matching line
        self.assertNotIn("hidden", r.text)         # .git/node_modules skipped

    def test_grep_file_glob_filter(self):
        r = self.ex.execute("grep", {"regex": "alpha", "glob": "*.txt"})
        self.assertIn("c.txt:1:", r.text)
        self.assertNotIn("a.py", r.text)

    def test_grep_single_file(self):
        r = self.ex.execute("grep", {"regex": "beta", "path": "sub/b.py"})
        self.assertTrue(r.ok)
        self.assertIn("b.py:1: beta = 2", r.text)

    def test_grep_bad_regex_refused(self):
        r = self.ex.execute("grep", {"regex": "(unclosed"})
        self.assertFalse(r.ok)
        self.assertIn("Bad grep regex", r.text)

    def test_grep_cap_is_honest(self):
        with mock.patch.object(tools, "SEARCH_MAX_HITS", 2):
            r = self.ex.execute("grep", {"regex": "alpha"})
        self.assertIn("capped at 2", r.text)
        self.assertEqual(r.text.count(":1:") + r.text.count(":2:"), 2)

    def test_spec_lists_new_tools_and_keeps_big_files_rule(self):
        spec = tools.TOOL_SPEC_FOR_PROMPT
        for name in ("fetch_url(url)", "glob(pattern", "grep(regex",
                     "read_image(path)"):
            self.assertIn(name, spec)
        self.assertIn("BIG FILES", spec)
        self.assertIn("~100 lines", spec)
        for name in ("fetch_url", "glob", "grep", "read_image"):
            self.assertIn(name, ToolExecutor.TOOL_NAMES)


if __name__ == "__main__":
    unittest.main()
