"""Web search activity block: styled query header, progress line that is
erased in place on a VT console, numbered results (title + domain + 1-line
snippet + dimmed URL), honest failure lines, no raw tool JSON on screen -
plus agent-loop integration and Ctrl-C-during-search behavior."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spark_code import config
from spark_code.agent import Agent
from spark_code.client import SparkClient
from spark_code.session import SessionStore
from spark_code.tools import ToolExecutor
from spark_code.ui import BOLD, ESC, GRAY, MAGENTA, RESET, UI, YELLOW

from tests.mock_server import MockSparkServer
from tests.test_websearch import GOOD_RESULTS, MockSearchServer, ddg_lite_page

QUERY = "python asyncio docs"


def results_data(n=5, status="results"):
    results = [{"title": t, "url": u, "snippet": s} for t, u, s in GOOD_RESULTS[:n]]
    return {"query": QUERY, "status": status,
            "provider": "ddg-lite", "results": results}


class TtyIO(io.StringIO):
    def isatty(self):
        return True


def render(ui, data, elapsed=1.23, tty=False):
    buf = TtyIO() if tty else io.StringIO()
    with contextlib.redirect_stdout(buf):
        ui.search_begin(str(data.get("query") or ""))
        ui.search_end(data, elapsed)
    return buf.getvalue()


class TestBlockRendering(unittest.TestCase):
    def test_results_block_shape_and_content(self):
        out = render(UI(color=False), results_data())
        self.assertIn("⚙ web search · python asyncio docs", out)
        self.assertIn("searching…", out)  # progress line (kept as history when piped)
        self.assertIn("·  5 result(s) via ddg-lite (1.2s)", out)
        # numbered title + domain lines
        self.assertIn("1. asyncio - Asynchronous I/O - Python 3 docs  ·  docs.python.org", out)
        self.assertIn("5. Coroutines and Tasks - Python asyncio docs  ·  docs.python.org", out)
        # 1-line snippet and the URL on its own line
        self.assertIn("       The asyncio module provides infrastructure", out)
        self.assertIn("       https://realpython.com/async-io-python/", out)
        # every line is single-line: no embedded newlines inside fields
        for line in out.splitlines():
            self.assertNotIn("\r", line)

    def test_no_raw_tool_json_anywhere(self):
        out = render(UI(color=False), results_data())
        self.assertNotIn('{"tool"', out)
        self.assertNotIn('"args"', out)
        self.assertNotIn("web_search(query=", out)

    def test_colors_when_enabled(self):
        out = render(UI(color=True), results_data(n=1), tty=True)
        self.assertIn(MAGENTA + "  ⚙ web search · " + RESET, out)
        self.assertIn(BOLD + QUERY + RESET, out)
        url_line = next(l for l in out.splitlines() if "https://" in l)
        self.assertTrue(url_line.startswith(GRAY + "       "))  # URL dimmed
        self.assertTrue(url_line.endswith(RESET))

    def test_long_snippet_collapses_to_one_line(self):
        data = results_data(n=1)
        data["results"][0]["snippet"] = ("word " * 100).strip()
        out = render(UI(color=False), data)
        snip_lines = [l for l in out.splitlines() if l.startswith("       word")]
        self.assertEqual(len(snip_lines), 1)
        self.assertTrue(snip_lines[0].endswith("…"))
        self.assertLessEqual(len(snip_lines[0]), 7 + UI.SEARCH_SNIPPET_CHARS + 1)

    def test_inline_progress_line_erased_not_left_behind(self):
        ui = UI(color=True)
        buf = TtyIO()
        with contextlib.redirect_stdout(buf):
            ui.search_begin(QUERY)
        partial = buf.getvalue()
        self.assertNotIn("\n", partial)          # progress line still open
        self.assertIn("searching…", partial)
        with contextlib.redirect_stdout(buf):
            ui.search_end(results_data(), 0.5)
        rest = buf.getvalue()[len(partial):]
        self.assertTrue(rest.startswith("\r" + ESC + "2K"))  # wiped in place
        self.assertEqual(rest.count("searching…"), 0)        # no leftover

    def test_failure_statuses_render_honestly(self):
        ui = UI(color=False)
        limited = render(ui, {"query": QUERY, "status": "limited",
                              "provider": None, "results": None})
        self.assertIn("unavailable: every provider failed", limited)
        capped = render(ui, {"query": QUERY, "status": "capped",
                             "provider": None, "results": None})
        self.assertIn("per-turn search cap reached", capped)
        none = render(ui, {"query": QUERY, "status": "results",
                           "provider": "bing", "results": []})
        self.assertIn("no results (via bing)", none)
        bad = render(ui, {"query": "", "status": "invalid",
                          "provider": None, "results": None})
        self.assertIn("did not run", bad)
        # and without color there is never an escape byte on screen
        for out in (limited, capped, none, bad):
            self.assertNotIn("\x1b", out)

    def test_search_abort_closes_the_line(self):
        ui = UI(color=True)
        buf = TtyIO()
        with contextlib.redirect_stdout(buf):
            ui.search_begin(QUERY)
            ui.search_abort(QUERY)
        out = buf.getvalue()
        self.assertIn("\r" + ESC + "2K", out)
        self.assertIn("interrupted", out)
        self.assertTrue(out.endswith("\n"))


class TestAgentSearchFlow(unittest.TestCase):
    def make_agent(self, srv, tmpdir, color=False):
        store = SessionStore(Path(tmpdir) / "sessions")
        session = store.create(cwd=tmpdir, model="mock-heretic-27b")
        client = SparkClient(base_url=srv.base_url, model="mock-heretic-27b")
        executor = ToolExecutor(cwd=tmpdir, approve=lambda a, s, d: True)
        ui = UI(yolo=True, color=color)
        return Agent(client, session, executor, ui), session, executor

    def scripts(self, srv):
        srv.scripts.append({  # the model searches...
            "reasoning": ["I should look this up."],
            "deltas": ["Let me search.\n```tool\n",
                       '{"tool": "web_search", "args": {"query": "' + QUERY + '"}}',
                       "\n```"],
            "usage": {"prompt_tokens": 60, "completion_tokens": 30},
        })
        srv.scripts.append({  # ...then answers with the results
            "deltas": ["According to the docs, asyncio is Python's async library."],
            "usage": {"prompt_tokens": 120, "completion_tokens": 15},
        })

    def test_full_search_turn_renders_one_clean_block(self):
        with tempfile.TemporaryDirectory() as tmp, \
                MockSparkServer() as srv, MockSearchServer() as search:
            search.httpd.pages = {"/lite/": ddg_lite_page(GOOD_RESULTS)}
            self.scripts(srv)
            agent, session, _ = self.make_agent(srv, tmp)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                stats = agent.run_turn("what is asyncio?")
            out = buf.getvalue()
            self.assertEqual(stats.tool_steps, 1)
            # the block: header + summary + numbered results
            self.assertIn("⚙ web search · python asyncio docs", out)
            self.assertIn("5 result(s) via ddg-lite", out)
            self.assertIn("1. asyncio - Asynchronous I/O - Python 3 docs", out)
            # thinking collapsed to its status line, block separated from text
            self.assertNotIn("I should look this up.", out)
            self.assertIn("thought for", out)
            # no generic args preview, no duplicate result-preview line
            self.assertNotIn("web_search(query=", out)
            self.assertNotIn("→ 5 result(s)", out)
            # the model still received the full formatted results
            tool_msg = next(m for m in session.messages
                            if m["role"] == "user" and "<tool_results>" in m["content"])
            self.assertIn("asyncio - Asynchronous I/O", tool_msg["content"])
            # block appears between the two spark replies
            self.assertLess(out.index("⚙ web search"),
                            out.index("According to the docs"))

    def test_ctrl_c_during_search_aborts_turn_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp, \
                MockSparkServer() as srv, MockSearchServer():
            srv.scripts.append({
                "deltas": ['```tool\n{"tool": "web_search", "args": {"query": "'
                           + QUERY + '"}}\n```'],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            })
            agent, session, executor = self.make_agent(srv, tmp)
            buf = io.StringIO()
            with mock.patch.object(executor.websearch, "search",
                                   side_effect=KeyboardInterrupt):
                with contextlib.redirect_stdout(buf):
                    stats = agent.run_turn("search something")
            out = buf.getvalue()
            self.assertTrue(stats.interrupted)
            self.assertIn("interrupted", out)
            self.assertTrue(out.endswith("\n"))  # progress line was closed
            # the aborted turn recorded no tool results for the model
            self.assertFalse(any("<tool_results>" in m["content"]
                                 for m in session.messages
                                 if m["role"] == "user"))
            # and the REPL-level turn handler survives (run_turn returned)
            self.assertEqual(stats.tool_steps, 1)


if __name__ == "__main__":
    unittest.main()
