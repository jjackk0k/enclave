"""Collapsible thinking pane: default-collapsed live status line, expanded
dimmed streaming, the /think toggle (persisted per session), clean re-render
of the last thinking, and no dangling lines on interrupt or mid-stream
errors. Rendering tests drive UI/ThinkingDisplay directly; integration tests
run the agent loop against the mock server with reasoning_content deltas."""

import contextlib
import io
import re
import tempfile
import types
import unittest
from pathlib import Path

from spark_code.agent import Agent
from spark_code.client import SparkClient
from spark_code.repl import Repl
from spark_code.session import SessionStore
from spark_code.tools import ToolExecutor
from spark_code.ui import ESC, GRAY, RESET, UI

from tests.mock_server import MockSparkServer


class TtyIO(io.StringIO):
    """Captured stdout that claims to be a console (exercises the inline
    rewrite path: \\r + erase-line instead of print-and-keep)."""

    def isatty(self):
        return True


def capture(ui_method, *args, tty=False, **kwargs):
    buf = TtyIO() if tty else io.StringIO()
    with contextlib.redirect_stdout(buf):
        ui_method(*args, **kwargs)
    return buf.getvalue()


def make_agent(srv, tmpdir, color=False):
    store = SessionStore(Path(tmpdir) / "sessions")
    session = store.create(cwd=tmpdir, model="mock-heretic-27b")
    client = SparkClient(base_url=srv.base_url, model="mock-heretic-27b")
    executor = ToolExecutor(cwd=tmpdir, approve=lambda a, s, d: True)
    ui = UI(yolo=True, color=color)
    return Agent(client, session, executor, ui), session


class TestCollapsedDefault(unittest.TestCase):
    def test_default_is_collapsed_and_persists_across_streams(self):
        ui = UI(color=False)
        self.assertFalse(ui.think.expanded)
        ui.think.expanded = True
        ui.think.begin()  # a new stream must not reset the user's toggle
        self.assertTrue(ui.think.expanded)

    def test_collapsed_piped_prints_nothing_until_finish(self):
        ui = UI(color=False)
        ui.think.begin()
        out = capture(ui.think.feed, "the model reasons quietly ")
        self.assertEqual(out, "")  # no live line while piped
        ui.think.feed("more reasoning")
        out = capture(ui.think.finish)
        self.assertEqual(out.count("\n"), 1)  # exactly one final line
        self.assertRegex(out, r"thought for \d+s · ~\d+ tokens — ctrl\+t to expand")
        self.assertNotIn("the model reasons", out)  # thinking text stays hidden

    def test_token_estimate_formats(self):
        ui = UI(color=False)
        ui.think.begin()
        ui.think.feed("x" * 40)  # 40 chars -> ~10 tokens
        out = capture(ui.think.finish)
        self.assertIn("~10 tokens", out)
        ui.think.begin()
        ui.think.feed("x" * 12400)  # -> ~3.1k tokens
        out = capture(ui.think.finish)
        self.assertIn("~3.1k tokens", out)

    def test_finish_without_any_thinking_is_a_noop(self):
        ui = UI(color=False)
        ui.think.begin()
        self.assertEqual(capture(ui.think.finish), "")

    def test_reasoning_after_content_started_is_buffered_silently(self):
        # a late reasoning delta must never rewrite over the streamed answer
        ui = UI(color=False)
        ui.think.begin()
        ui.think.feed("early reasoning")
        capture(ui.think.finish)  # content start closes the pane
        out = capture(ui.think.feed, "LATE reasoning delta")
        self.assertEqual(out, "")
        self.assertIn("LATE reasoning delta", ui.think.last_text)  # still recorded

    def test_inline_live_line_is_rewritten_not_stacked(self):
        ui = UI(color=True)
        ui.think.REDRAW_INTERVAL = 0  # no throttle for the test
        ui.think.begin()
        out = capture(ui.think.feed, "chunk one", tty=True)
        self.assertIn("· thinking…", out)
        self.assertNotIn("\n", out)  # live line stays open
        out2 = capture(ui.think.feed, "chunk two", tty=True)
        self.assertIn("\r" + ESC + "2K", out2)  # second draw erases the first
        out3 = capture(ui.think.finish, tty=True)
        self.assertTrue(out3.startswith("\r" + ESC + "2K"))  # live line wiped
        self.assertIn("spark> ", out3)  # prefix redrawn after the full-line erase
        self.assertIn("· thought for", out3)
        self.assertTrue(out3.endswith("\n"))  # cursor on a fresh line

    def test_no_ansi_when_color_off(self):
        ui = UI(color=False)
        ui.think.begin()
        capture(ui.think.feed, "plain")
        out = capture(ui.think.finish)
        self.assertNotIn("\x1b", out)

    def test_reasoning_text_is_sanitized(self):
        # a stray ESC in model output must never reach the terminal raw
        ui = UI(color=False)
        ui.think.expanded = True
        ui.think.begin()
        out = capture(ui.think.feed, "evil \x1b[31m red \rstuff")
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\r", out)
        self.assertIn("evil [31m red stuff", out)

    def test_narrow_pipe_encoding_never_crashes_print(self):
        # redirected stdout can be cp1252: ⚙/✓ must degrade, not raise
        import io as _io
        from spark_code.ui import _soften
        raw = _io.TextIOWrapper(_io.BytesIO(), encoding="cp1252")
        _soften(raw)
        raw.write("  ⚙ web search · ✓ — …\n")  # would raise without _soften
        raw.flush()
        self.assertIn(b"?", raw.buffer.getvalue())


class TestExpanded(unittest.TestCase):
    def test_expanded_streams_dimmed_live_then_summary(self):
        ui = UI(color=True)
        ui.think.expanded = True
        ui.think.begin()
        out = capture(ui.think.feed, "deep thought")
        self.assertIn(GRAY + "· thinking (ctrl+t to collapse):" + RESET, out)
        self.assertIn(GRAY + "deep thought" + RESET, out)
        out2 = capture(ui.think.finish)
        self.assertRegex(out2, r"thought for \d+s · ~\d+ tokens — ctrl\+t to collapse")
        self.assertIn(GRAY, out2)  # summary dimmed too

    def test_render_last_renders_wrapped_and_dimmed(self):
        ui = UI(color=True)
        ui.think.begin()
        ui.think.feed(("word " * 60).strip())  # 299 chars, must wrap
        capture(ui.think.finish)
        out = capture(ui.think.render_last)
        self.assertIn("· last thinking (", out)
        body = [l for l in out.splitlines() if "word" in l]
        self.assertGreater(len(body), 1)  # actually wrapped
        for line in body:
            self.assertTrue(line.startswith(GRAY + "    "))
            self.assertLessEqual(len(line.replace(GRAY, "").replace(RESET, "")), 80)
        self.assertTrue(out.endswith("\n\n"))  # separated from what follows

    def test_render_last_with_nothing_recorded(self):
        ui = UI(color=False)
        out = capture(ui.think.render_last)
        self.assertIn("no thinking recorded yet", out)


class TestAgentIntegration(unittest.TestCase):
    def test_collapsed_hides_reasoning_shows_status_line(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            srv.scripts.append({
                "reasoning": ["secret chain ", "of thought"],
                "deltas": ["The answer."],
                "usage": {"prompt_tokens": 50, "completion_tokens": 20},
            })
            agent, session = make_agent(srv, tmp)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                agent.run_turn("think about it")
            out = buf.getvalue()
            self.assertNotIn("secret chain", out)  # reasoning not on screen
            m = re.search(r"spark> +· thought for \d+s · ~\d+ tokens — ctrl\+t to expand\n", out)
            self.assertIsNotNone(m, out)
            # order: status line, then the answer on the next line
            self.assertLessEqual(m.end(), out.index("The answer."))
            # reasoning never enters history either
            self.assertNotIn("secret chain",
                             session.messages[1]["content"])

    def test_expanded_shows_reasoning_dimmed_before_answer(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            srv.scripts.append({
                "reasoning": ["visible reasoning"],
                "deltas": ["Answer here."],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            })
            agent, _ = make_agent(srv, tmp, color=True)
            agent.ui.think.expanded = True
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                agent.run_turn("hi")
            out = buf.getvalue()
            self.assertIn(GRAY + "visible reasoning" + RESET, out)
            self.assertLess(out.index("visible reasoning"), out.index("Answer here."))

    def test_interrupt_mid_thinking_leaves_no_dangling_line(self):
        class ThinkInterruptClient(SparkClient):
            def chat_stream(self, *a, **k):
                cb = k.get("on_reasoning")
                if cb:
                    cb("thinking hard")
                raise KeyboardInterrupt
                yield  # pragma: no cover - keeps this a generator

        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            store = SessionStore(Path(tmp) / "sessions")
            session = store.create(cwd=tmp, model="mock-heretic-27b")
            client = ThinkInterruptClient(base_url=srv.base_url, model="m")
            executor = ToolExecutor(cwd=tmp, approve=lambda a, s, d: True)
            ui = UI(yolo=True, color=True)  # inline path: the risky one
            agent = Agent(client, session, executor, ui)
            buf = TtyIO()
            with contextlib.redirect_stdout(buf):
                stats = agent.run_turn("hi")
            out = buf.getvalue()
            self.assertTrue(stats.interrupted)
            self.assertIn("· thinking…", out)          # live line was drawn
            self.assertIn("\r" + ESC + "2K", out)      # ...and wiped
            self.assertIn("⌀ interrupted", out)
            self.assertTrue(out.endswith("\n"))        # nothing left half-drawn


class TestCtrlTToggle(unittest.TestCase):
    """ctrl+t flips the thinking pane live: mid-stream it hides/resumes the
    dimmed echo; at the prompt it just flips the flag for the next stream."""

    def test_toggle_idle_flips_flag_silently(self):
        ui = UI(color=False)
        out = capture(ui.think.toggle_live)
        self.assertEqual(out, "")
        self.assertTrue(ui.think.expanded)

    def test_collapse_mid_stream_hides_echo_with_marker(self):
        ui = UI(color=False)
        ui.think.expanded = True
        ui.think.begin()
        out = capture(ui.think.feed, "visible part ")
        self.assertIn("visible part", out)
        out2 = capture(ui.think.toggle_live)  # collapse mid-stream
        self.assertIn("thinking hidden - ctrl+t to show", out2)
        out3 = capture(ui.think.feed, "now hidden")
        self.assertNotIn("now hidden", out3)
        out4 = capture(ui.think.finish)
        self.assertRegex(out4, r"thought for \d+s · ~\d+ tokens — ctrl\+t to expand")
        # and re-pressing expands again for the NEXT stream (state persists)
        ui.think.begin()
        self.assertFalse(ui.think.expanded)  # collapsed until re-pressed

    def test_expand_mid_stream_resumes_echo(self):
        ui = UI(color=False)
        ui.think.begin()  # collapsed + piped: nothing printed yet
        capture(ui.think.feed, "early")
        capture(ui.think.toggle_live)  # expand mid-stream
        out = capture(ui.think.feed, "later thought")
        self.assertIn("· thinking (ctrl+t to collapse):", out)
        self.assertIn("later thought", out)
        out2 = capture(ui.think.finish)
        self.assertRegex(out2, r"thought for \d+s · ~\d+ tokens — ctrl\+t to collapse")

    def test_status_bar_shows_pane_state(self):
        ui = UI(color=False)
        base = dict(model="m", ctx_used=0, ctx_limit=262144, ctx_total=524288,
                    tok_s=1.0, mode="Reasoning", cwd=r"C:\p", yolo=False,
                    thinking=True)
        self.assertIn("thinking:on·expanded", ui.status_text(think_expanded=True, **base))
        self.assertNotIn("expanded", ui.status_text(think_expanded=False, **base))
        self.assertIn("thinking:off", ui.status_text(thinking=False,
                                                     **{k: v for k, v in base.items()
                                                        if k != "thinking"}))


class TestThinkCommand(unittest.TestCase):
    def make_repl(self, tmp):
        store = SessionStore(Path(tmp) / "sessions")
        session = store.create(cwd=tmp, model="m")
        client = SparkClient(base_url="http://127.0.0.1:9", model="m")
        executor = ToolExecutor(cwd=tmp, approve=lambda a, s, d: True)
        ui = UI(yolo=True, color=False)
        agent = Agent(client, session, executor, ui)
        tunnel = types.SimpleNamespace(started_by_us=False)
        return Repl(client, store, session, agent, ui, tunnel, 262144, 524288)

    def test_toggle_roundtrip_and_explicit_args(self):
        with tempfile.TemporaryDirectory() as tmp:
            repl = self.make_repl(tmp)
            self.assertFalse(repl.ui.think.expanded)
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                repl.handle_command("/think")
            self.assertTrue(repl.ui.think.expanded)
            self.assertIn("EXPANDED", buf.getvalue())
            self.assertIn("no thinking recorded yet", buf.getvalue())
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                repl.handle_command("/think off")
            self.assertFalse(repl.ui.think.expanded)
            self.assertIn("COLLAPSED", buf.getvalue())
            with contextlib.redirect_stdout(io.StringIO()):
                repl.handle_command("/think on")  # explicit, idempotent
            self.assertTrue(repl.ui.think.expanded)

    def test_expand_renders_last_thinking(self):
        with tempfile.TemporaryDirectory() as tmp:
            repl = self.make_repl(tmp)
            repl.ui.think.last_text = "the model weighed the options"
            repl.ui.think.last_tokens = 7
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                repl.handle_command("/think")
            self.assertIn("the model weighed the options", buf.getvalue())

    def test_bad_arg_warns_without_toggling(self):
        with tempfile.TemporaryDirectory() as tmp:
            repl = self.make_repl(tmp)
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                repl.handle_command("/think banana")
            self.assertIn("usage: /think", buf.getvalue())
            self.assertFalse(repl.ui.think.expanded)

    def test_think_in_command_registry_and_help(self):
        from spark_code.commands import COMMANDS, filter_commands, help_text
        names = {c.name for c in COMMANDS}
        self.assertIn("/think", names)
        self.assertIn("/thinking", names)
        self.assertEqual([c.name for c in filter_commands("/thi")],
                         ["/thinking", "/think"])
        self.assertIn("/think", help_text())


if __name__ == "__main__":
    unittest.main()
