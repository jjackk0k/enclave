"""Esc interrupts any in-flight generation (Jack's repro: pass-2's Esc did
nothing while the model was thinking/streaming).

Root cause of the pass-2 failure: EscMonitor polled per stream chunk, so
during prefill (127k ctx ~= minutes at ~480 t/s ingest) or any server-side
stall no chunk arrived, no poll ran, and the blocked resp.readline() was
never interrupted. The fix: a background EscWatcher thread polls the console
input buffer on a timer, and its callback aborts the HTTP read itself
(client.abort() closes the response socket), so Esc works mid-prefill,
mid-thinking, and mid-content alike.

Semantics are the Ctrl-C path: partial reply kept, no tools run, no
double-counted usage, and the session stays clean for the next turn.
"""

import contextlib
import io
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from spark_code import lineedit
from spark_code.agent import Agent
from spark_code.client import SparkClient, StreamAborted
from spark_code.lineedit import BottomBarEditor, EscWatcher
from spark_code.session import SessionStore
from spark_code.tools import ToolExecutor
from spark_code.ui import UI

from tests.mock_server import MockSparkServer
from tests.test_lineedit import FakeKeys


class FakeConsole:
    """Scriptable kbhit/getwch pair for the watcher thread."""

    def __init__(self, keys):
        self.keys = list(keys)

    def kbhit(self):
        return bool(self.keys)

    def getwch(self):
        return self.keys.pop(0)


def wait_for(cond, timeout=3.0):
    t0 = time.time()
    while not cond() and time.time() - t0 < timeout:
        time.sleep(0.005)
    return cond()


class TestEscWatcher(unittest.TestCase):
    def test_disabled_without_console_is_noop(self):
        w = EscWatcher(on_esc=lambda: None)
        self.assertFalse(w.enabled)
        w.start()
        self.assertIsNone(w._thread)
        w.stop()  # must not raise

    def test_for_console_disabled_headless(self):
        # no console (piped stdin) -> disabled; force the assumption so this
        # holds whether unittest runs from an interactive terminal or not
        with mock.patch.object(sys.stdin, "isatty", return_value=False):
            self.assertFalse(EscWatcher.for_console(lambda: None).enabled)

    def test_posix_path_still_disabled(self):
        # no msvcrt at all -> the watcher never starts (Ctrl-C remains)
        with mock.patch.object(lineedit, "msvcrt", None):
            self.assertFalse(EscWatcher.for_console(lambda: None).enabled)

    def test_fires_once_on_esc_swallows_others_ignores_double_esc(self):
        fired = []
        con = FakeConsole(["h", "\x1b", "\x1b"])  # typeahead, Esc, double-Esc
        w = EscWatcher(lambda: fired.append(True), kbhit=con.kbhit,
                       getkey=con.getwch, interval=0.005)
        w.start()
        try:
            self.assertTrue(wait_for(lambda: fired), "watcher never fired")
            wait_for(lambda: not con.keys)  # all keys drained
        finally:
            w.stop()
        self.assertEqual(len(fired), 1)        # double-Esc ignored
        self.assertEqual(w.swallowed, ["h"])   # typeahead preserved
        self.assertIsNone(w._thread)           # joined, not lingering

    def test_watcher_fault_never_kills_the_agent(self):
        def boom():
            raise RuntimeError("console vanished")
        con = FakeConsole(["\x1b"])
        w = EscWatcher(boom, kbhit=con.kbhit, getkey=con.getwch, interval=0.005)
        w.start()
        time.sleep(0.05)
        w.stop()  # clean shutdown despite the exploding callback
        self.assertTrue(w.fired)

    def test_ctrl_t_toggles_and_is_never_replayed(self):
        toggles = []
        con = FakeConsole(["\x14", "\x14", "x", "\x1b"])  # toggle x2, typeahead, Esc
        w = EscWatcher(lambda: None, on_toggle=lambda: toggles.append(True),
                       kbhit=con.kbhit, getkey=con.getwch, interval=0.005)
        w.start()
        try:
            self.assertTrue(wait_for(lambda: not con.keys), "keys never drained")
        finally:
            w.stop()
        self.assertEqual(len(toggles), 2)       # repeatable, not one-shot
        self.assertEqual(w.swallowed, ["x"])    # ctrl+t never lands in typeahead
        self.assertTrue(w.fired)                # Esc still worked

    def test_swallowed_keys_replay_in_editor(self):
        shared = ["h", "i"]
        ed = BottomBarEditor(status_fn=lambda: "STATUS", color=False,
                             pending=shared)
        ed._w = lambda s: None  # capture; don't leak ANSI into test output
        with mock.patch.object(lineedit, "msvcrt", FakeKeys(["\r"])), \
                mock.patch.object(BottomBarEditor, "_size", lambda self: (80, 24)):
            result = ed.read_line()
        self.assertEqual(result, "hi")  # typeahead preserved across the turn
        self.assertEqual(shared, [])    # drained once, not replayed twice


class GatedWatcher(EscWatcher):
    """Releases its scripted keys only after the client saw the first delta,
    so the Esc lands deterministically mid-stream in tests."""

    def __init__(self, gate, keys, on_esc):
        con = FakeConsole(keys)
        super().__init__(on_esc, kbhit=con.kbhit, getkey=con.getwch, interval=0.01)
        self._gate = gate

    def _run(self):
        if self._gate.wait(5):
            super()._run()


def make_agent(srv, tmpdir, client=None):
    store = SessionStore(Path(tmpdir) / "sessions")
    session = store.create(cwd=tmpdir, model="mock-heretic-27b")
    if client is None:
        client = SparkClient(base_url=srv.base_url, model="mock-heretic-27b")
    executor = ToolExecutor(cwd=tmpdir, approve=lambda a, s, d: True)
    ui = UI(yolo=True, color=False)
    return Agent(client, session, executor, ui), session, ui


class TestEscAbortsStream(unittest.TestCase):
    def test_esc_mid_stream_aborts_and_next_turn_is_clean(self):
        class WatchedClient(SparkClient):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                self.first_delta = threading.Event()

            def chat_stream(self, *a, **k):
                for i, d in enumerate(super().chat_stream(*a, **k)):
                    if i == 0:
                        self.first_delta.set()
                    yield d

        with tempfile.TemporaryDirectory() as tmp, \
                MockSparkServer(chunk_delay=0.25) as srv:
            srv.scripts.append({
                "deltas": ["Hello", " world", " again"],
                "usage": {"prompt_tokens": 50, "completion_tokens": 20},
            })
            client = WatchedClient(base_url=srv.base_url, model="mock-heretic-27b")
            agent, session, ui = make_agent(srv, tmp, client=client)
            gated = GatedWatcher(client.first_delta, ["h", "\x1b"], client.abort)
            watchers = [gated]
            patch = mock.patch.object(
                EscWatcher, "for_console",
                lambda on_esc, on_toggle=None: watchers.pop(0) if watchers else EscWatcher(on_esc))
            buf = io.StringIO()
            with patch, contextlib.redirect_stdout(buf):
                stats = agent.run_turn("hi")
                self.assertTrue(stats.interrupted)
                out = buf.getvalue()
                self.assertIn("⌀ interrupted", out)
                self.assertNotIn("Traceback", out)
                # partial reply kept - a prefix of what was scripted,
                # displayed before the abort (a socket close may drain the
                # local receive buffer, so the exact cut point varies)
                partial = session.messages[-1]["content"]
                self.assertTrue(partial)
                self.assertTrue("Hello world again".startswith(partial))
                # no usage recorded from a cancelled stream
                self.assertEqual(session.total_prompt_tokens, 0)
                # the key pressed before Esc replays into the next input
                self.assertEqual(ui.key_buffer, ["h"])
                # turn 2: state is clean, the turn completes normally
                stats2 = agent.run_turn("again")
            self.assertFalse(stats2.interrupted)
            self.assertEqual(session.messages[-1]["content"], "Hello from mock!")
            self.assertEqual(session.total_prompt_tokens, 123)

    def test_esc_during_thinking_aborts_before_any_content(self):
        with tempfile.TemporaryDirectory() as tmp, \
                MockSparkServer(chunk_delay=0.25) as srv:
            srv.scripts.append({
                "reasoning": ["deep thought one", "deep thought two"],
                "deltas": ["never reached"],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            })

            class ReasonWatchedClient(SparkClient):
                def __init__(self, *a, **k):
                    super().__init__(*a, **k)
                    self.first_reasoning = threading.Event()

                def chat_stream(self, *a, **k):
                    cb = k.get("on_reasoning")
                    def wrapped(text):
                        self.first_reasoning.set()
                        if cb:
                            cb(text)
                    return super().chat_stream(*a, **dict(k, on_reasoning=wrapped))

            client = ReasonWatchedClient(base_url=srv.base_url, model="mock-heretic-27b")
            agent, session, ui = make_agent(srv, tmp, client=client)
            gated = GatedWatcher(client.first_reasoning, ["\x1b"], client.abort)
            buf = io.StringIO()
            with mock.patch.object(EscWatcher, "for_console",
                                   lambda on_esc, on_toggle=None: gated), \
                    contextlib.redirect_stdout(buf):
                stats = agent.run_turn("think")
            out = buf.getvalue()
            self.assertTrue(stats.interrupted)
            self.assertIn("⌀ interrupted", out)
            self.assertTrue(out.endswith("\n"))  # no dangling thinking line
            self.assertEqual(session.total_prompt_tokens, 0)
            # at most the deltas scripted before the cut could have been kept
            if len(session.messages) > 1:
                self.assertTrue("never reached".startswith(
                    session.messages[-1]["content"]))

    def test_watcher_stopped_before_tools_run(self):
        # Esc during tool execution is NOT watched (the stream is over); a
        # pressed Esc sits in the console buffer and can only deny the next
        # approval or abort the next stream - a tool never half-writes.
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            srv.scripts.append({
                "deltas": ['```tool\n{"tool": "write_file", "args": {"path": "f.txt", '
                           '"content": "complete"}}\n```'],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            })
            srv.scripts.append({
                "deltas": ["Done."],  # terminator: keeps auto-continue silent
                "usage": {"prompt_tokens": 20, "completion_tokens": 3},
            })
            agent, session, ui = make_agent(srv, tmp)
            started = []

            def spy_for_console(on_esc, on_toggle=None):
                w = EscWatcher(on_esc)  # disabled (headless)
                started.append(w)
                return w

            with mock.patch.object(EscWatcher, "for_console", spy_for_console), \
                    contextlib.redirect_stdout(io.StringIO()):
                stats = agent.run_turn("write f.txt")
            self.assertFalse(stats.interrupted)
            # the file was written whole - the tool ran to completion
            self.assertEqual((Path(tmp) / "f.txt").read_text(encoding="utf-8"),
                             "complete")
            # every watcher that started was also stopped (no lingering reader)
            self.assertTrue(all(w._thread is None for w in started))


if __name__ == "__main__":
    unittest.main()
