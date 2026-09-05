"""Auto-continue (Jack's 'stops randomly mid-turn' bug): the heuristic, the
chained nudges with cap, the off switch, and the hard rule that an interrupt
or an error path never triggers it."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spark_code import config
from spark_code.agent import Agent, needs_continuation
from spark_code.client import SparkClient
from spark_code.session import SessionStore
from spark_code.tools import ToolExecutor
from spark_code.ui import UI

from tests.mock_server import MockSparkServer


class TestNeedsContinuation(unittest.TestCase):
    def test_clean_finishes_stay_silent(self):
        for text in ("All done.", "Fixed it!", "Ready?", "here you go)",
                     'said "yes"', "it's done'", "value = 3}", "```\ncode\n```"):
            needed, _ = needs_continuation(text, "stop")
            self.assertFalse(needed, text)

    def test_weird_finish_reason_triggers(self):
        needed, reason = needs_continuation("Looks complete.", "length")
        self.assertTrue(needed)
        self.assertIn("length", reason)

    def test_empty_reply_triggers(self):
        self.assertTrue(needs_continuation("", "stop")[0])
        self.assertTrue(needs_continuation("   \n", "stop")[0])

    def test_open_fence_triggers(self):
        self.assertTrue(needs_continuation("Now the file:\n```python\nx = 1", "stop")[0])

    def test_mid_thought_endings_trigger(self):
        for text in ("Now part 2:", "first I will check the file,",
                     "let me think —", "opening (", "the result is"):
            self.assertTrue(needs_continuation(text, "stop")[0], text)


def make_agent(srv, tmpdir):
    store = SessionStore(Path(tmpdir) / "sessions")
    session = store.create(cwd=tmpdir, model="mock-heretic-27b")
    client = SparkClient(base_url=srv.base_url, model="mock-heretic-27b")
    executor = ToolExecutor(cwd=tmpdir, approve=lambda a, s, d: True)
    ui = UI(yolo=True, color=False)
    return Agent(client, session, executor, ui), session


class TestAutoContinueLoop(unittest.TestCase):
    def run_turn(self, srv, tmp, text="go"):
        agent, session = make_agent(srv, tmp)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            stats = agent.run_turn(text)
        return stats, session, buf.getvalue()

    def test_mid_thought_reply_gets_nudged_then_finishes(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            srv.scripts.append({"deltas": ["Let me start with part one:"],
                                "usage": {"prompt_tokens": 10, "completion_tokens": 5}})
            srv.scripts.append({"deltas": ["...and part two is done."],
                                "usage": {"prompt_tokens": 20, "completion_tokens": 6}})
            stats, session, out = self.run_turn(srv, tmp)
            self.assertEqual(stats.autocontinues, 1)
            self.assertIn("↻ auto-continue 1/3", out)
            self.assertIn("(ends mid-thought)", out)
            # the nudge is a real session message, and the answer completed
            kinds = [m["content"] for m in session.messages if m["role"] == "user"]
            self.assertTrue(any("Continue from exactly where you stopped" in c
                                for c in kinds))
            self.assertEqual(session.messages[-1]["content"], "...and part two is done.")
            self.assertEqual(session.total_prompt_tokens, 30)  # both streams counted

    def test_clean_finish_stays_silent(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            srv.scripts.append({"deltas": ["Everything is complete."],
                                "usage": {"prompt_tokens": 10, "completion_tokens": 5}})
            stats, session, out = self.run_turn(srv, tmp)
            self.assertEqual(stats.autocontinues, 0)
            self.assertNotIn("auto-continue", out)
            self.assertEqual(len(srv.requests), 1)

    def test_cap_is_loud_and_respected(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            for i in range(6):
                srv.scripts.append({"deltas": [f"part {i}:"],  # always cut off
                                    "usage": {"prompt_tokens": 10, "completion_tokens": 2}})
            stats, session, out = self.run_turn(srv, tmp)
            self.assertEqual(stats.autocontinues, config.AUTOCONTINUE_MAX)
            self.assertIn(f"auto-continue {config.AUTOCONTINUE_MAX}/{config.AUTOCONTINUE_MAX}", out)
            self.assertIn("say 'continue' to keep going", out)  # the loud cap
            # initial stream + 3 nudges, no more
            self.assertEqual(len(srv.requests), 1 + config.AUTOCONTINUE_MAX)

    def test_finish_length_triggers(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            srv.scripts.append({"deltas": ["This answer is complete looking."],
                                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
                                "finish": "length"})
            srv.scripts.append({"deltas": ["Rest of it."],
                                "usage": {"prompt_tokens": 20, "completion_tokens": 3}})
            stats, session, out = self.run_turn(srv, tmp)
            self.assertEqual(stats.autocontinues, 1)
            self.assertIn("finish: length", out)

    def test_off_switch(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            srv.scripts.append({"deltas": ["cut off:"],
                                "usage": {"prompt_tokens": 10, "completion_tokens": 2}})
            agent, session = make_agent(srv, tmp)
            agent.autocontinue = False
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                stats = agent.run_turn("go")
            self.assertEqual(stats.autocontinues, 0)
            self.assertEqual(len(srv.requests), 1)

    def test_never_after_interrupt(self):
        class InterruptingClient(SparkClient):
            def chat_stream(self, *a, **k):
                yield "partial reply:"
                raise KeyboardInterrupt

        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            store = SessionStore(Path(tmp) / "sessions")
            session = store.create(cwd=tmp, model="mock-heretic-27b")
            client = InterruptingClient(base_url=srv.base_url, model="m")
            executor = ToolExecutor(cwd=tmp, approve=lambda a, s, d: True)
            agent = Agent(client, session, executor, UI(yolo=True, color=False))
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                stats = agent.run_turn("go")
            self.assertTrue(stats.interrupted)
            self.assertEqual(stats.autocontinues, 0)  # the interrupt wins
            self.assertNotIn("auto-continue", buf.getvalue())

    def test_error_path_never_continues(self):
        # unparseable tool block + failed correction = honest error break,
        # and even a cut-off-looking error reply gets no nudge
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            srv.scripts.append({"deltas": ['```tool\n{broken'],
                                "usage": {"prompt_tokens": 10, "completion_tokens": 5}})
            srv.scripts.append({"deltas": ['```tool\n{still broken'],
                                "usage": {"prompt_tokens": 20, "completion_tokens": 5}})
            stats, session, out = self.run_turn(srv, tmp)
            self.assertEqual(stats.corrections_sent, 1)
            self.assertEqual(stats.autocontinues, 0)


class TestAutoContinueCommand(unittest.TestCase):
    def test_command_toggles_and_validates(self):
        import types
        from spark_code.repl import Repl
        with tempfile.TemporaryDirectory() as tmp:
            store = SessionStore(Path(tmp) / "sessions")
            session = store.create(cwd=tmp, model="m")
            client = SparkClient(base_url="http://127.0.0.1:9", model="m")
            executor = ToolExecutor(cwd=tmp, approve=lambda a, s, d: True)
            ui = UI(yolo=True, color=False)
            agent = Agent(client, session, executor, ui)
            repl = Repl(client, store, session, agent, ui,
                        types.SimpleNamespace(started_by_us=False), 262144, 524288)
            self.assertTrue(agent.autocontinue)  # default on
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                repl.handle_command("/autocontinue")
            self.assertFalse(agent.autocontinue)
            self.assertIn("OFF", buf.getvalue())
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                repl.handle_command("/autocontinue on")
            self.assertTrue(agent.autocontinue)
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                repl.handle_command("/autocontinue banana")
            self.assertIn("usage: /autocontinue", buf.getvalue())
            self.assertTrue(agent.autocontinue)  # unchanged by the bad arg


if __name__ == "__main__":
    unittest.main()
