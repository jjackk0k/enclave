"""Fast | Reasoning mode tests: sampling wiring, thinking flags, request body."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from spark_code import config
from spark_code.agent import Agent
from spark_code.client import SparkClient
from spark_code.session import SessionStore
from spark_code.tools import ToolExecutor
from spark_code.ui import UI

from tests.mock_server import MockSparkServer


def make_agent(srv, tmpdir):
    store = SessionStore(Path(tmpdir) / "sessions")
    session = store.create(cwd=tmpdir, model="mock-heretic-27b")
    client = SparkClient(base_url=srv.base_url, model="mock-heretic-27b")
    executor = ToolExecutor(cwd=tmpdir, approve=lambda a, s, d: True)
    ui = UI(yolo=True, color=False)
    return Agent(client, session, executor, ui)


class TestModes(unittest.TestCase):
    def test_three_tiers(self):
        self.assertEqual(set(config.EFFORT_MODES), {"fast", "standard", "reasoning"})
        self.assertEqual(config.DEFAULT_EFFORT, "standard")  # balanced: thinks, but capped
        budgets = [config.EFFORT_MODES[m]["max_tokens"] for m in ("fast", "standard", "reasoning")]
        self.assertLess(budgets[0], budgets[1])
        self.assertLess(budgets[1], budgets[2])  # fast < standard < reasoning

    def test_standard_is_default_with_thinking_on(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            agent = make_agent(srv, tmp)
            self.assertEqual(agent.mode, "standard")
            self.assertEqual(agent.mode_label, "Standard")
            self.assertTrue(agent.thinking)  # still reasons, just on a smaller budget
            with contextlib.redirect_stdout(io.StringIO()):
                agent.run_turn("hi")
            body = srv.requests[-1]
            self.assertEqual(body["max_tokens"], 8192)
            self.assertEqual(body["temperature"], 0.2)
            self.assertEqual(body["repeat_penalty"], 1.15)  # cockpit-aligned
            self.assertNotIn("chat_template_kwargs", body)

    def test_reasoning_tier_is_deep(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            agent = make_agent(srv, tmp)
            agent.set_mode("reasoning")
            self.assertTrue(agent.thinking)
            with contextlib.redirect_stdout(io.StringIO()):
                agent.run_turn("hi")
            body = srv.requests[-1]
            self.assertEqual(body["max_tokens"], 32768)

    def test_fast_mode_turns_thinking_off(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            agent = make_agent(srv, tmp)
            agent.set_mode("fast")
            self.assertEqual(agent.mode_label, "Fast")
            self.assertFalse(agent.thinking)
            with contextlib.redirect_stdout(io.StringIO()):
                agent.run_turn("hi")
            body = srv.requests[-1]
            self.assertEqual(body["max_tokens"], 4096)
            self.assertEqual(body["temperature"], 0.2)
            self.assertEqual(body["repeat_penalty"], 1.15)
            self.assertEqual(body["chat_template_kwargs"], {"enable_thinking": False})

    def test_switching_back_restores_thinking(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            agent = make_agent(srv, tmp)
            agent.thinking = False  # manual override while in reasoning
            agent.set_mode("fast")
            agent.set_mode("reasoning")
            self.assertTrue(agent.thinking)

    def test_unknown_mode_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            agent = make_agent(srv, tmp)
            with self.assertRaises(ValueError):
                agent.set_mode("medium")  # old levels are gone

    def test_sampling_defaults_match_cockpit(self):
        # verified live against ~/chatui/proxy.py DEFAULT_SAMPLING
        self.assertEqual(config.DEFAULT_TEMPERATURE, 0.2)
        self.assertEqual(config.DEFAULT_REPEAT_PENALTY, 1.15)


if __name__ == "__main__":
    unittest.main()
