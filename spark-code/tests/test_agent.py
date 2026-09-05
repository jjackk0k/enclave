"""Agent-loop integration tests against the mock server: tool execution
loop, one retry-with-correction on a malformed block, and the step cap."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from spark_code.agent import Agent
from spark_code.client import SparkClient
from spark_code.session import SessionStore
from spark_code.tools import ToolExecutor
from spark_code.ui import UI

from tests.mock_server import MockSparkServer


def make_agent(srv, tmpdir, max_steps=25):
    store = SessionStore(Path(tmpdir) / "sessions")
    session = store.create(cwd=tmpdir, model="mock-heretic-27b")
    client = SparkClient(base_url=srv.base_url, model="mock-heretic-27b")
    executor = ToolExecutor(cwd=tmpdir, approve=lambda a, s, d: True)
    ui = UI(yolo=True, color=False)
    return Agent(client, session, executor, ui, max_steps=max_steps), session


class TestAgentLoop(unittest.TestCase):
    def test_tool_call_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            (Path(tmp) / "note.txt").write_text("the answer is 42", encoding="utf-8")
            srv.scripts.append({
                "deltas": ["Let me check.\n```tool\n",
                           '{"tool": "read_file", "args": {"path": "note.txt"}}',
                           "\n```"],
                "usage": {"prompt_tokens": 50, "completion_tokens": 20},
            })
            srv.scripts.append({
                "deltas": ["The file says: the answer is 42."],
                "usage": {"prompt_tokens": 90, "completion_tokens": 12},
            })
            agent, session = make_agent(srv, tmp)
            with contextlib.redirect_stdout(io.StringIO()):
                stats = agent.run_turn("what is in note.txt?")
            self.assertEqual(stats.tool_steps, 1)
            self.assertEqual(stats.parse_failures, 0)
            roles = [m["role"] for m in session.messages]
            self.assertEqual(roles, ["user", "assistant", "user", "assistant"])
            self.assertIn("<tool_results>", session.messages[2]["content"])
            self.assertIn("the answer is 42", session.messages[2]["content"])
            self.assertEqual(session.total_prompt_tokens, 140)

    def test_malformed_block_triggers_one_correction(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            srv.scripts.append({
                "deltas": ['```tool\n{"tool": "list_dir", args: broken}\n```'],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            })
            srv.scripts.append({  # after correction: proper call
                "deltas": ['```tool\n{"tool": "list_dir", "args": {"path": "."}}\n```'],
                "usage": {"prompt_tokens": 30, "completion_tokens": 8},
            })
            srv.scripts.append({
                "deltas": ["Done."],
                "usage": {"prompt_tokens": 60, "completion_tokens": 3},
            })
            agent, session = make_agent(srv, tmp)
            with contextlib.redirect_stdout(io.StringIO()):
                stats = agent.run_turn("list files")
            self.assertEqual(stats.parse_failures, 1)
            self.assertEqual(stats.corrections_sent, 1)
            self.assertEqual(stats.tool_steps, 1)
            correction_msgs = [m for m in session.messages
                               if m["role"] == "user" and "PROTOCOL ERROR" in m["content"]]
            self.assertEqual(len(correction_msgs), 1)

    def test_step_cap_stops_and_asks(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            for _ in range(5):
                srv.scripts.append({
                    "deltas": ['```tool\n{"tool": "list_dir", "args": {}}\n```'],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5},
                })
            agent, session = make_agent(srv, tmp, max_steps=5)
            with contextlib.redirect_stdout(io.StringIO()):
                stats = agent.run_turn("loop forever")
            self.assertTrue(stats.hit_step_cap)
            self.assertEqual(stats.tool_steps, 5)


class TestInterrupt(unittest.TestCase):
    """Ctrl-C mid-stream: the turn must abort - no salvaged tool execution,
    no stale usage double-count from the previous turn's last_result."""

    def test_interrupt_aborts_turn_cleanly(self):
        class InterruptingClient(SparkClient):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                self.streams = 0

            def chat_stream(self, *a, **k):
                self.streams += 1
                gen = super().chat_stream(*a, **k)
                if self.streams == 2:
                    yield next(gen)  # one delta, then the user hits Ctrl-C
                    raise KeyboardInterrupt
                yield from gen

        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            store = SessionStore(Path(tmp) / "sessions")
            session = store.create(cwd=tmp, model="mock-heretic-27b")
            client = InterruptingClient(base_url=srv.base_url, model="mock-heretic-27b")
            executor = ToolExecutor(cwd=tmp, approve=lambda a, s, d: True)
            ui = UI(yolo=True, color=False)
            agent = Agent(client, session, executor, ui)

            # turn 1 completes normally: real usage 50 + 20
            srv.scripts.append({
                "deltas": ["plain answer."],  # terminator: keeps auto-continue silent
                "usage": {"prompt_tokens": 50, "completion_tokens": 20},
            })
            # turn 2: a COMPLETE tool block arrives before the interrupt -
            # it must NOT execute
            srv.scripts.append({
                "deltas": ['```tool\n{"tool": "list_dir", "args": {}}\n```'],
                "usage": {"prompt_tokens": 90, "completion_tokens": 10},
            })
            with contextlib.redirect_stdout(io.StringIO()):
                stats1 = agent.run_turn("hi")
                self.assertFalse(stats1.interrupted)
                stats2 = agent.run_turn("do something")
            self.assertTrue(stats2.interrupted)
            self.assertEqual(stats2.tool_steps, 0)
            # no tool results were produced for the interrupted turn
            self.assertFalse(any("<tool_results>" in m["content"]
                                 and m["role"] == "user"
                                 for m in session.messages[2:]))
            # usage was NOT double-counted from stale last_result:
            # only turn 1's real 50 + 20 are recorded
            self.assertEqual(session.total_prompt_tokens, 50)
            self.assertEqual(session.total_completion_tokens, 20)


class TestUnterminatedWriteRoundtrip(unittest.TestCase):
    """Full agent loop: mock server streams a write_file whose content string
    never closes (the 2026-09-04 live repro). The file must land on disk with
    exactly the streamed content, flagged truncated, no correction round-trip,
    and the model must be told to verify/append via the result text."""

    def test_unterminated_write_file_executes_and_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            srv.scripts.append({
                # fence closes, the JSON string never does (session-log shape)
                "deltas": ["Writing the page.\n```tool\n",
                           '{"tool": "write_file", "args": {"path": "page.html", '
                           '"content": "<!DOCTYPE html>\\n<html>\\n<body>partial',
                           "\n```"],
                "usage": {"prompt_tokens": 60, "completion_tokens": 30},
            })
            srv.scripts.append({
                "deltas": ["Written, verifying the tail now."],
                "usage": {"prompt_tokens": 90, "completion_tokens": 10},
            })
            agent, session = make_agent(srv, tmp)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                stats = agent.run_turn("build page.html")
            out = buf.getvalue()
            # the file actually landed, content verbatim from the stream
            written = (Path(tmp) / "page.html").read_text(encoding="utf-8")
            self.assertEqual(written, "<!DOCTYPE html>\n<html>\n<body>partial")
            # recovered as a salvage: no correction was sent
            self.assertEqual(stats.salvages, 1)
            self.assertEqual(stats.parse_failures, 0)
            self.assertEqual(stats.corrections_sent, 0)
            self.assertEqual(stats.tool_steps, 1)
            # the user saw the truncation warning
            self.assertIn("salvaged from an unterminated", out)
            # and the model was told honestly to verify/append
            tool_msg = next(m for m in session.messages
                            if m["role"] == "user" and "<tool_results>" in m["content"])
            self.assertIn('ok="true"', tool_msg["content"])
            self.assertIn("may be TRUNCATED", tool_msg["content"])
            self.assertIn("edit_file", tool_msg["content"])

    def test_unterminated_dangling_block_no_fence_also_recovers(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            srv.scripts.append({
                "deltas": ['```tool\n{"tool": "write_file", "args": {"path": "b.txt", '
                           '"content": "chunk one\\nchunk two'],  # stream just ends
                "usage": {"prompt_tokens": 10, "completion_tokens": 8},
            })
            srv.scripts.append({
                "deltas": ["Done."],  # terminator: keeps auto-continue silent
                "usage": {"prompt_tokens": 20, "completion_tokens": 2},
            })
            agent, session = make_agent(srv, tmp)
            with contextlib.redirect_stdout(io.StringIO()):
                stats = agent.run_turn("write b.txt")
            self.assertEqual((Path(tmp) / "b.txt").read_text(encoding="utf-8"),
                             "chunk one\nchunk two")
            self.assertEqual(stats.salvages, 1)
            self.assertEqual(stats.corrections_sent, 0)

    def test_still_broken_write_gets_one_correction_then_honest_stop(self):
        # cut inside `path`: nothing recoverable - correction fires as before
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            srv.scripts.append({
                "deltas": ['```tool\n{"tool": "write_file", "args": {"path": "WORK'],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            })
            srv.scripts.append({  # correction reply: proper call
                "deltas": ['```tool\n{"tool": "write_file", "args": {"path": "c.txt", '
                           '"content": "ok"}}\n```'],
                "usage": {"prompt_tokens": 30, "completion_tokens": 8},
            })
            srv.scripts.append({
                "deltas": ["Recovered."],
                "usage": {"prompt_tokens": 40, "completion_tokens": 3},
            })
            agent, session = make_agent(srv, tmp)
            with contextlib.redirect_stdout(io.StringIO()):
                stats = agent.run_turn("write something")
            self.assertEqual(stats.parse_failures, 1)
            self.assertEqual(stats.corrections_sent, 1)
            self.assertEqual((Path(tmp) / "c.txt").read_text(encoding="utf-8"), "ok")
            correction = next(m["content"] for m in session.messages
                              if m["role"] == "user" and "PROTOCOL ERROR" in m["content"])
            self.assertIn("write it in parts", correction)  # chunked-write guidance


class TestChunkedWriteGuidance(unittest.TestCase):
    def test_tool_spec_documents_parted_writes(self):
        from spark_code.tools import TOOL_SPEC_FOR_PROMPT
        self.assertIn("~100 lines", TOOL_SPEC_FOR_PROMPT)
        self.assertIn("edit_file", TOOL_SPEC_FOR_PROMPT)
        self.assertIn("old", TOOL_SPEC_FOR_PROMPT)  # the real anchor-append pattern

    def test_correction_template_teaches_parted_writes(self):
        from spark_code.agent import CORRECTION_TEMPLATE
        text = CORRECTION_TEMPLATE.format(error="x")
        self.assertIn("parts", text)
        self.assertIn("~100 lines", text)
        self.assertIn("edit_file", text)


class TestTodosTool(unittest.TestCase):
    def test_update_todos_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            srv.scripts.append({
                "deltas": ['```tool\n{"tool": "update_todos", "args": {"todos": ['
                           '{"content": "map the code", "status": "done"}, '
                           '{"content": "port the updater", "status": "in_progress"}'
                           ']}}\n```'],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            })
            srv.scripts.append({
                "deltas": ["On it."],
                "usage": {"prompt_tokens": 30, "completion_tokens": 3},
            })
            agent, session = make_agent(srv, tmp)
            with contextlib.redirect_stdout(io.StringIO()):
                stats = agent.run_turn("track this work")
            self.assertEqual(stats.tool_steps, 1)
            self.assertEqual(session.todos, [
                {"content": "map the code", "status": "done"},
                {"content": "port the updater", "status": "in_progress"},
            ])
            # persisted as an event: a fresh load replays the list
            loaded = session.store.load(session.id)
            self.assertEqual(loaded.todos, session.todos)
            # and the next request's system prompt carries the list
            self.assertIn("port the updater", agent.system_prompt())

    def test_update_todos_rejected_keeps_old_list(self):
        with tempfile.TemporaryDirectory() as tmp, MockSparkServer() as srv:
            agent, session = make_agent(srv, tmp)
            session.set_todos([{"content": "old", "status": "pending"}])
            result = agent._update_todos({"todos": [{"status": "nope"}]})
            self.assertFalse(result.ok)
            self.assertEqual(session.todos, [{"content": "old", "status": "pending"}])


if __name__ == "__main__":
    unittest.main()
