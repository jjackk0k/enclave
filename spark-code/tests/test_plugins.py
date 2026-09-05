"""Extension system (plugins/): load, /ext reload rescan, strict refusals
(missing fields, bad types, import errors), name collisions with built-ins
and between plugins, approval classes, and host isolation - a broken or
crashing plugin never takes the agent down."""

import tempfile
import unittest
from pathlib import Path

from spark_code.plugins import PluginRegistry
from spark_code.tools import ToolExecutor

GOOD = '''
TOOL = {"name": "word_count",
        "description": "count words in a file",
        "args": {"path": {"type": "string", "description": "file to count"}},
        "approval": "read"}

import os

def run(args, approve, cwd):
    with open(os.path.join(cwd, args["path"]), encoding="utf-8") as fh:
        return f"{len(fh.read().split())} words"
'''

WRITER = '''
TOOL = {"name": "stamp_file",
        "description": "append a stamp line to a file",
        "args": {"path": {"type": "string"}},
        "approval": "write"}

def run(args, approve, cwd):
    import os
    with open(os.path.join(cwd, args["path"]), "a", encoding="utf-8") as fh:
        fh.write("stamped\\n")
    return "stamped"
'''

CRASHER = '''
TOOL = {"name": "boom", "description": "always raises", "args": {}}

def run(args, approve, cwd):
    raise RuntimeError("plugin exploded")
'''


def make_registry(tmp, files):
    root = Path(tmp) / "plugins"
    root.mkdir()
    for name, body in files.items():
        (root / name).write_text(body, encoding="utf-8")
    return PluginRegistry(root=root, reserved=ToolExecutor.TOOL_NAMES)


class TestPluginLoading(unittest.TestCase):
    def test_load_and_spec_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg = make_registry(tmp, {"word_count.py": GOOD})
            self.assertIn("word_count", reg.plugins)
            self.assertEqual(reg.errors, [])
            spec = reg.spec_text()
            self.assertIn("word_count(path: string)", spec)
            self.assertIn("extension, approval: read", spec)

    def test_reload_picks_up_new_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg = make_registry(tmp, {"word_count.py": GOOD})
            self.assertEqual(len(reg.plugins), 1)
            (Path(tmp) / "plugins" / "stamp.py").write_text(WRITER, encoding="utf-8")
            reg.load()
            self.assertIn("stamp_file", reg.plugins)

    def test_refusals_are_reported_not_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg = make_registry(tmp, {
                "no_tool.py": "def run(args, approve):\n    return 'x'\n",
                "bad_name.py": GOOD.replace('"word_count"', '"Word Count!"'),
                "no_run.py": GOOD.replace("def run", "def not_run"),
                "bad_approval.py": GOOD.replace('"read"', '"yolo-forever"'),
                "bad_argtype.py": GOOD.replace('"string"', '"filehandle"'),
                "syntax_error.py": "TOOL = {\n",  # import-time failure
                "word_count.py": GOOD,
            })
            self.assertEqual(list(reg.plugins), ["word_count"])  # the good one loads
            self.assertEqual(len(reg.errors), 6)
            joined = " ".join(e for _, e in reg.errors)
            self.assertIn("missing TOOL", joined)
            self.assertIn("snake_case", joined)
            self.assertIn("callable run", joined)
            self.assertIn("approval", joined)
            self.assertIn("import failed", joined)

    def test_builtin_name_collision_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg = make_registry(tmp, {"evil.py": GOOD.replace('"word_count"', '"write_file"')})
            self.assertEqual(reg.plugins, {})
            self.assertIn("collides with a built-in", reg.errors[0][1])

    def test_plugin_name_collision_second_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg = make_registry(tmp, {"a.py": GOOD, "b.py": GOOD})
            self.assertEqual(len(reg.plugins), 1)
            self.assertIn("already provided", reg.errors[0][1])

    def test_underscore_prefixed_file_is_parked(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg = make_registry(tmp, {"_draft.py": GOOD, "word_count.py": GOOD})
            self.assertEqual(list(reg.plugins), ["word_count"])


class TestPluginExecution(unittest.TestCase):
    def make_executor(self, tmp, approve):
        ex = ToolExecutor(cwd=tmp, approve=approve)
        ex.plugins = PluginRegistry(root=Path(tmp) / "plugins",
                                    reserved=ex.TOOL_NAMES)
        return ex

    def test_execute_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "plugins").mkdir()
            (Path(tmp) / "plugins" / "word_count.py").write_text(GOOD, encoding="utf-8")
            (Path(tmp) / "note.txt").write_text("one two three", encoding="utf-8")
            ex = self.make_executor(tmp, lambda a, s, d: True)
            r = ex.execute("word_count", {"path": "note.txt"})
            self.assertTrue(r.ok, r.text)
            self.assertEqual(r.text, "3 words")

    def test_unknown_tool_lists_plugins(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "plugins").mkdir()
            (Path(tmp) / "plugins" / "word_count.py").write_text(GOOD, encoding="utf-8")
            ex = self.make_executor(tmp, lambda a, s, d: True)
            r = ex.execute("nope", {})
            self.assertFalse(r.ok)
            self.assertIn("word_count", r.text)

    def test_undeclared_args_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "plugins").mkdir()
            (Path(tmp) / "plugins" / "word_count.py").write_text(GOOD, encoding="utf-8")
            ex = self.make_executor(tmp, lambda a, s, d: True)
            r = ex.execute("word_count", {"path": "x", "evil": "rm -rf"})
            self.assertFalse(r.ok)
            self.assertIn("unknown argument", r.text)

    def test_write_class_prompts_and_denial_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "plugins").mkdir()
            (Path(tmp) / "plugins" / "stamp.py").write_text(WRITER, encoding="utf-8")
            target = Path(tmp) / "f.txt"
            target.write_text("orig\n", encoding="utf-8")
            calls = []
            ex = self.make_executor(tmp, lambda a, s, d: calls.append(a) or True)
            r = ex.execute("stamp_file", {"path": "f.txt"})
            self.assertTrue(r.ok)
            self.assertEqual(calls, ["write"])  # same approval class as built-ins
            self.assertIn("stamped", target.read_text(encoding="utf-8"))
            # denied: does not run
            ex2 = self.make_executor(tmp, lambda a, s, d: False)
            r = ex2.execute("stamp_file", {"path": "f.txt"})
            self.assertFalse(r.ok)
            self.assertIn("Denied", r.text)

    def test_read_class_never_prompts(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "plugins").mkdir()
            (Path(tmp) / "plugins" / "word_count.py").write_text(GOOD, encoding="utf-8")
            (Path(tmp) / "n.txt").write_text("x", encoding="utf-8")
            calls = []
            ex = self.make_executor(tmp, lambda a, s, d: calls.append(a) or True)
            ex.execute("word_count", {"path": "n.txt"})
            self.assertEqual(calls, [])

    def test_crashing_plugin_is_honest_failure_not_host_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "plugins").mkdir()
            (Path(tmp) / "plugins" / "boom.py").write_text(CRASHER, encoding="utf-8")
            ex = self.make_executor(tmp, lambda a, s, d: True)
            r = ex.execute("boom", {})
            self.assertFalse(r.ok)
            self.assertIn("plugin exploded", r.text)
            # host still fine afterwards
            self.assertTrue(ex.execute("list_dir", {}).ok)


class TestExtCommand(unittest.TestCase):
    def test_ext_lists_and_reload_rescans(self):
        import contextlib
        import io
        import types
        from spark_code.agent import Agent
        from spark_code.client import SparkClient
        from spark_code.repl import Repl
        from spark_code.session import SessionStore
        from spark_code.ui import UI
        with tempfile.TemporaryDirectory() as tmp:
            store = SessionStore(Path(tmp) / "sessions")
            session = store.create(cwd=tmp, model="m")
            client = SparkClient(base_url="http://127.0.0.1:9", model="m")
            executor = ToolExecutor(cwd=tmp, approve=lambda a, s, d: True)
            plugins_dir = Path(tmp) / "plugins"
            plugins_dir.mkdir()
            executor.plugins = PluginRegistry(root=plugins_dir,
                                              reserved=executor.TOOL_NAMES)
            agent = Agent(client, session, executor, UI(yolo=True, color=False))
            repl = Repl(client, store, session, agent, agent.ui,
                        types.SimpleNamespace(started_by_us=False), 262144, 524288)
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                repl.handle_command("/ext")
            self.assertIn("no extensions loaded", buf.getvalue())
            # the model writes itself a tool mid-session; /ext reload picks it up
            (plugins_dir / "word_count.py").write_text(GOOD, encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                repl.handle_command("/ext reload")
            self.assertIn("1 loaded", buf.getvalue())
            self.assertIn("word_count", agent.system_prompt())  # next turn knows it


if __name__ == "__main__":
    unittest.main()
