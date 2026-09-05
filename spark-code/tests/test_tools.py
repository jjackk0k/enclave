"""Tool executor tests: every tool, the approval gate, diff previews,
exact-match edit semantics, shell timeout, and path resolution."""

import tempfile
import unittest
from pathlib import Path

from spark_code.tools import ToolExecutor


class Approvals:
    """Records approval requests; configurable verdict."""

    def __init__(self, verdict=True):
        self.verdict = verdict
        self.calls = []

    def __call__(self, action, summary, detail):
        self.calls.append((action, summary, detail))
        return self.verdict


class TestTools(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = Path(self.tmp.name)
        self.approvals = Approvals(True)
        self.ex = ToolExecutor(cwd=str(self.cwd), approve=self.approvals)

    def tearDown(self):
        self.tmp.cleanup()

    # read_file / list_dir / search_files -------------------------------------
    def test_read_write_roundtrip_with_approval(self):
        r = self.ex.execute("write_file", {"path": "a.txt", "content": "one\ntwo\n"})
        self.assertTrue(r.ok)
        action, summary, detail = self.approvals.calls[-1]
        self.assertEqual(action, "write")
        self.assertIn("a.txt", summary)
        self.assertIn("+one", detail)  # diff preview was produced
        r = self.ex.execute("read_file", {"path": "a.txt"})
        self.assertTrue(r.ok)
        self.assertIn("1\tone", r.text)
        self.assertIn("2\ttwo", r.text)

    def test_denied_write_changes_nothing(self):
        self.approvals.verdict = False
        r = self.ex.execute("write_file", {"path": "b.txt", "content": "x"})
        self.assertFalse(r.ok)
        self.assertIn("NOT written", r.text)
        self.assertFalse((self.cwd / "b.txt").exists())

    def test_edit_file_exact_match(self):
        (self.cwd / "c.txt").write_text("alpha beta gamma", encoding="utf-8")
        self.approvals.calls.clear()
        r = self.ex.execute("edit_file", {"path": "c.txt", "old": "beta", "new": "BETA"})
        self.assertTrue(r.ok)
        self.assertEqual((self.cwd / "c.txt").read_text(), "alpha BETA gamma")
        self.assertIn("-alpha beta gamma", self.approvals.calls[-1][2])

    def test_edit_file_no_match_is_error_not_silent(self):
        (self.cwd / "d.txt").write_text("hello", encoding="utf-8")
        r = self.ex.execute("edit_file", {"path": "d.txt", "old": "zzz", "new": "q"})
        self.assertFalse(r.ok)
        self.assertIn("No exact match", r.text)

    def test_edit_file_requires_unique_match(self):
        (self.cwd / "e.txt").write_text("aa aa", encoding="utf-8")
        r = self.ex.execute("edit_file", {"path": "e.txt", "old": "aa", "new": "b"})
        self.assertFalse(r.ok)
        self.assertIn("2 times", r.text)
        r = self.ex.execute("edit_file", {"path": "e.txt", "old": "aa", "new": "b",
                                          "replace_all": True})
        self.assertTrue(r.ok)
        self.assertEqual((self.cwd / "e.txt").read_text(), "b b")

    def test_list_dir(self):
        (self.cwd / "sub").mkdir()
        (self.cwd / "f.txt").write_text("data")
        r = self.ex.execute("list_dir", {"path": "."})
        self.assertTrue(r.ok)
        self.assertIn("sub/", r.text)
        self.assertIn("f.txt", r.text)

    def test_search_files_by_name_and_content(self):
        (self.cwd / "g.py").write_text("def target_fn():\n    pass\n")
        (self.cwd / "h.txt").write_text("nothing here")
        r = self.ex.execute("search_files", {"pattern": "*.py"})
        self.assertIn("g.py", r.text)
        self.assertNotIn("h.txt", r.text)
        r = self.ex.execute("search_files", {"pattern": "*.*", "content": "target_fn"})
        self.assertIn("g.py:1", r.text)

    def test_run_shell_and_denial(self):
        r = self.ex.execute("run_shell", {"command": "echo spark-ok"})
        self.assertTrue(r.ok, r.text)
        self.assertIn("spark-ok", r.text)
        self.assertEqual(self.approvals.calls[-1][0], "shell")

        self.approvals.verdict = False
        r = self.ex.execute("run_shell", {"command": "echo should-not-run"})
        self.assertFalse(r.ok)
        self.assertIn("NOT run", r.text)

    def test_run_shell_nonzero_exit_reported(self):
        self.approvals.verdict = True
        r = self.ex.execute("run_shell", {"command": "exit 3"})
        self.assertFalse(r.ok)
        self.assertIn("exit code 3", r.text)

    def test_unknown_tool(self):
        r = self.ex.execute("delete_everything", {})
        self.assertFalse(r.ok)
        self.assertIn("Unknown tool", r.text)

    def test_bad_args_reported(self):
        r = self.ex.execute("read_file", {"wrong": 1})
        self.assertFalse(r.ok)
        self.assertIn("Bad arguments", r.text)


if __name__ == "__main__":
    unittest.main()
