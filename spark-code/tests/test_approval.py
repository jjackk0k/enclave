"""Approval prompt input path (Jack's live repros 2026-09-04):

1. A stray Ctrl-T echoed as literal "^T" and a partial redraw printed over
   the prompt - the raw reader now consumes non-answer keys silently and
   repaints only via full-line erase + redraw.
2. Pressing 'a' replayed the user's message - the reader consumes exactly
   one key; a follow-up Enter stays buffered and submits an empty line,
   which the REPL drops.

Also covers the input() fallback (piped stdin) and the yolo/always paths.
"""

import builtins
import contextlib
import io
import unittest
from unittest import mock

from spark_code import lineedit
from spark_code.lineedit import BottomBarEditor
from spark_code.ui import ESC, UI

from tests.test_lineedit import FakeKeys as EditorKeys


class FakeKeys:
    def __init__(self, seq):
        self.seq = list(seq)
        self.consumed = 0

    def __call__(self):
        self.consumed += 1
        if not self.seq:
            raise EOFError("script exhausted")
        return self.seq.pop(0)


def run_approve(ui, category="shell", summary="Run shell command", detail=None):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = ui.approve(category, summary, detail)
    return result, buf.getvalue()


def raw_ui(keys, color=True):
    ui = UI(color=color)
    ui.key_source = FakeKeys(keys)
    return ui


class TestRawApprovalReader(unittest.TestCase):
    def test_stray_ctrl_t_swallowed_no_echo_clean_repaint(self):
        # Jack's repro: Ctrl-T leaked as "^T" and the redraw overprinted.
        ui = raw_ui(["\x14", "a"])
        ok, out = run_approve(ui)
        self.assertTrue(ok)
        self.assertIn("shell", ui.always)
        self.assertNotIn("\x14", out)          # never echoed
        self.assertNotIn("^T", out)
        # prompt drawn once, then erased whole and redrawn with the answer
        self.assertEqual(out.count(UI.APPROVAL_PROMPT), 2)
        self.assertIn("\r" + ESC + "2K", out)

    def test_exactly_one_key_consumed_no_replay(self):
        # Jack's repro: 'a' then the previous message re-submitted. The
        # reader must take ONLY the answer key; the trailing Enter stays
        # buffered and becomes an empty line, which the REPL drops.
        ui = raw_ui(["a", "\r"])
        ok, _ = run_approve(ui)
        self.assertTrue(ok)
        self.assertEqual(ui.key_source.consumed, 1)
        self.assertEqual(ui.key_source.seq, ["\r"])  # Enter left for next input

    def test_leftover_enter_submits_empty_line_that_repl_drops(self):
        # the buffered "\r" reaches the bottom-bar editor: empty submit
        out = []
        ed = BottomBarEditor(status_fn=lambda: "STATUS", color=False)
        ed._w = out.append
        with mock.patch.object(lineedit, "msvcrt", EditorKeys(["\r"])), \
                mock.patch.object(BottomBarEditor, "_size", lambda self: (80, 24)):
            result = ed.read_line()
        self.assertEqual(result, "")  # repl.run skips empty text - nothing re-sent

    def test_answer_keys(self):
        self.assertTrue(run_approve(raw_ui(["y"]))[0])
        self.assertTrue(run_approve(raw_ui(["Y"]))[0])
        self.assertFalse(run_approve(raw_ui(["n"]))[0])
        self.assertFalse(run_approve(raw_ui(["\r"]))[0])   # Enter = default no
        self.assertFalse(run_approve(raw_ui(["\x1b"]))[0])  # Esc = no
        self.assertFalse(run_approve(raw_ui(["\x03"]))[0])  # Ctrl-C key = no

    def test_arrow_keys_swallowed_with_tail(self):
        ui = raw_ui(["\xe0", "H", "y"])  # up-arrow (2 bytes), then y
        ok, out = run_approve(ui)
        self.assertTrue(ok)
        self.assertEqual(ui.key_source.consumed, 3)  # prefix + tail + answer
        self.assertNotIn("\xe0", out)

    def test_raised_keyboardinterrupt_means_no(self):
        ui = UI(color=True)
        def boom():
            raise KeyboardInterrupt
        ui.key_source = boom
        ok, out = run_approve(ui)
        self.assertFalse(ok)
        self.assertTrue(out.endswith("\n"))

    def test_no_color_falls_back_to_plain_echo(self):
        # --no-color consoles: no VT erase, just the echoed answer
        ui = raw_ui(["y"], color=False)
        ok, out = run_approve(ui)
        self.assertTrue(ok)
        self.assertNotIn(ESC + "2K", out)
        self.assertTrue(out.endswith("y\n"))


class TestInputFallback(unittest.TestCase):
    def fallback(self, typed):
        ui = UI(color=False)
        ui.key_source = None
        with mock.patch.object(builtins, "input", return_value=typed):
            with contextlib.redirect_stdout(io.StringIO()):
                return ui.approve("write", "Overwrite x", None)

    def test_word_answers(self):
        self.assertTrue(self.fallback("yes"))
        self.assertTrue(self.fallback("y"))
        self.assertTrue(self.fallback("always"))
        self.assertFalse(self.fallback("no"))
        self.assertFalse(self.fallback(""))      # empty = no
        self.assertFalse(self.fallback("junk"))  # unknown = no

    def test_always_registers_category(self):
        ui = UI(color=False)
        ui.key_source = None
        with mock.patch.object(builtins, "input", return_value="a"):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(ui.approve("shell", "Run x", None))
        self.assertIn("shell", ui.always)

    def test_interrupt_during_input_means_no(self):
        ui = UI(color=False)
        ui.key_source = None
        with mock.patch.object(builtins, "input", side_effect=KeyboardInterrupt):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(ui.approve("shell", "Run x", None))


class TestAutoApprovePaths(unittest.TestCase):
    def test_yolo_never_reads_a_key(self):
        ui = raw_ui([])  # empty source: any read would raise EOFError
        ui.yolo = True
        ok, out = run_approve(ui)
        self.assertTrue(ok)
        self.assertIn("auto-approved (yolo)", out)
        self.assertEqual(ui.key_source.consumed, 0)

    def test_always_category_never_reads_a_key(self):
        ui = raw_ui([])
        ui.always.add("write")
        ok, out = run_approve(ui, category="write", detail="+added\n-removed\n")
        self.assertTrue(ok)
        self.assertIn("auto-approved (always)", out)
        self.assertIn("+added", out)  # write diffs still shown
        self.assertEqual(ui.key_source.consumed, 0)


if __name__ == "__main__":
    unittest.main()
