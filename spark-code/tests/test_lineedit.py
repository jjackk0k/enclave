"""Bottom-bar editor state-transition tests (stale-highlight regression).

The ANSI drawing only runs on a real console, so these tests drive the real
read_line() loop with a fake msvcrt key source and a captured output stream,
then assert on the editor's menu-row bookkeeping and the emitted erase
sequences. Terminal is fixed at 80x24: status row 23, input row 24, a full
8-row menu occupies rows 15-22.
"""

import unittest
from unittest import mock

from spark_code import lineedit
from spark_code.lineedit import MENU_MAX, BottomBarEditor

ESC = "\x1b["


class FakeKeys:
    def __init__(self, seq):
        self.seq = list(seq)

    def getwch(self):
        if not self.seq:
            raise EOFError("script exhausted")
        return self.seq.pop(0)


def clear_seq(row):
    """What _clear_line(row) emits."""
    return f"{ESC}{row};1H{ESC}2K"


def drive(keys):
    """Run read_line() over a scripted key sequence; return (result, editor, output)."""
    out = []
    ed = BottomBarEditor(status_fn=lambda: "STATUS", color=False)
    ed._w = out.append
    with mock.patch.object(lineedit, "msvcrt", FakeKeys(keys)), \
         mock.patch.object(BottomBarEditor, "_size", lambda self: (80, 24)):
        result = ed.read_line()
    return result, ed, "".join(out)


class TestMenuStateTransitions(unittest.TestCase):
    def test_menu_opens_on_slash_then_backspace_closes_and_erases(self):
        # type "/", menu opens (8 rows); backspace to empty -> menu must close
        # AND its rows must be erased, leaving just status + input.
        result, ed, out = drive("/" + "\x08" + "\r")
        self.assertEqual(result, "")
        self.assertEqual(ed._drawn_menu_rows, 0)
        # every previously-drawn menu row (15..22) got an explicit erase
        for row in range(15, 23):
            self.assertIn(clear_seq(row), out, f"row {row} not erased")

    def test_menu_open_state_visible_after_slash(self):
        # "/" then Enter: Enter fills the highlighted no-arg command (/help)
        # and submits it; the 8 drawn menu rows must be erased on submit.
        result, ed, out = drive("/" + "\r")
        self.assertEqual(result, "/help")
        self.assertEqual(ed._drawn_menu_rows, 0)
        for row in range(15, 23):
            self.assertIn(clear_seq(row), out)

    def test_esc_close_erases_menu_rows(self):
        # First Esc closes the menu (buffer keeps "/"); backspace then empties
        # it. The erase must happen at Esc time, not at submit.
        result, ed, out = drive("/" + "\x1b" + "\x08" + "\r")
        self.assertEqual(result, "")
        self.assertEqual(ed._drawn_menu_rows, 0)
        for row in range(15, 23):
            self.assertIn(clear_seq(row), out)

    def test_submit_while_menu_open_erases_rows(self):
        # "/help" has exactly one match and typed == chosen, so Enter submits
        # with the menu row still on screen - _submit must erase it.
        result, ed, out = drive("/help" + "\r")
        self.assertEqual(result, "/help")
        self.assertEqual(ed._drawn_menu_rows, 0)
        self.assertIn(clear_seq(22), out)  # the single menu row

    def test_shrinking_menu_erases_only_stale_rows(self):
        # "/s" -> 2 matches (rows 21-22); "t" -> "/st" -> 1 match (row 22);
        # row 21 is stale and must be erased.
        result, ed, out = drive("/st" + "\r")
        self.assertIn(clear_seq(21), out)
        self.assertEqual(ed._drawn_menu_rows, 0)  # after submit

    def test_non_slash_text_never_opens_menu(self):
        result, ed, out = drive("hello" + "\r")
        self.assertEqual(result, "hello")
        # no menu rows were ever drawn, so no band erases needed
        self.assertNotIn(clear_seq(15), out)

    def test_tab_completion_fills_command(self):
        result, ed, _ = drive("/hel" + "\t" + "\r")
        self.assertEqual(result, "/help")

    def test_ctrl_t_calls_hook_and_leaves_buffer_untouched(self):
        fired = []
        out = []
        ed = BottomBarEditor(status_fn=lambda: "STATUS", color=False,
                             on_ctrl_t=lambda: fired.append(True))
        ed._w = out.append
        with mock.patch.object(lineedit, "msvcrt", FakeKeys(["\x14", "\r"])), \
                mock.patch.object(BottomBarEditor, "_size", lambda self: (80, 24)):
            result = ed.read_line()
        self.assertEqual(result, "")      # the toggle never enters the input
        self.assertEqual(len(fired), 1)


if __name__ == "__main__":
    unittest.main()
