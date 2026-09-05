"""Hand-rolled bottom input bar with a live slash-command menu.

prompt_toolkit is NOT available in the managed runtime (verified), so this
is stdlib-only: msvcrt key reading + ANSI/VT cursor control (Windows 10+
consoles, enabled via os.system("") / SetConsoleMode upstream).

Layout, Claude Code / Kimi Code style:
    rows 1..R      chat output scrolls here (DECSTBM scroll region)
    menu rows      live /command matches, filtered as you type (when open)
    status row     cwd · model · ctx · tok/s · effort · thinking · $0.00
    last row       "you> " input line

Active only on a real console (isatty); piped stdin/stdout uses the plain
input() path in the REPL, which is also what the tests exercise.
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
from typing import Callable, List, Optional, Tuple

from .commands import COMMANDS, CommandSpec, filter_commands, tab_complete

if os.name == "nt":
    import msvcrt
else:  # pragma: no cover - this build targets Windows
    msvcrt = None

ESC = "\x1b["
MENU_MAX = 8
PROMPT = "you> "


def supports_fancy() -> bool:
    return (msvcrt is not None and sys.stdin.isatty() and sys.stdout.isatty())


class EscWatcher:
    """Background thread watching for Esc during an in-flight stream.

    Pass-2's EscMonitor polled per stream chunk, which meant Esc was dead
    whenever no chunk was arriving (prefill at large context, server-side
    stalls) - the blocked readline was never interrupted. This watcher is
    time-driven instead: it polls the console input buffer every ~40 ms and
    its on_esc callback aborts the HTTP read itself (client.abort() closes
    the response socket), so Esc works during prefill, thinking, and
    content streaming alike.

    Other keys pressed mid-stream land in `swallowed` and are replayed into
    the next input line (typeahead survives). A second Esc is ignored.
    Without a real console (piped stdin, POSIX) the watcher is disabled and
    start()/stop() are no-ops - Ctrl-C remains the interrupt there.
    """

    def __init__(self, on_esc, on_toggle=None, kbhit=None, getkey=None,
                 interval: float = 0.04) -> None:
        self._on_esc = on_esc
        self._on_toggle = on_toggle
        self._kbhit = kbhit
        self._getkey = getkey
        self._interval = interval
        self.swallowed: List[str] = []
        self.fired = False
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def enabled(self) -> bool:
        return self._kbhit is not None and self._getkey is not None

    @classmethod
    def for_console(cls, on_esc, on_toggle=None) -> "EscWatcher":
        if msvcrt is not None and sys.stdin.isatty():
            return cls(on_esc, on_toggle, msvcrt.kbhit, msvcrt.getwch)
        return cls(on_esc, on_toggle)

    def start(self) -> None:
        if not self.enabled or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="spark-esc-watcher")
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                while self._kbhit():
                    ch = self._getkey()
                    if ch == "\x1b":
                        if not self.fired:
                            self.fired = True
                            self._on_esc()
                        # double-Esc: consumed, never replayed to the prompt
                    elif ch == "\x14" and self._on_toggle is not None:
                        # ctrl+t: thinking pane toggle - repeatable, and never
                        # replayed as typeahead (that would toggle it twice)
                        self._on_toggle()
                    else:
                        self.swallowed.append(ch)
            except Exception:
                return  # a watcher fault must never take the agent down

    def stop(self) -> None:
        """Stop and join the thread, so it never lingers to eat keys at the
        next prompt."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
            self._thread = None


class BottomBarEditor:
    def __init__(self, status_fn: Callable[[], str], color: bool = True,
                 pending: Optional[List[str]] = None,
                 on_ctrl_t: Optional[Callable[[], None]] = None) -> None:
        self.status_fn = status_fn
        self.color = color
        self.history: List[str] = []
        self._hist_idx: Optional[int] = None
        self._draft = ""
        # ctrl+t toggles the thinking pane live; the status row reflects it
        # on the redraw that follows the keypress
        self.on_ctrl_t = on_ctrl_t
        # shared with UI.key_buffer: keys swallowed by the EscWatcher during
        # streaming are replayed here, so typeahead survives the turn
        self.pending = pending if pending is not None else []
        # Rows currently occupied by the menu on screen. Every redraw clears
        # the band that WAS menu and no longer is, so a closed/shrunk menu
        # never leaves a stale highlight behind.
        self._drawn_menu_rows = 0

    # -- low-level VT ---------------------------------------------------------
    def _w(self, s: str) -> None:
        sys.stdout.write(s)
        sys.stdout.flush()

    def _size(self) -> Tuple[int, int]:
        s = shutil.get_terminal_size()
        return max(40, s.columns), max(10, s.lines)

    def _move(self, row: int, col: int = 1) -> None:
        self._w(f"{ESC}{row};{col}H")

    def _clear_line(self, row: int) -> None:
        self._move(row)
        self._w(f"{ESC}2K")

    def _set_region(self, bottom: int) -> None:
        self._w(f"{ESC}1;{max(1, bottom)}r")

    # -- zone drawing -----------------------------------------------------------
    def _draw(self, buf: str, cur: int, matches: List[CommandSpec], sel: int) -> None:
        cols, rows = self._size()
        menu = matches[:MENU_MAX]
        new_rows = len(menu)
        status_row = rows - 1
        input_row = rows
        region_bottom = status_row - 1 - new_rows
        self._set_region(region_bottom)
        # Clear the band that WAS menu last redraw and is not menu now.
        # This is the stale-highlight fix: closing or shrinking the menu
        # (e.g. backspacing the "/" away, or Esc) erases its old rows.
        for r in range(status_row - self._drawn_menu_rows, status_row - new_rows):
            self._clear_line(r)
        # menu rows, oldest match at the top, highlighted selection
        for i, m in enumerate(menu):
            row = region_bottom + 1 + i
            self._move(row)
            label = (m.name + (" " + m.args if m.args else "")).ljust(24)
            text = ("  " + label + m.description)[: cols - 1]
            if i == sel and self.color:
                self._w(f"{ESC}7m{text}{ESC}0m{ESC}K")
            else:
                dim = f"{ESC}36m" if self.color else ""
                self._w(f"{dim}{text}{ESC}0m{ESC}K" if self.color else text + f"{ESC}K")
        # status row
        self._move(status_row)
        st = self.status_fn()[: cols - 1]
        if self.color:
            self._w(f"{ESC}90m{st}{ESC}0m{ESC}K")
        else:
            self._w(st + f"{ESC}K")
        # input row (show the tail if the line is longer than the screen)
        avail = cols - len(PROMPT) - 1
        shown = buf if len(buf) <= avail else "…" + buf[-(avail - 1):]
        self._move(input_row)
        p = f"{ESC}1;32m{PROMPT}{ESC}0m" if self.color else PROMPT
        self._w(p + shown + f"{ESC}K")
        cur_col = len(PROMPT) + 1 + (cur if len(buf) <= avail else avail)
        self._move(input_row, min(cur_col, cols))
        self._drawn_menu_rows = new_rows

    # -- submit / output handoff ---------------------------------------------------
    def _submit(self, buf: str) -> None:
        cols, rows = self._size()
        status_row = rows - 1
        # close the menu (erase its rows if still drawn), keep the status row
        # pinned, clear the input row
        self._set_region(status_row - 1)
        for r in range(status_row - self._drawn_menu_rows, status_row):
            self._clear_line(r)
        self._drawn_menu_rows = 0
        self._clear_line(rows)
        # echo the submitted line into the scroll region for the transcript
        self._move(status_row - 1)
        self._w("\n")
        echo = f"{PROMPT}{buf}"
        if self.color:
            echo = f"{ESC}1;32m{PROMPT}{ESC}0m{buf}"
        self._w(echo + "\n")

    # -- history ---------------------------------------------------------------------
    def _hist_prev(self, buf: str) -> Tuple[str, int]:
        if not self.history:
            return buf, len(buf)
        if self._hist_idx is None:
            self._draft = buf
            self._hist_idx = len(self.history) - 1
        elif self._hist_idx > 0:
            self._hist_idx -= 1
        buf = self.history[self._hist_idx]
        return buf, len(buf)

    def _hist_next(self, buf: str) -> Tuple[str, int]:
        if self._hist_idx is None:
            return buf, len(buf)
        if self._hist_idx < len(self.history) - 1:
            self._hist_idx += 1
            buf = self.history[self._hist_idx]
        else:
            self._hist_idx = None
            buf = self._draft
        return buf, len(buf)

    # -- main loop ------------------------------------------------------------------------
    def read_line(self) -> str:
        buf, cur, sel = "", 0, 0
        matches: List[CommandSpec] = []
        self._hist_idx = None
        # replay keys swallowed by the EscWatcher during the last turn
        injected = list(self.pending)
        self.pending.clear()
        self._draw(buf, cur, matches, sel)
        while True:
            ch = injected.pop(0) if injected else msvcrt.getwch()
            buf_changed = False
            nav = False
            if ch in ("\x00", "\xe0"):  # special key prefix
                code = msvcrt.getwch()
                if code == "H":      # up
                    if matches:
                        sel = (sel - 1) % len(matches[:MENU_MAX])
                    else:
                        buf, cur = self._hist_prev(buf)
                        buf_changed = True
                    nav = True
                elif code == "P":    # down
                    if matches:
                        sel = (sel + 1) % len(matches[:MENU_MAX])
                    else:
                        buf, cur = self._hist_next(buf)
                        buf_changed = True
                    nav = True
                elif code == "K":    # left
                    cur = max(0, cur - 1)
                elif code == "M":    # right
                    cur = min(len(buf), cur + 1)
                elif code == "G":    # home
                    cur = 0
                elif code == "O":    # end
                    cur = len(buf)
                elif code == "S":    # delete
                    if cur < len(buf):
                        buf = buf[:cur] + buf[cur + 1:]
                        buf_changed = True
            elif ch == "\x14":       # ctrl-t: toggle the thinking pane
                if self.on_ctrl_t:
                    self.on_ctrl_t()
                # buffer untouched; the trailing _draw refreshes the status row
            elif ch == "\r":         # enter
                if matches:
                    menu = matches[:MENU_MAX]
                    chosen = menu[min(sel, len(menu) - 1)]
                    typed = buf.split()[0] if buf else ""
                    if chosen.name != typed:
                        # first Enter fills the highlighted command
                        buf = chosen.usage()
                        cur = len(buf)
                        if chosen.takes_args:
                            matches, sel = filter_commands(buf), 0
                            self._draw(buf, cur, matches, sel)
                            continue
                        # no-arg command: fall through and submit it
                self._submit(buf)
                if buf.strip():
                    self.history.append(buf)
                return buf
            elif ch == "\t":         # tab completion
                buf, matches = tab_complete(buf)
                cur, sel = len(buf), 0
                self._draw(buf, cur, matches, sel)
                continue
            elif ch == "\x03":       # ctrl-c: clear, or exit when empty
                if not buf:
                    self._submit("")
                    raise KeyboardInterrupt
                buf, cur = "", 0
                buf_changed = True
            elif ch == "\x1b":       # esc: close menu, else clear line
                if matches:
                    matches, sel = [], 0
                    self._draw(buf, cur, matches, sel)
                    continue
                buf, cur = "", 0
                buf_changed = True
            elif ch == "\x08":       # backspace
                if cur > 0:
                    buf = buf[:cur - 1] + buf[cur:]
                    cur -= 1
                    buf_changed = True
            elif ch >= " ":          # printable
                buf = buf[:cur] + ch + buf[cur:]
                cur += 1
                buf_changed = True
            # other control chars are ignored
            if buf_changed:
                # menu-arrow nav never changes buf, so this only fires for
                # edits and history recalls - both need a fresh menu filter
                matches, sel = filter_commands(buf), 0
            self._draw(buf, cur, matches, sel)
