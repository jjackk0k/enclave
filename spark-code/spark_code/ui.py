"""Terminal UI: ANSI colors, the persistent one-line status bar, the
you>/spark> prefix convention, colored diffs, and the approval prompt.

Stdlib only. On Windows 10+ consoles `os.system("")` enables VT processing;
if the terminal doesn't support ANSI we degrade to plain text.
"""

from __future__ import annotations

import os
import shutil
import sys
import textwrap
import time
import urllib.parse
from typing import List, Optional, Set

from . import config, cost

ESC = "\x1b["
RESET = ESC + "0m"
BOLD = ESC + "1m"
DIM = ESC + "2m"
CYAN = ESC + "36m"
GREEN = ESC + "32m"
RED = ESC + "31m"
YELLOW = ESC + "33m"
MAGENTA = ESC + "35m"
GRAY = ESC + "90m"


def _soften(stream) -> None:
    """Piped/redirected streams may use a narrow legacy encoding (cp1252);
    the UI prints glyphs like ⚙/✓/· which would crash print() there.
    errors=replace degrades them to '?' instead of a UnicodeEncodeError."""
    try:
        stream.reconfigure(errors="replace")
    except Exception:
        pass


def enable_vt_mode() -> bool:
    if os.name == "nt":
        try:
            os.system("")  # enables VT sequences in conhost/Windows Terminal
        except Exception:
            pass
    _soften(sys.stdout)
    _soften(sys.stderr)
    return sys.stdout.isatty()


def short_model_name(model_id: str) -> str:
    """'/home/varvel/models/RVN-Q4_K_M-mtp.gguf' -> 'RVN-Q4_K_M-mtp'."""
    name = model_id.replace("\\", "/").rsplit("/", 1)[-1]
    for suffix in (".gguf", ".safetensors"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name or model_id


def friendly_model_name(model_id: str) -> str:
    """Raw served id -> owner-facing name via config.MODEL_ALIASES.
    Unknown ids fall back to the basename. Raw id stays visible in /status."""
    short = short_model_name(model_id)
    return config.MODEL_ALIASES.get(short, short)


def ctx_display(used: int, per_slot: int, server_total: int) -> str:
    """Honest context readout.

    - Slot cap >= the owner's 262k target (current config): plain 'ctx N/262,144'.
    - Server total larger than the slot cap: 'ctx N/<total> (slot cap <per-slot>)'.
    - Otherwise plain per-slot.
    """
    pct = f" ({100 * used / per_slot:.0f}%)" if per_slot else ""
    if per_slot >= config.CTX_OWNER_TARGET or server_total <= per_slot:
        return f"ctx {used:,}/{per_slot:,}{pct}"
    return f"ctx {used:,}/{server_total:,} (slot cap {per_slot:,}){pct}"


def fmt_tokens(n: int) -> str:
    """'3.1k' for thousands, exact below - matches the status-line idiom."""
    return f"{n / 1000:.1f}k" if n >= 1000 else str(n)


def _term_cols() -> int:
    try:
        return max(40, shutil.get_terminal_size().columns)
    except Exception:
        return 80


class ThinkingDisplay:
    """Collapsible thinking pane (Kimi Code style).

    Default COLLAPSED: while the model reasons, a single dimmed status line
    is rewritten in place (throttled) on a VT console:

        spark> · thinking… 7s · ~1.2k tokens — ctrl+t to expand

    and finalized when the answer starts (or the stream ends/aborts):

        spark> · thought for 12s · ~3.1k tokens — ctrl+t to expand

    EXPANDED (/think toggles, persists for the session): reasoning streams
    dimmed, followed by the same summary line. The last turn's thinking is
    kept in memory (never in session history) so /think can re-render it
    wrapped and dimmed on demand.

    Once closed (answer started), late reasoning deltas are buffered only -
    rewriting over streamed answer text is exactly the collision this class
    exists to prevent.
    """

    REDRAW_INTERVAL = 0.1  # seconds between live status-line rewrites

    def __init__(self, ui: "UI") -> None:
        self.ui = ui
        self.expanded = False      # user's session toggle; default collapsed
        self.last_text = ""        # last thinking on record (for /think)
        self.last_elapsed = 0.0
        self.last_tokens = 0
        self._reset()

    def _reset(self) -> None:
        self._parts: list = []
        self._chars = 0
        self._t0: Optional[float] = None
        self._open = False         # a live status line is on screen, no newline yet
        self._closed = False       # answer started / stream done: no more live writes
        self._header = False       # expanded-mode header already printed
        self._last_draw = 0.0

    def begin(self) -> None:
        """Start of one streamed completion. Never clears the user's toggle
        or the recorded last thinking."""
        self._reset()

    # -- streaming ----------------------------------------------------------
    def feed(self, text: str) -> None:
        # the model's reasoning is never trusted blindly: ESC/CR would let a
        # stray sequence wreck the terminal state
        text = text.replace("\x1b", "").replace("\r", "")
        if not text:
            return
        if self._t0 is None:
            self._t0 = time.perf_counter()
        self._parts.append(text)
        self._chars += len(text)
        if self._closed:
            # reasoning after the answer started: buffer, never draw over it
            self.last_text = "".join(self._parts).strip()
            return
        if self.expanded:
            if not self._header:
                self.ui.dim("· thinking (ctrl+t to collapse):")
                self._header = True
            self.ui.write_reasoning(text)
        elif self._inline():
            now = time.perf_counter()
            if not self._open or now - self._last_draw >= self.REDRAW_INTERVAL:
                self._draw_live(now)
        # piped/non-VT: nothing until finish() prints the single final line

    def toggle_live(self) -> bool:
        """ctrl+t: flip the pane. Mid-thinking this takes effect immediately -
        collapsing stops the dimmed echo (one marker line), expanding resumes
        it (the header reprints on the next delta). Outside a stream it just
        flips the flag for the next one. Safe to call from the watcher thread:
        single write calls only."""
        self.expanded = not self.expanded
        if self._closed or self._t0 is None:
            return self.expanded
        if self.expanded:
            # a collapsed live status line may be open - wipe it so the
            # reprinted header starts on a clean line
            if self._open and self._inline():
                self._w("\r" + ESC + "2K")
                self._open = False
            self._header = False  # next feed reprints the header
        else:
            if self._header:
                # the dimmed echo is on screen, possibly mid-line: close the
                # line, then the marker (already-printed text can't be
                # unprinted - the marker says the rest is hidden)
                print()
                self.ui.dim("  · (thinking hidden - ctrl+t to show)")
                self._header = False
        return self.expanded

    def finish(self) -> None:
        """Close the pane. Idempotent; safe to call from finally blocks, so
        Ctrl-C or a mid-stream error never leaves a dangling status line."""
        if self._closed:
            return
        self._closed = True
        if self._t0 is None:
            return  # no thinking streamed at all
        elapsed = time.perf_counter() - self._t0
        tokens = max(1, self._chars // 4)  # reasoning chars ≈ 4/token
        self.last_text = "".join(self._parts).strip()
        self.last_elapsed = elapsed
        self.last_tokens = tokens
        hint = "ctrl+t to collapse" if self.expanded else "ctrl+t to expand"
        summary = f"  · thought for {elapsed:.0f}s · ~{fmt_tokens(tokens)} tokens — {hint}"
        if self.expanded:
            if not self.last_text.endswith("\n"):
                print()  # end the dimmed reasoning line
            self.ui.dim(summary)
        elif self._inline() and self._open:
            # rewrite the live line in place, then move to a fresh line
            self._w("\r" + ESC + "2K" + self.ui._assistant_prefix()
                    + self.ui._c(summary, GRAY) + "\n")
            self._open = False
        else:
            self.ui.dim(summary)  # piped: the one and only line we print

    # -- on demand ------------------------------------------------------------
    def render_last(self) -> None:
        """Re-render the last turn's thinking, wrapped and dimmed (/think)."""
        if not self.last_text:
            self.ui.dim("  (no thinking recorded yet this session)")
            return
        self.ui.dim(f"  · last thinking "
                    f"({self.last_elapsed:.0f}s · ~{fmt_tokens(self.last_tokens)} tokens):")
        width = max(20, _term_cols() - 4)
        for para in self.last_text.splitlines():
            wrapped = textwrap.wrap(para, width=width) if para.strip() else [""]
            for line in wrapped:
                self.ui.dim("    " + line)
        print()

    # -- internals --------------------------------------------------------------
    def _inline(self) -> bool:
        return self.ui.color and sys.stdout.isatty()

    def _w(self, s: str) -> None:
        sys.stdout.write(s)
        sys.stdout.flush()

    def _draw_live(self, now: float) -> None:
        elapsed = now - (self._t0 or now)
        status = (f"  · thinking… {elapsed:.0f}s · ~{fmt_tokens(self._chars // 4)}"
                  " tokens — ctrl+t to expand")
        # keep the whole line inside the terminal width: a wrapped live line
        # would leave a stale row behind on the next rewrite
        status = status[: max(20, _term_cols() - 1 - len("spark> "))]
        prefix = self.ui._assistant_prefix() if self._open else ""
        if self._open:
            self._w("\r" + ESC + "2K")
        self._w(prefix + self.ui._c(status, GRAY))
        self._open = True
        self._last_draw = now


class UI:
    def __init__(self, yolo: bool = False, color: bool = True) -> None:
        self.yolo = yolo
        self.color = color
        self.always: Set[str] = set()  # categories approved "always" this session
        self.think = ThinkingDisplay(self)
        self._search_inline = False
        # keys the EscWatcher swallowed mid-turn; the editor replays them
        self.key_buffer: List[str] = []
        # raw one-key reader for the approval prompt (msvcrt on a real
        # console); None -> line input() fallback (piped stdin, non-Windows)
        self.key_source = None
        if os.name == "nt":
            try:
                import msvcrt
                if sys.stdin.isatty():
                    self.key_source = msvcrt.getwch
            except Exception:
                pass

    def _c(self, text: str, *codes: str) -> str:
        if not self.color or not codes:
            return text
        return "".join(codes) + text + RESET

    # -- messaging -------------------------------------------------------------
    def info(self, msg: str) -> None:
        print(self._c(msg, CYAN))

    def warn(self, msg: str) -> None:
        print(self._c(msg, YELLOW))

    def error(self, msg: str) -> None:
        print(self._c(msg, RED))

    def dim(self, msg: str) -> None:
        print(self._c(msg, GRAY))

    def banner(self, version: str, model: str, ctx_limit: int, ctx_total: int,
               ctx_source: str, cwd: str, tunnel_status: str) -> None:
        line = "=" * 64
        print(self._c(line, MAGENTA))
        print(self._c(f"  SPARK CODE v{version}", BOLD, MAGENTA)
              + self._c("  -  local coding agent on your DGX Spark", GRAY))
        print(self._c(line, MAGENTA))
        print(f"  model    : {model}")
        print(f"  context  : {ctx_limit:,} tokens per slot "
              f"(server total {ctx_total:,}; {ctx_source})")
        print(f"  cwd      : {cwd}")
        tunnel = "reused existing tunnel" if tunnel_status == "already-up" else "started by spark-code"
        print(f"  tunnel   : {tunnel}")
        print(f"  cost     : $0.00 - local model, no API bill, ever")
        print(self._c("  type / for the command menu (TAB completes) · /help", GRAY))
        if self.yolo:
            print(self._c("  yolo on - every write and shell command is auto-approved (/yolo toggles)", GRAY))
        else:
            print(self._c("  approvals on · --yolo auto-approves everything · 'a' = always per category", GRAY))
        print()

    # -- status bar ---------------------------------------------------------------
    def status_text(self, model: str, ctx_used: int, ctx_limit: int, ctx_total: int,
                    tok_s: float, mode: str, cwd: str, yolo: bool,
                    thinking: bool = True, session_cloud: float = 0.0,
                    think_expanded: bool = False) -> str:
        """One-line status; cwd leads because the owner always wants to see it."""
        speed = f"{tok_s:.1f} tok/s"  # never blank: 0.0 until the first measurement
        flags = " · YOLO" if yolo else ""
        if thinking:
            think = " · thinking:on·expanded" if think_expanded else " · thinking:on"
        else:
            think = " · thinking:off"
        cloud = f" · would-cost {cost.format_usd(session_cloud)}" if session_cloud > 0 else ""
        return (f"{cwd} · {model} · {ctx_display(ctx_used, ctx_limit, ctx_total)}"
                f" · {speed} · {mode}{think}{flags} · $0.00 local{cloud}")

    def status_bar(self, **kwargs) -> None:
        print(self._c(self.status_text(**kwargs), GRAY))

    # -- conversation prefixes ----------------------------------------------------
    def _assistant_prefix(self) -> str:
        return self._c("spark> ", BOLD, CYAN)

    def prompt_user(self) -> str:
        return input(self._c("you> ", BOLD, GREEN))

    def assistant_start(self) -> None:
        print(self._assistant_prefix(), end="", flush=True)

    def write(self, text: str) -> None:
        print(text, end="", flush=True)

    def write_reasoning(self, text: str) -> None:
        """Model's streamed thinking - dimmed, never stored in history."""
        print(self._c(text, GRAY), end="", flush=True)

    def assistant_end(self, tok_s: float, completion_tokens: int,
                      estimated: bool, finish_reason: str,
                      cloud_turn: float = 0.0, cloud_session: float = 0.0) -> None:
        print()
        speed = f"{tok_s:.1f} tok/s" if tok_s > 0 else "? tok/s"
        est = " (estimated)" if estimated else ""
        fin = f" · finish: {finish_reason}" if finish_reason and finish_reason != "stop" else ""
        cloud = ""
        if cloud_turn > 0:
            cloud = (f" · cloud equivalent {cost.format_usd(cloud_turn)} (ref)"
                     f" · session {cost.format_usd(cloud_session)} · $0.00 local")
        print(self._c(f"      [{completion_tokens} tokens{est} · {speed}{fin}{cloud}]", GRAY))

    def tool_activity(self, msg: str) -> None:
        print(self._c(f"  ⚙ {msg}", MAGENTA))

    # -- web search activity block ------------------------------------------------
    # A compact, self-contained block - the raw tool JSON never reaches the
    # screen. search_begin draws a progress line that search_end then either
    # rewrites in place (VT console) or leaves as history (piped).
    SEARCH_SNIPPET_CHARS = 110  # one clean line per result

    def _search_head(self, query: str) -> str:
        return self._c("  ⚙ web search · ", MAGENTA) + self._c(query, BOLD)

    def search_begin(self, query: str) -> None:
        self._search_inline = self.color and sys.stdout.isatty()
        shown = query
        if self._search_inline:
            # the progress line gets erased with 2K later, which only clears
            # one terminal row - it must never wrap
            budget = _term_cols() - 1 - len("  ⚙ web search · ") - len("  searching…")
            if len(shown) > budget:
                shown = shown[: max(10, budget - 1)].rstrip() + "…"
            sys.stdout.write(self._search_head(shown) + self._c("  searching…", GRAY))
            sys.stdout.flush()
        else:
            print(self._search_head(shown) + self._c("  searching…", GRAY))

    def _search_wipe(self) -> None:
        if self._search_inline:
            sys.stdout.write("\r" + ESC + "2K")
            sys.stdout.flush()
        self._search_inline = False

    def search_end(self, data: Optional[dict], elapsed: float) -> None:
        self._search_wipe()
        data = data or {}
        query = str(data.get("query") or "")
        status = str(data.get("status") or "")
        provider = str(data.get("provider") or "")
        results = data.get("results") or []
        secs = self._c(f" ({elapsed:.1f}s)", GRAY)
        if status == "results" and results:
            print(self._search_head(query)
                  + self._c(f"  ·  {len(results)} result(s) via {provider}", GRAY) + secs)
            for i, r in enumerate(results, 1):
                title = " ".join(str(r.get("title") or "").split()) or "(untitled)"
                url = str(r.get("url") or "")
                try:
                    domain = urllib.parse.urlparse(url).hostname or ""
                except Exception:
                    domain = ""
                print(f"    {i}. {title}" + (self._c(f"  ·  {domain}", GRAY) if domain else ""))
                snip = " ".join(str(r.get("snippet") or "").split())
                if snip:
                    if len(snip) > self.SEARCH_SNIPPET_CHARS:
                        snip = snip[: self.SEARCH_SNIPPET_CHARS - 1].rstrip() + "…"
                    print(self._c("       " + snip, GRAY))
                if url:
                    print(self._c("       " + url, GRAY))
        elif status == "results":
            print(self._search_head(query)
                  + self._c(f"  ·  no results (via {provider})", GRAY) + secs)
        elif status == "capped":
            print(self._search_head(query)
                  + self._c("  ·  per-turn search cap reached - answer with what you have", GRAY))
        elif status == "limited":
            print(self._search_head(query)
                  + self._c("  ·  unavailable: every provider failed or was rate-limited",
                            YELLOW) + secs)
        else:
            print(self._search_head(query)
                  + self._c("  ·  search did not run (bad arguments)", YELLOW))

    def search_abort(self, query: str = "") -> None:
        """Ctrl-C landed mid-fetch: close the progress line cleanly."""
        self._search_wipe()
        print(self._c("  ⚙ web search", MAGENTA)
              + (self._c(f" · {query}", GRAY) if query else "")
              + self._c("  ·  interrupted", YELLOW))

    # -- diffs ---------------------------------------------------------------------
    def print_diff(self, diff_text: str) -> None:
        for line in diff_text.splitlines():
            if line.startswith("+++") or line.startswith("---"):
                print(self._c(line, BOLD))
            elif line.startswith("+"):
                print(self._c(line, GREEN))
            elif line.startswith("-"):
                print(self._c(line, RED))
            elif line.startswith("@@"):
                print(self._c(line, CYAN))
            else:
                print(line)

    # -- approval --------------------------------------------------------------------
    APPROVAL_PROMPT = "  proceed? [y]es / [n]o / [a]lways: "

    def approve(self, category: str, summary: str, detail: Optional[str]) -> bool:
        """Return True to proceed. Handles y/n/always and --yolo."""
        if self.yolo or category in self.always:
            tag = "yolo" if self.yolo else "always"
            print(self._c(f"  ✓ auto-approved ({tag}): ", GREEN) + summary)
            if detail and category == "write":
                self.print_diff(detail)
            return True
        print(self._c("  approval needed · ", YELLOW) + summary)
        if detail:
            self.print_diff(detail)
        ans = self._read_approval()
        if ans == "y":
            return True
        if ans == "a":
            self.always.add(category)
            self.dim(f"  ('{category}' actions auto-approved for the rest of this session)")
            return True
        return False

    def _read_approval(self) -> str:
        """One keypress answers: y / n / a (Enter, Esc and Ctrl-C all mean no).

        Raw console path: any other key is consumed and IGNORED - it never
        echoes as ^T-style litter and the prompt is never half-repainted.
        The line is drawn once, then erased whole (\\r + 2K) and redrawn
        with the answer echoed, so nothing from the stream bleeds through.
        Exactly one key is consumed - a follow-up Enter stays buffered for
        the next prompt, where it submits an empty line (dropped by the REPL).
        Falls back to line input() when there is no raw key source.
        """
        if self.key_source is None:
            try:
                ans = input(self._c(self.APPROVAL_PROMPT, YELLOW)).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return "n"
            if ans in ("y", "yes"):
                return "y"
            if ans in ("a", "always"):
                return "a"
            return "n"
        sys.stdout.write(self._c(self.APPROVAL_PROMPT, YELLOW))
        sys.stdout.flush()
        try:
            while True:
                ch = self.key_source()
                if ch in ("\x00", "\xe0"):  # special-key prefix: swallow its tail too
                    self.key_source()
                    continue
                if ch in ("y", "Y"):
                    ans = "y"
                elif ch in ("a", "A"):
                    ans = "a"
                elif ch in ("n", "N", "\r", "\n", "\x1b", "\x03"):
                    ans = "n"
                else:
                    continue  # consumed silently - no echo, no redraw
                break
        except KeyboardInterrupt:
            sys.stdout.write("\n")
            sys.stdout.flush()
            return "n"
        # clean repaint: erase the whole line, redraw prompt + echoed answer
        if self.color:
            sys.stdout.write("\r" + ESC + "2K" + self._c(self.APPROVAL_PROMPT, YELLOW)
                             + self._c(ans, BOLD) + "\n")
        else:
            sys.stdout.write(ans + "\n")
        sys.stdout.flush()
        return ans
