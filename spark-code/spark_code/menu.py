"""The VARVEL Ops Console (spark-menu) — a premium dark red-team console.

customtkinter shell over the headless logic in menuops.py + opsmenu.py
(unit-tested); stdlib tk.Text panes where rich tagging is needed (event
stream, chat transcript). Three tabs under one stats bar:

  OPS    the 1-click hunt: left rail of state cards (TUNNEL / LANE / BRAIN /
         GHOST / PIPELINE) + START/STOP/PAUSE HUNT, the stage board as rich
         cards driven ONLY by the loop's real events.jsonl, and the live
         event stream with VERIFIED/UNVERIFIED counters + evidence buttons.
  CHAT   a chat tab on the lane model (SparkClient, reused): thinking
         toggle, effort selector, live context meter (tokens/262144).
         During HUNT ACTIVE the tab shows the profit-first banner instead
         of sending — ALL model capacity goes to the hunt.
  SPARK  the original spark-menu features (folder + REPL launch, tunnel
         connect, lane model management).

The GHOST gate is doctrine: START HUNT refuses unless the ghost chain is
verified live (dial + exit-differs-from-origin + DNS-leak sanity); a mid-hunt
ghost drop PAUSES the hunt, loud. All heavy work rides worker threads through
a queue polled by the tk mainloop. Run: `pythonw -m spark_code.menu` or the
built spark-menu.exe.
"""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, font as tkfont

import customtkinter as ctk

from . import __version__
from . import config, opsmenu
from .client import SparkClient
from .menuops import current_model, health, lane_list, lane_ssh, spawn_repl
from .tunnel import TunnelManager

ctk.set_appearance_mode("dark")

_POLL_MS = 200
_OPS_TICK_MS = 1000
_GHOST_RECHECK_TICKS = 120  # ~2 min between mid-hunt ghost re-checks

# --- design tokens (applied consistently) --------------------------------------
TK = {
    "bg": "#0a0e14",          # deep-space background
    "panel": "#11161f",       # panel surfaces
    "panel2": "#161d29",      # raised surfaces (cards)
    "border": "#1f2a3a",
    "text": "#d5e1f0",
    "dim": "#7d8aa0",
    "cyan": "#35f0d0",        # phosphor accent / ok / active
    "cyan_dim": "#1d6f63",
    "amber": "#f0b35e",       # warn
    "red": "#ff5470",         # crit
    "purple": "#b48cff",      # special (proofs, drafted)
    "blue": "#5aa2f0",
}
STATE_TONE = {  # state -> token key
    "idle": "dim", "active": "cyan", "done": "cyan", "failed": "red",
    "waiting": "amber", "up": "cyan", "down": "amber", "unknown": "red",
    "running": "cyan", "paused": "amber", "stopped": "dim",
    "started": "cyan", "starting-timeout": "amber", "missing": "red", "error": "red",
}
SEV_TONE = {  # findings-section severity badge -> token key
    "CRIT": "red", "CRITICAL": "red", "HIGH": "red", "MED": "amber",
    "MEDIUM": "amber", "LOW": "dim", "INFO": "dim",
}
VERDICT_TONE = {  # findings-section EVIDENCE badge -> token key (2026-09-18: no VERIFIED badge
    # exists — a replay-passed finding is FIRM (offline re-derivation, not a live confirmation);
    # only a demonstrated PoC, or the report gate's own `ready`, is SUBMITTABLE)
    "POC-DEMONSTRATED": "purple", "SUBMITTABLE": "cyan", "FIRM": "amber",
    "UNPROVEN": "amber", "UNVERIFIED": "dim", "CHECK-DEFECT": "red", "SKIPPED": "dim",
}


def _mono(size=11, weight="normal") -> tuple:
    fam = "Cascadia Code" if "Cascadia Code" in tkfont.families() else "Consolas"
    return (fam, size, weight)


def caps(s: str) -> str:
    """Tracked caps for section labels: STATE -> S T A T E."""
    return " ".join(s.upper())


class MenuApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.tunnel = TunnelManager()
        self._q: "queue.Queue[tuple]" = queue.Queue()
        self._ops_ticks = 0
        self._board_sig = None
        self._stream_sig = None
        self._transients = []  # console-posted lines — survive every stream re-render
        self._ghost = {"ok": False, "checks": {}, "remediation": [], "chain": None}
        self._chat = opsmenu.ChatState()
        self._chat_client = SparkClient()
        self._chat_busy = False
        self._poc_busy = False  # one forge at a time — the lane is shared with the hunt
        self._poc_target = None  # the evidence dir currently under the forge
        self._batch_running = False  # a FORGE ALL batch holds _poc_busy for its whole run
        self._batch_stop = False     # FORGE_STOP written; cancels after the current finding
        self._pipeline = ("stopped", "no hunt on record")

        self.title(f"VARVEL OPS CONSOLE · spark-code v{__version__}")
        self.minsize(1480, 940)
        self.configure(fg_color=TK["bg"])
        self.protocol("WM_DELETE_WINDOW", self._quit)

        self._build_stats_bar()
        self._build_tabs()

        self.after(_POLL_MS, self._drain)
        self.after(_OPS_TICK_MS, self._ops_tick)
        self._state_refresh()
        self._ghost_verify(background=True)

    # ==========================================================================
    # chrome: stats bar + tabs
    # ==========================================================================
    def _build_stats_bar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color=TK["panel"], corner_radius=0, height=38)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)
        ctk.CTkLabel(bar, text="◤VARVEL◢ OPS", font=("Segoe UI", 13, "bold"),
                     text_color=TK["cyan"]).pack(side="left", padx=(14, 6))
        ctk.CTkLabel(bar, text="governed autonomous bounty hunt · never submits",
                     font=("Segoe UI", 9), text_color=TK["dim"]).pack(side="left", padx=(0, 10))
        self.stat_model = self._stat_cell(bar, "MODEL", "—")
        self.stat_toks = self._stat_cell(bar, "SPEED", "— tok/s")
        self.stat_lane = self._stat_cell(bar, "LANE", "—")
        self.stat_effort = self._stat_cell(bar, "EFFORT", self._chat.effort)
        ctx = ctk.CTkFrame(bar, fg_color="transparent")
        ctx.pack(side="right", padx=14)
        self.ctx_label = ctk.CTkLabel(ctx, text="ctx — / 262144", font=_mono(10),
                                      text_color=TK["dim"])
        self.ctx_label.pack(side="right", padx=(8, 0))
        self.ctx_bar = ctk.CTkProgressBar(ctx, width=140, height=8,
                                          progress_color=TK["cyan"],
                                          fg_color=TK["border"])
        self.ctx_bar.set(0)
        self.ctx_bar.pack(side="right")

    def _stat_cell(self, parent, label, value):
        cell = ctk.CTkFrame(parent, fg_color="transparent")
        cell.pack(side="left", padx=14)
        ctk.CTkLabel(cell, text=caps(label), font=("Segoe UI", 7, "bold"),
                     text_color=TK["dim"]).pack(anchor="w")
        v = ctk.CTkLabel(cell, text=value, font=_mono(11, "bold"),
                         text_color=TK["text"])
        v.pack(anchor="w")
        return v

    def _build_tabs(self) -> None:
        self.tabs = ctk.CTkTabview(self, fg_color=TK["bg"],
                                   segmented_button_fg_color=TK["panel"],
                                   segmented_button_selected_color=TK["cyan_dim"],
                                   segmented_button_selected_hover_color=TK["cyan_dim"],
                                   segmented_button_unselected_color=TK["panel"],
                                   segmented_button_unselected_hover_color=TK["panel2"],
                                   text_color=TK["text"],
                                   anchor="w")
        self.tabs.pack(fill="both", expand=True, padx=8, pady=(4, 8))
        self.tabs.add("OPS")
        self.tabs.add("FINDINGS")
        self.tabs.add("CHAT")
        self.tabs.add("SPARK")
        self._build_ops_tab(self.tabs.tab("OPS"))
        self._build_findings_tab(self.tabs.tab("FINDINGS"))
        self._build_chat_tab(self.tabs.tab("CHAT"))
        self._build_spark_tab(self.tabs.tab("SPARK"))

    # ==========================================================================
    # OPS tab
    # ==========================================================================
    def _build_ops_tab(self, tab) -> None:
        tab.grid_columnconfigure(1, weight=3)
        tab.grid_columnconfigure(2, weight=2)
        tab.grid_rowconfigure(0, weight=1)

        # -- left rail ---------------------------------------------------------
        rail = ctk.CTkScrollableFrame(tab, fg_color=TK["bg"], width=300,
                                      scrollbar_button_color=TK["border"])
        rail.grid(row=0, column=0, sticky="ns", padx=(2, 6), pady=2)
        ctk.CTkLabel(rail, text=caps("state"), font=("Segoe UI", 9, "bold"),
                     text_color=TK["dim"]).pack(anchor="w", padx=4, pady=(4, 2))
        self.cards = {}
        for key in ("tunnel", "lane", "brain", "ghost", "pipeline", "docker"):
            self.cards[key] = self._state_card(rail, key)

        self.banner = ctk.CTkLabel(rail, text="", font=("Segoe UI", 9, "bold"),
                                   fg_color="#3d2e00", text_color=TK["amber"],
                                   corner_radius=6, wraplength=270, justify="left",
                                   padx=10, pady=6)
        self.banner.configure(text="⚡ HUNT ACTIVE — ALL MODEL CAPACITY TO THE HUNT\n"
                                   "chat + quick-launch paused until STOP")

        ctk.CTkLabel(rail, text=caps("hunt control"), font=("Segoe UI", 9, "bold"),
                     text_color=TK["dim"]).pack(anchor="w", padx=4, pady=(10, 2))
        self.start_btn = ctk.CTkButton(
            rail, text="▶  START HUNT", font=("Segoe UI", 13, "bold"), height=46,
            fg_color=TK["cyan_dim"], hover_color=TK["cyan"], text_color="#04110e",
            corner_radius=8, command=self._ops_start)
        self.start_btn.pack(fill="x", padx=4, pady=(2, 4))
        self.stop_btn = ctk.CTkButton(
            rail, text="■  STOP HUNT", font=("Segoe UI", 11, "bold"), height=34,
            fg_color="transparent", hover_color="#3a1620", text_color=TK["red"],
            border_color=TK["red"], border_width=1, corner_radius=8,
            command=self._ops_stop)
        self.stop_btn.pack(fill="x", padx=4, pady=4)
        self.pause_btn = ctk.CTkButton(
            rail, text="⏸  PAUSE / ▶ RESUME", font=("Segoe UI", 10), height=30,
            fg_color=TK["panel2"], hover_color=TK["border"], text_color=TK["text"],
            corner_radius=8, command=self._ops_pause_resume)
        self.pause_btn.pack(fill="x", padx=4, pady=4)
        self.ghost_btn = ctk.CTkButton(
            rail, text="⛨  VERIFY GHOST", font=("Segoe UI", 10), height=30,
            fg_color=TK["panel2"], hover_color=TK["border"], text_color=TK["purple"],
            corner_radius=8, command=lambda: self._ghost_verify(background=True))
        self.ghost_btn.pack(fill="x", padx=4, pady=(4, 10))

        # -- center: stage board -------------------------------------------------
        center = ctk.CTkFrame(tab, fg_color=TK["panel"], corner_radius=10,
                              border_color=TK["border"], border_width=1)
        center.grid(row=0, column=1, sticky="nsew", padx=4, pady=2)
        ctk.CTkLabel(center, text=caps("stage board"), font=("Segoe UI", 9, "bold"),
                     text_color=TK["dim"]).pack(anchor="w", padx=12, pady=(10, 4))
        grid = ctk.CTkFrame(center, fg_color="transparent")
        grid.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        for c in range(2):
            grid.grid_columnconfigure(c, weight=1)
        self.stage_cards = {}
        for i, name in enumerate(opsmenu.STAGES):
            card = ctk.CTkFrame(grid, fg_color=TK["panel2"], corner_radius=8,
                                border_color=TK["border"], border_width=1)
            card.grid(row=i // 2, column=i % 2, sticky="nsew", padx=4, pady=4)
            grid.grid_rowconfigure(i // 2, weight=1)
            head = ctk.CTkFrame(card, fg_color="transparent")
            head.pack(fill="x", padx=8, pady=(6, 0))
            ctk.CTkLabel(head, text=caps(name), font=_mono(10, "bold"),
                         text_color=TK["text"]).pack(side="left")
            pill = ctk.CTkLabel(head, text="idle", font=_mono(9, "bold"),
                                fg_color=TK["border"], text_color=TK["dim"],
                                corner_radius=8, padx=8, pady=1)
            pill.pack(side="right")
            msg = ctk.CTkLabel(card, text="", font=_mono(9), text_color=TK["dim"],
                               anchor="w", justify="left", wraplength=230)
            msg.pack(fill="x", padx=8, pady=(2, 2))
            at = ctk.CTkLabel(card, text="—", font=_mono(8), text_color=TK["dim"],
                              anchor="w")
            at.pack(fill="x", padx=8, pady=(0, 6))
            self.stage_cards[name] = (pill, msg, at)

        # -- right: counters + event stream --------------------------------------
        right = ctk.CTkFrame(tab, fg_color=TK["panel"], corner_radius=10,
                             border_color=TK["border"], border_width=1)
        right.grid(row=0, column=2, sticky="nsew", padx=(6, 2), pady=2)

        cnt = ctk.CTkFrame(right, fg_color="transparent")
        cnt.pack(fill="x", padx=10, pady=(10, 2))
        # THE COUNTERS TELL THE TRUTH (2026-09-18): the first big number used to read "VERIFIED"
        # over every replay-passed finding — 61 of them, mostly version→CVE matches that no
        # program will accept. SUBMITTABLE is the number that pays; FIRM is the honest name for
        # an offline re-derivation; UNVERIFIED stays what it always was.
        self.cnt_submittable = self._big_counter(cnt, "SUBMITTABLE", TK["cyan"], 0)
        self.cnt_firm = self._big_counter(cnt, "FIRM (NOT CONFIRMED)", TK["amber"], 2)
        self.cnt_unverified = self._big_counter(cnt, "UNVERIFIED", TK["red"], 4)
        self.cnt_drafted = self._big_counter(cnt, "DRAFTED", TK["purple"], 6)
        chips = ctk.CTkFrame(right, fg_color="transparent")
        chips.pack(fill="x", padx=10)
        self.chip_clean = self._chip(chips, "clean: —", TK["dim"])
        self.chip_vm = self._chip(chips, "VM idle", TK["blue"])
        self.chip_seen = self._chip(chips, "seen 0 · tested 0", TK["dim"])

        ctk.CTkLabel(right, text=caps("live event stream"),
                     font=("Segoe UI", 9, "bold"), text_color=TK["dim"]).pack(
                     anchor="w", padx=12, pady=(8, 2))
        self.stream = tk.Text(right, bg="#0c1119", fg=TK["text"], bd=0,
                              font=_mono(9), state="disabled", wrap="word",
                              insertbackground=TK["cyan"],
                              selectbackground=TK["cyan_dim"])
        self.stream.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        for tag, color in (("active", TK["cyan"]), ("done", TK["cyan"]),
                           ("failed", TK["red"]), ("error", TK["red"]),
                           ("warn", TK["amber"]), ("dim", TK["dim"]),
                           ("proof", TK["purple"]), ("app", TK["blue"])):
            self.stream.tag_config(tag, foreground=color)

        btns = ctk.CTkFrame(right, fg_color="transparent")
        btns.pack(fill="x", padx=10, pady=(0, 10))
        for label, target in (("Evidence", "evidence"), ("Outbox (review)", "outbox"),
                              ("Findings ledger", "findings")):
            ctk.CTkButton(btns, text=label, font=("Segoe UI", 9), height=26,
                          fg_color=TK["panel2"], hover_color=TK["border"],
                          text_color=TK["blue"], corner_radius=6,
                          command=lambda t=target: self._open(t)).pack(side="left", padx=2)
        # The PoC-forge: turn a replay-VERIFIED finding into a demonstrated PoC
        # (read-only, scope-guarded) and upgrade its draft — on the operator's click.
        self.poc_btn = ctk.CTkButton(
            btns, text="⚒  BUILD PoC", font=("Segoe UI", 9, "bold"), height=26,
            fg_color=TK["panel2"], hover_color=TK["border"], text_color=TK["purple"],
            corner_radius=6, command=self._poc_pick)
        self.poc_btn.pack(side="left", padx=(8, 2))

    def _state_card(self, parent, key):
        card = ctk.CTkFrame(parent, fg_color=TK["panel2"], corner_radius=8,
                            border_color=TK["border"], border_width=1)
        card.pack(fill="x", padx=4, pady=3)
        ctk.CTkLabel(card, text=caps(key), font=("Segoe UI", 7, "bold"),
                     text_color=TK["dim"]).pack(anchor="w", padx=8, pady=(5, 0))
        status = ctk.CTkLabel(card, text="…", font=_mono(11, "bold"),
                              text_color=TK["dim"], anchor="w")
        status.pack(anchor="w", padx=8)
        detail = ctk.CTkLabel(card, text="", font=_mono(8), text_color=TK["dim"],
                              anchor="w", justify="left", wraplength=260)
        detail.pack(anchor="w", padx=8, pady=(0, 5))
        return (status, detail)

    def _big_counter(self, parent, label, color, col):
        cell = ctk.CTkFrame(parent, fg_color="transparent")
        cell.grid(row=0, column=col, columnspan=2, padx=8, sticky="w")
        v = ctk.CTkLabel(cell, text="0", font=_mono(22, "bold"), text_color=color)
        v.pack(anchor="w")
        ctk.CTkLabel(cell, text=caps(label), font=("Segoe UI", 7, "bold"),
                     text_color=TK["dim"]).pack(anchor="w")
        parent.grid_columnconfigure(col, weight=1)
        parent.grid_columnconfigure(col + 1, weight=1)
        return v

    def _chip(self, parent, text, color):
        chip = ctk.CTkLabel(parent, text=text, font=_mono(9, "bold"),
                            fg_color=TK["panel2"], text_color=color,
                            corner_radius=6, padx=8, pady=2)
        chip.pack(side="left", padx=3, pady=2)
        return chip

    # ==========================================================================
    # FINDINGS tab — every ledger finding with VERIFY + REPORT
    # ==========================================================================
    # Placement decision: a dedicated tab (not a panel under the stage board) —
    # the OPS right rail is already dense (counters/chips/stream/buttons), and a
    # scrollable findings table is a list UI, not a dashboard card. Refresh is
    # ON DEMAND (↻ button + after a forge completes + once at build) rather than
    # per ops-tick: the parse is cheap but rebuilding rows every second would
    # flicker and fight the operator's scroll position.
    def _build_findings_tab(self, tab) -> None:
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_columnconfigure(0, weight=1)
        head = ctk.CTkFrame(tab, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=6, pady=(6, 2))
        ctk.CTkLabel(head, text=caps("findings — the hunt ledger: verify or report"),
                     font=("Segoe UI", 10, "bold"), text_color=TK["dim"]).pack(
                     side="left", padx=6, pady=4)
        self.findings_summary = ctk.CTkLabel(head, text="", font=_mono(9, "bold"),
                                             text_color=TK["purple"])
        self.findings_summary.pack(side="left", padx=16)
        # FORGE ALL: every forgeable finding through the PoC-forge in one click
        # (serial — the lane is shared). While a batch runs this same button is
        # the honest cancel: STOP BATCH writes FORGE_STOP, which lands AFTER the
        # current finding, never mid-forge.
        self.forge_all_btn = ctk.CTkButton(
            head, text="⚒  FORGE ALL", width=132, height=26, font=("Segoe UI", 9, "bold"),
            fg_color=TK["panel2"], hover_color=TK["border"], text_color=TK["purple"],
            corner_radius=6, text_color_disabled=TK["dim"],
            command=self._forge_all_click)
        self.forge_all_btn.pack(side="right", padx=6)
        ctk.CTkButton(head, text="↻  Refresh", width=96, height=26, font=("Segoe UI", 9),
                      fg_color=TK["panel2"], hover_color=TK["border"], text_color=TK["text"],
                      corner_radius=6, command=self._findings_refresh).pack(side="right", padx=6)
        self.findings_list = ctk.CTkScrollableFrame(tab, fg_color=TK["panel"],
                                                    scrollbar_button_color=TK["border"])
        self.findings_list.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))
        self._findings_rows = []
        self._findings_refresh()

    def _findings_refresh(self) -> None:
        for w in self._findings_rows:
            w.destroy()
        self._findings_rows = []
        rows = opsmenu.findings_index(opsmenu.HUNT_DIR)
        # The header's score line — real numbers from the rows, never invented.
        passed = sum(1 for r in rows if r.get("badge") == "POC-DEMONSTRATED")
        submittable = sum(1 for r in rows
                         if r.get("badge") in ("POC-DEMONSTRATED", "SUBMITTABLE"))
        firm = sum(1 for r in rows if r.get("badge") == "FIRM")
        unproven = sum(1 for r in rows
                       if r.get("badge") in ("UNPROVEN", "CHECK-DEFECT", "UNVERIFIED"))
        self.findings_summary.configure(
            text=f"{passed} PoC demonstrated · {submittable} submittable · "
                 f"{firm} firm (not confirmed) · {unproven} unproven/unverified")
        if not rows:
            empty = ctk.CTkLabel(self.findings_list,
                                 text="no findings in the ledger yet — the hunt writes "
                                      "findings.jsonl as it tests; replay-passed ones are "
                                      "forgeable, and only a demonstrated PoC is submittable",
                                 font=_mono(10), text_color=TK["dim"], justify="left")
            empty.pack(anchor="w", padx=12, pady=14)
            self._findings_rows.append(empty)
            return
        for row in rows:
            self._findings_row(row)

    def _findings_row(self, row: dict) -> None:
        frame = ctk.CTkFrame(self.findings_list, fg_color=TK["panel2"], corner_radius=6)
        frame.pack(fill="x", padx=4, pady=3)
        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.pack(fill="x", padx=6, pady=(6, 0))
        sev = (row.get("sev") or "info").upper()
        ctk.CTkLabel(top, text=sev, font=_mono(8, "bold"), width=48, anchor="w",
                     text_color=TK[SEV_TONE.get(sev, "dim")]).pack(side="left")
        badge = row.get("badge") or "UNVERIFIED"
        # A DEMONSTRATED finding wears it plainly: "POC PASS ✓" in the proof tone —
        # the strongest emphasis the palette has (these rows also pin to the top).
        # Everything below it says what it is: SUBMITTABLE ✓ for the report gate's own ready
        # over a live re-probe, and FIRM (NOT CONFIRMED) for an offline replay — never VERIFIED.
        badge_text = ("POC PASS ✓" if badge == "POC-DEMONSTRATED"
                      else "SUBMITTABLE ✓" if badge == "SUBMITTABLE"
                      else "FIRM (NOT CONFIRMED)" if badge == "FIRM" else badge)
        ctk.CTkLabel(top, text=badge_text, font=_mono(8, "bold"), width=118, anchor="w",
                     text_color=TK[VERDICT_TONE.get(badge, "dim")]).pack(side="left", padx=4)
        title = f"{row.get('opp') or '?'} — {(row.get('finding') or '')}"
        ctk.CTkLabel(top, text=title[:110], font=_mono(9), text_color=TK["text"],
                     anchor="w", justify="left", wraplength=620).pack(
                     side="left", fill="x", expand=True, padx=4)
        bot = ctk.CTkFrame(frame, fg_color="transparent")
        bot.pack(fill="x", padx=6, pady=(2, 6))
        forging = self._poc_busy and self._poc_target == row.get("evidence_dir")
        vstate = "disabled" if (self._poc_busy or not row.get("forgeable")) else "normal"
        ctk.CTkButton(bot, text="FORGING…" if forging else "VERIFY", width=92, height=24,
                      font=("Segoe UI", 9, "bold"), fg_color=TK["cyan_dim"],
                      hover_color=TK["cyan"], text_color="#04110e", corner_radius=6,
                      state=vstate, text_color_disabled=TK["dim"],
                      command=lambda r=row: self._verify_run(r)).pack(side="left", padx=2)
        ctk.CTkButton(bot, text="REPORT", width=92, height=24, font=("Segoe UI", 9),
                      fg_color=TK["panel"], hover_color=TK["border"], text_color=TK["blue"],
                      corner_radius=6, state="normal" if row.get("reportable") else "disabled",
                      text_color_disabled=TK["dim"],
                      command=lambda r=row: self._report_open(r)).pack(side="left", padx=2)
        reasons = []
        if not row.get("forgeable"):
            reasons.append("VERIFY off: " + (row.get("forge_reason") or "not forgeable"))
        if not row.get("reportable"):
            reasons.append("REPORT off: " + (row.get("report_reason") or "no draft"))
        if reasons:
            ctk.CTkLabel(bot, text="  ·  ".join(reasons), font=_mono(8),
                         text_color=TK["dim"], anchor="w", justify="left",
                         wraplength=640).pack(side="left", padx=8)
        self._findings_rows.append(frame)

    def _verify_run(self, row: dict) -> None:
        """FINDINGS VERIFY button — same pause→forge→resume contract as the
        OPS BUILD PoC picker (both ride the shared _forge_begin)."""
        if not row.get("forgeable"):
            self._stream_line("warn", "VERIFY off: " + (row.get("forge_reason") or "not forgeable"))
            return
        self._forge_begin(row["evidence_dir"],
                          f"VERIFY: {row.get('opp')} — {(row.get('finding') or '')[:64]}")

    def _report_open(self, row: dict) -> None:
        path = row.get("draft_path")
        if not path:
            self._stream_line("warn", "REPORT off: " + (row.get("report_reason") or "no draft"))
            return
        try:
            os.startfile(path)
        except Exception as exc:
            self._stream_line("error", f"could not open {path}: {exc}")

    # ==========================================================================
    # CHAT tab
    # ==========================================================================
    def _build_chat_tab(self, tab) -> None:
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(tab, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=2, pady=2)
        self.thinking_sw = ctk.CTkSwitch(
            top, text="thinking", font=("Segoe UI", 10), text_color=TK["text"],
            progress_color=TK["cyan_dim"], button_color=TK["cyan"],
            command=self._chat_toggle)
        self.thinking_sw.select()
        self.thinking_sw.pack(side="left", padx=6)
        ctk.CTkLabel(top, text="effort", font=("Segoe UI", 9),
                     text_color=TK["dim"]).pack(side="left", padx=(14, 2))
        self.effort_seg = ctk.CTkSegmentedButton(
            top, values=list(config.EFFORT_MODES),
            font=("Segoe UI", 9), command=self._chat_effort,
            selected_color=TK["cyan_dim"], selected_hover_color=TK["cyan_dim"],
            unselected_color=TK["panel2"], unselected_hover_color=TK["border"])
        self.effort_seg.set(self._chat.effort)
        self.effort_seg.pack(side="left")

        self.chat_log = tk.Text(tab, bg="#0c1119", fg=TK["text"], bd=0,
                                font=_mono(10), state="disabled", wrap="word",
                                insertbackground=TK["cyan"],
                                selectbackground=TK["cyan_dim"])
        self.chat_log.grid(row=1, column=0, sticky="nsew", padx=2, pady=2)
        self.chat_log.tag_config("you", foreground=TK["cyan"])
        self.chat_log.tag_config("reason", foreground=TK["dim"])
        self.chat_log.tag_config("err", foreground=TK["red"])
        self.chat_log.tag_config("note", foreground=TK["purple"])
        self._chat_print("note", "console chat on the lane model — thinking on, "
                                 "effort standard. During HUNT ACTIVE this tab is "
                                 "sealed (profit-first).\n")

        self.chat_input_row = ctk.CTkFrame(tab, fg_color="transparent")
        self.chat_input_row.grid(row=2, column=0, sticky="ew", padx=2, pady=(2, 4))
        self.chat_input_row.grid_columnconfigure(0, weight=1)
        self.chat_entry = ctk.CTkEntry(
            self.chat_input_row, font=_mono(10), fg_color=TK["panel2"],
            border_color=TK["border"], text_color=TK["text"],
            placeholder_text="message the lane model…", height=36)
        self.chat_entry.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.chat_entry.bind("<Return>", lambda _e: self._chat_send())
        self.chat_send_btn = ctk.CTkButton(
            self.chat_input_row, text="SEND", width=90, height=36,
            font=("Segoe UI", 10, "bold"), fg_color=TK["cyan_dim"],
            hover_color=TK["cyan"], text_color="#04110e", corner_radius=8,
            command=self._chat_send)
        self.chat_send_btn.grid(row=0, column=1)

        self.chat_seal = ctk.CTkLabel(
            tab, text="⚡ HUNT ACTIVE — ALL MODEL CAPACITY TO THE HUNT\n"
                      "the chat tab is sealed until the hunt STOPs (profit-first)",
            font=("Segoe UI", 10, "bold"), fg_color="#3d2e00",
            text_color=TK["amber"], corner_radius=8, pady=14)

    # ==========================================================================
    # SPARK tab (the original menu features)
    # ==========================================================================
    def _build_spark_tab(self, tab) -> None:
        tab.grid_columnconfigure(0, weight=1)
        box = ctk.CTkFrame(tab, fg_color=TK["panel"], corner_radius=10,
                           border_color=TK["border"], border_width=1)
        box.pack(fill="x", padx=6, pady=6)
        ctk.CTkLabel(box, text=caps("working folder (the REPL's cwd)"),
                     font=("Segoe UI", 8, "bold"), text_color=TK["dim"]).pack(
                     anchor="w", padx=10, pady=(8, 2))
        row = ctk.CTkFrame(box, fg_color="transparent")
        row.pack(fill="x", padx=8, pady=(0, 8))
        self.folder = ctk.CTkEntry(row, font=_mono(10), fg_color=TK["panel2"],
                                   border_color=TK["border"], text_color=TK["text"])
        self.folder.pack(side="left", fill="x", expand=True, padx=(0, 6))
        ctk.CTkButton(row, text="Browse…", width=80, fg_color=TK["panel2"],
                      hover_color=TK["border"], text_color=TK["text"],
                      command=self._browse).pack(side="left")
        self.resume = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(row, text="resume last session", variable=self.resume,
                        font=("Segoe UI", 9), text_color=TK["text"],
                        fg_color=TK["cyan_dim"], hover_color=TK["cyan_dim"]).pack(
                        side="left", padx=8)
        self.launch_btn = ctk.CTkButton(
            box, text="▶  Launch spark-code", font=("Segoe UI", 11, "bold"),
            fg_color=TK["cyan_dim"], hover_color=TK["cyan"], text_color="#04110e",
            command=self._launch)
        self.launch_btn.pack(pady=(0, 10))

        lane = ctk.CTkFrame(tab, fg_color=TK["panel"], corner_radius=10,
                            border_color=TK["border"], border_width=1)
        lane.pack(fill="x", padx=6, pady=6)
        ctk.CTkLabel(lane, text=caps("spark agent lane (gx10-d094 :8080)"),
                     font=("Segoe UI", 8, "bold"), text_color=TK["dim"]).pack(
                     anchor="w", padx=10, pady=(8, 2))
        lrow = ctk.CTkFrame(lane, fg_color="transparent")
        lrow.pack(fill="x", padx=8, pady=(0, 8))
        self.lane_dot = ctk.CTkLabel(lrow, text="●", font=("Segoe UI", 14),
                                     text_color=TK["dim"])
        self.lane_dot.pack(side="left")
        self.lane_state = ctk.CTkLabel(lrow, text="not checked yet", font=_mono(10),
                                       text_color=TK["text"])
        self.lane_state.pack(side="left", padx=8)
        for label, cmd in (("Connect", self._connect), ("Disconnect", self._disconnect),
                           ("Re-check", self._check)):
            ctk.CTkButton(lrow, text=label, width=88, height=26, font=("Segoe UI", 9),
                          fg_color=TK["panel2"], hover_color=TK["border"],
                          text_color=TK["text"], command=cmd).pack(side="left", padx=3)

        mbox = ctk.CTkFrame(tab, fg_color=TK["panel"], corner_radius=10,
                            border_color=TK["border"], border_width=1)
        mbox.pack(fill="both", expand=True, padx=6, pady=6)
        ctk.CTkLabel(mbox, text=caps("model on the lane"),
                     font=("Segoe UI", 8, "bold"), text_color=TK["dim"]).pack(
                     anchor="w", padx=10, pady=(8, 2))
        self.model_now = ctk.CTkLabel(mbox, text="loaded: ?", font=_mono(10),
                                      text_color=TK["text"])
        self.model_now.pack(anchor="w", padx=10)
        self.model_list = tk.Listbox(mbox, height=7, exportselection=False,
                                     bg="#0c1119", fg=TK["text"], bd=0,
                                     highlightthickness=0,
                                     font=_mono(9), selectbackground=TK["cyan_dim"],
                                     activestyle="none")
        self.model_list.pack(fill="both", expand=True, padx=10, pady=6)
        mrow = ctk.CTkFrame(mbox, fg_color="transparent")
        mrow.pack(fill="x", padx=8, pady=(0, 8))
        ctk.CTkButton(mrow, text="Refresh list", height=26, font=("Segoe UI", 9),
                      fg_color=TK["panel2"], hover_color=TK["border"],
                      text_color=TK["text"], command=self._refresh_models).pack(side="left", padx=3)
        self.load_btn = ctk.CTkButton(mrow, text="Load selected", height=26,
                                      font=("Segoe UI", 9), fg_color=TK["panel2"],
                                      hover_color=TK["border"], text_color=TK["text"],
                                      command=self._load_selected)
        self.load_btn.pack(side="left", padx=3)
        self.restore_btn = ctk.CTkButton(mrow, text="Restore stock lane", height=26,
                                         font=("Segoe UI", 9), fg_color=TK["panel2"],
                                         hover_color=TK["border"], text_color=TK["text"],
                                         command=self._restore_stock)
        self.restore_btn.pack(side="left", padx=3)

    # ==========================================================================
    # queue drain + ops tick
    # ==========================================================================
    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self._q.get_nowait()
                if kind == "app":
                    self._stream_line("app", payload)
                elif kind == "lane":
                    ok, detail, model = payload
                    self.lane_dot.configure(text_color=TK["cyan"] if ok else TK["red"])
                    self.lane_state.configure(text=("up: " if ok else "down: ") + detail)
                    self.model_now.configure(text="loaded: " + (model or "?"))
                    if model:
                        self.stat_model.configure(text=model[:34])
                elif kind == "models":
                    ok, names, raw = payload
                    self.model_list.delete(0, "end")
                    for n in names:
                        self.model_list.insert("end", n)
                    if not ok:
                        self._stream_line("error", "model list failed: " + raw)
                elif kind == "ops-state":
                    pipeline, lane, brain, tunnel = payload
                    self._pipeline = pipeline
                    self._render_state(pipeline, lane, brain, tunnel)
                elif kind == "ghost":
                    self._ghost = payload
                    self._render_ghost()
                elif kind == "docker":
                    self._set_card("docker", payload[0], payload[1])
                elif kind == "ghost-drop":
                    self._stream_line("error", payload)
                    self.banner.configure(text="⛨ GHOST DROPPED — HUNT PAUSED\n" + payload[:220])
                    if not self.banner.winfo_manager():
                        self.banner.pack(fill="x", padx=4, pady=4,
                                         before=self.start_btn)
                elif kind == "ops-hunt":
                    ok, msg = payload
                    self._stream_line("done" if ok else "failed", ("✔ " if ok else "✖ ") + msg)
                    self._state_refresh()
                elif kind == "poc-done":
                    self._poc_finish(*payload)
                elif kind == "poc-row-done":
                    # a batch forge landed a verdict — badges may have changed
                    self._findings_refresh()
                elif kind == "batch-done":
                    self._forge_all_finish(payload)
                elif kind == "chat-delta":
                    self._chat_append(payload)
                elif kind == "chat-reason":
                    self._chat_append(payload, tag="reason")
                elif kind == "chat-done":
                    self._chat_finish(*payload)
        except queue.Empty:
            pass
        self.after(_POLL_MS, self._drain)

    def _ops_tick(self) -> None:
        self._ops_ticks += 1
        b = opsmenu.board(opsmenu.read_events(opsmenu.HUNT_DIR))
        self._render_board(b)
        self._render_stream(opsmenu.read_events(opsmenu.HUNT_DIR)[-220:])
        if self._ops_ticks % 10 == 1:
            self._state_refresh()
        # mid-hunt ghost watch: every ~2 min while running
        if (self._pipeline[0] == "running"
                and self._ops_ticks % _GHOST_RECHECK_TICKS == 30):
            def watch():
                state, detail = opsmenu.ghost_watch_tick(opsmenu.HUNT_DIR)
                if state == "dropped":
                    self._q.put(("ghost-drop", detail))
                    self._q.put(("ghost", opsmenu.ghost_preflight()))
                elif state == "degraded":
                    self._q.put(("app", "⛨ " + detail[:200]))
            threading.Thread(target=watch, daemon=True).start()
        self.after(_OPS_TICK_MS, self._ops_tick)

    def _state_refresh(self) -> None:
        def work():
            pipeline = opsmenu.pipeline_status(opsmenu.HUNT_DIR)
            lane = opsmenu.lane_status()
            brain = opsmenu.brain_status()
            tunnel = health()
            model = current_model() if tunnel[0] else None
            self._q.put(("ops-state", (pipeline, lane, brain, tunnel)))
            self._q.put(("lane", (tunnel[0], tunnel[1], model)))
            self._q.put(("docker", opsmenu.docker_status()))
        threading.Thread(target=work, daemon=True).start()

    # ==========================================================================
    # rendering
    # ==========================================================================
    def _render_state(self, pipeline, lane, brain, tunnel) -> None:
        self._set_card("tunnel", "up" if tunnel[0] else "down",
                       f"127.0.0.1:8080 {tunnel[1]}")
        self._set_card("lane", lane[0], lane[1])
        self._set_card("brain", brain[0], brain[1])
        self._set_card("pipeline", pipeline[0], pipeline[1])
        running = pipeline[0] == "running"
        paused = pipeline[0] == "paused"
        if running or paused:
            self.banner.configure(
                text=("⚡ HUNT ACTIVE — ALL MODEL CAPACITY TO THE HUNT\n"
                      "chat + quick-launch paused until STOP") if running else
                ("⏸ HUNT PAUSED — model capacity is FREE\nRESUME returns it to the hunt"))
            if not self.banner.winfo_manager():
                self.banner.pack(fill="x", padx=4, pady=4, before=self.start_btn)
        else:
            self.banner.pack_forget()
        # profit-first: the chat tab seals; spark quick-launch greys out
        if running:
            self.chat_input_row.grid_remove()
            self.chat_seal.grid(row=2, column=0, sticky="ew", padx=2, pady=(2, 4))
        else:
            self.chat_seal.grid_remove()
            self.chat_input_row.grid(row=2, column=0, sticky="ew", padx=2, pady=(2, 4))
        for btn in (self.launch_btn, self.load_btn, self.restore_btn):
            btn.configure(state="disabled" if running else "normal")
        # the hunt controls wear the pipeline state on their face
        if running or paused:
            self.start_btn.configure(state="disabled", fg_color=TK["border"],
                                     text_color=TK["dim"])
            self.stop_btn.configure(state="normal")
            self.pause_btn.configure(state="normal")
        else:
            self.start_btn.configure(state="normal", fg_color=TK["cyan_dim"],
                                     text_color="#04110e")
            self.stop_btn.configure(state="disabled", text_color_disabled=TK["dim"])
            self.pause_btn.configure(state="disabled", text_color_disabled=TK["dim"])
        # stats bar lane activity
        activity = opsmenu.lane_activity(pipeline[0], lane[0])
        self.stat_lane.configure(text=activity,
                                 text_color=TK[{"hunt": "cyan", "paused": "amber",
                                                "training": "amber", "idle": "dim",
                                                "down": "red"}.get(activity, "dim")])

    def _set_card(self, key, state, detail) -> None:
        status, det = self.cards[key]
        tone = STATE_TONE.get(state, "dim")
        status.configure(text=state.upper(), text_color=TK[tone])
        det.configure(text=(detail or "")[:140])

    def _render_ghost(self) -> None:
        g = self._ghost
        if g.get("ok"):
            detail = (g.get("checks", {}).get("exit", {}).get("detail")
                      or "verified live")
            self._set_card("ghost", "up", detail)
        else:
            checks = g.get("checks") or {}
            failed = next((f"{k}: {v.get('detail')}" for k, v in checks.items()
                           if not v.get("ok")), "not verified")
            self._set_card("ghost", "unknown" if not checks else "down", failed[:140])

    def _render_board(self, b: dict) -> None:
        sig = repr(([(s["state"], s["at"], s["msg"]) for s in b["stages"].values()],
                    b["counters"], b["clean"], b["vm"]))
        if sig == self._board_sig:
            return
        self._board_sig = sig
        for name, (pill, msg, at) in self.stage_cards.items():
            s = b["stages"].get(name, {"state": "idle", "at": None, "msg": ""})
            tone = STATE_TONE.get(s["state"], "dim")
            pill.configure(text=s["state"], text_color=TK[tone],
                           fg_color=TK["panel"] if s["state"] == "idle" else TK["border"])
            text, when = s["msg"] or "", s["at"]
            if s["state"] == "idle" and not text:
                # an idle card still says something TRUE: this stage's last real
                # result, or that it never ran — never a blank shrug
                last = (b.get("last_run") or {}).get(name)
                if last:
                    text, when = "last: " + (last["msg"] or last["state"]), last["at"]
                else:
                    text = "no work reached this stage yet"
            msg.configure(text=text[:120])
            at.configure(text=(when or "—")[11:19] or "—")
        c = b["counters"]
        self.cnt_submittable.configure(text=str(c.get("submittable", 0)))
        self.cnt_firm.configure(text=str(c.get("firm", 0)))
        self.cnt_unverified.configure(text=str(c.get("unverified", 0)))
        self.cnt_drafted.configure(text=str(c.get("drafted", 0)))
        self.chip_seen.configure(text=f"seen {c.get('seen', 0)} · tested {c.get('tested', 0)}")
        if b["clean"] is True:
            self.chip_clean.configure(text="clean ✓ (verified)", text_color=TK["cyan"])
        elif b["clean"] is False:
            self.chip_clean.configure(text="RESIDUE ✗ (named)", text_color=TK["red"])
        else:
            self.chip_clean.configure(text="clean: —", text_color=TK["dim"])
        vm = b.get("vm") or {}
        vm_txt = "VM " + (vm.get("provider") or "idle") + (" · ACTIVE" if vm.get("state") == "active" else "")
        if b.get("brain") == "waiting":
            vm_txt += " · brain waits (lane down)"
        self.chip_vm.configure(text=vm_txt[:52])
        # While the hunt runs, the loop's OWN ghost verdict owns the card —
        # "chain in use by loop" is emitted after the loop's verified dial.
        gl = b.get("ghost")
        if gl and gl.get("state") and self._pipeline[0] in ("running", "paused"):
            if gl["state"] == "in-use":
                self._set_card("ghost", "up",
                               f"chain in use by loop: {gl.get('chain') or '?'} (loop-verified dial, fail-closed)")
            elif gl["state"] == "down":
                self._set_card("ghost", "down", (gl.get("msg") or "ghost chain down — the loop refused")[:140])
            elif gl["state"] == "off":
                self._set_card("ghost", "waiting", "loop reports NO chain — direct egress (gate blocks real hunts)")

    def _fmt_event(self, ev: dict):
        ts = (ev.get("ts") or "")[11:19]
        kind = ev.get("type")
        if kind == "stage":
            return ev.get("state", "dim"), f"{ts} {ev.get('stage', ''):<16} {ev.get('state', ''):<8} {(ev.get('msg') or '')[:96]}"
        if kind == "loop":
            return "active" if ev.get("state") in ("started", "resumed") else "warn" if ev.get("state") in ("paused", "stopping") else "dim", \
                f"{ts} loop {ev.get('state', ''):<10} {(ev.get('msg') or '')[:96]}"
        if kind == "error":
            return "error", f"{ts} ERROR {(ev.get('msg') or '')[:110]}"
        if kind == "proof":
            v = ev.get("verdict") or ("verified" if ev.get("verified") else "unproven")
            label = {"verified": "VERIFIED", "poc-verified": "POC-VERIFIED",
                     "poc-unproven": "POC-UNPROVEN", "check-defect": "CHECK-DEFECT",
                     "unproven": "UNPROVEN", "skipped": "SKIPPED"}.get(v, v.upper())
            tag = "proof" if v in ("verified", "poc-verified") else "failed" if v == "check-defect" else "warn"
            return tag, f"{ts} PROOF {ev.get('finding', '')[:40]} {label} [{ev.get('recorder', '')}]"
        if kind == "poc-forge":
            st = ev.get("state", "")
            tag = ("proof" if st in ("marker", "draft-upgraded")
                   else "failed" if st in ("scope-refused", "policy-rejected", "transport-error")
                   else "warn" if st in ("contract-rejected", "give-up", "brain-error")
                   else "active")
            return tag, f"{ts} forge {st:<18} {(ev.get('msg') or '')[:88]}"
        if kind == "cleanup":
            return "done" if ev.get("state") == "verified-clean" else "failed", \
                f"{ts} cleanup {ev.get('state', ''):<14} {(ev.get('detail') or '')[:88]}"
        if kind in ("vm", "recorder", "brain", "opportunity"):
            label = kind if kind != "opportunity" else f"opp {ev.get('state', '')}"
            extra = ev.get("msg") or ev.get("note") or ev.get("opp") or ""
            return "dim", f"{ts} {label:<10} {str(extra)[:100]}"
        if kind == "gather":
            st = ev.get("state", "")
            tag = "active" if st in ("active", "asset") else "failed" if st == "failed" else "done" if st == "done" else "warn"
            return tag, f"{ts} gather {st:<9} {(ev.get('asset') or ''):<24} {(ev.get('msg') or '')[:80]}"
        if kind == "heartbeat":
            return "active", f"{ts} ♥ {(ev.get('msg') or '')[:106]}"
        if kind == "cycle":
            return "proof", f"{ts} ■ {(ev.get('msg') or '')[:106]}"
        if kind == "watchdog":
            return "dim", f"{ts} ⏱ {(ev.get('msg') or '')[:106]}"
        return None

    def _render_stream(self, events) -> None:
        # Append-stable: the file projection PLUS the console's own transient
        # lines (opsmenu.build_stream owns the merge — the vanishing-lines bug
        # was rebuilding from the file alone).
        lines = opsmenu.build_stream(events, self._transients, self._fmt_event)
        sig = (len(lines), lines[-1] if lines else None)
        if sig == self._stream_sig:
            return
        self._stream_sig = sig
        self.stream.configure(state="normal")
        self.stream.delete("1.0", "end")
        for tag, text in lines:
            self.stream.insert("end", text + "\n", tag)
        self.stream.see("end")
        self.stream.configure(state="disabled")

    def _stream_line(self, tag: str, text: str) -> None:
        # Post a transient console line: instant paint AND durable — it joins
        # self._transients, so the next tick's re-render keeps it.
        tag = tag if tag in ("active", "done", "failed", "error", "warn", "dim", "proof", "app") else "dim"
        self._transients.append((tag, text.rstrip()))
        if len(self._transients) > opsmenu.TRANSIENT_CAP:
            del self._transients[:len(self._transients) - opsmenu.TRANSIENT_CAP]
        self.stream.configure(state="normal")
        self.stream.insert("end", text.rstrip() + "\n", tag)
        self.stream.see("end")
        self.stream.configure(state="disabled")
        self._stream_sig = None  # force the next tick to reconcile (merged)

    # ==========================================================================
    # hunt control
    # ==========================================================================
    def _ghost_verify(self, background: bool) -> None:
        def work():
            self._set_card_safe("ghost", "waiting", "verifying chain (dial · exit · dns)…")
            r = opsmenu.ghost_preflight()
            self._q.put(("ghost", r))
        if background:
            threading.Thread(target=work, daemon=True).start()
        else:
            work()

    def _set_card_safe(self, key, state, detail) -> None:
        self._q.put(("app", f"ghost: {state} — {detail}"))

    def _ops_start(self) -> None:
        def work():
            # THE GHOST GATE — the hunt never runs exposed.
            self._q.put(("app", "START HUNT: ghost pre-flight gate…"))
            r = opsmenu.ghost_preflight()
            self._q.put(("ghost", r))
            if not r.get("ok"):
                self._q.put(("failed", "✖ START REFUSED — ghost is not verified live:"))
                for line in r.get("remediation") or ["no remediation detail"]:
                    self._q.put(("error", "   ⛨ " + line))
                self._q.put(("app", "fix the chain, VERIFY GHOST, then START again"))
                return
            self._q.put(("app", f"ghost verified ({r.get('chain')}, {r.get('engagement')})"))
            self._q.put(("app", "START HUNT: tunnel + health check…"))
            try:
                status = self.tunnel.ensure()
                self._q.put(("app", "tunnel: " + status))
            except Exception as exc:
                self._q.put(("warn", f"tunnel/lane not answering ({type(exc).__name__}) — "
                                     "lane likely down / training; starting anyway (recon waits)"))
            ok, msg = opsmenu.start_hunt(opsmenu.HUNT_DIR)
            self._q.put(("ops-hunt", (ok, msg)))
        threading.Thread(target=work, daemon=True).start()

    def _ops_stop(self) -> None:
        def work():
            self._q.put(("app", "STOP HUNT: STOP file → grace → cmdline-checked kill…"))
            ok, msg = opsmenu.stop_hunt(opsmenu.HUNT_DIR)
            self._q.put(("ops-hunt", (ok, msg)))
        threading.Thread(target=work, daemon=True).start()

    def _ops_pause_resume(self) -> None:
        def work():
            state, _ = opsmenu.pipeline_status(opsmenu.HUNT_DIR)
            if state == "running":
                ok, msg = opsmenu.pause_hunt(opsmenu.HUNT_DIR)
            elif state == "paused":
                ok, msg = opsmenu.resume_hunt(opsmenu.HUNT_DIR)
            else:
                ok, msg = False, f"the hunt is {state} — nothing to pause/resume"
            self._q.put(("ops-hunt", (ok, msg)))
        threading.Thread(target=work, daemon=True).start()

    def _open(self, target: str) -> None:
        base = opsmenu.HUNT_DIR
        path = {"evidence": base / "evidence", "outbox": base / "outbox",
                "findings": base / "findings.jsonl"}[target]
        if not path.exists():
            self._stream_line("warn", f"nothing yet at {path} — the hunt writes it when it happens")
            return
        try:
            os.startfile(str(path))
        except Exception as exc:
            self._stream_line("error", f"could not open {path}: {exc}")

    # ==========================================================================
    # The PoC-forge, on the operator's click — ONE contract for BOTH entry points
    # (the OPS BUILD PoC picker and the FINDINGS VERIFY button):
    #   pause the hunt (capacity to the finding) → forge → auto-resume
    # The pause/resume contract itself lives in opsmenu.verify_finding (never
    # resumes an operator's pause, resumes after success AND error); the shared
    # _forge_begin owns the one-at-a-time busy guard + the streaming path, so
    # the two buttons can never double-pause or fight — the guard is
    # structural, not a convention each call site must remember.
    # ==========================================================================
    def _poc_pick(self) -> None:
        """Offer the replay-VERIFIED findings with an evidence bundle; one
        forge at a time (the lane is shared with the hunt)."""
        if self._poc_busy:
            self._stream_line("warn", "a PoC forge is already running — one at a time (the lane is shared with the hunt)")
            return
        cands = opsmenu.poc_candidates(opsmenu.HUNT_DIR)
        if not cands:
            self._stream_line("warn", "no replay-VERIFIED findings with an evidence bundle yet — the forge only takes verified findings")
            return
        dlg = ctk.CTkToplevel(self)
        dlg.title("BUILD PoC — pick a verified finding")
        dlg.configure(fg_color=TK["bg"])
        dlg.geometry("820x460")
        dlg.transient(self)
        ctk.CTkLabel(dlg, text=caps("verified findings — the forge demonstrates REAL exploitability (read-only)"),
                     font=("Segoe UI", 10, "bold"), text_color=TK["dim"]).pack(
                     anchor="w", padx=12, pady=(10, 4))
        scroll = ctk.CTkScrollableFrame(dlg, fg_color=TK["panel"],
                                        scrollbar_button_color=TK["border"])
        scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        for cand in cands:
            row = ctk.CTkFrame(scroll, fg_color=TK["panel2"], corner_radius=6)
            row.pack(fill="x", padx=4, pady=3)
            state = cand.get("poc") or "not forged yet"
            when = f" · {cand['pocAt'][11:19]}" if cand.get("pocAt") else ""
            text = f"{cand.get('opp') or '?'} — {(cand.get('finding') or '')[:78]}\n{state}{when}"
            ctk.CTkLabel(row, text=text, font=_mono(9), text_color=TK["text"],
                         anchor="w", justify="left", wraplength=620).pack(
                         side="left", fill="x", expand=True, padx=8, pady=6)
            btn = ctk.CTkButton(row, text="FORGE", width=70, height=26,
                                font=("Segoe UI", 9, "bold"), fg_color=TK["cyan_dim"],
                                hover_color=TK["cyan"], text_color="#04110e",
                                corner_radius=6,
                                command=lambda c=cand: (dlg.destroy(), self._poc_run(c)))
            btn.pack(side="right", padx=8)

    def _forge_begin(self, target: str, label: str) -> bool:
        """The shared forge kickoff. Returns False (with an honest line) when
        a forge is already running — ONE at a time, the lane is shared."""
        if self._poc_busy:
            self._stream_line("warn", "a PoC forge is already running — one at a time (the lane is shared with the hunt)")
            return False
        self._poc_busy = True
        self._poc_target = target
        self.poc_btn.configure(state="disabled", text_color_disabled=TK["dim"])
        self._forge_all_btn_render()  # a single forge greys out FORGE ALL too
        self._findings_refresh()  # rows show FORGING… / all VERIFY disabled
        self._stream_line("app", label)

        def work():
            self._q.put(("app", "forge up — pause the hunt → forge → auto-resume; bounded: ≤3 brain attempts "
                                "(≤10 min each), stage watchdog 19 min, console bound 20 min; "
                                "READ-ONLY probes only, scope-guarded, ghost-routed"))
            ok, msg, result = opsmenu.verify_finding(
                target, note=lambda t: self._q.put(("app", t)))
            self._q.put(("poc-done", (ok, msg, result)))
        threading.Thread(target=work, daemon=True).start()
        return True

    def _poc_run(self, cand: dict) -> None:
        """OPS BUILD PoC picker — same pause→forge→resume contract as VERIFY."""
        self._forge_begin(cand["evidenceDir"],
                          f"BUILD PoC: forging {cand.get('opp')} — {(cand.get('finding') or '')[:64]}")

    def _poc_finish(self, ok: bool, msg: str, result: dict) -> None:
        self._poc_busy = False
        self._poc_target = None
        self.poc_btn.configure(state="normal")
        self._forge_all_btn_render()
        cls = (result or {}).get("verdictClass")
        tag = "proof" if cls == "poc-verified" else "warn" if cls == "poc-unproven" else "failed" if not ok or cls == "check-defect" else "app"
        self._stream_line(tag, ("✔ " if ok else "✖ ") + msg)
        self._findings_refresh()  # a forge verdict may have changed a row's badge/buttons

    # ==========================================================================
    # FORGE ALL — the batch rides the SAME one-at-a-time guard as a single
    # forge: _poc_busy is set for the batch's whole run, so VERIFY / BUILD PoC
    # grey out structurally (and opsmenu.forge_all holds FORGE_ALL_LOCK +
    # refuses if any forge is active — the property holds at both layers).
    # While the batch runs, its button is the honest cancel: STOP BATCH writes
    # FORGE_STOP, which lands BETWEEN runs, never mid-forge.
    # ==========================================================================
    def _forge_all_btn_render(self) -> None:
        """The button's face from the shared guard: idle → FORGE ALL; single
        forge busy → greyed; batch running → STOP BATCH (then STOPPING… once
        the cancel is requested — the current finding still finishes)."""
        if self._batch_running:
            if self._batch_stop:
                self.forge_all_btn.configure(state="disabled",
                                             text="⏹  STOPPING… (after current)")
            else:
                self.forge_all_btn.configure(state="normal", text="⏹  STOP BATCH")
        else:
            self.forge_all_btn.configure(
                state="disabled" if self._poc_busy else "normal",
                text="⚒  FORGE ALL")

    def _forge_all_click(self) -> None:
        """One button, two honest faces: start the batch, or stop it."""
        if self._batch_running:
            self._forge_all_stop()
        else:
            self._forge_all_begin()

    def _forge_all_begin(self) -> None:
        if self._poc_busy:
            self._stream_line("warn", "a PoC forge is already running — one at a time (the lane is shared with the hunt)")
            return
        self._poc_busy = True
        self._batch_running = True
        self._batch_stop = False
        self.poc_btn.configure(state="disabled", text_color_disabled=TK["dim"])
        self._forge_all_btn_render()
        self._findings_refresh()  # all VERIFY buttons grey out under the shared guard
        self._stream_line("app", "FORGE ALL: every forgeable finding, critical first — already-proven "
                                 "ones are skipped; pause once → forge each (serial) → resume once")

        def work():
            def note(t):
                self._q.put(("app", t))
                if t.startswith("→ "):
                    # a verdict line landed — refresh so the row's badge flips live
                    self._q.put(("poc-row-done", None))
            try:
                summary = opsmenu.forge_all(opsmenu.HUNT_DIR, note=note)
            except Exception as exc:
                summary = {"refused": f"the batch died mid-run: {type(exc).__name__}: {exc}"}
            self._q.put(("batch-done", summary))
        threading.Thread(target=work, daemon=True).start()

    def _forge_all_stop(self) -> None:
        """STOP BATCH: write FORGE_STOP — the batch finishes the current
        finding and then stops, honestly (never a mid-forge kill)."""
        if not self._batch_running:
            return
        try:
            (opsmenu.HUNT_DIR / opsmenu.FORGE_STOP_FILE).write_text(
                "stop requested by the operator — the batch finishes the current finding, honestly\n")
        except OSError as exc:
            self._stream_line("error", f"could not write FORGE_STOP: {exc}")
            return
        self._batch_stop = True
        self._forge_all_btn_render()
        self._stream_line("warn", "FORGE STOP requested — the batch stops after the current finding (never mid-forge)")

    def _forge_all_finish(self, summary: dict) -> None:
        self._poc_busy = False
        self._batch_running = False
        self._batch_stop = False
        self.poc_btn.configure(state="normal")
        self._forge_all_btn_render()
        refused = (summary or {}).get("refused")
        if refused:
            self._stream_line("warn", f"⚒  FORGE ALL refused: {refused}")
        # the batch's own progress lines + the final "FORGE ALL done: …" summary
        # (and the "hunt resumed" note, when we paused) already streamed via note
        self._findings_refresh()

    # ==========================================================================
    # chat tab
    # ==========================================================================
    def _chat_toggle(self) -> None:
        self._chat.thinking = bool(self.thinking_sw.get())

    def _chat_effort(self, value: str) -> None:
        self._chat.effort = value
        self.stat_effort.configure(text=value)

    def _chat_print(self, tag: str, text: str) -> None:
        self.chat_log.configure(state="normal")
        self.chat_log.insert("end", text, tag)
        self.chat_log.see("end")
        self.chat_log.configure(state="disabled")

    def _chat_append(self, delta: str, tag: str = None) -> None:
        self.chat_log.configure(state="normal")
        self.chat_log.insert("end", delta, tag or "")
        self.chat_log.see("end")
        self.chat_log.configure(state="disabled")

    def _chat_send(self) -> None:
        if self._chat_busy:
            return
        text = self.chat_entry.get().strip()
        if not text:
            return
        ok, reason = opsmenu.chat_gate(self._pipeline[0])
        if not ok:
            self._chat_print("err", "✖ " + reason + "\n")
            return
        self._chat_busy = True
        self.chat_entry.delete(0, "end")
        self.chat_send_btn.configure(state="disabled", text="…")
        self._chat_print("you", "you ▸ " + text + "\n")

        def work():
            def delta(d):
                self._q.put(("chat-delta", d))

            def reason_cb(d):
                self._q.put(("chat-reason", d))
            ok2, reply = opsmenu.chat_send(self._chat, self._chat_client, text,
                                           on_delta=delta, on_reasoning=reason_cb)
            self._q.put(("chat-done", (ok2, reply)))
        threading.Thread(target=work, daemon=True).start()

    def _chat_finish(self, ok: bool, reply: str) -> None:
        self._chat_busy = False
        self.chat_send_btn.configure(state="normal", text="SEND")
        if not ok:
            self._chat_print("err", "\n✖ " + reply + "\n")
        else:
            self._chat_append("\n\n")
        self.stat_toks.configure(
            text=(f"{self._chat.last_tok_s:.1f} tok/s" if self._chat.last_tok_s else "— tok/s"))
        self._ctx_refresh()

    def _ctx_refresh(self) -> None:
        used, limit, pct = self._chat.context_meter()
        self.ctx_bar.set(min(1.0, used / limit if limit else 0))
        self.ctx_label.configure(text=f"ctx {used:,} / {limit:,} ({pct}%)")

    # ==========================================================================
    # spark tab (ported features)
    # ==========================================================================
    def _browse(self) -> None:
        path = filedialog.askdirectory(parent=self, title="spark-code working folder")
        if path:
            self.folder.delete(0, "end")
            self.folder.insert(0, path)

    def _launch(self) -> None:
        cwd = self.folder.get().strip()
        if not cwd:
            self._stream_line("warn", "pick a working folder first")
            return
        ok, msg = spawn_repl(cwd, resume_last=self.resume.get())
        self._stream_line("done" if ok else "failed", ("▶ " if ok else "! ") + msg)

    def _connect(self) -> None:
        def work():
            self._q.put(("app", "connecting: ssh tunnel + health check…"))
            try:
                status = self.tunnel.ensure()
            except Exception as exc:
                self._q.put(("app", f"tunnel failed: {exc}"))
                self._q.put(("lane", (False, "tunnel failed", None)))
                return
            self._q.put(("app", "tunnel started by the menu" if status == "started"
                        else "lane was already reachable (tunnel not ours)"))
            self._state_refresh()
        threading.Thread(target=work, daemon=True).start()

    def _disconnect(self) -> None:
        self._stream_line("done" if self.tunnel.close() else "dim",
                          "tunnel we started: closed" if self.tunnel.started_by_us else
                          "no tunnel started by this menu — a pre-existing tunnel is left alone")
        self._state_refresh()

    def _check(self) -> None:
        self._state_refresh()

    def _refresh_models(self) -> None:
        def work():
            self._q.put(("models", lane_list()))
        threading.Thread(target=work, daemon=True).start()

    def _selected_model(self):
        sel = self.model_list.curselection()
        return self.model_list.get(sel[0]) if sel else None

    def _load_selected(self) -> None:
        name = self._selected_model()
        if not name:
            self._stream_line("warn", "select a model in the list first")
            return
        self._stream_line("app", f"loading {name} on the lane (health-verify + rollback can take a minute)…")
        self._lane_verb(["load", name])

    def _restore_stock(self) -> None:
        self._stream_line("app", "restoring the stock RVN + DFlash2 lane…")
        self._lane_verb(["restore-stock"])

    def _lane_verb(self, args) -> None:
        def work():
            ok, out = lane_ssh(args)
            self._q.put(("app", out or ("ok" if ok else "failed")))
            self._q.put(("app", "✔ lane reports healthy" if ok else
                         "✖ LANE ACTION FAILED — see above; the far side rolls back loud "
                         "and agent-lane.sh remains the fallback"))
            self._state_refresh()
        threading.Thread(target=work, daemon=True).start()

    def _quit(self) -> None:
        state, _ = opsmenu.pipeline_status(opsmenu.HUNT_DIR)
        if state in ("running", "paused"):
            ok, msg = opsmenu.stop_hunt(opsmenu.HUNT_DIR, grace_s=5.0)
        if self.tunnel.started_by_us:
            self.tunnel.close()
        self.destroy()


def main() -> None:
    app = MenuApp()
    app.mainloop()


if __name__ == "__main__":
    main()
