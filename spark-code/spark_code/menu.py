"""The spark-code menu: a small clickable tkinter window (stdlib only).

- Folder field + Browse + Launch: opens the REPL in its own console with
  cwd = the chosen folder (optionally --resume-last).
- Connect/Disconnect: opens the owner's standard SSH tunnel (the same
  command spark-code.bat uses) and health-checks it, green/red.
- Models: lists the GGUFs on the Spark (via ~/engine-switch/lane-models.sh,
  additive - agent-lane.sh is never touched), shows which one is loaded,
  and can switch/restore with health-verify + loud rollback on the far side.

All blocking work runs on worker threads; results come back through a queue
polled by the tk mainloop, so the window never freezes. The logic lives in
menuops.py (unit-tested headless); this file is the thin UI. Run it with
`python -m spark_code.menu`, or the built spark-menu.exe.
"""

from __future__ import annotations

import queue
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog

from . import __version__
from .menuops import current_model, health, lane_list, lane_ssh, spawn_repl
from .tunnel import TunnelManager

_POLL_MS = 200


class MenuApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.tunnel = TunnelManager()
        self._q: "queue.Queue[tuple]" = queue.Queue()

        root.title(f"spark-code v{__version__}")
        root.minsize(560, 520)

        pad = {"padx": 10, "pady": 4}
        tk.Label(root, text="SPARK CODE", font=("Segoe UI", 16, "bold"),
                 fg="#c586c0").pack(**pad)

        # -- folder + launch -------------------------------------------------
        box = tk.LabelFrame(root, text="working folder (the REPL's cwd)")
        box.pack(fill="x", **pad)
        self.folder = tk.StringVar()
        tk.Entry(box, textvariable=self.folder).pack(side="left", fill="x",
                                                     expand=True, padx=6, pady=6)
        tk.Button(box, text="Browse…", command=self._browse).pack(side="left", padx=6)
        self.resume = tk.BooleanVar(value=False)
        tk.Checkbutton(box, text="resume last session",
                       variable=self.resume).pack(side="left", padx=6)
        tk.Button(root, text="▶ Launch spark-code",
                  command=self._launch).pack(**pad)

        # -- tunnel / lane status -------------------------------------------
        lane = tk.LabelFrame(root, text="Spark agent lane (gx10-d094 :8080)")
        lane.pack(fill="x", **pad)
        row = tk.Frame(lane)
        row.pack(fill="x", padx=6, pady=4)
        self.dot = tk.Label(row, text="●", font=("Segoe UI", 14), fg="gray")
        self.dot.pack(side="left")
        self.lane_state = tk.StringVar(value="not checked yet")
        tk.Label(row, textvariable=self.lane_state).pack(side="left", padx=8)
        tk.Button(row, text="Connect", command=self._connect).pack(side="left", padx=4)
        tk.Button(row, text="Disconnect", command=self._disconnect).pack(side="left")
        tk.Button(row, text="Re-check", command=self._check).pack(side="left", padx=4)

        # -- models -----------------------------------------------------------
        mbox = tk.LabelFrame(root, text="model on the lane")
        mbox.pack(fill="both", expand=True, **pad)
        self.model_now = tk.StringVar(value="loaded: ?")
        tk.Label(mbox, textvariable=self.model_now).pack(anchor="w", padx=6)
        self.model_list = tk.Listbox(mbox, height=6, exportselection=False)
        self.model_list.pack(fill="both", expand=True, padx=6, pady=4)
        mrow = tk.Frame(mbox)
        mrow.pack(fill="x", padx=6, pady=4)
        tk.Button(mrow, text="Refresh list", command=self._refresh_models).pack(side="left")
        tk.Button(mrow, text="Load selected",
                  command=self._load_selected).pack(side="left", padx=4)
        tk.Button(mrow, text="Restore stock lane",
                  command=self._restore_stock).pack(side="left")

        # -- log ---------------------------------------------------------------
        self.log = tk.Text(root, height=8, state="disabled", bg="#111",
                           fg="#ccc", font=("Consolas", 9))
        self.log.pack(fill="both", expand=True, **pad)

        self.root.protocol("WM_DELETE_WINDOW", self._quit)
        self._check()
        self._refresh_models()
        root.after(_POLL_MS, self._drain)

    # -- helpers ---------------------------------------------------------------
    def say(self, msg: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", msg.rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self._q.get_nowait()
                if kind == "log":
                    self.say(payload)
                elif kind == "lane":
                    ok, detail, model = payload
                    self.dot.configure(fg="#3f3" if ok else "#f44")
                    self.lane_state.set(("up: " if ok else "down: ") + detail)
                    self.model_now.set("loaded: " + (model or "?"))
                elif kind == "models":
                    ok, names, raw = payload
                    self.model_list.delete(0, "end")
                    for n in names:
                        self.model_list.insert("end", n)
                    if not ok:
                        self.say("! model list failed: " + raw)
        except queue.Empty:
            pass
        self.root.after(_POLL_MS, self._drain)

    # -- folder / launch ---------------------------------------------------------
    def _browse(self) -> None:
        path = filedialog.askdirectory(parent=self.root,
                                       title="spark-code working folder")
        if path:
            self.folder.set(path)

    def _launch(self) -> None:
        cwd = self.folder.get().strip()
        if not cwd:
            self.say("! pick a working folder first")
            return
        ok, msg = spawn_repl(cwd, resume_last=self.resume.get())
        self.say(("▶ " if ok else "! ") + msg)

    # -- tunnel -------------------------------------------------------------------
    def _connect(self) -> None:
        def work():
            self._q.put(("log", "connecting: ssh tunnel + health check…"))
            try:
                status = self.tunnel.ensure()
            except Exception as exc:
                self._q.put(("log", f"! tunnel failed: {exc}"))
                self._q.put(("lane", (False, "tunnel failed", None)))
                return
            note = "tunnel started by the menu" if status == "started" \
                else "lane was already reachable (tunnel not ours)"
            self._q.put(("log", note))
            self._check()
        threading.Thread(target=work, daemon=True).start()

    def _disconnect(self) -> None:
        if self.tunnel.close():
            self.say("tunnel we started: closed")
        else:
            self.say("no tunnel started by this menu - nothing closed "
                     "(a pre-existing tunnel is left alone)")
        self._check()

    def _check(self) -> None:
        def work():
            ok, detail = health()
            model = current_model() if ok else None
            self._q.put(("lane", (ok, detail, model)))
        threading.Thread(target=work, daemon=True).start()

    # -- models ---------------------------------------------------------------------
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
            self.say("! select a model in the list first")
            return
        self.say(f"loading {name} on the lane (health-verify + rollback can "
                 "take a minute)…")
        self._lane_verb(["load", name])

    def _restore_stock(self) -> None:
        self.say("restoring the stock RVN + DFlash2 lane…")
        self._lane_verb(["restore-stock"])

    def _lane_verb(self, args) -> None:
        def work():
            ok, out = lane_ssh(args)
            self._q.put(("log", out or ("ok" if ok else "failed")))
            self._q.put(("log", "✔ lane reports healthy" if ok else
                         "✖ LANE ACTION FAILED - see above; the far side rolls "
                         "back loud and agent-lane.sh remains the fallback"))
            self._check()
        threading.Thread(target=work, daemon=True).start()

    def _quit(self) -> None:
        if self.tunnel.started_by_us:
            self.tunnel.close()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    MenuApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
