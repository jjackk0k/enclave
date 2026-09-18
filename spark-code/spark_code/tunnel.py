"""SSH tunnel lifecycle — self-healing since 2026-09-12.

The lane (127.0.0.1:8080) is kept alive by the TUNNEL-KEEPER: a small
powershell loop (tunnel-keeper.ps1, next to this package) that probes the
lane every 20s and re-opens the owner's standard SSH tunnel whenever it is
down — through WiFi flaps, router reboots, and Spark naps. It is launched
hidden + detached by ensure() when it isn't already running, and it is
deliberately NOT ours to close: it belongs to the PC (the operator can also
pin it to Windows startup), so the lane heals without any app or session
staying open. A raw one-shot ssh used to die silently on the first flap —
that fragility is what this replaced.

close() only ever terminates a legacy tunnel child THIS process spawned
(`self.proc`); the keeper is never killed by the console.
"""

from __future__ import annotations

import subprocess
import sys
import time
import urllib.request
from typing import Optional

from . import config

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_DETACHED = getattr(subprocess, "DETACHED_PROCESS", 0)
_NEW_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

KEEPER_PS1 = config.ROOT / "tunnel-keeper.ps1"


class TunnelStartError(Exception):
    pass


def endpoint_up(base_url: str = config.BASE_URL, timeout: float = 3.0) -> bool:
    try:
        with urllib.request.urlopen(base_url.rstrip("/") + "/v1/models", timeout=timeout):
            return True
    except Exception:
        return False


def _keeper_running(runner=None) -> bool:
    """True when a tunnel-keeper.ps1 powershell is alive (cmdline-checked —
    a random powershell is never mistaken for it). Never raises: an
    unanswerable probe reads as 'not running' and the keeper simply gets
    spawned (idempotent on the keeper's side)."""
    if runner is None:
        from .menuops import run_hidden as runner
    try:
        r = runner(["powershell.exe", "-NoProfile", "-Command",
                    "(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'tunnel-keeper\\.ps1' } | Measure-Object).Count"],
                   timeout=15)
        out = (r.stdout or "").strip() if hasattr(r, "stdout") else str(r)
        return out.isdigit() and int(out) > 0
    except Exception:
        return False


class TunnelManager:
    def __init__(self) -> None:
        self.proc: Optional[subprocess.Popen] = None
        self.started_by_us = False

    def _ensure_keeper(self, popen=None) -> None:
        """Spawn the tunnel-keeper hidden + detached if it isn't running.
        Idempotent (the keeper itself also refuses to double-open the ssh)."""
        if _keeper_running():
            return
        if popen is None:
            from .menuops import popen_hidden as popen
        popen(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
               "-WindowStyle", "Hidden", "-File", str(KEEPER_PS1)],
              creationflags=_DETACHED | _NEW_GROUP)

    def ensure(self, wait_s: float = 15.0) -> str:
        """Guarantee the endpoint answers. Returns 'already-up' or 'started'.

        Idempotent and safe to call repeatedly (e.g. before every turn): the
        keeper is brought up first (it re-tries the ssh every 20s forever),
        then we wait up to wait_s for the lane. A Spark that is genuinely
        unreachable raises an HONEST error that says the keeper keeps
        retrying on its own — no click, no session, no residue required.
        """
        if endpoint_up():
            return "already-up"

        self._ensure_keeper()
        deadline = time.time() + wait_s
        while time.time() < deadline:
            if endpoint_up(timeout=2.0):
                return "started"
            time.sleep(1.0)
        raise TunnelStartError(
            "The tunnel-keeper is running and re-tries every 20s on its own —\n"
            "the Spark is unreachable right now (check it is powered and on the\n"
            "network). The lane heals BY ITSELF the moment the Spark answers;\n"
            "no click and no open app needed.\n" + config.TUNNEL_HELP
        )

    def heal(self) -> bool:
        """Best-effort re-establishment used before each turn: if the lane is
        dark, try to bring it back (the keeper does the real work). Never raises -
        returns True when the endpoint answers afterwards. A failed heal just means
        the next request will report the tunnel-down error honestly."""
        if endpoint_up():
            return True
        try:
            self.ensure()
            return True
        except Exception:
            return False

    def close(self) -> bool:
        """Terminate the tunnel only if THIS process spawned a legacy child.
        The keeper is NEVER closed — it belongs to the PC, not this app."""
        if self.proc is None:
            return False
        try:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
            return True
        finally:
            self.proc = None
            self.started_by_us = False
