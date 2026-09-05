"""SSH tunnel lifecycle.

Spark Code never leaves residue: it spawns no permanent processes of its
own. If the agent lane doesn't answer on 127.0.0.1:8080 at startup, we
open the owner's standard SSH tunnel as a hidden, detached child process
(same command as heretic-code.bat), remember that WE started it, and on
exit offer to close it. Tunnels we did not start are left alone.

Closing the CLI (and the tunnel we opened) frees the llama.cpp server
slot the session was using; nothing persists on the Spark beyond the
shared llama-server itself.
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


class TunnelStartError(Exception):
    pass


def endpoint_up(base_url: str = config.BASE_URL, timeout: float = 3.0) -> bool:
    try:
        with urllib.request.urlopen(base_url.rstrip("/") + "/v1/models", timeout=timeout):
            return True
    except Exception:
        return False


class TunnelManager:
    def __init__(self) -> None:
        self.proc: Optional[subprocess.Popen] = None
        self.started_by_us = False

    def ensure(self, wait_s: float = 15.0) -> str:
        """Guarantee the endpoint answers. Returns 'already-up' or 'started'.

        Idempotent and safe to call repeatedly (e.g. before every turn): if we
        already own a live tunnel process we just wait for it rather than
        spawning a second SSH, so a WiFi flap / Spark sleep heals on the next
        prompt instead of failing the turn.
        """
        if endpoint_up():
            return "already-up"

        # Reuse our existing (still-alive) tunnel: only wait for it to answer,
        # don't open a duplicate SSH that would fight over :8080.
        if self.proc is not None and self.proc.poll() is None:
            deadline = time.time() + wait_s
            while time.time() < deadline:
                if endpoint_up(timeout=2.0):
                    return "already-up"
                time.sleep(1.0)
            raise TunnelStartError(
                "The SSH tunnel spark-code opened is alive but the model server\n"
                "is not answering - llama-server on the Spark may be down or busy\n"
                "(model swap / benchmark). Try again in a few minutes, and check\n"
                "that `ssh varvel@gx10-d094.local` works without a password."
            )

        self.proc = subprocess.Popen(
            config.SSH_ARGS,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=_CREATE_NO_WINDOW | _DETACHED | _NEW_GROUP,
        )
        self.started_by_us = True
        deadline = time.time() + wait_s
        while time.time() < deadline:
            if endpoint_up(timeout=2.0):
                return "started"
            if self.proc.poll() is not None:
                raise TunnelStartError(
                    "The SSH tunnel process exited immediately "
                    f"(code {self.proc.returncode}).\n" + config.TUNNEL_HELP
                )
            time.sleep(1.0)
        raise TunnelStartError(
            "Agent lane unreachable after 15s. The tunnel opened but the model\n"
            "server did not answer - llama-server on the Spark is likely down or\n"
            "busy (model swap / benchmark). Try again in a few minutes, and check\n"
            "that `ssh varvel@gx10-d094.local` works without a password."
        )

    def heal(self) -> bool:
        """Best-effort re-establishment used before each turn: if the lane is
        dark, try to bring it back (reusing or opening our tunnel). Never raises -
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
        """Terminate the tunnel only if THIS process started it."""
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
