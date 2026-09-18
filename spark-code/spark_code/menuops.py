"""Logic behind the clickable menu (menu.py), kept UI-free so tests can drive
it: tunnel connect/health, model management over ssh via the additive
~/engine-switch/lane-models.sh on the Spark, and the launch commands for the
REPL (from the menu) and the menu (from /menu in the REPL).
"""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional, Tuple

from . import config

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_DETACHED = getattr(subprocess, "DETACHED_PROCESS", 0)
_NEW_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
_NEW_CONSOLE = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)

# exes produced by scripts/build_exe.py land next to the package
REPL_EXE = config.ROOT / "spark-code.exe"    # console build of the agent
MENU_EXE = config.ROOT / "spark-menu.exe"    # windowed build of this menu

LANE_SCRIPT = "~/engine-switch/lane-models.sh"
SSH_BASE = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
            config.SSH_TARGET]


# --- windowless spawning (the console-window-flash fix) -------------------------
# Under a WINDOWED parent (pythonw / the frozen spark-menu.exe) every console
# child (ssh.exe, tasklist.exe, powershell.exe, taskkill.exe, node.exe) would
# otherwise allocate a brand-new visible console window on each spawn — that
# was the flash Jack saw every refresh tick. ONE helper owns the posture so no
# future poll loop can reintroduce it: CREATE_NO_WINDOW plus detached stdio,
# so nothing ever attaches to (or allocates) a console.
def _hidden_kwargs(kwargs: dict) -> dict:
    kw = dict(kwargs)
    kw["creationflags"] = kw.get("creationflags", 0) | _CREATE_NO_WINDOW
    return kw


def run_hidden(cmd, **kwargs):
    """subprocess.run, windowless. capture_output callers keep their pipes;
    anything else is silenced to DEVNULL so no console is inherited."""
    kw = _hidden_kwargs(kwargs)
    if not (kw.get("capture_output") or kw.get("stdout") is not None):
        kw["stdout"] = subprocess.DEVNULL
    if kw.get("stderr") is None and not kw.get("capture_output"):
        kw["stderr"] = subprocess.DEVNULL
    if kw.get("stdin") is None:
        kw["stdin"] = subprocess.DEVNULL
    return subprocess.run(cmd, **kw)


def popen_hidden(cmd, **kwargs):
    """subprocess.Popen, windowless (same doctrine; long-lived children too)."""
    kw = _hidden_kwargs(kwargs)
    if kw.get("stdin") is None:
        kw["stdin"] = subprocess.DEVNULL
    if kw.get("stdout") is None:
        kw["stdout"] = subprocess.DEVNULL
    if kw.get("stderr") is None:
        kw["stderr"] = subprocess.DEVNULL
    return subprocess.Popen(cmd, **kw)


def health(timeout: float = 3.0) -> Tuple[bool, str]:
    """GET the lane's /health through the local tunnel."""
    url = config.BASE_URL.rstrip("/") + "/health"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return True, f"healthy (HTTP {resp.status})"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except Exception as exc:
        return False, f"unreachable ({type(exc).__name__})"


def current_model(timeout: float = 3.0) -> Optional[str]:
    try:
        with urllib.request.urlopen(config.BASE_URL.rstrip("/") + "/v1/models",
                                    timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        ids = [m["id"] for m in data.get("data", [])]
        return ids[0] if ids else None
    except Exception:
        return None


def lane_ssh(args: List[str], timeout: float = 300.0) -> Tuple[bool, str]:
    """Run a lane-models.sh verb on the Spark. Returns (ok, combined output).
    Never raises; a dead ssh path is an honest (False, error). Windowless —
    this fires on the menu's refresh tick, and a console flash per tick was
    the reported bug."""
    cmd = SSH_BASE + [" ".join([LANE_SCRIPT] + args)]
    try:
        proc = run_hidden(cmd, capture_output=True, text=True,
                          errors="replace", timeout=timeout)
    except Exception as exc:
        return False, f"ssh failed: {type(exc).__name__}: {exc}"
    out = (proc.stdout + proc.stderr).strip()
    return proc.returncode == 0, out


def lane_list() -> Tuple[bool, List[str], str]:
    """GGUF filenames in ~/models on the Spark."""
    ok, out = lane_ssh(["list"], timeout=30)
    if not ok:
        return False, [], out
    return True, [l for l in out.splitlines() if l.endswith(".gguf")], out


def python_for_console() -> str:
    """The REPL needs a console python even when the menu runs under pythonw."""
    exe = sys.executable
    if exe.lower().endswith("pythonw.exe"):
        sibling = str(Path(exe).with_name("python.exe"))
        if Path(sibling).exists():
            return sibling
    return exe


def python_for_window() -> str:
    """The menu prefers pythonw (no console flash) when it exists."""
    exe = sys.executable
    if not exe.lower().endswith("pythonw.exe"):
        sibling = str(Path(exe).with_name("pythonw.exe"))
        if Path(sibling).exists():
            return sibling
    return exe


def launch_repl_cmd(resume_last: bool = False) -> List[str]:
    """The command the menu's Launch spawns for the REPL (cwd goes to Popen).
    The console exe build wins when present; otherwise the venv python."""
    if REPL_EXE.exists():
        cmd = [str(REPL_EXE)]
    else:
        cmd = [python_for_console(), "-m", "spark_code"]
    if resume_last:
        cmd.append("--resume-last")
    return cmd


def spawn_repl(cwd: str, resume_last: bool = False) -> Tuple[bool, str]:
    """Open the REPL in its own console window, working directory = cwd.
    Deliberately VISIBLE (CREATE_NEW_CONSOLE) — the REPL is a console app the
    user interacts with; this is the one spawn the flash fix must NOT hide."""
    try:
        subprocess.Popen(launch_repl_cmd(resume_last), cwd=cwd,
                         creationflags=_NEW_CONSOLE | _NEW_GROUP)
    except Exception as exc:
        return False, f"launch failed: {type(exc).__name__}: {exc}"
    return True, f"launched in {cwd}"


def spawn_menu_detached() -> Tuple[bool, str]:
    """/menu in the REPL: re-open the menu window. This process keeps
    running (the REPL then exits cleanly through its normal shutdown)."""
    if MENU_EXE.exists():
        cmd = [str(MENU_EXE)]
    else:
        cmd = [python_for_window(), "-m", "spark_code.menu"]
    try:
        popen_hidden(cmd, creationflags=_DETACHED | _NEW_GROUP)
    except Exception as exc:
        return False, f"could not open the menu: {type(exc).__name__}: {exc}"
    return True, "menu opened"
