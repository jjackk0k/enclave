"""VARVEL Ops Console logic (the 1-click hunt), kept UI-free so tests can
drive it: the state panel (tunnel / lane / brain / pipeline), START/STOP/PAUSE
for the hunt-loop child process, and the events.jsonl -> stage-board
projection the tkinter shell renders.

The hunt loop itself is enclave/varvel/tools/huntloop.mjs (the 24/7 engine);
this module spawns it as a TRACKED child, tails its events file, and reverses
it cleanly. All state comes from real files/processes — the board NEVER
invents a stage state (an event the loop did not write does not exist).

START is self-sufficient for docker: ensure_docker() launches Docker Desktop
when the engine is down and waits, bounded — reported on the start message,
never a refusal (the loop's vm-verification degrades honestly without it).

Killing is cmdline-checked: a pid is only signalled when its command line
actually contains 'huntloop' — a reused pid is never murdered by mistake.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import config, menuops

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_NEW_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

# The enclave checkout: spark-code/ is a child of it (source layout AND the
# built exes, which live next to the package).
ENCLAVE = config.ROOT.parent
VARVEL = ENCLAVE / "varvel"
HUNTLOOP = VARVEL / "tools" / "huntloop.mjs"
HUNT_DIR = VARVEL / "data" / "huntloop"          # matches huntloop.mjs's default root
PID_FILE = "hunt.pid"
EVENTS_FILE = "events.jsonl"
STOP_FILE = "STOP"
PAUSE_FILE = "PAUSE"

# The board's stage vocabulary — EXACTLY huntloop.mjs's STAGES (kept in sync;
# the tests pin this against the module's own list).
STAGES = ["watch", "intake", "scope-check", "recon", "testing",
          "vm-verification", "evidence", "report", "poc-forge", "ledger", "cleanup"]

BRAIN_ENV = {
    "VARVEL_BRAIN_PROVIDER": "openai-compatible",
    # /v1: the OpenAI-compatible root of the lane (brain-provider appends /chat/completions)
    "VARVEL_BRAIN_BASE_URL": config.BASE_URL.rstrip("/") + "/v1",
}


def find_node() -> Optional[str]:
    """node.exe on PATH (the hunt loop's runtime), or None — an honest refusal."""
    return shutil.which("node")


# --- lane / brain -------------------------------------------------------------
_LANE_STATUS_RE = re.compile(r"health=(\d+)\s+model=(\S+)")


def lane_status(timeout: float = 60.0) -> Tuple[str, str]:
    """(state, detail) from the Spark's lane script. 'down' is a FIRST-CLASS
    state (the GPU is training — not an error): the console shows it plainly
    and the hunt's recon stage simply waits for the lane, honestly."""
    ok, out = menuops.lane_ssh(["status"], timeout=timeout)
    if not ok:
        return "unknown", f"lane status unreachable ({out.strip()[:120]})"
    m = _LANE_STATUS_RE.search(out)
    if not m:
        return "unknown", f"unparsable lane status: {out.strip()[:120]}"
    health, model = m.group(1), m.group(2)
    if health == "000000" or set(health) == {"0"}:
        return "down", f"lane down / training (model={model})"
    return "up", f"lane up (health {health}, model={model})"


def brain_status() -> Tuple[str, str]:
    """(state, detail): configured provider + whether the endpoint answers.
    The lane being down is reported as 'waiting', never as a brain error."""
    up, detail = menuops.health()
    model = menuops.current_model() if up else None
    if up:
        return "up", f"openai-compatible @ {BRAIN_ENV['VARVEL_BRAIN_BASE_URL']} (model={model or '?'})"
    return "waiting", f"brain endpoint not answering ({detail}) — recon waits; nothing is invented"


# --- docker: the vm-verification sandbox's engine -------------------------------
# vm-verification replays payloads in `docker run --network none` sandboxes;
# with the engine down that stage degrades (transcript-only) and a finding can
# never reach VERIFIED — docker is on the profit critical path. The 1-click
# START is therefore self-sufficient: ensure_docker() launches Docker Desktop
# when the engine is down and waits, bounded, for readiness. Docker absence
# NEVER blocks a start (the loop degrades honestly); the console reports it.
def docker_desktop_paths(env: Optional[dict] = None) -> List[Path]:
    """Candidate Docker Desktop.exe locations: the system-wide install first,
    then the per-user (%LOCALAPPDATA%) install."""
    env = env if env is not None else os.environ
    paths = [Path(env.get("ProgramFiles") or r"C:\Program Files")
             / "Docker" / "Docker" / "Docker Desktop.exe"]
    local = env.get("LOCALAPPDATA")
    if local:
        paths.append(Path(local) / "Docker" / "Docker Desktop.exe")
    return paths


def find_docker_desktop(env: Optional[dict] = None) -> Optional[str]:
    """The installed Docker Desktop launcher, or None — an honest absence."""
    for p in docker_desktop_paths(env):
        if p.exists():
            return str(p)
    return None


def docker_engine_up(runner=menuops.run_hidden, timeout: float = 5.0,
                     cli: str = "docker") -> Tuple[bool, str]:
    """Cheap liveness probe: `docker info` answering rc 0. Never raises —
    an absent CLI or a hung daemon is (False, honest detail)."""
    try:
        r = runner([cli, "info"], capture_output=True, text=True, timeout=timeout)
    except Exception as exc:
        return False, f"`docker info` failed: {type(exc).__name__}: {exc}"
    if r.returncode == 0:
        return True, "engine answering"
    err = " ".join(((r.stderr or "") + " " + (r.stdout or "")).split())
    return False, (f"engine not answering (rc={r.returncode}"
                   + (f": {err[:100]}" if err else "") + ")")


_DOCKER_LAST: Optional[Tuple[str, str]] = None  # ensure_docker()'s last verdict


def ensure_docker(wait_s: float = 120.0, poll_s: float = 3.0, probe_s: float = 5.0,
                  runner=menuops.run_hidden, popen=menuops.popen_hidden,
                  desktop_finder=find_docker_desktop, which=shutil.which,
                  sleeper=time.sleep, clock=time.monotonic) -> Tuple[str, str]:
    """Make the 1-click START self-sufficient for docker: probe the engine;
    when it is down, launch Docker Desktop (windowless) and wait — bounded —
    for readiness. NEVER raises: docker absence degrades the hunt's
    vm-verification, it must not crash a start.

    Returns (state, detail) with states:
      up               engine already answering — nothing spawned
      started          was down; Desktop launched; engine ready after Ns
      starting-timeout Desktop launched but the engine did not answer in time
                       (an honest timeout, never a lied green)
      down             engine down and no Docker Desktop.exe to launch
      missing          no docker CLI AND no Docker Desktop.exe (uninstalled?)
      error            the launch (or the ensure itself) raised
    The verdict is remembered in _DOCKER_LAST for the STATE rail's DOCKER line."""
    global _DOCKER_LAST
    try:
        up, _ = docker_engine_up(runner, probe_s)
        if up:
            _DOCKER_LAST = ("up", "engine already running")
            return _DOCKER_LAST
        desktop = desktop_finder()
        cli = which("docker")
        if cli is None and desktop is not None:
            # A Desktop install carries its CLI next to itself; a console
            # started before the install just lacks it on PATH.
            sibling = Path(desktop).parent / "resources" / "bin" / "docker.exe"
            if sibling.exists():
                cli = str(sibling)
        if desktop is None and cli is None:
            _DOCKER_LAST = ("missing", "no docker CLI on PATH and no Docker Desktop.exe "
                                       "(uninstalled?) — vm-verification degrades "
                                       "(transcript-only), honestly")
            return _DOCKER_LAST
        if desktop is None:
            _DOCKER_LAST = ("down", "engine down and no Docker Desktop.exe found to start it "
                                    "— vm-verification degrades (transcript-only), honestly")
            return _DOCKER_LAST
        try:
            popen([desktop])
        except Exception as exc:
            _DOCKER_LAST = ("error", f"Docker Desktop launch failed: {type(exc).__name__}: {exc}")
            return _DOCKER_LAST
        t0 = clock()
        deadline = t0 + wait_s
        detail = "no probe ran"
        while clock() < deadline:
            up, detail = docker_engine_up(runner, probe_s, cli or "docker")
            if up:
                _DOCKER_LAST = ("started", f"engine ready after {clock() - t0:.0f}s")
                return _DOCKER_LAST
            sleeper(poll_s)
        _DOCKER_LAST = ("starting-timeout",
                        f"engine did not answer within {wait_s:.0f}s of launching Docker Desktop "
                        f"(last probe: {detail}) — it may still come up; "
                        "vm-verification degrades until it does")
        return _DOCKER_LAST
    except Exception as exc:  # the hard contract: docker never crashes a start
        _DOCKER_LAST = ("error", f"docker ensure failed: {type(exc).__name__}: {exc}")
        return _DOCKER_LAST


def _docker_note(state: str, detail: str) -> str:
    """The one-line docker suffix on the START message: ready states are
    stated plainly, degraded ones are a loud NOTE (reported, never blocking)."""
    if state in ("up", "started"):
        return f"docker: {state}, {detail}"
    return f"NOTE: docker {state} — {detail}"


def docker_status(runner=menuops.run_hidden, which=shutil.which,
                  desktop_finder=find_docker_desktop,
                  probe_s: float = 3.0) -> Tuple[str, str]:
    """(state, detail) for the STATE rail's DOCKER card: a cheap live
    `docker info` probe — never a launch. States: up | down | missing.
    A down engine carries ensure_docker()'s last verdict when there is one
    (a 'starting-timeout' there explains WHY it is down right now)."""
    if which("docker") is None:
        if desktop_finder() is None:
            return "missing", ("no docker CLI on PATH and no Docker Desktop.exe — "
                               "vm-verification degrades (transcript-only), honestly")
        return "down", "docker CLI not on PATH but Docker Desktop is installed — engine not probeable"
    up, detail = docker_engine_up(runner, probe_s)
    if up:
        return "up", "engine answering"
    if _DOCKER_LAST and _DOCKER_LAST[0] not in ("up", "started"):
        return "down", f"{_DOCKER_LAST[0]}: {_DOCKER_LAST[1]}"
    return "down", detail


# --- the tracked child --------------------------------------------------------
def _pid_file(hunt_dir: Path) -> Path:
    return Path(hunt_dir) / PID_FILE


def read_pid(hunt_dir: Path) -> Optional[int]:
    try:
        return int(_pid_file(hunt_dir).read_text().strip())
    except Exception:
        return None


def pid_alive(pid: int, runner=menuops.run_hidden) -> bool:
    """tasklist probe — never raises; an unreadable process table means dead.
    Windowless: this fires on the console's refresh tick (the flash fix)."""
    try:
        r = runner(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                   capture_output=True, text=True, timeout=10)
    except Exception:
        return False
    return str(pid) in (r.stdout or "")


def process_cmdline(pid: int, runner=menuops.run_hidden) -> str:
    """The process's command line via PowerShell CIM ('' when gone/unreadable).
    The ONLY evidence a kill is ever based on. Windowless (the flash fix)."""
    ps = f'(Get-CimInstance Win32_Process -Filter "ProcessId={pid}").CommandLine'
    try:
        r = runner(["powershell", "-NoProfile", "-Command", ps],
                   capture_output=True, text=True, timeout=15)
    except Exception:
        return ""
    return (r.stdout or "").strip()


def is_hunt_process(pid: int, runner=menuops.run_hidden) -> bool:
    """True only when pid's cmdline actually runs the hunt loop."""
    return "huntloop" in process_cmdline(pid, runner).lower()


def hunt_cmd(hunt_dir: Path, fixture: Optional[str] = None,
             mock_brain: bool = False, once: bool = False,
             interval: Optional[int] = None,
             max_opps: Optional[int] = None) -> List[str]:
    node = find_node()
    if not node:
        raise FileNotFoundError("node.exe not on PATH — the hunt loop needs Node.js")
    cmd = [node, str(HUNTLOOP), "--dir", str(hunt_dir)]
    if fixture:
        cmd += ["--fixture", fixture]
    if mock_brain:
        cmd.append("--mock-brain")
    if once:
        cmd.append("--once")
    if interval is not None:
        cmd += ["--interval", str(interval)]
    if max_opps is not None:
        cmd += ["--max-opps", str(max_opps)]
    return cmd


def hunt_env(hunt_dir: Path, model: Optional[str] = None) -> Dict[str, str]:
    """The child's environment: the brain points at the local lane and the
    hunt owns its watcher state (self-contained, cleans with the hunt dir)."""
    env = dict(os.environ)
    env.update(BRAIN_ENV)
    if model:
        env["VARVEL_BRAIN_MODEL"] = model
    env["VARVEL_HUNTLOOP_DIR"] = str(hunt_dir)
    env["VARVEL_H1WATCH_DIR"] = str(Path(hunt_dir) / "h1watch")
    return env


def pipeline_status(hunt_dir: Path) -> Tuple[str, str]:
    """(state, detail): running / paused / stopped, from the pid file + a
    cmdline-checked liveness probe."""
    pid = read_pid(hunt_dir)
    if pid is None:
        return "stopped", "no hunt on record"
    if pid_alive(pid) and is_hunt_process(pid):
        if (Path(hunt_dir) / PAUSE_FILE).exists():
            return "paused", f"hunt paused (pid {pid}) — model capacity is FREE"
        return "running", f"hunt active (pid {pid})"
    return "stopped", f"last hunt pid {pid} is gone"


def start_hunt(hunt_dir: Path = HUNT_DIR, fixture: Optional[str] = None,
               mock_brain: bool = False, once: bool = False,
               interval: Optional[int] = 300, max_opps: Optional[int] = 10,
               popen=menuops.popen_hidden) -> Tuple[bool, str]:
    """START HUNT: preflight (node, loop present, not already running), then
    ensure_docker() (start Docker Desktop + bounded wait when the engine is
    down — vm-verification's profit path; reported in the message, NEVER a
    start refusal), then spawn the hunt loop as a tracked child and record
    its pid. The lane may be down (training) — that is reported in the
    message and the loop's recon stage waits for it; it is NOT a start
    failure. The child is spawned windowless (the flash fix).

    Live defaults since the 2026-09-12 cadence review: 10 opportunities per
    cycle, 300s between cycles — cross-program parallelism is the scaling
    axis (per-target pacing stays inside gather.mjs's CADENCE contract)."""
    if not HUNTLOOP.exists():
        return False, f"hunt loop missing at {HUNTLOOP}"
    if find_node() is None:
        return False, "node.exe not on PATH — cannot run the hunt loop"
    state, detail = pipeline_status(hunt_dir)
    if state in ("running", "paused"):
        return False, f"hunt already {state} — STOP it first (never two hunts at once)"
    Path(hunt_dir).mkdir(parents=True, exist_ok=True)
    # A stale STOP/PAUSE from a previous run must not poison the new child.
    for f in (STOP_FILE, PAUSE_FILE):
        try:
            (Path(hunt_dir) / f).unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
    lane, lane_detail = lane_status()
    model = menuops.current_model() if lane == "up" else None
    # Self-sufficient START: bring the docker engine up BEFORE the loop spawns
    # (vm-verification needs it for a finding to reach VERIFIED). This never
    # blocks or refuses the start — the loop degrades honestly; the verdict
    # rides the start message.
    docker_state, docker_detail = ensure_docker()
    try:
        cmd = hunt_cmd(hunt_dir, fixture=fixture, mock_brain=mock_brain,
                       once=once, interval=interval, max_opps=max_opps)
    except FileNotFoundError as exc:
        return False, str(exc)
    log = open(Path(hunt_dir) / "child-stdout.log", "ab")
    try:
        proc = popen(cmd, cwd=str(VARVEL), env=hunt_env(hunt_dir, model),
                     stdout=log, stderr=subprocess.STDOUT,
                     creationflags=_NEW_GROUP)
    except Exception as exc:
        log.close()
        return False, f"hunt spawn failed: {type(exc).__name__}: {exc}"
    finally:
        # The child inherited its own handle; the parent's copy is never needed again.
        try:
            log.close()
        except Exception:
            pass
    _pid_file(hunt_dir).write_text(str(proc.pid))
    note = f"hunt started (pid {proc.pid}) — {_docker_note(docker_state, docker_detail)}"
    if lane != "up":
        note += f" — NOTE: {lane_detail}; recon waits for the lane, honestly"
    return True, note


def stop_hunt(hunt_dir: Path = HUNT_DIR, grace_s: float = 8.0,
              runner=menuops.run_hidden) -> Tuple[bool, str]:
    """STOP HUNT, reversed cleanly: the STOP file asks the loop to finish its
    stage boundary and exit; a stubborn child is then killed — but ONLY when
    its cmdline still says huntloop (cmdline-checked kills only, no orphans
    and no pid-reuse murders)."""
    pid = read_pid(hunt_dir)
    if pid is None:
        return True, "no hunt on record — nothing to stop"
    if not pid_alive(pid, runner):
        _pid_file(hunt_dir).unlink(missing_ok=True)
        return True, f"hunt pid {pid} already gone (cleaned the pid file)"
    if not is_hunt_process(pid, runner):
        _pid_file(hunt_dir).unlink(missing_ok=True)
        return False, (f"pid {pid} is alive but its cmdline is NOT the hunt loop — "
                       "refusing to kill a stranger; removed the stale pid file")
    Path(hunt_dir).mkdir(parents=True, exist_ok=True)
    (Path(hunt_dir) / STOP_FILE).write_text("stop requested by the ops console\n")
    deadline = time.time() + grace_s
    while time.time() < deadline:
        if not pid_alive(pid, runner):
            _pid_file(hunt_dir).unlink(missing_ok=True)
            return True, f"hunt stopped gracefully (pid {pid} exited on the STOP file)"
        time.sleep(0.5)
    # Grace expired: cmdline-check AGAIN, then kill the tree.
    if not is_hunt_process(pid, runner):
        _pid_file(hunt_dir).unlink(missing_ok=True)
        return False, f"pid {pid} changed identity mid-stop — kill REFUSED (cmdline re-check)"
    try:
        runner(["taskkill", "/PID", str(pid), "/T", "/F"],
               capture_output=True, text=True, timeout=15)
    except Exception as exc:
        return False, f"taskkill failed: {type(exc).__name__}: {exc}"
    _pid_file(hunt_dir).unlink(missing_ok=True)
    return True, f"hunt stopped (pid {pid} killed after {grace_s}s grace, cmdline-checked)"


def pause_hunt(hunt_dir: Path = HUNT_DIR, reason: str = "paused by the ops console") -> Tuple[bool, str]:
    state, _ = pipeline_status(hunt_dir)
    if state != "running":
        return False, f"cannot pause — the hunt is {state}"
    (Path(hunt_dir) / PAUSE_FILE).write_text(reason + "\n")
    return True, "PAUSE written — the loop parks at the next stage boundary; ALL model capacity freed"


def resume_hunt(hunt_dir: Path = HUNT_DIR) -> Tuple[bool, str]:
    try:
        (Path(hunt_dir) / PAUSE_FILE).unlink()
    except FileNotFoundError:
        return False, "the hunt is not paused"
    return True, "PAUSE lifted — ALL model capacity returns to the hunt"


# --- events.jsonl -> the stage board -------------------------------------------
def read_events(hunt_dir: Path = HUNT_DIR, max_bytes: int = 2_000_000) -> List[dict]:
    """The tail of the loop's event stream. Bad lines are SKIPPED (a torn
    write on kill is expected), never invented."""
    path = Path(hunt_dir) / EVENTS_FILE
    try:
        data = path.read_bytes()
    except Exception:
        return []
    if len(data) > max_bytes:
        data = data[-max_bytes:]
        data = data[data.index(b"\n") + 1:] if b"\n" in data else b""
    events = []
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(ev, dict):
            events.append(ev)
    return events


def board(events: List[dict]) -> dict:
    """Project the event stream into the board model. Pure derivation:
    every state shown is the LAST event of its kind the loop actually wrote;
    a new opportunity resets the per-stage states to idle. `last_run` keeps
    each stage's last done/failed ACROSS resets, so an idle card can still
    say something true instead of going blank."""
    stages = {s: {"state": "idle", "at": None, "msg": ""} for s in STAGES}
    last_run = {s: None for s in STAGES}
    out = {
        "stages": stages,
        "last_run": last_run,
        "counters": {"seen": 0, "tested": 0, "verified": 0, "unverified": 0,
                     "drafted": 0, "cleaned": 0},
        "loop": None,          # started|paused|resumed|sleeping|stopping|stopped
        "loop_msg": "",
        "clean": None,         # None (no cleanup yet) | True (verified-clean) | False (residue)
        "clean_detail": "",
        "vm": {"state": "idle", "provider": None},
        "brain": None,         # 'waiting' while the lane is down
        "recorder": None,
        "ghost": None,         # the loop's own ghost verdict: in-use | off | down | skipped
        "last_ts": None,
    }
    for ev in events:
        ts = ev.get("ts")
        if ts:
            out["last_ts"] = ts
        kind = ev.get("type")
        if kind == "stage":
            name = ev.get("stage")
            if name in stages:
                rec = {"state": ev.get("state", "idle"),
                       "at": ts, "msg": ev.get("msg", "")}
                stages[name] = rec
                if rec["state"] in ("done", "failed"):
                    last_run[name] = dict(rec)  # a copy — the reset mutates stages in place
        elif kind == "opportunity" and ev.get("state") == "start":
            for s in stages.values():
                s.update({"state": "idle", "at": None, "msg": ""})
        elif kind == "counters" and isinstance(ev.get("data"), dict):
            out["counters"].update({k: v for k, v in ev["data"].items()
                                    if k in out["counters"]})
        elif kind == "loop":
            out["loop"] = ev.get("state")
            out["loop_msg"] = ev.get("msg", "")
        elif kind == "cleanup":
            out["clean"] = ev.get("state") == "verified-clean"
            out["clean_detail"] = ev.get("detail", "")
        elif kind == "vm":
            out["vm"] = {"state": ev.get("state", "idle"),
                         "provider": (ev.get("provider") or {}).get("name")}
        elif kind == "ghost":
            out["ghost"] = {"state": ev.get("state"), "chain": ev.get("chain"),
                            "msg": ev.get("msg", "")}
        elif kind == "brain":
            out["brain"] = ev.get("state")
        elif kind == "recorder":
            out["recorder"] = ev.get("recorder")
    return out


# =============================================================================
# GHOST PRE-FLIGHT GATE (the doctrine: START HUNT refuses unless the ghost
# chain is VERIFIED LIVE; mid-hunt a ghost drop PAUSES the hunt, loud)
# =============================================================================
# The chain comes from varvel/data/settings.json — the same file varvel's
# engine/settings.mjs reads: per-engagement keys `ghost.mode` (off|on|
# required), `ghost.chain` (comma-separated proxy URLs), `ghost.checkUrl`
# (echo endpoint), `ghost.expectExit` (pinned exit IP), `ghost.pinStrict`.
#
# THREE CHECKS, all over stdlib sockets (injected fakes in tests — no real
# network in the suite):
#   (a) DIAL   — the proxy answers a SOCKS5 greeting and its CONNECT to the
#                echo host succeeds (REP=0x00). The failure carries the REP
#                code's meaning, never a bare "failed".
#   (b) EXIT   — the IP-echo endpoint fetched THROUGH the chain returns an
#                IP; fetched DIRECTLY it returns the origin egress IP; the
#                two MUST differ (exposed = refuse). A pinned expectExit must
#                also match (pinStrict: mismatch = refuse; unpinned: loud
#                warning, still green).
#   (c) DNS    — leak sanity: the CONNECT goes out with ATYP=domain (remote
#                resolution, by construction — asserted), and a negative
#                control CONNECT to an unresolvable .invalid canary must be
#                REFUSED BY THE PROXY (REP!=0), proving resolution really
#                happens on the proxy's resolver, not leaked locally.
#
# Echo endpoints (lightweight, noted per doctrine): the engagement's
# ghost.checkUrl, default https://api.ipify.org?format=json; plain-text
# fallbacks https://ifconfig.me/ip and https://checkip.amazonaws.com are
# tried in order on shape failure. The IPs are compared as parsed text —
# never assumed.

GHOST_SETTINGS = VARVEL / "data" / "settings.json"
GHOST_DEFAULT_CHECK_URL = "https://api.ipify.org?format=json"
GHOST_FALLBACK_CHECK_URLS = ["https://ifconfig.me/ip", "https://checkip.amazonaws.com"]

_SOCKS5_REPS = {
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}


def ghost_config(settings_path: Path = GHOST_SETTINGS,
                 env: Optional[dict] = None) -> Tuple[Optional[dict], str]:
    """(config, source-engagement) — the FIRST engagement carrying a
    ghost.chain, preferring the env-named engagement (VARVEL_ENGAGEMENT)
    then any ghost.mode on|required. (None, reason) when nothing is armed."""
    env = env if env is not None else os.environ
    try:
        data = json.loads(Path(settings_path).read_text(encoding="utf-8"))
    except Exception as exc:
        return None, f"cannot read {settings_path}: {type(exc).__name__}"
    if not isinstance(data, dict):
        return None, f"{settings_path} is not an engagement map"

    def cfg_of(eng: str) -> Optional[dict]:
        e = data.get(eng)
        if not isinstance(e, dict):
            return None
        chain = str(e.get("ghost.chain") or "").strip()
        if not chain:
            return None
        return {
            "engagement": eng,
            "mode": str(e.get("ghost.mode") or "off"),
            "chain": chain,
            "checkUrl": str(e.get("ghost.checkUrl") or GHOST_DEFAULT_CHECK_URL),
            "expectExit": str(e.get("ghost.expectExit") or "").strip() or None,
            "pinStrict": bool(e.get("ghost.pinStrict")),
        }

    named = (env or {}).get("VARVEL_ENGAGEMENT")
    if named:
        c = cfg_of(named)
        if c:
            return c, named
    for eng in data:
        c = cfg_of(eng)
        if c and c["mode"] in ("on", "required"):
            return c, eng
    for eng in data:
        c = cfg_of(eng)
        if c:
            return c, eng
    return None, "no engagement in settings.json carries a ghost.chain"


# --- the raw dialer (real network; tests inject fakes) ------------------------
def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("proxy closed mid-reply")
        buf += chunk
    return buf


def socks5_dial(proxy_host: str, proxy_port: int, dest_host: str,
                dest_port: int, timeout: float = 8.0,
                sock_factory=None) -> Tuple[bool, str, Optional[object]]:
    """SOCKS5 no-auth CONNECT with ATYP=domain (remote DNS — the DNS-leak
    posture is decided HERE, by construction). Returns (ok, detail, sock).
    REP codes are translated via _SOCKS5_REPS, never reported bare."""
    make = sock_factory or __import__("socket").create_connection
    s = None
    try:
        s = make((proxy_host, proxy_port), timeout)
        s.sendall(b"\x05\x01\x00")                      # VER 5, 1 method, no-auth
        if _recv_exact(s, 2) != b"\x05\x00":
            return False, "proxy refused no-auth SOCKS5 (it demands authentication)", None
        hb = dest_host.encode("idna") if isinstance(dest_host, str) else dest_host
        import struct
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb
                  + struct.pack(">H", dest_port))       # CONNECT, ATYP=domain
        hdr = _recv_exact(s, 4)
        rep = hdr[1]
        if rep != 0x00:
            return False, f"proxy CONNECT to {dest_host}:{dest_port} refused: " \
                          f"{_SOCKS5_REPS.get(rep, f'REP 0x{rep:02x}')}", None
        atyp = hdr[3]                                   # drain BND.ADDR
        if atyp == 0x01:
            _recv_exact(s, 4)
        elif atyp == 0x03:
            ln = _recv_exact(s, 1)[0]
            _recv_exact(s, ln)
        elif atyp == 0x04:
            _recv_exact(s, 16)
        _recv_exact(s, 2)                               # BND.PORT
        return True, f"CONNECT {dest_host}:{dest_port} ok (remote DNS)", s
    except Exception as exc:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
        return False, f"dial {proxy_host}:{proxy_port} failed: {type(exc).__name__}: {exc}", None


def _parse_proxy(chain_url: str) -> Tuple[str, str, int]:
    from urllib.parse import urlparse
    u = urlparse(chain_url.strip())
    scheme = (u.scheme or "socks5").lower()
    if not u.hostname:
        raise ValueError(f"unparseable proxy URL: {chain_url!r}")
    return scheme, u.hostname, u.port or (1080 if scheme == "socks5" else 8080)


def fetch_ip_direct(url: str, timeout: float = 8.0) -> Tuple[bool, str]:
    """The origin egress IP, no proxy. (ok, ip-or-error)."""
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "varvel-ghost-check/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", "replace")
        return _extract_ip(body)
    except Exception as exc:
        return False, f"direct echo fetch failed: {type(exc).__name__}: {exc}"


def fetch_ip_via_chain(chain_url: str, url: str, timeout: float = 10.0,
                       dialer=socks5_dial) -> Tuple[bool, str]:
    """The exit IP as the chain sees it: SOCKS5 CONNECT (remote DNS) to the
    echo host, TLS if https, one minimal GET. (ok, ip-or-error)."""
    from urllib.parse import urlparse
    try:
        scheme, phost, pport = _parse_proxy(chain_url.split(",")[0])
        if scheme not in ("socks5", "socks5h"):
            return False, f"proxy scheme '{scheme}' not implemented (socks5 chains only, loudly)"
        u = urlparse(url)
        host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
        ok, detail, s = dialer(phost, pport, host, port, timeout)
        if not ok:
            return False, detail
        try:
            if u.scheme == "https":
                import ssl
                s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
            path = (u.path or "/") + (("?" + u.query) if u.query else "")
            s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                       "User-Agent: varvel-ghost-check/1.0\r\nConnection: close\r\n\r\n").encode())
            body = b""
            while len(body) < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    break
                body += chunk
            text = body.decode("utf-8", "replace")
            ix = text.find("\r\n\r\n")                 # strip HTTP headers
            return _extract_ip(text[ix + 4:] if ix != -1 else text)
        finally:
            try:
                s.close()
            except Exception:
                pass
    except Exception as exc:
        return False, f"chain echo fetch failed: {type(exc).__name__}: {exc}"


def _extract_ip(body: str) -> Tuple[bool, str]:
    import re
    body = (body or "").strip()
    try:
        j = json.loads(body)
        if isinstance(j, dict) and isinstance(j.get("ip"), str):
            body = j["ip"].strip()
    except (json.JSONDecodeError, TypeError):
        pass
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", body)
    if m:
        return True, m.group(1)
    v6 = re.search(r"\b([0-9a-fA-F:]{3,39})\b", body)
    if v6 and ":" in v6.group(1):
        return True, v6.group(1)
    return False, f"no IP parseable from the echo body ({body[:80]!r})"


def ghost_preflight(settings_path: Path = GHOST_SETTINGS,
                    env: Optional[dict] = None,
                    dialer=socks5_dial,
                    direct_fetch=fetch_ip_direct,
                    chain_fetch=fetch_ip_via_chain,
                    timeout: float = 8.0) -> dict:
    """THE GATE. Returns {ok, chain, engagement, checks, remediation[]} —
    ok only when DIAL + EXIT + DNS all pass. Every failure carries its
    remediation line (the console shows them verbatim)."""
    cfg, source = ghost_config(settings_path, env)
    if cfg is None:
        return {"ok": False, "chain": None, "engagement": None,
                "checks": {"config": {"ok": False, "detail": source}},
                "remediation": [f"arm a ghost chain first: {source} — set ghost.mode/ghost.chain "
                                "in varvel/data/settings.json (the hunt never runs exposed)"]}
    chain = cfg["chain"].split(",")[0].strip()
    checks: Dict[str, dict] = {"config": {"ok": True, "detail":
                                          f"{source}: mode={cfg['mode']} chain={chain}"}}
    remediation: List[str] = []
    try:
        scheme, phost, pport = _parse_proxy(chain)
    except ValueError as exc:
        return {"ok": False, "chain": chain, "engagement": source,
                "checks": {**checks, "dial": {"ok": False, "detail": str(exc)}},
                "remediation": [f"fix ghost.chain in settings.json: {exc}"]}

    # (a) DIAL — proxy answers + CONNECTs the echo host (remote DNS).
    from urllib.parse import urlparse
    echo = urlparse(cfg["checkUrl"])
    ok, detail, s = dialer(phost, pport, echo.hostname,
                           echo.port or (443 if echo.scheme == "https" else 80), timeout)
    if s is not None:
        try:
            s.close()
        except Exception:
            pass
    checks["dial"] = {"ok": ok, "detail": detail}
    if not ok:
        remediation.append(f"the ghost proxy {phost}:{pport} is not dialable ({detail}) — start the "
                           "ghost egress (the lab SOCKS5 up-link) or repoint ghost.chain; START HUNT stays blocked")

    # (c) DNS-leak sanity — the canary MUST be refused by the proxy's resolver.
    canary = f"ghost-canary-{int(time.time())}.invalid"
    okc, detailc, sc = dialer(phost, pport, canary, 80, timeout)
    if sc is not None:
        try:
            sc.close()
        except Exception:
            pass
    dns_ok = (not okc)  # a refusal is the PASS here
    checks["dns"] = {"ok": dns_ok,
                     "detail": ("canary .invalid refused by the proxy's resolver — resolution rides "
                                "the chain (ATYP=domain CONNECTs by construction)" if dns_ok
                                else f"canary unexpectedly CONNECTED ({detailc}) — the 'proxy' resolves "
                                     "impossible names; DNS path cannot be trusted")}
    if not dns_ok:
        remediation.append("the proxy resolved an impossible .invalid canary — DNS-leak sanity failed; "
                           "verify the chain is a real SOCKS5 egress, not a local resolver masquerading")

    # (b) EXIT — chain IP vs origin IP must differ; the pin (expectExit) must match.
    okd, direct_ip = direct_fetch(cfg["checkUrl"], timeout)
    okx, exit_ip = chain_fetch(chain, cfg["checkUrl"], timeout)
    exit_ok = okd and okx and direct_ip != exit_ip
    detail_x = (f"origin {direct_ip} → exit {exit_ip} (differ ✓)" if exit_ok
                else "; ".join(p for p in [
                    f"direct={'ERR ' + direct_ip if not okd else direct_ip}",
                    f"chain={'ERR ' + exit_ip if not okx else exit_ip}",
                    "origin == exit — EXPOSED" if okd and okx and direct_ip == exit_ip else ""]) if True else "")
    checks["exit"] = {"ok": bool(exit_ok), "detail": detail_x,
                      **({"origin": direct_ip} if okd else {}), **({"exit": exit_ip} if okx else {})}
    if not okd:
        remediation.append(f"the direct IP echo failed ({direct_ip}) — cannot prove the exit differs; "
                           "check the echo endpoint (ghost.checkUrl) and local egress")
    elif not okx:
        remediation.append(f"the chain IP echo failed ({exit_ip}) — the proxy dials but cannot reach the "
                           "echo endpoint; check the up-link")
    elif direct_ip == exit_ip:
        remediation.append(f"EXPOSED: the chain exit IS the origin IP ({exit_ip}) — the proxy is a loop "
                           "back to your own egress; fix ghost.chain before any hunt")
    if exit_ok and cfg.get("expectExit"):
        pin_ok = exit_ip == cfg["expectExit"]
        checks["pin"] = {"ok": pin_ok or not cfg["pinStrict"],
                         "detail": (f"exit {exit_ip} == pinned expectExit ✓" if pin_ok else
                                    f"exit {exit_ip} != pinned expectExit {cfg['expectExit']}"
                                    + (" (pinStrict — REFUSING)" if cfg["pinStrict"] else " (loud warning, unpinned)"))}
        if not pin_ok and cfg["pinStrict"]:
            remediation.append(f"ghost.pinStrict is set and the exit is {exit_ip}, not the pinned "
                               f"{cfg['expectExit']} — reconnect the correct Mullvad server or update ghost.expectExit")
    elif exit_ok:
        # NO PIN = identity-diff mode: (a) dial + (b) exit≠origin + (c) DNS
        # sanity already passed — pinStrict applies ONLY when a pin is
        # deliberately set; an absent pin is never a failure.
        checks["pin"] = {"ok": True,
                         "detail": "no exit pin set — identity-diff mode (exit ≠ origin proven; set ghost.expectExit to pin one Mullvad server)"}

    ok_all = all(c.get("ok") for c in checks.values())
    return {"ok": ok_all, "chain": chain, "engagement": source,
            "checks": checks, "remediation": remediation}


_GHOST_STRIKES: Dict[str, int] = {}  # hunt_dir -> consecutive FAILED watch ticks


def ghost_watch_tick(hunt_dir: Path = HUNT_DIR, checker=None,
                     settings_path: Path = GHOST_SETTINGS,
                     strikes: int = 2) -> Tuple[str, str]:
    """Mid-hunt re-check (the console calls this every few minutes while the
    hunt runs). A PROVEN drop — `strikes` consecutive failed ticks, default 2
    — PAUSES the hunt loud; a single transient failure is 'degraded' and
    never pauses (one slow echo fetch through a consumer VPN is weather, not
    exposure — and the loop's own per-request fetch is fail-closed, so no
    byte leaks between ticks). Returns ('ok'|'degraded'|'dropped'|
    'not-running', detail)."""
    key = str(hunt_dir)
    state, _ = pipeline_status(hunt_dir)
    if state != "running":
        _GHOST_STRIKES.pop(key, None)
        return "not-running", f"hunt is {state} — the ghost watch is idle"
    check = checker or (lambda: ghost_preflight(settings_path))
    r = check()
    if r.get("ok"):
        _GHOST_STRIKES.pop(key, None)
        return "ok", "ghost still verified live"
    n = _GHOST_STRIKES.get(key, 0) + 1
    _GHOST_STRIKES[key] = n
    reason = "; ".join(r.get("remediation") or ["ghost check failed without remediation detail"])
    if n < strikes:
        return "degraded", (f"ghost check failed ({n}/{strikes} before any pause) — NOT pausing "
                            f"on a possible blip: {reason}")
    _GHOST_STRIKES.pop(key, None)
    ok_pause, msg = pause_hunt(hunt_dir, reason=f"ghost watchdog: {n} consecutive failed checks")
    return "dropped", (f"GHOST DROPPED mid-hunt — hunt PAUSED after {n} consecutive failed "
                       f"checks ({msg}): {reason}")


# =============================================================================
# CHAT TAB + CONTEXT METER + STATS BAR (headless logic; the UI is menu.py)
# =============================================================================
from .client import SparkClient  # noqa: E402  (reused, never reimplemented)
from .compact import estimate_tokens  # noqa: E402

CTX_LIMIT = config.CTX_OWNER_TARGET  # 262144 per-slot on the lane


class ChatState:
    """One console chat session: the message list, the thinking toggle, and
    the last stream's real usage (SparkClient.last_result)."""

    def __init__(self) -> None:
        self.messages: List[dict] = []
        self.thinking: bool = True
        self.effort: str = config.DEFAULT_EFFORT
        self.last_prompt_tokens: int = 0
        self.last_completion_tokens: int = 0
        self.last_tok_s: float = 0.0

    def context_used(self) -> int:
        """Tokens used of the per-slot window: the server's REAL prompt count
        from the last turn when we have it, else the char/4 estimate of the
        queued history (never less honest than the REPL's meter)."""
        return max(self.last_prompt_tokens, estimate_tokens(self.messages))

    def context_meter(self, limit: int = CTX_LIMIT) -> Tuple[int, int, float]:
        used = self.context_used()
        pct = round((used / limit) * 100, 1) if limit > 0 else 0.0
        return used, limit, pct


def chat_gate(pipeline_state: str) -> Tuple[bool, str]:
    """Profit-first: during HUNT ACTIVE the chat tab shows the banner instead
    of sending — ALL model capacity goes to the hunt."""
    if pipeline_state == "running":
        return False, "HUNT ACTIVE — all model capacity to the hunt (STOP the hunt to chat)"
    if pipeline_state == "paused":
        return True, "hunt paused — capacity free"
    return True, ""


def chat_send(state: ChatState, client: SparkClient, text: str,
              max_tokens: Optional[int] = None,
              on_delta=None, on_reasoning=None) -> Tuple[bool, str]:
    """One turn against the lane (worker-thread safe): appends the exchange,
    streams deltas to on_delta, records real usage. Never raises — errors
    come back as (False, honest message) and the user message stays."""
    text = (text or "").strip()
    if not text:
        return False, "empty message"
    cfg = config.EFFORT_MODES.get(state.effort, config.EFFORT_MODES[config.DEFAULT_EFFORT])
    state.messages.append({"role": "user", "content": text})
    reply_parts: List[str] = []
    try:
        stream = client.chat_stream(
            state.messages, max_tokens or cfg["max_tokens"],
            thinking=state.thinking and cfg["thinking"], on_reasoning=on_reasoning)
        for delta in stream:
            reply_parts.append(delta)
            if on_delta:
                on_delta(delta)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    reply = "".join(reply_parts)
    state.messages.append({"role": "assistant", "content": reply})
    r = client.last_result
    state.last_prompt_tokens = r.prompt_tokens
    state.last_completion_tokens = r.completion_tokens
    state.last_tok_s = r.tok_per_s
    return True, reply


def lane_activity(pipeline_state: str, lane_state: str) -> str:
    """The stats bar's lane-activity word: hunt | training | down | idle."""
    if pipeline_state == "running":
        return "hunt"
    if pipeline_state == "paused":
        return "paused"
    if lane_state == "down":
        return "training"
    if lane_state == "up":
        return "idle"
    return "down"


def stats_fields(model: Optional[str], tok_s: float, activity: str,
                 effort: str) -> Dict[str, str]:
    """The stats bar's four fields, formatted in one place (tested)."""
    return {
        "model": model or "—",
        "tok_s": f"{tok_s:.1f} tok/s" if tok_s and tok_s > 0 else "— tok/s",
        "activity": activity,
        "effort": effort,
    }


# --- the append-stable event stream (the vanishing-lines fix) ---------------------
# The console's stream pane renders TWO line families: (1) the projection of the
# loop's events.jsonl tail (file-driven, rebuilt every tick) and (2) TRANSIENT
# lines the console itself posts (ghost-verify progress, spawn results, button
# feedback). The bug: the tick rebuilt the pane from the file alone, deleting the
# transients — a line posted between ticks vanished on the next refresh. The
# merge policy lives HERE so it's testable headless: file events first (the
# authoritative history), transients appended after, in arrival order, capped.

TRANSIENT_CAP = 300


def build_stream(events: List[dict], transients: List[Tuple[str, str]],
                 fmt, cap: int = TRANSIENT_CAP) -> List[Tuple[str, str]]:
    """(tag, text) lines for the stream pane. fmt(event) -> (tag, text) | None.
    Transients survive every re-render — append-stability is the contract."""
    lines = []
    for ev in events:
        row = fmt(ev)
        if row:
            lines.append(row)
    for tag, text in (transients or [])[-cap:]:
        lines.append((tag, text))
    return lines


# =============================================================================
# PoC FORGE (the BUILD PoC button) — varvel/tools/pocforge.mjs on demand
# =============================================================================
# The forge takes ONE replay-verified evidence bundle and tries to demonstrate
# REAL exploitability (read-only probes, scope-guarded, ghost-routed), then
# upgrades the outbox draft. The console spawns it as a TRACKED child, exactly
# like the hunt loop: windowless, bounded wait, ONE JSON verdict line on
# stdout. One forge at a time — the lane is shared with the hunt (a lock file
# with a cmdline-checked pid, the same doctrine as the hunt's pid file).

POCFORGE = VARVEL / "tools" / "pocforge.mjs"
POC_LOCK_FILE = "pocforge.lock"
FINDINGS_FILE = "findings.jsonl"
POC_TIMEOUT_S = 1200.0  # the honest 20-min bound (the forge's own stage watchdog is 19 min)


def pocforge_cmd(evidence_dir: Path, hunt_dir: Path,
                 outbox_dir: Optional[Path] = None) -> List[str]:
    """The forge child command: node tools/pocforge.mjs --finding <dir>."""
    node = find_node()
    if not node:
        raise FileNotFoundError("node.exe not on PATH — the PoC forge needs Node.js")
    cmd = [node, str(POCFORGE), "--finding", str(evidence_dir), "--dir", str(hunt_dir)]
    if outbox_dir is not None:
        cmd += ["--outbox", str(outbox_dir)]
    return cmd


def is_pocforge_process(pid: int, runner=menuops.run_hidden) -> bool:
    """True only when pid's cmdline actually runs the PoC forge (same
    cmdline-checked doctrine as the hunt's kills — a reused pid is never trusted)."""
    return "pocforge" in process_cmdline(pid, runner).lower()


def _poc_lock(hunt_dir: Path) -> Path:
    return Path(hunt_dir) / POC_LOCK_FILE


def poc_forge_active(hunt_dir: Path = HUNT_DIR,
                     runner=menuops.run_hidden) -> Tuple[bool, str]:
    """(active, detail): the one-at-a-time guard. A lock counts only while its
    pid is alive AND its cmdline says pocforge; a stale lock is cleaned loudly,
    never obeyed."""
    try:
        pid = int(_poc_lock(hunt_dir).read_text().strip())
    except Exception:
        return False, "no forge on record"
    if pid_alive(pid, runner) and is_pocforge_process(pid, runner):
        return True, f"a PoC forge is already running (pid {pid}) — one at a time, the lane is shared with the hunt"
    try:
        _poc_lock(hunt_dir).unlink()
    except OSError:
        pass
    return False, f"stale forge lock (pid {pid} gone or not a forge) — cleaned"


def poc_candidates(hunt_dir: Path = HUNT_DIR) -> List[dict]:
    """The BUILD PoC menu: replay-VERIFIED findings whose evidence dir exists.
    Read-only over the loop's findings ledger (bad lines skipped, never
    invented; the latest line per evidence dir wins). A finding already forged
    carries its poc-result verdict — shown, never hidden."""
    try:
        lines = (Path(hunt_dir) / FINDINGS_FILE).read_text(
            encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    by_dir: Dict[str, dict] = {}
    order: List[str] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict) or rec.get("verified") is not True:
            continue
        ev = rec.get("evidenceDir")
        if not ev or not Path(str(ev)).is_dir():
            continue
        key = str(ev)
        if key not in by_dir:
            order.append(key)
        by_dir[key] = rec
    out = []
    for key in order:
        rec = by_dir[key]
        poc = None
        try:
            poc = json.loads((Path(key) / "poc-result.json").read_text(encoding="utf-8"))
        except Exception:
            poc = None
        out.append({
            "opp": rec.get("opp"),
            "finding": rec.get("finding"),
            "sev": rec.get("sev"),
            "at": rec.get("ts"),
            "evidenceDir": key,
            "poc": (poc or {}).get("verdictClass") if isinstance(poc, dict) else None,
            "pocAt": (poc or {}).get("at") if isinstance(poc, dict) else None,
        })
    return out


def build_poc(evidence_dir, hunt_dir: Path = HUNT_DIR,
              outbox_dir: Optional[Path] = None, timeout_s: float = POC_TIMEOUT_S,
              popen=menuops.popen_hidden, runner=menuops.run_hidden,
              env: Optional[dict] = None, model: Optional[str] = None
              ) -> Tuple[bool, str, dict]:
    """BUILD PoC: spawn the forge windowless, wait bounded (an HONEST timeout,
    never a lied verdict), parse the ONE JSON result line it prints.

    Returns (ok, message, result) — result carries the forge's own
    verdictClass (poc-verified / poc-unproven / check-defect) verbatim; the
    message names it. Never raises: every failure is an honest (False, …, {})."""
    evidence_dir = Path(evidence_dir)
    if not POCFORGE.exists():
        return False, f"PoC forge missing at {POCFORGE}", {}
    if not evidence_dir.is_dir():
        return False, f"evidence dir not found: {evidence_dir}", {}
    if find_node() is None:
        return False, "node.exe not on PATH — cannot run the PoC forge", {}
    active, detail = poc_forge_active(hunt_dir, runner)
    if active:
        return False, f"REFUSED — {detail}", {}
    try:
        cmd = pocforge_cmd(evidence_dir, hunt_dir, outbox_dir)
    except FileNotFoundError as exc:
        return False, str(exc), {}
    if model is None:
        # The forge's brain REFUSES without an explicit model id (brain-provider.mjs:
        # 'openai-compatible brain needs a model id') — resolve it the way START HUNT does.
        model = menuops.current_model()
    child_env = env if env is not None else hunt_env(Path(hunt_dir), model)
    Path(hunt_dir).mkdir(parents=True, exist_ok=True)
    try:
        proc = popen(cmd, cwd=str(VARVEL), env=child_env,
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                     text=True, encoding="utf-8", errors="replace",
                     creationflags=_NEW_GROUP)
    except Exception as exc:
        return False, f"forge spawn failed: {type(exc).__name__}: {exc}", {}
    _poc_lock(hunt_dir).write_text(str(proc.pid))
    try:
        try:
            out, _ = proc.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
            return False, (f"forge did not finish within {timeout_s / 60:.0f} min — killed "
                           f"(pid {proc.pid}); its own 19-min stage watchdog normally ends it first — "
                           "the claim stays UNPROVEN, never assumed"), {}
        except Exception as exc:
            return False, f"forge wait failed: {type(exc).__name__}: {exc}", {}
    finally:
        try:
            _poc_lock(hunt_dir).unlink()
        except OSError:
            pass
    verdict = None
    for line in reversed((out or "").splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(doc, dict) and ("verdictClass" in doc or "ok" in doc):
            verdict = doc
            break
    if verdict is None:
        tail = " | ".join((out or "").splitlines()[-3:])[:200]
        return False, (f"forge produced no JSON verdict line (rc {proc.returncode}; "
                       f"tail: {tail or 'empty'}) — nothing is assumed"), {}
    cls = verdict.get("verdictClass")
    if cls == "poc-verified":
        host = (verdict.get("proof") or {}).get("host") or ""
        msg = (f"PoC DEMONSTRATED on {host} — the declared impact marker was captured live; "
               "the outbox draft was upgraded (operator review, NEVER submitted)")
    elif cls:
        msg = f"forge verdict: {cls} — {str(verdict.get('reason') or '')[:160]}"
    else:
        msg = f"forge run failed: {str(verdict.get('reason') or verdict.get('error') or 'unknown')[:160]}"
    return bool(verdict.get("ok", True)), msg, verdict


# =============================================================================
# FINDINGS INDEX + VERIFY orchestration (the console's FINDINGS section)
# =============================================================================
# findings_index() lists EVERY finding in the hunt ledger with severity +
# verdict badges and the two affordances per row: VERIFY (forge the evidence
# bundle — only replay-VERIFIED findings with the dir on disk) and REPORT
# (open the outbox draft — only findings the report stage actually drafted,
# i.e. verified ones; the disabled reason says exactly that). Read-only over
# the ledger and the outbox — this module never writes findings.jsonl.
#
# verify_finding() is the VERIFY button's orchestration: pause the hunt
# (freeing the brain lane for the forge), run build_poc, then resume — but
# ONLY when THIS call was what paused (an operator-paused hunt stays paused),
# and the resume rides try/finally so it happens after success AND error.

# POC-DEMONSTRATED pins to the very TOP (a proven finding outranks everything),
# then the verified band → unproven → anything else (unverified/check-defect/…).
_BADGE_RANK = {"POC-DEMONSTRATED": 0, "SUBMITTABLE": 1, "FIRM": 2, "UNPROVEN": 3}

# FORGE ALL queue order: the sharpest severity first, newest first within a band.
_SEV_RANK = {"critical": 0, "crit": 0, "high": 1, "medium": 2, "med": 2,
             "low": 3, "info": 4, "informational": 4, "none": 4}


def findings_index(hunt_dir: Path = HUNT_DIR) -> List[dict]:
    """All findings from the ledger, sorted POC-DEMONSTRATED first (proven
    winners pin to the top), then verified → unproven → unverified (newest
    first within each band). Bad lines are skipped, never invented; the ledger
    is append-only so the LATEST line per evidence dir (else per opp+finding)
    wins. Each row:
      opp, finding, sev, verdict, verified, ts,
      evidence_dir (None when the ledger carries none), has_evidence,
      poc (the forge's verdictClass when a poc-result.json exists),
      grade + submittable (the loop's computed evidence grade, never asserted),
      badge (POC-DEMONSTRATED | SUBMITTABLE | FIRM | UNPROVEN | CHECK-DEFECT
             | SKIPPED | UNVERIFIED) — only a demonstrated PoC or the report gate's own
             `ready` earns a submittable badge; a replay alone is FIRM, never VERIFIED,
      draft_path (existing outbox .md or None),
      forgeable + forge_reason, reportable + report_reason
    Disabled-state reasons are honest and specific — the UI shows them verbatim."""
    hunt_dir = Path(hunt_dir)
    try:
        lines = (hunt_dir / FINDINGS_FILE).read_text(
            encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []

    norm = lambda s: str(s).replace("\\", "/").rstrip("/")
    # The outbox map: normalized evidence-bundle path -> draft file, anchored
    # on the draft header's own "Evidence bundle:" line (pocforge's findDraft
    # anchor — never a filename convention guessed from the finding title).
    drafts: Dict[str, str] = {}
    try:
        names = [f for f in os.listdir(hunt_dir / "outbox") if f.endswith(".md")]
    except Exception:
        names = []
    for name in names:
        p = hunt_dir / "outbox" / name
        try:
            head = p.read_text(encoding="utf-8", errors="replace")[:1600]
        except Exception:
            continue
        m = re.search(r"Evidence bundle: (.+?) -->", head)
        if m:
            drafts[norm(m.group(1).strip())] = str(p)

    by_key: Dict[str, dict] = {}
    order: List[str] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict) or not rec.get("finding"):
            continue
        ev = str(rec.get("evidenceDir") or "")
        key = norm(ev) if ev else f"{rec.get('opp')}|{rec.get('finding')}"
        if key not in by_key:
            order.append(key)
        by_key[key] = rec

    rows = []
    for key in order:
        rec = by_key[key]
        ev = str(rec.get("evidenceDir") or "")
        has_ev = bool(ev) and Path(ev).is_dir()
        poc = None
        if has_ev:
            try:
                doc = json.loads((Path(ev) / "poc-result.json").read_text(encoding="utf-8"))
                poc = doc.get("verdictClass") if isinstance(doc, dict) else None
            except Exception:
                poc = None
        verdict = str(rec.get("verdict") or "unverified")
        verified = rec.get("verified") is True
        # THE GRADE, NOT THE REPLAY (2026-09-18 — the operator's findings-board report):
        # a replay-passed finding used to render as "VERIFIED", which reads — reasonably — as
        # "this is a real, fileable bug". But the replay runs INSIDE the isolated sandbox
        # (--network none): it re-derives the recorded fingerprint OFFLINE and never re-probes
        # the host, so it passes for any recorded bundle. The ledger's own `grade` (written by
        # tools/huntloop.mjs findingGrade()) says what actually stands:
        #   poc-demonstrated — the forge captured a LIVE impact marker (read-only, scope-guarded)
        #   firm             — an offline re-derivation of a live-observed fingerprint
        #   submittable      — computed by the loop from the report gate, never asserted
        # VERIFIED is therefore no longer a badge: only a demonstrated PoC (or the report
        # gate's own `ready` over a non-self-referential target re-probe) is submittable.
        grade = str(rec.get("grade") or "").strip().lower()
        submittable = rec.get("submittable") is True
        if poc == "poc-verified" or grade == "poc-demonstrated":
            badge = "POC-DEMONSTRATED"
        elif submittable:
            badge = "SUBMITTABLE"
        elif grade == "firm" or (not grade and verdict == "verified"):
            # Legacy lines (written before the grade existed) carry only verdict=verified —
            # that is an offline replay, so they are labeled FIRM, never VERIFIED.
            badge = "FIRM"
        elif verdict == "unproven":
            badge = "UNPROVEN"
        elif verdict == "check-defect":
            badge = "CHECK-DEFECT"
        elif verdict == "skipped":
            badge = "SKIPPED"
        else:
            badge = "UNVERIFIED"
        draft = drafts.get(norm(ev)) if ev else None
        if draft is None and ev:
            tail = "/".join(norm(ev).split("/")[-2:])  # <opp-slug>/<finding-slug>
            draft = next((p for k, p in drafts.items() if k.endswith(tail)), None)
        forgeable = bool(verified and has_ev)
        if forgeable:
            forge_reason = ""
        elif not verified:
            forge_reason = (f"the forge only takes replay-VERIFIED findings "
                            f"(this one is {verdict})")
        else:
            forge_reason = "the evidence dir is missing from disk — nothing to forge"
        reportable = draft is not None
        if reportable:
            report_reason = ""
        elif not verified:
            report_reason = ("no draft exists — the hunt's report stage only drafts "
                             "replay-VERIFIED findings (an unverified claim is not a draft)")
        else:
            report_reason = "no outbox draft names this evidence bundle"
        rows.append({
            "opp": rec.get("opp"), "finding": rec.get("finding"),
            "sev": rec.get("sev") or "info", "verdict": verdict, "verified": verified,
            "grade": grade or None, "submittable": submittable,
            "readiness": rec.get("readiness"), "oracle_kind": rec.get("oracleKind"),
            "ts": rec.get("ts"), "evidence_dir": ev or None, "has_evidence": has_ev,
            "poc": poc, "badge": badge, "draft_path": draft,
            "forgeable": forgeable, "forge_reason": forge_reason,
            "reportable": reportable, "report_reason": report_reason,
        })
    # newest first within each badge band (stable sorts, secondary key first)
    rows.sort(key=lambda r: r["ts"] or "", reverse=True)
    rows.sort(key=lambda r: _BADGE_RANK.get(r["badge"], 4))
    return rows


def verify_finding(evidence_dir, hunt_dir: Path = HUNT_DIR, pause: bool = True,
                   note=None, **forge_kwargs) -> Tuple[bool, str, dict]:
    """VERIFY a finding: pause the hunt (the brain lane goes to the forge),
    run build_poc on the evidence bundle, then resume — see the pause/resume
    contract. note(text) receives the progress lines the console streams;
    returns build_poc's (ok, message, result) verbatim.

    THE PAUSE/RESUME CONTRACT:
      * pauses ONLY a running hunt (a stopped one has nothing to pause)
      * resumes ONLY when THIS call was what paused — an operator-paused hunt
        STAYS paused (the operator's hand is never overridden)
      * the resume rides try/finally: it fires after success AND after error,
        including a forge that raises — a paused hunt is never orphaned
      * a failed pause is named and the forge runs anyway (the lane is shared;
        slower, never unsafe — the forge's own bounds still hold)"""
    note = note or (lambda t: None)
    we_paused = False
    if pause:
        state, _ = pipeline_status(hunt_dir)
        if state == "running":
            ok, msg = pause_hunt(hunt_dir, reason="VERIFY: the console paused the hunt for a PoC forge")
            if ok:
                we_paused = True
                note("hunt paused for the forge — capacity to the finding")
            else:
                note(f"could not pause the hunt ({msg}) — forging alongside it, honestly named")
        elif state == "paused":
            note("hunt already paused by the operator — it STAYS paused after the forge (not ours to resume)")
        else:
            note(f"hunt is {state} — nothing to pause; forging now")
    try:
        return build_poc(evidence_dir, hunt_dir=hunt_dir, **forge_kwargs)
    finally:
        if we_paused:
            ok, msg = resume_hunt(hunt_dir)
            note("hunt resumed after the forge" if ok
                 else f"RESUME FAILED ({msg}) — the hunt is still paused; resume it by hand")


# =============================================================================
# FORGE ALL (the batch): every forgeable finding through the PoC-forge, once
# =============================================================================
# One click works through EVERY replay-verified finding with the same forge the
# single VERIFY/BUILD PoC buttons use (build_poc — windowless, bounded, one
# JSON verdict). The batch's own doctrine:
#   * QUEUE   findings_index rows that are forgeable and NOT already
#             poc-verified (a proven finding is never re-forged), ordered
#             critical → high → medium → low → info, newest first within a band.
#   * LANE    one pause at the start, one resume at the end (never per finding)
#             with verify_finding's exact contract: resume ONLY when this batch
#             paused, the resume rides try/finally (success, error AND cancel).
#   * SERIAL  one forge at a time, always — the brain lane is shared with the
#             hunt. No parallelism, ever.
#   * CANCEL  a FORGE_STOP file in the hunt dir stops the batch BETWEEN runs
#             (never mid-forge); the file is deleted and the summary says
#             cancelled: yes, honestly.
#   * LOCKS   the batch holds FORGE_ALL_LOCK for its whole run (pid +
#             cmdline-checked, same semantics as the hunt's pid file); each
#             individual forge still holds pocforge.lock for its own run.
#             A row that errors is recorded as 'error' and the batch continues.

FORGE_ALL_LOCK_FILE = "FORGE_ALL_LOCK"
FORGE_STOP_FILE = "FORGE_STOP"


def _forge_all_lock(hunt_dir: Path) -> Path:
    return Path(hunt_dir) / FORGE_ALL_LOCK_FILE


def is_forge_all_process(pid: int, runner=menuops.run_hidden) -> bool:
    """True only when pid's cmdline is the ops console (a batch's owner is the
    console process itself — spark-menu.exe or `python -m spark_code.menu`)."""
    cl = process_cmdline(pid, runner).lower()
    return "spark-menu" in cl or "spark_code.menu" in cl


def forge_all_active(hunt_dir: Path = HUNT_DIR,
                     runner=menuops.run_hidden) -> Tuple[bool, str]:
    """(active, detail): the one-batch-at-a-time guard. A lock counts only
    while its pid is alive AND its cmdline is the ops console; a stale lock is
    cleaned loudly, never obeyed (the same doctrine as the forge lock)."""
    try:
        pid = int(_forge_all_lock(hunt_dir).read_text().strip())
    except Exception:
        return False, "no forge-all batch on record"
    if pid_alive(pid, runner) and is_forge_all_process(pid, runner):
        return True, (f"a FORGE ALL batch is already running (console pid {pid}) — "
                      "one batch at a time, the lane is shared with the hunt")
    try:
        _forge_all_lock(hunt_dir).unlink()
    except OSError:
        pass
    return False, f"stale forge-all lock (pid {pid} gone or not the console) — cleaned"


def forge_all(hunt_dir: Path = HUNT_DIR, pause: bool = True,
              limit: Optional[int] = None, note=None,
              popen=menuops.popen_hidden, runner=menuops.run_hidden,
              env: Optional[dict] = None, model: Optional[str] = None,
              stop_file_name: str = FORGE_STOP_FILE) -> dict:
    """FORGE ALL: work through every forgeable finding with build_poc, serially.

    Returns the summary dict:
      {total, poc_verified: [evidence dirs], poc_unproven, check_defect,
       errors, skipped_already_proven, cancelled, paused_by_us, duration_s,
       refused}
    `refused` is None on a real run, or the reason string when the batch never
    started (another forge active / another batch active) — a loud refusal,
    never a silent no-op. note(text) receives the progress lines the console
    streams: per-finding start, the verdict line, and the final summary."""
    note = note or (lambda t: None)
    t0 = time.monotonic()
    hunt_dir = Path(hunt_dir)
    summary = {"total": 0, "poc_verified": [], "poc_unproven": 0,
               "check_defect": 0, "errors": 0, "skipped_already_proven": 0,
               "cancelled": False, "paused_by_us": False, "duration_s": 0.0,
               "refused": None}

    def _refuse(detail: str) -> dict:
        note(f"REFUSED — {detail}")
        summary["refused"] = detail
        summary["duration_s"] = round(time.monotonic() - t0, 1)
        return summary

    active, detail = forge_all_active(hunt_dir, runner)
    if active:
        return _refuse(detail)
    active, detail = poc_forge_active(hunt_dir, runner)
    if active:
        return _refuse(detail)

    rows = findings_index(hunt_dir)
    summary["skipped_already_proven"] = sum(
        1 for r in rows if r.get("forgeable") and r.get("poc") == "poc-verified")
    queue = [r for r in rows
             if r.get("forgeable") and r.get("poc") != "poc-verified"]
    # severity band first, newest first within a band (stable sorts, secondary
    # key first — the same idiom as findings_index's own ordering)
    queue.sort(key=lambda r: r.get("ts") or "", reverse=True)
    queue.sort(key=lambda r: _SEV_RANK.get(str(r.get("sev") or "info").lower(),
                                           _SEV_RANK["info"]))
    if limit is not None:
        queue = queue[:max(0, int(limit))]
    summary["total"] = total = len(queue)

    hunt_dir.mkdir(parents=True, exist_ok=True)
    stop_path = hunt_dir / stop_file_name
    # A stale FORGE_STOP from a crashed batch must not poison this one
    # (the same doctrine as start_hunt cleaning a stale STOP/PAUSE).
    try:
        stop_path.unlink()
    except OSError:
        pass
    _forge_all_lock(hunt_dir).write_text(str(os.getpid()))

    we_paused = False
    try:
        if pause:
            state, _ = pipeline_status(hunt_dir)
            if state == "running":
                ok, msg = pause_hunt(hunt_dir, reason="FORGE ALL: the console paused the hunt for a PoC batch")
                if ok:
                    we_paused = True
                    summary["paused_by_us"] = True
                    note("hunt paused for the batch — capacity to the findings")
                else:
                    note(f"could not pause the hunt ({msg}) — forging alongside it, honestly named")
            elif state == "paused":
                note("hunt already paused by the operator — it STAYS paused after the batch (not ours to resume)")
            else:
                note(f"hunt is {state} — nothing to pause; forging now")
        if total == 0:
            if summary["skipped_already_proven"]:
                note("nothing to forge — every forgeable finding is already poc-verified")
            elif rows:
                note("nothing to forge — no finding is forgeable (the forge only takes "
                     "replay-VERIFIED findings with evidence on disk)")
            else:
                note("no findings in the ledger yet — the hunt writes findings.jsonl as it tests")
        for i, row in enumerate(queue, 1):
            if stop_path.exists():
                # The operator's cancel lands BETWEEN runs, never mid-forge.
                summary["cancelled"] = True
                try:
                    stop_path.unlink()
                except OSError:
                    pass
                note(f"FORGE STOP honored — the batch stops after {i - 1} finished finding(s); "
                     "the rest stay unforged, honestly")
                break
            note(f"forge {i}/{total}: {row.get('opp') or '?'} — "
                 f"{(row.get('finding') or '')[:56]} …")
            try:
                ok, msg, result = build_poc(row["evidence_dir"], hunt_dir=hunt_dir,
                                            popen=popen, runner=runner,
                                            env=env, model=model)
            except Exception as exc:
                # build_poc's contract is 'never raises' — if a row still does,
                # name it and continue: one buggy row never kills a 38-finding batch.
                summary["errors"] += 1
                note(f"→ error: {type(exc).__name__}: {exc}")
                continue
            cls = (result or {}).get("verdictClass")
            if not ok:
                summary["errors"] += 1
                note(f"→ error: {msg}")
            elif cls == "poc-verified":
                summary["poc_verified"].append(row.get("evidence_dir"))
                note("→ poc-verified")
            elif cls == "poc-unproven":
                summary["poc_unproven"] += 1
                note("→ poc-unproven")
            elif cls == "check-defect":
                summary["check_defect"] += 1
                note("→ check-defect")
            else:
                summary["errors"] += 1
                note(f"→ error: ok but an unclassified verdict ({cls!r}) — counted honestly")
        summary["duration_s"] = round(time.monotonic() - t0, 1)
        note(f"FORGE ALL done: {len(summary['poc_verified'])} poc-verified, "
             f"{summary['poc_unproven']} unproven, "
             f"{summary['check_defect'] + summary['errors']} defects/errors, "
             f"cancelled: {'yes' if summary['cancelled'] else 'no'}")
    finally:
        try:
            _forge_all_lock(hunt_dir).unlink()
        except OSError:
            pass
        # A stop that raced the FINAL finding is swept too — never poison the
        # next batch (the work all completed; cancelled stays honestly False).
        try:
            stop_path.unlink()
        except OSError:
            pass
        if we_paused:
            ok, msg = resume_hunt(hunt_dir)
            note("hunt resumed after the batch" if ok
                 else f"RESUME FAILED ({msg}) — the hunt is still paused; resume it by hand")
    return summary
