"""Pings & schedules: owner-set reminders that surface as an automatic agent
turn. Pure parsing / validation / rendering, unit-tested; persistence lives in
the session log (a "ping" event), so a schedule survives /resume exactly like
todos do.

Two shapes:
  once   - fires at one absolute time (relative offset or HH:MM) then is removed
  every  - recurring interval from now (e.g. every 30m); refires each period

A ping "fires" by the REPL injecting its message as a real user turn, so it goes
through the normal agent loop (tools, approvals, session log). It surfaces at
the next REPL control point (turn boundary / prompt) - honest for a terminal app,
no background thread interrupting your typing.
"""

from __future__ import annotations

import re
import time
from typing import List, Optional, Tuple

MAX_PINGS = 50
MAX_MESSAGE = 400
MIN_INTERVAL_S = 5   # recurring floor: prevents a spin if someone types "1s"

_REL_RX = re.compile(r"^(\d+)([smhd])$")
_CLOCK_RX = re.compile(r"^([0-9]{1,2}):([0-9]{2})$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_relative(token: str) -> Optional[int]:
    """'30s'/'5m'/'2h'/'1d' -> seconds; None if not a relative token."""
    m = _REL_RX.match((token or "").strip().lower())
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    secs = n * _UNITS[unit]
    return secs if secs > 0 else None


def parse_clock(token: str, now: Optional[float] = None) -> Optional[int]:
    """'HH:MM'/'H:MM' -> an epoch timestamp for that wall-clock time.

    If the time is already past today it rolls to tomorrow (honest + documented).
    Uses local wall clock via mktime so it matches what the owner sees on screen;
    returns None if not a valid clock token. `now` is injectable for tests.
    """
    m = _CLOCK_RX.match((token or "").strip())
    if not m:
        return None
    hour, minute = int(m.group(1)), int(m.group(2))
    if hour > 23 or minute > 59:
        return None
    now = time.time() if now is None else now
    base = time.localtime(now)
    today_00 = time.mktime((base.tm_year, base.tm_mon, base.tm_mday,
                            0, 0, 0, base.tm_wday, base.tm_yday, base.tm_isdst))
    ts = int(today_00) + hour * 3600 + minute * 60
    if ts <= now:
        ts += 86400   # already passed today -> tomorrow at the same time
    return ts


def validate_pings(raw) -> Tuple[Optional[List[dict]], Optional[str]]:
    """Normalize a ping list (as stored in the session log). Returns (items, error).

    Each item: {id, kind:'once'|'every', message:str, due_ts:number,
                interval_s:int(>0 for 'every')}. Mirrors todos.validate_todos.
    """
    if not isinstance(raw, list):
        return None, '"pings" must be a JSON array of ping objects'
    if len(raw) > MAX_PINGS:
        return None, f"too many pings ({len(raw)}; max {MAX_PINGS})"
    items = []
    for i, entry in enumerate(raw, 1):
        if not isinstance(entry, dict):
            return None, f"ping {i} must be an object"
        kind = entry.get("kind")
        if kind not in ("once", "every"):
            return None, f'ping {i}: kind must be "once" or "every"'
        message = entry.get("message")
        if not isinstance(message, str) or not message.strip():
            return None, f'ping {i} needs a non-empty "message" string'
        due_ts = entry.get("due_ts")
        if not isinstance(due_ts, (int, float)) or due_ts < 0:
            return None, f'ping {i}: "due_ts" must be a number >= 0'
        interval_s = int(entry.get("interval_s", 0) or 0)
        if kind == "every":
            if interval_s < MIN_INTERVAL_S:
                return None, (f'ping {i}: recurring interval must be at least '
                              f'{MIN_INTERVAL_S}s')
        else:
            interval_s = 0
        items.append({"id": str(entry.get("id") or "?"), "kind": kind,
                      "message": message.strip()[:MAX_MESSAGE],
                      "due_ts": float(due_ts), "interval_s": interval_s})
    return items, None


def due_ids(pings: List[dict], now: Optional[float] = None) -> List[str]:
    """Ids of pings whose time has come (due_ts <= now). Order preserved."""
    now = time.time() if now is None else now
    return [p["id"] for p in pings if float(p.get("due_ts", 1e18)) <= now]


def _human_due(due_ts: int, now: Optional[float] = None) -> str:
    """'in 29m' / 'at 14:05' style label for the list view."""
    now = time.time() if now is None else now
    dt = due_ts - now
    if dt <= 0:
        return "due now"
    if dt < 3600:
        return f"in {int(dt // 60)}m"
    if dt < 86400:
        h, rem = divmod(int(dt), 3600)
        m = int(rem // 60)
        return (f"in {h}h{m:02d}" if m else f"in {h}h")
    d, rem = divmod(int(dt), 86400)
    h = int((rem % 86400) // 3600)
    return f"in {d}d{h:02d}" if h else f"in {d}d"


def render(pings: List[dict], now: Optional[float] = None) -> str:
    """Human list for /pings. Empty state is explicit, like todos."""
    if not pings:
        return "(no pings scheduled - use /ping or /every to add one)"
    lines = [f"{len(pings)} active"]
    now = time.time() if now is None else now
    for p in sorted(pings, key=lambda x: float(x.get("due_ts", 1e18))):
        kind = (f"every {p['interval_s'] // 60}m"
                if p["kind"] == "every" and p["interval_s"] >= 60
                else f"every {p['interval_s']}s" if p["kind"] == "every" else "once")
        lines.append(f"[{p['id']}] {kind:<12} {_human_due(int(p['due_ts']), now):<9} - {p['message']}")
    return "\n".join(lines)
