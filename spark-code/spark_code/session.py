"""Session persistence: JSONL event logs under spark-code/sessions/.

Every user/assistant message, compaction, clear, and token-usage sample is
appended as one JSON line, so closing the terminal at any point loses
nothing. /resume replays the event log to rebuild the full context.
Nothing is written anywhere on the Spark - the files live on the PC only.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Union

from . import config


@dataclass
class SessionInfo:
    id: str
    path: Path
    cwd: str
    created: float
    model: str
    n_messages: int
    last_ts: float


class Session:
    def __init__(self, store: "SessionStore", session_id: str, path: Path,
                 meta: dict, messages: List[dict], tot_prompt: int, tot_completion: int,
                 todos: Optional[List[dict]] = None, last_ctx_used: int = 0,
                 pings: Optional[List[dict]] = None):
        self.store = store
        self.id = session_id
        self.path = path
        self.meta = meta
        self.messages: List[dict] = messages
        self.total_prompt_tokens = tot_prompt
        self.total_completion_tokens = tot_completion
        self.todos: List[dict] = list(todos or [])
        # owner-set reminders/schedules (pings.py); independent of /clear so a
        # context wipe never drops your scheduled pings - they survive like todos.
        self.pings: List[dict] = list(pings or [])
        # last real per-slot context fill (prompt+completion of the most recent
        # stream); 0 = unknown (fresh session, or just after compact/clear)
        self.last_ctx_used = last_ctx_used

    # -- live appends ---------------------------------------------------------
    def _append(self, event: dict) -> None:
        event.setdefault("ts", time.time())
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
            fh.flush()  # push past the OS page cache NOW: a hard kill or power
                        # loss must never lose an already-shown message

    def add_message(self, role: str, content: Union[str, List[dict]]) -> None:
        """content is text, or a multipart list when a turn attached an image
        (read_image) - JSONL round-trips either shape."""
        self.messages.append({"role": role, "content": content})
        self._append({"t": "msg", "role": role, "content": content})

    def add_usage(self, prompt_tokens: int, completion_tokens: int) -> None:
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        self.last_ctx_used = prompt_tokens + completion_tokens
        self._append({"t": "usage", "prompt": prompt_tokens, "completion": completion_tokens})

    def set_todos(self, items: List[dict]) -> None:
        self.todos = list(items)
        self._append({"t": "todos", "items": items})

    def set_pings(self, items: List[dict]) -> None:
        """Persist the full ping/schedule list (validated by pings.validate_pings).
        Stored as one event so /resume rebuilds it exactly; independent of clear()."""
        self.pings = list(items)
        self._append({"t": "ping", "pings": items})

    def set_effort(self, mode: str) -> None:
        """Persist the current effort tier (fast/standard/reasoning). Stored as one
        event so /resume restores it exactly - otherwise a reopened session silently
        falls back to config.DEFAULT_EFFORT and the owner's chosen mode is lost."""
        self.meta["effort"] = mode
        self._append({"t": "effort", "mode": mode})

    def apply_compact(self, summary: str, kept: List[dict]) -> None:
        self.messages = [{"role": "user", "content": summary}] + list(kept)
        self.last_ctx_used = 0  # unknown until the next stream reports real usage
        self._append({"t": "compact", "summary": summary, "kept": kept})

    def clear(self) -> None:
        self.messages = []
        self.todos = []
        self.last_ctx_used = 0
        self._append({"t": "clear"})

    def set_model(self, model: str) -> None:
        self.meta["model"] = model
        self._append({"t": "model", "model": model})

    def info(self) -> SessionInfo:
        return SessionInfo(
            id=self.id, path=self.path, cwd=self.meta.get("cwd", "?"),
            created=self.meta.get("created", 0), model=self.meta.get("model", "?"),
            n_messages=len(self.messages),
            last_ts=self.path.stat().st_mtime if self.path.exists() else 0,
        )


class SessionStore:
    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root) if root else config.SESSIONS_DIR
        self.root.mkdir(parents=True, exist_ok=True)

    # -- creation ---------------------------------------------------------------
    def create(self, cwd: str, model: str) -> Session:
        sid = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)
        path = self.root / f"{sid}.jsonl"
        meta = {"cwd": cwd, "created": time.time(), "model": model, "app": config.APP_NAME}
        session = Session(self, sid, path, meta, [], 0, 0)
        session._append({"t": "meta", **meta})
        return session

    # -- loading ------------------------------------------------------------------
    def load(self, session_id: str) -> Session:
        path = self._find(session_id)
        if path is None:
            raise KeyError(f"No saved session matches '{session_id}'. Try /sessions to list them.")
        meta: dict = {}
        messages: List[dict] = []
        todos: List[dict] = []
        pings: List[dict] = []
        tot_p = tot_c = 0
        last_ctx = 0
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue  # skip a torn final line from a hard kill
                t = ev.get("t")
                if t == "meta":
                    meta.update({k: v for k, v in ev.items() if k not in ("t", "ts")})
                elif t == "msg":
                    messages.append({"role": ev["role"], "content": ev["content"]})
                elif t == "compact":
                    messages = [{"role": "user", "content": ev["summary"]}] + list(ev.get("kept", []))
                    last_ctx = 0
                elif t == "clear":
                    messages = []
                    todos = []
                    last_ctx = 0
                elif t == "usage":
                    tot_p += int(ev.get("prompt", 0))
                    tot_c += int(ev.get("completion", 0))
                    last_ctx = int(ev.get("prompt", 0)) + int(ev.get("completion", 0))
                elif t == "todos":
                    items = ev.get("items")
                    if isinstance(items, list):
                        todos = items
                elif t == "ping":
                    plist = ev.get("pings")
                    if isinstance(plist, list):
                        pings = plist
                elif t == "effort":
                    mode = ev.get("mode")
                    if isinstance(mode, str) and mode:
                        meta["effort"] = mode
                elif t == "model":
                    meta["model"] = ev.get("model", meta.get("model"))
        return Session(self, path.stem, path, meta, messages, tot_p, tot_c,
                       todos=todos, last_ctx_used=last_ctx, pings=pings)

    def _find(self, session_id: str) -> Optional[Path]:
        exact = self.root / f"{session_id}.jsonl"
        if exact.exists():
            return exact
        matches = sorted(self.root.glob(f"{session_id}*.jsonl"))
        if len(matches) == 1:
            return matches[0]
        matches = sorted(self.root.glob(f"*{session_id}*.jsonl"))
        if len(matches) == 1:
            return matches[0]
        return None

    # -- listing -------------------------------------------------------------------
    def list(self) -> List[SessionInfo]:
        infos = []
        for path in sorted(self.root.glob("*.jsonl")):
            try:
                infos.append(self.load(path.stem).info())
            except Exception:
                continue
        infos.sort(key=lambda i: i.last_ts, reverse=True)
        return infos

    def latest_id(self) -> Optional[str]:
        infos = self.list()
        return infos[0].id if infos else None
