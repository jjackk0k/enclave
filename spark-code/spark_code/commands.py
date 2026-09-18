"""Slash-command registry + the pure matching logic behind the live menu
and TAB completion. Kept side-effect free so it is fully unit-testable;
the REPL help text is generated from this table so docs never drift.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass(frozen=True)
class CommandSpec:
    name: str          # "/status"
    args: str          # "" | "<id>" | "[fast|reasoning]"
    description: str

    @property
    def takes_args(self) -> bool:
        return bool(self.args)

    def usage(self) -> str:
        """Canonical filled form: '/effort ' (args expected) or '/status'."""
        return self.name + (" " if self.takes_args else "")


COMMANDS: List[CommandSpec] = [
    CommandSpec("/help", "", "list all commands"),
    CommandSpec("/status", "", "model, context, speed, effort, session, tunnel"),
    CommandSpec("/compact", "", "summarize history via the model, keep recent turns verbatim"),
    CommandSpec("/clear", "", "wipe this session's context (event is logged)"),
    CommandSpec("/sessions", "", "list saved sessions on disk"),
    CommandSpec("/resume", "<id>", "restore a saved session with full context"),
    CommandSpec("/new", "", "start a fresh session"),
    CommandSpec("/model", "", "list models on the server and switch"),
    CommandSpec("/effort", "[fast|standard|reasoning]",
                "switch tier: Fast (direct, 4k) · Standard (thinking, 8k, default) · Reasoning (deep thinking, 32k)"),
    CommandSpec("/fast", "", "alias for /effort fast"),
    CommandSpec("/standard", "", "alias for /effort standard"),
    CommandSpec("/reasoning", "", "alias for /effort reasoning"),
    CommandSpec("/thinking", "[on|off]", "turn the model's reasoning on/off (default on)"),
    CommandSpec("/think", "[on|off]", "expand/collapse the thinking pane; expanding re-shows the last thinking"),
    CommandSpec("/cost", "", "token totals: $0.00 local + hypothetical cloud equivalent"),
    CommandSpec("/todo", "", "show the task list the model maintains for this session"),
    CommandSpec("/ext", "[reload]", "list tool extensions from plugins/; reload rescans"),
    CommandSpec("/autocontinue", "[on|off]", "auto-nudge the model when a reply looks cut off (default on)"),
    CommandSpec("/ping", "<when> <message>", "one-shot reminder: fires as an agent turn at that time ('30m', '2h', or HH:MM) then is removed"),
    CommandSpec("/every", "<interval> <message>", "recurring reminder (e.g. every 30m); refires each period until /pings clears it"),
    CommandSpec("/pings", "[clear|cancel <id>]", "list scheduled reminders; 'clear' removes all, 'cancel <id>' one"),
    CommandSpec("/menu", "", "save and exit to the spark-code menu window"),
    CommandSpec("/yolo", "", "toggle auto-approve for writes and shell commands"),
    CommandSpec("/reconnect", "", "re-open the SSH tunnel if it died"),
    CommandSpec("/exit", "", "quit (offers to close the tunnel if we started it)"),
]

_ALIASES = {"/quit": "/exit"}


def canonical(name: str) -> str:
    return _ALIASES.get(name, name)


def filter_commands(buffer: str) -> List[CommandSpec]:
    """Menu contents for a partially-typed buffer.

    Only active while typing the command token itself ('/stat'); once a
    space is typed we are in argument territory and the menu closes.
    """
    if not buffer.startswith("/") or " " in buffer:
        return []
    token = buffer.lower()
    if token == "/":
        return list(COMMANDS)
    return [c for c in COMMANDS if c.name.startswith(token)]


def tab_complete(buffer: str) -> Tuple[str, List[CommandSpec]]:
    """TAB behavior: single match fills the canonical usage; multiple
    matches extend to the longest common prefix and keep the menu open."""
    matches = filter_commands(buffer)
    if not matches:
        return buffer, []
    if len(matches) == 1:
        return matches[0].usage(), matches
    names = [c.name for c in matches]
    common = names[0]
    for n in names[1:]:
        while not n.startswith(common):
            common = common[:-1]
    typed = buffer.split()[0] if buffer else "/"
    if len(common) > len(typed):
        return common, matches
    return buffer, matches


def help_text() -> str:
    width = max(len(c.name) + len(c.args) for c in COMMANDS) + 1
    lines = ["Commands:"]
    for c in COMMANDS:
        label = (c.name + (" " + c.args if c.args else "")).ljust(width)
        lines.append(f"  {label} {c.description}")
    lines.append("")
    lines.append("Anything else is sent to the model. The agent works in the directory")
    lines.append("you launched from; every file write shows a diff and every shell command")
    lines.append("is shown before it runs (y / n / always).")
    return "\n".join(lines)
