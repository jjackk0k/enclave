"""Tool extensions: drop-in plugins the model (or the owner) can add.

One .py file per extension in plugins/ (next to the package, or next to the
exe when frozen). Format:

    TOOL = {
        "name": "word_count",          # required, ^[a-z][a-z0-9_]*$
        "description": "count words in a file",   # required, non-empty
        "args": {"path": {"type": "string",      # required; {} allowed
                          "description": "file to count"}},
        "approval": "read",            # optional: "read" (default) | "write" | "shell"
    }

    def run(args, approve, cwd):       # required; return text for the model
        ...
        return "42 words"

Validation is strict: a name colliding with a built-in tool or another
plugin, missing fields, bad arg types, and import errors are all REFUSED and
reported (via /ext) - a broken plugin never crashes the host. write/shell
class extensions prompt through the same approval path as the built-ins
before they run, and also receive the `approve` callback for finer-grained
prompts inside run().  is the agent's working directory - resolve relative paths against it.
"""

from __future__ import annotations

import importlib.util
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import config


class PluginError(Exception):
    pass


_NAME_RX = re.compile(r"^[a-z][a-z0-9_]*$")
_ARG_TYPES = {"string", "integer", "number", "boolean"}
_APPROVALS = ("read", "write", "shell")


@dataclass
class Plugin:
    name: str
    description: str
    args: dict
    approval: str
    path: Path
    run: Callable


def _load_one(path: Path) -> Plugin:
    """Import and validate one plugin file; PluginError on any defect."""
    try:
        spec = importlib.util.spec_from_file_location(f"spark_ext_{path.stem}", path)
        if spec is None or spec.loader is None:
            raise PluginError("could not build an import spec")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except PluginError:
        raise
    except Exception as exc:
        raise PluginError(f"import failed: {type(exc).__name__}: {exc}") from exc

    tool = getattr(mod, "TOOL", None)
    if not isinstance(tool, dict):
        raise PluginError("missing TOOL dict")
    name = tool.get("name")
    if not isinstance(name, str) or not _NAME_RX.match(name):
        raise PluginError("TOOL['name'] must be a snake_case string (a-z, 0-9, _)")
    description = tool.get("description")
    if not isinstance(description, str) or not description.strip():
        raise PluginError("TOOL['description'] must be a non-empty string")
    args = tool.get("args")
    if not isinstance(args, dict):
        raise PluginError("TOOL['args'] must be a dict (use {} for no arguments)")
    for arg_name, spec_d in args.items():
        if not isinstance(arg_name, str) or not arg_name:
            raise PluginError("TOOL['args'] keys must be non-empty strings")
        if not isinstance(spec_d, dict) or spec_d.get("type") not in _ARG_TYPES:
            raise PluginError(
                f"TOOL['args']['{arg_name}'] needs a 'type' of "
                + "/".join(sorted(_ARG_TYPES)))
    approval = tool.get("approval", "read")
    if approval not in _APPROVALS:
        raise PluginError(f"TOOL['approval'] must be one of {_APPROVALS}")
    run = getattr(mod, "run", None)
    if not callable(run):
        raise PluginError("missing a callable run(args, approve, cwd)")
    return Plugin(name=name, description=description.strip(), args=args,
                  approval=approval, path=path, run=run)


class PluginRegistry:
    """plugins/ scanner. load() rescans from scratch (used by /ext reload);
    refused files land in `errors` with their reason, never raise."""

    def __init__(self, root: Optional[Path] = None,
                 reserved: Tuple[str, ...] = ()) -> None:
        self.root = Path(root) if root else config.PLUGINS_DIR
        self.reserved = set(reserved)
        self.plugins: Dict[str, Plugin] = {}
        self.errors: List[Tuple[str, str]] = []
        self.load()

    def load(self) -> None:
        self.plugins = {}
        self.errors = []
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            files = sorted(self.root.glob("*.py"))
        except OSError as exc:
            self.errors.append((str(self.root), f"cannot scan: {exc}"))
            return
        for path in files:
            if path.name.startswith("_"):
                continue  # convention: _foo.py is parked, not loaded
            try:
                plugin = _load_one(path)
            except PluginError as exc:
                self.errors.append((path.name, str(exc)))
                continue
            if plugin.name in self.reserved:
                self.errors.append((path.name,
                                    f"name '{plugin.name}' collides with a built-in tool"))
                continue
            if plugin.name in self.plugins:
                self.errors.append((path.name,
                                    f"name '{plugin.name}' already provided by "
                                    f"{self.plugins[plugin.name].path.name}"))
                continue
            self.plugins[plugin.name] = plugin

    def spec_text(self) -> str:
        """Extra lines for the system prompt's tool spec (empty when none)."""
        if not self.plugins:
            return ""
        lines = ["", "Extension tools (plugins/, same ```tool protocol):"]
        for p in sorted(self.plugins.values(), key=lambda p: p.name):
            sig = ", ".join(f"{k}: {v['type']}" for k, v in p.args.items())
            lines.append(f"- {p.name}({sig})  {p.description} "
                         f"[extension, approval: {p.approval}]")
        return "\n".join(lines) + "\n"
