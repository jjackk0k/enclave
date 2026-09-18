"""Tools the model can call: read_file, write_file, edit_file, run_shell,
list_dir, search_files, web_search.

Every mutating or executing tool goes through an `approve(action, summary,
detail)` callback before anything happens; the caller (REPL) decides
y/n/always or auto-approves under --yolo. File writes and edits are
previewed as unified diffs. Paths resolve against the launch cwd and the
fully-resolved path is always shown in the approval prompt. Read-only
tools (read_file, list_dir, search_files, web_search) never prompt.
"""

from __future__ import annotations

import base64
import difflib
import fnmatch
import io
import os
import re
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from . import config
from .plugins import PluginRegistry
from .websearch import SEARCH_HEADERS, WebSearch, format_results

ApproveFn = Callable[[str, str, Optional[str]], bool]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".vs"}
READ_MAX_LINES = 2000
READ_MAX_CHARS = 100_000
SHELL_OUT_CAP = 8000
SEARCH_MAX_HITS = 200
FETCH_MAX_RAW = 200_000      # bytes read off the wire
FETCH_MAX_TEXT = 8_000       # chars returned to the model
FETCH_TIMEOUT = 20           # seconds
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
IMAGE_MAX_BYTES = 10 * 1024 * 1024
IMAGE_MAX_DIM = 1568         # longest side, when Pillow is importable


@dataclass
class ToolResult:
    ok: bool
    text: str
    # optional structured payload for rich UI rendering (web_search sets
    # {"query", "status", "provider", "results"} so the agent loop can draw
    # the search activity block instead of a one-line text preview)
    data: Optional[dict] = None


def make_diff(old: str, new: str, path: str) -> str:
    lines = difflib.unified_diff(
        old.splitlines(keepends=True),
        new.splitlines(keepends=True),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
    )
    return "".join(lines)


def _trunc(text: str, cap: int) -> str:
    if len(text) <= cap:
        return text
    return text[:cap] + f"\n... [truncated: {len(text) - cap} more chars]"


class _MainText(HTMLParser):
    """Readable main text out of an HTML page: skip script/style/nav and
    other chrome, keep block structure as line breaks, collapse whitespace."""

    SKIP_TAGS = {"script", "style", "noscript", "nav", "header", "footer",
                 "form", "svg", "select", "button"}
    BLOCK_TAGS = {"p", "div", "br", "li", "tr", "td", "section", "article",
                  "pre", "blockquote", "title",
                  "h1", "h2", "h3", "h4", "h5", "h6"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip = 0
        self.parts: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP_TAGS:
            self._skip += 1
        elif not self._skip and tag in self.BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP_TAGS:
            if self._skip:
                self._skip -= 1
        elif not self._skip and tag in self.BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        # source newlines inside a block are just whitespace in HTML
        if not self._skip and data.strip():
            self.parts.append(data.replace("\r", " ").replace("\n", " "))

    def text(self) -> str:
        lines = (" ".join(l.split()) for l in "".join(self.parts).splitlines())
        return "\n".join(l for l in lines if l)


_LOGIN_MARKERS = ("log in", "login", "sign in", "signin", "password")


def _looks_like_login_wall(html: str, text: str) -> bool:
    """Heuristic, honestly phrased upstream: little readable text plus the
    usual auth chrome means the real content is behind a login."""
    if len(text) > 400:
        return False
    low = html.lower()
    return ('type="password"' in low) or sum(m in low for m in _LOGIN_MARKERS) >= 2


def _pil():
    """Pillow only if already importable in this runtime - never a new dep."""
    try:
        from PIL import Image
        return Image
    except ImportError:
        return None


def _downscale_image(raw: bytes) -> Tuple[bytes, str]:
    """Shrink to IMAGE_MAX_DIM on the longest side when Pillow is available
    and the image is larger; otherwise (or on any PIL failure) the raw file
    goes through unchanged, with a note. Never silently drops the image."""
    Image = _pil()
    if Image is None:
        return raw, "Pillow not available - sent raw (10MB cap)"
    try:
        im = Image.open(io.BytesIO(raw))
        w, h = im.size
        if max(w, h) <= IMAGE_MAX_DIM:
            return raw, f"{w}x{h}"
        im.thumbnail((IMAGE_MAX_DIM, IMAGE_MAX_DIM))
        if im.mode not in ("RGB", "L", "P"):
            im = im.convert("RGB")
        buf = io.BytesIO()
        im.save(buf, format="PNG")
        return buf.getvalue(), f"downscaled {w}x{h} -> {im.size[0]}x{im.size[1]}"
    except Exception:
        return raw, "Pillow could not process it - sent raw"


class ToolExecutor:
    TOOL_NAMES = ("read_file", "write_file", "edit_file",
                  "run_shell", "list_dir", "search_files", "web_search",
                  "fetch_url", "glob", "grep", "read_image")

    def __init__(self, cwd: str, approve: ApproveFn,
                 shell_timeout: int = config.SHELL_DEFAULT_TIMEOUT) -> None:
        self.cwd = Path(cwd).resolve()
        self.approve = approve
        self.shell_timeout = shell_timeout
        self.websearch = WebSearch()
        # set by __main__ to client.supports_vision; None/False = the
        # endpoint is text-only and read_image says so honestly
        self.vision_probe: Optional[Callable[[], bool]] = None
        # extensions from plugins/; names colliding with built-ins are refused
        self.plugins = PluginRegistry(reserved=self.TOOL_NAMES)

    def begin_turn(self) -> None:
        """Reset per-turn tool budgets (web_search cap). The agent loop calls
        this at the start of every user turn."""
        self.websearch.begin_turn()

    # -- dispatch -------------------------------------------------------------
    def execute(self, name: str, args: dict) -> ToolResult:
        fn = {
            "read_file": self.read_file,
            "write_file": self.write_file,
            "edit_file": self.edit_file,
            "run_shell": self.run_shell,
            "list_dir": self.list_dir,
            "search_files": self.search_files,
            "web_search": self.web_search,
            "fetch_url": self.fetch_url,
            "glob": self.glob,
            "grep": self.grep,
            "read_image": self.read_image,
        }.get(name)
        if fn is None:
            plugin = self.plugins.plugins.get(name)
            if plugin is not None:
                return self._execute_plugin(plugin, args)
            known = list(self.TOOL_NAMES) + sorted(self.plugins.plugins)
            return ToolResult(False, f"Unknown tool '{name}'. Available: {', '.join(known)}")
        try:
            return fn(**args)
        except TypeError as exc:
            return ToolResult(False, f"Bad arguments for {name}: {exc}")
        except Exception as exc:
            return ToolResult(False, f"{name} failed: {type(exc).__name__}: {exc}")

    def _execute_plugin(self, plugin, args: dict) -> ToolResult:
        """Extensions get the built-in approval classes: write/shell prompt
        once up front (same y/n/always path), and run() also receives the
        approve callback for finer-grained prompts. A plugin exception is an
        honest tool failure, never a host crash."""
        if plugin.approval in ("write", "shell"):
            if not self.approve(plugin.approval,
                                f"Extension '{plugin.name}' ({plugin.path.name}) wants to run "
                                f"with approval class '{plugin.approval}': {plugin.description}",
                                None):
                return ToolResult(False, "Denied by user; the extension did not run.")
        unknown = [k for k in args if k not in plugin.args]
        if unknown:
            return ToolResult(False, f"{plugin.name}: unknown argument(s) "
                                     f"{unknown}; declared: {sorted(plugin.args)}")
        try:
            out = plugin.run(args, self.approve, str(self.cwd))
        except Exception as exc:
            return ToolResult(False, f"extension '{plugin.name}' failed: "
                                     f"{type(exc).__name__}: {exc}")
        return ToolResult(True, str(out))

    # -- helpers ---------------------------------------------------------------
    def _resolve(self, path: str) -> Path:
        p = Path(os.path.expandvars(os.path.expanduser(path)))
        if not p.is_absolute():
            p = self.cwd / p
        return p.resolve()

    def _iter_files(self, root: Path):
        """Every file under root, skipping dependency/VCS dirs (the same
        .gitignore-ish walk search_files has always used)."""
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                yield Path(dirpath) / fn

    # -- tools -------------------------------------------------------------------
    def read_file(self, path: str, offset: int = 1, limit: int = READ_MAX_LINES) -> ToolResult:
        p = self._resolve(path)
        if not p.is_file():
            return ToolResult(False, f"Not a file: {p}")
        raw = p.read_bytes()
        if len(raw) > READ_MAX_CHARS:
            raw = raw[:READ_MAX_CHARS]
            truncated = True
        else:
            truncated = False
        text = raw.decode("utf-8", "replace")
        lines = text.splitlines()
        start = max(1, int(offset))
        end = min(len(lines), start + max(1, min(int(limit), READ_MAX_LINES)) - 1)
        body = "\n".join(f"{i}\t{lines[i - 1]}" for i in range(start, end + 1))
        note = []
        if end < len(lines):
            note.append(f"showing lines {start}-{end} of {len(lines)}")
        if truncated:
            note.append("file exceeded 100KB, truncated")
        suffix = f"\n[{'; '.join(note)}]" if note else ""
        return ToolResult(True, f"# {p}{suffix}\n{body}")

    def write_file(self, path: str, content: str) -> ToolResult:
        p = self._resolve(path)
        old = p.read_text(encoding="utf-8", errors="replace") if p.exists() else None
        n_lines = content.count("\n") + (1 if content else 0)
        if old is None:
            summary = f"Create new file {p} ({n_lines} lines)"
            detail = make_diff("", content, str(p))
        else:
            if old == content:
                return ToolResult(True, f"No change: {p} already has exactly this content.")
            added = sum(1 for l in difflib.unified_diff(old.splitlines(), content.splitlines()) if l.startswith("+") and not l.startswith("+++"))
            removed = sum(1 for l in difflib.unified_diff(old.splitlines(), content.splitlines()) if l.startswith("-") and not l.startswith("---"))
            summary = f"Overwrite {p} (+{added}/-{removed} lines)"
            detail = make_diff(old, content, str(p))
        if not self.approve("write", summary, detail):
            return ToolResult(False, "Denied by user; file was NOT written.")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return ToolResult(True, f"Wrote {p} ({n_lines} lines, {len(content)} chars).")

    def edit_file(self, path: str, old: str, new: str, replace_all: bool = False) -> ToolResult:
        p = self._resolve(path)
        if not p.is_file():
            return ToolResult(False, f"Not a file: {p}")
        text = p.read_text(encoding="utf-8", errors="replace")
        count = text.count(old)
        if count == 0:
            return ToolResult(False, f"No exact match for `old` in {p}. Re-read the file and retry with the exact text.")
        if count > 1 and not replace_all:
            return ToolResult(False, f"`old` matches {count} times in {p}; it must be unique. Add more surrounding context or set replace_all=true.")
        updated = text.replace(old, new) if replace_all else text.replace(old, new, 1)
        summary = f"Edit {p} ({count} replacement{'s' if count > 1 else ''})"
        detail = make_diff(text, updated, str(p))
        if not self.approve("write", summary, detail):
            return ToolResult(False, "Denied by user; file was NOT edited.")
        p.write_text(updated, encoding="utf-8")
        return ToolResult(True, f"Edited {p}: replaced {count} occurrence(s).")

    def run_shell(self, command: str, timeout: Optional[int] = None) -> ToolResult:
        t = min(int(timeout or self.shell_timeout), config.SHELL_MAX_TIMEOUT)
        summary = f"Run shell command (cwd={self.cwd}, timeout={t}s):\n  {command}"
        if not self.approve("shell", summary, None):
            return ToolResult(False, "Denied by user; command was NOT run.")
        shell = ["cmd", "/c", command] if os.name == "nt" else ["sh", "-c", command]
        popen_kwargs: dict = dict(cwd=str(self.cwd), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, errors="replace")
        if os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen(shell, **popen_kwargs)
        try:
            stdout, stderr = proc.communicate(timeout=t)
        except subprocess.TimeoutExpired:
            # A bare proc.kill() here only kills cmd.exe/sh itself. Any
            # grandchild it spawned (a hung python.exe, a stuck network
            # call, antivirus holding a new interpreter) survives and
            # keeps the stdout/stderr pipes open - so the communicate()
            # that follows would block with NO timeout of its own, and
            # this tool call never returns at all. This is the actual
            # cause of the observed hang (Esc does nothing, no timeout
            # message ever prints): Esc only aborts the model's HTTP
            # stream, and there is no code path back here to report
            # anything until the pipe closes, which it never does.
            self._kill_tree(proc.pid)
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()  # last resort - never let one stuck command hang the turn
                stdout, stderr = "", ""
            return ToolResult(False, f"Command timed out after {t}s and was killed, "
                                      f"including any child processes it spawned.")
        out = ""
        if stdout:
            out += stdout
        if stderr:
            out += ("\n[stderr]\n" if out else "[stderr]\n") + stderr
        out = _trunc(out.strip(), SHELL_OUT_CAP)
        return ToolResult(proc.returncode == 0,
                          f"exit code {proc.returncode}\n{out or '(no output)'}")

    @staticmethod
    def _kill_tree(pid: int) -> None:
        """Kill pid and every descendant it spawned. Needed because a plain
        proc.kill() only terminates the immediate cmd.exe/sh - a grandchild
        process keeps running and holds the output pipe open, which is
        exactly what causes run_shell to hang past its own timeout."""
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           capture_output=True)
        else:
            import signal
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except ProcessLookupError:
                pass  # already gone

    def list_dir(self, path: str = ".") -> ToolResult:
        p = self._resolve(path)
        if not p.is_dir():
            return ToolResult(False, f"Not a directory: {p}")
        entries = sorted(p.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower()))
        rows = []
        for e in entries[:500]:
            if e.is_dir():
                rows.append(f"  <dir>  {e.name}/")
            else:
                try:
                    size = e.stat().st_size
                except OSError:
                    size = -1
                rows.append(f"  {size:>10}  {e.name}")
        more = f"\n... [{len(entries) - 500} more entries]" if len(entries) > 500 else ""
        return ToolResult(True, f"# {p}\n" + ("\n".join(rows) or "(empty)") + more)

    def search_files(self, pattern: str, path: str = ".",
                     content: Optional[str] = None) -> ToolResult:
        root = self._resolve(path)
        if not root.is_dir():
            return ToolResult(False, f"Not a directory: {root}")
        rx = None
        if content:
            try:
                rx = re.compile(content)
            except re.error as exc:
                return ToolResult(False, f"Bad content regex: {exc}")
        hits: List[str] = []
        for full in self._iter_files(root):
            if not fnmatch.fnmatch(full.name.lower(), pattern.lower()):
                continue
            rel = full.relative_to(root)
            if rx is None:
                hits.append(str(rel))
            else:
                try:
                    if full.stat().st_size > 2_000_000:
                        continue
                    for i, line in enumerate(full.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                        if rx.search(line):
                            hits.append(f"{rel}:{i}: {line.strip()[:160]}")
                            break
                except OSError:
                    continue
            if len(hits) >= SEARCH_MAX_HITS:
                break
        note = f" (capped at {SEARCH_MAX_HITS})" if len(hits) >= SEARCH_MAX_HITS else ""
        return ToolResult(True, f"{len(hits)} match(es) for {pattern!r} under {root}{note}\n"
                                + ("\n".join(hits) or "(none)"))

    def glob(self, pattern: str, path: str = ".") -> ToolResult:
        """Find files by glob pattern. `*.py` matches at any depth; a pattern
        containing a slash (e.g. 'src/**/*.py') matches the relative path."""
        root = self._resolve(path)
        if not root.is_dir():
            return ToolResult(False, f"Not a directory: {root}")
        pat = pattern.lower().replace("\\", "/")
        hits: List[str] = []
        for full in self._iter_files(root):
            rel = full.relative_to(root)
            if fnmatch.fnmatch(full.name.lower(), pat) or \
                    fnmatch.fnmatch(rel.as_posix().lower(), pat):
                hits.append(str(rel))
            if len(hits) >= SEARCH_MAX_HITS:
                break
        note = f" (capped at {SEARCH_MAX_HITS})" if len(hits) >= SEARCH_MAX_HITS else ""
        return ToolResult(True, f"{len(hits)} file(s) matching {pattern!r} under {root}{note}\n"
                                + ("\n".join(sorted(hits)) or "(none)"))

    def grep(self, regex: str, path: str = ".", glob: str = "*") -> ToolResult:
        """Regex content search: every matching line as path:line: text,
        capped at SEARCH_MAX_HITS. Files over 2MB are skipped."""
        root = self._resolve(path)
        try:
            rx = re.compile(regex)
        except re.error as exc:
            return ToolResult(False, f"Bad grep regex: {exc}")
        files = [root] if root.is_file() else (self._iter_files(root) if root.is_dir()
                                               else None)
        if files is None:
            return ToolResult(False, f"Not a file or directory: {root}")
        hits: List[str] = []
        for full in files:
            if not fnmatch.fnmatch(full.name.lower(), glob.lower()):
                continue
            try:
                if full.stat().st_size > 2_000_000:
                    continue
                lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            rel = full.relative_to(root) if root.is_dir() else full.name
            for i, line in enumerate(lines, 1):
                if rx.search(line):
                    hits.append(f"{rel}:{i}: {line.strip()[:160]}")
                    if len(hits) >= SEARCH_MAX_HITS:
                        break
            if len(hits) >= SEARCH_MAX_HITS:
                break
        note = f" (capped at {SEARCH_MAX_HITS})" if len(hits) >= SEARCH_MAX_HITS else ""
        return ToolResult(True, f"{len(hits)} line(s) matching /{regex}/ under {root}{note}\n"
                                + ("\n".join(hits) or "(none)"))

    def fetch_url(self, url: str) -> ToolResult:
        """Fetch one http/https page and return its readable main text.
        Read-only public-internet fetch, same approval class as web_search."""
        url = (url or "").strip()
        if not url.startswith(("http://", "https://")):
            return ToolResult(False, f"fetch_url only fetches http/https URLs "
                                     f"(got {url!r}).")
        req = urllib.request.Request(url, headers=SEARCH_HEADERS)
        try:
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                final_url = resp.geturl()  # after redirects
                ctype = resp.headers.get("Content-Type", "")
                raw = resp.read(FETCH_MAX_RAW + 1)
        except urllib.error.HTTPError as exc:
            return ToolResult(False, f"fetch_url got HTTP {exc.code} "
                                     f"({exc.reason}) from {url}")
        except Exception as exc:
            return ToolResult(False, f"fetch_url could not reach {url}: "
                                     f"{type(exc).__name__}: {exc}")
        notes = []
        if len(raw) > FETCH_MAX_RAW:
            raw = raw[:FETCH_MAX_RAW]
            notes.append(f"page exceeded {FETCH_MAX_RAW // 1000}KB - only the "
                         "first part was read")
        base = ctype.split(";")[0].strip().lower()
        if base and not (base.startswith("text/")
                         or base in ("application/json", "application/xhtml+xml",
                                     "application/xml")):
            return ToolResult(False, f"fetch_url got content-type {ctype!r} from {url} - "
                                     f"not readable text ({len(raw):,} bytes discarded). "
                                     "Download it with a shell tool if you need the bytes.")
        charset = "utf-8"
        m = re.search(r"charset=([\w.-]+)", ctype)
        if m:
            charset = m.group(1)
        html = raw.decode(charset, "replace")
        if "html" in base:
            parser = _MainText()
            parser.feed(html)
            text = parser.text()
            if _looks_like_login_wall(html, text):
                notes.append("this page looks like a login wall - the real "
                             "content is behind authentication")
        else:
            text = "\n".join(l for l in
                             (" ".join(l.split()) for l in html.splitlines()) if l)
        if len(text) > FETCH_MAX_TEXT:
            text = text[:FETCH_MAX_TEXT]
            notes.append(f"text truncated to {FETCH_MAX_TEXT:,} chars")
        head = f"# {final_url}"
        if final_url != url:
            head += f" (redirected from {url})"
        head += f" [{base or 'unknown content-type'}, {len(raw):,} bytes]"
        if notes:
            head += "\n[" + "; ".join(notes) + "]"
        return ToolResult(True, head + "\n" + (text or "(no readable text on the page)"))

    def read_image(self, path: str) -> ToolResult:
        """Attach an image from disk to the conversation as a base64 data URL
        (the agent loop adds it to the tool-results message). Honest refusal
        when the serving endpoint is text-only - the base64 is never dumped
        into context as text."""
        p = self._resolve(path)
        if not p.is_file():
            return ToolResult(False, f"Not a file: {p}")
        ext = p.suffix.lower()
        if ext not in IMAGE_EXTS:
            return ToolResult(False, f"read_image handles {', '.join(sorted(IMAGE_EXTS))} "
                                     f"- {p.name!r} is not a supported image.")
        raw = p.read_bytes()
        if len(raw) > IMAGE_MAX_BYTES:
            return ToolResult(False, f"{p.name} is {len(raw) / 1e6:.1f}MB - over the "
                                     f"{IMAGE_MAX_BYTES // (1024 * 1024)}MB image cap. "
                                     "Downscale or convert it first.")
        if self.vision_probe is None or not self.vision_probe():
            return ToolResult(False, "Vision is not supported by the serving endpoint "
                                     "(text-only model or the probe failed), so the image "
                                     "was NOT sent. Describe the relevant detail in text, "
                                     "or read text out of the file another way.")
        sent, note = _downscale_image(raw)
        mime = "image/png" if "downscaled" in note else \
            {".png": "image/png", ".gif": "image/gif", ".webp": "image/webp",
             ".bmp": "image/bmp"}.get(ext, "image/jpeg")
        dataurl = f"data:{mime};base64," + base64.b64encode(sent).decode()
        return ToolResult(True,
                          f"[image attached: {p} - {note}, {len(sent):,} bytes sent]",
                          data={"image_dataurl": dataurl})

    def web_search(self, query: str) -> ToolResult:
        # Read-only public-internet fetch over urllib - no approval, like
        # read_file/list_dir. Provider chain + cache + per-turn cap live in
        # websearch.py; this is just the tool-facing wrapper. `data` feeds
        # the UI's search activity block (agent.py); `text` feeds the model.
        query = (query or "").strip()
        if not query:
            return ToolResult(False, "web_search needs a non-empty query.",
                              data={"query": "", "status": "invalid",
                                    "provider": None, "results": None})
        status, results, provider = self.websearch.search(query)
        meta = {"query": query, "status": status,
                "provider": provider, "results": results}
        if status == "capped":
            return ToolResult(
                False, f"Per-turn web search cap reached "
                       f"({config.SEARCH_MAX_PER_TURN} searches). "
                       f"Answer with what you have, or search next turn.",
                data=meta)
        if status == "limited":
            return ToolResult(
                False, "Web search unavailable right now: every provider "
                       "(ddg-lite, ddg-html, bing, mojeek) failed, was "
                       "rate-limited, or returned a degraded page. Try a "
                       "different query or try again later.",
                data=meta)
        if not results:
            return ToolResult(True, f"No results found for {query!r} (via {provider}).",
                              data=meta)
        return ToolResult(True, format_results(query, results, provider), data=meta)


TOOL_SPEC_FOR_PROMPT = """\
Available tools (call them with ```tool fenced JSON blocks):
- read_file(path, offset=1, limit=2000)      read a text file with line numbers
- write_file(path, content)                  create or fully overwrite a file (user approves a diff)
- edit_file(path, old, new, replace_all=false) exact-match replacement; old must be unique unless replace_all (user approves a diff)
- run_shell(command, timeout=60)             run a Windows cmd command in the working directory (user approves)
- list_dir(path=".")                         list a directory with sizes
- search_files(pattern, path=".", content=null) glob filenames (e.g. "*.py"); optional regex to also match file contents
- glob(pattern, path=".")                    find files by glob pattern; "*.py" matches any depth, "src/**/*.py" matches paths (read-only)
- grep(regex, path=".", glob="*")            search file contents; every matching line as path:line: text (read-only)
- web_search(query)                        search the public web (no approval); use when the request needs current/external facts; prefer 1-3 focused queries; cite sources
- fetch_url(url)                           fetch one http/https page and return its readable main text (read-only)
- read_image(path)                         look at an image file (png/jpg/gif/webp/bmp) when the endpoint supports vision
- update_todos(todos=[{content, status}])    replace the session task list; status: pending|in_progress|done (session state, no approval)

BIG FILES: over ~100 lines, write in parts - write_file the first part, then append with
edit_file (old = the file's current last line, new = that same line plus the next chunk).
One giant JSON string is how writes get truncated.
"""
