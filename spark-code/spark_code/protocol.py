"""Fenced-JSON tool-call protocol.

The model is instructed to emit tool calls as fenced blocks anywhere in
its reply:

    ```tool
    {"tool": "read_file", "args": {"path": "README.md"}}
    ```

(`tool_call` is accepted as an alias fence language.)

Some models (this project has seen it live with Hermes/Qwen-style chat
templates) ignore that instruction under load and fall back to their own
built-in native tool-call syntax instead:

    <tool_call>
    <function=read_file>
    <parameter=path>README.md</parameter>
    </function>
    </tool_call>

Before this was handled, that whole block was invisible to the parser (it
contains no ``` fence), so `filt.calls` stayed empty with no ParseFailure
either - the agent loop treated it as a plain-text final answer, and
auto-continue kept nudging "continue" forever, producing an infinite
repeat loop. ToolStreamFilter now recognizes both forms; a native XML
block is normalized into the same ToolCall structure and recorded in
`salvaged` (not `failures`) so it's surfaced honestly without costing a
correction round-trip.

ToolStreamFilter consumes streamed chunks incrementally: ordinary text is
passed through for display, tool blocks are captured, parsed strictly, and
never shown to the user. Malformed blocks are recorded as ParseFailure so
the agent loop can send one retry-with-correction message and honestly
log the failure.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

TOOL_FENCE_LANGS = ("tool", "tool_call")

# Native Hermes/Qwen-style tool-call syntax, accepted alongside the fence
# (see module docstring - this is the format the model actually falls
# back to under load, regardless of what the system prompt asks for).
XML_OPEN = "<tool_call>"
XML_CLOSE = "</tool_call>"


@dataclass
class ToolCall:
    tool: str
    args: dict
    raw: str
    # True when the call was recovered from an unterminated JSON string:
    # the streamed content may be cut off - the agent loop tells both the
    # user (UI warn) and the model (result text) to verify and complete it
    truncated: bool = False


@dataclass
class ParseFailure:
    raw: str
    error: str


def _looks_like_fence_start(buf: str) -> int:
    """Length of trailing text that could be the start of a ``` fence."""
    if buf.endswith("``"):
        return 2
    if buf.endswith("`"):
        return 1
    return 0


def _looks_like_partial_tag(buf: str, tag: str) -> int:
    """Length of trailing text that could be the start of `tag` (e.g. a
    chunk boundary landing mid-'<tool_call>'). Mirrors _looks_like_fence_start
    for the XML form so streaming never emits a tag opener as visible text."""
    for n in range(min(len(buf), len(tag) - 1), 0, -1):
        if tag.startswith(buf[-n:]):
            return n
    return 0


class ToolStreamFilter:
    """Incrementally split a streamed reply into display text + tool calls."""

    def __init__(self) -> None:
        self.buf = ""
        self.calls: List[ToolCall] = []
        self.failures: List[ParseFailure] = []
        self.salvaged: List[ParseFailure] = []  # malformed blocks we recovered a call from
        self.raw_text_parts: List[str] = []  # every chunk, verbatim

    # -- streaming API ------------------------------------------------------
    def feed(self, chunk: str) -> str:
        """Feed a streamed chunk; return text safe to display right now."""
        self.raw_text_parts.append(chunk)
        self.buf += chunk
        return self._process(final=False)

    def finish(self) -> str:
        """Flush at end of stream; salvage or report a dangling tool block."""
        return self._process(final=True)

    @property
    def raw_text(self) -> str:
        return "".join(self.raw_text_parts)

    # -- internals ----------------------------------------------------------
    def _process(self, final: bool) -> str:
        out: List[str] = []
        while True:
            idx_fence = self.buf.find("```")
            idx_xml = self.buf.find(XML_OPEN)
            if idx_xml != -1 and (idx_fence == -1 or idx_xml < idx_fence):
                idx, is_xml = idx_xml, True
            else:
                idx, is_xml = idx_fence, False

            if idx == -1:
                hold = 0
                if not final:
                    hold = max(_looks_like_fence_start(self.buf),
                               _looks_like_partial_tag(self.buf, XML_OPEN))
                emit = self.buf[: len(self.buf) - hold] if hold else self.buf
                self.buf = self.buf[len(emit):]
                if emit:
                    out.append(emit)
                break

            if idx > 0:
                out.append(self.buf[:idx])
                self.buf = self.buf[idx:]

            if is_xml:
                close = self.buf.find(XML_CLOSE)
                if close == -1:
                    if final:
                        self._parse_xml_block(self.buf[len(XML_OPEN):])
                        self.buf = ""
                    break  # wait for the closing tag
                self._parse_xml_block(self.buf[len(XML_OPEN):close])
                self.buf = self.buf[close + len(XML_CLOSE):]
                continue  # keep scanning the rest of the buffer

            # buf now starts with ```; need the opener line to classify it
            nl = self.buf.find("\n")
            if nl == -1:
                if final:
                    out.append(self.buf)  # dangling backticks are just text
                    self.buf = ""
                break

            opener = self.buf[3:nl].strip().lower()
            if opener in TOOL_FENCE_LANGS:
                close = self.buf.find("```", nl + 1)
                if close == -1:
                    if final:
                        self._parse_block(self.buf[nl + 1:])
                        self.buf = ""
                    break  # wait for the closing fence
                self._parse_block(self.buf[nl + 1:close])
                self.buf = self.buf[close + 3:]
                # keep scanning the rest of the buffer
            else:
                # ordinary code fence - pass the opener through as text
                out.append(self.buf[: nl + 1])
                self.buf = self.buf[nl + 1:]
        return "".join(out)

    _FUNC_RE = re.compile(r"<function=([^>]+)>(.*?)</function>", re.DOTALL)
    _FUNC_UNCLOSED_RE = re.compile(r"<function=([^>]+)>(.*)", re.DOTALL)
    _PARAM_RE = re.compile(r"<parameter=([^>]+)>(.*?)</parameter>", re.DOTALL)

    _NESTED_FENCE_RE = re.compile(
        r"```(?:tool|tool_call)\s*\n(.*?)```", re.DOTALL)

    def _parse_xml_block(self, inner: str) -> None:
        """Normalize the model's native <function=NAME><parameter=K>V</parameter>
        form into the same {"tool":..., "args":{...}} shape and hand it to
        _parse_block, so every downstream repair/validation/salvage rule
        keeps working unchanged for either wire format."""
        inner = inner.strip()
        if not inner:
            self.failures.append(ParseFailure(raw=inner, error="empty <tool_call> block"))
            return
        m = self._FUNC_RE.search(inner) or self._FUNC_UNCLOSED_RE.search(inner)
        if not m:
            # The model sometimes abandons the XML wrapper mid-thought
            # (observed live 2026-09-05: a bare, unmatched '</function>'
            # immediately followed by a fully-formed ```tool fence for the
            # SAME call) and correctly writes the fenced JSON form right
            # after it, all still inside the outer <tool_call>...</tool_call>
            # span. That valid call shouldn't be thrown away just because
            # it's wrapped in leftover XML debris - recover it directly.
            nested = self._NESTED_FENCE_RE.search(inner)
            if nested:
                self.salvaged.append(ParseFailure(
                    raw=inner,
                    error="recovered a ```tool fence nested inside an "
                          "abandoned/malformed <tool_call> XML wrapper"))
                self._parse_block(nested.group(1).strip())
                return
            self.failures.append(ParseFailure(
                raw=inner,
                error="<tool_call> block missing <function=NAME>...</function>"))
            return
        name = m.group(1).strip()
        if not name:
            self.failures.append(ParseFailure(raw=inner, error="<function=> had no name"))
            return
        args = {key.strip(): _coerce_param_value(val)
                for key, val in self._PARAM_RE.findall(m.group(2))}
        self.salvaged.append(ParseFailure(
            raw=inner,
            error="accepted native <tool_call>/<function> XML "
                  "(model's built-in syntax, not the ```tool fence)"))
        self._parse_block(json.dumps({"tool": name, "args": args}))

    def _parse_block(self, raw: str) -> None:
        raw = raw.strip()
        if not raw:
            self.failures.append(ParseFailure(raw=raw, error="empty tool block"))
            return
        truncated = False
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as exc:
            obj = None
            if "Invalid \\escape" in str(exc):
                obj = self._salvage_invalid_escapes(raw, exc)
            if obj is None:
                obj = self._salvage(raw, exc)
            if obj is None:
                recovered = self._salvage_unterminated(raw, exc)
                if recovered is None:
                    return
                obj, truncated = recovered
                # _salvage already logged the strict parse failure; the
                # recovery supersedes it - keep the salvage note, drop the
                # failure so no pointless correction round-trip fires
                self.failures.pop()
        # Common model mistakes that used to cost a full correction round-trip
        # (observed live 2026-09-04: the agent itself kept emitting "task"
        # instead of "tool", which stopped every turn until it was re-emitted).
        # Repair them in place and surface honestly via self.salvaged - no
        # failure, so the agent loop never stalls waiting for a retry.
        if not (isinstance(obj, dict) and isinstance(obj.get("tool"), str)
                and isinstance(obj.get("args", {}), dict)):
            repaired = self._repair_common_mistakes(raw, obj)
            if repaired is None:
                if not isinstance(obj, dict):
                    err = 'expected a JSON object with a string "tool" field'
                elif not isinstance(obj.get("tool"), str):
                    err = ('expected a string "tool" field (a non-empty "task" '
                           'alias is accepted and repaired)')
                else:
                    err = '"args" must be a JSON object'
                self.failures.append(ParseFailure(raw=raw, error=err))
                return
            obj = repaired[0]
        args = obj.get("args", {})
        if not isinstance(args, dict):
            self.failures.append(
                ParseFailure(raw=raw, error='"args" must be a JSON object')
            )
            return
        self.calls.append(ToolCall(tool=obj["tool"], args=args, raw=raw,
                                   truncated=truncated))

    def _repair_common_mistakes(self, raw: str, obj) -> Optional[Tuple[dict, str]]:
        """Try to fix common model mistakes in a parsed tool-call object.

        Returns (obj_with_tool_str, args_dict) on success, or None if the block
        is genuinely malformed and should stay a hard failure. Only repairs that
        are unambiguous: 'task' as an alias for 'tool', missing/None 'args'
        defaulting to {}, and backticked tool names.
        """
        if not isinstance(obj, dict):
            return None
        # 1) 'task' instead of 'tool' (the most common live mistake)
        if not isinstance(obj.get("tool"), str):
            task = obj.get("task")
            if isinstance(task, str) and task.strip():
                obj["tool"] = task.strip()
            else:
                return None
        # 2) missing or null 'args' -> default to empty dict (harmless for most tools)
        args = obj.get("args")
        if args is None:
            obj["args"] = {}
        elif not isinstance(args, dict):
            return None
        else:
            pass  # already a valid dict; leave as-is
        # 3) backticked tool name (e.g. "`read_file`")
        tname = obj.get("tool")
        if isinstance(tname, str) and tname.startswith("\"") and tname.endswith("\""):
            inner = tname[1:-1].strip()
            if inner:
                obj["tool"] = inner
        # Honest surfacing (same style as _salvage / _salvage_unterminated):
        # the agent loop prints a dim "(recovered ...)" line instead of silently
        # succeeding or stalling on a correction round-trip. We only reach here
        # when at least one repair actually fired, so this is never noise.
        self.salvaged.append(ParseFailure(
            raw=raw,
            error="repaired common tool-call mistake "
                  "('task'->'tool' and/or missing 'args')"))
        return obj, obj.get("args", {})

    _BAD_ESCAPE_RE = re.compile(r'\\(?!["\\/bfnrtu])')

    def _salvage_invalid_escapes(self, raw: str, exc: json.JSONDecodeError) -> Optional[dict]:
        """The model wrote real content containing a literal backslash - a
        Windows path, a regex, a markdown escape - without doubling it for
        JSON (observed live 2026-09-05: 'C:\\Users\\Jack' where JSON needs
        'C:\\\\Users\\\\Jack'). json.loads rejects any backslash not
        followed by one of the 8 valid JSON escape characters
        (" \\ / b f n r t u). Doubling every invalid backslash recovers the
        model's almost-certainly-intended literal text without touching any
        backslash that was already a legitimate escape.

        Only tried when json.loads' own error explicitly names this cause
        (the "Invalid \\escape" caller check), so a differently-broken
        block still fails honestly instead of getting force-fed through a
        repair aimed at something else."""
        fixed = self._BAD_ESCAPE_RE.sub(r"\\\\", raw)
        try:
            obj = json.loads(fixed)
        except json.JSONDecodeError:
            return None  # not just an unescaped backslash - stays an honest failure
        self.salvaged.append(ParseFailure(
            raw=raw,
            error="repaired unescaped backslash(es) in the JSON string "
                  "(a literal path/regex the model didn't double for JSON)"))
        return obj

    def _salvage(self, raw: str, exc: json.JSONDecodeError) -> Optional[dict]:
        """Recover a leading valid JSON object when the ONLY trailing junk is
        an XML-style close tag. This model sometimes ends a block with
        '</tool_call>' instead of the closing fence (observed live in the
        session log, costing a full correction round-trip each time)."""
        try:
            obj, end = json.JSONDecoder().raw_decode(raw)
        except json.JSONDecodeError:
            self.failures.append(ParseFailure(raw=raw, error=f"invalid JSON: {exc}"))
            return None
        m = re.fullmatch(r"\s*</(tool[_a-zA-Z]*)>\s*", raw[end:])
        if not m:
            self.failures.append(ParseFailure(raw=raw, error=f"invalid JSON: {exc}"))
            return None
        self.salvaged.append(
            ParseFailure(raw=raw, error=f"closed with '</{m.group(1)}>' instead of the ``` fence"))
        return obj

    # The big free-form string each tool takes; the cut is only recoverable
    # when THIS final argument is the one that was truncated.
    _CUT_VALUE_KEYS = {"write_file": "content", "edit_file": "new"}

    def _salvage_unterminated(self, raw: str, exc: json.JSONDecodeError):
        """Recover a write_file/edit_file whose content string was cut
        mid-stream (observed live 2026-09-04: the model emitted a whole HTML
        page as one JSON string and never emitted the closing quote - the
        fence closed, parse died with 'Unterminated string', one correction
        round-trip failed the same way, and the work was lost).

        Only the unterminated-string failure qualifies, only for a
        write_file/edit_file whose head (tool + args + every argument before
        the big string) still parses as valid JSON, and only when the raw
        remainder decodes as a JSON string body (strict=False, so raw
        newlines the model left in survive). The content is what ACTUALLY
        streamed - nothing is invented. Any ambiguity -> None, and the
        honest parse failure already recorded upstream stands.

        Returns (obj, True) on recovery; the True marks the call truncated.
        """
        if "Unterminated string" not in str(exc):
            return None
        tm = re.search(r'"tool"\s*:\s*"(write_file|edit_file)"', raw)
        if not tm:
            return None
        tool = tm.group(1)
        key = self._CUT_VALUE_KEYS[tool]
        m = re.search(r'"' + key + r'"\s*:\s*"', raw[tm.end():])
        if not m:
            return None
        val_start = tm.end() + m.end()  # right after the value's opening quote
        head = raw[:val_start]
        try:
            probe = json.loads(head + '"}}')  # close the string + both objects
        except json.JSONDecodeError:
            return None  # the head itself is broken - nothing safe to recover
        args = probe.get("args", {})
        required = ("path",) if tool == "write_file" else ("path", "old")
        if any(r not in args for r in required):
            return None  # the cut ate a required argument - fail honestly
        content = _decode_open_string(raw[val_start:])
        if content is None:
            return None
        probe["args"][key] = content
        self.salvaged.append(ParseFailure(
            raw=raw,
            error=f"unterminated JSON string - recovered possibly-truncated "
                  f"'{key}' for {tool} ({len(content)} chars)"))
        return probe, True


_INT_RE = re.compile(r"-?\d+")
_FLOAT_RE = re.compile(r"-?\d+\.\d+")


def _coerce_param_value(raw: str):
    """<parameter> values arrive as plain text with no type info, and the
    model reliably puts each value on its own line (observed live:
    '<parameter=path>\\nC:\\...\\repl.py\\n</parameter>'), which is tag
    formatting, not content. Strip exactly one leading/trailing newline
    (plus the spaces on that edge line) before classifying/returning, so
    paths and regexes match; anything past that first newline on each
    side - i.e. actual multi-line file content - is left untouched."""
    v = raw
    if "\n" in v:
        head, _, rest = v.partition("\n")
        if not head.strip():
            v = rest
        tail_nl = v.rfind("\n")
        if tail_nl != -1 and not v[tail_nl + 1:].strip():
            v = v[:tail_nl]
    stripped = v.strip()
    if stripped.lower() == "true":
        return True
    if stripped.lower() == "false":
        return False
    if _INT_RE.fullmatch(stripped):
        return int(stripped)
    if _FLOAT_RE.fullmatch(stripped):
        return float(stripped)
    return v


def _decode_open_string(s: str) -> Optional[str]:
    """Decode the body of a JSON string that lost its closing quote.

    Wraps the remainder in quotes and parses with strict=False, so raw
    newlines/tabs the model left inside the content survive. A dangling
    trailing backslash (the stream was cut mid-escape) is dropped - that
    incomplete escape is the honest cut point. A remainder containing a
    real closing quote followed by more JSON keys fails to decode here, so
    that ambiguous shape stays an honest failure upstream.
    """
    candidates = [s]
    if s.endswith("\\"):
        candidates.append(s[:-1])
    for c in candidates:
        try:
            return json.loads('"' + c + '"', strict=False)
        except json.JSONDecodeError:
            continue
    return None


def parse_tool_blocks(text: str) -> Tuple[List[ToolCall], List[ParseFailure], str]:
    """One-shot helper (used by tests): returns (calls, failures, display_text)."""
    f = ToolStreamFilter()
    display = f.feed(text) + f.finish()
    return f.calls, f.failures, display
