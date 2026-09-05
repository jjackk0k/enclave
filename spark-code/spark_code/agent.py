"""The agent loop: stream a reply, extract fenced-JSON tool calls, execute
them with approvals, feed results back, repeat - uncapped by default
(config.MAX_TOOL_STEPS can set a cap). Malformed tool blocks get exactly one
retry-with-correction and parse failures are surfaced to the user honestly.
"""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass
from typing import List, Optional

from . import config, cost, todos as todos_mod
from .client import SparkClient, StreamAborted, TunnelDownError, ServerError
from .lineedit import EscWatcher
from .protocol import ToolStreamFilter
from .session import Session
from .tools import TOOL_SPEC_FOR_PROMPT, ToolExecutor, ToolResult
from .ui import UI

SYSTEM_TEMPLATE = """\
You are Spark Code, a careful terminal coding agent running on the owner's PC.
You are backed by a local model on the owner's DGX Spark; there is no API cost,
but context is finite, so be concise.

Current working directory (all relative paths resolve here): {cwd}
Platform: Windows. run_shell executes `cmd /c <command>`.

{tool_spec}
TOOL CALLING PROTOCOL (strict):
- To call a tool, emit EXACTLY ONE fenced block per call, anywhere in your reply:
```tool
{{"tool": "<name>", "args": {{...}}}}
```
- The JSON must be valid, on the documented schema. No comments, no trailing text inside the block.
- You may emit several tool calls in one reply.
- After you emit tool calls, STOP writing and wait: results arrive in a
  <tool_results> message, then you continue.
- NEVER fabricate tool results. If you did not call a tool, you do not know its output.
- If no tool is needed, just answer normally in plain markdown.

WORKING STYLE:
- Read files before editing them. Prefer edit_file over write_file for changes to existing files.
- Before a destructive or hard-to-reverse shell command, warn the user in text first.
- The user approves every write/edit/shell command (or has enabled auto-approve); never claim a
  file was written or a command ran unless a tool result says so.
- Show paths, line counts, and commands in your prose so the user always knows where you are working.
- For multi-step work, maintain the session task list with update_todos: mark a task
  in_progress BEFORE starting it and done the moment it finishes. The user sees it via /todo.
"""

TODO_TOOL = "update_todos"

CORRECTION_TEMPLATE = (
    "PROTOCOL ERROR: your previous reply contained a ```tool block that could not be parsed "
    "({error}). Re-emit the tool call as a single ```tool fenced block containing valid JSON "
    'with "tool" and "args" fields. If the file content is long, write it in parts instead: '
    "write_file for the first ~100 lines, then edit_file with \"old\" = the file's last line "
    'and "new" = that line plus the next chunk. Output nothing else.'
)

AUTOCONTINUE_NUDGE = ("Continue from exactly where you stopped - your last reply "
                      "looked cut off.")

_CLEAN_ENDINGS = ('.', '!', '?', ')', ']', '}', '`', '"', "'")


def needs_continuation(reply: str, finish_reason: str) -> "tuple[bool, str]":
    """Does this reply look cut off mid-turn? (Jack's live bug: 'spark code
    sometimes just stops randomly mid-turn'. Session-log evidence: replies
    ending mid-CSS, mid-sentence, or with an open fence - one had NO usage
    frame at all, i.e. the stream was severed server-side.)

    Returns (needed, reason). Honest terminators end clean: . ! ? ) ] } ` " '
    """
    if finish_reason not in ("", "stop"):
        return True, f"finish: {finish_reason}"
    text = reply.strip()
    if not text:
        return True, "empty reply"
    if text.count("```") % 2 == 1:
        return True, "code fence left open"
    if text.endswith((":", ",", "—", "(", "[")):
        return True, "ends mid-thought"
    if not text.endswith(_CLEAN_ENDINGS):
        return True, "no sentence terminator (reply may be cut off)"
    return False, ""


@dataclass
class TurnStats:
    tool_steps: int = 0
    parse_failures: int = 0
    salvages: int = 0
    corrections_sent: int = 0
    hit_step_cap: bool = False
    interrupted: bool = False
    autocontinues: int = 0
    tok_per_s: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0


class Agent:
    def __init__(self, client: SparkClient, session: Session,
                 executor: ToolExecutor, ui: UI,
                 effort: str = config.DEFAULT_EFFORT,
                 max_steps: Optional[int] = config.MAX_TOOL_STEPS) -> None:
        self.client = client
        self.session = session
        self.executor = executor
        self.ui = ui
        self.max_steps = max_steps
        self.autocontinue = True  # /autocontinue toggles; default on
        self.set_mode(effort)

    # -- the effort tiers: Fast | Standard | Reasoning ---------------------------
    @property
    def mode(self) -> str:
        return self._mode

    @property
    def mode_label(self) -> str:
        return config.EFFORT_MODES[self._mode]["label"]

    @property
    def mode_cfg(self) -> dict:
        return config.EFFORT_MODES[self._mode]

    def set_mode(self, mode: str) -> None:
        if mode not in config.EFFORT_MODES:
            raise ValueError(f"unknown mode {mode!r} (use "
                             + "/".join(config.EFFORT_MODES) + ")")
        self._mode = mode
        # switching modes sets thinking from the mode; /thinking can override after
        self.thinking = config.EFFORT_MODES[mode]["thinking"]

    # -- prompt -----------------------------------------------------------------
    def system_prompt(self) -> str:
        spec = TOOL_SPEC_FOR_PROMPT + self.executor.plugins.spec_text()
        prompt = SYSTEM_TEMPLATE.format(cwd=self.executor.cwd, tool_spec=spec)
        if self.session.todos:
            prompt += ("\nCURRENT TASK LIST (keep it current with update_todos):\n"
                       + todos_mod.render_todos(self.session.todos) + "\n")
        return prompt

    def _api_messages(self) -> List[dict]:
        return [{"role": "system", "content": self.system_prompt()}] + self.session.messages

    # -- one streamed completion, returned via the filter --------------------------
    def _stream_once(self, stats: TurnStats) -> ToolStreamFilter:
        filt = ToolStreamFilter()
        self.ui.assistant_start()
        think = self.ui.think
        think.begin()
        # Esc aborts the in-flight stream: the watcher thread's on_esc calls
        # client.abort(), which closes the HTTP response and breaks even a
        # blocked readline (prefill/stalls), not just the gaps between
        # chunks. Same semantics as Ctrl-C. No-op without a real console.
        esc = EscWatcher.for_console(on_esc=self.client.abort,
                                     on_toggle=self.ui.think.toggle_live)
        esc.start()
        try:
            for delta in self.client.chat_stream(
                self._api_messages(),
                max_tokens=self.mode_cfg["max_tokens"],
                temperature=config.DEFAULT_TEMPERATURE,
                repeat_penalty=config.DEFAULT_REPEAT_PENALTY,
                thinking=self.thinking,
                on_reasoning=think.feed,
            ):
                think.finish()  # first content delta closes the thinking pane
                display = filt.feed(delta)
                if display:
                    self.ui.write(display)
        except (KeyboardInterrupt, StreamAborted):
            stats.interrupted = True
        finally:
            # join the watcher first so its `swallowed` list is final, then
            # close the pane: no dangling "thinking…" line after Ctrl-C, Esc,
            # or a mid-stream server error
            esc.stop()
            think.finish()
            self.ui.key_buffer.extend(esc.swallowed)  # typeahead survives
        tail = filt.finish()
        if tail:
            self.ui.write(tail)
        if stats.interrupted:
            # Ctrl-C / Esc: keep the partial reply, but do NOT read
            # client.last_result (it still holds the PREVIOUS turn's counts -
            # reusing them double-counted session usage) and do NOT run
            # salvaged tool calls.
            self.ui.warn("\n  ⌀ interrupted - partial reply kept; no tools run")
            return filt
        r = self.client.last_result
        stats.tok_per_s = r.tok_per_s
        stats.prompt_tokens = r.prompt_tokens
        stats.completion_tokens = r.completion_tokens
        cloud_turn = cost.turn_cost(r.prompt_tokens, r.completion_tokens)
        cloud_session = cost.turn_cost(
            self.session.total_prompt_tokens + r.prompt_tokens,
            self.session.total_completion_tokens + r.completion_tokens)
        self.ui.assistant_end(r.tok_per_s, r.completion_tokens,
                              r.tokens_estimated, r.finish_reason,
                              cloud_turn=cloud_turn, cloud_session=cloud_session)
        return filt

    # -- the agent loop --------------------------------------------------------------
    def run_turn(self, user_text: str) -> TurnStats:
        stats = TurnStats()
        self.executor.begin_turn()  # reset per-turn tool budgets (web search cap)
        self.session.add_message("user", user_text)
        corrections = 0
        continues = 0  # auto-continue nudges this turn (capped, dimmed, honest)

        step_iter = range(1, self.max_steps + 1) if self.max_steps else itertools.count(1)
        for step in step_iter:
            filt = self._stream_once(stats)
            if stats.prompt_tokens:
                self.session.add_usage(stats.prompt_tokens, stats.completion_tokens)
            raw = filt.raw_text
            if raw.strip():
                self.session.add_message("assistant", raw)
            if stats.interrupted:
                break  # Ctrl-C: partial reply kept above; run no tools

            stats.parse_failures += len(filt.failures)
            for failure in filt.failures:
                self.ui.warn(f"  ! tool-call parse failure: {failure.error}")
                self.ui.dim(f"    raw block: {failure.raw[:200]}")
            stats.salvages += len(filt.salvaged)
            for salv in filt.salvaged:
                self.ui.dim(f"  (recovered a tool call from a malformed block: {salv.error})")

            if filt.failures and not filt.calls and corrections < 1:
                corrections += 1
                stats.corrections_sent = corrections
                self.ui.dim("  (asking the model to re-emit the tool call correctly)")
                self.session.add_message(
                    "user", CORRECTION_TEMPLATE.format(error=filt.failures[0].error))
                continue
            if filt.failures and not filt.calls and corrections >= 1:
                self.ui.error("  ! tool call still unparseable after one correction; "
                              "continuing with the text reply only.")
                break

            if not filt.calls:
                if self._maybe_autocontinue(stats, filt, continues):
                    continues += 1
                    stats.autocontinues = continues
                    continue
                break  # normal final answer

            stats.tool_steps += len(filt.calls)
            result_blocks = []
            image_parts = []  # read_image attachments ride the same message
            for call in filt.calls:
                if call.tool == "web_search":
                    # rich block instead of the generic args preview: the UI
                    # shows query, progress, and a numbered results summary
                    query = str(call.args.get("query") or "").strip()
                    self.ui.search_begin(query)
                    t0 = time.perf_counter()
                    try:
                        result = self.executor.execute(call.tool, call.args)
                    except KeyboardInterrupt:
                        self.ui.search_abort(query)
                        stats.interrupted = True
                        self.ui.warn("  ⌀ interrupted - search aborted; turn stopped")
                        break
                    self.ui.search_end(result.data, time.perf_counter() - t0)
                else:
                    args_preview = ", ".join(f"{k}={str(v)[:60]!r}" for k, v in call.args.items())
                    self.ui.tool_activity(f"{call.tool}({args_preview})")
                    try:
                        if call.tool == TODO_TOOL:
                            result = self._update_todos(call.args)  # session state, no approval
                        else:
                            result = self.executor.execute(call.tool, call.args)
                    except KeyboardInterrupt:
                        stats.interrupted = True
                        self.ui.warn("\n  ⌀ interrupted during tool execution - turn stopped")
                        break
                ok = "true" if result.ok else "false"
                text = result.text
                if len(text) > config.TOOL_RESULT_CHAR_CAP:
                    text = text[:config.TOOL_RESULT_CHAR_CAP] + "\n... [result truncated]"
                if call.truncated:
                    # recovered from an unterminated JSON block: the user gets
                    # a warn, the model gets told to verify and complete it
                    self.ui.warn(f"  ⚠ {call.tool} was salvaged from an unterminated "
                                 "JSON block - the written content may be cut off")
                    text += ("\n[spark-code note: this call's JSON was unterminated; "
                             "the content was recovered from the raw stream and may be "
                             "TRUNCATED (or carry stray trailing JSON braces). "
                             "read_file the result, then append the missing part with "
                             "edit_file (old = the file's last line, new = that line + "
                             "the rest) or rewrite the file in parts.]")
                result_blocks.append(
                    f'<result tool="{call.tool}" ok="{ok}">\n{text}\n</result>')
                if result.data and result.data.get("image_dataurl"):
                    image_parts.append({"type": "image_url",
                                        "image_url": {"url": result.data["image_dataurl"]}})
                if call.tool != "web_search":  # the search block already showed the outcome
                    first_line = result.text.splitlines()[0] if result.text else "(empty)"
                    (self.ui.info if result.ok else self.ui.warn)(f"    → {first_line[:140]}")
            if stats.interrupted:
                # Ctrl-C during tools: discard the partial batch - the model
                # must not act on results of a turn the user aborted
                break
            results_text = "<tool_results>\n" + "\n".join(result_blocks) + "\n</tool_results>"
            if image_parts:
                # multipart content: the model actually SEES the image
                self.session.add_message(
                    "user", [{"type": "text", "text": results_text}] + image_parts)
            else:
                self.session.add_message("user", results_text)
        else:
            stats.hit_step_cap = True
            self.ui.warn(f"\n  ! hit the {self.max_steps}-tool-step cap for this turn. "
                         "Say 'continue' to keep going, or redirect me.")

        return stats

    # -- auto-continue for cut-off replies ------------------------------------------
    def _maybe_autocontinue(self, stats: TurnStats, filt: ToolStreamFilter,
                            continues: int) -> bool:
        """Jack's random-stop fix: a reply that looks cut off gets a short
        'continue' nudge instead of silently ending the turn. Never fires
        after an interrupt, an error path, or a clean finish; capped at
        config.AUTOCONTINUE_MAX chained nudges, loudly."""
        if not self.autocontinue or stats.interrupted:
            return False
        r = self.client.last_result
        needed, reason = needs_continuation(filt.raw_text, r.finish_reason)
        if not needed:
            return False
        if continues >= config.AUTOCONTINUE_MAX:
            self.ui.warn(f"\n  ! reply still looks cut off after {continues} "
                         "auto-continues - say 'continue' to keep going")
            return False
        self.ui.dim(f"  ↻ auto-continue {continues + 1}/{config.AUTOCONTINUE_MAX} "
                    f"({reason})")
        self.session.add_message("user", AUTOCONTINUE_NUDGE)
        return True

    # -- session task list (update_todos tool) -----------------------------------
    def _update_todos(self, args: dict) -> ToolResult:
        """Handled in the agent loop (not the executor): it mutates session
        state only - no file writes, no shell - so no approval is needed.
        Persisted as a session event, so the list survives /resume."""
        items, err = todos_mod.validate_todos(args.get("todos"))
        if err:
            return ToolResult(False, f"update_todos rejected: {err}")
        self.session.set_todos(items)
        return ToolResult(True, "Task list updated:\n" + todos_mod.render_todos(items))
