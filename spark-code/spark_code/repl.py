"""The interactive REPL: pinned bottom input bar (with live slash menu when
on a real console), slash commands, session lifecycle, cost meter, and clean
shutdown (including the tunnel-ownership question).
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional

from . import compact as compact_mod
from . import config, cost, todos as todos_mod
from .agent import Agent
from .client import ServerError, SparkClient, StreamAborted, TunnelDownError
from .commands import canonical, help_text
from .lineedit import BottomBarEditor, EscWatcher, supports_fancy
from .session import Session, SessionStore
from .tunnel import TunnelManager
from .ui import UI, YELLOW, friendly_model_name


class Repl:
    def __init__(self, client: SparkClient, store: SessionStore, session: Session,
                 agent: Agent, ui: UI, tunnel: TunnelManager,
                 ctx_limit: int, ctx_total: int) -> None:
        self.client = client
        self.store = store
        self.session = session
        self.agent = agent
        self.ui = ui
        self.tunnel = tunnel
        self.ctx_limit = ctx_limit    # honest per-slot cap (drives compaction)
        self.ctx_total = ctx_total    # server total (display only)
        self.last_tok_s = 0.0
        # last real per-slot fill from the session log (0 for fresh sessions
        # or right after compact/clear - corrected by the next stream's usage)
        self.ctx_used = session.last_ctx_used
        self.running = True
        self.editor: Optional[BottomBarEditor] = None
        if supports_fancy() and ui.color:
            self.editor = BottomBarEditor(status_fn=self._status_line, color=ui.color,
                                          pending=ui.key_buffer,
                                          on_ctrl_t=self._toggle_think_pane)

    # -- status ----------------------------------------------------------------
    def _status_line(self) -> str:
        return self.ui.status_text(
            model=friendly_model_name(self.client.model or "?"),
            ctx_used=self.ctx_used, ctx_limit=self.ctx_limit, ctx_total=self.ctx_total,
            tok_s=self.last_tok_s, mode=self.agent.mode_label,
            cwd=str(self.agent.executor.cwd), yolo=self.ui.yolo,
            thinking=self.agent.thinking,
            think_expanded=self.ui.think.expanded,
            session_cloud=cost.turn_cost(self.session.total_prompt_tokens,
                                         self.session.total_completion_tokens),
        )

    def _toggle_think_pane(self) -> None:
        """ctrl+t (editor hotkey and the stream watcher): flip the thinking
        pane. Feedback lands in the status row on the next redraw; mid-stream
        the pane prints its own marker."""
        self.ui.think.toggle_live()

    # -- main loop -------------------------------------------------------------
    def run(self) -> None:
        while self.running:
            try:
                if self.editor is not None:
                    text = self.editor.read_line()
                else:
                    self.ui.dim(self._status_line())
                    text = self.ui.prompt_user()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            text = text.strip()
            if not text:
                continue
            try:
                if text.startswith("/"):
                    self.handle_command(text)
                else:
                    self._chat_turn(text)
            except TunnelDownError as exc:
                self.ui.error("\n✖ tunnel down\n" + str(exc))
                if self.tunnel.started_by_us:
                    self.ui.dim("  (the tunnel spark-code started has died; "
                                "type /reconnect to open a new one)")
            except ServerError as exc:
                self.ui.error("\n✖ model server error\n  " + str(exc))
            except KeyboardInterrupt:
                # Ctrl-C landed outside the stream reader (e.g. mid-compact).
                # Abort the action, keep the session and the REPL alive;
                # Ctrl-C at the input prompt above is the one that exits.
                self.ui.warn("\n  ⌀ interrupted")
            except Exception as exc:  # never crash the REPL on a turn
                self.ui.error(f"\n✖ unexpected error: {type(exc).__name__}: {exc}")
        self._shutdown()

    def _chat_turn(self, text: str) -> None:
        # Heal first: if the Spark went dark between turns (WiFi flap, laptop
        # sleep, tunnel death), bring the lane back before spending a turn on it.
        # Fast no-op when already up; never raises - a failed heal just means the
        # request below reports the tunnel-down error honestly instead of hanging.
        self.tunnel.heal()
        stats = self.agent.run_turn(text)
        self.last_tok_s = stats.tok_per_s
        if stats.prompt_tokens:
            self.ctx_used = stats.prompt_tokens + stats.completion_tokens
            if compact_mod.should_suggest_compact(self.ctx_used, self.ctx_limit):
                self.ui.warn(f"  context is {100 * self.ctx_used / self.ctx_limit:.0f}% "
                             "of the per-slot cap - consider /compact")

    # -- commands ------------------------------------------------------------------
    def handle_command(self, text: str) -> None:
        parts = text.split(None, 1)
        cmd = canonical(parts[0].lower())
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd == "/exit":
            self.running = False
        elif cmd == "/help":
            print(help_text())
        elif cmd == "/status":
            self._cmd_status()
        elif cmd == "/clear":
            self.session.clear()
            self.ctx_used = 0
            self.ui.info(f"  context cleared (session {self.session.id} continues, event logged)")
        elif cmd == "/compact":
            self._cmd_compact()
        elif cmd == "/sessions":
            self._cmd_sessions()
        elif cmd == "/resume":
            if arg.strip():
                self._cmd_resume(arg)
            else:
                self._cmd_resume_picker()
        elif cmd == "/new":
            self._cmd_new()
        elif cmd == "/model":
            self._cmd_model()
        elif cmd == "/effort":
            self._cmd_effort(arg)
        elif cmd in ("/fast", "/reasoning"):
            self._cmd_effort(cmd[1:])
        elif cmd == "/standard":
            self._cmd_effort("standard")
        elif cmd == "/thinking":
            self._cmd_thinking(arg)
        elif cmd == "/think":
            self._cmd_think(arg)
        elif cmd == "/cost":
            self._cmd_cost()
        elif cmd == "/todo":
            self._cmd_todo()
        elif cmd == "/ext":
            self._cmd_ext(arg)
        elif cmd == "/autocontinue":
            self._cmd_autocontinue(arg)
        elif cmd == "/menu":
            self._cmd_menu()
        elif cmd == "/yolo":
            self.ui.yolo = not self.ui.yolo
            state = "ON - all writes and shell commands auto-approved" if self.ui.yolo else "OFF - approvals required"
            self.ui.info(f"  yolo mode {state}")
        elif cmd == "/reconnect":
            self._cmd_reconnect()
        else:
            self.ui.warn(f"  unknown command: {cmd}   (type /help)")

    def _cmd_status(self) -> None:
        tunnel_state = ("started by spark-code (will offer to close on exit)"
                        if self.tunnel.started_by_us else "pre-existing (left alone on exit)")
        cloud = cost.turn_cost(self.session.total_prompt_tokens,
                               self.session.total_completion_tokens)
        print(f"""\
  model      : {friendly_model_name(self.client.model or '?')}
  raw id     : {self.client.model or '?'}
  endpoint   : {self.client.base_url}
  context    : {self.ctx_used:,} used / {self.ctx_limit:,} per slot (server total {self.ctx_total:,})
  thinking   : {'on (collapsible pane - /think expands the last one)' if self.agent.thinking else 'off (enable_thinking=false)'}
  last speed : {self.last_tok_s:.1f} tok/s
  mode       : {self.agent.mode_label} (max_tokens={self.agent.mode_cfg['max_tokens']:,})
  session    : {self.session.id}  ({len(self.session.messages)} messages)
  saved at   : {self.session.path}
  cwd        : {self.agent.executor.cwd}
  tunnel     : {tunnel_state}
  yolo       : {'on' if self.ui.yolo else 'off'}
  cost       : $0.00 local · would have cost {cost.format_usd(cloud)} on a cloud API (ref)""")

    def _cmd_compact(self) -> None:
        if len(self.session.messages) < 4:
            self.ui.warn("  not enough history to compact yet")
            return
        before_est = max(self.ctx_used, compact_mod.estimate_tokens(self.session.messages))
        self.ui.dim(f"  compacting {len(self.session.messages)} messages "
                    f"(~{before_est:,} tokens) via the model...")
        request = compact_mod.build_compaction_request(self.session.messages)
        summary_parts = []
        self.ui.assistant_start()
        think = self.ui.think
        think.begin()
        esc = EscWatcher.for_console(on_esc=self.client.abort,
                                     on_toggle=self._toggle_think_pane)
        esc.start()
        try:
            for delta in self.client.chat_stream(
                [{"role": "system", "content": "You are a precise summarizer. Follow the requested section structure exactly."},
                 {"role": "user", "content": request}],
                max_tokens=6144, temperature=config.DEFAULT_TEMPERATURE,
                repeat_penalty=config.DEFAULT_REPEAT_PENALTY,
                thinking=self.agent.thinking,
                on_reasoning=think.feed,
            ):
                think.finish()  # first summary token closes the thinking pane
                summary_parts.append(delta)
                self.ui.write(delta)
        except StreamAborted:
            self.ui.warn("\n  ⌀ interrupted - compaction aborted; history unchanged")
            return
        finally:
            esc.stop()
            think.finish()  # never leave a dangling status line, even on Esc/Ctrl-C
            self.ui.key_buffer.extend(esc.swallowed)
        print()
        r = self.client.last_result
        summary = "".join(summary_parts).strip()
        if not summary:
            self.ui.error("  compaction failed: model returned an empty summary; history unchanged")
            return
        new_messages = compact_mod.apply_compaction(self.session.messages, summary,
                                                    keep_last=config.COMPACT_KEEP_LAST)
        kept_est = compact_mod.estimate_tokens(new_messages[1:])
        # session.apply_compact stores the summary with its prefix marker
        self.session.apply_compact(compact_mod.SUMMARY_PREFIX + summary, new_messages[1:])
        self.ctx_used = 0  # unknown until the next turn reports real usage
        self.ui.info(
            f"  compacted: ~{before_est:,} → ~{r.completion_tokens + kept_est:,} tokens "
            f"(structured summary {r.completion_tokens:,} + last {len(new_messages) - 1} turns verbatim; "
            "event logged - survives /resume)")

    def _cmd_sessions(self) -> None:
        infos = self.store.list()
        if not infos:
            self.ui.dim("  no saved sessions yet")
            return
        print(f"  {'id':<22} {'messages':>8}  {'last active':<19}  cwd")
        for i in infos[:20]:
            marker = " *" if i.id == self.session.id else ""
            print(f"  {i.id:<22} {i.n_messages:>8}  "
                  f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(i.last_ts))}  "
                  f"{i.cwd}{marker}")
        if len(infos) > 20:
            self.ui.dim(f"  ... and {len(infos) - 20} more in {self.store.root}")

    def _cmd_resume(self, arg: str) -> None:
        if not arg:
            self.ui.warn("  usage: /resume <id>   (see /sessions)")
            return
        try:
            session = self.store.load(arg)
        except KeyError as exc:
            self.ui.error(f"  {exc}")
            return
        self._swap_session(session, f"resumed {session.id}: {len(session.messages)} messages restored")

    def _cmd_resume_picker(self) -> None:
        """Bare /resume (no id): show the 3 most recent sessions, let the
        user pick one, restore its full context, and chdir back into the
        folder it was originally running in. /resume <id> is unaffected -
        that path still goes through _cmd_resume above."""
        infos = self.store.list()[:3]
        if not infos:
            self.ui.warn("  no saved sessions yet")
            return
        print("  latest sessions:")
        for i, info in enumerate(infos, start=1):
            marker = " *" if info.id == self.session.id else ""
            print(f"  {i}. {info.id:<22} {info.n_messages:>4} msgs  "
                  f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info.last_ts))}  "
                  f"{info.cwd}{marker}")
        try:
            ans = input(f"  resume which? [1-{len(infos)}, enter=1]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        ans = ans or "1"
        if not ans.isdigit() or not (1 <= int(ans) <= len(infos)):
            self.ui.warn("  invalid selection; resume cancelled")
            return
        chosen = infos[int(ans) - 1]
        try:
            session = self.store.load(chosen.id)
        except KeyError as exc:
            self.ui.error(f"  {exc}")
            return
        self._swap_session(session, f"resumed {session.id}: {len(session.messages)} messages restored")
        target = session.meta.get("cwd") if session.meta else None
        if not target:
            return
        p = Path(target)
        if not p.is_dir():
            self.ui.warn(f"  original folder no longer exists: {target} (staying put)")
            return
        os.chdir(p)
        self.agent.executor.cwd = p
        self.ui.dim(f"  switched working directory to {p}")

    def _cmd_new(self) -> None:
        session = self.store.create(cwd=str(self.agent.executor.cwd),
                                    model=self.client.model or "?")
        self._swap_session(session, f"new session {session.id}")

    def _swap_session(self, session: Session, note: str) -> None:
        self.session = session
        self.agent.session = session
        if session.meta.get("model"):
            self.client.model = session.meta["model"]
        self.ctx_used = session.last_ctx_used
        self.ui.info(f"  {note}")
        self.ui.dim(f"  saved at {session.path}")

    def _cmd_model(self) -> None:
        models = self.client.list_models()
        print("  models on the server:")
        for i, m in enumerate(models, 1):
            marker = "  <-- current" if m == self.client.model else ""
            print(f"    {i}. {friendly_model_name(m)}  ({m}){marker}")
        if not models:
            return
        try:
            ans = input("  switch to number (enter to keep): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not ans:
            return
        try:
            idx = int(ans) - 1
            self.client.model = models[idx]
        except (ValueError, IndexError):
            self.ui.warn("  invalid selection; model unchanged")
            return
        self.session.set_model(self.client.model)
        self.ui.info(f"  model is now {friendly_model_name(self.client.model)}")

    def _cmd_effort(self, arg: str) -> None:
        tiers = "/".join(config.EFFORT_MODES)
        if not arg:
            cfg = self.agent.mode_cfg
            self.ui.info(f"  mode is {self.agent.mode_label} "
                         f"(thinking {'on' if cfg['thinking'] else 'off'}, "
                         f"max_tokens={cfg['max_tokens']:,}); "
                         f"usage: /effort {tiers}")
            return
        arg = arg.lower()
        if arg not in config.EFFORT_MODES:
            self.ui.warn(f"  unknown mode '{arg}' - use {tiers}")
            return
        self.agent.set_mode(arg)
        cfg = self.agent.mode_cfg
        self.ui.info(f"  mode set to {self.agent.mode_label} "
                     f"(thinking {'on' if cfg['thinking'] else 'off'}, "
                     f"max_tokens={cfg['max_tokens']:,})")

    def _cmd_thinking(self, arg: str) -> None:
        if arg in ("on", ""):
            self.agent.thinking = not self.agent.thinking if not arg else True
        elif arg == "off":
            self.agent.thinking = False
        else:
            self.ui.warn("  usage: /thinking on|off")
            return
        state = ("ON - reasoning shows as a collapsible pane above the answer "
                 "(/think expands it)"
                 if self.agent.thinking else
                 "OFF - server gets enable_thinking=false, answers directly")
        self.ui.info(f"  thinking {state}")

    def _cmd_think(self, arg: str) -> None:
        """Expand/collapse the thinking pane. Display-only: the model still
        thinks unless /thinking off; the toggle persists for the session."""
        think = self.ui.think
        if arg in ("on", "expand"):
            think.expanded = True
        elif arg in ("off", "collapse"):
            think.expanded = False
        elif arg:
            self.ui.warn("  usage: /think [on|off]   (bare /think toggles)")
            return
        else:
            think.expanded = not think.expanded
        if think.expanded:
            self.ui.info("  thinking EXPANDED - reasoning streams dimmed, live "
                         "(collapses again with /think)")
            think.render_last()  # show what the model just thought, if anything
        else:
            self.ui.info("  thinking COLLAPSED - a single live status line "
                         "while the model thinks")

    def _cmd_cost(self) -> None:
        p, c = self.session.total_prompt_tokens, self.session.total_completion_tokens
        cloud = cost.turn_cost(p, c)
        self.ui.info(
            f"  session tokens: {p:,} prompt + {c:,} completion\n"
            f"  local cost: $0.00 - your Spark, no meter, ever\n"
            f"  cloud equivalent: {cost.format_usd(cloud)} "
            f"({config.CLOUD_REFERENCE['label']}: "
            f"${config.CLOUD_REFERENCE['input_per_1m']:.2f}/1M in, "
            f"${config.CLOUD_REFERENCE['output_per_1m']:.2f}/1M out)")

    def _cmd_todo(self) -> None:
        for line in todos_mod.render_todos(self.session.todos).splitlines():
            print("  " + line)
        self.ui.dim("  (the model maintains this list with the update_todos tool)")

    def _cmd_ext(self, arg: str) -> None:
        reg = self.agent.executor.plugins
        if arg == "reload":
            reg.load()
            self.ui.info(f"  extensions reloaded: {len(reg.plugins)} loaded, "
                         f"{len(reg.errors)} refused")
        if reg.plugins:
            print(f"  {len(reg.plugins)} extension(s) from {reg.root}:")
            for p in sorted(reg.plugins.values(), key=lambda p: p.name):
                print(f"    {p.name} ({p.approval}) - {p.description}  [{p.path.name}]")
        else:
            self.ui.dim(f"  no extensions loaded (drop a .py in {reg.root}; "
                        "format in README, then /ext reload)")
        for fname, err in reg.errors:
            self.ui.warn(f"  refused {fname}: {err}")

    def _cmd_autocontinue(self, arg: str) -> None:
        if arg in ("on", ""):
            self.agent.autocontinue = not self.agent.autocontinue if not arg else True
        elif arg == "off":
            self.agent.autocontinue = False
        else:
            self.ui.warn("  usage: /autocontinue on|off")
            return
        state = ("ON - a reply that looks cut off gets a 'continue' nudge "
                 f"(max {config.AUTOCONTINUE_MAX} chained)"
                 if self.agent.autocontinue else
                 "OFF - turns end exactly where the model stops")
        self.ui.info(f"  auto-continue {state}")

    def _cmd_menu(self) -> None:
        from . import menuops
        ok, msg = menuops.spawn_menu_detached()
        if not ok:
            self.ui.warn(f"  {msg}")
            return
        self.ui.dim(f"  {msg} - session saved as on normal exit")
        self.running = False  # clean exit path: _shutdown() saves + offers

    def _cmd_reconnect(self) -> None:
        try:
            status = self.tunnel.ensure()
            self.ui.info("  tunnel " + ("was already up" if status == "already-up" else "re-established"))
        except Exception as exc:
            self.ui.error(f"  reconnect failed: {exc}")

    # -- shutdown ----------------------------------------------------------------------
    def _shutdown(self) -> None:
        self.ui.dim(f"\n  session {self.session.id} saved at {self.session.path}")
        self.ui.dim("  closing the CLI frees its slot on the Spark's server; "
                    "nothing of yours stays running there.")
        if self.tunnel.started_by_us:
            try:
                ans = input(self.ui._c("  spark-code started the SSH tunnel - close it? [Y/n]: ", YELLOW)).strip().lower()
            except (EOFError, KeyboardInterrupt):
                ans = "y"
                print()
            if ans in ("", "y", "yes"):
                if self.tunnel.close():
                    self.ui.dim("  tunnel closed.")
            else:
                self.ui.dim("  tunnel left running (other sessions may be using it).")
        self.ui.dim("  bye.")
