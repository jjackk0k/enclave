# Spark Code

A terminal coding agent in the Claude Code / Kimi Code class, running on this
PC and backed entirely by the DGX Spark's local model (Qwen 3.8 27B "Heretic"
RVN on llama-server, agent lane). Stdlib-only Python — no pip installs, no
residue.

## Quick start

```bat
spark-menu.exe                    :: clickable menu (build once: python scripts\build_exe.py)
spark-code.bat                    :: interactive REPL, approvals on
spark-code.bat --yolo             :: auto-approve all writes + shell commands
spark-code.bat --resume-last      :: reopen the most recent session
spark-code.bat --resume <id>      :: reopen a specific session (see /sessions)
spark-code.bat --effort fast      :: start in Fast mode (default is Reasoning)
```

**The agent operates in the folder you launch it from.** `cd` into a project
first, then launch (or pick the folder in the menu). Add
`C:\Users\Jack\Downloads\enclave\spark-code` to PATH to run it from anywhere.

## The menu (spark-menu.exe)

A small tkinter window — stdlib, no deps. It does not replace the .bat; it's
the clickable front door:

- **Working folder**: path field + Browse… + a "resume last session" toggle;
  **Launch** opens the REPL in its own console with that folder as cwd.
- **Connect / Disconnect**: opens the same SSH tunnel spark-code.bat uses
  (`ssh -N -L 8080:127.0.0.1:8080 varvel@gx10-d094.local`) and health-checks
  `127.0.0.1:8080/health` — green/red dot plus the loaded model. Disconnect
  only ever kills the tunnel the menu itself started; a pre-existing tunnel
  is left alone.
- **Model on the lane**: lists the GGUFs in `~/models` on the Spark, shows
  which one is loaded, and can switch or restore stock. Every action goes
  over ssh to `~/engine-switch/lane-models.sh` — an ADDITIVE script
  (`agent-lane.sh` is never modified; kills are cmdline-checked). A switch
  health-verifies for up to 240s and rolls back LOUD to the stock
  RVN + DFlash2 lane on failure. `plan <gguf>` shows the exact actions
  without touching anything.
- `/menu` inside the REPL saves the session (normal exit path) and re-opens
  this window.

Build the exes once (internet needed, ~2 min):

```bat
python scripts\build_exe.py    :: isolated .build-venv + PyInstaller;
                              ::  writes spark-menu.exe + spark-code.exe here
```

If you'd rather not build: `pythonw -m spark_code.menu` runs the same menu
from source. Rebuild after changing `spark_code/` — the exes don't
auto-update.

## Interface (Claude Code / Kimi Code layout)

- **Pinned bottom input bar.** Chat output scrolls above; the bottom of the
  screen holds the slash menu (when open), the status line, and the `you>`
  input line. The **status line leads with the current directory**, then
  friendly model name, context, tok/s, mode, thinking state, and cost.
- **Collapsible thinking pane.** The model's reasoning collapses to a single
  live status line — `spark> · thinking… 7s · ~1.2k tokens — ctrl+t to expand`
  — rewritten in place while it thinks and finalized to `· thought for 12s ·
  ~3.1k tokens` when the answer starts. **Ctrl+T toggles it live everywhere**:
  at the prompt (the status row shows `thinking:on·expanded`), and mid-stream
  (collapsing stops the dimmed echo with a `(thinking hidden - ctrl+t to show)`
  marker; re-pressing resumes it). `/think` does the same and also re-renders
  the last turn's thinking wrapped. The toggle persists for the session.
  Reasoning is display-only — it never enters history or the tool parser.
- **Clean web search block.** When the model calls `web_search` you get a
  compact activity block — styled query, a `searching…` progress line (erased
  in place on a VT console), then numbered results with title, domain, a
  one-line snippet, and the URL dimmed. No raw tool JSON, ever.
- **Slash-command menu.** Type `/` and a live menu of matching commands with
  descriptions appears above the input, filtering as you type. **TAB** fills
  to the closest match (common prefix when several match), ↑/↓ navigate the
  menu, Enter fills then submits, Esc closes the menu. ↑/↓ recall input
  history when the menu is closed. Ctrl-C clears the line (exits when empty).
- Implemented with raw `msvcrt` key reading + ANSI/VT scroll regions —
  `prompt_toolkit` is not available in the managed runtime (verified), so the
  whole layer is hand-rolled stdlib. On a non-console (piped stdin) it
  degrades to the classic plain prompt automatically.

## Infrastructure

- Model server: `llama-server` on `gx10-d094.local:8080` (OpenAI-compatible),
  bound to Spark localhost, reached via SSH tunnel
  `ssh ... -N -L 8080:127.0.0.1:8080 varvel@gx10-d094.local`.
- If `127.0.0.1:8080` doesn't answer at startup, Spark Code opens that tunnel
  itself as a hidden detached process, remembers that it did, and **offers to
  close it on exit**. Tunnels it did not start are left alone.
- **Context: 262,144 tokens per slot, for real.** The agent lane runs
  `-c 524288 -np 2` (upgraded 2026-09-03 from `-c 262144`; KV q8 at 524288/2
  slots ≈ 16 GB, fits comfortably — 40 GB free after restart). `/props`
  reports the per-slot value (verified live: it is NOT divided again), and
  the status bar shows plain `ctx N/262,144`. If the lane ever runs with a
  split context again, the bar shows it honestly:
  `ctx N/524,288 (slot cap 262,144)`-style.

## Modes: Fast | Reasoning

Exactly two modes, aligned with the Spark cockpit's sampling defaults
(`~/chatui/proxy.py` `DEFAULT_SAMPLING`, verified live: **temperature 0.2,
repeat_penalty 1.15** — sent per-request, llama.cpp's native keys):

- **Reasoning** (default): thinking ON (reasoning streams dimmed), max_tokens
  32,768. Cockpit-quality answers.
- **Fast**: thinking OFF via `chat_template_kwargs.enable_thinking=false`
  (proven honored by this server), max_tokens 4,096. Direct answers.

Switch with `/effort fast|reasoning` or the bare `/fast` / `/reasoning`
aliases; `/effort` alone shows the current mode. The status bar shows
**Fast** or **Reasoning**. `/thinking on|off` overrides thinking inside a
mode without changing the mode label.

## Transparency & cost

- Real token counts from `stream_options: {include_usage: true}`; tok/s is
  measured client-side from chunk arrival times (pure decode speed).
- **Thinking is ON by default** (Reasoning mode) — the model's reasoning
  collapses to a one-line live status above the answer (`/think` expands it
  into a dimmed, wrapped view). `/thinking off` sends
  `chat_template_kwargs.enable_thinking=false` (verified: this server's
  template honors it) and the model answers directly.
- After every turn: `[N tokens · X tok/s · cloud equivalent $0.0042 (ref) ·
  session $0.0123 · $0.00 local]`. The cloud figure is **reference pricing
  only** (frontier-class list prices in `config.CLOUD_REFERENCE`) — what the
  same tokens WOULD have cost. The local model is $0.00, always.
- File writes/edits show a full unified diff and wait for `y / n / always`.
  Shell commands are shown with cwd and timeout, and wait for approval.
  **The approval prompt is single-keypress** (y / n / a — Enter, Esc and
  Ctrl-C all mean no); stray keys are consumed silently and the line is
  repainted via full-line erase, never overprinted. `--yolo` or `/yolo`
  auto-approves; `always` approves a category for the session. The startup
  banner reminds you of both.

## Extensions: the model can write its own tools

Drop a `.py` file in `plugins/` (next to the package; next to the exe when
frozen). One file = one tool:

```python
TOOL = {
    "name": "word_count",            # required, snake_case
    "description": "count words in a file",   # required
    "args": {"path": {"type": "string",      # required; {} allowed
                      "description": "file to count"}},
    "approval": "read",              # optional: read (default) | write | shell
}

def run(args, approve, cwd):         # required; cwd = the agent's folder
    import os
    with open(os.path.join(cwd, args["path"]), encoding="utf-8") as fh:
        return f"{len(fh.read().split())} words"
```

The model can write this file mid-session (via `write_file`, with your
approval as always); `/ext reload` picks it up, `/ext` lists what's loaded
and what was refused. Validation is strict: a name colliding with a built-in
or another plugin, missing fields, bad arg types, or an import error are
refused and reported — a broken plugin never crashes the host. Undeclared
arguments are rejected. `write`/`shell`-class extensions prompt through the
same y/n/always approval path as the built-ins before they run; `read` ones
never prompt. Files starting with `_` are parked (not loaded).

## Commands

Type `/` for the live menu. Generated from the same registry, so it can't drift:

| command | effect |
|---|---|
| `/help` | command list |
| `/status` | friendly + raw model id, context, speed, mode, session, tunnel |
| `/compact` | structured summary (goal / requirements / decisions / files / tool state / open tasks), last 4 turns kept verbatim, before→after token counts |
| `/clear` | wipe context (logged in the session file) |
| `/sessions` | list saved sessions |
| `/resume <id>` | restore full context of a saved session |
| `/new` | fresh session |
| `/model` | list server models and switch |
| `/effort` | show current mode; `/effort fast` or `/effort reasoning` switches |
| `/fast` `/reasoning` | bare aliases for the two modes |
| `/thinking on\|off` | reasoning on/off server-side (default on; bare `/thinking` toggles) |
| `/think [on\|off]` | expand/collapse the thinking pane; expanding re-shows the last thinking wrapped + dimmed |
| `/cost` | token totals: $0.00 local + hypothetical cloud equivalent |
| `/todo` | show the task list the model maintains for this session |
| `/ext [reload]` | list tool extensions from `plugins/`; `reload` rescans (the model can write itself a new tool mid-session, then you reload) |
| `/autocontinue [on\|off]` | auto-nudge the model when a reply looks cut off (default on; max 3 chained, loud at the cap) |
| `/menu` | save the session and return to the spark-code menu window |
| `/yolo` | toggle auto-approve |
| `/reconnect` | re-open the SSH tunnel if it died |
| `/exit` | quit; offers to close the tunnel if spark-code started it |

Unknown commands say so. `/compact` is suggested automatically at 60% of the
per-slot cap, and the compaction event is in the session log, so it survives
`/resume` (verified live).

## Tools the model can call

`read_file`, `write_file`, `edit_file` (exact-match replace, must be unique),
`run_shell` (cmd /c, timeout 60s default, 300s cap), `list_dir`,
`search_files` (glob + optional content regex), `glob` (find files by glob
pattern; `*.py` matches at any depth, `src/**/*.py` matches paths) and
`grep` (regex content search, every matching line as `path:line: text`,
200-hit cap) — both read-only over the same walker that skips `.git`,
`node_modules` & co., `fetch_url` (one http/https page → readable main text:
script/style/nav stripped, whitespace collapsed, 200KB raw / 8k-char return
caps, 20s timeout, redirects followed, honest status/content-type/too-large
errors, login-wall note), `read_image` (png/jpg/gif/webp/bmp → base64
data-URL in the tool-results message when the endpoint supports vision —
probed once per session with a 1x1 png, cached; the current text-only lane
answers the probe with an HTTP error, so the tool honestly says "vision is
not supported" and never dumps base64 into context; 10MB cap, downscaled to
1568px when Pillow is importable), `web_search` (public web
search — stdlib multi-provider chain ddg-lite → ddg-html → Bing → Mojeek,
no API keys; read-only so no approval; 20 searches per turn, 5 results each,
25s total budget, 5-min cache), and `update_todos`
(session task list: pending / in_progress / done — session state only, so no
approval; visible any time via `/todo`; re-injected into the system prompt so
it survives compaction and `/resume`). Tool calls use a strict fenced-JSON
protocol (```` ```tool ```` blocks); a block accidentally closed with an
XML-style `</tool_call>` tag is salvaged (and logged dimly) instead of costing
a correction round-trip. A `write_file`/`edit_file` whose big content string
is **cut off mid-stream** (the model never closes the JSON string — seen live
on Reasoning effort with a whole HTML page inline) is **salvaged**: the head
is re-validated, the streamed content is recovered verbatim (never invented),
the write executes with a truncation warning to you *and* a note in the tool
result telling the model to verify and append the rest. Anything ambiguous
still fails honestly: genuinely malformed blocks get exactly one
retry-with-correction (which now also teaches the chunked-write pattern), and
parse failures are shown. The spec itself tells the model: **files over ~100
lines are written in parts** — `write_file` for the first chunk, then
`edit_file` with `old` = the file's last line and `new` = that line + the next
chunk. Tool steps per turn are uncapped by default (`config.MAX_TOOL_STEPS`
can set a cap; when a cap is hit the agent stops and asks).

## Network resilience

Transient connection failures — refused/reset connections (WiFi flap, tunnel
restart) and HTTP 429/5xx — get **3 retries with 1s/2s/4s backoff**, announced
dimly, but only *before the first content token has streamed* (retrying
mid-stream would duplicate output). Once text is flowing, or after a full
300s read stall (that means a busy slot, not a flap), errors surface honestly.
Ctrl-C **or Esc** aborts the turn immediately — even mid-prefill or during a
server-side stall: a background watcher thread polls the console for Esc on a
timer and its callback **closes the HTTP response**, breaking the blocked
stream read (an earlier per-chunk poll only worked while tokens were actively
arriving). The partial text is kept in history, no salvaged tool calls run,
and token usage is not double-counted; the marker is `⌀ interrupted`. Keys
you type mid-turn are swallowed and replayed into the next input line, so
typeahead is never eaten. Esc during *tool execution* is not read until the
current tool finishes — a write never lands half-done; the Esc then denies
the next approval or aborts the next stream. On a non-console (piped stdin)
or POSIX the watcher is a no-op and Ctrl-C still works.
Ctrl-C during a tool (e.g. a slow web search) aborts the turn the same way —
the REPL stays alive, the progress line is closed cleanly, and the thinking
status line is never left dangling after an interrupt or a mid-stream error.

**Auto-continue (the "stops randomly mid-turn" fix).** When a reply ends
looking cut off — a weird `finish_reason` (e.g. `length`), an open code
fence, a trailing colon/comma/dash, no sentence terminator, or an empty
reply — the agent injects a short "continue" nudge itself, dimmed as
`↻ auto-continue 1/3`, chained at most 3 times per turn (loud at the cap).
It never fires after an interrupt or an error path. Evidence from the
session log: one stop had **no usage frame at all** — the stream was severed
server-side mid-CSS — and the one-correction-per-turn budget was already
spent, so the turn just fell out. `/autocontinue off` disables it.

## Session lifecycle

- Every message/compaction/clear/usage sample/task-list update is appended as
  one JSON line to `sessions/<id>.jsonl` **on the PC** — closing the terminal
  loses nothing; `--resume-last` / `/resume <id>` replays the log to rebuild
  full context, including the task list and the last real context-fill reading
  (so the status bar's `ctx` number is honest from the first prompt, not 0).
  A torn final line from a hard kill is skipped on load.
- Spark Code spawns **no** permanent processes, starts **no** model servers on
  the Spark, and leaves no background residue. Closing the CLI frees the
  llama.cpp slot it was using; the only thing on the Spark is the shared
  `llama-server` itself.

## Development

```bat
cd spark-code
python -m unittest discover -s tests   :: 272 tests, mock server, no live dependency
python scripts\live_smoke.py           :: live check: tunnel, models, 262k probe, thinking toggle, tok/s
python scripts\build_exe.py            :: build spark-menu.exe + spark-code.exe (PyInstaller, isolated venv)
```

Layout: `spark_code/` (package: client, protocol, tools, websearch, agent
loop, repl, lineedit, commands, compact, todos, cost, sessions, tunnel, ui,
plugins, menuops, menu), `plugins/` (tool extensions), `tests/` (mock
llama-server + mock search server + unit/integration tests),
`scripts/` (live_smoke, build_exe, lane-models.sh = the additive Spark-side
lane manager the menu drives, entry_menu/entry_repl for PyInstaller),
`reference/` (copies of the original launcher patterns this replaces).

## Known limitations

- The fancy bottom bar needs a real Windows console; under piped stdin it
  falls back to a plain prompt (which is what scripts and tests use).
- TAB completion covers slash commands, not file paths in arguments.
- The editor is single-line; pasted multi-line text submits per line.
- The slash-menu drawing code only runs on a live console; state transitions
  (open → close/shrink → rows erased) are covered by driving the real key
  loop with a fake key source in `tests/test_lineedit.py`, but eyeball the
  rendering once in a real terminal after changes.
- In Reasoning mode a huge task can spend the whole 32k budget thinking —
  you'll see `finish: length`; say "continue" or switch to `/fast`.
- Tool calling is prompt-protocol based, not native API tool-calling; truncated
  write/edit blocks are salvaged (flagged), and genuinely malformed blocks cost
  one correction round-trip (logged honestly).
- Paths outside the launch cwd are allowed but always shown in full in the
  approval prompt.
- One server slot: if another client hogs both llama.cpp slots, requests wait
  and a 300s read timeout errors honestly instead of hanging forever.
