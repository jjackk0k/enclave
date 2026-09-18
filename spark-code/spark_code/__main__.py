"""spark-code entry point.

Usage:
    python -m spark_code [--yolo] [--resume <id>] [--resume-last]
                         [--effort fast|reasoning] [--model <id>]

The agent operates in the directory it was launched from.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__, config
from .agent import Agent
from .client import ServerError, SparkClient, TunnelDownError
from .repl import Repl
from .session import SessionStore
from .tools import ToolExecutor
from .tunnel import TunnelManager, TunnelStartError
from .ui import UI, enable_vt_mode, friendly_model_name


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="spark-code",
                                description="Terminal coding agent backed by the DGX Spark's local model.")
    p.add_argument("--yolo", action="store_true",
                   help="auto-approve all file writes and shell commands")
    p.add_argument("--resume", metavar="ID", help="resume a saved session (see /sessions)")
    p.add_argument("--resume-last", action="store_true", help="resume the most recent session")
    p.add_argument("--effort", choices=list(config.EFFORT_MODES), default=config.DEFAULT_EFFORT,
                   help=("tier: fast (direct, 4k) · standard (thinking, 8k, default) "
                         "· reasoning (deep thinking, 32k)"))
    p.add_argument("--model", metavar="ID", help="model id to use (default: first from /v1/models)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    enable_vt_mode()
    ui = UI(yolo=args.yolo, color=not args.no_color)
    cwd = os.getcwd()

    # -- 1. tunnel ------------------------------------------------------------
    tunnel = TunnelManager()
    try:
        tunnel_status = tunnel.ensure()
    except TunnelStartError as exc:
        ui.error("✖ cannot reach the Spark's agent lane\n" + str(exc))
        return 2
    if tunnel_status == "started":
        ui.dim("[spark-code] agent lane was down; opened the SSH tunnel to the Spark (hidden).")

    # -- 2. server handshake ----------------------------------------------------
    def retry_note(attempt: int, wait: float, exc: Exception) -> None:
        reason = ("endpoint unreachable" if isinstance(exc, TunnelDownError)
                  else str(exc).splitlines()[0][:100])
        ui.dim(f"  (connection hiccup: {reason}; "
               f"retry {attempt}/{len(config.RETRY_BACKOFF_S)} in {wait:.0f}s)")

    client = SparkClient(on_retry=retry_note)
    try:
        models = client.list_models()
    except (TunnelDownError, ServerError) as exc:
        ui.error(f"✖ handshake failed: {exc}")
        return 2
    if not models:
        ui.error("✖ /v1/models returned no models - is llama-server loaded on the Spark?")
        return 2
    if args.model:
        if args.model not in models:
            ui.warn(f"  requested model '{args.model}' not in server list {models}; using it anyway")
        client.model = args.model
    else:
        client.model = models[0]

    try:
        ctx_limit, ctx_total, ctx_source = client.probe_context_limit()
    except TunnelDownError as exc:
        ui.error(f"✖ {exc}")
        return 2

    # -- 3. session --------------------------------------------------------------
    store = SessionStore()
    session = None
    if args.resume_last:
        latest = store.latest_id()
        if latest:
            session = store.load(latest)
        else:
            ui.warn("  no saved sessions; starting a new one")
    elif args.resume:
        try:
            session = store.load(args.resume)
        except KeyError as exc:
            ui.error(f"✖ {exc}")
            return 2
    if session is None:
        session = store.create(cwd=cwd, model=client.model)
    elif session.meta.get("model") and not args.model:
        client.model = session.meta["model"]
        ui.dim(f"  session was using model {client.model}")

    # A resumed session remembers its effort tier (fast/standard/reasoning). If the
    # log has one, honor it over the CLI default so reopening doesn't silently reset.
    _saved_effort = session.meta.get("effort") if session.meta else None
    if _saved_effort and _saved_effort in config.EFFORT_MODES:
        args.effort = _saved_effort

    # -- 4. go ---------------------------------------------------------------------
    executor = ToolExecutor(cwd=cwd, approve=ui.approve)
    executor.vision_probe = client.supports_vision  # read_image capability check
    agent = Agent(client, session, executor, ui, effort=args.effort)
    ui.banner(__version__, friendly_model_name(client.model), ctx_limit, ctx_total,
              ctx_source, cwd, tunnel_status)
    if session.messages:
        ui.info(f"  resumed session {session.id}: {len(session.messages)} messages in context")
    repl = Repl(client, store, session, agent, ui, tunnel, ctx_limit, ctx_total)
    try:
        repl.run()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
