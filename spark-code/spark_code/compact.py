"""Context compaction: the model summarizes the conversation so far into a
running summary; history is then replaced with [summary + last few turns].
This is the same compaction pattern used by full-size coding agents.
"""

from __future__ import annotations

from typing import List

from . import config

SUMMARY_PREFIX = (
    "[Running summary of the earlier conversation - treat it as accurate history]\n"
)

COMPACTION_INSTRUCTION = """\
Produce a structured handoff summary for the coding agent that continues this
conversation. Use EXACTLY these section headers, in this order:

## Goal
The user's objective, in one or two sentences.
## Requirements & constraints
Every explicit requirement, preference, or constraint the user stated.
## Decisions made
Decisions taken and the reasoning behind them.
## Files touched
Each file path read/created/edited, and its current state.
## Tool & environment state
Commands run, their outcomes, servers/ports/processes involved.
## Open tasks & next steps
What remains, and the immediate next step.

Rules: be factual and compact (400-600 words total); never invent details;
omit a section entirely if it would be empty; output only the summary."""


def _content_text(content) -> str:
    """Message content is a plain string, or a multipart list when a turn
    attached an image (read_image). Images contribute a marker, not pixels."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, dict) and p.get("type") == "text":
                parts.append(p.get("text", ""))
            elif isinstance(p, dict):
                parts.append("[image]")
        return "\n".join(parts)
    return str(content)


def build_compaction_request(messages: List[dict], max_chars: int = 24_000) -> str:
    """Render history + instruction into a single user prompt for the model."""
    parts = []
    total = 0
    for m in messages:
        role = m.get("role", "?").upper()
        content = _content_text(m.get("content", ""))
        block = f"--- {role} ---\n{content}"
        if total + len(block) > max_chars:
            remaining = max_chars - total
            if remaining > 400:
                parts.append(block[:remaining] + "\n... [older history truncated for summarization]")
            break
        parts.append(block)
        total += len(block)
    return "\n\n".join(parts) + "\n\n" + COMPACTION_INSTRUCTION


def apply_compaction(messages: List[dict], summary: str,
                     keep_last: int = config.COMPACT_KEEP_LAST) -> List[dict]:
    """Return the post-compaction message list: summary + the most recent turns."""
    kept = list(messages[-keep_last:]) if keep_last > 0 else []
    return [{"role": "user", "content": SUMMARY_PREFIX + summary.strip()}] + kept


def estimate_tokens(messages: List[dict]) -> int:
    """Rough char/4 estimate, used only to report pre-compaction size.
    An attached image counts a flat ~1,100 tokens (vision-tile order)."""
    total = 0
    for m in messages:
        content = m.get("content", "")
        total += len(_content_text(content)) // 4
        if isinstance(content, list):
            total += sum(1100 for p in content
                         if isinstance(p, dict) and p.get("type") == "image_url")
    return total


def should_suggest_compact(used_tokens: int, ctx_limit: int) -> bool:
    """Suggest /compact once the per-slot context is ~60% full."""
    return ctx_limit > 0 and used_tokens > int(ctx_limit * config.COMPACT_SUGGEST_AT)
