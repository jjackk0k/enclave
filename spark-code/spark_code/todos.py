"""Session task list: the model maintains it with the update_todos tool,
the user inspects it with /todo. Pure validation + rendering, unit-tested;
persistence lives in the session log (a "todos" event), so the list
survives /resume like everything else.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

STATUSES = ("pending", "in_progress", "done")
MAX_ITEMS = 50
MAX_CONTENT = 200

_MARKS = {"done": "[x]", "in_progress": "[>]", "pending": "[ ]"}


def validate_todos(raw) -> Tuple[Optional[List[dict]], Optional[str]]:
    """Normalize the model's `todos` argument. Returns (items, error)."""
    if not isinstance(raw, list):
        return None, '"todos" must be a JSON array of {"content", "status"} objects'
    if len(raw) > MAX_ITEMS:
        return None, f"too many items ({len(raw)}; max {MAX_ITEMS})"
    items = []
    for i, entry in enumerate(raw, 1):
        if not isinstance(entry, dict):
            return None, f"item {i} must be an object with content + status"
        content = entry.get("content")
        if not isinstance(content, str) or not content.strip():
            return None, f'item {i} needs a non-empty "content" string'
        status = entry.get("status", "pending")
        if status not in STATUSES:
            return None, f"item {i}: status must be one of {', '.join(STATUSES)}"
        items.append({"content": content.strip()[:MAX_CONTENT], "status": status})
    return items, None


def render_todos(items: List[dict]) -> str:
    if not items:
        return "(task list is empty)"
    done = sum(1 for t in items if t.get("status") == "done")
    lines = [f"{done}/{len(items)} done"]
    for t in items:
        lines.append(f"{_MARKS.get(t.get('status'), '[ ]')} {t.get('content', '?')}")
    return "\n".join(lines)
