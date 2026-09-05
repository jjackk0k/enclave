"""One-shot patch for ui.py thinking-status line (line-based, no text matching)."""
import io
from pathlib import Path

p = Path("spark_code/ui.py")
text = p.read_text(encoding="utf-8")
lines = text.splitlines(keepends=True)

# Find the two lines we care about (grep said 205/206).
hint_idx = next(i for i, l in enumerate(lines) if 'ctrl+t to collapse' in l and 'hint =' in l)
tok_line = hint_idx + 1  # summary line follows
print("patching at lines", hint_idx + 1, tok_line + 1)
for j in (hint_idx, tok_line):
    print(j + 1, repr(lines[j]))

# Replace the pair with a guarded version: only show if expanded OR tokens>0.
old_hint = lines[hint_idx]
old_sum = lines[tok_line]
indent = old_hint[: len(old_hint) - len(old_hint.lstrip())]
guarded = (
    f"{indent}if self.expanded or tokens > 0:\n"
    f"{indent}    hint = \"ctrl+t to collapse\" if self.expanded else \"ctrl+t to expand\"\n"
    f"{indent}    summary = f\"  · thought for {{elapsed:.0f}}s · ~{{fmt_tokens(tokens)}} tokens — {{hint}}\"\n"
)
lines[hint_idx:tok_line + 1] = [guarded]
p.write_text("".join(lines), encoding="utf-8")
print("done:", p, "now", len(p.read_text(encoding='utf-8').splitlines()), "lines")
