"""Patch ToolStreamFilter._salvace to accept a valid tool call followed by
ANY trailing data (the 'Extra data' case), not just an XML close tag.
Idempotent."""
import sys
from pathlib import Path

P = Path(__file__).resolve().parent / "spark_code" / "protocol.py"
text = P.read_text(encoding="utf-8")

OLD = (
    '        self.salvaged.append(\n'
    '            ParseFailure(raw=raw, error=f"closed with \'</{m.group(1)}>\' instead of the