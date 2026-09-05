"""Hypothetical cloud-cost meter.

The local model is $0.00, always. This answers a different question: what
WOULD these tokens have cost on a frontier-class cloud API, at reference
list prices (config.CLOUD_REFERENCE)? Pure functions, unit-tested.
"""

from __future__ import annotations

from . import config


def turn_cost(prompt_tokens: int, completion_tokens: int,
              table: dict = None) -> float:
    t = table or config.CLOUD_REFERENCE
    return (prompt_tokens * t["input_per_1m"]
            + completion_tokens * t["output_per_1m"]) / 1_000_000


def format_usd(value: float) -> str:
    if value >= 100:
        return f"${value:,.2f}"
    return f"${value:.4f}"
