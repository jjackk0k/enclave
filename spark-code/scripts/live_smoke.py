"""Live smoke test for Spark Code (requires the real Spark).

- ensures the SSH tunnel (starts it if the lane is down)
- lists models from /v1/models
- probes /props for the honest per-slot context cap
- asks one trivial question with streaming, prints each delta as it arrives
- reports real token counts (include_usage) and client-measured tok/s
- closes the tunnel only if this script started it

Run:  python scripts\\live_smoke.py   (from the spark-code directory)
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from spark_code.client import SparkClient
from spark_code.tunnel import TunnelManager


def main() -> int:
    tunnel = TunnelManager()
    status = tunnel.ensure()
    print(f"[smoke] tunnel: {'reused existing' if status == 'already-up' else 'STARTED by this script'}")

    client = SparkClient()
    models = client.list_models()
    print(f"[smoke] models: {models}")
    client.model = models[0]

    ctx_limit, ctx_total, ctx_source = client.probe_context_limit()
    print(f"[smoke] per-slot context: {ctx_limit:,} (server total {ctx_total:,})  ({ctx_source})")

    question = "Reply with exactly: SPARK OK"
    print(f"[smoke] asking {client.model!r}: {question!r}")
    print("[smoke] reasoning (dimmed): ", end="", flush=True)
    reasoning_chars = [0]

    def on_reasoning(text):
        reasoning_chars[0] += len(text)
        print(f"\x1b[90m{text}\x1b[0m", end="", flush=True)

    started = time.perf_counter()
    answer_parts = []
    for delta in client.chat_stream(
        [{"role": "user", "content": question}],
        max_tokens=512, temperature=0.0,
        on_reasoning=on_reasoning,
    ):
        answer_parts.append(delta)
    print()
    print(f"[smoke] answer: {''.join(answer_parts)!r}  (reasoning: {reasoning_chars[0]} chars)")
    r = client.last_result
    est = " (estimated - server sent no usage!)" if r.tokens_estimated else " (real, from include_usage)"
    print(f"[smoke] usage: {r.prompt_tokens} prompt + {r.completion_tokens} completion tokens{est}")
    print(f"[smoke] speed: {r.tok_per_s:.1f} tok/s decode  (wall {r.elapsed_s:.2f}s)")
    print(f"[smoke] finish_reason: {r.finish_reason}")

    # thinking=off must suppress reasoning server-side (enable_thinking=false)
    reasoning_chars[0] = 0
    answer2 = "".join(client.chat_stream(
        [{"role": "user", "content": "Say OK"}],
        max_tokens=64, temperature=0.0, thinking=False,
        on_reasoning=lambda t: reasoning_chars.__setitem__(0, reasoning_chars[0] + len(t)),
    ))
    print(f"[smoke] thinking=off: answer {answer2!r}, reasoning chars: {reasoning_chars[0]} "
          f"({'suppressed correctly' if reasoning_chars[0] == 0 else 'STILL THINKING - kwarg not honored'})")

    if tunnel.started_by_us:
        tunnel.close()
        print("[smoke] tunnel closed (this script started it).")
    else:
        print("[smoke] tunnel left running (pre-existing, not ours).")
    print("[smoke] PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
