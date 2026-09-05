"""Central configuration for Spark Code.

Everything points at the agent lane of the llama-server running on the
DGX Spark (gx10-d094.local), reached through a localhost SSH tunnel.
"""

from pathlib import Path

APP_NAME = "spark-code"
DISPLAY_NAME = "Spark Code"

# --- endpoint / tunnel -----------------------------------------------------
BASE_URL = "http://127.0.0.1:8080"
SSH_TARGET = "varvel@gx10-d094.local"
SSH_ARGS = [
    "ssh",
    "-o", "BatchMode=yes",
    "-o", "ExitOnForwardFailure=yes",
    "-o", "ServerAliveInterval=30",
    "-N",
    "-L", "8080:127.0.0.1:8080",
    SSH_TARGET,
]

# The server now runs with -c 524288 -np 2 (upgraded 2026-09-03: KV q8 at
# 524288/2 slots is ~16GB, fits in the Spark's 40GB+ available). /props
# reports the PER-SLOT n_ctx (262144 after the upgrade); if the probe fails
# we fall back to this honest per-slot cap.
FALLBACK_PER_SLOT_CTX = 262144
# The per-slot context the owner expects the lane to provide.
CTX_OWNER_TARGET = 262144

# --- display ---------------------------------------------------------------
# Friendly names for served model ids (raw id always shown in /status).
MODEL_ALIASES = {
    "RVN-Q4_K_M-mtp": "Qwen 3.8 27B · Heretic",
    "RVN-Q4_K_M": "Qwen 3.8 27B · Heretic",
}

# --- hypothetical cloud cost meter -----------------------------------------
# Reference pricing ONLY: what these tokens WOULD cost on a frontier-class
# cloud API. The local model itself is $0.00, always.
CLOUD_REFERENCE = {
    "label": "frontier-class API reference (list price)",
    "input_per_1m": 3.00,
    "output_per_1m": 15.00,
}

# --- generation ------------------------------------------------------------
# Three tiers. Reasoning is deep (thinking on + a big budget); standard is
# balanced (still thinks, but capped so it stops over-thinking - the new default);
# fast answers directly with no reasoning stream.
EFFORT_MODES = {
    "reasoning": {"label": "Reasoning", "thinking": True, "max_tokens": 32768},
    "standard": {"label": "Standard", "thinking": True, "max_tokens": 8192},
    "fast": {"label": "Fast", "thinking": False, "max_tokens": 4096},
}
DEFAULT_EFFORT = "standard"
# Sampling verified live against the cockpit proxy DEFAULT_SAMPLING
# (~/chatui/proxy.py: {"temperature": 0.2, "repeat_penalty": 1.15}).
DEFAULT_TEMPERATURE = 0.2
DEFAULT_REPEAT_PENALTY = 1.15

# --- agent loop ------------------------------------------------------------
MAX_TOOL_STEPS = None        # per user turn; None = uncapped (Jack 2026-09-03), set an int to re-cap
SHELL_DEFAULT_TIMEOUT = 60   # seconds
SHELL_MAX_TIMEOUT = 300
TOOL_RESULT_CHAR_CAP = 8000
COMPACT_KEEP_LAST = 4        # verbatim turns kept after /compact
COMPACT_SUGGEST_AT = 0.6     # fraction of per-slot context
# Auto-continue: a reply that looks cut off (weird finish_reason, open code
# fence, no sentence terminator, or empty) gets a short "continue" nudge,
# chained at most this many times per turn (loud when the cap is hit).
AUTOCONTINUE_MAX = 3

# --- network resilience ------------------------------------------------------
# WiFi-flap tolerance: transient failures (connection refused/reset, HTTP
# 429/5xx) get 3 retries with this backoff, but only BEFORE the first content
# token has streamed (retrying mid-stream would duplicate output). A full
# read-timeout stall is never retried - that means a busy slot, reported
# honestly instead.
RETRY_BACKOFF_S = (1.0, 2.0, 4.0)
RETRY_HTTP_CODES = (429, 500, 502, 503, 504)

# --- web search --------------------------------------------------------------
# Stdlib-only multi-provider web search, no API keys (ported from the Spark
# cockpit's ~/chatui/proxy.py chain). Runs from this PC over the public
# internet via urllib - read-only, so no approval prompt.
SEARCH_MAX_PER_TURN = 20  # web_search calls per user turn
SEARCH_RESULTS = 5        # results returned per search
SEARCH_TOTAL_BUDGET = 25  # seconds across the whole provider chain
SEARCH_CACHE_TTL = 300    # identical queries cached in memory for 5 min

# --- paths -----------------------------------------------------------------
# Where the app lives on disk. From source this is simply the package's parent
# directory (the spark-code/ folder). When frozen into a PyInstaller one-file
# exe, every bundled module - config.py included - runs from a throwaway temp
# extraction dir (_MEIxxxxxx), so __file__ points THERE; any path derived from it
# would silently resolve into that folder and vanish on exit. That is exactly why
# the menu's Launch button did nothing: REPL_EXE (config.ROOT / "spark-code.exe")
# pointed at a temp dir, .exists() was False, so it fell back to spawning
# sys.executable -m spark_code which, for the windowed exe, IS the menu itself.
#
# Anchor to the real executable instead: PyInstaller leaves sys.executable as the
# actual on-disk path (only _MEIPASS is the temp dir), and both exes sit next to
# each other in the install folder - so this one root fixes Launch, sessions/
# resume, and plugins/ for spark-menu.exe AND spark-code.exe at once.
import sys as _sys


def _app_root() -> Path:
    """The spark-code/ directory on disk (or the exe's own folder when frozen)."""
    if getattr(_sys, "frozen", False):
        return Path(_sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


ROOT = _app_root()                 # source: spark-code/ dir; frozen: exe's folder
SESSIONS_DIR = ROOT / "sessions"   # real + persistent, shared by both exes and the .bat path
PLUGINS_DIR = ROOT / "plugins"     # extensions live next to the package (source) or exe (frozen)

# --- help text shown when the tunnel is down -------------------------------
TUNNEL_HELP = (
    "The SSH tunnel to the Spark is not answering on 127.0.0.1:8080.\n"
    "Fix: run this in any terminal (key auth is already set up):\n"
    "    " + " ".join(SSH_ARGS) + "\n"
    "or just restart spark-code and it will open the tunnel for you.\n"
    "If the tunnel IS up, the llama-server agent lane on the Spark may be\n"
    "down or busy (model swap / benchmark) - try again in a few minutes."
)
