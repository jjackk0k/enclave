#!/usr/bin/env bash
# lane-models.sh — ADDITIVE model management for the spark-code agent lane
# (:8080). Added 2026-09-04 for the spark-code menu. agent-lane.sh is NEVER
# modified; this script is a parallel tool. Kills are cmdline-checked
# (pattern match on /proc/<pid>/cmdline), never raw pidfile-free pids.
#
# Verbs:
#   list            GGUF files in ~/models (one per line)
#   current         model id the lane currently serves (/v1/models)
#   status          health + current model, one line
#   plan <gguf>     print the exact actions a load would take (no changes)
#   load <gguf>     stop the lane, start it on <gguf>, health-verify,
#                   roll back LOUD to stock on any failure
#   unload          stop the lane (leave it down)
#   restore-stock   load the stock RVN + DFlash2 drafter config
#
# Set SPARK_LANE_DRYRUN=1 to print instead of execute (verification path
# used by the menu's own tests; makes `load` side-effect free).
set -uo pipefail

M=/home/varvel/models
PORT=8080
LOG=/home/varvel/engine-switch/lane-8080.log
LL=/home/varvel/llama.cpp/build-tuned/bin/llama-server
[ -x "$LL" ] || LL=/home/varvel/llama.cpp/build/bin/llama-server

# Stock = exactly what agent-lane.sh launches (verified 2026-09-04).
STOCK_MODEL=RVN-Q4_K_M-mtp.gguf
STOCK_DRAFTER=Qwen3.8-27B-DFlash2-Q4_K_M.gguf

say(){ echo "[lane-models] $*"; }
DRYRUN=${SPARK_LANE_DRYRUN:-0}

health_code(){
  curl -s -o /dev/null -w '%{http_code}' --max-time 2 \
    "http://127.0.0.1:$PORT/health" 2>/dev/null || echo 000
}

current_model(){
  curl -s --max-time 3 "http://127.0.0.1:$PORT/v1/models" 2>/dev/null \
    | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
}

stop_lane(){
  # cmdline-checked kill only (same discipline as agent-lane.sh)
  for p in $(pgrep -f "llama-server.*--port $PORT" 2>/dev/null || true); do
    cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null || true)
    case "$cmd" in
      *llama-server*) say "stopping lane pid $p ($cmd)"; [ "$DRYRUN" = 1 ] || kill "$p" ;;
      *) say "pid $p cmdline is not llama-server - leaving it alone" ;;
    esac
  done
  [ "$DRYRUN" = 1 ] || sleep 2
}

start_lane(){  # $1 = gguf filename (must exist in $M)
  local gguf="$1"
  say "launching $gguf on :$PORT (tuned binary, DFlash2 drafter, -c 524288 -np 2)"
  if [ "$DRYRUN" = 1 ]; then
    say "DRYRUN: $LL -m $M/$gguf -md $M/$STOCK_DRAFTER --spec-type draft-dflash ..."
    return 0
  fi
  nohup "$LL" -m "$M/$gguf" \
    -md "$M/$STOCK_DRAFTER" \
    --spec-type draft-dflash --spec-draft-n-max 7 \
    -ngl 99 -fa on \
    -c 524288 -np 2 --port "$PORT" \
    >"$LOG" 2>&1 </dev/null &
  echo $! > /home/varvel/engine-switch/lane-8080.pid
}

wait_healthy(){  # 240s, same cadence as agent-lane.sh
  for i in $(seq 1 120); do
    [ "$(health_code)" = "200" ] && { say "healthy after $((i*2))s"; return 0; }
    [ "$DRYRUN" = 1 ] && { say "DRYRUN: skipping health wait"; return 0; }
    sleep 2
  done
  say "WARNING: not healthy after 240s - check $LOG"
  return 1
}

load_model(){  # $1 = gguf; health-verify, roll back LOUD on failure
  local gguf="$1"
  [ -f "$M/$gguf" ] || { say "FATAL: $M/$gguf does not exist"; exit 1; }
  local before; before=$(current_model || true)
  say "switching lane: ${before:-none} -> $gguf"
  stop_lane
  start_lane "$gguf"
  if wait_healthy && [ "$(current_model || true)" != "" ]; then
    say "OK: lane now serves $(current_model)"
    return 0
  fi
  say "ROLLBACK: $gguf failed health-verify - restoring stock $STOCK_MODEL"
  stop_lane
  start_lane "$STOCK_MODEL"
  if wait_healthy; then
    say "ROLLBACK OK: stock lane healthy ($(current_model))"
  else
    say "ROLLBACK FAILED TOO - run: bash ~/agent-lane.sh start  (and check $LOG)"
  fi
  exit 1
}

case "${1:-status}" in
  list)     for f in "$M"/*.gguf; do basename "$f"; done ;;
  current)  current_model || say "(lane down)" ;;
  status)   code=$(health_code)
            say "health=$code model=$(current_model || echo none)" ;;
  plan)     g="${2:?plan needs a gguf name}"
            say "PLAN for $g:"
            say "  1. cmdline-checked stop of llama-server on :$PORT"
            say "  2. start: $LL -m $M/$g -md $M/$STOCK_DRAFTER --spec-type draft-dflash --spec-draft-n-max 7 -ngl 99 -fa on -c 524288 -np 2 --port $PORT"
            say "  3. health-verify /health up to 240s + /v1/models check"
            say "  4. on failure: loud rollback to $STOCK_MODEL"
            [ -f "$M/$g" ] && say "  file exists ✔" || say "  FATAL: $M/$g missing" ;;
  load)     load_model "${2:?load needs a gguf name}" ;;
  unload)   stop_lane; say "lane stopped (left down; start it with restore-stock or agent-lane.sh start)" ;;
  restore-stock) load_model "$STOCK_MODEL" ;;
  *) echo "usage: lane-models.sh list|current|status|plan <gguf>|load <gguf>|unload|restore-stock" >&2; exit 2 ;;
esac
