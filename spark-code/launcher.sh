#!/usr/bin/env bash
set -u
REPO="JonathanColetti/Qwen3.8-27B-Uncensored-GGUF"
FILE="Qwen3.8-27B-Uncensored-Q4_K_M.gguf"
mkdir -p "$HOME/models" || { echo "PREFLIGHT_FAIL: cannot create ~/models"; exit 1; }
cd "$HOME/models" || { echo "PREFLIGHT_FAIL: cd failed"; exit 1; }
if ! command -v hf >/dev/null 2>&1; then
  echo "PREFLIGHT_FAIL: 'hf' CLI not found in PATH=$PATH"
  exit 127
fi
echo "FREE_KB=$(df -Pk . | awk 'NR==2{print $4}')"
if [ -f "$FILE" ]; then
  echo "NOTE: existing file present:"; ls -lh "$FILE"
fi
nohup hf download "$REPO" "$FILE" --local-dir . > dl.log 2>&1 &
echo "LAUNCHED pid=$! log=$(pwd)/dl.log start=$(date)"
