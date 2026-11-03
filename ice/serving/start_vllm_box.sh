#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/env.sh"; source "$HERE/env.box.sh"
LOG="$ICE_RUN_DIR/vllm.log"
if ss -ltn 2>/dev/null | grep -q ":$VLLM_PORT "; then echo "port $VLLM_PORT busy; stop_vllm first" >&2; exit 1; fi
CMD=( "$VLLM_BIN" serve "$QWEN_MODEL" --port "$VLLM_PORT" --quantization modelopt --gpu-memory-utilization "$VLLM_GPU_UTIL" --max-model-len "$VLLM_MAX_MODEL_LEN" --max-num-seqs 2 --enable-auto-tool-choice --tool-call-parser qwen3_coder )
echo ">>> ${CMD[*]}"
if [ "${1:-}" = "--fg" ]; then exec "${CMD[@]}"; fi
setsid "${CMD[@]}" > "$LOG" 2>&1 < /dev/null &
echo ">>> vLLM pid $! log $LOG"
