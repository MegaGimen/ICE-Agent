#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/env.sh"; source "$HERE/env.box.sh"
MODEL="$KEV_MODEL"; FG=0
for a in "$@"; do case "$a" in --fallback) MODEL="$KEV_MODEL_FALLBACK";; --fg) FG=1;; esac; done
LOG="$ICE_RUN_DIR/kev.log"
if ss -ltn 2>/dev/null | grep -q ":$KEV_PORT "; then echo "port $KEV_PORT busy" >&2; exit 1; fi
CMD=( "$KEV_PY" -m kev.serve --run "$MODEL" --port "$KEV_PORT" --device cuda )
echo ">>> model $MODEL port $KEV_PORT (PREFIX_CACHE=$KEV_PREFIX_CACHE CUDA_GRAPHS=$KEV_CUDA_GRAPHS TRUNCATE=$KEV_TRUNCATE_STATES)"
if [ "$FG" = 1 ]; then exec "${CMD[@]}"; fi
setsid "${CMD[@]}" > "$LOG" 2>&1 < /dev/null &
echo ">>> Kev pid $! log $LOG"
