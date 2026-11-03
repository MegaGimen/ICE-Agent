#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/env.sh"; source "$HERE/env.box.sh"
cd "$HERE/../.."
[ -f "$HOME/ice-data/kb/attack.jsonl" ] || "$KEV_PY" -m ice.kb.attack_build || true
export CUDA_VISIBLE_DEVICES=
LOG="$ICE_RUN_DIR/embed.log"
if [ "${1:-}" = "--fg" ]; then exec "$KEV_PY" -m ice.kb.embed_service; fi
setsid "$KEV_PY" -m ice.kb.embed_service > "$LOG" 2>&1 < /dev/null &
echo ">>> embed pid $! log $LOG (CPU, :8020)"
