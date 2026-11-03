#!/usr/bin/env bash
# Ordered startup for the Clore container (no systemd): vLLM -> Kev -> embed -> daemon.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/env.sh"; source "$HERE/env.box.sh"
w(){ local u="$1" n="$2" t="${3:-600}" i=0; echo -n ">>> wait $n "; until curl -sf -m5 "$u" >/dev/null 2>&1; do [ $i -ge $t ] && { echo " TIMEOUT"; return 1; }; echo -n .; sleep 5; i=$((i+5)); done; echo " OK(${i}s)"; }
echo "== vLLM =="; ss -ltn|grep -q ":$VLLM_PORT " || bash "$HERE/start_vllm_box.sh"; w "http://localhost:$VLLM_PORT/health" vLLM 600 || exit 1
echo "== Kev =="; ss -ltn|grep -q ":$KEV_PORT " || bash "$HERE/start_kev_box.sh" "$@"; w "http://localhost:$KEV_PORT/v1/models" Kev 900 || exit 1
echo "== embed =="; ss -ltn|grep -q ":8020 " || bash "$HERE/start_embed_box.sh"; w "http://127.0.0.1:8020/health" embed 300 || echo "(embed slow; continuing)"
echo "== daemon =="; bash "$HERE/start_daemon_box.sh"
echo ">>> ICE up. GPU:"; nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader
