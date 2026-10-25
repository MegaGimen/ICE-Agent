#!/usr/bin/env bash
# 知识库 / 经验库的句向量检索服务（plan.md §7.3 bge-m3）。跑在 kev-env 的 CPU 上，不占 GPU。
# 用法: start_embed.sh [--fg]   日志 $ICE_RUN_DIR/embed.log，监听 127.0.0.1:8020
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$HERE/env.sh"
cd "$HERE/../.."
[ -f "$HOME/ice-data/kb/attack.jsonl" ] || python3 -m ice.kb.attack_build
export CUDA_VISIBLE_DEVICES=
if [ "${1:-}" = "--fg" ]; then exec "$KEV_PY" -m ice.kb.embed_service; fi
nohup "$KEV_PY" -m ice.kb.embed_service > "$ICE_RUN_DIR/embed.log" 2>&1 &
echo ">>> embed service pid $!，日志 $ICE_RUN_DIR/embed.log"
