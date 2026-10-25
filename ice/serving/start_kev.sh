#!/usr/bin/env bash
# 启动决策模型 Kev（plan.md §7.2 / §8.3 step 5）。必须在 vLLM 就绪之后再起。
# 用法: start_kev.sh [--fallback] [--fg]
#   --fallback  用 Kev-9B（更快，backward 更弱）而非 Kev-27B
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$HERE/env.sh"

MODEL="$KEV_MODEL"
FG=0
for a in "$@"; do
  case "$a" in
    --fallback) MODEL="$KEV_MODEL_FALLBACK" ;;
    --fg) FG=1 ;;
  esac
done

LOG="$ICE_RUN_DIR/kev.log"

if ss -ltn 2>/dev/null | grep -q ":$KEV_PORT "; then
  echo "端口 $KEV_PORT 已在监听，Kev 似乎已启动。用 'fuser -k $KEV_PORT/tcp' 先停。" >&2
  exit 1
fi

# Kev 绑 127.0.0.1（plan.md §8.1：主机侧守护进程调用，不对沙箱暴露）
CMD=( "$KEV_PY" -m kev.serve --run "$MODEL" --port "$KEV_PORT" --device cuda )
echo ">>> Kev 模型: $MODEL  端口: $KEV_PORT"
echo ">>> 命令: ${CMD[*]}"
echo ">>> （源码在 ~/ice-build/bundle/kev；此目录已随 kev-env 安装）"

if [ "$FG" = 1 ]; then
  exec "${CMD[@]}"
else
  nohup "${CMD[@]}" > "$LOG" 2>&1 &
  echo ">>> Kev 后台启动 pid $!，日志: $LOG"
  echo ">>> 等待就绪: ice/serving/health_check.sh kev --wait"
fi
