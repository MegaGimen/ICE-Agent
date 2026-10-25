#!/usr/bin/env bash
# 启动主模型 vLLM（plan.md §7.1 / §8.3 step 4）。
# 必须先于 Kev 启动：vLLM 启动时检查"空闲 ≥ util×总内存"。
# 用法: start_vllm.sh [--fg]   默认后台启动并把日志写到 $ICE_RUN_DIR/vllm.log
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$HERE/env.sh"

LOG="$ICE_RUN_DIR/vllm.log"

if ss -ltn 2>/dev/null | grep -q ":$VLLM_PORT "; then
  echo "端口 $VLLM_PORT 已在监听，vLLM 似乎已启动。用 'fuser -k $VLLM_PORT/tcp' 先停。" >&2
  exit 1
fi

CMD=( "$VLLM_BIN" serve "$QWEN_MODEL"
  --port "$VLLM_PORT"
  --gpu-memory-utilization 0.35
  --max-model-len 8192
  --max-num-seqs 2
  --enable-auto-tool-choice
  --tool-call-parser qwen3_coder )
# 注意：不加 --reasoning-parser；不要把 sm_121 加进 vLLM 的 FP4_ARCHS。

echo ">>> Marlin 后端环境："
echo "    VLLM_USE_FLASHINFER_MOE_FP4=$VLLM_USE_FLASHINFER_MOE_FP4"
echo "    VLLM_NVFP4_GEMM_BACKEND=$VLLM_NVFP4_GEMM_BACKEND"
echo "    VLLM_MARLIN_USE_ATOMIC_ADD=$VLLM_MARLIN_USE_ATOMIC_ADD"
echo ">>> 模型: $QWEN_MODEL  (HF_HUB_CACHE=$HF_HUB_CACHE)"
echo ">>> 命令: ${CMD[*]}"

if [ "${1:-}" = "--fg" ]; then
  exec "${CMD[@]}"
else
  nohup "${CMD[@]}" > "$LOG" 2>&1 &
  echo ">>> vLLM 后台启动 pid $!，日志: $LOG"
  echo ">>> 就绪约需 6 分钟。等待就绪: ice/serving/health_check.sh vllm --wait"
fi
