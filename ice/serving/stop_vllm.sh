#!/usr/bin/env bash
# 停 vLLM。注意：`fuser -k 8000/tcp` 只杀 API server，EngineCore 子进程会成孤儿继续占 ~44 GB 统一内存，
# 导致下次启动"空闲不足"失败。这里连 EngineCore 一起停，等内存真正释放。
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$HERE/env.sh"
fuser -k "$VLLM_PORT/tcp" 2>/dev/null || true
pkill -f 'VLLM::EngineCore' 2>/dev/null || true
for _ in $(seq 1 30); do
  pgrep -f 'VLLM::EngineCore|vllm serve' >/dev/null || { echo ">>> vLLM 已停"; exit 0; }
  sleep 2
done
echo ">>> 60s 后仍有残留，强制 kill -9" >&2
pkill -9 -f 'VLLM::EngineCore|vllm serve' 2>/dev/null || true
