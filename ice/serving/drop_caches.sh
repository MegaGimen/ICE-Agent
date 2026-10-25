#!/usr/bin/env bash
# 清页缓存（plan.md §8.3 step 3）。刚从 U 盘拷/读模型后，页缓存占住统一内存，
# 需先清掉，否则 vLLM 启动检查"空闲 ≥ util×总内存"会失败 / OOM。
# 有 root 用 drop_caches；随后打印 CUDA 实际可见空闲。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$HERE/env.sh"

echo ">>> sync + drop_caches"
sync
if [ "$(id -u)" -eq 0 ]; then
  echo 3 > /proc/sys/vm/drop_caches
elif sudo -n true 2>/dev/null; then
  echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
else
  echo "WARN: 无 root，跳过 drop_caches（如遇 OOM 请手动 sudo 执行，或对模型文件 fadvise DONTNEED）" >&2
fi

echo ">>> CUDA 实际可见空闲（free 不准，以此为准）："
"$VLLM_PY" "$HERE/free_mem.py" || true
