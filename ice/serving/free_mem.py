#!/usr/bin/env python3
"""真实 GPU 可见空闲内存检查（plan.md §8.3）。

GB10 统一内存下 `free` 不准：刚拷完模型，页缓存占住统一内存，CUDA 可见空闲
会变小，vLLM 一启动就 OOM。用 torch.cuda.mem_get_info() 看 CUDA 实际可见空闲。

退出码 0 并打印 free/total(GiB)。可带阈值参数：free_mem.py 25  → 若空闲 < 25GiB 退出码 2。
"""
import sys

try:
    import torch
except Exception as e:  # pragma: no cover - 环境问题
    print(f"torch import failed: {e}", file=sys.stderr)
    sys.exit(3)

if not torch.cuda.is_available():
    print("CUDA not available", file=sys.stderr)
    sys.exit(3)

free, total = torch.cuda.mem_get_info()
gib = 1024 ** 3
free_g, total_g = free / gib, total / gib
print(f"CUDA visible free {free_g:.1f} GiB / total {total_g:.1f} GiB "
      f"(used {total_g - free_g:.1f} GiB)")

if len(sys.argv) > 1:
    need = float(sys.argv[1])
    if free_g < need:
        print(f"WARNING: free {free_g:.1f} GiB < required {need:.1f} GiB", file=sys.stderr)
        sys.exit(2)
