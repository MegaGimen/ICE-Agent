#!/usr/bin/env bash
# ICE 公共环境变量 —— 所有 serving 脚本 source 本文件。
# plan.md §7.1 / §8.3：模型路径必须用 HF_HUB_CACHE（HF_HOME 会找不到模型）。

# 模型缓存（HF 缓存目录）。优先用主盘 NVMe 副本（加载快），没有则退回 U 盘（exFAT，慢）。
if [ -z "${HF_HUB_CACHE:-}" ]; then
  if [ -d "$HOME/ice_models/models--jaredpalmer--kev-27b" ]; then
    HF_HUB_CACHE="$HOME/ice_models"
  else
    HF_HUB_CACHE="/media/dell/TECLAST/models/ice_models"
  fi
fi
export HF_HUB_CACHE
export HF_HUB_OFFLINE="${HF_HUB_OFFLINE:-1}"
export TRANSFORMERS_OFFLINE="${TRANSFORMERS_OFFLINE:-1}"

# venv 位置（install_offline.sh 默认装到 ~/ice-envs）
export ICE_ENVS="${ICE_ENVS:-$HOME/ice-envs}"
export VLLM_PY="${VLLM_PY:-$ICE_ENVS/vllm-env/bin/python}"
export VLLM_BIN="${VLLM_BIN:-$ICE_ENVS/vllm-env/bin/vllm}"
export KEV_PY="${KEV_PY:-$ICE_ENVS/kev-env/bin/python}"

# 服务端口（plan.md §8.1）
export VLLM_PORT="${VLLM_PORT:-8000}"
export KEV_PORT="${KEV_PORT:-8010}"

# 模型 ID（HF 仓库名，缓存命中后不会联网）
export QWEN_MODEL="${QWEN_MODEL:-nvidia/Qwen3.6-35B-A3B-NVFP4}"
export KEV_MODEL="${KEV_MODEL:-jaredpalmer/kev-27b}"
export KEV_MODEL_FALLBACK="${KEV_MODEL_FALLBACK:-jaredpalmer/kev-9b}"

# GB10 sm_121 上 NVFP4 走 Marlin 后端（plan.md §7.1）
export VLLM_USE_FLASHINFER_MOE_FP4="${VLLM_USE_FLASHINFER_MOE_FP4:-0}"
export VLLM_NVFP4_GEMM_BACKEND="${VLLM_NVFP4_GEMM_BACKEND:-marlin}"
export VLLM_MARLIN_USE_ATOMIC_ADD="${VLLM_MARLIN_USE_ATOMIC_ADD:-1}"

# 运行日志目录
export ICE_RUN_DIR="${ICE_RUN_DIR:-$HOME/ice-build}"
mkdir -p "$ICE_RUN_DIR"

# FlashInfer / Triton 运行时要 JIT 编译（需 ninja + nvcc）。脚本直接调 venv 里的二进制、不 activate，
# 所以要手动把 venv bin 和 CUDA bin 放进 PATH，否则报 "No such file or directory: 'ninja'"。
export CUDA_HOME="${CUDA_HOME:-/usr/local/cuda}"
export PATH="$ICE_ENVS/vllm-env/bin:$CUDA_HOME/bin:$PATH"
