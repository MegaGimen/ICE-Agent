#!/usr/bin/env bash
# Box-local overrides for RTX PRO 6000 Blackwell (sm_120, 96GB DEDICATED VRAM), Clore container.
# Differs from the GB10 plan: dedicated VRAM (no unified-memory page-cache contention, no drop_caches),
# 96GB total (vs 120GB), and co-locating vLLM + Kev-27B on ONE card, so Kev runs lean.
export HOME="${HOME:-/root}"
export ICE_ENVS=/root/ice-envs
export HF_HUB_CACHE=/root/ice_models
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
export VLLM_PY=/root/ice-envs/vllm-env/bin/python
export VLLM_BIN=/root/ice-envs/vllm-env/bin/vllm
export KEV_PY=/root/ice-envs/kev-env/bin/python
export VLLM_PORT=8000 KEV_PORT=8010
export QWEN_MODEL=nvidia/Qwen3.6-35B-A3B-NVFP4
export KEV_MODEL=jaredpalmer/kev-27b
export KEV_MODEL_FALLBACK=jaredpalmer/kev-9b
# vLLM NVFP4 MoE: marlin GEMM (generic Blackwell), no flashinfer MoE JIT
export VLLM_USE_FLASHINFER_MOE_FP4=0 VLLM_NVFP4_GEMM_BACKEND=marlin VLLM_MARLIN_USE_ATOMIC_ADD=1
# 96GB co-location budget: vLLM ~0.30 (~29GB weights+KV), Kev ~58GB. max-model-len trimmed to save KV.
export VLLM_GPU_UTIL="${VLLM_GPU_UTIL:-0.30}"
export VLLM_MAX_MODEL_LEN="${VLLM_MAX_MODEL_LEN:-65536}"
# Kev lean: no prefix-state cache, no CUDA-graph buffers, truncate over-length states instead of 422.
export KEV_PREFIX_CACHE="${KEV_PREFIX_CACHE:-0}"
export KEV_CUDA_GRAPHS="${KEV_CUDA_GRAPHS:-0}"
export KEV_TRUNCATE_STATES="${KEV_TRUNCATE_STATES:-1}"
export ICE_RUN_DIR=/root/ice-build
mkdir -p "$ICE_RUN_DIR"
# Triton/vLLM JIT needs a host C compiler (and a CUDA bin for ptxas when present).
export CC="${CC:-gcc}" CXX="${CXX:-g++}"
export TRITON_PTXAS_PATH="${TRITON_PTXAS_PATH:-}"
# No nvcc/CUDA-toolkit in this container: keep vLLM off FlashInfer (its sampler/attn JIT needs nvcc).
# NVFP4 MoE already runs via Marlin (no nvcc); sampler falls back to the Torch-native path.
export VLLM_USE_FLASHINFER_SAMPLER=0
export VLLM_ATTENTION_BACKEND="${VLLM_ATTENTION_BACKEND:-TRITON_ATTN}"
export VLLM_USE_FLASHINFER_MOE_FP4=0

# --- OpenClaw investigation agent (installed 2026-11-03) ---
# agent.py shells out to $ICE_NC <sandbox> agent ...; oc.sh maps that onto `openclaw agent --local`
# (no OpenShell/Docker sandbox: this container is not privileged). ICE_AGENT_USER empty = stay root,
# since OpenClaw state lives in /root/.openclaw and there is no dell user on this box.
export ICE_NC=/root/ICE/ice/serving/oc.sh
export ICE_AGENT_USER=
export PATH=/root/node24/bin:$PATH
export OPENCLAW_DISABLE_TELEMETRY=1 NODE_NO_WARNINGS=1

# --- test-box posture (no Slack): approve everything, execute nothing ---
# ICE_AUTO_APPROVE=1 : every ASK is approved locally with no human (runtime._AutoApproveStore).
# ICE_DRY_RUN=1      : gate verdicts + approvals run as usual but NO command is executed.
#   These two belong together. Turning dry run off while auto-approve is on lets ICE run
#   irreversible containment as root on this host (it has proposed `rm -f /root/.ssh/authorized_keys`,
#   which would end SSH access to this box). Flip ICE_DRY_RUN only with a human approver wired up.
export ICE_AUTO_APPROVE=1
export ICE_DRY_RUN=1
# Critical assets for THIS box (config.py defaults point at a /home/dell GB10 layout that does not
# exist here, so ICE was not protecting its own install or the SSH key).
export ICE_CRITICAL_ASSETS="/root/ICE,/root/ice-envs,/root/ice_models,/root/ice-state,/root/ice-build,/root/.ssh,/root/.ssh/authorized_keys,/root/.openclaw,/root/node24,ice,ice-daemon,vllm,kev,openclaw,osqueryd,sshd,8000,8010,8020,8083,8088,127.0.0.1"
