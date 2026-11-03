#!/usr/bin/env bash
# ICE on the recording VM: no local models at all.
#
#   agent (investigation policy) : Alibaba Model Studio Token Plan, OpenAI-compatible, via OpenClaw
#   decision model (gate + judge): TypeSafe Jev, hosted System One  (KevClient talks to it unchanged)
#   embedding                    : bge-m3 on this box's CPU
#
# Unlike the GPU box this machine is a real privileged VM (systemd PID 1, cap_sys_admin, cap_net_admin,
# docker, /dev/kvm), so per-episode disposable target containers and iptables scenarios are possible.
#
# Secrets come from the repo .env (gitignored), keyed `Jev` and `Bailian`. Never echo them.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

_ice_env_value() {   # $1 = key in .env
  [ -f "$REPO/.env" ] || return 0
  sed -nE "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*(.*[^[:space:]])[[:space:]]*$/\1/p" "$REPO/.env" | head -1
}

# ---- decision model: Jev (hosted System One) -------------------------------------------------
# KevClient appends /v1/systemone and /v1/models to KEV_URL, so the bare root is what it wants.
export KEV_URL="${KEV_URL:-https://api.typesafe.ai}"
export KEV_MODEL="${KEV_MODEL:-jev-latest}"
export KEV_TIMEOUT="${KEV_TIMEOUT:-120}"
if [ -z "${KEV_API_KEY:-}" ]; then KEV_API_KEY="$(_ice_env_value Jev)"; export KEV_API_KEY; fi

# ---- agent model: Token Plan (used by OpenClaw, configured in ~/.openclaw/openclaw.json) ------
export ICE_AGENT_BASE_URL="${ICE_AGENT_BASE_URL:-https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1}"
export ICE_AGENT_MODEL="${ICE_AGENT_MODEL:-qwen3.8-max}"
if [ -z "${ICE_AGENT_API_KEY:-}" ]; then ICE_AGENT_API_KEY="$(_ice_env_value Bailian)"; export ICE_AGENT_API_KEY; fi

# ---- health gating ---------------------------------------------------------------------------
# The agent model is a hosted API with no endpoint for us to poll, so drop that check. Kev's check
# follows KEV_URL automatically (main.py). The embedding service is local, so it stays.
export ICE_MAIN_MODEL_HEALTH=""

# ---- ICE itself ------------------------------------------------------------------------------
export ICE_STATE_DIR="${ICE_STATE_DIR:-/root/ice-state}"
export ICE_RUN_DIR="${ICE_RUN_DIR:-/root/ice-build}"
export ICE_DATASET_DIR="${ICE_DATASET_DIR:-/root/ice-dataset}"
export ICE_RIG_DIR="${ICE_RIG_DIR:-/root/ice-rig}"
export ICE_OSQUERYI="${ICE_OSQUERYI:-/usr/bin/osqueryi}"
export ICE_DAEMON_PY="${ICE_DAEMON_PY:-/root/ice-envs/daemon-env/bin/python}"
export ICE_EMBED_PY="${ICE_EMBED_PY:-/root/ice-envs/embed-env/bin/python}"
export HF_HUB_CACHE="${HF_HUB_CACHE:-/root/ice_models}"

# ---- OpenClaw / investigation agent ----------------------------------------------------------
export PATH="/root/node24/bin:/root/.local/bin:$PATH"
export OPENCLAW_DISABLE_TELEMETRY=1 NODE_NO_WARNINGS=1
export ICE_OPENCLAW_BIN="${ICE_OPENCLAW_BIN:-/root/node24/bin/openclaw}"
# agent.py shells out to $ICE_NC <sandbox> agent ...; oc.sh maps that onto `openclaw agent --local`.
export ICE_NC="${ICE_NC:-$REPO/ice/serving/oc.sh}"
export ICE_AGENT_USER="${ICE_AGENT_USER:-}"

mkdir -p "$ICE_RUN_DIR" "$ICE_STATE_DIR"

echo ">>> decision model: $KEV_MODEL @ $KEV_URL  (key $([ -n "$KEV_API_KEY" ] && echo set || echo MISSING))"
echo ">>> agent model   : $ICE_AGENT_MODEL @ ${ICE_AGENT_BASE_URL%/*}/…  (key $([ -n "$ICE_AGENT_API_KEY" ] && echo set || echo MISSING))"
echo ">>> no local model services; main-model health check disabled"
