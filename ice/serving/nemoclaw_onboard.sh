#!/usr/bin/env bash
# NemoClaw / OpenClaw 沙箱 onboard（推理接已在运行的本地 vLLM :8000）。先确认 vLLM 已就绪。
# 用法: nemoclaw_onboard.sh [--fresh]
#   --fresh  先删掉沙箱 'ice' 再建。改 context/max-tokens 必须用它：重建时 NemoClaw 会从
#            "重建前备份"恢复 /sandbox/.openclaw/openclaw.json，把新参数覆盖回旧值。
# Slack token 从仓库根目录 .env 读（键名 slack-bot-token / slack-app-token），不落盘、不打印。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NC="$HERE/nc.sh"
ENV_FILE="$HERE/../../.env"
SANDBOX="${NEMOCLAW_SANDBOX_NAME:-ice}"

curl -sf -m 5 localhost:8000/health >/dev/null || { echo "vLLM :8000 未就绪，先起 vLLM" >&2; exit 1; }

if [ "${1:-}" = "--fresh" ]; then
  # --keep-vllm：destroy 默认会停掉 vLLM
  "$NC" "$SANDBOX" destroy --yes --keep-vllm --no-cleanup-gateway || true
fi

if [ -f "$ENV_FILE" ]; then
  SLACK_BOT_TOKEN="$(sed -nE 's/^slack-bot-token=(.*)$/\1/p' "$ENV_FILE")"
  SLACK_APP_TOKEN="$(sed -nE 's/^slack-app-token=(.*)$/\1/p' "$ENV_FILE")"
  export SLACK_BOT_TOKEN SLACK_APP_TOKEN
fi

# OpenClaw 自带 system prompt + 工具定义约 22k tokens；context 必须 >8192（vLLM 也要 --max-model-len ≥ 此值）。
# MAX_TOKENS 给足：Qwen 先思考再调工具。
export NEMOCLAW_NON_INTERACTIVE=1 NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE=1 NEMOCLAW_DISABLE_TELEMETRY=1
export NEMOCLAW_PROVIDER=vllm NEMOCLAW_MODEL="${QWEN_MODEL:-nvidia/Qwen3.6-35B-A3B-NVFP4}"
export NEMOCLAW_SANDBOX_NAME="$SANDBOX" NEMOCLAW_POLICY_MODE=suggested
export NEMOCLAW_CONTEXT_WINDOW="${NEMOCLAW_CONTEXT_WINDOW:-65536}" NEMOCLAW_MAX_TOKENS="${NEMOCLAW_MAX_TOKENS:-8192}"
exec "$NC" onboard --non-interactive
