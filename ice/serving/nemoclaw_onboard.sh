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
  # Slack 访问白名单（成员 ID / 频道 ID，逗号分隔；不是密钥）。不设 = DM 走 pairing、频道全部忽略。
  SLACK_ALLOWED_USERS="${SLACK_ALLOWED_USERS:-$(sed -nE 's/^slack-allowed-users=(.*)$/\1/p' "$ENV_FILE")}"
  SLACK_ALLOWED_CHANNELS="${SLACK_ALLOWED_CHANNELS:-$(sed -nE 's/^slack-allowed-channels=(.*)$/\1/p' "$ENV_FILE")}"
  if [ -n "$SLACK_ALLOWED_USERS" ]; then export SLACK_ALLOWED_USERS; fi
  if [ -n "$SLACK_ALLOWED_CHANNELS" ]; then export SLACK_ALLOWED_CHANNELS; fi
fi

# MCP 私有 CA（plan §9 step 2）：沙箱要信任 deploy/create-local-ca.sh 生成的 CA，必须在 onboard 时给。
CA="$HERE/../../deploy/local-secrets/ca.crt"
if [ -f "$CA" ]; then export NEMOCLAW_CORPORATE_CA_BUNDLE="$(readlink -f "$CA")"; fi

# OpenClaw 自带 system prompt + 工具定义约 22k tokens；context 必须 >8192（vLLM 也要 --max-model-len ≥ 此值）。
# MAX_TOKENS 给足：Qwen 先思考再调工具。
export NEMOCLAW_NON_INTERACTIVE=1 NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE=1 NEMOCLAW_DISABLE_TELEMETRY=1
export NEMOCLAW_PROVIDER=vllm NEMOCLAW_MODEL="${QWEN_MODEL:-nvidia/Qwen3.6-35B-A3B-NVFP4}"
export NEMOCLAW_SANDBOX_NAME="$SANDBOX" NEMOCLAW_POLICY_MODE=suggested
export NEMOCLAW_CONTEXT_WINDOW="${NEMOCLAW_CONTEXT_WINDOW:-65536}" NEMOCLAW_MAX_TOKENS="${NEMOCLAW_MAX_TOKENS:-8192}"
"$NC" onboard --non-interactive

# Disable OpenClaw's built-in heartbeat (plan: ICE's own daemon drives everything; the heartbeat only
# DMs the operator and spends inference). every=0m stops the recurring self-poll, target=none silences it.
HB="$HOME/.nemoclaw/sandboxes" # noqa
"$NC" "$SANDBOX" exec -- python3 -c "import json;p='/sandbox/.openclaw/openclaw.json';c=json.load(open(p));c.setdefault('agents',{}).setdefault('defaults',{})['heartbeat']={'every':'0m','target':'none'};json.dump(c,open(p,'w'),indent=1);print('heartbeat disabled')" || true

# 重建沙箱会丢掉 MCP 注册：主机侧 MCP（deploy/run_mcp_link.sh）在跑时自动重新注册（plan §9 step 5）。
TOKEN_FILE="$HERE/../../deploy/local-secrets/mcp.token"
MCP_IP="${ICE_MCP_PRIVATE_IP:-172.18.0.1}"
if [ -f "$TOKEN_FILE" ] && ss -ltn | grep -q "$MCP_IP:8443 "; then
  ICE_MCP_TOKEN="$(cat "$TOKEN_FILE")"; export ICE_MCP_TOKEN
  # 旧沙箱的 MCP provider 会残留在 OpenShell 网关里；新沙箱没有对应策略时 mcp add 报
  # "non-prefix partial state" 并拒绝注册，所以先删掉它（不存在时无害）。
  PATH="$HOME/.local/bin:$PATH" sg docker -c "openshell provider delete $SANDBOX-mcp-ice-host" >/dev/null 2>&1 || true
  "$NC" "$SANDBOX" mcp add ice-host --url "https://$MCP_IP:8443/mcp" --env ICE_MCP_TOKEN \
    --trusted-private-host "$MCP_IP" | tail -2
else
  echo "MCP link not running; register later: nc.sh $SANDBOX mcp add ice-host --url https://$MCP_IP:8443/mcp ..." >&2
fi
