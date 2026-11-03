#!/usr/bin/env bash
# ICE -> OpenClaw bridge.
#
# ice/daemon/investigate/agent.py invokes the agent as (old NemoClaw sandbox CLI shape):
#     $ICE_NC <sandbox> agent --session-key <case_id> --json -m <message>
#
# OpenClaw 2026.10 has no sandbox positional and runs the agent embedded with --local.
# --local is what this box needs: the OpenShell/Docker sandbox cannot run here because the
# Clore container is not privileged (no cap_sys_admin, no iptables), so no nested dockerd.
#
# Point ICE at this script with ICE_NC=/root/ICE/ice/serving/oc.sh and set ICE_AGENT_USER=
# (empty) so the root daemon does not try to sudo to a non-existent 'dell' user.
set -euo pipefail

export HOME="${HOME:-/root}"
export PATH="/root/node24/bin:$PATH"          # OpenClaw needs node >= 24.22.1
export OPENCLAW_DISABLE_TELEMETRY=1 NODE_NO_WARNINGS=1

# Drop the sandbox name the old CLI took as its first positional.
if [ "$#" -gt 0 ]; then shift; fi

if [ "${1:-}" = "agent" ]; then
  shift
  exec openclaw agent --local "$@"
fi

# Anything else (mcp, config, models, ...) passes straight through.
exec openclaw "$@"
