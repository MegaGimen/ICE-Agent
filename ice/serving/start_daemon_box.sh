#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/env.sh"; source "$HERE/env.box.sh"
cd "$HERE/../.."
export ICE_STATE_DIR="${ICE_STATE_DIR:-/root/ice-state}"
export ICE_DASHBOARD_PORT="${ICE_DASHBOARD_PORT:-8088}"
mkdir -p "$ICE_STATE_DIR"
DP=/root/ice-envs/daemon-env/bin/python
LOG="$ICE_RUN_DIR/daemon.log"
if [ "${1:-}" = "--fg" ]; then shift; exec "$DP" -m ice.daemon.main "$@"; fi
setsid "$DP" -m ice.daemon.main "$@" > "$LOG" 2>&1 < /dev/null &
echo ">>> daemon pid $! log $LOG (dashboard :$ICE_DASHBOARD_PORT, MCP :8083 loopback)"
