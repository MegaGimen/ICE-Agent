#!/usr/bin/env bash
# Start the MCP link: link-test MCP on 127.0.0.1:8083 + nginx TLS on PRIVATE_IP:8443 (plan §9 step 4).
# Usage: deploy/run_mcp_link.sh [start|stop|status]
# Token lives in deploy/local-secrets/mcp.token (gitignored). Swap the link-test server for
# ice/daemon/mcp_server.py later; nginx and the NemoClaw registration stay the same.
set -euo pipefail
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$D/local-secrets"
RUN="${ICE_RUN_DIR:-$HOME/ice-build}/mcp-link"
PRIVATE_IP="${ICE_MCP_PRIVATE_IP:-172.18.0.1}"
mkdir -p "$RUN"

case "${1:-start}" in
start)
  [ -f "$S/mcp.crt" ] || { echo "run deploy/create-local-ca.sh $PRIVATE_IP first" >&2; exit 1; }
  [ -f "$S/mcp.token" ] || (umask 077; python3 -c 'import secrets;print(secrets.token_urlsafe(32))' > "$S/mcp.token")
  sed -e "s#PRIVATE_IP#$PRIVATE_IP#g" -e "s#ABSOLUTE_WORKTREE_PATH#$(dirname "$D")#g" \
      "$D/nginx-ice-mcp.conf.template" > "$RUN/server.conf"
  cat > "$RUN/nginx.conf" <<CONF
worker_processes 1;
pid $RUN/nginx.pid;
error_log $RUN/nginx-error.log;
events { worker_connections 256; }
http {
  access_log $RUN/nginx-access.log;
  proxy_buffering off;
  include $RUN/server.conf;
}
CONF
  if ! ss -ltn | grep -q '127.0.0.1:8083 '; then
    ICE_MCP_TOKEN="$(cat "$S/mcp.token")" nohup "$HOME/ice-envs/daemon-env/bin/python" "$D/mcp_link_test.py" \
      > "$RUN/mcp.log" 2>&1 &
    echo "link-test MCP pid $!"
  fi
  sudo nginx -t -c "$RUN/nginx.conf" -p "$RUN" 2>&1 | tail -1
  if [ -f "$RUN/nginx.pid" ] && sudo kill -0 "$(cat "$RUN/nginx.pid")" 2>/dev/null; then
    sudo nginx -c "$RUN/nginx.conf" -p "$RUN" -s reload
  else
    sudo nginx -c "$RUN/nginx.conf" -p "$RUN"
  fi
  echo "MCP link: https://$PRIVATE_IP:8443/mcp -> 127.0.0.1:8083"
  ;;
stop)
  [ -f "$RUN/nginx.pid" ] && sudo nginx -c "$RUN/nginx.conf" -p "$RUN" -s quit || true
  fuser -k 8083/tcp 2>/dev/null || true
  ;;
status)
  ss -ltn | grep -E "127.0.0.1:8083 |$PRIVATE_IP:8443 " || echo "not listening"
  ;;
esac
