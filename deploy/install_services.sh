#!/usr/bin/env bash
# Install and start ICE as resident services (plan §6.1: the host daemon runs as root).
#   sudo deploy/install_services.sh          # first install / update units
# Kill switch while running: sudo touch /var/lib/ice/KILL   (rm to release)
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$D")"
OWNER="${ICE_OWNER:-dell}"
STATE=/var/lib/ice
PRIVATE_IP="${ICE_MCP_PRIVATE_IP:-172.18.0.1}"

# 1. state: host-only, root-owned. Carry over the development state once (baseline, snapshots, cases, graph, audit).
if [ ! -d "$STATE" ]; then
  if [ -d "/home/$OWNER/ice-state" ]; then cp -a "/home/$OWNER/ice-state" "$STATE"; else mkdir -p "$STATE"; fi
  chown -R root:root "$STATE"
fi
chmod 700 "$STATE"

# 2. nginx config for the MCP TLS proxy
mkdir -p /etc/ice
sed -e "s#PRIVATE_IP#$PRIVATE_IP#g" -e "s#ABSOLUTE_WORKTREE_PATH#$REPO#g" "$D/nginx-ice-mcp.conf.template" > /etc/ice/nginx-mcp-server.conf
cat > /etc/ice/nginx-mcp.conf <<CONF
worker_processes 1;
pid /run/ice-mcp-proxy.pid;
error_log /var/log/ice-mcp-proxy.error.log;
events { worker_connections 256; }
http {
  access_log /var/log/ice-mcp-proxy.access.log;
  proxy_buffering off;
  include /etc/ice/nginx-mcp-server.conf;
}
CONF

# 3. stop the hand-started development processes these units replace
RUN="/home/$OWNER/ice-build/mcp-link"
if [ -f "$RUN/nginx.pid" ] && kill -0 "$(cat "$RUN/nginx.pid")" 2>/dev/null; then
  nginx -c "$RUN/nginx.conf" -p "$RUN" -s quit || true
fi
pkill -u "$OWNER" -f 'ice.kb.embed_service' || true
fuser -k 8083/tcp 2>/dev/null || true
sleep 2

# 4. units
install -m 644 "$D"/systemd/ice-*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ice-embed.service ice-mcp-proxy.service ice-daemon.service
systemctl --no-pager --lines=0 status ice-embed.service ice-mcp-proxy.service ice-daemon.service | grep -E '●|Active:'
