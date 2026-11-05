#!/usr/bin/env bash
# Push this checkout to the recording box. The excludes are the point of the script.
#
#   ice/exercise/push_repo.sh            # then: ssh box 'bash /root/prep.sh' to rebuild the image
#
# deploy/local-secrets holds the MCP bearer token the daemon reads and the agent sends. It is
# gitignored, so this checkout does not have it, and a --delete sync from here once wiped it off
# the box -- after which every prepared image came up with a daemon that exited 1 before logging
# anything, and the episode aborted with "the daemon did not come up with the machine".
set -euo pipefail

BOX="${ICE_BOX:-root@220.86.159.73}"
PORT="${ICE_BOX_PORT:-21530}"
REMOTE="${ICE_BOX_REPO:-/root/ICE}"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"

rsync -a --delete --info=stats1 \
  --exclude deploy/local-secrets --exclude dataset --exclude .git \
  --exclude __pycache__ --exclude '*.pyc' --exclude .pytest_cache \
  -e "ssh -p $PORT -o ConnectTimeout=15" "$HERE/" "$BOX:$REMOTE/"
echo ">>> pushed $HERE -> $BOX:$REMOTE"
