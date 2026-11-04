#!/usr/bin/env bash
# Pull recorded bundles off the recording box onto this machine.
#
# The box is a rented instance and its disk goes with it; four bundles were already lost to a
# relaunch script that cleared the dataset on every run. Bundles are small (about 1.7 MB each) and
# self-contained -- evidence.json carries the diffs the judge is handed -- so a copy here is a
# complete dataset, reviewable and re-judgeable without the box.
#
#   ice/exercise/sync_bundles.sh                 # pull new bundles
#   ice/exercise/sync_bundles.sh --delete-remote # pull, then free the space on the box
set -euo pipefail

BOX="${ICE_BOX:-root@220.86.159.73}"
PORT="${ICE_BOX_PORT:-21530}"
REMOTE="${ICE_BOX_DATASET:-/root/ice-dataset}"
LOCAL="${ICE_LOCAL_DATASET:-$(cd "$(dirname "$0")/../.." && pwd)/dataset}"

mkdir -p "$LOCAL"
echo ">>> $BOX:$REMOTE  ->  $LOCAL"
rsync -a --info=stats1 -e "ssh -p $PORT -o ConnectTimeout=15" "$BOX:$REMOTE/" "$LOCAL/"

if [ "${1:-}" = "--delete-remote" ]; then
    # Only ever after a successful rsync, and only bundles that arrived.
    for d in "$LOCAL"/*/; do
        name=$(basename "$d")
        [ -f "$d/episode.json" ] || continue
        ssh -p "$PORT" "$BOX" "rm -rf ${REMOTE}/${name}" && echo "    freed $name on the box"
    done
fi

echo ">>> $(ls -1d "$LOCAL"/*/ 2>/dev/null | wc -l) bundles here, $(du -sh "$LOCAL" | cut -f1) total"
