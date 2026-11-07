#!/usr/bin/env bash
# Start an episode: a clean machine, the baseline reading taken, and nothing done to it yet.
#
#   ice/exercise/record_t0.sh
#
# It resets -- a fresh overlay over the golden image IS a clean machine, and anything left running
# from a previous attempt is shut down -- boots it, checks the daemon came up with it, takes the T0
# osquery reading, and stops. It prints the ssh command for the machine.
#
# Then do whatever this episode is about, by hand or with a script of your own, and finish with
# ice/exercise/record_t1.sh <benign|attack>. The state in between lives in
# $ICE_RUN_DIR/episode-in-progress.json.
set -euo pipefail
cd "$(dirname "$0")/../.."
export HOME=/root
[ -f /root/.ice-env ] && . /root/.ice-env
# shellcheck source=ice/serving/record_env_vm.sh
source ice/serving/record_env_vm.sh
exec "$ICE_DAEMON_PY" -u -m ice.exercise.record t0 "$@"
