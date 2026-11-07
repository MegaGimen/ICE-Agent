#!/usr/bin/env bash
# Record one episode. The host-side entry point: everything about what the episode does lives in
# the arm script it is handed, so a new case is a new file, not an edit to the recorder.
#
#   ice/exercise/record_episode.sh <benign|attack> <arm-script> [expected-file]
#
#   benign | attack   benign: scored on the operator's-work axis (best 0), and the judge is told no
#                     attack was armed. attack: scored on the seven clearing/damage axes.
#   arm-script        a shell script, run whole inside the VM between T0 and T1 -- the change this
#                     episode is about. $ICE_ARM_URL is the base of a loopback server over the rig
#                     directory, so the script can `curl -s $ICE_ARM_URL/<file> -o ...` to bring an
#                     unknown file onto the machine the way a real one would arrive.
#   expected-file     benign only, optional: one line per thing the operator placed, for the judge
#                     to check the agent left alone. Lines starting with # are ignored.
#
# Deliberate interference (stop the agent part way, inject destructive commands after it) is not
# here: those are research knobs on ice.exercise.record, not part of the standard recording.
set -euo pipefail

usage() { echo "usage: record_episode.sh <benign|attack> <arm-script> [expected-file]" >&2; exit 2; }
[ $# -ge 2 ] || usage
case "$1" in
  benign) BENIGN=1 ;;
  attack) BENIGN=0 ;;
  *) echo "first argument must be 'benign' or 'attack', not '$1'" >&2; usage ;;
esac
ARM=$(realpath "$2")
[ -f "$ARM" ] || { echo "arm script not found: $2" >&2; exit 2; }
EXP=""
if [ $# -ge 3 ] && [ -n "$3" ]; then
  EXP=$(realpath "$3")
  [ -f "$EXP" ] || { echo "expected-file not found: $3" >&2; exit 2; }
fi

cd "$(dirname "$0")/../.."
export HOME=/root
[ -f /root/.ice-env ] && . /root/.ice-env
# shellcheck source=ice/serving/record_env_vm.sh
source ice/serving/record_env_vm.sh

echo ">>> arm=$1 script=$ARM${EXP:+ expected=$EXP}"
exec env \
  ICE_ARM_SCRIPT="$ARM" \
  ICE_ARM_BENIGN="$BENIGN" \
  ICE_ARM_EXPECTED="$EXP" \
  "$ICE_DAEMON_PY" -u -m ice.exercise.record run persistence --episodes 1
