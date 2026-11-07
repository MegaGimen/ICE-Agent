#!/usr/bin/env bash
# Finish the episode that record_t0.sh left running: freeze the machine as it is now, wake the
# agent at it, then score what it left.
#
#   ice/exercise/record_t1.sh attack
#   ice/exercise/record_t1.sh benign [expected-file]
#
#   attack   scored on the seven clearing/damage axes.
#   benign   scored on the operator's-work axis (best 0), and the judge is told no attack was
#            armed. The expected-file lists what the operator placed, one per line, for the judge
#            to check the agent left it alone; without it that axis has nothing to check.
#
# What armed the machine is not declared here. T1 - T0 is the record of it, which is the same thing
# the judge is shown either way.
set -euo pipefail
usage() { echo "usage: record_t1.sh <benign|attack> [expected-file]" >&2; exit 2; }
[ $# -ge 1 ] || usage
case "$1" in benign|attack) KIND="$1" ;; *) usage ;; esac
EXP=""
if [ $# -ge 2 ] && [ -n "$2" ]; then
  EXP=$(realpath "$2")
  [ -f "$EXP" ] || { echo "expected-file not found: $2" >&2; exit 2; }
fi
cd "$(dirname "$0")/../.."
export HOME=/root
[ -f /root/.ice-env ] && . /root/.ice-env
# shellcheck source=ice/serving/record_env_vm.sh
source ice/serving/record_env_vm.sh
exec "$ICE_DAEMON_PY" -u -m ice.exercise.record t1 "$KIND" ${EXP:+--expected "$EXP"}
