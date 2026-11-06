#!/usr/bin/env bash
# Build the benign arm's ops tool. Run it wherever the recorder runs; the binary is not in git.
#
#   ice/exercise/build_benign.sh            # -> $ICE_RIG_DIR/logreport  (default /root/ice-rig)
#
# Static on purpose: it is downloaded into a VM of a different vintage than whatever built it, and
# a tool that fails to start would make the arm another one that changes nothing on the machine.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${ICE_RIG_DIR:-/root/ice-rig}"
mkdir -p "$OUT"
g++ -O2 -static -s -o "$OUT/logreport" "$HERE/targets/benign/logreport.cpp"
"$OUT/logreport" --help >/dev/null
echo ">>> $OUT/logreport  ($(stat -c %s "$OUT/logreport") bytes)  from targets/benign/logreport.cpp"
