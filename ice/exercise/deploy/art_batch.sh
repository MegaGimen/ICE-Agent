#!/usr/bin/env bash
# Record one episode for every ART linux sh/bash test in the list, serially, slowly. Skips tests a
# bundle already exists for. Stops the whole batch on an LLM API error (e.g. quota/429) so it can
# be resumed after a top-up. Bundles are named art_<technique>_<guid8>-<ts>-001 (lower-case to
# satisfy intake) and carry their per-episode diff snapshots gzipped (ICE_BUNDLE_SNAPSHOTS=1).
# An arm that changes nothing the readings can see (unsatisfiable ART tests) is skipped by the
# recorder before the agent/judge run, so it costs a boot but no model-API round.
#
#   art_batch.sh /root/art-batch.list
set -u
LIST="${1:-/root/art-batch.list}"
ARTPY=/root/ice-envs/art-env/bin/python
ATOMICS=/root/art-atomics/atomics
KEY=/root/ice-vm/id_ed25519
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
L=/root/ice-logs
DS=/root/ice-dataset
STOP=/root/art-batch.STOP
cd /root/ICE
export HOME=/root
[ -f /root/.ice-env ] && . /root/.ice-env
source ice/serving/record_env_vm.sh
export ICE_BUNDLE_SNAPSHOTS=1
export ICE_ATOMICS_PATH=/opt/ice/atomics
rm -f "$STOP"

api_error() {   # look in a log for signatures that mean "the model API, not us"
  grep -qiE "usage allocated quota|quota exceeded|HTTP 429|rate.?limit|throttl|insufficient_quota|HTTP 50[0-9]|billing|payment" "$1" 2>/dev/null
}

n=0; done=0; skipped=0; empty=0
total=$(grep -c . "$LIST")
while read -r spec <&3; do
  [ -n "$spec" ] || continue
  n=$((n+1))
  tech="${spec%%:*}"; guid="${spec##*:}"
  pref="art_$(echo "$tech" | tr 'A-Z.' 'a-z_')_$(echo "$guid" | tr -d - | cut -c1-8)"
  if grep -lsq '"scored": true' "$DS/${pref}-"*/episode.json 2>/dev/null; then
    skipped=$((skipped+1)); echo "[$n/$total] skip $tech ($pref, scored bundle exists)"; continue
  fi
  echo "##### [$n/$total] $tech $guid  -> $pref  $(date -u +%H:%M:%S)"

  # render the real ART command; a test we cannot render (missing default, non-trivial deps) is
  # skipped, not a reason to stop the batch.
  if ! "$ARTPY" -m ice.exercise.art_render "$ATOMICS" "$tech" "$guid" > "$L/$pref.cmd" 2>"$L/$pref.render.err"; then
    echo "      render skip: $(tail -1 "$L/$pref.render.err")"; continue
  fi

  rm -f /root/ice-build/episode-in-progress.json
  ICE_EPISODE_PREFIX="$pref" bash ice/exercise/record_t0.sh > "$L/$pref.t0.log" 2>&1 || {
    echo "      t0 failed"; api_error "$L/$pref.t0.log" && { echo API-ERROR-STOP > "$STOP"; break; }; continue; }
  PORT=$("$ICE_DAEMON_PY" - <<'PYEOF'
import json; print(json.load(open("/root/ice-build/episode-in-progress.json"))["port"])
PYEOF
)
  # Run the arm detached, with its (and its children's) fds on files, so an ART test that
  # backgrounds a long-running process (a masqueraded daemon, a watcher, a busy-loop) does not
  # hold the ssh channel open and hang the batch. setsid + redirect frees the channel the
  # moment the foreground script returns; the 180s timeout is the backstop, by which point the
  # arm's persistent changes are already in place so T1 can proceed either way.
  timeout 420 ssh -i "$KEY" $SSH_OPTS -p "$PORT" root@127.0.0.1 \
    'cat > /tmp/ice_arm.sh; setsid bash /tmp/ice_arm.sh >/tmp/ice_arm.out 2>&1 </dev/null; echo "arm rc=$?"; sed "s/^/[arm] /" /tmp/ice_arm.out | tail -40; rm -f /tmp/ice_arm.sh /tmp/ice_arm.out' \
    < "$L/$pref.cmd" > "$L/$pref.arm.log" 2>&1
  ICE_EPISODE_PREFIX="$pref" bash ice/exercise/record_t1.sh attack > "$L/$pref.t1.log" 2>&1

  # did this episode fail because of the model API? if so, stop so the user can top up.
  bdir=$(ls -d "$DS/${pref}-"* 2>/dev/null | head -1)
  if api_error "$L/$pref.t1.log" || api_error "$L/$pref.arm.log"; then
    echo "      !! API error -> stopping the batch"; echo "API-ERROR at $tech $guid" > "$STOP"; break
  fi
  if [ -n "$bdir" ] && "$ICE_DAEMON_PY" - "$bdir/episode.json" <<'PYEOF'
import json,sys
r=(json.load(open(sys.argv[1])).get("reward") or {})
reason=str(r.get("unscored_reason") or "")
sys.exit(0 if any(k in reason for k in ("HTTP 429","quota","HTTP 50","throttl","rate limit")) else 1)
PYEOF
  then echo "      !! API error in judge -> stopping the batch"; echo "API-ERROR judge at $tech" > "$STOP"; break; fi

  # an arm that moved nothing is skipped by the recorder before the agent/judge ran; tally it as
  # empty, not done, so the final counts are honest.
  if [ -n "$bdir" ] && grep -q '"aborted": "empty arm"' "$bdir/episode.json" 2>/dev/null; then
    empty=$((empty+1)); echo "      empty arm (no T1-T0 change) -> skipped before agent/judge"; continue
  fi

  done=$((done+1))
  v=$(grep -E 'value=' "$L/$pref.t1.log" | tail -1)
  echo "##### [$n/$total] $tech done  $(date -u +%H:%M:%S)  $v"
done 3< "$LIST"

echo "##### BATCH END  recorded=$done empty=$empty skipped=$skipped  $([ -f "$STOP" ] && echo "STOPPED: $(cat "$STOP")" || echo "list exhausted")  $(date -u +%FT%TZ)"
