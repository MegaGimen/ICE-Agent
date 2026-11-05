#!/usr/bin/env bash
# Recording posture for ice.exercise.record (dataset collection), on top of env.sh + env.box.sh.
#   source ice/serving/record_env.sh
#
# This is NOT the monitoring posture. Actions execute for real here, because each agent step has to
# build on the real consequences of the previous one; a dry-run trajectory would be counterfactual.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$HERE/env.sh"
# shellcheck source=env.box.sh
source "$HERE/env.box.sh"

export ICE_RECORD_MODE=1        # Kev is not a safety-gate veto; it scores the finished trajectory
export ICE_AUTO_APPROVE=1       # no human in the loop
export ICE_DRY_RUN=0            # execute for real (overrides env.box.sh)

export ICE_STATE_DIR="${ICE_STATE_DIR:-/root/ice-state}"
# Every change reaches investigation and no decision model is consulted. The flag file this used to
# key off existed for a pre-attack warmup that no longer happens: T0 is the image, ready, and the
# attack is the first thing that touches the machine, so there is no reset noise to protect against.
export ICE_FORCE_ESCALATE=1

# Deterministic floor, deliberately kept: static policy, not Kev's judgement and not a human gate.
# Without it an episode can delete this rig's SSH key or models and end the whole data collection.
export ICE_DENY_CRITICAL_ASSETS=1

export ICE_DATASET_DIR="${ICE_DATASET_DIR:-/root/ice-dataset}"
export ICE_RIG_DIR="${ICE_RIG_DIR:-/root/ice-rig}"
export ICE_DAEMON_PY="${ICE_DAEMON_PY:-/root/ice-envs/daemon-env/bin/python}"
export ICE_OPENCLAW_BIN="${ICE_OPENCLAW_BIN:-/root/node24/bin/openclaw}"

# Per-episode timing. The ssh-sandboxed agent is slow (every exec round-trips over SSH), so the
# investigation timeout is generous; raise ICE_RECORD_TIMEOUT if episodes time out.
export ICE_RECORD_WARMUP="${ICE_RECORD_WARMUP:-75}"    # seconds for the daemon to take T0 of the clean box
export ICE_RECORD_TIMEOUT="${ICE_RECORD_TIMEOUT:-900}" # seconds to wait for an investigated case
export ICE_RECORD_SETTLE="${ICE_RECORD_SETTLE:-60}"    # seconds to let remediation + backward finish

echo ">>> recording posture: RECORD_MODE=$ICE_RECORD_MODE AUTO_APPROVE=$ICE_AUTO_APPROVE" \
     "DRY_RUN=$ICE_DRY_RUN DENY_CRITICAL=$ICE_DENY_CRITICAL_ASSETS"
echo ">>> force-escalate: every change is investigated; no decision model is consulted"
echo ">>> dataset: $ICE_DATASET_DIR   state: $ICE_STATE_DIR   baseline: $ICE_RIG_DIR"
