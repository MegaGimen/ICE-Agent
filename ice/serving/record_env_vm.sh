#!/usr/bin/env bash
# Recording posture on the VM (hosted models). Source this, not record_env.sh (that one is for the
# GPU box and sources env.box.sh).
#
#   source ice/serving/record_env_vm.sh
#
# Actions execute for real: each agent step has to build on the real consequences of the previous
# one, so a dry-run trajectory would be counterfactual. This VM is privileged, so the target is
# meant to be a disposable container -- until that lands, reset is the scoped tar snapshot.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.vm.sh
source "$HERE/env.vm.sh"

export ICE_RECORD_MODE=1        # the decision model is not a safety-gate veto; it scores instead
export ICE_AUTO_APPROVE=1       # no human in the loop
export ICE_DRY_RUN=0            # execute for real

# Force every change to investigation, but only while an attack is armed (the recorder touches the
# flag just before arming). Forcing for the whole run spends the episode on reset/warmup noise.
export ICE_FORCE_ESCALATE_FLAG="$ICE_STATE_DIR/FORCE_ESCALATE"

# Deterministic floor: static policy, not the decision model's judgement and not a human gate.
# Without it an auto-approved episode can delete this rig's own access or stop its services.
export ICE_DENY_CRITICAL_ASSETS=1
export ICE_CRITICAL_ASSETS="${ICE_CRITICAL_ASSETS:-/root/ICE,/root/ice-envs,/root/ice-state,/root/ice-build,/root/ice-dataset,/root/ice-rig,/root/ice_models,/root/ice-data,/root/.ssh,/root/.ssh/authorized_keys,/root/.openclaw,/root/node24,ice,ice-daemon,osqueryd,sshd,openclaw,8020,8083,8088,127.0.0.1}"

export ICE_RECORD_WARMUP="${ICE_RECORD_WARMUP:-75}"     # seconds for the daemon to take T0 of the clean box
export ICE_RECORD_TIMEOUT="${ICE_RECORD_TIMEOUT:-900}"  # seconds to wait for an investigated case
export ICE_RECORD_SETTLE="${ICE_RECORD_SETTLE:-60}"     # seconds for remediation + backward to finish

echo ">>> recording: RECORD_MODE=$ICE_RECORD_MODE AUTO_APPROVE=$ICE_AUTO_APPROVE DRY_RUN=$ICE_DRY_RUN" \
     "DENY_CRITICAL=$ICE_DENY_CRITICAL_ASSETS"
echo ">>> force-escalate flag: $ICE_FORCE_ESCALATE_FLAG"
echo ">>> dataset: $ICE_DATASET_DIR   state: $ICE_STATE_DIR"
