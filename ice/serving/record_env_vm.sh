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
# Critical assets used to be how the rig protected itself: a list of its own paths, services and
# model endpoints that the safety gate would refuse to let any command name. It was a policy over
# string matching, and it was needed because the agent ran on the same machine as the recorder --
# which is also how ICE came to run `iptables -I OUTPUT -d <relay> -j DROP` on the address serving
# both its own model and the judge, auto-approved, cutting off its own brain.
#
# The episode now runs in a VM of its own and the recorder, the judge and the snapshots are outside
# it, so the protection is the virtualization boundary rather than a list. What is left here is the
# product's own idea of what must not be touched on the machine it defends, which is a different
# question and belongs to ICE rather than to the rig.
export ICE_CRITICAL_ASSETS="${ICE_CRITICAL_ASSETS:-/etc/shadow,/etc/sudoers,/root/.ssh/authorized_keys,sshd,osqueryd}"

export ICE_RECORD_WARMUP="${ICE_RECORD_WARMUP:-75}"     # seconds for the daemon to take T0 of the clean box
export ICE_RECORD_TIMEOUT="${ICE_RECORD_TIMEOUT:-900}"  # seconds to wait for an investigated case
export ICE_RECORD_SETTLE="${ICE_RECORD_SETTLE:-60}"     # seconds for remediation + backward to finish

echo ">>> recording: RECORD_MODE=$ICE_RECORD_MODE AUTO_APPROVE=$ICE_AUTO_APPROVE DRY_RUN=$ICE_DRY_RUN" \
     "DENY_CRITICAL=$ICE_DENY_CRITICAL_ASSETS"
echo ">>> force-escalate flag: $ICE_FORCE_ESCALATE_FLAG"
# Where finished bundles go. The recording box is a rented instance and its disk goes with it, so a
# bundle that exists only there is one release away from gone. ICE_INTAKE_* is host-only: the token
# must not reach the VM, which is the machine under attack.
export ICE_INTAKE_URL="${ICE_INTAKE_URL:-http://8.216.48.82:8137}"
export ICE_INTAKE_TOKEN="${ICE_INTAKE_TOKEN:-}"
echo ">>> dataset: $ICE_DATASET_DIR   state: $ICE_STATE_DIR"
