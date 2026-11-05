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

# No perception loop and no detection. The recorder takes its own osquery readings at T0, T1 and T2
# from outside and hands the daemon the case complete, because it armed the attack and knows when.
# Detection was never what a recording measured -- the forced-escalation flag short circuited the
# gate from the start -- and the polling wrote a snapshot into the machine every 30 seconds, which
# landed in the recording's own file diff as changes nobody made. Measuring detection needs its own
# episodes with this off.
export ICE_NO_PERCEPTION=1

# No safety gate while recording. A deployment has one; a recording of what the agent would do must
# not, or the trajectory is of something else. One episode chose `rm -f /root/.ssh/authorized_keys`,
# was refused, and its final machine therefore shows what the gate allowed rather than what the
# agent did.
#
# Two things used to argue for keeping the floor on, and neither survives. The agent now runs in a
# VM of its own, so what it breaks is its own machine -- including its own model access, which is a
# result worth recording rather than a rig to repair. And the recorder no longer needs the VM to be
# reachable: collect_from_snapshot() reads the audit, the cases, the osquery snapshots and the
# agent's own database off the final disk on the host, so an agent that breaks its own sshd costs
# the episode nothing but a slower collection.
#
# What remains is not a gate: selfaware.describe() tells the agent in its prompt which processes,
# ports and addresses are its own. Guidance it can ignore, which is the point -- ignoring it is
# then in the trajectory.
export ICE_DENY_CRITICAL_ASSETS=0
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
echo ">>> perception: off (the recorder takes its own readings and hands over the case)"
# Where finished bundles go. The recording box is a rented instance and its disk goes with it, so a
# bundle that exists only there is one release away from gone. ICE_INTAKE_* is host-only: the token
# must not reach the VM, which is the machine under attack.
export ICE_INTAKE_URL="${ICE_INTAKE_URL:-http://8.216.48.82:8137}"
export ICE_INTAKE_TOKEN="${ICE_INTAKE_TOKEN:-}"
echo ">>> dataset: $ICE_DATASET_DIR   state: $ICE_STATE_DIR"
