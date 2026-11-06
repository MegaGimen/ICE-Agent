"""Authorized exercise scenarios (plan.md §5; targets/SCENARIOS.md).

Each scenario is a real attack simulation with a KNOWN answer (the drill column of the
true/drill table): we know the ATT&CK techniques, so the harness can grade ICE's verdict
against ground truth instead of waiting for backward to find residue. Commands are run on
THIS host by the harness (run as root), so every scenario is reversible and clearly labeled.

`attack` is the original; `variant` is a different technique reaching the same goal; `normal`
is a benign control the learned lesson must NOT fire on. `facts` are structured tags the
error-book retest detector reads (see drill.py): the lesson fires on an artifact class, not on
a name or payload.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Scenario:
    id: str
    display: str
    techniques: List[str]                 # ground-truth ATT&CK ids
    attack: List[str]                     # shell commands (run as root)
    cleanup: List[str]
    markers: List[str]                    # substrings expected in the case triggers (to find the case)
    artifacts: List[str]                  # bare identifiers expected in blast_radius (scope grading)
    facts: Dict[str, bool]                # structured tags for the retest detector (original)
    variant: List[str] = field(default_factory=list)
    variant_cleanup: List[str] = field(default_factory=list)
    variant_facts: Dict[str, bool] = field(default_factory=dict)
    # The variant reaches the same goal by another technique, so the substrings that find its case
    # are its own -- the original's markers do not appear in it.
    variant_markers: List[str] = field(default_factory=list)
    normal: List[str] = field(default_factory=list)
    normal_cleanup: List[str] = field(default_factory=list)
    normal_facts: Dict[str, bool] = field(default_factory=dict)


# Scenario 1 — Persistence (targets/SCENARIOS.md row 1).
#   original: ART T1136.001 #6 (account in the root group) + T1053.003 #3 (cron in /etc/cron.d).
#   variant : ART T1543.002 (a systemd service set to autostart) replacing the cron.
#   normal  : the ordinary provisioning of a deploy account -- an account with its own home, its own
#             key, a cron entry that runs a system binary, and a package install. It has to be
#             visible where the attack is visible: installing a package alone changed nothing in any
#             table ICE watches, so the recorder's T0->T1 diff was 0 entries, no case was ever opened,
#             and the benign arm measured nothing about the agent at all (it could not produce a
#             false positive, only confirm that nothing broke). The shape is deliberately close to
#             the attack's, and every discriminating detail is real: the home is the account's own,
#             the group is the account's own, the key is a new key rather than one already on the
#             machine, and the cron runs /usr/sbin/logrotate rather than something dropped with it.
#             The package install this arm used to be is gone: the image has no apt index and no
#             route to a mirror, so `apt-get install -y -q sl` returned rc=100 "Unable to locate
#             package sl" on every episode it ever ran. The arm was not merely invisible to the
#             tables -- nothing happened on the machine at all, and the file diff showed only
#             systemd's private tmp directories. Anything added here has to be checked for `ok` in
#             the episode log, not assumed.
PERSISTENCE = Scenario(
    id="persistence",
    display="Persistence: privileged account + cron (ATT&CK T1136.001 + T1053.003)",
    techniques=["T1136.001", "T1053.003"],
    attack=[
        "useradd -g 0 -M -d /root -s /bin/bash -c evil_account butter",
        "sh -c 'echo \"butter:BetterWithButter\" | chpasswd'",
        "sh -c 'echo \"*/5 * * * * root /usr/bin/id > /tmp/atomic_art.log 2>&1\" > /etc/cron.d/persistevil'",
    ],
    cleanup=["userdel butter", "rm -f /etc/cron.d/persistevil /tmp/atomic_art.log"],
    markers=["butter", "persistevil"],
    artifacts=["butter", "/etc/cron.d/persistevil"],
    facts={"new_privileged_account": True, "new_cron": True},
    variant=[
        "sh -c 'printf \"[Unit]\\nDescription=art persist\\n[Service]\\nExecStart=/usr/bin/id\\n[Install]\\nWantedBy=multi-user.target\\n\" > /etc/systemd/system/art-persist.service'",
        "systemctl enable art-persist.service",
    ],
    variant_cleanup=["systemctl disable art-persist.service", "rm -f /etc/systemd/system/art-persist.service"],
    variant_facts={"new_autostart_unit": True},
    variant_markers=["art-persist"],
    normal=[
        "useradd -m -s /bin/bash -c 'deploy service account' deploy",
        "install -d -m 700 -o deploy -g deploy /home/deploy/.ssh",
        # A key of its own, made on the machine: a new row in ssh_keys whose hash is nobody else's.
        "ssh-keygen -q -t ed25519 -N '' -C 'deploy@ops' -f /root/.deploy_provision_key "
        "&& install -m 600 -o deploy -g deploy /root/.deploy_provision_key.pub "
        "/home/deploy/.ssh/authorized_keys "
        "&& rm -f /root/.deploy_provision_key /root/.deploy_provision_key.pub",
        "printf '17 3 * * * root /usr/sbin/logrotate /etc/logrotate.conf\\n' "
        "> /etc/cron.d/logrotate-extra",
    ],
    normal_cleanup=["userdel -r deploy", "rm -f /etc/cron.d/logrotate-extra"],
    normal_facts={"package_install": True, "service_account_provisioned": True,
                  "legitimate_cron": True, "legitimate_ssh_key": True},
)

SCENARIOS: Dict[str, Scenario] = {s.id: s for s in (PERSISTENCE,)}
