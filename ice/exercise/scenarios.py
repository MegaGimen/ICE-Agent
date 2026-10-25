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
    normal: List[str] = field(default_factory=list)
    normal_cleanup: List[str] = field(default_factory=list)
    normal_facts: Dict[str, bool] = field(default_factory=dict)


# Scenario 1 — Persistence (targets/SCENARIOS.md row 1).
#   original: ART T1136.001 #6 (account in the root group) + T1053.003 #3 (cron in /etc/cron.d).
#   variant : ART T1543.002 (a systemd service set to autostart) replacing the cron.
#   normal  : install a real package (drops a systemd unit via dpkg) — benign, has a package trail.
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
    normal=["apt-get install -y -q sl"],
    normal_cleanup=["apt-get remove -y -q sl"],
    normal_facts={"package_install": True},
)

SCENARIOS: Dict[str, Scenario] = {s.id: s for s in (PERSISTENCE,)}
