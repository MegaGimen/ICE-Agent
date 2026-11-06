"""A benign arm ICE cannot see measures nothing.

    python3 -m pytest tests/test_benign_arm_visible.py

The benign arm was `apt-get install -y -q sl`. None of the ten tables the recorder reads covers
installed packages, so the T0->T1 diff was 0 entries, the hand-over had nothing in it, no case was
ever opened, and the episode reported "NO case" after waiting out the full investigation window. It
could not produce a false positive -- the one thing the benign arm exists to measure -- only confirm
that nothing broke.

So the arm now provisions a deploy account: an account, a key and a cron entry, which is where the
attack is visible too. Every discriminating detail is real, and that is the point: the agent has to
tell this apart from the attack on the facts, not on which tables moved.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ice.exercise.scenarios import SCENARIOS  # noqa: E402

S = SCENARIOS["persistence"]
NORMAL = " ; ".join(S.normal)


def test_it_touches_the_tables_the_attack_touches() -> None:
    assert "useradd" in NORMAL                      # accounts
    assert "authorized_keys" in NORMAL              # ssh_keys
    assert "/etc/cron.d/" in NORMAL                 # cron


def test_every_discriminating_detail_differs_from_the_attack() -> None:
    attack = " ; ".join(S.attack)
    # The attack puts the account in the root group with root's home and sets a password.
    assert "-g 0" in attack and "-d /root" in attack and "chpasswd" in attack
    # The benign account gets its own home (-m) and neither of those.
    assert "-m " in NORMAL and "-g 0" not in NORMAL and "-d /root" not in NORMAL
    assert "chpasswd" not in NORMAL
    # Its key is generated on the machine, so the hash is nobody else's -- not a row that appears
    # because a home directory was pointed at an existing one.
    assert "ssh-keygen" in NORMAL
    # Its cron runs a system binary that was already there.
    assert "/usr/sbin/logrotate" in NORMAL


def test_it_cleans_up_after_itself() -> None:
    cleanup = " ; ".join(S.normal_cleanup)
    for marker in ("userdel", "/etc/cron.d/logrotate-extra", "apt-get remove"):
        assert marker in cleanup
    # userdel -r is right here and wrong on the attack's account: this home IS the account's own.
    assert "userdel -r deploy" in cleanup


def test_the_provisioning_key_does_not_stay_on_disk() -> None:
    assert "rm -f /root/.deploy_provision_key" in NORMAL


def test_the_arm_is_still_marked_benign() -> None:
    import os
    os.environ["ICE_SCENARIO_ARM"] = "normal"
    import importlib
    from ice.exercise import record
    importlib.reload(record)
    arm = record.arm_of(S)
    assert arm["benign"] is True and arm["markers"] == []
    assert arm["commands"] == S.normal


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
