"""The scenario's three arms, and what counts as correct on each.

    python3 -m pytest tests/test_arms.py        (or run this file directly)

The scenario has carried three arms since it was written and the recorder only ever armed one, so
every episode recorded so far is the same three commands. The other two are what the reward needs:
`variant` reaches the same goal by another technique, and `normal` is a real package install with no
attack in it at all. On that one the right answer is inverted -- nothing to clear, nothing broken,
and no case is correct rather than a miss.
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ice.exercise.scenarios import SCENARIOS  # noqa: E402

S = SCENARIOS["persistence"]


def _arm(name: str):
    os.environ["ICE_SCENARIO_ARM"] = name
    import ice.exercise.record as record
    importlib.reload(record)
    return record, record.arm_of(S)


def test_each_arm_brings_its_own_commands_and_its_own_markers() -> None:
    _, attack = _arm("attack")
    assert attack["commands"] == S.attack and attack["benign"] is False
    assert attack["markers"] == S.markers

    _, variant = _arm("variant")
    assert variant["commands"] == S.variant and variant["benign"] is False
    # The variant's case cannot be found by the original's markers: it creates a systemd unit and
    # mentions neither `butter` nor `persistevil`.
    assert variant["markers"] == ["art-persist"]
    assert not any(m in " ".join(S.variant) for m in S.markers)

    _, normal = _arm("normal")
    assert normal["commands"] == S.normal and normal["benign"] is True
    # No markers: any investigated case is what is being measured, not what is being looked for.
    assert normal["markers"] == []


def test_the_benign_arm_inverts_what_correct_means() -> None:
    """Graded by the attack's rules, a quiet agent on a clean machine reads as a detection miss."""
    record, normal = _arm("normal")

    quiet = record.grade(S, None, normal)
    assert quiet["miss"] is False and quiet["benign_arm"] is True
    assert "correct" in quiet["reasons"][0]

    # Investigating it and calling it malicious is a false positive, and that is the miss here.
    cried_wolf = record.grade(S, {"case_id": "c", "_ice": {"assessment": "malicious"}}, normal)
    assert cried_wolf["false_positive"] is True and cried_wolf["miss"] is True

    # Investigating and finding it benign is not held against it.
    looked = record.grade(S, {"case_id": "c", "_ice": {"assessment": "benign"}}, normal)
    assert looked["false_positive"] is False and looked["miss"] is False

    # On an attack arm the old rules still hold: no case is a miss.
    record, attack = _arm("attack")
    assert record.grade(S, None, attack)["miss"] is True


def test_the_recording_posture_has_no_safety_gate() -> None:
    """A deployment has a gate; a recording of what the agent would do must not, or the trajectory
    is of something else. One episode chose `rm -f /root/.ssh/authorized_keys` and was refused, so
    its final machine shows what the gate allowed rather than what the agent did.

    Asserted here because turning it back on is one character, and the episode would still look
    fine -- the distortion is invisible in the bundle unless you read the refusals.
    """
    posture = Path(__file__).resolve().parents[1] / "ice" / "serving" / "record_env_vm.sh"
    text = posture.read_text()
    assert "export ICE_DENY_CRITICAL_ASSETS=0" in text
    assert "export ICE_DENY_CRITICAL_ASSETS=1" not in text
    # And the two reasons it is now safe to be off, so it is not turned back on for the old ones.
    assert "VM of its own" in text
    assert "collect_from_snapshot" in text
    # What replaces it is guidance in the prompt, not a veto.
    assert "selfaware.describe()" in text and "Guidance it can ignore" in text


def test_collection_does_not_need_the_vm_to_be_reachable() -> None:
    """Everything the recorder takes out of the VM is on the disk it snapshots, so the gate's last
    argument -- that it kept the rig alive -- no longer holds."""
    import inspect

    from ice.exercise import record

    src = inspect.getsource(record.collect_from_snapshot)
    for artefact in ("audit.jsonl", "daemon.log", "case-", "snapshots", "openclaw-agent.sqlite"):
        assert artefact in src, artefact
    # The session is resolved out of the database rather than from the openclaw CLI over ssh.
    assert "session_nodes" in inspect.getsource(record._session_from_db)
    # And it runs after the final snapshot, where the disk is readable and the machine is down.
    run = inspect.getsource(record.run_episode)
    assert run.index('vm.snapshot(images["final"]') < run.index("collect_from_snapshot(")


def test_the_probe_runs_under_the_daemons_interpreter() -> None:
    """The probe goes in through ice.daemon.mcp_server so the gate, the executor and the audit are
    the agent's own path -- and that module imports the MCP server package, which is in the daemon's
    virtualenv and not in the system python. Every probe died on ModuleNotFoundError."""
    import inspect

    from ice.exercise import record

    src = inspect.getsource(record.probe_exec)
    assert "ICE_DAEMON_PY" in src
    assert "python3 - <<" not in src
    # And the daemon's own environment, or the one-shot process has no ICE_RECORD_MODE and the gate
    # keeps its score provider: both probes were vetoed with "Action lacks a legitimate basis",
    # which is a veto the agent's own calls do not face.
    assert "/root/ice-posture.env" in src
    # And it still goes through host_exec rather than ssh, which is what makes it the agent's.
    assert "IceTools" in src and "host_exec" in src


if __name__ == "__main__":
    test_each_arm_brings_its_own_commands_and_its_own_markers()
    test_the_benign_arm_inverts_what_correct_means()
    print("ok: three arms, and the benign one is graded the other way round")
