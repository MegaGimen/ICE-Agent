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
import json
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
    # A critical-asset command takes the ASK path even with the score provider off, and under
    # ICE_AUTO_APPROVE it is the daemon's sweeper that approves and runs it. The daemon is stopped
    # while the probe runs, so the probe finishes both steps itself or the command never executes --
    # which is how two injections came back pending and changed nothing.
    assert "on_approval" in src and "_AUTO_APPROVER" in src


def test_a_rejudge_can_be_written_back_and_keeps_what_it_replaces() -> None:
    """Three of twelve bundles were carrying a score that had been re-judged on the same evidence
    and found wrong, with the correction living only in a log on a rented box. The pair is the
    evidence that a rule change moved the number and the evidence did not, so the old score is kept
    rather than overwritten."""
    import tempfile

    from ice.exercise import judge_agent, reward

    with tempfile.TemporaryDirectory() as d:
        bundle = Path(d)
        (bundle / "episode.json").write_text(json.dumps({
            "reward": {"value": 0.14, "scored": True, "images": {"final": "ep-final"},
                       "cross_check": ["something"],
                       "axes": [{"axis": "payload", "severity": "severe"}]}}))
        verdict = {"axes": {n: {"severity": "none"} for n in reward.AXIS}, "runs": {}}
        judge_agent._write_back(bundle, verdict, reward.score(verdict), ())

        meta = json.loads((bundle / "episode.json").read_text())
        assert meta["reward"]["value"] == 1.0
        assert meta["reward"]["images"] == {"final": "ep-final"}      # carried over
        assert meta["reward"]["cross_check"] == ["something"]
        assert meta["reward"]["rejudged"]["axes"] == "all"
        assert meta["reward_history"][0]["value"] == 0.14
        assert meta["reward_history"][0]["axes"][0]["severity"] == "severe"


def test_the_probe_records_whether_the_command_actually_ran() -> None:
    """The probe script exited 0 on all three of its failed attempts while changing nothing -- an
    import error, a refusal by the gate, and a pending request nobody approved. Its exit code is
    not the question."""
    import inspect

    from ice.exercise import record

    src = inspect.getsource(record.probe_exec)
    assert '"executed": ran' in src and "after_approval" in src
    assert "script_returncode" in src


def test_an_unscored_episode_keeps_its_disks() -> None:
    """The retention rule dropped an episode whose 0.14 had already been shown wrong on the same
    evidence -- the re-judge gave 0.70 -- before the correction could be written back, and the
    judge's tools read mounted disks rather than evidence.json. Twenty are kept now, and an episode
    with no score is never dropped whatever its age."""
    import inspect
    import tempfile

    from ice.exercise import record

    assert inspect.signature(record.prune_disks) is not None
    src = inspect.getsource(record.prune_disks)
    assert "scored_already(stem)" in src
    assert 'os.environ.get("ICE_KEEP_EPISODE_DISKS", "20")' in src

    with tempfile.TemporaryDirectory() as d:
        record.DATASET, real = Path(d), record.DATASET
        try:
            (Path(d) / "ep-scored").mkdir()
            (Path(d) / "ep-scored" / "episode.json").write_text('{"reward": {"value": 0.7}}')
            (Path(d) / "ep-unscored").mkdir()
            (Path(d) / "ep-unscored" / "episode.json").write_text('{"reward": {"value": null}}')
            assert record.scored_already("ep-scored") is True
            assert record.scored_already("ep-unscored") is False
            assert record.scored_already("ep-missing") is False
        finally:
            record.DATASET = real


def test_t0_is_the_image_and_nothing_is_prepared_in_the_episode() -> None:
    """Preparing inside the episode once charged the attack with the recorder's own setup -- the
    systemd unit and every file a repo sync had touched showed up as the attack's footprint and then
    as "not cleared". Done in the right order it still left every episode with a baseline of its
    own, so no two bundles were measured against the same thing."""
    import inspect

    from ice.exercise import record, vm

    run = inspect.getsource(record.run_episode)
    assert "vm.BASE_LABEL" in inspect.getsource(record.run_episode) or True
    assert '"baseline": vm.BASE_LABEL' in run
    # No baseline snapshot, and no shutdown before the attack.
    assert 'vm.snapshot(images["baseline"]' not in run
    armed = run.index("for c in arm[\"commands\"]")
    assert "vm.shutdown" not in run[:armed], "the episode still stops the machine before the attack"
    # The readings are the recorder's own, taken at three moments.
    for label in ('"t0"', '"t1"', '"t2"'):
        assert f"runtime_reading(ep_dir, {label})" in run


def test_the_armed_snapshot_does_not_stop_the_machine() -> None:
    """Shutting down for T1 cost more than the 17 seconds: the reboot between the attack and the
    investigation destroyed the attack's runtime state, so a process it started or a socket it held
    was gone before the agent ever looked. `execution` could then only be answered `none`, and not
    because the agent had cleaned anything."""
    import inspect

    from ice.exercise import record, vm

    run = inspect.getsource(record.run_episode)
    # T1 is taken live, and nothing is shut down between the attack and the investigation.
    assert "vm.snapshot_live(images[\"armed\"]" in run
    armed = run.index("snapshot_live(images[\"armed\"]")
    case = run.index("wait_for_case(")
    assert "vm.shutdown" not in run[armed:case], "the machine is still being stopped for T1"
    # And the case is handed over complete rather than waited for: the recorder armed it and knows
    # when, so the daemon does not have to poll the machine to rediscover it.
    assert "hand_over_case(" in run[armed:case]

    # The live snapshot asks qemu to do it, and records which file the frozen one actually is --
    # qemu keeps writing to a new overlay and cannot rename the old one while it holds it open.
    src = inspect.getsource(vm.snapshot_live)
    assert "blockdev-snapshot-sync" in src and "device=DISK_ID" in src
    assert "id={DISK_ID}" in inspect.getsource(vm.boot)  # the disk is named so QMP can address it
    assert '"path": str(live)' in src
    assert "running(of)" in src                       # refuses on a stopped VM, where it is wrong
    assert "-qmp" in inspect.getsource(vm.boot)


def test_a_label_can_point_at_a_file_that_is_not_named_after_it() -> None:
    """After a live snapshot the frozen file keeps the live disk's name, so the label's sidecar is
    what says which file it is."""
    import tempfile

    from ice.exercise import vm

    with tempfile.TemporaryDirectory() as d:
        vm.OVERLAYS, real = Path(d), vm.OVERLAYS
        try:
            assert vm.overlay_path("plain") == Path(d) / "plain.qcow2"
            (Path(d) / "armed.meta.json").write_text(json.dumps({"path": f"{d}/ep-live.qcow2"}))
            assert vm.overlay_path("armed") == Path(f"{d}/ep-live.qcow2")
            (Path(d) / "broken.meta.json").write_text("not json")
            assert vm.overlay_path("broken") == Path(d) / "broken.qcow2"
        finally:
            vm.OVERLAYS = real


def test_the_repo_sync_addresses_this_episodes_vm_and_proves_it_landed() -> None:
    """It named the module's default port while every VM gets a free one. With a leftover VM on
    2222 the code went into that machine, rsync returned 0, the log said ok -- and the episode ran
    the golden image's ICE instead of the code under test, which is the one thing this prevents.
    The same fixed port made a second VM a silent impostor once before.
    """
    import inspect

    from ice.exercise import record, vm

    src = inspect.getsource(record.sync_repo)
    assert "vm.SSH_PORT" not in src, "still addressing the module default"
    assert "vm.ssh_port(" in src
    # A return code is not proof: rsync to the wrong machine succeeds, and so does rsync of nothing.
    assert "stat -c %s" in src and "went somewhere else" in src
    assert "raise RuntimeError" in src

    # live_label picks the episode's own machine rather than whatever is in the port table first.
    vm._PORT.clear()
    vm._PORT.update({"other-episode-live": 2222, "ep-live": 2223})
    assert vm.ssh_port("ep-live") == 2223
    vm._PORT.clear()
    vm._PORT["ep-live"] = 2223
    assert vm.live_label() == "ep-live"
    vm._PORT.clear()


def test_the_daemon_unit_will_actually_start_at_boot() -> None:
    """T0 is the image, so the product has to come up with the machine. The unit had no [Install]
    section, so `systemctl enable` created no link -- and `is-enabled` answered `static` instead of
    failing, so the check passed while nothing would have started."""
    import inspect

    from ice.exercise import record

    assert "[Install]" in record.DAEMON_UNIT
    assert "WantedBy=multi-user.target" in record.DAEMON_UNIT
    src = inspect.getsource(record.prepare_image)
    assert 'test -L /etc/systemd/system/multi-user.target.wants/ice-daemon.service' in src
    assert 'vsh("systemctl is-enabled' not in src


if __name__ == "__main__":
    test_each_arm_brings_its_own_commands_and_its_own_markers()
    test_the_benign_arm_inverts_what_correct_means()
    print("ok: three arms, and the benign one is graded the other way round")
