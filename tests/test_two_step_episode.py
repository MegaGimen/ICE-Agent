"""An episode in two halves, armed by hand in between.

    python3 -m pytest tests/test_two_step_episode.py

record_t0.sh resets the machine and takes the baseline; whatever the episode is about is then done
over ssh, by a person or by a script of their own; record_t1.sh <benign|attack> freezes the machine,
wakes the agent at it and scores what it left. The two halves are separate processes, possibly far
apart in time, so what the first one knows is written down for the second: which machine, which
snapshot labels, and the ssh port -- which is per-process state in vm.py and would otherwise fall
back to whatever is on the module default.
"""
from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = Path(__file__).resolve().parents[1]
REC = (ROOT / "ice" / "exercise" / "record.py").read_text()


def test_the_halves_split_at_the_baseline_reading() -> None:
    from ice.exercise import record

    t0 = inspect.getsource(record.start_episode)
    t1 = inspect.getsource(record.finish_episode)
    # T0 resets and reads; it does not arm, snapshot or judge.
    assert "boot_target(ep)" in t0 and 'runtime_reading(ep_dir, "t0")' in t0
    for later in ("snapshot_live", "hand_over_case", "wait_for_case", "_score", "upload_bundle"):
        assert later not in t0, f"the T0 half should not {later}"
    # T1 does all of that and nothing of the reset.
    for step in ("snapshot_live", "hand_over_case", "wait_for_case", "upload_bundle"):
        assert step in t1, step
    assert "boot_target" not in t1


def test_the_state_file_carries_the_machine_to_the_second_process() -> None:
    from ice.exercise import record

    t0 = inspect.getsource(record.start_episode)
    assert "STATE_FILE.write_text" in t0
    for key in ('"episode"', '"images"', '"live"', '"port"'):
        assert key in t0, key
    adopt = inspect.getsource(record.adopt_episode)
    assert "vm.adopt_port(state[\"live\"], state[\"port\"])" in adopt
    # and it refuses rather than guessing when the machine is gone
    assert "is not running any more" in adopt
    assert "is-active ice-daemon.service" in adopt


def test_adopt_port_is_what_lets_a_second_process_address_it() -> None:
    from ice.exercise import vm

    before = dict(vm._PORT)
    try:
        vm.adopt_port("ep-x-live", 2345)
        assert vm.ssh_port("ep-x-live") == 2345
        base = vm._ssh_base("ep-x-live")
        assert base[base.index("-p") + 1] == "2345"
    finally:
        vm._PORT.clear()
        vm._PORT.update(before)


def test_a_finished_episode_clears_the_state_file() -> None:
    t1 = REC[REC.index("def finish_episode"):REC.index("def dirty_check") if "def dirty_check" in REC
             else REC.index("def main")]
    assert "STATE_FILE.unlink(missing_ok=True)" in t1


def test_the_manual_arm_declares_nothing_about_what_was_done() -> None:
    """T1 - T0 is the record of it. The arm's own commands were never part of the judge's evidence,
    so there is nothing lost by not knowing them -- only the scoring kind has to be stated."""
    from ice.exercise import record

    attack = record.manual_arm(False)
    assert attack["benign"] is False and attack["commands"] == [] and attack["markers"] == []
    assert attack["manual"] is True

    benign = record.manual_arm(True)
    assert benign["benign"] is True and benign["arm"] == "benign"


def test_a_benign_expected_list_is_read_from_a_file(tmp_path) -> None:
    from ice.exercise import record

    f = tmp_path / "expected.txt"
    f.write_text("# ignored\n/usr/local/bin/logreport -- the tool\n\n/etc/cron.d/logreport\n")
    out = record.manual_arm(True, str(f))
    assert out["expected"] == ["/usr/local/bin/logreport -- the tool", "/etc/cron.d/logreport"]


def test_the_two_launchers_exist_and_take_what_they_should() -> None:
    t0 = (ROOT / "ice" / "exercise" / "record_t0.sh").read_text()
    t1 = (ROOT / "ice" / "exercise" / "record_t1.sh").read_text()
    assert "record t0" in t0
    assert "record t1" in t1
    assert 'case "$1" in benign|attack)' in t1
    assert "--expected" in t1
    for sh in (t0, t1):
        assert "record_env_vm.sh" in sh          # the recording posture, not the deployment one


def test_t0_prints_how_to_reach_the_machine() -> None:
    """The point of the split is doing something to the machine by hand, so the ssh line has to be
    in front of you -- the port is a free one, different every episode."""
    main = REC[REC.index('if a.cmd == "t0":'):REC.index('if a.cmd == "t1":')]
    assert "ssh -i" in main and "-p {port}" in main
    assert "id_ed25519" in main
    assert "t1 attack" in main


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
