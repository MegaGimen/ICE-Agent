"""An episode's arm is a script on the host, run whole inside the VM.

    python3 -m pytest tests/test_arm_script.py

The arm used to be one of three command lists hardcoded on the Scenario, chosen by an env string.
That made a new case an edit to the recorder. The standard entry point is now
an arm script: a file the recorder runs between T0 and T1 without knowing or caring what is in it.
run_cases.sh drives the five-case matrix this way. The standard single episode goes further and
takes the recorder out of the arming entirely -- record_t0.sh, do whatever to the machine,
record_t1.sh <benign|attack> -- which is tests/test_two_step_episode.py.
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = Path(__file__).resolve().parents[1]


def _arm_of(env, tmp_path):
    """Reload record with these ICE_ARM_* set, and return arm_of(persistence)."""
    for k in ("ICE_ARM_SCRIPT", "ICE_ARM_BENIGN", "ICE_ARM_EXPECTED", "ICE_SCENARIO_ARM"):
        os.environ.pop(k, None)
    os.environ.update(env)
    try:
        from ice.exercise import record, scenarios
        importlib.reload(record)
        return record.arm_of(scenarios.SCENARIOS["persistence"])
    finally:
        for k in env:
            os.environ.pop(k, None)
        from ice.exercise import record
        importlib.reload(record)


def test_a_script_arm_carries_its_body_and_the_benign_flag(tmp_path) -> None:
    arm = tmp_path / "attack.sh"
    arm.write_text("#!/bin/bash\nuseradd -g 0 -d /root butter\n")
    out = _arm_of({"ICE_ARM_SCRIPT": str(arm), "ICE_ARM_BENIGN": "0"}, tmp_path)
    assert out["benign"] is False
    assert "useradd -g 0 -d /root butter" in out["script"]
    assert out["markers"] == []                 # found by time, there is no artifact name to match
    assert out["script_name"] == "attack.sh"


def test_a_benign_script_reads_its_expected_list(tmp_path) -> None:
    arm = tmp_path / "benign.sh"
    arm.write_text("#!/bin/bash\ntrue\n")
    exp = tmp_path / "benign.expected"
    exp.write_text("# a comment, ignored\n/usr/local/bin/logreport -- the tool\n\n/etc/cron.d/x\n")
    out = _arm_of({"ICE_ARM_SCRIPT": str(arm), "ICE_ARM_BENIGN": "1",
                   "ICE_ARM_EXPECTED": str(exp)}, tmp_path)
    assert out["benign"] is True
    assert out["expected"] == ["/usr/local/bin/logreport -- the tool", "/etc/cron.d/x"]
    assert out["arm"] == "benign"


def test_the_scenario_arms_still_work_without_a_script(tmp_path) -> None:
    out = _arm_of({"ICE_SCENARIO_ARM": "attack"}, tmp_path)
    assert not out.get("script")                 # no script body on a scenario arm
    assert out["commands"]                       # the hardcoded list is still there


def test_run_arm_sends_a_script_whole_and_exposes_the_url() -> None:
    src = (ROOT / "ice" / "exercise" / "record.py").read_text()
    body = src[src.index("def run_arm"):src.index("def _mcp_port")]
    assert "export ICE_ARM_URL=" in body
    assert "vsh(body, label=arm[\"arm\"], check=True" in body     # whole, and must succeed
    assert "server.shutdown()" in body                            # the server does not outlive it
    # the command-list path keeps {tool_url}
    assert '"{tool_url}" in c' in body


def test_the_env_knobs_are_what_an_arm_script_is_selected_with() -> None:
    src = (ROOT / "ice" / "exercise" / "record.py").read_text()
    for knob in ("ICE_ARM_SCRIPT", "ICE_ARM_BENIGN", "ICE_ARM_EXPECTED"):
        assert f'os.environ.get("{knob}"' in src, knob


def test_the_example_arms_are_present_and_valid() -> None:
    import subprocess
    for name in ("attack-persistence.sh", "benign-logreport.sh"):
        f = ROOT / "targets" / "arms" / name
        assert f.exists(), name
        assert subprocess.run(["bash", "-n", str(f)], capture_output=True).returncode == 0, name
    benign = (ROOT / "targets" / "arms" / "benign-logreport.sh").read_text()
    assert "$ICE_ARM_URL/logreport" in benign    # it downloads, it does not conjure the binary
    assert (ROOT / "targets" / "arms" / "benign-logreport.expected").exists()


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
