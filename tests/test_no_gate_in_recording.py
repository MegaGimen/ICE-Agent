"""A recording has no safety gate, and the recorder waits for the machine rather than a clock.

    python3 -m pytest tests/test_no_gate_in_recording.py

Two faults, one cause. The gate held irreversible actions on the ASK path even while recording, so
the orchestrator spent a model round trip per action asking the agent to write an explanation for a
human who was never going to read it -- and the recorder's fixed 60s settle then expired before the
later actions ran. One episode executed 1 of its 4 proposed actions and was scored as an agent that
left the machine dirty. The trajectory where an action is refused is a trajectory of the gate.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ice.daemon.safety.gate import SafetyGate, SafetyPolicy  # noqa: E402

POLICY = dict(authorized_targets=("ice-target",), bound_target="ice-target",
              critical_assets=("/root/.ssh/authorized_keys", "sshd"), deny_critical_assets=True)

DESTRUCTIVE = ("rm -f /root/.ssh/authorized_keys",      # critical asset AND irreversible
               "userdel -r deploy",                      # irreversible, takes a home with it
               "shred -u /etc/shadow",
               "truncate -s 0 /var/log/auth.log")


def test_recording_approves_everything_as_it_is_asked() -> None:
    gate = SafetyGate(policy=SafetyPolicy(**POLICY), approve_on_request=True)
    for cmd in DESTRUCTIVE:
        v = gate.safety_gate(cmd, "containment")
        assert v.decision.value == "AUTO", cmd
        assert "no gate" in v.reason
        assert v.request_id is None      # nothing is queued, so nothing waits for an approval


def test_deployment_still_refuses_them() -> None:
    gate = SafetyGate(policy=SafetyPolicy(**POLICY))
    assert gate.safety_gate(DESTRUCTIVE[0], "containment").decision.value == "DENY"


def test_the_switch_is_off_unless_it_is_asked_for() -> None:
    assert SafetyGate(policy=SafetyPolicy(**POLICY)).approve_on_request is False


def test_the_runtime_turns_it_on_only_for_recording() -> None:
    src = (Path(__file__).resolve().parents[1] / "ice" / "daemon" / "runtime.py").read_text()
    assert "approve_on_request=record_mode" in src


def test_the_recorder_waits_for_quiet_not_for_a_clock() -> None:
    src = (Path(__file__).resolve().parents[1] / "ice" / "exercise" / "record.py").read_text()
    body = src[src.index("def wait_until_quiet"):src.index("def _mcp_port")]
    assert "executed_in_vm()" in body            # it watches the audit the daemon writes
    assert '"cut_off": True' in body             # and says so when it gave up at the cap
    run = src[src.index("def run_episode"):]
    assert "wait_until_quiet()" in run
    assert "time.sleep(SETTLE_SECONDS)" not in run


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
