"""Two things the rig has to get right about time: when it freezes the disk, and when it interrupts.

    python3 -m pytest tests/test_rig_timing.py

The live snapshot is crash-consistent on purpose -- that is what "the machine as it was at that
instant" means -- but a benign episode downloaded a 1.9 MiB binary into /usr/local/bin seconds
before T1 and the snapshot had the directory empty: the judge's file evidence said /usr/local/bin
held nothing at T0, T1 and T2 while the runtime table showed that same binary running at T1.
Journal replay recovers metadata, not data that never left memory.

And the half-stop interference was watched from outside the process. First the recorder polled the
audit over ssh every two seconds; that worked while the gate's ASK path cost a model round trip per
action. With no gate the actions are consecutive subprocess calls:

  05:52:18.520  userdel butter                 exit 0
  05:52:18.528  rm -f /etc/cron.d/persistevil  exit 0
  05:52:18.536  rm -f /tmp/atomic_art.log      exit 0

Eight milliseconds apart, three inside sixteen. A 50ms watcher inside the VM read the audit for the
first time with all three already done and logged "stopping the daemon after 3 executed command(s)".
Nothing outside the process can land between them -- grep alone costs more than 8ms -- so the
process doing the executing counts them itself and exits where it stands.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

ROOT = pathlib.Path(__file__).resolve().parents[1]
VM = (ROOT / "ice" / "exercise" / "vm.py").read_text()
REC = (ROOT / "ice" / "exercise" / "record.py").read_text()


MCP = (ROOT / "ice" / "daemon" / "mcp_server.py").read_text()


def test_the_guest_is_flushed_before_the_disk_is_frozen() -> None:
    body = VM[VM.index("def snapshot_live"):VM.index("def alive(")]
    assert 'ssh(["sync"]' in body
    # against the call, not the docstring's mention of it
    assert body.index('ssh(["sync"]') < body.index('_qmp(of, "blockdev-snapshot-sync"')
    assert "label=of" in body            # the episode's own VM, not whichever is on 2222


def test_a_failed_sync_is_said_out_loud() -> None:
    body = VM[VM.index("def snapshot_live"):VM.index("def alive(")]
    assert "sync failed" in body and "missing recent writes" in body


def test_the_daemon_counts_its_own_executions() -> None:
    body = MCP[MCP.index("def _stop_after_exec"):MCP.index("    # -- host_exec")]
    assert 'os.environ.get("ICE_STOP_AFTER_EXEC"' in body
    assert "os._exit(9)" in body                       # not a clean shutdown, see below
    assert "_EXECUTED += 1" in body


def test_it_exits_hard_because_a_polite_stop_finishes_the_batch() -> None:
    body = MCP[MCP.index("def _stop_after_exec"):MCP.index("    # -- host_exec")]
    assert "finishes dispatching the actions it" in body
    # and it leaves a marker in the audit, so the bundle can show the episode was cut off on purpose
    assert 'rt.audit.write("stopped_after_exec"' in body


def test_it_is_called_right_after_the_execution_is_audited() -> None:
    host_exec = MCP[MCP.index("    def host_exec("):MCP.index("        if verdict.decision is GateDecision.ASK")]
    assert host_exec.index('audit.write("host_exec.executed"') < host_exec.index("_stop_after_exec(self.rt)")
    assert host_exec.index("_stop_after_exec(self.rt)") < host_exec.index("return ToolResult")


def test_nothing_happens_without_the_knob() -> None:
    """Read as text, like the other daemon checks here: the MCP dependency is not installed on
    every machine that runs these tests, and this is a question about two lines of code."""
    body = MCP[MCP.index("def _stop_after_exec"):MCP.index("    # -- host_exec")]
    assert 'n = int(os.environ.get("ICE_STOP_AFTER_EXEC", "0") or 0)' in body
    assert "if n <= 0:\n        return" in body
    # and it only exits on the nth, not before
    assert "if _EXECUTED < n:\n        return" in body


def test_the_recorder_checks_the_episode_came_out_as_asked() -> None:
    """A half-stop that did not bite produced two episodes that looked like clean remediations
    (value 1.0, every clearing axis `none`) and nothing in the bundle said otherwise."""
    body = REC[REC.index("def half_stop_outcome"):REC.index("def probe_exec")]
    assert "stopped_after_exec" in body                # the daemon's own marker
    assert '"as_asked": got == n and marked' in body
    assert "not half-remediated as asked" in body
    run = REC[REC.index("def run_episode"):]
    assert "half_stop_outcome(STOP_AFTER_EXEC)" in run


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
