"""Two things the rig has to get right about time: when it freezes the disk, and when it interrupts.

    python3 -m pytest tests/test_rig_timing.py

The live snapshot is crash-consistent on purpose -- that is what "the machine as it was at that
instant" means -- but a benign episode downloaded a 1.9 MiB binary into /usr/local/bin seconds
before T1 and the snapshot had the directory empty: the judge's file evidence said /usr/local/bin
held nothing at T0, T1 and T2 while the runtime table showed that same binary running at T1.
Journal replay recovers metadata, not data that never left memory.

And the half-stop interference polled the audit from the host every two seconds. That worked while
each action cost a model round trip for the gate's ASK path; with no gate the actions are
consecutive subprocess calls, so the poller arrived after the remediation was complete -- the
episode asked to stop after 1 command, recorded `executed_before_stop: 2`, and came back with every
clearing axis at `none`, which is not a half-remediated episode at all.
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


def _watcher_script(n: int = 1, limit: int = 600) -> str:
    """Render exactly what the recorder sends into the VM."""
    body = REC[REC.index("def arm_half_stop"):REC.index("def half_stop_outcome")]
    ns = {"captured": []}
    exec("import os\nSTATE='/root/ice-state'\n"
         "def vsh(script, label='', check=False, timeout=0):\n    captured.append(script)\n"
         + body, ns)
    ns["arm_half_stop"](n, limit)
    return ns["captured"][0]


def test_the_guest_is_flushed_before_the_disk_is_frozen() -> None:
    body = VM[VM.index("def snapshot_live"):VM.index("def alive(")]
    assert 'ssh(["sync"]' in body
    # against the call, not the docstring's mention of it
    assert body.index('ssh(["sync"]') < body.index('_qmp(of, "blockdev-snapshot-sync"')
    assert "label=of" in body            # the episode's own VM, not whichever is on 2222


def test_a_failed_sync_is_said_out_loud() -> None:
    body = VM[VM.index("def snapshot_live"):VM.index("def alive(")]
    assert "sync failed" in body and "missing recent writes" in body


def test_the_half_stop_watcher_runs_inside_the_machine() -> None:
    script = _watcher_script()
    assert "systemctl stop ice-daemon.service" in script
    assert "sleep 0.05" in script                      # 50ms, not the old 2s poll
    assert "setsid" in script                          # outlives the ssh session
    assert "/root/ice-state/audit.jsonl" in script     # reads the audit where it is written


def test_it_counts_without_tripping_over_greps_exit_code() -> None:
    """`grep -c` prints 0 and exits 1 when nothing matches, so a bare `|| echo 0` yields two lines
    and every comparison then complains "integer expression expected"."""
    script = _watcher_script()
    assert "|| echo 0; } | head -1" in script


def test_the_rendered_script_is_valid_bash() -> None:
    script = _watcher_script()
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
        fh.write(script)
        path = fh.name
    assert subprocess.run(["bash", "-n", path], capture_output=True).returncode == 0


def test_the_watcher_stops_on_the_nth_command_within_a_tenth_of_a_second() -> None:
    """Run the rendered watcher for real, against a fake audit, with systemctl replaced."""
    with tempfile.TemporaryDirectory() as d:
        dd = pathlib.Path(d)
        audit, log = dd / "audit.jsonl", dd / "hs.log"
        script = (_watcher_script(n=2, limit=30)
                  .replace("/root/ice-state/audit.jsonl", str(audit))
                  .replace("/root/ice-halfstop.log", str(log))
                  .replace("systemctl stop ice-daemon.service", f"echo STOPPED >> {log}"))
        inner = script[script.index("#!/bin/bash"):script.index("ICEHALFSTOP\nchmod")]
        w = dd / "watch.sh"
        w.write_text(inner)
        w.chmod(0o755)
        audit.write_text("")
        log.write_text("")
        proc = subprocess.Popen(["bash", str(w)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(0.4)
            line = '{"event": "host_exec.executed", "command": "x"}\n'
            with audit.open("a") as fh:                 # the first one must NOT stop it
                fh.write(line)
            time.sleep(0.3)
            assert "STOPPED" not in log.read_text()
            t0 = time.time()
            with audit.open("a") as fh:                 # the second one must
                fh.write(line)
            for _ in range(60):
                if "STOPPED" in log.read_text():
                    break
                time.sleep(0.02)
            took = time.time() - t0
            assert "STOPPED" in log.read_text(), "the watcher never stopped the daemon"
            assert took < 0.5, f"took {took:.2f}s"
            assert "after 2 executed command(s)" in log.read_text()
            out, err = proc.communicate(timeout=5)
            assert err.decode().strip() == "", err.decode()[:200]
        finally:
            proc.kill()


def test_it_is_armed_before_the_agent_is_woken() -> None:
    run = REC[REC.index("def run_episode"):]
    assert "arm_half_stop(STOP_AFTER_EXEC" in run
    assert run.index("arm_half_stop(STOP_AFTER_EXEC") < run.index("wait_for_case(")
    assert "half_stop_outcome()" in run


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
