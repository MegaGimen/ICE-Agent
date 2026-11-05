"""The audit the judge reads has to be the one the machine finished writing.

    python3 -m pytest tests/test_collect_authority.py

`collect()` pulls the audit over ssh while the daemon is still running, and an action approved in
the settle tail lands in it afterwards. One episode executed
`sed -i /ice-vm/d /root/.ssh/authorized_keys` at 07:47:13.789 -- the file's own mtime to the
millisecond -- and the bundle's audit had 36 lines and two executed commands while the disk had 40
and three. The judge is told that damage must name the command that produced it, so an audit missing
the command sets the evidence against the rule.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

REC = (Path(__file__).resolve().parents[1] / "ice" / "exercise" / "record.py").read_text()
BODY = REC[REC.index("def collect_from_snapshot"):REC.index("def want_traj")]


def test_the_machine_written_evidence_comes_off_the_shut_down_disk() -> None:
    for line in ('ep_dir / "ice-audit.jsonl", "audit", authoritative=True',
                 'ep_dir / "daemon.log", "daemon.log", authoritative=True',
                 'f"case {src.stem}", authoritative=True'):
        assert line in BODY, line


def test_the_agents_own_files_are_still_only_filled_in() -> None:
    """The trajectory and the osquery readings do not grow after the pull, and re-reading the
    agent's sqlite is expensive, so those stay fill-in-only."""
    tail = BODY[BODY.index("if not list(ep_dir.glob"):]
    assert "authoritative=True" not in tail


def test_an_identical_file_is_not_copied_twice() -> None:
    assert "local.stat().st_size == src.stat().st_size" in BODY


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
