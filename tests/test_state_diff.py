"""A change entry is a `+` with nothing above it, so the whole table goes with it.

    python3 -m pytest tests/test_state_diff.py        (or run this file directly)

The case this exists for. The attack created an account whose home is /root, so osquery read
/root/.ssh/authorized_keys twice and listed the one key under two names. The diff reported a new row
in `ssh_keys`, which is true, and the agent read it as a new key in the file, which is not: it then
proposed `sed -i '/ice-vm/d' /root/.ssh/authorized_keys` and deleted the only key the machine had.
Both rows carry the same hash. Seeing them side by side is all it would have taken.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ice.daemon.perception import diff as diff_mod  # noqa: E402

KEY = "549e2b4f3859"


class Snap:
    """Only what render() uses: a table's rows by key."""

    def __init__(self, tables):
        self.tables, self.errors, self.ts = tables, {}, 0.0

    def rows(self, name):
        return self.tables.get(name, {})


def test_the_unmarked_lines_are_the_baseline() -> None:
    t0 = Snap({"ssh_keys": {f"root#{KEY}": {"username": "root", "algorithm": "ssh-ed25519"},
                            f"ubuntu#{KEY}": {"username": "ubuntu", "algorithm": "ssh-ed25519"}}})
    t1 = Snap({"ssh_keys": {f"root#{KEY}": {"username": "root", "algorithm": "ssh-ed25519"},
                            f"ubuntu#{KEY}": {"username": "ubuntu", "algorithm": "ssh-ed25519"},
                            f"butter#{KEY}": {"username": "butter", "algorithm": "ssh-ed25519"}}})
    block = diff_mod.render(t0, t1, ["ssh_keys"])["ssh_keys"]
    lines = block.splitlines()

    assert "3 row(s) now" in lines[0]
    body = [l for l in lines[1:]]
    assert sum(1 for l in body if l.startswith("+ ")) == 1
    assert sum(1 for l in body if l.startswith("  ")) == 2
    # The decisive thing: the key's hash is on the new line and on the old ones, in one view.
    assert all(KEY in l for l in body)
    assert any(l.startswith("+ ") and "butter" in l for l in body)
    assert any(l.startswith("  ") and "root" in l for l in body)


def test_a_removal_is_shown_although_it_is_not_in_the_state_now() -> None:
    t0 = Snap({"accounts": {"alice": {"username": "alice"}, "bob": {"username": "bob"}}})
    t1 = Snap({"accounts": {"alice": {"username": "alice"}}})
    body = diff_mod.render(t0, t1, ["accounts"])["accounts"].splitlines()[1:]
    assert any(l.startswith("- ") and "bob" in l for l in body)
    assert any(l.startswith("  ") and "alice" in l for l in body)


def test_a_modified_row_is_shown_both_ways() -> None:
    t0 = Snap({"accounts": {"alice": {"username": "alice", "shell": "/usr/sbin/nologin"}}})
    t1 = Snap({"accounts": {"alice": {"username": "alice", "shell": "/bin/bash"}}})
    body = diff_mod.render(t0, t1, ["accounts"])["accounts"].splitlines()[1:]
    assert sum(1 for l in body if l.startswith("- ")) == 1
    assert sum(1 for l in body if l.startswith("+ ")) == 1


def test_changed_lines_survive_the_cap() -> None:
    """A table with hundreds of rows must not push the one `+` out of the window."""
    many = {f"user{i:03d}": {"username": f"user{i:03d}"} for i in range(300)}
    t0 = Snap({"accounts": dict(many)})
    t1 = Snap({"accounts": dict(many, intruder={"username": "intruder"})})
    block = diff_mod.render(t0, t1, ["accounts"])["accounts"]
    body = block.splitlines()[1:]
    assert len(body) <= diff_mod.MAX_ROWS
    assert any(l.startswith("+ ") and "intruder" in l for l in body)
    assert "not shown" in block.splitlines()[0]


def test_a_table_nobody_escalated_is_not_rendered() -> None:
    t0 = Snap({"accounts": {"alice": {"username": "alice"}}})
    t1 = Snap({"accounts": {"alice": {"username": "alice"}}})
    assert diff_mod.render(t0, t1, ["processes"]) == {}       # flow tables have no baseline to mark
    assert diff_mod.render(t0, t1, ["nosuchtable"]) == {}


def test_the_prompt_says_what_the_marks_mean_and_what_they_do_not() -> None:
    from ice.daemon.investigate import prompts

    msg = prompts.wake_message("case-1", "h", [], state_diff={"ssh_keys": "  root#abc"})
    assert "State now, against the baseline snapshot" in msg
    assert "an unmarked line was already there" in msg
    # And the thing the agent got wrong: a `+` is not a finding about the attack.
    assert "not a list of the attack's work" in msg
    assert "something that already existed showing up under a new key" in msg
    assert "  root#abc" in msg


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
    print("ok: the table goes with the change, and the unmarked lines are the baseline")


def test_a_handed_over_entry_is_rebuilt_whole() -> None:
    """to_dict() flattens the nested dataclasses, and a Provenance left as a dict crashed the
    investigation on e.provenance.user -- after the hand-over had been audited, so the episode read
    as an agent that did nothing rather than as a rig that broke."""
    import json as _json

    from ice.daemon.contracts import ChangeEntry, ChangeType, Direction, Provenance

    original = ChangeEntry(type=ChangeType.ACCOUNT, table="accounts", field="butter",
                           value="added: account butter uid=1001",
                           provenance=Provenance(who="useradd", pid=856, user="root"),
                           untrusted={"username": "butter"})
    payload = _json.loads(_json.dumps({"entries": [original.to_dict()]}))

    rebuilt = [ChangeEntry(**{**e, "type": ChangeType(e["type"]),
                              "direction": Direction(e.get("direction", "na")),
                              "provenance": Provenance(**(e.get("provenance") or {}))})
               for e in payload["entries"]][0]

    # The attribute access that crashed, and the shapes the gate and the prompt rely on.
    assert rebuilt.provenance.user == "root" and rebuilt.provenance.who == "useradd"
    assert isinstance(rebuilt.type, ChangeType) and isinstance(rebuilt.direction, Direction)
    assert rebuilt.untrusted == {"username": "butter"}
    assert rebuilt.field.split("#", 1)[0] == "butter"


def test_the_orchestrator_rebuilds_it_that_way() -> None:
    """Read as text, not imported: the daemon's MCP dependency is not installed on every machine
    that runs these tests, and this is a question about one line of code."""
    src = (Path(__file__).resolve().parents[1]
           / "ice" / "daemon" / "orchestrator.py").read_text()
    body = src[src.index("def investigate_handed_over"):src.index("def run_forever")]
    assert 'Provenance(**(e.get("provenance") or {}))' in body
    assert "ChangeType(e[\"type\"])" in body and "Direction(e.get(\"direction\"" in body

def test_a_baseline_of_nothing_marks_the_whole_machine_as_new() -> None:
    """The failure this guards against, stated as the agent saw it: with no T0 in the store, every
    row of every escalated table rendered as `+` -- all 34 stock accounts, all 15 critical files and
    root's own SSH key. The agent then deleted root's key, reasoning correctly from a false input."""
    t1 = Snap({"ssh_keys": {f"root#{KEY}": {"username": "root"},
                            f"butter#{KEY}": {"username": "butter"}}})
    block = diff_mod.render(None, t1, ["ssh_keys"])["ssh_keys"]
    body = block.splitlines()[1:]
    assert all(l.startswith("+ ") for l in body)        # what we must never hand an agent again


def test_the_recorder_hands_the_baseline_over_and_the_daemon_stores_it() -> None:
    """Two halves of one contract, read as text: the recording's daemon runs no perception loop, so
    the hand-over is the only thing that can put a T0 in the store for `before()` to find."""
    root = Path(__file__).resolve().parents[1]
    rec = (root / "ice" / "exercise" / "record.py").read_text()
    body = rec[rec.index("def hand_over_case"):rec.index("def _mcp_port")]
    assert '"baseline": t0' in body

    src = (root / "ice" / "daemon" / "orchestrator.py").read_text()
    handed = src[src.index("def investigate_handed_over"):src.index("def run_forever")]
    assert 'payload.get("baseline")' in handed
    assert "self.store.save(snap)" in handed
    # and the baseline must be stored before the case runs, or `before()` still finds nothing
    assert handed.index("self.store.save(snap)") < handed.index("return self.run_case")
