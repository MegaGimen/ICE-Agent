"""Reading an episode's commands back out of the audit, and parsing a judge's reply.

    python3 -m pytest tests/test_command_trace.py        (or run this file directly)

Path verification used to live here, against a tarball of 19 declared paths plus whatever osquery
collected. ice.exercise.image replaced it and tests/test_image.py covers the replacement; what is
left here is the audit reader and the reply parser, both of which had real failures of their own.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ice.exercise import command_trace as ct  # noqa: E402


def test_audit_reader(tmp_path: Path) -> None:
    """Executed and refused commands come from different events and must not be mixed up: a refused
    command ran nothing, so it explains no change on the machine."""
    audit = tmp_path / "audit.jsonl"
    audit.write_text("\n".join(json.dumps(e) for e in [
        {"event": "snapshot", "ts": 1},
        {"event": "host_exec.executed", "command": "userdel butter",
         "result": {"returncode": 0, "stderr": ""}, "by": "ice", "case": "case-1"},
        {"event": "host_exec.verdict", "command": "sed -i /etc/passwd",
         "verdict": {"decision": "DENY", "reason": "Critical asset is denied by policy"}},
        {"event": "host_exec.verdict", "command": "rm -f /etc/cron.d/x",
         "verdict": {"decision": "ALLOW", "reason": "ok"}},
        {"event": "host_exec.executed", "command": "rm -f /etc/cron.d/x",
         "result": {"returncode": 6, "stderr": "no such file"}, "dry_run": True},
    ]) + "\n")

    runs = ct.executed_commands(audit)
    assert [c["command"] for c in runs] == ["userdel butter", "rm -f /etc/cron.d/x"]
    assert runs[0]["returncode"] == 0 and runs[0]["case"] == "case-1"
    assert runs[1]["returncode"] == 6 and runs[1]["dry_run"] is True

    refused = ct.refused_commands(audit)
    assert [c["command"] for c in refused] == ["sed -i /etc/passwd"]   # the ALLOW is not a refusal

    # A malformed line must not lose the rest of the log, and a missing file is not an exception.
    audit.write_text("not json\n" + json.dumps(
        {"event": "host_exec.executed", "command": "ls", "result": {"returncode": 0}}) + "\n")
    assert [c["command"] for c in ct.executed_commands(audit)] == ["ls"]
    assert ct.executed_commands(tmp_path / "missing.jsonl") == []


def test_judge_reply_parsing() -> None:
    """A correct judgement must survive the shapes a model actually replies in.

    Both of these were real: one episode's reply had a sentence before the object, so parsing the
    whole string failed at char 0 and every path the judge had worked out -- all of them right --
    was discarded, leaving the verification layer empty. The same reply also named its per-command
    list `commands` rather than the `command_effects` the prompt asks for.
    """
    from ice.exercise.evaluate import json_object, paths_from

    assert json_object('{"a": 1}') == {"a": 1}
    assert json_object('Let me work through each command.\n\n{"paths_to_check": ["/etc/passwd"]}') \
        == {"paths_to_check": ["/etc/passwd"]}
    assert json_object("```json\n{\"a\": 2}\n```") == {"a": 2}
    assert json_object("no json here") is None
    assert json_object("") is None

    # Renamed key, paths nested per command: still a usable answer.
    assert paths_from({"commands": [{"command": "userdel butter",
                                     "paths": ["/etc/passwd", "/etc/shadow"]},
                                    {"command": "rm -f /etc/cron.d/x",
                                     "paths": ["/etc/cron.d/x"]}]}) \
        == ["/etc/passwd", "/etc/shadow", "/etc/cron.d/x"]
    # The flat list wins first place, nested paths are added, duplicates collapse, globs dropped.
    assert paths_from({"paths_to_check": ["/etc/group", "not-a-path"],
                       "command_effects": [{"paths": ["/etc/group", "/etc/gshadow"]}]}) \
        == ["/etc/group", "/etc/gshadow"]
    assert paths_from({}) == []


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        test_audit_reader(Path(d))
    test_judge_reply_parsing()
    print("ok: audit reader, judge reply parsing")
