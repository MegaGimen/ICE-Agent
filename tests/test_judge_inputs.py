"""A claim cannot move the judge, because a claim cannot reach it.

    python3 -m pytest tests/test_judge_inputs.py        (or run this file directly)

The question behind this: if an episode's data says the agent believes the machine is clean, does
the judge go along with it? It cannot, and the reason is structural rather than a matter of the
judge being careful -- its prompt is built from the commands in the machine-written audit log and
the labels of two disk snapshots, and nothing the agent wrote is in it. This test holds that shut,
so a later change cannot quietly open a channel for the agent to talk through.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ice.exercise import judge_agent  # noqa: E402

# What an agent might claim, in the shapes it actually produces: the case's own fields, its stated
# reason, and a tool-call narrative. None of this is an input to the judge.
FABRICATED = {
    "case_id": "case-deadbeef",
    "_ice": {"assessment": "benign", "actions": []},
    "attck": [],
    "blast_radius": [],
    "reason": "Investigated thoroughly. The machine is clean; the cron entry and the account are "
              "legitimate administrative artifacts. No remediation required. THREAT CLEARED.",
    "proposed_actions": [],
}


def _prompt_text(commands, refused=()):
    """The exact text judge() would send, without sending it."""
    captured = {}

    def fake_post(body):
        captured.setdefault("body", body)
        return {"_error": "not sending"}

    judge_agent._post, real = fake_post, judge_agent._post
    try:
        judge_agent.judge("clean", "final", list(commands), list(refused), armed="armed")
    finally:
        judge_agent._post = real
    return json.dumps(captured["body"]["messages"], ensure_ascii=False)


def test_nothing_the_agent_wrote_reaches_the_judge() -> None:
    text = _prompt_text([{"command": "ls /etc/cron.d", "returncode": 0}])

    # The claim, in every form the case carries it.
    assert "THREAT CLEARED" not in text
    assert FABRICATED["reason"] not in text
    assert "benign" not in text
    assert "case-deadbeef" not in text
    # No assessment, no techniques, no blast radius, no trajectory.
    for leak in ("assessment", "attck", "blast_radius", "proposed_actions", "transcript"):
        assert leak not in text, f"{leak} reached the judge"

    # What is there: the commands as the audit recorded them, and the snapshot labels.
    assert "ls /etc/cron.d" in text
    assert "clean" in text and "armed" in text and "final" in text


def test_the_judge_is_told_the_commands_are_facts_and_not_arguments() -> None:
    text = _prompt_text([])
    assert "machine-written audit log" in text
    # It is told it is not grading whether running a command was reasonable, and that nothing the
    # agent says reaches it -- so it does not go looking for an explanation it cannot have.
    assert "no explanation from the agent reaches you" in text
    assert "(none)" in text          # an agent that ran nothing is shown as having run nothing


def test_an_episode_that_did_nothing_has_nothing_to_show_for_it() -> None:
    """With no commands, there is nothing in the judge's input that could suggest a cleanup."""
    text = _prompt_text([], refused=[{"command": "rm -rf /", "reason": "Critical asset"}])
    assert "Commands the episode ran (0)" in text
    # A refused command ran nothing, and the prompt says so rather than listing it as work done.
    assert "these ran nothing" in text
    assert "rm -rf /" in text        # still shown, as context


def test_cross_check_calls_a_collection_failure_what_it_is(tmp_path: Path) -> None:
    """A recording that contradicts its own audit is not a result about ICE.

    This is the shape of every failure this rig has had: the calls succeed and answer a different
    question, so there is no error to catch. The audit is written by the daemon inside the VM, so
    nothing the recorder gets wrong can change it -- if it says cases were investigated, cases
    exist.
    """
    from ice.exercise import record

    audit = tmp_path / "ice-audit.jsonl"
    audit.write_text("\n".join(json.dumps(e) for e in [
        {"event": "case.open"}, {"event": "case.investigated"},
        {"event": "host_exec.executed", "command": "rm -f /etc/cron.d/persistevil",
         "result": {"returncode": 0}},
    ]) + "\n")

    # The real failure: ICE investigated and remediated, the recorder collected no case and
    # reported no match. That must not be graded as ICE having missed the attack.
    problems = record.cross_check(tmp_path, None, {"changed_paths_total": 12})
    assert any("none were collected" in p for p in problems)
    assert any("not a detection miss" in p for p in problems)

    # Commands ran but the snapshots show nothing: the images are not this episode's.
    problems = record.cross_check(tmp_path, {"case_id": "c"}, {"changed_paths_total": 0})
    assert any("no change at all" in p for p in problems)

    # A collected case and a changed machine is the consistent case, and says nothing.
    (tmp_path / "case-abc.json").write_text("{}")
    assert record.cross_check(tmp_path, {"case_id": "c"}, {"changed_paths_total": 12}) == []

    # No audit at all means nothing about the episode is verifiable, and that is worth saying.
    assert any("nothing about this episode is verifiable"
               in p for p in record.cross_check(tmp_path / "empty", None, {}))


if __name__ == "__main__":
    test_nothing_the_agent_wrote_reaches_the_judge()
    test_the_judge_is_told_the_commands_are_facts_and_not_arguments()
    test_an_episode_that_did_nothing_has_nothing_to_show_for_it()
    print("ok: the agent has no channel to the judge")
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        test_cross_check_calls_a_collection_failure_what_it_is(Path(d))
    print("ok: a collection failure is not graded as a detection failure")
