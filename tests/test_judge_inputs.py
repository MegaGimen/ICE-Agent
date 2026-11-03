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


if __name__ == "__main__":
    test_nothing_the_agent_wrote_reaches_the_judge()
    test_the_judge_is_told_the_commands_are_facts_and_not_arguments()
    test_an_episode_that_did_nothing_has_nothing_to_show_for_it()
    print("ok: the agent has no channel to the judge")
