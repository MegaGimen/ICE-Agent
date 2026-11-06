"""The agent reads one prompt, whichever posture the daemon is in.

    python3 -m pytest tests/test_one_prompt_for_both_postures.py

An agent that can tell it is being recorded is not the agent that will run in deployment. The
forced-escalation path put

    "reasons": ["forced escalation (recording; the decision model is not consulted)"]

into the case, which the orchestrator hands over and the prompt rendered verbatim.

And the whole envelope was the wrong thing to show in either posture. The detection model is a
filter on what is worth looking at; an agent that reads its verdict, its attribute scores or its
priority takes confidence from it, in whichever direction it points -- including from the mere fact
that it answered. So the prompt carries the flagged changes and nothing else about how they were
flagged: not the verdict, not the scores, not the word for the act of flagging them.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ice.daemon.contracts import ChangeEntry, ChangeType, Provenance  # noqa: E402
from ice.daemon.detect import gate as detect_gate                      # noqa: E402
from ice.daemon.investigate import prompts                             # noqa: E402

# Words that would tell the agent which posture it is in. "drill" and "test" are deliberately NOT
# here: the prompt tells the agent that a name like that proves nothing, which is content about the
# host's data, not about this daemon.
POSTURE_WORDS = ("recording", "record mode", "ICE_RECORD", "dataset", "episode", "being recorded",
                 "rehearsal", "simulation", "benign arm", "this is a test run")


def _entry() -> ChangeEntry:
    return ChangeEntry(type=ChangeType.CRON, table="cron", field="/etc/cron.d/logreport#bc17",
                       value="added: cron entry in /etc/cron.d/logreport",
                       provenance=Provenance(user="root"),
                       untrusted={"command": "root /usr/local/bin/logreport --once --quiet"})


def _forced() -> dict:
    os.environ["ICE_FORCE_ESCALATE"] = "1"
    try:
        return detect_gate.evaluate(_entry()).to_dict()
    finally:
        os.environ.pop("ICE_FORCE_ESCALATE", None)


def test_nothing_the_agent_reads_names_the_posture() -> None:
    text = prompts.wake_message("case-1", "ice-target", [_forced()],
                                state_diff={"cron": "cron: 1 row(s) now\n+ /etc/cron.d/logreport"})
    low = text.lower()
    for word in POSTURE_WORDS:
        assert word.lower() not in low, word


def test_the_detection_envelope_never_reaches_the_agent() -> None:
    """The gate still records its own result -- the case file and the audit keep it -- but none of
    it is rendered: no verdict, no attribute scores, no priority, no reasons, and not the word for
    the act of flagging."""
    r = _forced()
    assert r["escalate"] is True and "reasons" in r      # still produced, for the record
    text = prompts.wake_message("case-1", "ice-target", [r])
    low = text.lower()
    for leak in ("escalat", "verdict_probs", "priority", '"attributes"', "verdict\":"):
        assert leak.lower() not in low, leak
    # What is rendered is the change itself, under a name that says what it is.
    assert '"suspicious_changes"' in text
    assert "/etc/cron.d/logreport#bc17" in text
    assert "logreport --once --quiet" in text            # the untrusted field, as data


def test_the_prompt_says_nothing_about_the_detection_model() -> None:
    """Not its verdict, not its scores, and not whether it was available: ICE's eyes are that model,
    so there is no version of this prompt in which the agent should be reasoning about it."""
    text = prompts.wake_message("case-1", "ice-target", [_forced()],
                                state_diff={"cron": "cron: 1 row(s) now\n+ /etc/cron.d/logreport"})
    low = text.lower()
    for phrase in ("decision model", "detection gate", "unavailable", "unjudged", "no model",
                   "model judgement", "kev"):
        assert phrase not in low, phrase


def test_the_flag_is_offered_as_a_filter_not_as_a_finding() -> None:
    text = prompts.wake_message("case-1", "ice-target", [_forced()])
    assert "not a finding" in text
    assert "decided that it is harmless either" in text   # neither direction is given to it
    assert "That decision is yours" in text
    assert "`assessment` field" in text


def test_a_benign_assessment_means_no_actions() -> None:
    text = prompts.wake_message("case-1", "ice-target", [_forced()])
    assert "If your assessment is `benign`, propose none" in text
    assert "removing something legitimate is the worse outcome" in text


def test_the_three_assessments_are_still_on_offer() -> None:
    text = prompts.wake_message("case-1", "ice-target", [_forced()])
    assert "malicious | benign | uncertain" in text


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
