"""The agent reads one prompt, whichever posture the daemon is in.

    python3 -m pytest tests/test_one_prompt_for_both_postures.py

A deployment cannot assume that the escalation it received means a threat -- the decision model
upstream can be wrong, or unreachable -- so a recording must not assume it either. And an agent that
can tell it is being recorded is not the agent that will run in deployment.

What was wrong: the forced-escalation path put

    "reasons": ["forced escalation (recording; the decision model is not consulted)"]

into the case, which the orchestrator hands over and the prompt renders verbatim. It told the agent
it was in a recording. The same entries also carried `"verdict": "normal"` from the dataclass
default, which asserts a judgement that nothing had made.
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


def test_an_unjudged_change_is_not_reported_as_normal() -> None:
    """`verdict: "normal"` is a judgement. Nothing judged this, so the field is empty and the
    reason says what actually happened."""
    r = _forced()
    assert r["escalate"] is True
    assert r["verdict"] == ""
    assert r["attributes"] == {} and r["verdict_probs"] == {}
    assert r["reasons"] == ["escalated without a model verdict"]
    assert all("recording" not in x for x in r["reasons"])


def test_the_model_being_down_reads_the_same_way() -> None:
    """The deployment case with no verdict: the gate fails open toward investigation and says so in
    the same shape, so the agent cannot tell the two situations apart by their wording. (Code
    comments may say which posture a branch is for; the agent never reads code.)"""
    src = (Path(__file__).resolve().parents[1] / "ice" / "daemon" / "detect" / "gate.py").read_text()
    body = src[src.index("def evaluate("):src.index("def evaluate_many(")]
    assert body.count('res.verdict = ""') == 2            # forced, and model-unavailable
    reasons = [ln for ln in body.splitlines() if "res.reasons.append(" in ln]
    assert len(reasons) >= 2
    for ln in reasons:
        for word in POSTURE_WORDS:
            assert word.lower() not in ln.lower(), ln


def test_the_prompt_says_escalation_is_not_a_verdict() -> None:
    text = prompts.wake_message("case-1", "ice-target", [_forced()])
    assert "Escalation is not a verdict" in text
    assert "that decision is yours" in text
    # and the source line no longer reads as a finding
    assert "not a judgement that it is a threat" in text


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
