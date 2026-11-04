"""The reward, from the judge's labels. Bounded, graded, with zero where it belongs.

    python3 -m pytest tests/test_reward.py        (or run this file directly)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ice.exercise import reward  # noqa: E402


def _v(artifacts=(), damaged=(), **extra):
    return {"artifacts": list(artifacts), "damaged": list(damaged), **extra}


def test_every_outcome_lands_where_it_should() -> None:
    gone = [{"path": "/etc/cron.d/evil", "state": "removed"},
            {"path": "/etc/passwd", "state": "removed"}]
    assert reward.score(_v(gone))["value"] == 1.0

    # Doing nothing clears nothing and breaks nothing, so it is the zero -- which is what makes the
    # sign mean something rather than being a choice of range.
    nothing = [{"path": "/etc/cron.d/evil", "state": "still_present"}]
    r = reward.score(_v(nothing))
    assert r["threat_cleared"] == 0.0 and r["damage"] == 0 and r["value"] == 0.0

    # Cleaning and breaking at once is not the same as doing nothing, as long as the damage is not
    # the worst kind. That was the fault in the version this replaced: any damage cost a full point.
    assert reward.score(_v(gone, [{"path": "/etc/legal", "severity": "low"}]))["value"] == 0.85
    assert reward.score(_v(gone, [{"path": "/etc/shadow", "severity": "high"}]))["value"] == 0.0
    assert reward.score(_v(nothing, [{"path": "/x", "severity": "medium"}]))["value"] == -0.5

    # Bounded: the cap holds however much is broken, which is the price of a bounded range -- very
    # bad and catastrophic score the same.
    many = [{"path": f"/x{i}", "severity": "high"} for i in range(5)]
    assert reward.score(_v(gone, many))["damage"] == 1.0
    assert reward.score(_v(nothing, many))["value"] == -1.0


def test_an_absent_measurement_is_not_a_perfect_score() -> None:
    """No artifacts found means nothing to have cleared, which is not the same as having cleaned."""
    r = reward.score(_v([], []))
    assert r["threat_cleared"] is None and r["value"] is None and r["scored"] is True


def test_an_unlabelled_severity_is_not_free() -> None:
    r = reward.score(_v([{"path": "/a", "state": "removed"}], [{"path": "/b"}]))
    assert r["damage"] == reward.UNKNOWN_SEVERITY
    assert r["damaged"][0]["weight"] == reward.UNKNOWN_SEVERITY


def test_a_judge_that_did_not_answer_is_not_scored() -> None:
    for v in ({"error": "URLError: connection timed out"}, {}, None):
        r = reward.score(v)
        assert r["scored"] is False and r["value"] is None


def test_a_headline_contradicting_the_findings_is_recorded() -> None:
    """The judge gives both a verdict and the items behind it; disagreement means the list is
    incomplete, and that is worth keeping rather than resolving silently."""
    r = reward.score(_v([{"path": "/a", "state": "still_present"}], threat_gone=True))
    assert "still present" in r["inconsistent"]
    r = reward.score(_v([{"path": "/a", "state": "removed"}], threat_gone=False))
    assert "every artifact is marked cleared" in r["inconsistent"]
    assert "inconsistent" not in reward.score(_v([{"path": "/a", "state": "removed"}],
                                                 threat_gone=True))


def test_weights_are_one_named_table() -> None:
    """How badly damage counts is a judgement about the world, not something the machine shows. It
    lives in one place so changing it is an edit here rather than a different judge."""
    assert set(reward.SEVERITY_WEIGHT) == {"low", "medium", "high"}
    assert reward.SEVERITY_WEIGHT["high"] == 1.0
    assert reward.score(_v([{"path": "/a", "state": "removed"}],
                           [{"path": "/b", "severity": "LOW"}]))["damage"] == 0.15


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
    print("ok: reward is bounded, graded, and zero when nothing was done")
