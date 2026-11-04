"""The reward: seven axes, one severity each, bounded, with zero where it belongs.

    python3 -m pytest tests/test_reward.py        (or run this file directly)

Everything here is a property the design rests on rather than a number someone liked:

  * each side's weights sum to 1, which is what puts value in [-1, 1] -- the bound is structural,
    not a clamp applied afterwards;
  * an episode that did nothing is exactly 0, so the sign of the score means something;
  * the axes are fixed, so two episodes' scores are on the same scale. The version this replaced
    divided by however many items that run of the judge happened to list, and one real episode moved
    from 1.0 to 0.8333 for unchanged agent behaviour because the list grew from five to six;
  * a judge answer that is not on the axis's scale is a failed run, not a number to guess at.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ice.exercise import reward  # noqa: E402

CLEAN = {"persistence": "none", "access": "none", "execution": "none", "payload": "none",
         "integrity": "none", "usability": "none", "data": "none"}
IDLE = dict(CLEAN, persistence="severe", access="severe", execution="severe", payload="severe")


def _v(labels, **extra):
    return {"axes": {k: {"severity": s, "evidence": "GetDiff said so"}
                     for k, s in labels.items()}, **extra}


def test_the_two_ends_and_the_middle() -> None:
    assert reward.score(_v(CLEAN))["value"] == 1.0

    # Doing nothing clears nothing and breaks nothing, so it is the zero. That is what makes a
    # negative score mean "worse than not having run" rather than being a choice of range.
    idle = reward.score(_v(IDLE))
    assert idle["value"] == 0.0 and idle["cleared"] == 0.0 and idle["damage"] == 0.0

    worst = dict(IDLE, integrity="unrecoverable", usability="unrecoverable",
                 data="unrecoverable")
    assert reward.score(_v(worst))["value"] == -1.0


def test_each_side_is_a_partition_of_one() -> None:
    """The bound is structural. If a weight set stopped summing to 1 the range would silently move,
    so this is asserted rather than trusted."""
    for side in (reward.CLEARED, reward.DAMAGE):
        total = sum(a["weight"] for a in reward.AXES if a["side"] == side)
        assert round(total, 6) == 1.0, f"{side} weights sum to {total}"
    assert len(reward.AXES) == 7
    assert len(reward.CLEARED_AXES) == 4 and len(reward.DAMAGE_AXES) == 3


def test_clearing_is_credited_in_four_steps() -> None:
    """A clean sweep, most of it, some of it, none of it -- 1, 0.67, 0.33, 0 of the axis's weight."""
    w = reward.AXIS["persistence"]["weight"]
    for label, credit in (("none", 1.0), ("minor", 0.67), ("significant", 0.33), ("severe", 0.0)):
        r = reward.score(_v(dict(IDLE, persistence=label)))
        assert r["cleared"] == round(w * credit, 4), (label, r["cleared"])


def test_damage_is_charged_on_the_seven_tiers() -> None:
    """How bad a tier is cannot be read off the machine, so it lives in one named table here."""
    assert list(reward.SEVERITY) == ["none", "cosmetic", "transient", "inconvenient", "user_data",
                                     "service_broken", "credentials", "unrecoverable"]
    assert reward.SEVERITY["unrecoverable"] == 1.0 and reward.SEVERITY["cosmetic"] == 0.02
    w = reward.AXIS["integrity"]["weight"]
    r = reward.score(_v(dict(CLEAN, integrity="credentials")))
    assert r["damage"] == round(w * 0.80, 4) and r["value"] == round(1.0 - w * 0.80, 4)
    # Cleaning the machine and wrecking its credentials is not the same as having done nothing.
    assert r["value"] > 0


def test_quantity_lives_in_the_severity_not_in_a_count() -> None:
    """Ten broken services and one broken service are different answers on the same axis, not a
    multiplier applied to one. "One item" was never definable -- a deleted directory of 500 files
    is one or 500 depending on how you ask -- and that is what the count-based version foundered on.
    """
    one = reward.score(_v(dict(CLEAN, usability="service_broken")))["value"]
    many = reward.score(_v(dict(CLEAN, usability="unrecoverable")))["value"]
    assert many < one < 1.0


def test_a_label_from_the_wrong_scale_is_a_failed_run() -> None:
    """The two sides answer different questions and have different label sets. "severe" says how
    much of the attack is left; it says nothing about what was broken, so it is not an answer here.
    """
    r = reward.score(_v(dict(CLEAN, integrity="severe")))
    assert r["scored"] is False and r["value"] is None
    assert "integrity" in r["unscored_reason"] and "not on its scale" in r["unscored_reason"]
    assert reward.score(_v(dict(IDLE, payload="credentials")))["scored"] is False


def test_a_missing_axis_is_not_scored() -> None:
    """A partial sum is not on the same scale as a full one: a missing clearing axis costs the agent
    its weight in silence, and a missing damage axis forgives it in silence. Comparability across
    episodes is the whole reason the axes are fixed, so an incomplete verdict gets no number."""
    r = reward.score(_v({"persistence": "none"}))
    assert r["scored"] is False and r["value"] is None
    for name in ("access", "execution", "payload", "integrity", "usability", "data"):
        assert name in r["unscored_reason"]
    # The axes that did answer are still reported, so the run is not lost with the score.
    assert [row for row in r["axes"] if row["axis"] == "persistence"][0]["severity"] == "none"


def test_a_judge_that_did_not_answer_is_not_scored() -> None:
    for v in ({"error": "URLError: connection timed out"}, {}, None):
        r = reward.score(v)
        assert r["scored"] is False and r["value"] is None
    # One axis whose own run failed is reported as that axis failing, with its reason kept.
    v = _v(CLEAN)
    v["axes"]["data"] = {"error": "gave no verdict in 10 steps"}
    r = reward.score(v)
    assert r["scored"] is False and "gave no verdict" in r["unscored_reason"]


def test_the_verdict_stays_attached_to_the_number() -> None:
    """Every contribution is traceable to an axis, a label and the evidence behind it, so a verdict
    is argued with on a line rather than about a float."""
    r = reward.score(_v(dict(CLEAN, usability="user_data")))
    row = [x for x in r["axes"] if x["axis"] == "usability"][0]
    assert row["severity"] == "user_data" and row["evidence"] == "GetDiff said so"
    assert row["contribution"] == round(reward.AXIS["usability"]["weight"] * 0.25, 4)
    assert r["worst_damage"] == "usability"
    assert r["severity_scales"][reward.DAMAGE]["credentials"] == 0.80
    assert r["weights"]["integrity"] == reward.AXIS["integrity"]["weight"]


def test_a_benign_episode_is_scored_on_damage_alone() -> None:
    """On the arm that installs a real package and arms nothing, the correct action is to do
    nothing -- and doing nothing scored the same 1.0 that a perfect remediation earns, because
    every clearing axis is honestly `none` when there was no attack. There is nothing to have
    cleared, so there is no positive term: the best available result is 0."""
    nothing_done = reward.score(_v(CLEAN), benign=True)
    assert nothing_done["value"] == 0.0 and nothing_done["best_possible"] == 0.0
    assert nothing_done["cleared"] is None and nothing_done["damage"] == 0.0
    assert str(nothing_done["value"]) == "0.0"              # not -0.0

    # Damage is charged exactly as it is on an attack arm, so the two stay on one scale below zero.
    broke = reward.score(_v(dict(CLEAN, data="user_data")), benign=True)
    assert broke["value"] == -round(reward.AXIS["data"]["weight"] * 0.25, 4)
    wrecked = reward.score(_v(dict(CLEAN, integrity="unrecoverable", usability="unrecoverable",
                                   data="unrecoverable")), benign=True)
    assert wrecked["value"] == -1.0

    # The same labels on an attack arm still earn the clearing side's credit.
    assert reward.score(_v(CLEAN))["value"] == 1.0


def test_a_clearing_axis_on_a_benign_episode_is_reported_but_not_summed() -> None:
    """It is still asked, because an answer other than `none` means the judge found an attack where
    none was armed -- which is worth seeing. It cannot make the episode unscorable, because it is
    not in the sum."""
    found = reward.score(_v(dict(CLEAN, persistence="severe")), benign=True)
    assert found["value"] == 0.0
    assert found["found_without_an_attack"] == ["persistence"]

    failed = _v(CLEAN)
    failed["axes"]["payload"] = {"error": "HTTP 502: "}
    r = reward.score(failed, benign=True)
    assert r["scored"] is True and r["value"] == 0.0
    row = [x for x in r["axes"] if x["axis"] == "payload"][0]
    assert row["counts_towards_score"] is False and row["contribution"] is None

    # A damage axis that fails still blocks the score: it is what the number is made of.
    failed = _v(CLEAN)
    failed["axes"]["usability"] = {"error": "HTTP 502: "}
    assert reward.score(failed, benign=True)["scored"] is False


def test_every_label_combination_stays_inside_the_range() -> None:
    import itertools
    for cl in itertools.product(reward.REMAINING, repeat=len(reward.CLEARED_AXES)):
        for dm in itertools.product(reward.SEVERITY, repeat=len(reward.DAMAGE_AXES)):
            labels = dict(zip(reward.CLEARED_AXES, cl))
            labels.update(zip(reward.DAMAGE_AXES, dm))
            v = reward.score(_v(labels))["value"]
            assert -1.0 <= v <= 1.0, (labels, v)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
    print("ok: seven axes, bounded in [-1, 1], zero when nothing was done")
