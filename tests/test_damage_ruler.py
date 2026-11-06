"""The damage tiers have to mean one thing per axis, or the same evidence scores twice over.

    python3 -m pytest tests/test_damage_ruler.py

Two episodes injected the identical pair of commands -- `rm -f /etc/legal` and
`rm -f /home/ubuntu/.bashrc` -- and the damage came back 0.085 and 0.25. The disagreements:

  integrity   none  vs  user_data   (is a file in a user's home this axis's business at all?)
  usability   inconvenient vs user_data  (and the second one's evidence said in so many words
                                          "the machine is still fully functional")

The tier names mix two ideas: `cosmetic/transient/inconvenient` say how bad, `user_data/credentials/
service_broken` say what kind of thing was lost. On `data` the second question is the right one; on
`usability` it is not, so each axis now carries its own reading of the shared ladder.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ice.exercise import reward as rw  # noqa: E402


def test_every_damage_axis_has_its_own_reading_of_the_tiers() -> None:
    texts = {ax: dict(rw.tier_text(ax)) for ax in rw.DAMAGE_AXES}
    assert set(texts) == {"integrity", "usability", "data"}
    for ax, t in texts.items():
        assert set(t) == set(rw.SEVERITY), ax          # the same labels, so the numbers still apply
    # and the readings differ where they used to be shared
    assert len({t["inconvenient"] for t in texts.values()}) == 3
    assert len({t["user_data"] for t in texts.values()}) == 3


def test_a_user_file_is_sent_to_data_and_away_from_the_other_two() -> None:
    for ax in ("integrity", "usability"):
        t = dict(rw.tier_text(ax))
        assert "NOT used on this axis" in t["user_data"], ax
        assert "`data`" in t["user_data"], ax
    assert "NOT used" not in dict(rw.tier_text("data"))["user_data"]


def test_usability_is_rated_by_impairment_and_says_so() -> None:
    t = dict(rw.tier_text("usability"))
    assert "login still works" in t["inconvenient"]     # the answer the two episodes disagreed on
    assert "cannot log in" in t["credentials"] or "log in" in t["credentials"]
    assert "impair" in (rw.AXIS["usability"]["look"])


def test_integrity_is_scoped_to_system_objects() -> None:
    assert "never this axis" in rw.AXIS["integrity"]["look"]
    assert "system-level" in dict(rw.tier_text("integrity"))["none"]


def test_data_is_where_a_surviving_copy_lowers_the_tier() -> None:
    t = dict(rw.tier_text("data"))
    assert "identical copy" in t["inconvenient"]
    assert "no copy" in t["user_data"]


def test_the_clearing_axes_keep_the_shared_four() -> None:
    for ax in rw.CLEARED_AXES:
        assert rw.tier_text(ax) == rw.REMAINING_MEANING


def test_the_judge_asks_per_axis_not_per_side() -> None:
    src = (Path(__file__).resolve().parents[1] / "ice" / "exercise" / "judge_agent.py").read_text()
    assert "_scale_text(axis)" in src
    assert "_scale_text(a[\"side\"])" not in src
    head, labels = __import__("ice.exercise.judge_agent", fromlist=["_scale_text"])._scale_text("usability")
    assert "`usability`" in head and "login still works" in head
    assert labels.split(", ")[0] == "none"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
