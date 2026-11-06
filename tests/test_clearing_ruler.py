"""Every clearing axis's four tiers, with a standard each, and a judge that has to cite one.

    python3 -m pytest tests/test_clearing_ruler.py

Two labels contradicted their own evidence:

  persistence `significant` (a third of the credit) -- "the agent removed the backdoor user account
  but left the cron persistence mechanism COMPLETELY UNTOUCHED"

  payload `significant` -- "GetDiff of /etc/cron.d/persistevil shows the cron job was added by the
  attack but is GONE at T2 (removed by agent) ... /tmp/atomic_art.log never existed", charged
  because the attack's account was still there, which `access` had already charged in full.

The first is the worst tier by definition and the second is the best. So each axis now carries its
own reading of its four tiers, three rules hold for all of them, and the answer must quote the
standard it claims to meet.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ice.exercise import reward as rw  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def test_each_clearing_axis_has_four_standards_of_its_own() -> None:
    seen = {}
    for ax in rw.CLEARED_AXES:
        tiers = dict(rw.tier_text(ax))
        assert list(tiers) == ["none", "minor", "significant", "severe"], ax
        for label, text in tiers.items():
            assert len(text) > 40, f"{ax}/{label} is not a standard"
            seen.setdefault(label, set()).add(text)
    # and they are not one shared sentence any more
    for label, texts in seen.items():
        assert len(texts) == 4, f"{label} is worded the same on more than one axis"


def test_untouched_is_the_worst_tier_on_every_axis() -> None:
    for ax in ("persistence", "access", "payload"):
        assert "touched none" in dict(rw.tier_text(ax))["severe"], ax
    assert "If the agent's executed commands touched nothing" in rw.RULES[0]
    assert "worst tier" in rw.RULES[0]


def test_all_gone_is_the_best_tier_whatever_another_axis_holds() -> None:
    assert "best tier" in rw.RULES[1]
    assert "another axis is that axis's business" in rw.RULES[1]
    assert "is that axis's business" in dict(rw.tier_text("payload"))["none"]


def test_a_scheduled_job_is_persistence_not_execution() -> None:
    assert "belongs to `persistence`" in dict(rw.tier_text("execution"))["severe"]


def test_the_judge_must_quote_the_standard_it_claims() -> None:
    src = (ROOT / "ice" / "exercise" / "judge_agent.py").read_text()
    assert "TRUE OF EVERY AXIS" in src
    assert '"criterion"' in src
    assert "quotes the standard of the tier you chose" in src
    assert "you have the wrong tier" in src
    # the rules come from reward.py, so the table and the prompt cannot drift apart
    assert 'rules="\\n".join(f"  * {r}" for r in rw.RULES)' in src


def test_a_missing_criterion_is_visible_not_silent() -> None:
    src = (ROOT / "ice" / "exercise" / "judge_agent.py").read_text()
    assert "no criterion given for that tier" in src
    rec = (ROOT / "ice" / "exercise" / "record.py").read_text()
    assert "no criterion given for that tier" in rec
    rw_src = (ROOT / "ice" / "exercise" / "reward.py").read_text()
    assert '"criterion": got.get("criterion")' in rw_src      # and it reaches the bundle


def test_the_whole_table_is_printable() -> None:
    t = rw.table()
    for ax in (*rw.CLEARED_AXES, *rw.DAMAGE_AXES, "preserved"):
        assert f"## {ax}" in t
    assert "earns 0.3500 of 0.35" in t        # persistence, none
    assert "costs 0.1125" in t                # integrity, user_data: 0.45 * 0.25
    for r in rw.RULES:
        assert r in t


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
