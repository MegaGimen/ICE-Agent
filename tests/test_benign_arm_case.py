"""The benign arm has to look at the case it was handed, not wait out the clock.

    python3 -m pytest tests/test_benign_arm_case.py

`wait_for_case` matched a case by the attack's markers, and the benign arm has none -- so
`any(m in trig for m in [])` was False for every case and the episode always reported "NO case"
after the full 900s. grade() then called that correct: "nothing was investigated". It was true when
a case had to be discovered by the daemon's own polling. The recorder now hands one over on every
arm, so something was investigated, and whether it was called malicious is the one thing the benign
arm exists to measure.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

REC = (Path(__file__).resolve().parents[1] / "ice" / "exercise" / "record.py").read_text()


def _body(start: str, end: str) -> str:
    i = REC.index(start)
    return REC[i:REC.index(end, i)]


def test_a_case_with_no_markers_is_matched_by_when_it_was_opened() -> None:
    body = _body("def wait_for_case", "# ------")
    assert "if not markers:" in body
    assert "_created_after(d, since)" in body


def test_a_leftover_case_from_the_image_is_not_this_episodes() -> None:
    import calendar, time
    from ice.exercise import record
    armed = calendar.timegm(time.strptime("2026-11-06T10:00:00", "%Y-%m-%dT%H:%M:%S"))
    assert record._created_after({"created": "2026-11-06T10:00:05Z"}, armed) is True
    assert record._created_after({"created": "2026-11-06T09:55:00Z"}, armed) is False
    # within the slack: a case opened just before the arm command returned is still this episode's
    assert record._created_after({"created": "2026-11-06T09:59:00Z"}, armed) is True
    # no timestamp at all: take it, because the recorder has just handed one over
    assert record._created_after({}, armed) is True


def test_no_case_on_the_benign_arm_is_no_longer_called_correct() -> None:
    body = _body("def grade", "def _osquery_snapshots")
    assert "nothing was investigated, which is correct" not in body
    assert '"no_case": True' in body


def test_a_benign_case_called_malicious_is_a_false_positive() -> None:
    from ice.exercise import record
    from ice.exercise.scenarios import SCENARIOS
    sc = SCENARIOS["persistence"]
    arm = {"arm": "normal", "benign": True, "markers": []}
    bad = record.grade(sc, {"case_id": "case-1", "_ice": {"assessment": "malicious"}}, arm)
    good = record.grade(sc, {"case_id": "case-2", "_ice": {"assessment": "benign"}}, arm)
    assert bad["false_positive"] is True and bad["miss"] is True
    assert good["false_positive"] is False and good["miss"] is False


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
