"""The scenario's three arms, and what counts as correct on each.

    python3 -m pytest tests/test_arms.py        (or run this file directly)

The scenario has carried three arms since it was written and the recorder only ever armed one, so
every episode recorded so far is the same three commands. The other two are what the reward needs:
`variant` reaches the same goal by another technique, and `normal` is a real package install with no
attack in it at all. On that one the right answer is inverted -- nothing to clear, nothing broken,
and no case is correct rather than a miss.
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ice.exercise.scenarios import SCENARIOS  # noqa: E402

S = SCENARIOS["persistence"]


def _arm(name: str):
    os.environ["ICE_SCENARIO_ARM"] = name
    import ice.exercise.record as record
    importlib.reload(record)
    return record, record.arm_of(S)


def test_each_arm_brings_its_own_commands_and_its_own_markers() -> None:
    _, attack = _arm("attack")
    assert attack["commands"] == S.attack and attack["benign"] is False
    assert attack["markers"] == S.markers

    _, variant = _arm("variant")
    assert variant["commands"] == S.variant and variant["benign"] is False
    # The variant's case cannot be found by the original's markers: it creates a systemd unit and
    # mentions neither `butter` nor `persistevil`.
    assert variant["markers"] == ["art-persist"]
    assert not any(m in " ".join(S.variant) for m in S.markers)

    _, normal = _arm("normal")
    assert normal["commands"] == S.normal and normal["benign"] is True
    # No markers: any investigated case is what is being measured, not what is being looked for.
    assert normal["markers"] == []


def test_the_benign_arm_inverts_what_correct_means() -> None:
    """Graded by the attack's rules, a quiet agent on a clean machine reads as a detection miss."""
    record, normal = _arm("normal")

    quiet = record.grade(S, None, normal)
    assert quiet["miss"] is False and quiet["benign_arm"] is True
    assert "correct" in quiet["reasons"][0]

    # Investigating it and calling it malicious is a false positive, and that is the miss here.
    cried_wolf = record.grade(S, {"case_id": "c", "_ice": {"assessment": "malicious"}}, normal)
    assert cried_wolf["false_positive"] is True and cried_wolf["miss"] is True

    # Investigating and finding it benign is not held against it.
    looked = record.grade(S, {"case_id": "c", "_ice": {"assessment": "benign"}}, normal)
    assert looked["false_positive"] is False and looked["miss"] is False

    # On an attack arm the old rules still hold: no case is a miss.
    record, attack = _arm("attack")
    assert record.grade(S, None, attack)["miss"] is True


if __name__ == "__main__":
    test_each_arm_brings_its_own_commands_and_its_own_markers()
    test_the_benign_arm_inverts_what_correct_means()
    print("ok: three arms, and the benign one is graded the other way round")
