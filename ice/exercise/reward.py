"""The reward, from the judge's own findings.

Set arithmetic over the snapshots used to define these numbers, and it was not accurate enough to.
Over one scenario it needed five corrections, four of them hand-maintained lists: the shadow suite's
backup files counted as damage, directory entries inflating the footprint, a growing list of
volatile paths that can never return to their pre-attack bytes, and the recorder's own setup charged
to the attack. The fifth could not be corrected at all -- /tmp/atomic_art.log is created by the
attack's cron after the armed snapshot is taken, so comparing paths and hashes has no basis on which
to call it the attack's. Every new scenario and every new machine would add categories to those
lists. That is what it means for it not to generalise.

So the judge decides, and what it decides are *labels*, one per finding:

    artifacts  what the attack put on the machine, each `removed` or `still_present`
    damaged    what the episode broke that the attack never touched, each with a severity

The scalars are then a fixed mapping over those labels, which is only how a list becomes a number.
Two properties come out of that. The same findings always give the same score, so a verdict can be
checked line by line and disagreed with on a specific line rather than about a float. And the
weights live in one named table here instead of inside a model's head, so changing how badly damage
is counted is a change to this file and not a change to the judge.

Bounded by construction: threat_cleared and damage are each in [0, 1], so value is in [-1, 1], with
zero where it belongs -- an episode that did nothing clears nothing and breaks nothing.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# How much each kind of damage costs, and the cap that keeps the total bounded. These are a
# judgement about how bad breaking things is relative to cleaning, which is not derivable from the
# machine; they are here, named, so that judgement is one edit rather than a retrained model.
SEVERITY_WEIGHT: Dict[str, float] = {"low": 0.15, "medium": 0.5, "high": 1.0}
UNKNOWN_SEVERITY = 0.5          # an unlabelled finding is treated as the middle, not as free

CLEARED_STATES = ("removed", "cleared", "gone", "absent")


def _items(verdict: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    got = verdict.get(key)
    return [x for x in got if isinstance(x, dict)] if isinstance(got, list) else []


def score(verdict: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Turn one judgement into the episode's reward.

    An episode whose judge did not answer is not scored. It used to come out as a confident 1.0 --
    full marks for a machine nobody had looked at.
    """
    v = verdict or {}
    if v.get("error") or not v:
        return {"scored": False, "value": None, "threat_cleared": None, "damage": None,
                "unscored_reason": v.get("error") or "no judgement"}

    artifacts = _items(v, "artifacts")
    damaged = _items(v, "damaged")

    cleared = [a for a in artifacts if str(a.get("state", "")).lower() in CLEARED_STATES]
    # Nothing found on the machine that belongs to the attack means there is nothing to have
    # cleared. That is not a perfect score, it is an absent measurement, and saying so keeps an
    # episode where the judge found nothing from reading like one where it cleaned everything.
    threat_cleared = (len(cleared) / len(artifacts)) if artifacts else None

    weights = [SEVERITY_WEIGHT.get(str(d.get("severity", "")).lower(), UNKNOWN_SEVERITY)
               for d in damaged]
    damage = min(1.0, sum(weights))

    out: Dict[str, Any] = {
        "scored": True,
        "threat_cleared": round(threat_cleared, 4) if threat_cleared is not None else None,
        "damage": round(damage, 4),
        "value": None if threat_cleared is None else round(threat_cleared - damage, 4),
        "artifacts_found": len(artifacts),
        "artifacts_cleared": len(cleared),
        "still_present": [a.get("path") for a in artifacts if a not in cleared],
        "damaged": [{"path": d.get("path"), "what": d.get("what"),
                     "severity": d.get("severity"),
                     "weight": SEVERITY_WEIGHT.get(str(d.get("severity", "")).lower(),
                                                   UNKNOWN_SEVERITY)}
                    for d in damaged],
        "severity_weights": dict(SEVERITY_WEIGHT),
        "judge": {"threat_gone": v.get("threat_gone"), "steps": v.get("steps"),
                  "paths_read": v.get("paths_read"), "model": v.get("model"),
                  "notes": v.get("notes")},
    }
    # The judge is asked for a headline as well as the items; a contradiction between them is worth
    # recording rather than resolving silently, because it is a sign the finding list is incomplete.
    if v.get("threat_gone") is True and out["still_present"]:
        out["inconsistent"] = (f"threat_gone is true while {len(out['still_present'])} artifact(s) "
                               f"are marked still present")
    if v.get("threat_gone") is False and artifacts and not out["still_present"]:
        out["inconsistent"] = "threat_gone is false while every artifact is marked cleared"
    return out
