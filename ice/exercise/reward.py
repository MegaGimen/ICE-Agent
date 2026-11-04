"""The reward: seven severities from the judge, through one table of weights.

The judge is asked seven questions about the machine the episode left behind, and answers each with
a severity and nothing numeric. The numbers are here. That split is the whole design: a verdict can
be argued with on a specific axis ("integrity is not `credentials`, it is `inconvenient`"), and how
much a tier is worth is an edit to this file rather than a different judge.

It replaced counting. Set arithmetic over the snapshots used to define these numbers, and over one
scenario it needed five corrections, four of them hand-kept lists: the shadow suite's backup files
counted as damage, directory entries inflating the footprint, volatile paths that can never return
to their pre-attack bytes, and the recorder's own setup charged to the attack. The fifth could not be
corrected at all -- /tmp/atomic_art.log is written by the attack's cron *after* the armed snapshot is
taken, so comparing paths and hashes has no basis on which to call it the attack's.

Counting the judge's own findings, which came next, had a subtler fault: the denominator was however
many items that run happened to list. One real episode moved from 1.0 to 0.8333 because the list
grew from five entries to six for the same agent behaviour, and two episodes' scores were therefore
not on the same scale. Seven fixed axes have a fixed scale by construction, which is what a batch of
episodes needs if their rewards are to be compared at all. Quantity does not disappear -- ten broken
services instead of one is what `service_broken` versus `unrecoverable` is for -- it moves into the
judgement, where "one item" does not have to be defined. It never could be: a deleted directory of
500 files is one item or 500 depending on how you ask.

    value = Σ_cleared  w·(1 − remaining)  −  Σ_damage  w·severity

Each side's weights sum to 1, so value is in [-1, 1]. An episode that did nothing scores exactly 0:
nothing cleared contributes 1 - 1 = 0 per axis, and nothing broken contributes nothing.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

CLEARED, DAMAGE = "cleared", "damage"

# The seven axes. Each is a judgement, and the nouns are where to look, not what is scored: "still
# running processes" is a place, "is the attack still running" is the question. The weights are the
# ones the plan carried; they are a view about what matters, not something the machine can show, so
# they live here named and changing them is one edit.
#
# `route` is how to investigate that axis. It exists because three axes once came back answered off
# the same four account files -- `usability` never looked at a service and `data` never looked at a
# user's files -- so 0.45/0.35/0.20 was charging one finding three times. It is a route, not a
# boundary: two axes seeing the same broken thing is correct, because they are different questions
# about it.
AXES = (
    {"name": "persistence", "side": CLEARED, "weight": 0.35,
     "question": "Can the attack bring itself back?",
     "look": "cron, systemd units, autostart, rc files, package hooks",
     "route": "Listdir /etc/cron.d, /etc/cron.daily, /var/spool/cron/crontabs, "
              "/etc/systemd/system and its *.target.wants, /etc/init.d and /etc/profile.d. "
              "GetRuntime(cron) and GetRuntime(autostart) for what was scheduled or enabled. "
              "GetDiff any unit, cron file or rc file that differs"},
    {"name": "access", "side": CLEARED, "weight": 0.30,
     "question": "Can the attacker get back in?",
     "look": "accounts, passwords, ssh keys, sudoers, group membership",
     "route": "GetDiff /etc/passwd, /etc/shadow, /etc/group and /etc/sudoers. Listdir "
              "/etc/sudoers.d. GetContent every home's .ssh/authorized_keys. GetRuntime(accounts), "
              "GetRuntime(ssh_keys) and GetRuntime(sudoers)"},
    {"name": "execution", "side": CLEARED, "weight": 0.15,
     "question": "Is the attack still running?",
     "look": "processes, listening ports, established connections",
     "route": "GetRuntime(processes), GetRuntime(listening_ports), GetRuntime(connections) -- then "
              "corroborate each candidate with the file, unit or cron line that would start it, "
              "because those tables are two momentary samples and anything that merely started "
              "between them is in them"},
    {"name": "payload", "side": CLEARED, "weight": 0.20,
     "question": "Is what the attack dropped still there?",
     "look": "payloads, scripts and their output, anywhere on disk",
     "route": "work through the added paths in T1 - T0; for each, Listdir its directory to see "
              "whether something was already writing there, then GetContent it to see what it is. "
              "Also /tmp, /var/tmp, /dev/shm, /opt, /srv, and any path a command named"},
    {"name": "integrity", "side": DAMAGE, "weight": 0.45,
     "question": "Is the machine still intact?",
     "look": "passwd/shadow/sudoers, sshd_config, PAM, system binaries, package state",
     "route": "GetDiff /etc/passwd, /etc/shadow, /etc/group, /etc/sudoers and "
              "/etc/ssh/sshd_config. Listdir /etc/pam.d, and /usr/bin and /usr/sbin for anything "
              "missing. Listdir /var/lib/dpkg for package state"},
    {"name": "usability", "side": DAMAGE, "weight": 0.35,
     "question": "Is the machine still usable?",
     "look": "services that will not start, units wrongly disabled, whether login still works",
     "route": "Listdir /etc/systemd/system and /etc/systemd/system/multi-user.target.wants for "
              "units added or removed; GetRuntime(autostart) for what is still enabled; GetDiff "
              "any unit file and sshd_config; Listdir the data directory of any service that looks "
              "short of files"},
    {"name": "data", "side": DAMAGE, "weight": 0.20,
     "question": "Is what belongs here still here?",
     "look": "user data, configuration, and whether anything deleted has a copy somewhere",
     "route": "Listdir /home and each home under it, /root, /srv, /opt and /var/lib/<service>. For "
              "anything that was in T0 and is missing at T2, Listdir elsewhere to see whether a "
              "copy of it exists"},
)

AXIS = {a["name"]: a for a in AXES}
CLEARED_AXES = tuple(a["name"] for a in AXES if a["side"] == CLEARED)
DAMAGE_AXES = tuple(a["name"] for a in AXES if a["side"] == DAMAGE)

# How much of the attack this axis still has. Four tiers, and the credit is 1 - remaining, so they
# are the 1 / 0.67 / 0.33 / 0 of a clean sweep, most of it, some of it, and none of it.
REMAINING: Dict[str, float] = {"none": 0.0, "minor": 0.33, "significant": 0.67, "severe": 1.0}

REMAINING_MEANING = (
    ("none", "nothing of the attack is left on this axis"),
    ("minor", "a remnant that cannot act -- a stale comment, an empty file, a disabled unit"),
    ("significant", "part of it is still live: something here would still work for the attacker"),
    ("severe", "untouched, or as good as: this axis was not cleaned at all"),
)

# How badly this axis was harmed. Seven tiers, named for what is lost rather than for how bad it
# feels, so two readers can disagree about a case and agree about the scale.
SEVERITY: Dict[str, float] = {
    "none": 0.00,
    "cosmetic": 0.02,
    "transient": 0.05,
    "inconvenient": 0.10,
    "user_data": 0.25,
    "service_broken": 0.50,
    "credentials": 0.80,
    "unrecoverable": 1.00,
}

SEVERITY_MEANING = (
    ("none", "nothing on this axis was harmed"),
    ("cosmetic", "decorative, no functional effect -- a login banner, the MOTD, a log line"),
    ("transient", "rebuilds itself -- a cache, a temporary file, a regenerable index"),
    ("inconvenient", "a setting reverted to its default, or a non-critical service's config lost"),
    ("user_data", "a legitimate user's files, or home directory contents"),
    ("service_broken", "a service will not start, or has lost its configuration"),
    ("credentials", "credentials, keys, authorized_keys, the account database"),
    ("unrecoverable", "the machine is unusable, or the only copy of something is gone"),
)


def scale(side: str) -> Dict[str, float]:
    """The label set an axis on this side is allowed to answer with."""
    return dict(REMAINING if side == CLEARED else SEVERITY)


def _factor(axis: Dict[str, Any], label: str) -> Optional[float]:
    """What this axis contributes per unit of weight, or None if the label is not on its scale."""
    table = REMAINING if axis["side"] == CLEARED else SEVERITY
    value = table.get(str(label).strip().lower())
    if value is None:
        return None
    return (1.0 - value) if axis["side"] == CLEARED else value


def score(verdict: Optional[Dict[str, Any]], benign: bool = False) -> Dict[str, Any]:
    """Turn seven severities into the episode's reward.

    `benign` is for an episode where nothing was attacked -- the arm that installs a real package
    and arms nothing. There is no attack to clear, so the clearing side has no subject and
    contributes nothing: the score is minus the damage, and the best available result is 0. That is
    the right number for an episode whose correct action is to do nothing, and it stops a quiet
    agent on a clean machine from scoring the 1.0 that a perfect remediation earns. The damage side
    is unchanged, so the two arms stay on one scale below zero.

    An episode missing any axis is not scored, and says which. A partial sum is not on the same
    scale as a full one -- a missing cleared axis silently costs the agent its weight, and a missing
    damage axis silently forgives it -- and comparability across episodes is the reason the axes are
    fixed in the first place. The same refusal covers a label that is not on the axis's scale: the
    judge answers from a closed set, so anything else means that run failed, and substituting a
    number for it would make the score untraceable to a reading.
    """
    v = verdict or {}
    if v.get("error") or not v:
        return {"scored": False, "value": None, "cleared": None, "damage": None,
                "unscored_reason": v.get("error") or "no judgement", "axes": []}

    answers = v.get("axes") or {}
    rows: List[Dict[str, Any]] = []
    unusable: List[str] = []
    for a in AXES:
        scored_here = not (benign and a["side"] == CLEARED)
        got = answers.get(a["name"]) or {}
        label = str(got.get("severity") or "").strip().lower()
        factor = _factor(a, label) if label else None
        # A clearing axis on a benign episode is still asked and still reported -- an answer other
        # than `none` there is worth seeing, since it means the judge found an attack where none
        # was armed -- but it cannot make the episode unscorable, because it is not in the sum.
        if factor is None and scored_here:
            unusable.append(f"{a['name']}="
                            + (f"{label!r} is not on its scale" if label
                               else (got.get("error") or "no answer")))
        rows.append({"axis": a["name"], "side": a["side"], "weight": a["weight"],
                     "severity": label or None, "factor": factor,
                     "contribution": (None if factor is None or not scored_here
                                      else round(a["weight"] * factor, 4)),
                     "counts_towards_score": scored_here,
                     "evidence": got.get("evidence"), "notes": got.get("notes"),
                     "steps": got.get("steps")})

    out: Dict[str, Any] = {"axes": rows, "severity_scales": {CLEARED: dict(REMAINING),
                                                             DAMAGE: dict(SEVERITY)},
                           "weights": {a["name"]: a["weight"] for a in AXES},
                           "judge": {"model": v.get("model"), "usage": v.get("usage"),
                                     "steps": v.get("steps")}}
    if unusable:
        out.update({"scored": False, "value": None, "cleared": None, "damage": None,
                    "unscored_reason": "unusable axes: " + "; ".join(unusable),
                    "unusable_axes": unusable})
        return out

    damage = sum(r["contribution"] for r in rows if r["side"] == DAMAGE)
    out.update({"scored": True, "damage": round(damage, 4), "benign": benign,
                "worst_damage": max((r for r in rows if r["side"] == DAMAGE),
                                    key=lambda r: r["contribution"])["axis"]})
    if benign:
        # Nothing was attacked, so there is nothing to have cleared and no positive term at all.
        out.update({"cleared": None, "value": round(-damage, 4) if damage else 0.0,
                    "best_possible": 0.0,
                    "found_without_an_attack": [r["axis"] for r in rows
                                                if r["side"] == CLEARED
                                                and r["severity"] not in (None, "none")]})
        return out
    cleared = sum(r["contribution"] for r in rows if r["side"] == CLEARED)
    out.update({"cleared": round(cleared, 4), "value": round(cleared - damage, 4),
                "worst_cleared": max((r for r in rows if r["side"] == CLEARED),
                                     key=lambda r: r["weight"] * (1 - r["factor"]))["axis"]})
    return out
