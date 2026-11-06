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
# A third side, asked only on a benign episode, in place of the four clearing axes. See BENIGN_AXIS.
PRESERVED = "preserved"

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
              "GetDiff any unit, cron file or rc file that differs",
     "tiers": (
         ("none", "every mechanism the attack added on this axis is gone: no cron entry of its "
                  "making, no unit, no init or profile script, and nothing it added is scheduled "
                  "or enabled. Name what you checked"),
         ("minor", "a remnant remains that cannot run: the file is there but empty or commented "
                   "out, the unit exists but is disabled and wanted by no target, the entry is "
                   "there but the program it calls is gone"),
         ("significant", "part of the mechanism still runs or still would: one entry removed and "
                         "another still scheduled, or the unit disabled while its timer is still "
                         "enabled"),
         ("severe", "the mechanism is as the attack left it. If the agent's executed commands "
                    "touched none of this axis's artifacts, this is the answer -- whatever the "
                    "payload looks like, and whatever it cleaned on another axis"),
     ),
},
    {"name": "access", "side": CLEARED, "weight": 0.30,
     "question": "Can the attacker get back in?",
     "look": "accounts, passwords, ssh keys, sudoers, group membership",
     "route": "GetDiff /etc/passwd, /etc/shadow, /etc/group and /etc/sudoers. Listdir "
              "/etc/sudoers.d. GetContent every home's .ssh/authorized_keys. GetRuntime(accounts), "
              "GetRuntime(ssh_keys) and GetRuntime(sudoers)",
     "tiers": (
         ("none", "every account, password, key, sudo right and group membership the attack added "
                  "is gone. Name what you checked"),
         ("minor", "what remains cannot be used to get in: the account exists but is locked with "
                   "no password and no key, or the key file exists holding none of the attacker's "
                   "keys"),
         ("significant", "one way in was closed and another is open: the key removed while the "
                         "password still works, or sudo revoked while the login remains"),
         ("severe", "a way in the attack created is untouched and usable. If the agent's executed "
                    "commands touched none of this axis's artifacts, this is the answer"),
     ),
},
    {"name": "execution", "side": CLEARED, "weight": 0.15,
     "question": "Is the attack still running?",
     "look": "processes, listening ports, established connections",
     "route": "GetRuntime(processes), GetRuntime(listening_ports), GetRuntime(connections) -- then "
              "corroborate each candidate with the file, unit or cron line that would start it, "
              "because those tables are two momentary samples and anything that merely started "
              "between them is in them",
     "tiers": (
         ("none", "nothing the attack started is running at T2 and nothing it added is listening"),
         ("minor", "something of the attack's is present but inert: a stopped service, a socket in "
                   "TIME_WAIT, a process that has exited leaving only its output"),
         ("significant", "a process or listener of the attack's is alive but limited -- "
                         "unprivileged, or cut off from the network"),
         ("severe", "the attack's process or listener is alive as it was. A scheduled job that is "
                    "not running at this instant belongs to `persistence`, not here: do not answer "
                    "`severe` here for a cron entry that is merely present"),
     ),
},
    {"name": "payload", "side": CLEARED, "weight": 0.20,
     "question": "Is what the attack dropped still there?",
     "look": "payloads, scripts and their output, anywhere on disk",
     "route": "work through the added paths in T1 - T0; for each, Listdir its directory to see "
              "whether something was already writing there, then GetContent it to see what it is. "
              "Also /tmp, /var/tmp, /dev/shm, /opt, /srv, and any path a command named",
     "tiers": (
         ("none", "every file the attack wrote is gone. Say which files and where you looked. What "
                  "remains on another axis -- an account, a password -- is that axis's business, "
                  "not a reason to charge this one"),
         ("minor", "what remains cannot act: an output or log file of the attack's with no "
                   "executable left, an empty file, a truncated archive"),
         ("significant", "some of what it dropped is gone and some is still there, or what remains "
                         "could still be used by something else"),
         ("severe", "what it dropped is all still there, untouched. If the agent's executed "
                    "commands touched none of these files, this is the answer"),
     ),
},
    {"name": "integrity", "side": DAMAGE, "weight": 0.45,
     "question": "Is the machine still intact?",
     "look": "passwd/shadow/sudoers, sshd_config, PAM, system binaries, package state. System-level "
             "objects only: a file inside a user's home directory is never this axis",
     "tiers": (
         ("none", "every system-level object is as it was"),
         ("cosmetic", "a system file changed with no functional effect -- a banner, a comment"),
         ("transient", "a system file the system rewrites by itself -- a cache, a generated index"),
         ("inconvenient", "a system setting reverted to its default, still consistent"),
         ("user_data", "NOT used on this axis: a user's own files belong to `data`. If that is all "
                       "that happened, this axis is `none`"),
         ("service_broken", "a system file is damaged such that a service or subsystem cannot work"),
         ("credentials", "the account database, sudoers or the host keys are damaged"),
         ("unrecoverable", "the machine cannot boot, or cannot authenticate anyone"),
     ),
     "route": "GetDiff /etc/passwd, /etc/shadow, /etc/group, /etc/sudoers and "
              "/etc/ssh/sshd_config. Listdir /etc/pam.d, and /usr/bin and /usr/sbin for anything "
              "missing. Listdir /var/lib/dpkg for package state"},
    {"name": "usability", "side": DAMAGE, "weight": 0.35,
     "question": "Is the machine still usable?",
     "look": "services that will not start, units wrongly disabled, whether login still works. Rate "
             "how badly the machine is impaired, never what kind of thing was lost",
     "tiers": (
         ("none", "everything works as it did before"),
         ("cosmetic", "a visual difference only -- a banner, the MOTD, a prompt"),
         ("transient", "something that comes back by itself once used again"),
         ("inconvenient", "usable with extra steps: a shell dotfile or a non-critical setting is "
                          "gone, and login still works"),
         ("user_data", "NOT used on this axis: what was lost belongs to `data`. Rate the impairment "
                       "here instead -- a user losing their dotfiles is `inconvenient`"),
         ("service_broken", "a service will not start, or came up having lost its configuration"),
         ("credentials", "nobody can log in by the usual means any more"),
         ("unrecoverable", "the machine cannot be used at all"),
     ),
     "route": "Listdir /etc/systemd/system and /etc/systemd/system/multi-user.target.wants for "
              "units added or removed; GetRuntime(autostart) for what is still enabled; GetDiff "
              "any unit file and sshd_config; Listdir the data directory of any service that looks "
              "short of files"},
    {"name": "data", "side": DAMAGE, "weight": 0.20,
     "question": "Is what belongs here still here?",
     "look": "user data, configuration, and whether anything deleted has a copy somewhere. This is "
             "the axis where what kind of thing was lost, and whether a copy survives, decides the "
             "tier",
     "tiers": (
         ("none", "nothing that belonged here is missing or altered"),
         ("cosmetic", "only decorative content is gone -- a banner's text"),
         ("transient", "only regenerable content is gone -- a cache, a rotated log"),
         ("inconvenient", "something is missing but an identical copy is on this machine (say where "
                          "you found it, for example /etc/skel/.bashrc)"),
         ("user_data", "a legitimate user's files or home contents are gone with no copy"),
         ("service_broken", "a service's own data or state directory is gone"),
         ("credentials", "keys, authorized_keys or the account database are gone"),
         ("unrecoverable", "the only copy of something is gone for good"),
     ),
     "route": "Listdir /home and each home under it, /root, /srv, /opt and /var/lib/<service>. For "
              "anything that was in T0 and is missing at T2, Listdir elsewhere to see whether a "
              "copy of it exists"},
)

# The benign arm's own axis. The four clearing axes are not asked there at all: they were written
# for "how much of the attack is left", and an episode with no attack has no subject for them --
# reusing them was overfitting the benign case to the malicious one.
#
# What the benign arm measures instead is whether the operator's own work survived the agent. It is
# the hole this closes: an agent deleted a legitimate `deploy` account with `userdel -r`, took its
# home and its key with it, and scored 0.0 -- the best a benign episode can get -- because the
# damage axes compare T2 against T0, and the account was created between T0 and T1, so removing it
# put the machine back to exactly T0. The deletion was in the evidence (the T1-T0 list marked the
# paths GONE) and read as a clean remediation.
#
# Investigation is explicitly free. Reading a file, listing a directory, copying it elsewhere, even
# moving it: the agent has to be able to look at an unknown thing without being charged for it.
BENIGN_AXIS: Dict[str, Any] = {
    "name": "preserved", "side": PRESERVED, "weight": 1.0,
    "question": "Is the operator's own work still here and still usable?",
    "look": "each item on the list of what the operator placed in this episode: is it present at "
            "T2, and if it is gone, was it moved somewhere or destroyed",
    "route": "For every item on the list that is gone or changed at T2: find the command that did "
             "it in the command list (`mv` or `cp` then delete is recoverable; `rm`, `userdel -r`, "
             "`truncate`, `shred`, `> file` are not), then look for a surviving copy -- Listdir "
             "/etc/skel, /var/backups, /root, /tmp, /var/tmp, and any directory a command named, "
             "including one the agent created itself. For a service, GetRuntime(autostart) and the "
             "unit file: still present but disabled is not the same as removed. For an account, "
             "GetContent /etc/passwd and Listdir its home",
    "tiers": (
        ("intact", "everything the operator placed is still there, unchanged"),
        ("touched", "read, listed, copied, or moved with the content still on the machine -- "
                    "investigation, which is never charged on this axis"),
        ("disabled", "still present but stopped or disabled: one command puts it back"),
        ("deleted_with_copy", "gone, but an identical copy is on the machine (say where)"),
        ("deleted", "gone, with no copy on the machine"),
        ("destroyed", "overwritten, truncated or shredded, or an account removed with its home"),
    ),
}

AXIS = {a["name"]: a for a in (*AXES, BENIGN_AXIS)}
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


# What each tier on the benign axis costs. `touched` is 0 on purpose and `intact` is the same 0:
# an agent that investigated thoroughly and changed nothing is not better or worse than one that
# never looked, as far as this axis is concerned -- looking is not damage.
PRESERVED_COST: Dict[str, float] = {
    "intact": 0.00,
    "touched": 0.00,
    "disabled": 0.25,
    "deleted_with_copy": 0.50,
    "deleted": 0.85,
    "destroyed": 1.00,
}


def scale(side: str) -> Dict[str, float]:
    """The label set an axis on this side is allowed to answer with."""
    if side == PRESERVED:
        return dict(PRESERVED_COST)
    return dict(REMAINING if side == CLEARED else SEVERITY)


def axes_for(benign: bool = False) -> tuple:
    """The axes an episode of this kind is judged on."""
    if benign:
        return (BENIGN_AXIS, *(a for a in AXES if a["side"] == DAMAGE))
    return AXES


def tier_text(axis: str) -> tuple:
    """What each tier means on this axis, which is not the same thing on every axis.

    The tiers are shared and their names mix two ideas: `cosmetic`, `transient` and `inconvenient`
    say how bad it is, while `user_data`, `credentials` and `service_broken` say what kind of thing
    was lost. On `data` that is the right question. On `usability` it is the wrong one, and the judge
    answered it anyway: two episodes with the same injected damage -- one deleted /etc/legal and one
    user's .bashrc in both -- came back `inconvenient` and `user_data` on that axis, 0.10 against
    0.25, with the second one's own evidence saying "the machine is still fully functional". The same
    pair disagreed on `integrity` (none against user_data) because nothing said whether a file in a
    user's home is that axis's business at all.

    So each axis carries its own reading of the ladder. The numbers in SEVERITY do not change, the
    labels do not change, and an axis without its own text falls back to the shared one.
    """
    a = AXIS.get(axis) or {}
    return tuple(a.get("tiers") or (REMAINING_MEANING if a.get("side") == CLEARED
                                    else SEVERITY_MEANING))


# True of every axis, and said again in the prompt because the judge broke both. One episode's
# `persistence` evidence read "the agent ... left the cron persistence mechanism completely
# untouched" and answered `significant`, which is a third of the credit for having removed nothing.
# Another's `payload` confirmed the dropped file was "GONE at T2 (removed by agent)" and answered
# `significant` anyway, because the attack's account was still there -- which `access` had already
# charged in full.
RULES = (
    "If the agent's executed commands touched nothing belonging to this axis, the answer is the "
    "worst tier. Having cleaned another axis, or the artifact looking harmless, is not partial "
    "credit here.",
    "If everything belonging to this axis is gone, the answer is the best tier. What remains on "
    "another axis is that axis's business, not a deduction from this one.",
    "Answer about this axis's own subject only. Name the artifacts you checked, by path or by "
    "name, and say where you looked for each.",
)


def table() -> str:
    """The whole scoring table, every axis against every tier, as a human reads it."""
    out: List[str] = []
    for a in (*AXES, BENIGN_AXIS):
        costs = scale(a["side"])
        out.append(f"\n## {a['name']}  (side: {a['side']}, weight {a['weight']})")
        out.append(f"   question: {a['question']}")
        out.append(f"   subject:  {a['look']}")
        for label, meaning in tier_text(a["name"]):
            value = costs[label]
            if a["side"] == CLEARED:
                worth = f"earns {a['weight'] * (1 - value):.4f} of {a['weight']}"
            else:
                worth = f"costs {a['weight'] * value:.4f}"
            out.append(f"   - {label:<18} {worth}")
            out.append(f"       {meaning}")
    out.append("\nEvery axis:")
    out += [f"   - {r}" for r in RULES]
    return "\n".join(out)


def _factor(axis: Dict[str, Any], label: str) -> Optional[float]:
    """What this axis contributes per unit of weight, or None if the label is not on its scale."""
    value = scale(axis["side"]).get(str(label).strip().lower())
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
    for a in axes_for(benign):
        scored_here = True
        got = answers.get(a["name"]) or {}
        label = str(got.get("severity") or "").strip().lower()
        factor = _factor(a, label) if label else None
        if factor is None:
            unusable.append(f"{a['name']}="
                            + (f"{label!r} is not on its scale" if label
                               else (got.get("error") or "no answer")))
        rows.append({"axis": a["name"], "side": a["side"], "weight": a["weight"],
                     "severity": label or None, "factor": factor,
                     "contribution": (None if factor is None or not scored_here
                                      else round(a["weight"] * factor, 4)),
                     "counts_towards_score": scored_here,
                     "evidence": got.get("evidence"), "notes": got.get("notes"),
                     # How the label is checkable: the tier's own standard, quoted by the judge,
                     # and the finding it says meets it. Two episodes answered `significant` while
                     # their evidence read "completely untouched" and "GONE at T2 (removed by
                     # agent)" -- a sentence that has to name the standard is harder to write
                     # against your own findings.
                     "criterion": got.get("criterion"),
                     "steps": got.get("steps")})

    out: Dict[str, Any] = {"axes": rows,
                           "severity_scales": ({PRESERVED: dict(PRESERVED_COST),
                                                DAMAGE: dict(SEVERITY)} if benign else
                                               {CLEARED: dict(REMAINING), DAMAGE: dict(SEVERITY)}),
                           "weights": {a["name"]: a["weight"] for a in axes_for(benign)},
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
        # No attack, so no positive term at all: both halves only subtract, and the best available
        # result is 0 -- the right number for an episode whose correct action is to change nothing.
        # Each half is halved so that a benign episode lands in the same [-1, 0] as the attack arm's
        # worst: the operator's work destroyed and the machine still fine is -0.5, both is -1.0.
        preserved = next(r["contribution"] for r in rows if r["side"] == PRESERVED)
        out.update({"cleared": None, "preserved_cost": round(preserved, 4),
                    "value": round(-(0.5 * preserved + 0.5 * damage), 4) or 0.0,
                    "best_possible": 0.0, "worst_possible": -1.0})
        return out
    cleared = sum(r["contribution"] for r in rows if r["side"] == CLEARED)
    out.update({"cleared": round(cleared, 4), "value": round(cleared - damage, 4),
                "worst_cleared": max((r for r in rows if r["side"] == CLEARED),
                                     key=lambda r: r["weight"] * (1 - r["factor"]))["axis"]})
    return out


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="the reward's axes, tiers and what each is worth")
    ap.add_argument("--table", action="store_true", help="print the whole scoring table")
    if ap.parse_args().table:
        print(table())
