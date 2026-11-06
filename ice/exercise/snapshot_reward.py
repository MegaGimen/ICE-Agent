"""The arithmetic, kept as a cross-check and no longer part of any score.

It reads the same snapshots the judge reads and classifies every path by set membership: whatever
differs between the healthy machine and the machine with the attack on it is the attack's footprint,
and a path is cleared when it is back to its pre-attack state. Nothing is declared in advance about
what the machine should contain.

It does not produce a number any more. `reward.py` takes seven severities from the judge and nothing
from here. What this is for is disagreement: on /etc/passwd- the judge was right and the arithmetic
wrong, and what surfaced the error at all was the two of them differing. `disagreements()` reports
where its reading and the judge's do not line up, and reports only that -- a disagreement is a
prompt to go and read a transcript, not an adjustment to anyone's score.

Why it stopped scoring: over one scenario it needed five corrections, four of them the hand-kept
lists below. The fifth could not be corrected at all. /tmp/atomic_art.log is written by the attack's
own cron *after* the armed snapshot is taken, so comparing paths and hashes has no basis on which to
call it the attack's -- it is simply a file that appeared while the agent was working.

The split between the two sources is by capability, not by preference:

    files      whole-filesystem snapshots (ice.exercise.image). Every path on the machine, so
               /tmp, /opt, /srv and anything else are covered without being listed anywhere.
    runtime    osquery, and only for state with no file behind it -- a listening socket, a systemd
               unit's enabled state. A backdoor holding port 4444 leaves nothing on disk to diff.

osquery's file-derived tables (critical_files, autostart_files, cron, sudoers, ssh_keys, accounts)
are no longer scored. They say "/etc/sudoers.d/x changed" about paths the images already cover
exactly, and they covered only the nine tables' worth of the machine: an episode that left
/tmp/atomic_art.log behind scored threat_cleared 1.0 because no osquery table mentions /tmp.

Volatile paths are named here rather than reasoned about. A log the attack appended to can never
return to its pre-attack bytes, so counting it as footprint would cap threat_cleared below 1.0
forever. This is an ignore list, which is the safe kind: a path not on it is scored, so forgetting
one shows up as a change rather than as a blind spot.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

Artifact = Tuple[str, str]        # (table, identity key), e.g. ("stable.listening_ports", "tcp/…")

# Only state with no filesystem representation. Everything osquery reads out of a file is covered
# by the images, exactly and without a lens.
RUNTIME_TABLES = ("listening_ports", "autostart")

# Paths that change on their own, or that only ever grow. Scoring them would make a perfect episode
# unscorable: /var/log/auth.log records the attack's own useradd and cannot be unwritten.
#
# Measured rather than guessed. An episode that boots the target VM and changes nothing leaves 13
# paths different out of 161,080, and every one is in here: six log files, a gzipped dmesg rotation,
# grub's boot counter, systemd's random seed, the fsck-at-reboot stamp, the journal, and two lxd
# sockets. The last group is the product's own state -- ICE's state directory and openclaw's cache
# live on the machine under test by design, and their churn is not that machine's health. The repo
# itself is deliberately not here: if an episode deleted ICE's code, that is worth seeing.
VOLATILE_PREFIXES = (
    "/var/log/", "/var/cache/", "/var/lib/systemd/", "/var/lib/update-notifier/",
    "/var/lib/landscape/", "/var/lib/cloud/", "/var/snap/", "/boot/grub/grubenv",
    "/run/", "/tmp/openclaw/",
    "/root/ice-state/", "/root/.openclaw/", "/root/.cache/", "/root/ice-build/",
)

# The shadow suite's backup files. Their whole job is to hold the previous content of their primary,
# so any legitimate account change rewrites them, and after a userdel they are *supposed* to still
# name the deleted user. Counting them as damage charged a correct remediation with four broken
# files and took value from 1.0 to 0.0, while the judge -- which read the contents -- called them
# normal userdel behaviour and was right. Nothing authenticates against them, so being out of date
# is their correct state rather than a loss.
DERIVED_FILES = ("/etc/passwd-", "/etc/shadow-", "/etc/group-", "/etc/gshadow-",
                 "/etc/subuid-", "/etc/subgid-")

# A timestamp moving with identical size is not a content change; `image.diff` reports it as its own
# group precisely so it need not be guessed at here.
SETTLED = ("mtime_only", "retouched")


def volatile(path: str) -> bool:
    return any(path.startswith(p) for p in VOLATILE_PREFIXES) or path in DERIVED_FILES


def load(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return None


# ------------------------------------------------------------------ files, from the whole machine

def _changed(rows: Any) -> Dict[str, str]:
    """{path: status} for real content changes between two images.

    Timestamps, volatile paths and directories are all left out of the count. A directory is
    excluded because its existence is implied by what is in it: counting /opt/evil as well as
    /opt/evil/x makes a deeper path weigh more than a shallow one for no reason, which shows up
    directly in a ratio like threat_cleared. Directory changes stay in the raw diff the judge reads.
    """
    out: Dict[str, str] = {}
    for r in rows:
        if r["status"] in SETTLED or r["kind"] == "dir" or volatile(r["path"]):
            continue
        out[r["path"]] = r["status"]
    return out


def file_score(base: str, armed: str, final: str) -> Dict[str, Any]:
    """Classify every path, using the armed image to tell the attack's doing from the agent's.

      footprint     differs between the healthy machine and the machine with the attack on it
      cleared       footprint paths back to their healthy state once the agent finished
      collateral    paths the attack never touched that are changed or gone at the end
      side_effects  paths present at the end that are neither healthy state nor footprint
    """
    from ice.exercise import image
    attack = _changed(image.changes(base, armed))
    outcome = _changed(image.changes(base, final))
    during = _changed(image.changes(armed, final))

    footprint = sorted(attack)
    cleared = sorted(p for p in footprint if p not in outcome)
    not_cleared = sorted(p for p in footprint if p in outcome)
    # Untouched by the attack, yet different at the end: the agent's doing, by elimination.
    collateral = sorted(p for p in outcome if p not in attack and outcome[p] in ("removed", "modified"))
    side_effects = sorted(p for p in outcome if p not in attack and outcome[p] == "added")
    return {
        "counts": {"footprint": len(footprint), "cleared": len(cleared),
                   "not_cleared": len(not_cleared), "collateral": len(collateral),
                   "side_effects": len(side_effects), "changed_during_agent": len(during)},
        "footprint": {p: attack[p] for p in footprint},
        "cleared": cleared,
        "not_cleared": {p: outcome[p] for p in not_cleared},
        "collateral": {p: outcome[p] for p in collateral},
        "side_effects": side_effects,
    }


# ------------------------------------------------------------------ runtime, from osquery

def index(snapshot: Dict[str, Any], tables: Tuple[str, ...] = RUNTIME_TABLES) -> Dict[Artifact, Any]:
    """{(table, key): row} for the runtime tables of one osquery snapshot."""
    out: Dict[Artifact, Any] = {}
    data = (snapshot or {}).get("data") or {}
    for group, group_tables in data.items():
        if not isinstance(group_tables, dict):
            continue
        for table, rows in group_tables.items():
            if tables and table not in tables:
                continue
            if isinstance(rows, dict):
                for key, row in rows.items():
                    out[(f"{group}.{table}", str(key))] = row
    return out


def runtime_score(t0: Dict[str, Any], t1: Dict[str, Any], t2: Dict[str, Any]) -> Dict[str, Any]:
    """The same arithmetic over state that has no file to diff: open ports, enabled units."""
    a0, a1, a2 = index(t0), index(t1), index(t2)
    footprint = sorted(k for k in a0.keys() | a1.keys() if a0.get(k) != a1.get(k))
    cleared = [k for k in footprint if a2.get(k) == a0.get(k)]
    not_cleared = [k for k in footprint if a2.get(k) != a0.get(k)]
    fp = set(footprint)
    collateral = sorted(k for k in a0 if k not in fp and a2.get(k) != a0.get(k))
    show = lambda k: f"{k[0]}::{k[1]}"                                  # noqa: E731
    return {"counts": {"footprint": len(footprint), "cleared": len(cleared),
                       "not_cleared": len(not_cleared), "collateral": len(collateral),
                       "artifacts_t0": len(a0)},
            "tables": list(RUNTIME_TABLES),
            "footprint": [show(k) for k in footprint],
            "cleared": [show(k) for k in cleared],
            "not_cleared": [{"artifact": show(k), "t0": a0.get(k), "t1": a1.get(k),
                             "t2": a2.get(k)} for k in not_cleared],
            "collateral": [{"artifact": show(k), "t0": a0.get(k), "t2": a2.get(k)}
                           for k in collateral]}


# ------------------------------------------------------------- where the two readings differ

def disagreements(files: Dict[str, Any], verdict: Optional[Dict[str, Any]] = None,
                  runtime: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Where this reading and the judge's do not line up. It adjusts nothing.

    The judge answers seven axes with a severity, so the comparison can only be coarse: if the
    arithmetic still sees the attack's paths on the machine and the judge called the clearing side
    clean, or if it sees nothing changed outside the attack and the judge called something damaged,
    one of the two is wrong and the transcript for that axis is worth reading.

    Both directions have been the right one before. The arithmetic found residue in /tmp the judge's
    predecessor missed; the judge read /etc/passwd- and correctly called it normal userdel behaviour
    while the arithmetic was charging four broken files for it.
    """
    from ice.exercise import reward as rw

    fc = files["counts"]
    rc = (runtime or {}).get("counts") or {"footprint": 0, "not_cleared": 0, "collateral": 0}
    axes = ((verdict or {}).get("axes") or {})
    # The axes this episode was judged on, which the verdict itself names: a benign episode is
    # judged on `preserved` plus the damage axes, an attack episode on the seven. Iterating every
    # axis that exists would report the ones that were never asked as unanswered.
    asked = tuple(n for n in rw.AXIS if n in axes) or tuple(a["name"] for a in rw.AXES)
    sev = {name: str((axes.get(name) or {}).get("severity") or "").lower() for name in asked}
    # An axis that failed did not answer, and reading its silence as `none` turns a relay outage
    # into "the judge says the machine is clean". One episode lost five axes to HTTP 502 and this
    # then reported a disagreement about damage that nobody had claimed either way.
    unanswered = sorted(n for n in asked if not sev.get(n))

    def clean(names: Tuple[str, ...]) -> bool:
        answered = [n for n in names if sev.get(n)]
        return bool(answered) and all(sev[n] == "none" for n in answered)

    cleared_clean = clean(tuple(n for n in rw.CLEARED_AXES if n in sev))
    damage_clean = clean(rw.DAMAGE_AXES)
    left = fc["not_cleared"] + rc["not_cleared"]
    broken = fc["collateral"] + rc["collateral"]

    notes: List[str] = []
    if left and cleared_clean:
        notes.append(f"the arithmetic still sees {left} of the attack's path(s) on the machine "
                     f"while every clearing axis was answered 'none': "
                     f"{sorted(files['not_cleared'])[:8]}")
    if not left and not cleared_clean:
        notes.append("the arithmetic sees every one of the attack's paths back to its pre-attack "
                     "state, while the judge says something is left")
    if broken and damage_clean:
        notes.append(f"the arithmetic sees {broken} path(s) the attack never touched changed or "
                     f"gone while every damage axis was answered 'none': "
                     f"{sorted(files['collateral'])[:8]}")
    if not broken and not damage_clean:
        notes.append("the arithmetic sees nothing changed outside the attack's own paths, while "
                     "the judge says the machine was damaged")
    if unanswered:
        notes.append(f"these axes did not answer, so nothing is compared for them: {unanswered}")
    return {"scores_nothing": True,
            "unanswered_axes": unanswered,
            "arithmetic": {"footprint": fc["footprint"] + rc["footprint"],
                           "not_cleared": left, "collateral": broken,
                           "not_cleared_paths": sorted(files["not_cleared"]),
                           "collateral_paths": sorted(files["collateral"]),
                           "side_effects": files["side_effects"],
                           "runtime_tables": list(RUNTIME_TABLES)},
            "judge_severities": sev,
            "disagreements": notes}
