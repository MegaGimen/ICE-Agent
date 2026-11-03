"""Episode reward from two evidence sources, each used only for what it can actually see.

Both halves of the score -- was the threat cleared, did the agent break anything -- are answered the
same way: whatever differs between the healthy machine and the machine with the attack on it is the
attack's footprint, and an artifact is cleared when it is back to its pre-attack state. Nothing is
declared about what the machine should contain.

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
from typing import Any, Dict, Optional, Tuple

Artifact = Tuple[str, str]        # (table, identity key), e.g. ("stable.listening_ports", "tcp/…")

# Only state with no filesystem representation. Everything osquery reads out of a file is covered
# by the images, exactly and without a lens.
RUNTIME_TABLES = ("listening_ports", "autostart")

# Paths that change on their own, or that only ever grow. Scoring them would make a perfect episode
# unscorable: /var/log/auth.log records the attack's own useradd and cannot be unwritten.
VOLATILE_PREFIXES = (
    "/var/log/", "/var/lib/landscape/", "/var/lib/update-notifier/", "/var/lib/systemd/",
    "/var/cache/", "/tmp/openclaw/",
)

# A timestamp moving with identical size is not a content change; `image.diff` reports it as its own
# group precisely so it need not be guessed at here.
SETTLED = ("mtime_only", "retouched")


def volatile(path: str) -> bool:
    return any(path.startswith(p) for p in VOLATILE_PREFIXES)


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


# ------------------------------------------------------------------ the number

def reward(files: Dict[str, Any], runtime: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """threat_cleared over both footprints together; damage counted, not rated.

    A file artifact and an open port both have to come back for the threat to be cleared, so the two
    footprints are added rather than averaged -- otherwise a closed port could pay for a backdoor
    left on disk. `value` subtracts damage so wiping the machine to "clear" it scores no better than
    doing nothing, and damage is a count of paths rather than a share of the filesystem: one deleted
    /etc/shadow out of 178,000 files is not a rounding error.
    """
    fc = files["counts"]
    rc = (runtime or {}).get("counts") or {"footprint": 0, "cleared": 0, "not_cleared": 0,
                                           "collateral": 0}
    fp = fc["footprint"] + rc["footprint"]
    done = fc["cleared"] + rc["cleared"]
    damage = fc["collateral"] + rc["collateral"]
    cleared = (done / fp) if fp else None          # None: nothing was planted, nothing to clear
    out = {
        "threat_cleared": round(cleared, 4) if cleared is not None else None,
        "damaged_count": damage,
        "footprint": fp,
        "footprint_files": fc["footprint"],
        "footprint_runtime": rc["footprint"],
        "not_cleared": fc["not_cleared"] + rc["not_cleared"],
        "side_effects": fc["side_effects"],
        "deterministic": True,
        "evidence": {"files": "whole-filesystem images", "runtime": list(RUNTIME_TABLES)},
    }
    out["value"] = None if cleared is None else round(cleared - (1.0 if damage else 0.0), 4)
    return out
