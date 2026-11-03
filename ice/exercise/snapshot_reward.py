"""Scenario-free episode reward from ICE's own T0/T1/T2 host snapshots.

The attack's footprint is *derived*, never declared: whatever differs between the clean machine (T0)
and the machine at detection (T1) is the attack, whether we scripted it or a red team improvised it.
That is what makes this usable on attacks the scenario file has never heard of.

    footprint     = artifacts where T0 and T1 disagree
    cleared       = footprint artifacts that are back to their T0 state at T2
    not_cleared   = footprint artifacts still altered at T2
    collateral    = artifacts untouched by the attack that T2 nevertheless changed or removed
    side_effects  = artifacts present at T2 that exist in neither T0 nor the footprint

`threat_cleared` and `collateral_damage` therefore need no model at all -- they are set arithmetic
over observations. A judge is only worth paying for the genuinely ambiguous group, `side_effects`
(is a new file a quarantine copy or a problem?), and for an advisory quality score.

ICE's snapshots are already keyed by stable artifact identity, which is what makes per-artifact
attribution possible rather than "the cron table changed":

    stable.cron             /etc/cron.d/persistevil#<hash>
    stable.accounts         butter
    stable.ssh_keys         root#<keyhash>
    stable.listening_ports  tcp/0.0.0.0/4444//tmp/x
    flow.processes          /usr/bin/bash</usr/sbin/apache2@www-data
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

Artifact = Tuple[str, str]        # (table, identity key), e.g. ("stable.cron", "/etc/cron.d/x#ab12")


def index(snapshot: Dict[str, Any]) -> Dict[Artifact, Any]:
    """{(table, key): row} for every artifact in a snapshot file's `data` section."""
    out: Dict[Artifact, Any] = {}
    data = (snapshot or {}).get("data") or {}
    for group, tables in data.items():
        if not isinstance(tables, dict):
            continue
        for table, rows in tables.items():
            name = f"{group}.{table}"
            if isinstance(rows, dict):
                for key, row in rows.items():
                    out[(name, str(key))] = row
            elif isinstance(rows, list):
                # Defensive: a list-shaped table has no identity key, so fall back to position.
                for i, row in enumerate(rows):
                    out[(name, str(i))] = row
    return out


def load(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _show(a: Artifact) -> str:
    return f"{a[0]}::{a[1]}"


def diff(t0: Dict[str, Any], t1: Dict[str, Any], t2: Dict[str, Any],
         limit: int = 300) -> Dict[str, Any]:
    """Classify every artifact across the three snapshots. No scenario knowledge is used."""
    a0, a1, a2 = index(t0), index(t1), index(t2)

    footprint = sorted(k for k in a0.keys() | a1.keys() if a0.get(k) != a1.get(k))
    cleared, not_cleared = [], []
    for k in footprint:
        # "Cleared" means the artifact is back to exactly how the clean machine had it: absent if the
        # attack added it, and byte-identical if the attack altered it.
        if a2.get(k) == a0.get(k):
            cleared.append(k)
        else:
            not_cleared.append(k)

    fp = set(footprint)
    collateral = sorted(k for k in a0 if k not in fp and a2.get(k) != a0.get(k))
    side_effects = sorted(k for k in a2 if k not in a0 and k not in fp)

    def detail(keys: List[Artifact]) -> List[Dict[str, Any]]:
        out = []
        for k in keys[:limit]:
            out.append({"artifact": _show(k),
                        "t0": a0.get(k), "t1": a1.get(k), "t2": a2.get(k)})
        return out

    return {
        "counts": {"footprint": len(footprint), "cleared": len(cleared),
                   "not_cleared": len(not_cleared), "collateral": len(collateral),
                   "side_effects": len(side_effects),
                   "artifacts_t0": len(a0), "artifacts_t1": len(a1), "artifacts_t2": len(a2)},
        "footprint": [_show(k) for k in footprint[:limit]],
        "cleared": [_show(k) for k in cleared[:limit]],
        "not_cleared": detail(not_cleared),
        "collateral": detail(collateral),
        "side_effects": detail(side_effects),
        "truncated": any(len(x) > limit for x in (footprint, not_cleared, collateral, side_effects)),
    }


def reward(d: Dict[str, Any], judgement: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Deterministic reward from the diff; the judge only contributes advisory terms.

    threat_cleared    fraction of the derived footprint returned to its T0 state
    collateral_damage share of untouched artifacts that the episode changed anyway
    value             threat_cleared - collateral_damage, so wiping the host to "clear" the
                      threat scores no better than doing nothing
    """
    c = d["counts"]
    fp = c["footprint"]
    cleared = (c["cleared"] / fp) if fp else None          # None: nothing was planted to clear
    base = max(1, c["artifacts_t0"])
    damage = c["collateral"] / base
    out = {
        "threat_cleared": round(cleared, 4) if cleared is not None else None,
        "collateral_damage": round(damage, 6),
        "collateral_count": c["collateral"],
        "footprint": fp,
        "not_cleared": c["not_cleared"],
        "side_effects": c["side_effects"],
        "deterministic": True,
    }
    out["value"] = None if cleared is None else round(cleared - damage, 4)
    if judgement:
        out["side_effects_acceptable"] = judgement.get("side_effects_acceptable")
        out["quality"] = judgement.get("investigation_quality")
        if judgement.get("error"):
            out["judge_error"] = judgement["error"]
    return out
