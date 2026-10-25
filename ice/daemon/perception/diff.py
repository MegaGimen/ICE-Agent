"""Snapshot diff -> structured change entries (plan.md §2.1/§2.2, colab §3.1).

Stable tables: any added / removed / modified row versus the previous snapshot.
Flow tables: rows whose normalized combination is not in the baseline ("seen before").
Attacker-controllable strings go verbatim into `untrusted`; `value` is built only from
table names, keys we construct, and the action, so it carries no attacker text beyond
what a path or key already contains.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional

from ice.daemon.contracts import ChangeEntry, Direction, Provenance
from ice.daemon.perception.snapshot import TABLES, Snapshot, Table
from ice.daemon.perception.store import Baseline

HOST = __import__("socket").gethostname()


def _untrusted(t: Table, row: Dict, prefix: str = "") -> Dict[str, str]:
    return {f"{prefix}{f}": str(row.get(f)) for f in t.untrusted if row.get(f) not in (None, "")}


def _entry(t: Table, action: str, key: str, row: Dict, meta: Dict, ts: float, seen_before: bool,
           changed: Optional[List[str]] = None, old: Optional[Dict] = None) -> ChangeEntry:
    full = meta.get("_row", row)
    prov = t.provenance(full) if t.name != "connections" else Provenance(
        who=full.get("path") or full.get("name"),
        pid=int(full["pid"]) if str(full.get("pid", "")).isdigit() else None,
        user=full.get("username"))
    untrusted = _untrusted(t, full)
    if old:
        untrusted.update(_untrusted(t, old, prefix="old_"))
    # Fields that are neither attacker-controllable nor bookkeeping are safe context for the gate.
    facts = {k: v for k, v in row.items() if k not in t.untrusted}
    summary = t.summary(full) if t.name != "connections" else f"connection {key}"
    value = f"{action}: {summary}"
    if changed:
        value += f" (fields changed: {', '.join(changed)})"
    e = ChangeEntry(
        type=t.change_type, table=t.name, field=",".join(changed or []) or key,
        value=value, provenance=prov, seen_before=seen_before,
        src_ip=meta.get("remote_address"),
        direction=Direction(meta["direction"]) if meta.get("direction") else Direction.NA,
        host=HOST, ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)), untrusted=untrusted,
    )
    # Not part of the frozen contract (to_dict omits it); the detection gate uses it as structured context.
    e.facts = facts
    return e


def diff(prev: Optional[Snapshot], cur: Snapshot, baseline: Baseline, learning: bool = False) -> List[ChangeEntry]:
    """Return change entries between two snapshots and update the flow baseline.

    With `learning=True` (first run, or a quiet warm-up period) nothing is reported: stable
    tables only establish the reference and every flow combination joins the baseline.
    """
    out: List[ChangeEntry] = []
    for t in TABLES:
        if t.name in cur.errors or (prev is not None and t.name in prev.errors):
            continue  # a failed query must not look like "everything was removed"
        rows = cur.rows(t.name)
        meta = cur.meta.get(t.name, {})
        if t.kind == "flow":
            new = [k for k in rows if not baseline.known(t.name, k)]
            if not learning:
                out += [_entry(t, "new", k, rows[k], meta.get(k, {}), cur.ts, seen_before=False) for k in new]
            baseline.add(t.name, new, cur.ts)
            continue
        if prev is None or learning:
            continue
        before = prev.rows(t.name)
        for k in rows.keys() - before.keys():
            out.append(_entry(t, "added", k, rows[k], meta.get(k, {}), cur.ts, seen_before=False))
        for k in before.keys() - rows.keys():
            out.append(_entry(t, "removed", k, before[k], prev.meta.get(t.name, {}).get(k, {}), cur.ts, seen_before=True))
        for k in rows.keys() & before.keys():
            if rows[k] != before[k]:
                changed = sorted(f for f in rows[k].keys() | before[k].keys() if rows[k].get(f) != before[k].get(f))
                out.append(_entry(t, "modified", k, rows[k], meta.get(k, {}), cur.ts, seen_before=True,
                                  changed=changed, old=before[k]))
    return out
