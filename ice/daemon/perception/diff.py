"""Snapshot diff -> structured change entries (plan.md §2.1/§2.2, colab §3.1).

Stable tables: any added / removed / modified row versus the previous snapshot.
Flow tables: rows whose normalized combination is not in the baseline ("seen before").
Attacker-controllable strings go verbatim into `untrusted`; `value` is built only from
table names, keys we construct, and the action, so it carries no attacker text beyond
what a path or key already contains.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional, Tuple

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


MAX_ROWS = int(__import__("os").environ.get("ICE_STATE_DIFF_ROWS", "80"))


def render(prev: Optional[Snapshot], cur: Snapshot, tables: List[str]) -> Dict[str, str]:
    """One table's state now, with the changes marked, in the shape of a unified diff.

    A change entry on its own says `added: <row>` and nothing about what it was added to, and the
    rows that did not change are by definition absent from a diff. So the consumer gets a `+` with
    no "above" -- which is how an agent came to read a new row in `ssh_keys` as a new key in the
    file. It was the same key: the attack had pointed a new account's home at /root, so osquery read
    /root/.ssh/authorized_keys twice and listed it under two names. Both rows carried the same hash,
    and seeing them side by side is all it would have taken.

    So the whole table is handed over as it is now, with `+` on what appeared, `-` on what is gone
    and a space on what was already there. The baseline is not sent separately: an unmarked line
    *is* the baseline.
    """
    out: Dict[str, str] = {}
    by_name = {t.name: t for t in TABLES}
    for name in dict.fromkeys(tables):
        t = by_name.get(name)
        if t is None or t.kind != "stable":
            continue
        now = cur.rows(name)
        was = prev.rows(name) if prev is not None else {}
        lines: List[Tuple[int, str]] = []        # (sort rank, text) -- changes first when capped
        for k in sorted(now.keys() | was.keys()):
            summary = t.summary(now.get(k) or was.get(k) or {})
            label = f"{k}   {summary}".rstrip()
            if k not in was:
                lines.append((0, f"+ {label}"))
            elif k not in now:
                lines.append((0, f"- {label}"))
            elif now[k] != was[k]:
                lines.append((0, f"- {k}   {t.summary(was[k])}".rstrip()))
                lines.append((0, f"+ {label}"))
            else:
                lines.append((1, f"  {label}"))
        kept = sorted(lines, key=lambda x: x[0])[:MAX_ROWS]
        body = "\n".join(text for _, text in sorted(kept, key=lambda x: x[1].lstrip("+- ")))
        omitted = len(lines) - len(kept)
        head = (f"{name}: {len(now)} row(s) now"
                + (f", {omitted} unchanged row(s) not shown" if omitted else ""))
        out[name] = f"{head}\n{body}"
    return out


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
