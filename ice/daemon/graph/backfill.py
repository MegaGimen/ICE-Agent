"""Write every stored case into the correlation graph (after the graph was added or rebuilt).

  python -m ice.daemon.graph.backfill          # uses ICE_STATE_DIR (default ~/ice-state)

Idempotent: objects and edges are merged by natural key. Run it while the daemon is stopped
(Kùzu allows one writer process per database).
"""
from __future__ import annotations

import os
from pathlib import Path

from ice.daemon.contracts import Case
from ice.daemon.graph.store import Graph
from ice.daemon.investigate.case import _idents
from ice.daemon.orchestrator import CaseStore
from ice.daemon.perception.store import SnapshotStore


def main() -> None:
    state = Path(os.environ.get("ICE_STATE_DIR", Path.home() / "ice-state"))
    graph = Graph(state / "graph" / "kuzu", source=os.uname().nodename)
    latest = SnapshotStore(state / "snapshots").latest()
    accounts = set(latest.rows("accounts")) if latest and "accounts" not in latest.errors else None
    n = 0
    for d in CaseStore(state / "cases").all():
        case = Case.from_dict(d)
        case.ioc, case.blast_radius = _idents(case.ioc), _idents(case.blast_radius)   # older cases kept prose
        meta = d.get("_ice") or {}
        written = graph.record_case(case, meta.get("assessment"), accounts,
                                    source=f"replay:{os.uname().nodename}" if meta.get("replay") else None)
        print(f"{case.case_id}: {written}")
        n += 1
    print(f"{n} cases; graph now {graph.stats()}")


if __name__ == "__main__":
    main()
