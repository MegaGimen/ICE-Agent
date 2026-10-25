"""Snapshot history and the "seen before" baseline, persisted under the ICE state dir.

History gives backward its T0/T1/T2 (plan.md §4): T0 is the last snapshot before a case's
first trigger, T1 the snapshot that triggered it, T2 one taken after remediation.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from ice.daemon.perception.snapshot import Snapshot

STATE_DIR = Path(os.environ.get("ICE_STATE_DIR", Path.home() / "ice-state"))


def _atomic_write(path: Path, data: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(data)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


class SnapshotStore:
    """Keeps the last `keep` snapshots on disk (one JSON file each) plus an in-memory index."""

    def __init__(self, directory: Path = STATE_DIR / "snapshots", keep: int = 240):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.keep = keep
        self._lock = threading.Lock()
        self._index: List[float] = sorted(float(p.stem) for p in self.dir.glob("*.json") if _is_ts(p.stem))

    def _path(self, ts: float) -> Path:
        return self.dir / f"{ts:.3f}.json"

    def save(self, snap: Snapshot) -> None:
        with self._lock:
            _atomic_write(self._path(snap.ts), json.dumps(snap.to_dict()))
            self._index.append(snap.ts)
            self._index.sort()
            while len(self._index) > self.keep:
                old = self._index.pop(0)
                self._path(old).unlink(missing_ok=True)

    def load(self, ts: float) -> Snapshot:
        return Snapshot.from_dict(json.loads(self._path(ts).read_text()))

    def latest(self) -> Optional[Snapshot]:
        with self._lock:
            ts = self._index[-1] if self._index else None
        return self.load(ts) if ts is not None else None

    def before(self, ts: float) -> Optional[Snapshot]:
        """The newest snapshot taken strictly before `ts` (T0 for a case first seen at `ts`)."""
        with self._lock:
            older = [t for t in self._index if t < ts]
        return self.load(older[-1]) if older else None

    def at_or_after(self, ts: float) -> Optional[Snapshot]:
        with self._lock:
            newer = [t for t in self._index if t >= ts]
        return self.load(newer[0]) if newer else None

    def since(self, ts: float) -> List[Snapshot]:
        with self._lock:
            newer = [t for t in self._index if t > ts]
        return [self.load(t) for t in newer]


def _is_ts(s: str) -> bool:
    try:
        float(s)
        return True
    except ValueError:
        return False


class Baseline:
    """Flow combinations seen before: {table: {key: first_seen_ts}}. Persisted on every change."""

    def __init__(self, path: Path = STATE_DIR / "baseline.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.Lock()
        self.seen: Dict[str, Dict[str, float]] = json.loads(self.path.read_text()) if self.path.exists() else {}

    def known(self, table: str, key: str) -> bool:
        return key in self.seen.get(table, {})

    def add(self, table: str, keys, ts: Optional[float] = None) -> int:
        ts = ts or time.time()
        added = 0
        with self._lock:
            bucket = self.seen.setdefault(table, {})
            for k in keys:
                if k not in bucket:
                    bucket[k] = ts
                    added += 1
            if added:
                _atomic_write(self.path, json.dumps(self.seen))
        return added

    def size(self) -> Dict[str, int]:
        return {t: len(v) for t, v in self.seen.items()}
