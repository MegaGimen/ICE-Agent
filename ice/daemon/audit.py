"""Append-only audit log (plan.md §3 step ⑦): every tool call, gate verdict, and execution.

JSON lines with a hash chain — each record carries the sha256 of the previous one — so a
deleted or edited record breaks `verify()`. Lives in the host state dir, outside the sandbox.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.Lock()
        self._last = GENESIS
        if self.path.exists():
            for rec in self._records():
                self._last = rec["hash"]
        else:
            fd = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)

    def _records(self) -> Iterator[Dict[str, Any]]:
        with self.path.open() as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)

    def write(self, event: str, **fields: Any) -> Dict[str, Any]:
        with self._lock:
            rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **fields,
                   "prev": self._last}
            body = json.dumps(rec, sort_keys=True, ensure_ascii=False, default=str)
            rec["hash"] = hashlib.sha256(body.encode()).hexdigest()
            with self.path.open("a") as f:
                f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
            self._last = rec["hash"]
            return rec

    def verify(self) -> Optional[int]:
        """Return None if the chain is intact, else the 0-based index of the first bad record."""
        prev = GENESIS
        for i, rec in enumerate(self._records()):
            h = rec.pop("hash", None)
            body = json.dumps(rec, sort_keys=True, ensure_ascii=False, default=str)
            if rec.get("prev") != prev or hashlib.sha256(body.encode()).hexdigest() != h:
                return i
            prev = h
        return None

    def tail(self, n: int = 20):
        recs = list(self._records())
        return recs[-n:]
