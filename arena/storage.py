from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import threading
import time

from .contracts import canonical


def write_json(path: Path, value, *, private=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    temporary.replace(path)


class Journal:
    """Append-only controller evidence; a hash chain detects accidental corruption.

    This is not an OS isolation boundary: LocalLab only admits HTTP application actions.
    """

    def __init__(self, path: Path, context_id: str | None = None):
        self.path = path
        self.context_id = context_id
        path.parent.mkdir(parents=True, exist_ok=True)
        self.rows = []
        self.lock = threading.Lock()
        self.start = time.monotonic()

    def append(self, kind, data):
        with self.lock:
            row = {"seq": len(self.rows), "elapsed": time.monotonic() - self.start,
                   "monotonic_ns": time.monotonic_ns(),
                   "context_id": self.context_id,
                   "kind": kind, "data": data,
                   "prev": self.rows[-1]["hash"] if self.rows else "0" * 64}
            # Callers keep editing conversation lists and submitted dictionaries.
            # Evidence owns a frozen JSON copy, not those mutable Python objects.
            row = json.loads(canonical(row))
            row["hash"] = hashlib.sha256(canonical(row)).hexdigest()
            with self.path.open("a") as stream:
                stream.write(json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n")
            self.rows.append(row)
            return row["seq"]


def read_journal(path: Path):
    rows = []
    previous = "0" * 64
    for line in path.read_text().splitlines():
        row = json.loads(line)
        given = row.pop("hash")
        if row["seq"] != len(rows) or row["prev"] != previous:
            raise ValueError("evidence sequence or previous hash is invalid")
        if hashlib.sha256(canonical(row)).hexdigest() != given:
            raise ValueError("evidence hash mismatch")
        row["hash"] = given
        rows.append(row)
        previous = given
    return rows
