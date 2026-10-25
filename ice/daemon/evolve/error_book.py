"""Keep missed signals and candidate experience notes out of the active set.

The SQLite file stays local and is ignored by Git. Candidate notes are inert
text; a separate detector must evaluate them in authorized exercise fixtures.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any


Detector = Callable[[str, Mapping[str, Any]], bool]


class ErrorBook:
    def __init__(self, path: str | Path):
        location = str(path)
        if location != ":memory:":
            if os.path.islink(location):
                raise PermissionError("Error book cannot be a symbolic link")
            try:
                descriptor = os.open(location, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                metadata = os.stat(location)
                if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
                    raise PermissionError("Error book must not be readable by other users")
            else:
                os.close(descriptor)
        self.connection = sqlite3.connect(location)
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS misses (
                id INTEGER PRIMARY KEY,
                case_id TEXT NOT NULL,
                signal TEXT NOT NULL,
                evidence TEXT NOT NULL,
                recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS candidates (
                id INTEGER PRIMARY KEY,
                miss_id INTEGER NOT NULL REFERENCES misses(id),
                note TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'draft'
                    CHECK(status IN ('draft', 'eligible', 'active'))
            );
            CREATE TABLE IF NOT EXISTS retests (
                id INTEGER PRIMARY KEY,
                candidate_id INTEGER NOT NULL REFERENCES candidates(id),
                original_detected INTEGER NOT NULL,
                variant_detected INTEGER NOT NULL,
                normal_flagged INTEGER NOT NULL,
                recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS regression_runs (
                id INTEGER PRIMARY KEY,
                candidate_id INTEGER NOT NULL REFERENCES candidates(id),
                scenario TEXT NOT NULL,
                expected INTEGER NOT NULL,
                observed INTEGER NOT NULL,
                recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """)

    def close(self) -> None:
        self.connection.close()

    def record_miss(self, case_id: str, signal: str, evidence: Mapping[str, Any]) -> int:
        if not case_id or not signal:
            raise ValueError("case_id and signal are required")
        with self.connection:
            cursor = self.connection.execute(
                "INSERT INTO misses(case_id, signal, evidence) VALUES (?, ?, ?)",
                (case_id, signal, json.dumps(evidence, sort_keys=True)),
            )
        return int(cursor.lastrowid)

    def propose(self, miss_id: int, note: str) -> int:
        if not note.strip():
            raise ValueError("Candidate note is required")
        with self.connection:
            cursor = self.connection.execute(
                "INSERT INTO candidates(miss_id, note) VALUES (?, ?)", (miss_id, note)
            )
        return int(cursor.lastrowid)

    def retest(
        self,
        candidate_id: int,
        original: Mapping[str, Any],
        variant: Mapping[str, Any],
        normal: Mapping[str, Any],
        detector: Detector,
    ) -> bool:
        row = self.connection.execute("SELECT note FROM candidates WHERE id = ?", (candidate_id,)).fetchone()
        if row is None:
            raise KeyError(candidate_id)
        note = str(row[0])
        results = (bool(detector(note, scenario)) for scenario in (original, variant, normal))
        original_hit, variant_hit, normal_hit = results
        eligible = original_hit and variant_hit and not normal_hit
        with self.connection:
            self.connection.execute(
                "INSERT INTO retests(candidate_id, original_detected, variant_detected, normal_flagged) VALUES (?, ?, ?, ?)",
                (candidate_id, original_hit, variant_hit, normal_hit),
            )
            self.connection.execute(
                "UPDATE candidates SET status = CASE WHEN status = 'active' AND ? THEN 'active' ELSE ? END WHERE id = ?",
                (eligible, "eligible" if eligible else "draft", candidate_id),
            )
        return eligible

    def promote(self, candidate_id: int) -> None:
        """Activate only after the latest three-way retest was successful."""
        row = self.connection.execute(
            "SELECT status FROM candidates WHERE id = ?", (candidate_id,)
        ).fetchone()
        if row is None:
            raise KeyError(candidate_id)
        if row[0] != "eligible":
            raise ValueError("Candidate has not passed its original, variant, and normal retest")
        with self.connection:
            self.connection.execute(
                "UPDATE candidates SET status = 'active' WHERE id = ?", (candidate_id,)
            )

    def active_notes(self) -> list[str]:
        return [row[0] for row in self.connection.execute(
            "SELECT note FROM candidates WHERE status = 'active' ORDER BY id"
        )]

    def run_regression(
        self,
        scenarios: Mapping[str, tuple[Mapping[str, Any], bool]],
        detector: Detector,
    ) -> dict[int, bool]:
        """Rerun the full labeled exercise set and demote failing notes."""
        if not scenarios:
            raise ValueError("A labeled regression set is required")
        candidates = list(self.connection.execute(
            "SELECT id, note FROM candidates WHERE status = 'active' ORDER BY id"
        ))
        outcomes: dict[int, bool] = {}
        for candidate_id, note in candidates:
            observations = [
                (label, bool(expected), bool(detector(note, scenario)))
                for label, (scenario, expected) in scenarios.items()
            ]
            passed = all(expected == observed for _, expected, observed in observations)
            with self.connection:
                self.connection.executemany(
                    "INSERT INTO regression_runs(candidate_id, scenario, expected, observed) VALUES (?, ?, ?, ?)",
                    ((candidate_id, label, expected, observed) for label, expected, observed in observations),
                )
                if not passed:
                    self.connection.execute(
                        "UPDATE candidates SET status = 'draft' WHERE id = ?", (candidate_id,)
                    )
            outcomes[int(candidate_id)] = passed
        return outcomes

    def record_backward_misses(self, result: object) -> list[int]:
        """Capture residuals the forward case may have omitted."""
        contracted = getattr(result, "result", result)
        case_id = str(getattr(contracted, "case_id"))
        recorded: list[int] = []
        for item in getattr(contracted, "missed_by_forward"):
            signal = str(item.get("path") or item.get("indicator") or "unknown")
            if self.connection.execute(
                "SELECT 1 FROM misses WHERE case_id = ? AND signal = ? LIMIT 1",
                (case_id, signal),
            ).fetchone():
                continue
            recorded.append(self.record_miss(case_id, signal, item))
        return recorded
