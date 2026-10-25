"""osquery runner (plan.md §2.1). One `osqueryi --json` call per query.

The daemon runs as root (plan §6.1); when it does not (development), queries go through
`sudo -n` so root-only tables (user crontabs, shadow-backed users, every authorized_keys)
are still visible.
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, List

OSQUERYI = os.environ.get("ICE_OSQUERYI", "/usr/bin/osqueryi")
DEFAULT_TIMEOUT = float(os.environ.get("ICE_OSQUERY_TIMEOUT", "30"))


class OsqueryError(RuntimeError):
    pass


def _argv(sql: str) -> List[str]:
    argv = [OSQUERYI, "--json", "--logger_min_status=2", sql]
    if os.geteuid() != 0:
        argv = ["sudo", "-n"] + argv
    return argv


def run_query(sql: str, timeout: float = DEFAULT_TIMEOUT) -> List[Dict[str, Any]]:
    """Run one osquery SQL statement and return its rows (values are strings, as osquery emits them)."""
    try:
        proc = subprocess.run(_argv(sql), capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise OsqueryError(f"osquery timed out after {timeout}s") from e
    if proc.returncode != 0:
        raise OsqueryError(f"osquery exit {proc.returncode}: {proc.stderr.strip()[:500]}")
    out = proc.stdout.strip()
    if not out:
        return []
    try:
        rows = json.loads(out)
    except json.JSONDecodeError as e:
        raise OsqueryError(f"osquery returned non-JSON output: {out[:200]}") from e
    if not isinstance(rows, list):
        raise OsqueryError("osquery output is not a list")
    return rows
