"""The commands the episode actually ran, read back out of the audit.

`executed_commands()` reads `host_exec.executed`. That list is complete for deliberate host
mutation by construction: the agent's own shell runs as the unprivileged sandbox user and cannot
write root-owned paths, so every change it meant to make had to go through `host_exec`.
`refused_commands()` reads the ones the gate denied -- they ran nothing and explain no change.

Verification of the paths those commands point at used to live here too, against a tarball of 19
declared paths plus whatever osquery happened to collect. ice.exercise.image replaced it: the
evidence is now the whole filesystem before and after, so there is no coverage question to reason
around and nothing to label unverifiable.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def executed_commands(audit_path: Path) -> List[Dict[str, Any]]:
    """Every command the episode really ran, in order, with its exit status."""
    out: List[Dict[str, Any]] = []
    try:
        lines = Path(audit_path).read_text().splitlines()
    except OSError:
        return out
    for line in lines:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("event") != "host_exec.executed":
            continue
        res = e.get("result") or {}
        out.append({"command": e.get("command"),
                    "returncode": res.get("returncode"),
                    "stderr": (res.get("stderr") or "")[:300],
                    "dry_run": bool(e.get("dry_run")),
                    "by": e.get("by"),
                    "case": e.get("case")})
    return out


def refused_commands(audit_path: Path) -> List[Dict[str, Any]]:
    """Commands the gate refused, for context: these ran nothing and cannot explain any change."""
    out: List[Dict[str, Any]] = []
    try:
        lines = Path(audit_path).read_text().splitlines()
    except OSError:
        return out
    for line in lines:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("event") != "host_exec.verdict":
            continue
        v = e.get("verdict") or {}
        if str(v.get("decision", "")).upper().endswith("DENY"):
            out.append({"command": e.get("command"), "reason": v.get("reason")})
    return out
