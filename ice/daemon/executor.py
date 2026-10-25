"""Host executor (plan.md §3 step ⑥). Runs only commands the safety gate returned AUTO for,
or that a human approved through ICE Gate — callers must check that; this module does not.

Commands run as argv via shlex (no shell), so the exact string the gate reviewed is the
exact program and arguments that run: no expansion, no pipes, no redirections.
"""
from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import asdict, dataclass
from typing import Dict

MAX_OUTPUT = 8000


@dataclass
class ExecResult:
    command: str
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False

    def to_dict(self) -> Dict:
        return asdict(self)


def run(command: str, timeout: float = 60.0) -> ExecResult:
    argv = shlex.split(command)
    t = time.time()
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return ExecResult(command, p.returncode, p.stdout[-MAX_OUTPUT:], p.stderr[-MAX_OUTPUT:], round(time.time() - t, 3))
    except subprocess.TimeoutExpired as e:
        return ExecResult(command, -1, (e.stdout or "")[-MAX_OUTPUT:] if isinstance(e.stdout, str) else "",
                          "timed out", round(time.time() - t, 3), timed_out=True)
    except (FileNotFoundError, PermissionError) as e:
        return ExecResult(command, -1, "", f"{type(e).__name__}: {e}", round(time.time() - t, 3))
