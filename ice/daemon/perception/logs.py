"""Event-stream channel (plan.md §2.1 channel 2): auth.log, for actions that come and go
between snapshots (SSH brute force, a login from a new network).

Failed SSH logins are aggregated per source IP over a sliding window; an entry is emitted
each time an IP crosses a threshold. Successful logins are reported when the
(user, source network) pair has not been seen before.
"""
from __future__ import annotations

import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple

from ice.daemon.contracts import ChangeEntry, ChangeType, Direction, Provenance
from ice.daemon.perception.snapshot import ip_bucket
from ice.daemon.perception.store import Baseline

AUTH_LOG = Path(os.environ.get("ICE_AUTH_LOG", "/var/log/auth.log"))
WINDOW_S = 300
THRESHOLDS = (5, 20, 100)

_LINE = re.compile(r"^(?P<ts>\S+) (?P<host>\S+) sshd(?:-session)?\[(?P<pid>\d+)\]: (?P<msg>.*)$")
_FAILED = re.compile(r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>.*?) from (?P<ip>\S+) port \d+")
_INVALID = re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>\S+) port \d+")
_ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+")


def _ts(s: str) -> float:
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return time.time()


class AuthLogWatcher:
    """Tails auth.log from where it left off (handles rotation by inode / size)."""

    def __init__(self, baseline: Baseline, path: Path = AUTH_LOG, from_end: bool = True):
        self.path = Path(path)
        self.baseline = baseline
        self._inode: Optional[int] = None
        self._offset = 0
        self._fails: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        self._crossed: Dict[str, int] = {}
        if from_end and self.path.exists():
            st = self.path.stat()
            self._inode, self._offset = st.st_ino, st.st_size

    def _read_new(self) -> List[str]:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return []
        if self._inode != st.st_ino or st.st_size < self._offset:
            self._inode, self._offset = st.st_ino, 0   # rotated or truncated
        with self.path.open("rb") as f:
            f.seek(self._offset)
            data = f.read()
        # Only consume complete lines; a partial last line is read next time.
        end = data.rfind(b"\n") + 1
        self._offset += end
        return data[:end].decode(errors="replace").splitlines()

    def poll(self) -> List[ChangeEntry]:
        out: List[ChangeEntry] = []
        for line in self._read_new():
            m = _LINE.match(line)
            if not m:
                continue
            ts, host, msg = _ts(m["ts"]), m["host"], m["msg"]
            if (f := _FAILED.match(msg) or _INVALID.match(msg)):
                out += self._failure(f["ip"], f["user"], ts, host, line)
            elif (a := _ACCEPTED.match(msg)):
                out += self._accepted(a["ip"], a["user"], a["method"], ts, host, line)
        return out

    def _failure(self, ip: str, user: str, ts: float, host: str, line: str) -> List[ChangeEntry]:
        q = self._fails[ip]
        q.append((ts, user))
        while q and q[0][0] < ts - WINDOW_S:
            q.popleft()
        if not q:
            self._crossed.pop(ip, None)
        level = max((t for t in THRESHOLDS if len(q) >= t), default=0)
        if level <= self._crossed.get(ip, 0):
            return []
        self._crossed[ip] = level
        users = sorted({u for _, u in q})
        net, private = ip_bucket(ip)
        return [ChangeEntry(
            type=ChangeType.LOGIN, table="auth_log", field="sshd_failed",
            value=f"{len(q)} failed SSH logins from {ip} ({'private' if private else 'public'} {net}) "
                  f"within {WINDOW_S // 60} min, {len(users)} distinct usernames",
            provenance=Provenance(who="sshd"), seen_before=self.baseline.known("ssh_sources", net),
            src_ip=ip, direction=Direction.INBOUND, host=host,
            ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
            untrusted={"usernames_tried": ", ".join(users[:20]), "last_line": line[-300:]},
        )]

    def _accepted(self, ip: str, user: str, method: str, ts: float, host: str, line: str) -> List[ChangeEntry]:
        net, private = ip_bucket(ip)
        key = f"{user}@{net}"
        if self.baseline.known("ssh_logins", key):
            return []
        self.baseline.add("ssh_logins", [key], ts)
        self.baseline.add("ssh_sources", [net], ts)
        failed_before = len(self._fails.get(ip, ()))
        return [ChangeEntry(
            type=ChangeType.LOGIN, table="auth_log", field="sshd_accepted",
            value=f"SSH login accepted ({method}) for a user from {ip} ({'private' if private else 'public'} {net}), "
                  f"first time for this user/network; {failed_before} failures from this IP in the last {WINDOW_S // 60} min",
            provenance=Provenance(who="sshd", user=user), seen_before=False,
            src_ip=ip, direction=Direction.INBOUND, host=host,
            ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
            untrusted={"user": user, "last_line": line[-300:]},
        )]

    def learn_history(self) -> int:
        """Seed the login baseline from the whole current log (used during warm-up)."""
        n = 0
        if not self.path.exists():
            return 0
        for line in self.path.read_text(errors="replace").splitlines():
            m = _LINE.match(line)
            a = _ACCEPTED.match(m["msg"]) if m else None
            if a:
                net, _ = ip_bucket(a["ip"])
                n += self.baseline.add("ssh_logins", [f"{a['user']}@{net}"])
                self.baseline.add("ssh_sources", [net])
        return n
