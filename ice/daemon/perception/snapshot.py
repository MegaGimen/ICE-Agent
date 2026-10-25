"""Host snapshots (plan.md §2.1).

A snapshot is a nested mapping `{kind: {table: {natural_key: row}}}`:

  * stable tables — cron, autostart, accounts, sudoers, SSH keys, listening ports, critical
    file hashes. Any change versus the previous snapshot is reported.
  * flow tables — processes and network connections. Rows are keyed by a normalized
    combination (no pids, IPs bucketed to networks) and only combinations never seen before
    are reported.

Natural keys never contain pids, so backward (backward/verify.py) can flatten T0/T1/T2
snapshots into `kind.table.key.field` paths and compare them directly.
"""
from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from ice.daemon.contracts import ChangeType, Direction, Provenance
from ice.daemon.perception.osq import OsqueryError, run_query

Row = Dict[str, Any]

# Files whose content should never change in normal operation (fingerprinted by sha256).
CRITICAL_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers",
    "/etc/ssh/sshd_config", "/etc/crontab", "/etc/ld.so.preload", "/etc/hosts",
    "/etc/pam.d/sshd", "/etc/pam.d/common-auth", "/etc/rc.local", "/etc/profile",
    "/etc/bash.bashrc", "/etc/environment", "/root/.bashrc", "/root/.profile",
]


def _h(*parts: Any) -> str:
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:12]


def _proc_label(path: str, name: str) -> str:
    """Executable identity without per-instance noise (kernel thread suffixes like kworker/3:1)."""
    if path:
        return path
    return re.sub(r"[/:]\d+.*$", "", name or "?")


def ip_bucket(ip: str) -> Tuple[str, bool]:
    """Bucket an address to its network (/24 IPv4, /48 IPv6). Returns (bucket, is_private)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip, False
    prefix = 24 if addr.version == 4 else 48
    net = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
    return str(net), (addr.is_private or addr.is_loopback or addr.is_link_local)


@dataclass
class Table:
    name: str
    change_type: ChangeType
    kind: str                                  # "stable" | "flow"
    sql: str
    key: Callable[[Row], str]
    provenance: Callable[[Row], Provenance] = lambda r: Provenance()
    untrusted: Tuple[str, ...] = ()            # attacker-controllable fields, kept verbatim
    summary: Callable[[Row], str] = lambda r: ""
    drop: Tuple[str, ...] = ()                 # fields used only for keys/provenance


def _listen_port(r: Row) -> str:
    port = str(r.get("port", ""))
    if r.get("address") in ("127.0.0.1", "::1") and port.isdigit() and int(port) >= 32768:
        return "ephemeral"
    return port


def _cron_user(path: str) -> Optional[str]:
    m = re.match(r"^/var/spool/cron/(?:crontabs/)?([^/]+)$", path or "")
    return m.group(1) if m else ("root" if path in ("/etc/crontab",) or (path or "").startswith("/etc/cron") else None)


TABLES: List[Table] = [
    Table(
        "cron", ChangeType.CRON, "stable",
        "SELECT event, minute, hour, day_of_month, month, day_of_week, command, path FROM crontab",
        key=lambda r: f"{r.get('path')}#{_h(r.get('event'), r.get('minute'), r.get('hour'), r.get('day_of_month'), r.get('month'), r.get('day_of_week'), r.get('command'))}",
        provenance=lambda r: Provenance(user=_cron_user(r.get("path", ""))),
        untrusted=("command",),
        summary=lambda r: f"cron entry in {r.get('path')}",
    ),
    Table(
        "autostart", ChangeType.AUTOSTART, "stable",
        "SELECT id, fragment_path, unit_file_state, user FROM systemd_units "
        "WHERE unit_file_state IN ('enabled','enabled-runtime','linked','alias') AND id NOT LIKE '%@%.%'",
        key=lambda r: r.get("id", ""),
        provenance=lambda r: Provenance(user=r.get("user") or None),
        untrusted=("id", "fragment_path"),
        summary=lambda r: f"enabled systemd unit {r.get('id')}",
    ),
    Table(
        "autostart_files", ChangeType.AUTOSTART, "stable",
        "SELECT path, sha256 FROM hash WHERE path IN (SELECT path FROM file WHERE "
        "path LIKE '/etc/systemd/system/%%' OR path LIKE '/home/%/.config/systemd/user/%%' "
        "OR path LIKE '/root/.config/systemd/user/%%' OR path LIKE '/etc/profile.d/%%' "
        "OR path LIKE '/etc/init.d/%%' OR path LIKE '/etc/xdg/autostart/%%' "
        "OR path LIKE '/home/%/.config/autostart/%%') AND sha256 != ''",
        key=lambda r: r.get("path", ""),
        provenance=lambda r: Provenance(user=(re.match(r"^/home/([^/]+)/", r.get("path", "")) or [None, None])[1]),
        untrusted=("path",),
        summary=lambda r: f"autostart file {r.get('path')}",
    ),
    Table(
        "accounts", ChangeType.ACCOUNT, "stable",
        "SELECT uid, gid, username, shell, directory FROM users",
        key=lambda r: f"{r.get('username')}",
        provenance=lambda r: Provenance(user=r.get("username")),
        untrusted=("username", "directory", "shell"),
        summary=lambda r: f"account {r.get('username')} uid={r.get('uid')}",
    ),
    Table(
        "sudoers", ChangeType.SUDOERS, "stable",
        "SELECT source, header, rule_details FROM sudoers",
        key=lambda r: f"{r.get('source')}#{_h(r.get('header'), r.get('rule_details'))}",
        untrusted=("header", "rule_details"),
        summary=lambda r: f"sudoers rule in {r.get('source')}",
    ),
    Table(
        "ssh_keys", ChangeType.SSH_KEY, "stable",
        "SELECT u.username, k.key_file, k.algorithm, k.key, k.comment "
        "FROM users u JOIN authorized_keys k USING (uid)",
        key=lambda r: f"{r.get('username')}#{_h(r.get('key'))}",
        provenance=lambda r: Provenance(user=r.get("username")),
        untrusted=("comment", "key_file"),
        summary=lambda r: f"SSH authorized key for {r.get('username')} ({r.get('algorithm')})",
    ),
    # Loopback listeners on ephemeral ports (dev tools, language servers, CLIs) change on every run and are
    # unreachable from outside: one bucket per program. Any non-loopback or fixed-port listener stays exact.
    Table(
        "listening_ports", ChangeType.LISTEN_PORT, "stable",
        "SELECT l.protocol, l.address, l.port, p.name, p.path, u.username "
        "FROM listening_ports l LEFT JOIN processes p USING (pid) LEFT JOIN users u ON p.uid = u.uid "
        "WHERE l.protocol IN (6, 17) AND l.port != 0",
        key=lambda r: f"{'tcp' if r.get('protocol') == '6' else 'udp'}/{r.get('address')}/{_listen_port(r)}/{_proc_label(r.get('path', ''), r.get('name', ''))}",
        provenance=lambda r: Provenance(who=_proc_label(r.get("path", ""), r.get("name", "")), user=r.get("username")),
        untrusted=("name", "path"),
        summary=lambda r: f"listening {'tcp' if r.get('protocol') == '6' else 'udp'} {r.get('address')}:{r.get('port')}",
    ),
    Table(
        "critical_files", ChangeType.SYSTEM_FILE, "stable",
        "SELECT path, sha256 FROM hash WHERE path IN (" + ",".join(f"'{p}'" for p in CRITICAL_FILES) + ")",
        key=lambda r: r.get("path", ""),
        summary=lambda r: f"critical file {r.get('path')}",
    ),
    Table(
        "processes", ChangeType.PROCESS, "flow",
        "SELECT p.pid, p.name, p.path, p.cmdline, p.cwd, u.username, pp.name AS parent_name, pp.path AS parent_path, "
        "p.parent AS ppid FROM processes p LEFT JOIN processes pp ON p.parent = pp.pid LEFT JOIN users u ON p.uid = u.uid",
        key=lambda r: f"{_proc_label(r.get('path', ''), r.get('name', ''))}<{_proc_label(r.get('parent_path', ''), r.get('parent_name', ''))}@{r.get('username')}",
        provenance=lambda r: Provenance(
            who=_proc_label(r.get("path", ""), r.get("name", "")),
            pid=int(r["pid"]) if str(r.get("pid", "")).isdigit() else None,
            ppid=int(r["ppid"]) if str(r.get("ppid", "")).isdigit() else None,
            parent=_proc_label(r.get("parent_path", ""), r.get("parent_name", "")),
            user=r.get("username"),
        ),
        untrusted=("cmdline", "cwd", "name"),
        summary=lambda r: f"process {_proc_label(r.get('path', ''), r.get('name', ''))} (parent {_proc_label(r.get('parent_path', ''), r.get('parent_name', ''))}, user {r.get('username')})",
        drop=("pid", "ppid"),
    ),
    Table(
        "connections", ChangeType.CONNECTION, "flow",
        "SELECT p.pid, p.name, p.path, u.username, s.remote_address, s.remote_port, s.local_port, s.protocol, s.state "
        "FROM process_open_sockets s JOIN processes p USING (pid) LEFT JOIN users u ON p.uid = u.uid "
        "WHERE s.family IN (2, 10) AND s.remote_address NOT IN ('', '0.0.0.0', '::', '127.0.0.1', '::1') "
        "AND s.remote_port != 0",
        key=lambda r: "",   # filled in by collect(): needs the listening-port set for direction
        untrusted=("name", "path"),
        drop=("pid",),
    ),
]
TABLES_BY_NAME = {t.name: t for t in TABLES}


@dataclass
class Snapshot:
    ts: float
    data: Dict[str, Dict[str, Dict[str, Row]]] = field(default_factory=dict)   # kind -> table -> key -> row
    errors: Dict[str, str] = field(default_factory=dict)
    # Per-key extras the diff needs but backward must not compare (pids, raw remote IPs, direction).
    meta: Dict[str, Dict[str, Row]] = field(default_factory=dict)

    def rows(self, table: str) -> Dict[str, Row]:
        t = TABLES_BY_NAME[table]
        return self.data.get(t.kind, {}).get(table, {})

    def to_dict(self) -> Dict[str, Any]:
        return {"ts": self.ts, "data": self.data, "errors": self.errors, "meta": self.meta}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Snapshot":
        return cls(ts=d["ts"], data=d.get("data", {}), errors=d.get("errors", {}), meta=d.get("meta", {}))


# Infrastructure whose HTTPS egress rotates across cloud IP ranges (Slack, tailscale control plane): their
# outbound public 443 traffic is bucketed as one network, so a new cloud /24 is not "never seen". A new
# executable, port, or direction from them is still reported. Generic interpreters (python, node) are
# deliberately absent: any user's malware would share that path.
TRUSTED_EGRESS = [g for g in os.environ.get(
    "ICE_TRUSTED_EGRESS", "/opt/openshell/bin/*,/usr/sbin/tailscaled").split(",") if g]


def _connection_key(r: Row, listening: set) -> Tuple[str, Direction, str]:
    proto = "tcp" if r.get("protocol") == "6" else "udp"
    inbound = (proto, r.get("local_port")) in listening
    direction = Direction.INBOUND if inbound else Direction.OUTBOUND
    bucket, private = ip_bucket(r.get("remote_address", ""))
    port = r.get("local_port") if inbound else r.get("remote_port")
    scope = "private" if private else "public"
    exe = r.get("path") or ""
    if (not inbound and not private and port == "443"
            and any(fnmatch.fnmatchcase(exe, g) for g in TRUSTED_EGRESS)):
        bucket = "*"
    key = f"{_proc_label(r.get('path', ''), r.get('name', ''))}@{r.get('username')}|{direction.value}|{proto}/{port}|{scope}:{bucket}"
    return key, direction, bucket


def collect(tables: Optional[List[str]] = None) -> Snapshot:
    """Take one snapshot. A failing table is recorded in `errors` and left out (never reported as removed)."""
    snap = Snapshot(ts=time.time())
    raw: Dict[str, List[Row]] = {}
    for t in TABLES:
        if tables and t.name not in tables:
            continue
        try:
            raw[t.name] = run_query(t.sql)
        except OsqueryError as e:
            snap.errors[t.name] = str(e)
    listening = {("tcp" if r.get("protocol") == "6" else "udp", r.get("port")) for r in raw.get("listening_ports", [])}
    for name, rows in raw.items():
        t = TABLES_BY_NAME[name]
        bucket: Dict[str, Row] = {}
        meta: Dict[str, Row] = {}
        for r in rows:
            if name == "connections":
                k, direction, net = _connection_key(r, listening)
                m = {"direction": direction.value, "remote_address": r.get("remote_address"), "net": net,
                     "pid": r.get("pid")}
                r = {kk: v for kk, v in r.items() if kk not in ("remote_address", "local_port", "state")}
                r["remote_net"] = net
            else:
                k = t.key(r)
                m = {kk: r.get(kk) for kk in t.drop}
            row = {kk: v for kk, v in r.items() if kk not in t.drop}
            # Two live instances of one flow combination collapse to one row; keep the first.
            if k not in bucket:
                bucket[k] = row
                meta[k] = {**m, "_row": r}
        snap.data.setdefault(t.kind, {})[name] = bucket
        snap.meta[name] = meta
    return snap
