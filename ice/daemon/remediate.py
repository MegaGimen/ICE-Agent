"""Deterministic containment (plan.md §3.3/§3.4).

The LLM is not a reliable source of remediation: across exercises it judged intrusions benign, or
believed the artifacts were already gone, and proposed nothing — so the execute stage never fired.
This builds a conservative removal action for each change the detection gate (Kev) flagged malicious,
straight from the structured change-entry, independent of what the LLM said. Each action is one
program with literal arguments (no shell), still goes through the safety gate (these are irreversible,
so the gate forces ASK -> human approval), and is only proposed for an artifact that still exists.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from ice.daemon.contracts import ChangeEntry, ChangeType, ProposedAction
from ice.daemon.detect.gate import GateResult
from ice.daemon.perception.osq import OsqueryError, run_query

log = logging.getLogger("ice.remediate")


def _q1(sql: str) -> bool:
    """True if the query returns at least one row (artifact still present)."""
    try:
        return bool(run_query(sql))
    except OsqueryError:
        return True   # can't tell -> propose anyway; the human decides at ASK


def _sqlstr(v: str) -> str:
    return v.replace("'", "''")


def _containment(entry: ChangeEntry) -> Optional[ProposedAction]:
    """Map one gate-flagged change to a conservative removal command, if the artifact still exists."""
    t, user = entry.type, (entry.provenance.user or "")
    key = entry.field or ""

    if t is ChangeType.CRON:
        path = key.split("#", 1)[0]
        if not path:
            return None
        if not _q1(f"SELECT 1 FROM crontab WHERE path = '{_sqlstr(path)}'"):
            return None
        if path.startswith("/var/spool/cron/") and user:
            return ProposedAction(command=f"crontab -r -u {user}",
                                  intent=f"Remove the compromised crontab for {user} ({path})", targets=[path])
        if path.startswith("/etc/cron.d/"):
            return ProposedAction(command=f"rm -f {path}",
                                  intent=f"Remove the malicious cron file {path}", targets=[path])
        return None   # /etc/crontab and others: too broad to remove automatically

    if t is ChangeType.SSH_KEY and user:
        if not _q1(f"SELECT 1 FROM users u JOIN authorized_keys k USING (uid) WHERE u.username = '{_sqlstr(user)}'"):
            return None
        home = (run_query(f"SELECT directory FROM users WHERE username='{_sqlstr(user)}'") or [{}])[0].get("directory")
        if not home:
            return None
        return ProposedAction(command=f"rm -f {home}/.ssh/authorized_keys",
                              intent=f"Remove the attacker SSH authorized key(s) for {user}", targets=[f"{home}/.ssh/authorized_keys"])

    if t is ChangeType.ACCOUNT:
        u = key or user
        if not u or not _q1(f"SELECT 1 FROM users WHERE username = '{_sqlstr(u)}'"):
            return None
        return ProposedAction(command=f"userdel -r {u}",
                              intent=f"Remove the attacker-created account {u}", targets=[u])

    if t is ChangeType.AUTOSTART:
        if key.endswith((".service", ".timer", ".socket", ".target", ".path", ".mount")):
            return ProposedAction(command=f"systemctl disable --now {key}",
                                  intent=f"Disable the malicious autostart unit {key}", targets=[key])
        if key.startswith("/") and _q1(f"SELECT 1 FROM file WHERE path = '{_sqlstr(key)}'"):
            return ProposedAction(command=f"rm -f {key}",
                                  intent=f"Remove the malicious autostart file {key}", targets=[key])
        return None

    return None   # processes/connections/ports: containment is pid/stateful; left to investigation


def propose_containment(escalated: List[GateResult], strong_only: bool = True) -> List[ProposedAction]:
    """Containment actions for every escalation the gate judged malicious (or, if strong_only is False,
    anything it escalated). Deduplicated by command; existence is checked per artifact."""
    out: List[ProposedAction] = []
    seen = set()
    for r in escalated:
        gate_malicious = r.verdict == "malicious" or any(v >= 0.90 for v in r.attributes.values())
        if strong_only and not gate_malicious:
            continue
        try:
            action = _containment(r.entry)
        except OsqueryError as e:  # noqa: BLE001
            log.warning("containment probe failed for %s: %s", r.entry.entry_id, e)
            continue
        if action and action.command not in seen:
            seen.add(action.command)
            out.append(action)
    return out
