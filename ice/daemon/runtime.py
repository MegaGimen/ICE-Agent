"""Daemon runtime: builds and holds the shared host-side objects (plan.md §6.1).

Everything here lives outside the sandbox. The MCP server, orchestrator, and ICE Gate
service share one Runtime so a pending approval, its explanation, and its case session
are tied together on the host where the agent cannot touch them.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ice.daemon import config as cfg
from ice.daemon.audit import AuditLog
from ice.daemon.safety.approval import ApprovalPolicy, ApprovalStore
from ice.daemon.safety.gate import SafetyGate, SafetyPolicy, configure_safety_gate, judge_score_provider

log = logging.getLogger("ice.runtime")


@dataclass
class PendingAction:
    """Host-side record of an ASK: which case asked, what exactly, and its human explanation."""
    request_id: str
    case_id: Optional[str]
    command: str
    intent: str
    verdict: Dict[str, Any]
    created: float = field(default_factory=time.time)
    explanation: Optional[str] = None
    status: str = "pending"            # pending -> approved/denied -> executed
    result: Optional[Dict[str, Any]] = None


class PendingRegistry:
    """Persists PendingAction records (json) so a restart does not orphan an approval."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.items: Dict[str, PendingAction] = {}
        if self.path.exists():
            for d in json.loads(self.path.read_text()):
                self.items[d["request_id"]] = PendingAction(**d)

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps([vars(p) for p in self.items.values()], default=str))
        tmp.chmod(0o600)
        tmp.replace(self.path)

    def add(self, p: PendingAction) -> None:
        with self._lock:
            self.items[p.request_id] = p
            self._save()

    def update(self, request_id: str, **fields: Any) -> Optional[PendingAction]:
        with self._lock:
            p = self.items.get(request_id)
            if p:
                for k, v in fields.items():
                    setattr(p, k, v)
                self._save()
            return p

    def get(self, request_id: str) -> Optional[PendingAction]:
        return self.items.get(request_id)


class Runtime:
    def __init__(self, conf: Optional[cfg.Config] = None):
        self.conf = conf or cfg.load()
        sd = self.conf.state_dir
        sd.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.audit = AuditLog(sd / "audit.jsonl")
        self.pending = PendingRegistry(sd / "pending.json")
        policy = SafetyPolicy(
            authorized_targets=(self.conf.hostname,),
            bound_target=self.conf.hostname,          # host_exec always runs on this host
            critical_assets=self.conf.critical_assets,
        )
        self.gate = SafetyGate(policy=policy, score_provider=judge_score_provider)
        self.approvals: Optional[ApprovalStore] = None
        if self.conf.slack_ready:
            self.approvals = ApprovalStore(
                sd / "approvals.sqlite3",
                ApprovalPolicy(team_id=self.conf.slack_team_id, channel_id=self.conf.slack_alert_channel,
                               allowed_user_ids=frozenset(self.conf.slack_approver_ids),
                               request_ttl_seconds=int(os.environ.get("ICE_APPROVAL_TTL", "600"))),
                approval_guard=self.gate.current_policy_allows,
            )
            self.gate.approval_queue = self.approvals
        else:
            # Without a verified approval channel every ASK fails closed to DENY (gate.py).
            log.warning("Slack approval channel not configured: ASK actions will be denied")
        configure_safety_gate(self.gate)
        # Correlation graph (plan §11): optional — the pipeline runs without it.
        self.graph = None
        try:
            from ice.daemon.graph.store import Graph
            self.graph = Graph(sd / "graph" / "kuzu", source=self.conf.hostname)
        except Exception:  # noqa: BLE001
            log.exception("correlation graph unavailable")
        # Dry run: gate verdicts and approvals happen as usual, but no command is executed. Set for --replay,
        # so synthetic events never drive real changes on the host.
        self.dry_run = os.environ.get("ICE_DRY_RUN") == "1"
        # Case whose agent run is in progress; host_exec ASKs are attributed to it.
        self._case_lock = threading.Lock()
        self.current_case: Optional[str] = None
        # Read-only tool calls per case (plan risk: an agent that keeps exploring burns minutes per call).
        self.tool_budget = int(os.environ.get("ICE_TOOL_BUDGET", "12"))
        self._tool_calls: Dict[Optional[str], int] = {}
        # Hooks set by the ICE Gate service: called on a new ASK and on an explanation.
        self.on_ask: List[Callable[[PendingAction], None]] = []
        self.on_explain: List[Callable[[PendingAction], None]] = []

    def set_current_case(self, case_id: Optional[str]) -> None:
        with self._case_lock:
            self.current_case = case_id
            self._tool_calls.pop(case_id, None)

    def spend_tool_call(self) -> bool:
        """Count one read-only call against the current case; False once the budget is used up."""
        with self._case_lock:
            n = self._tool_calls.get(self.current_case, 0) + 1
            self._tool_calls[self.current_case] = n
            return n <= self.tool_budget

    def kill_switch(self, on: bool) -> None:
        """plan §3.4: emergency stop — every host_exec is denied while on."""
        # SafetyPolicy is frozen (safety/gate.py): swap in a copy rather than mutating it.
        self.gate.policy = dataclasses.replace(self.gate.policy, kill_switch=on)
        self.audit.write("kill_switch", on=on)


_runtime: Optional[Runtime] = None


def get_runtime() -> Runtime:
    global _runtime
    if _runtime is None:
        _runtime = Runtime()
    return _runtime
