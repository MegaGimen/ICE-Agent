"""Review an exact proposed command before an external gate considers execution.

This module never executes commands or accepts an agent's assertion of approval.
An ASK request is delivered to an out-of-sandbox approval queue with put_nowait().
The queue's consumer is responsible for authenticating the human and authorizing
the exact command and target identified by request_id.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from threading import Lock
from time import monotonic
from typing import Mapping, Protocol, TypedDict
from uuid import uuid4
import re
import shlex


class SafetyVerdict(TypedDict):
    decision: str
    scores: dict[str, float]
    request_id: str | None
    reason: str


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    command: str
    target: str
    intent: str
    reason: str


class ApprovalQueue(Protocol):
    def put_nowait(self, item: ApprovalRequest) -> None: ...


@dataclass(frozen=True)
class SafetyPolicy:
    authorized_targets: tuple[str, ...] = ()
    critical_assets: tuple[str, ...] = ()
    deny_critical_assets: bool = False
    kill_switch: bool = False
    max_requests_per_window: int = 20
    window_seconds: float = 60.0
    # Only these commands can qualify for AUTO. All other in-scope commands
    # require human approval, including unfamiliar commands and shell syntax.
    read_only_commands: frozenset[str] = frozenset(
        {"date", "hostname", "id", "uname", "uptime", "whoami"}
    )


_SHELL_SYNTAX = re.compile(r"[;&|<>`$\\\n\r]")
_IRREVERSIBLE = frozenset(
    {"chmod", "chown", "dd", "fdisk", "iptables", "kill", "mkfs", "mount", "nft", "reboot", "rm", "shutdown", "systemctl", "ufw", "umount"}
)


@dataclass
class SafetyGate:
    policy: SafetyPolicy
    approval_queue: ApprovalQueue | None = None
    _times: deque[float] = field(default_factory=deque, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def safety_gate(self, command: str | Mapping[str, object], intent: str | Mapping[str, object]) -> SafetyVerdict:
        """Review the supplied command and explicit target, returning a verdict.

        Intent is untrusted explanatory text. It cannot approve or override a
        command. No command can be AUTO without an explicitly authorized target.
        """
        raw, target = _extract_command_and_target(command)
        explanation = intent if isinstance(intent, str) else str(intent.get("reason", ""))
        if self.policy.kill_switch:
            return _verdict("DENY", "Kill switch is active", scope=0)
        if not raw or not target:
            return _verdict("DENY", "Command and target are required", scope=0)
        if not _matches(target, self.policy.authorized_targets):
            return _verdict("DENY", "Target is outside the authorized scope", scope=0)
        if self.policy.max_requests_per_window <= 0 or self.policy.window_seconds <= 0:
            return _verdict("DENY", "Rate limit policy is invalid", scope=1)
        with self._lock:
            now = monotonic()
            while self._times and self._times[0] <= now - self.policy.window_seconds:
                self._times.popleft()
            if len(self._times) >= self.policy.max_requests_per_window:
                return _verdict("DENY", "Rate limit exceeded", scope=1)
            self._times.append(now)

        critical = _matches(target, self.policy.critical_assets)
        if critical and self.policy.deny_critical_assets:
            return _verdict("DENY", "Critical asset is denied by policy", scope=1)
        try:
            parts = shlex.split(raw)
        except ValueError:
            return _verdict("DENY", "Command syntax could not be parsed", scope=1)
        if not parts:
            return _verdict("DENY", "Command is empty", scope=1)
        program = parts[0].rsplit("/", 1)[-1]
        irreversible = program in _IRREVERSIBLE
        shell_syntax = bool(_SHELL_SYNTAX.search(raw))
        # Arguments can change a command's behavior (for example, find -exec),
        # and an absolute path can name an attacker-controlled executable.
        read_only = (
            len(parts) == 1
            and parts[0] == program
            and program in self.policy.read_only_commands
            and not shell_syntax
        )
        if read_only and not critical:
            return _verdict("AUTO", "Authorized read-only command", legit=1, reversible=1, scope=1)

        reason = (
            "Critical asset requires approval" if critical else
            "Irreversible action requires approval" if irreversible else
            "Command requires human review"
        )
        if self.approval_queue is None:
            return _verdict("DENY", "Approval channel is unavailable", reversible=0 if irreversible else 0.5, scope=1)
        request_id = str(uuid4())
        request = ApprovalRequest(request_id, raw, target, explanation, reason)
        try:
            self.approval_queue.put_nowait(request)
        except Exception:
            return _verdict("DENY", "Approval request could not be queued", reversible=0 if irreversible else 0.5, scope=1)
        return _verdict("ASK", reason, legit=0.5, human=1, reversible=0 if irreversible else 0.5, scope=1, request_id=request_id)


def safety_gate(
    command: str | Mapping[str, object],
    intent: str | Mapping[str, object],
    *,
    gate: SafetyGate | None = None,
) -> SafetyVerdict:
    """Shared entry point. An unconfigured gate fails closed."""
    return (gate or SafetyGate(SafetyPolicy())).safety_gate(command, intent)


def _extract_command_and_target(command: str | Mapping[str, object]) -> tuple[str, str]:
    if isinstance(command, Mapping):
        raw = command.get("command", "")
        target = command.get("target", "")
    else:
        # A target taken from intent would be an untrusted description rather
        # than the target bound to the actual proposed execution.
        return "", ""
    if not isinstance(raw, str) or not isinstance(target, str):
        return "", ""
    return raw.strip(), target.strip()


def _matches(target: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatchcase(target, pattern) for pattern in patterns)


def _verdict(
    decision: str,
    reason: str,
    *,
    legit: float = 0,
    human: float = 0,
    reversible: float = 0,
    scope: float = 0,
    request_id: str | None = None,
) -> SafetyVerdict:
    return {
        "decision": decision,
        "scores": {"legit": legit, "needs_human": human, "reversible": reversible, "scope_match": scope},
        "request_id": request_id,
        "reason": reason,
    }
