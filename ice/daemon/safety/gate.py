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
from typing import Callable, Mapping, Protocol
from uuid import uuid4
import json
import math
import re
import shlex

from ice.daemon.contracts import (
    GateDecision, JudgeKind, JudgeQuery, ProposedAction, SafetyScores, SafetyVerdict,
)
from ice.daemon.judge import judge_batch

@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    command: str
    target: str
    intent: str
    reason: str
    scores: Mapping[str, float]
    scored: bool


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
    # Adapter owned by the intake side. It must score the full command/target,
    # not the agent's explanation alone. Its output is never an approval.
    score_provider: Callable[[str, str, str], Mapping[str, object]] | None = None
    _times: deque[float] = field(default_factory=deque, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def current_policy_allows(self, command: str, target: str) -> bool:
        """Recheck hard stops before dispatching an approved stored action."""
        if self.policy.kill_switch or not _matches(target, self.policy.authorized_targets):
            return False
        if self.policy.deny_critical_assets:
            try:
                parts = shlex.split(command)
            except ValueError:
                return False
            if any(_matches(item, self.policy.critical_assets) for item in (target, *parts[1:])):
                return False
        return True

    def safety_gate(self, command: str | Mapping[str, object] | ProposedAction, intent: str | Mapping[str, object]) -> SafetyVerdict:
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

        try:
            parts = shlex.split(raw)
        except ValueError:
            return _verdict("DENY", "Command syntax could not be parsed", scope=1)
        if not parts:
            return _verdict("DENY", "Command is empty", scope=1)
        # Inspect both the declared target and literal command arguments. A
        # model can understate the target in ProposedAction.targets.
        critical = any(
            _matches(candidate, self.policy.critical_assets)
            for candidate in (target, *parts[1:])
        )
        if critical and self.policy.deny_critical_assets:
            return _verdict("DENY", "Critical asset is denied by policy", scope=1)
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
        scores = _assess(self.score_provider, raw, target, explanation)
        if scores is None and self.score_provider is not None:
            return _verdict("DENY", "Safety scoring failed", scope=1)
        if scores is not None:
            if scores["legit"] < 0.40:
                return _verdict("DENY", "Action lacks a legitimate basis", **_score_kwargs(scores))
            if scores["scope_match"] < 0.50:
                return _verdict("DENY", "Proposed effects exceed the stated scope", **_score_kwargs(scores))
        if (
            read_only and not critical and scores is not None
            and scores["needs_human"] < 0.70 and scores["reversible"] >= 0.70
        ):
            return _verdict("AUTO", "Authorized low-impact command", **_score_kwargs(scores))

        reason = (
            "Critical asset requires approval" if critical else
            "Irreversible action requires approval" if irreversible else
            "Command requires human review" if scores is not None else
            "Safety score unavailable; human review required"
        )
        if self.approval_queue is None:
            return _verdict("DENY", "Approval channel is unavailable", reversible=0 if irreversible else 0.5, scope=1)
        request_id = str(uuid4())
        shown_scores = scores or {"legit": 0.5, "needs_human": 1.0, "reversible": 0.0 if irreversible else 0.5, "scope_match": 1.0}
        request = ApprovalRequest(request_id, raw, target, explanation, reason, shown_scores, scores is not None)
        try:
            self.approval_queue.put_nowait(request)
        except Exception:
            return _verdict("DENY", "Approval request could not be queued", reversible=0 if irreversible else 0.5, scope=1)
        return _verdict("ASK", reason, **_score_kwargs(shown_scores), request_id=request_id)


_configured: SafetyGate | None = None


def configure_safety_gate(gate: SafetyGate) -> None:
    """Bind the host-owned policy, judge adapter, and approval queue at startup."""
    global _configured
    _configured = gate


def safety_gate(
    command: str | Mapping[str, object] | ProposedAction,
    intent: str | Mapping[str, object],
    *,
    gate: SafetyGate | None = None,
) -> SafetyVerdict:
    """Shared entry point. An unconfigured gate fails closed."""
    verdict = (gate or _configured or SafetyGate(SafetyPolicy())).safety_gate(command, intent)
    if isinstance(command, ProposedAction):
        verdict.action_id = command.action_id
    return verdict


def _extract_command_and_target(command: str | Mapping[str, object] | ProposedAction) -> tuple[str, str]:
    if isinstance(command, ProposedAction):
        if len(command.targets) != 1:
            return "", ""
        return command.command.strip(), command.targets[0].strip()
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
    return any(
        fnmatchcase(target, pattern) or (pattern.startswith("/") and target.startswith(pattern.rstrip("/") + "/"))
        for pattern in patterns
    )


def _assess(
    provider: Callable[[str, str, str], Mapping[str, object]] | None,
    command: str,
    target: str,
    intent: str,
) -> dict[str, float] | None:
    if provider is None:
        return None
    try:
        result = provider(command, target, intent)
        scores = {name: float(result[name]) for name in ("legit", "needs_human", "reversible", "scope_match")}
    except Exception:
        # A failed or unavailable scoring backend must not result in AUTO.
        return None
    if any(not math.isfinite(value) or not 0 <= value <= 1 for value in scores.values()):
        return None
    return scores


def _score_kwargs(scores: Mapping[str, float]) -> dict[str, float]:
    return {
        "legit": scores["legit"],
        "human": scores["needs_human"],
        "reversible": scores["reversible"],
        "scope": scores["scope_match"],
    }


def judge_score_provider(command: str, target: str, intent: str) -> dict[str, float]:
    """Map the intake side's frozen judge() helper onto four safety axes."""
    context = json.dumps({"command": command, "target": target, "intent": intent}, ensure_ascii=False)
    questions = {
        "legit": "Is the exact action legitimate for the stated security incident?",
        "needs_human": "How much human judgment is required before this exact action?",
        "reversible": "How reversible are the exact effects of this action?",
        "scope_match": "How closely do the actual effects match the stated intent and target?",
    }
    levels = ["very low", "low", "uncertain", "high", "very high"]
    queries = {
        name: JudgeQuery(kind=JudgeKind.SCORE, question=question, context=context, options=levels)
        for name, question in questions.items()
    }
    responses = judge_batch(context, queries)
    result: dict[str, float] = {}
    for name, response in responses.items():
        if response.score is None:
            raise ValueError(f"Kev omitted {name} score")
        result[name] = response.score
    return result


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
    safety = "safe" if decision == "AUTO" else "destructive" if reversible == 0 else "risky"
    return SafetyVerdict(
        decision=GateDecision(decision),
        scores=SafetyScores(legit=legit, needs_human=human, reversible=reversible, scope_match=scope, safety=safety),
        request_id=request_id,
        reason=reason,
    )
