"""Host-only pending approvals and signed Slack interaction handling.

Keep this store and callback outside the OpenShell sandbox. A callback may
authorize one stored action, but this module never executes it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import parse_qs

from .gate import ApprovalRequest


@dataclass(frozen=True)
class ApprovalPolicy:
    team_id: str
    channel_id: str
    allowed_user_ids: frozenset[str]
    request_ttl_seconds: int = 600

    def __post_init__(self) -> None:
        if not self.team_id or not self.channel_id or not self.allowed_user_ids:
            raise ValueError("Team, channel, and approver IDs are required")
        if self.request_ttl_seconds <= 0:
            raise ValueError("Approval expiry must be positive")


@dataclass(frozen=True)
class ApprovalDecision:
    request_id: str
    approved: bool
    command: str
    target: str
    user_id: str


class ApprovalStore:
    """Local pending store; put_nowait matches SafetyGate's queue protocol."""

    def __init__(
        self,
        path: str | Path,
        policy: ApprovalPolicy,
        approval_guard: Callable[[str, str], bool] | None = None,
    ):
        self.policy = policy
        self.approval_guard = approval_guard
        self._lock = threading.Lock()
        location = str(path)
        if location != ":memory:":
            if os.path.islink(location):
                raise PermissionError("Approval database cannot be a symbolic link")
            try:
                descriptor = os.open(location, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                metadata = os.stat(location)
                if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
                    raise PermissionError("Approval database must not be readable by other users")
            else:
                os.close(descriptor)
        self._db = sqlite3.connect(location, timeout=0, check_same_thread=False)
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS approvals (
                request_id TEXT PRIMARY KEY,
                command TEXT NOT NULL,
                target TEXT NOT NULL,
                intent TEXT NOT NULL,
                reason TEXT NOT NULL,
                scores TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending','approved','denied')),
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                decided_by TEXT
            )
        """)
        self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def put_nowait(self, request: ApprovalRequest) -> None:
        """Persist before ASK is returned; fail closed if the store is busy."""
        if not self._lock.acquire(blocking=False):
            raise BlockingIOError("Approval store is busy")
        try:
            now = int(time.time())
            with self._db:
                self._db.execute(
                    "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (request.request_id, request.command, request.target, request.intent,
                     request.reason, json.dumps(dict(request.scores)), "pending", now,
                     now + self.policy.request_ttl_seconds, None),
                )
        finally:
            self._lock.release()

    def decide(self, request_id: str, approved: bool, user_id: str) -> ApprovalDecision:
        """Consume a pending request once after the caller verifies Slack."""
        if not request_id or user_id not in self.policy.allowed_user_ids:
            raise PermissionError("Approver is not authorized")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT command,target,status,expires_at FROM approvals WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                if row is None or row[2] != "pending" or row[3] <= int(time.time()):
                    raise ValueError("Approval request is absent, expired, or already decided")
                command, target = row[:2]
                if approved and (self.approval_guard is None or not self.approval_guard(command, target)):
                    raise PermissionError("Current host policy does not allow approval")
                self._db.execute(
                    "UPDATE approvals SET status = ?, decided_by = ? WHERE request_id = ?",
                    ("approved" if approved else "denied", user_id, request_id),
                )
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        return ApprovalDecision(request_id, approved, command, target, user_id)


def verify_slack_signature(
    raw_body: bytes, headers: Mapping[str, str], signing_secret: str, *, now: int | None = None
) -> bool:
    """Verify Slack's v0 HMAC over the unmodified request body."""
    if not signing_secret or len(raw_body) > 65536:
        return False
    lower = {key.lower(): value for key, value in headers.items()}
    timestamp = lower.get("x-slack-request-timestamp", "")
    supplied = lower.get("x-slack-signature", "")
    try:
        stamp = int(timestamp)
        if not timestamp.isascii() or not timestamp.isdecimal():
            return False
    except ValueError:
        return False
    if abs((int(time.time()) if now is None else now) - stamp) > 300:
        return False
    base = b"v0:" + timestamp.encode("ascii") + b":" + raw_body
    expected = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, supplied)


def handle_slack_interaction(
    raw_body: bytes,
    headers: Mapping[str, str],
    signing_secret: str,
    store: ApprovalStore,
) -> ApprovalDecision:
    """Authenticate one Block Kit button event and consume its request ID."""
    if not verify_slack_signature(raw_body, headers, signing_secret):
        raise PermissionError("Invalid Slack signature or timestamp")
    form = parse_qs(raw_body.decode("utf-8"), strict_parsing=True)
    if len(form.get("payload", ())) != 1:
        raise ValueError("Expected one Slack payload")
    payload = json.loads(form["payload"][0])
    if not isinstance(payload, dict) or payload.get("type") != "block_actions":
        raise ValueError("Expected a block action")
    user = payload.get("user")
    team = payload.get("team")
    channel = payload.get("channel")
    if not all(isinstance(item, dict) for item in (user, team, channel)):
        raise ValueError("Slack identity fields are missing")
    user_id = user.get("id")
    team_id = team.get("id")
    channel_id = channel.get("id")
    if not all(isinstance(item, str) for item in (user_id, team_id, channel_id)):
        raise ValueError("Slack identity fields must be strings")
    if (team_id != store.policy.team_id or channel_id != store.policy.channel_id
            or user_id not in store.policy.allowed_user_ids):
        raise PermissionError("Slack workspace, channel, or user is not authorized")
    actions = payload.get("actions")
    if not isinstance(actions, list) or len(actions) != 1 or not isinstance(actions[0], dict):
        raise ValueError("Expected one button action")
    action_id = actions[0].get("action_id")
    if action_id not in {"ice_gate_approve", "ice_gate_deny"}:
        raise ValueError("Unknown ICE Gate action")
    request_id = actions[0].get("value")
    if not isinstance(request_id, str):
        raise ValueError("Missing approval request ID")
    return store.decide(request_id, action_id == "ice_gate_approve", user_id)
