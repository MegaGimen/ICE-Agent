"""Wake the OpenClaw agent for a case (plan.md §6.1/§6.2): `nemoclaw <sandbox> agent
--session-key <case_id> --json -m <message>`, one session per case so follow-ups (approval
results, explanations) land in the same conversation.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

log = logging.getLogger("ice.agent")

NC = Path(os.environ.get("ICE_NC", Path(__file__).resolve().parents[3] / "ice" / "serving" / "nc.sh"))
SANDBOX = os.environ.get("NEMOCLAW_SANDBOX_NAME", "ice")
# The sandbox is registered under this user's NemoClaw state (~/.nemoclaw, nvm node). When the daemon runs
# as root (plan §6.1), agent wake-ups drop to that user instead of running nemoclaw as root.
AGENT_USER = os.environ.get("ICE_AGENT_USER", "dell")


@dataclass
class AgentReply:
    ok: bool
    text: str = ""
    tools: List[str] = field(default_factory=list)
    stop: Optional[str] = None
    error: Optional[str] = None
    seconds: float = 0.0
    tokens_in: int = 0
    tokens_out: int = 0


def wake(session_key: str, message: str, timeout: float = 900.0) -> AgentReply:
    t = time.time()
    argv = [str(NC), SANDBOX, "agent", "--session-key", session_key, "--json", "-m", message]
    if os.geteuid() == 0 and AGENT_USER:
        argv = ["sudo", "-u", AGENT_USER, "-H", "--"] + argv
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return AgentReply(False, error=f"agent timed out after {timeout:.0f}s", seconds=time.time() - t)
    out = p.stdout
    start = out.find("{")
    if start < 0:
        return AgentReply(False, error=f"no JSON from agent (exit {p.returncode}): {p.stderr.strip()[-400:]}",
                          seconds=time.time() - t)
    try:
        j = json.loads(out[start:])
    except json.JSONDecodeError as e:
        return AgentReply(False, error=f"bad agent JSON: {e}", seconds=time.time() - t)
    r = j.get("result") or {}
    meta = r.get("meta") or {}
    am = meta.get("agentMeta") or {}
    usage = am.get("usage") or {}
    text = "\n".join(pl.get("text", "") for pl in r.get("payloads") or [] if pl.get("text"))
    err = meta.get("error")
    reply = AgentReply(
        ok=err is None and meta.get("stopReason") != "length",
        text=text,
        tools=list((am.get("terminalReceipt") or {}).get("successfulToolNames") or []),
        stop=meta.get("stopReason"),
        error=(err.get("message") if isinstance(err, dict) else err) or (
            "reply truncated at output token limit" if meta.get("stopReason") == "length" else None),
        seconds=round(time.time() - t, 1),
        tokens_in=int(usage.get("input") or 0),
        tokens_out=int(usage.get("output") or 0),
    )
    log.info("agent %s: ok=%s %.1fs tools=%s", session_key, reply.ok, reply.seconds, reply.tools)
    return reply
