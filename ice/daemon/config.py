"""Daemon configuration: environment first, then non-secret keys from the repo `.env`.

Secrets (Slack tokens, the MCP bearer token) are read where they are used and never logged.
"""
from __future__ import annotations

import os
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Tuple

REPO = Path(__file__).resolve().parents[2]
ENV_FILE = Path(os.environ.get("ICE_ENV_FILE", REPO / ".env"))


def load_env_file(path: Path = ENV_FILE) -> Dict[str, str]:
    """Parse `key=value` lines; keys may contain hyphens (this repo's .env uses them)."""
    out: Dict[str, str] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*?)\s*$", line)
            if m and not line.lstrip().startswith("#"):
                out[m[1]] = m[2]
    return out


def _get(env: Dict[str, str], name: str, file_key: str, default: str = "") -> str:
    return os.environ.get(name) or env.get(file_key) or default


@dataclass
class Config:
    hostname: str
    state_dir: Path
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8083
    snapshot_interval_s: float = 30.0
    warmup_cycles: int = 2
    sandbox: str = "ice"
    # Slack (non-secret identifiers; tokens are looked up separately)
    slack_team_id: str = ""
    slack_alert_channel: str = ""          # channel ID for alerts + ICE Gate cards
    slack_approver_ids: Tuple[str, ...] = ()
    # Safety policy facts the decision model cannot infer (plan §3.4)
    critical_assets: Tuple[str, ...] = ()
    extra: Dict[str, str] = field(default_factory=dict)

    @property
    def slack_ready(self) -> bool:
        return bool(self.slack_team_id and self.slack_alert_channel and self.slack_approver_ids)


def load() -> Config:
    env = load_env_file()
    state = Path(os.environ.get("ICE_STATE_DIR", Path.home() / "ice-state"))
    approvers = tuple(x for x in re.split(r"[,\s]+", _get(env, "ICE_SLACK_APPROVERS", "slack-allowed-users")) if x)
    default_assets = (
        # ICE itself and the services it depends on
        "ice", "ice-daemon", "/home/dell/ICE", "/home/dell/ice-envs", "/home/dell/ice_models",
        "vllm", "kev", "nginx", "openshell", "nemoclaw", "osqueryd", "8000", "8010", "8083", "8443",
        # environment: default gateway and the sandbox bridge
        "192.168.40.1", "172.18.0.1",
    )
    assets = tuple(x for x in re.split(r"[,\s]+", _get(env, "ICE_CRITICAL_ASSETS", "ice-critical-assets")) if x)
    return Config(
        hostname=socket.gethostname(),
        state_dir=state,
        mcp_port=int(os.environ.get("ICE_MCP_PORT", "8083")),
        snapshot_interval_s=float(os.environ.get("ICE_SNAPSHOT_INTERVAL", "30")),
        warmup_cycles=int(os.environ.get("ICE_WARMUP_CYCLES", "2")),
        sandbox=os.environ.get("NEMOCLAW_SANDBOX_NAME", "ice"),
        slack_team_id=_get(env, "ICE_SLACK_TEAM_ID", "slack-team-id"),
        slack_alert_channel=_get(env, "ICE_SLACK_CHANNEL", "slack-allowed-channels").split(",")[0].strip(),
        slack_approver_ids=approvers,
        critical_assets=assets or default_assets,
    )


def secret(file_key: str, env_name: Optional[str] = None) -> str:
    """Read a secret from the environment or .env. Never print the return value."""
    return (env_name and os.environ.get(env_name)) or load_env_file().get(file_key, "")
