"""What ICE is, so it does not take itself apart.

An agent defending a host is a process on that host, talking to a model over the network. Both of
those look exactly like what it is hunting. It has done it twice: seeing sustained outbound HTTPS to
an address with no history on the box, it concluded C2 (T1071.001, confidence 0.78, blast_radius
['43.161.253.230', 'butter']) and ran `iptables -I OUTPUT -d 43.161.253.230 -j DROP`. That address
serves its own model. The investigation it was in the middle of then ran 200 seconds, used no tools
and reached no conclusion.

The investigation prompt already carried a paragraph of ICE's own components, but hand-written and
by then years stale -- it named an nginx proxy, a vLLM server and paths under /home/dell that no
longer exist anywhere, and it never mentioned the model endpoints at all. So this derives the list
from ICE's own configuration instead: the interpreter running it, the repository it was imported
from, its state directory, its ports, and the hosts behind every endpoint it was configured with.
Self-knowledge rather than a list someone has to remember to update.

Two places use it. The investigation prompt says what these are, so the agent does not propose
disabling them. The safety gate takes them as critical assets, which it matches against every
argument of a command, so a proposal that slipped through the prompt is refused instead of run.

The trade-off is real and worth stating: ICE can no longer quarantine the address its own model
answers on, even if that address were genuinely hostile. You cannot both depend on an endpoint and
be able to cut it off. What the gate does instead of silently allowing it is refuse and record the
refusal, which leaves the proposal visible in the trace rather than hidden or executed.
"""
from __future__ import annotations

import os
import socket
import sys
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlsplit

# Endpoints ICE may be configured with, and what each one is for. The value is the environment
# variable; anything unset is simply not part of the footprint.
ENDPOINT_VARS: Tuple[Tuple[str, str], ...] = (
    ("decision model", "KEV_URL"),
    ("decision model", "ICE_KEV_URL"),
    ("investigating agent's model", "ICE_AGENT_BASE_URL"),
    ("main model", "ICE_MAIN_MODEL_BASE_URL"),
    ("embedding service", "ICE_EMBED_URL"),
)

# Process and service names belonging to ICE or to the agent it dispatches.
OWN_PROCESSES: Tuple[str, ...] = (
    "osqueryd", "osqueryi", "openclaw", "node", "ice-daemon", "ice.daemon.main",
)


def _host(url: str) -> str:
    try:
        parts = urlsplit(url if "//" in url else "//" + url)
        return parts.hostname or ""
    except ValueError:
        return ""


def _resolve(host: str) -> List[str]:
    if not host or host.replace(".", "").isdigit():
        return [host] if host else []
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    return sorted({i[4][0] for i in infos})


def endpoints() -> List[Dict[str, object]]:
    """Every endpoint ICE was configured with, resolved. One entry per distinct URL."""
    seen: Dict[str, Dict[str, object]] = {}
    for purpose, var in ENDPOINT_VARS:
        url = (os.environ.get(var) or "").strip()
        if not url:
            continue
        host = _host(url)
        if not host or host in ("localhost", "127.0.0.1", "::1"):
            continue                              # local services are covered by paths and ports
        entry = seen.setdefault(host, {"purpose": purpose, "host": host, "url": url,
                                       "addresses": _resolve(host)})
        if purpose not in str(entry["purpose"]):
            entry["purpose"] = f"{entry['purpose']}, {purpose}"
    return list(seen.values())


def paths() -> List[str]:
    """Where ICE and the agent live on disk, derived from what is actually running."""
    import ice
    out = [str(Path(ice.__file__).resolve().parents[1]),          # the repository
           str(Path(sys.executable).resolve().parents[1]),        # the interpreter's root
           os.environ.get("ICE_STATE_DIR", "") or str(Path.home() / "ice-state"),
           os.environ.get("ICE_RUN_DIR", "/root/ice-build"),
           os.environ.get("OPENCLAW_HOME", "") or str(Path.home() / ".openclaw")]
    for var in ("ICE_NC", "ICE_OPENCLAW_BIN", "ICE_DAEMON_PY"):
        val = os.environ.get(var)
        if val and val.startswith("/"):
            out.append(str(Path(val).resolve().parent))
    return sorted({p for p in out if p and p != "/"})


def ports() -> List[str]:
    return sorted({os.environ.get("ICE_MCP_PORT", "8083"),
                   os.environ.get("ICE_DASHBOARD_PORT", "8088")})


def assets() -> Tuple[str, ...]:
    """The footprint as the safety gate wants it: paths, ports, process names and addresses."""
    out: List[str] = list(paths()) + ports() + list(OWN_PROCESSES)
    for e in endpoints():
        out.append(str(e["host"]))
        out.extend(str(a) for a in e["addresses"])          # type: ignore[arg-type]
    return tuple(sorted(set(out)))


def describe() -> str:
    """The paragraph the investigation prompt carries, built from the live configuration."""
    lines = ["These are ICE's own components. They are not attack evidence and must never be "
             "targeted, disabled, killed or blocked, however they look:"]
    for e in endpoints():
        addrs = ", ".join(str(a) for a in e["addresses"]) or "unresolved"  # type: ignore[arg-type]
        lines.append(f"  - {e['host']} ({addrs}) — {e['purpose']}. Outbound HTTPS to this address "
                     f"is ICE's own traffic, not a C2 beacon. Blocking it disables ICE, including "
                     f"this investigation.")
    lines.append(f"  - the processes {', '.join(OWN_PROCESSES)}, and ICE's own listening ports "
                 f"{', '.join(ports())}.")
    lines.append(f"  - everything under {', '.join(paths())}.")
    lines.append("If the evidence genuinely points at one of these, say so in your findings and "
                 "leave it out of proposed_actions: a human has to decide, and the safety gate "
                 "will refuse the action anyway.")
    return "\n".join(lines)
