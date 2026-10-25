"""ICE host daemon entry point (plan.md §6.1): one process hosts the MCP server, the ICE Gate
listener, and the orchestrator loop, so pending approvals, the current case, and the tool
budget are shared in memory on the host.

  python -m ice.daemon.main                  # run forever (plan: as root)
  python -m ice.daemon.main --once           # one perception cycle, then exit
  python -m ice.daemon.main --replay cron_curl_pipe_sh
        # also feed labeled synthetic change entries (ice/fixtures/gate_cases.py) into the first
        # cycle: exercises the whole pipeline on data only, nothing is done to the host first.

Emergency stop (plan §3.4): while <state_dir>/KILL exists, every host_exec is denied.
"""
from __future__ import annotations

import argparse
import logging
import os
import signal
import threading

from ice.daemon.mcp_server import build_app, mcp_token
from ice.daemon.orchestrator import Notifier, Orchestrator
from ice.daemon.runtime import Runtime

log = logging.getLogger("ice.main")


def _start_mcp(rt: Runtime) -> None:
    import uvicorn
    app, _ = build_app(rt, mcp_token())
    server = uvicorn.Server(uvicorn.Config(app, host=rt.conf.mcp_host, port=rt.conf.mcp_port, log_level="warning"))
    threading.Thread(target=server.run, name="mcp", daemon=True).start()
    log.info("MCP server on http://%s:%s/mcp", rt.conf.mcp_host, rt.conf.mcp_port)


HEALTH = {
    "vLLM": "http://localhost:8000/health",
    "Kev": "http://localhost:8010/v1/models",
    "embedding service": "http://127.0.0.1:8020/health",
}


def _up(url: str) -> bool:
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status == 200
    except Exception:  # noqa: BLE001
        return False


def _mcp_proxy_up() -> bool:
    import socket
    try:
        with socket.create_connection((os.environ.get("ICE_MCP_PRIVATE_IP", "172.18.0.1"), 8443), timeout=3):
            return True
    except OSError:
        return False


def _health() -> dict:
    h = {name: _up(url) for name, url in HEALTH.items()}
    h["MCP proxy"] = _mcp_proxy_up()
    return h


def _wait_for_models(stop: threading.Event, timeout: float = 1800) -> bool:
    """The orchestrator must not start cycles against missing models: every change would be escalated
    unjudged and every investigation would fail. Wait (and say so once) until vLLM and Kev answer."""
    import time
    from ice.daemon.notify import status
    t0, told = time.time(), False
    while not stop.is_set():
        h = _health()
        if h["vLLM"] and h["Kev"]:
            return True
        if not told:
            status.post("daemon", "waiting", "models not ready: " + ", ".join(k for k in ("vLLM", "Kev") if not h[k]))
            told = True
        if time.time() - t0 > timeout:
            status.post("daemon", "failed", f"models still not ready after {timeout:.0f}s")
            return False
        stop.wait(10)
    return False


def _watch_health(stop: threading.Event, interval: float = 60) -> None:
    """Report each component going down or coming back once, instead of failing silently."""
    from ice.daemon.notify import status
    last = _health()
    while not stop.wait(interval):
        now = _health()
        for name, up in now.items():
            if up != last.get(name):
                status.post(name, "recovered" if up else "degraded",
                            "answering again" if up else "not answering; ICE keeps monitoring, affected steps degrade")
        last = now


def _watch_kill_switch(rt: Runtime, stop: threading.Event) -> None:
    flag = rt.conf.state_dir / "KILL"
    state = None
    while not stop.is_set():
        on = flag.exists()
        if on != state:
            rt.kill_switch(on)
            log.warning("kill switch %s", "ON: all host_exec denied" if on else "off")
            state = on
        stop.wait(1.0)


def main() -> None:
    ap = argparse.ArgumentParser(description="ICE host daemon")
    ap.add_argument("--once", action="store_true", help="run one cycle and exit (cases still complete)")
    ap.add_argument("--replay", default="", help="comma-separated synthetic fixture names to inject")
    ap.add_argument("--no-slack", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    rt = Runtime()
    notifier: Notifier = Notifier()
    listener = None
    if rt.conf.slack_ready and not a.no_slack:
        from ice.daemon.notify.slack import IceGateListener, SlackNotifier
        notifier = SlackNotifier(rt.conf)
    orch = Orchestrator(rt, notifier)
    if rt.conf.slack_ready and not a.no_slack:
        listener = IceGateListener(rt, notifier, orch.on_approval)
        listener.start()

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    threading.Thread(target=_watch_kill_switch, args=(rt, stop), name="kill-switch", daemon=True).start()
    _start_mcp(rt)
    if not a.once and not a.replay:   # resident service: report readiness and keep watching health
        from ice.daemon.notify import status
        if not _wait_for_models(stop):
            return
        h = _health()
        graph = rt.graph.stats() if rt.graph else {}
        status.post("daemon", "online", "monitoring every %.0fs · %s · approvals %s · graph %d cases · kill switch %s" % (
            rt.conf.snapshot_interval_s, ", ".join(f"{k} {'up' if v else 'DOWN'}" for k, v in h.items()),
            "via ICE Gate" if rt.approvals else "NOT configured (ASK -> DENY)", graph.get("Incident", 0),
            "ON" if (rt.conf.state_dir / "KILL").exists() else "off"))
        threading.Thread(target=_watch_health, args=(stop,), name="health", daemon=True).start()
        signal.signal(signal.SIGTERM, lambda *_: (status.post("daemon", "stopping", "SIGTERM"), stop.set()))

    if a.replay:
        from ice.fixtures.gate_cases import CASES
        wanted = [n.strip() for n in a.replay.split(",") if n.strip()]
        entries = [e for name, _, e in CASES if name in wanted]
        missing = set(wanted) - {name for name, _, _ in CASES}
        if missing:
            raise SystemExit(f"unknown fixtures: {sorted(missing)}")
        warm = max(2, rt.conf.warmup_cycles)
        # Synthetic events must never drive real changes: replay runs dry unless explicitly overridden.
        rt.dry_run = os.environ.get("ICE_REPLAY_LIVE") != "1"
        orch.inject(entries, min_cycle=warm)
        rt.audit.write("replay", fixtures=wanted)
        log.info("replaying %d synthetic entries after %d real cycles (%s): %s", len(entries), warm,
                 "DRY RUN, nothing executed" if rt.dry_run else "LIVE", wanted)

    if a.once:
        import time
        started = time.time()
        orch.cycle()
        while orch.injection_pending and not stop.is_set():   # real cycles first, so the replay has a T0
            stop.wait(5.0)
            orch.cycle()

        ttl = rt.approvals.policy.request_ttl_seconds if rt.approvals else 600

        def waiting() -> bool:   # this run's ASKs only, until the approval TTL runs out
            return any(p.status == "pending" and p.created >= started and time.time() - p.created < ttl
                       for p in rt.pending.items.values())
        if listener and waiting():
            log.info("waiting for ICE Gate decisions (Ctrl-C to stop)")
            try:
                while not stop.is_set() and waiting():
                    stop.wait(2.0)
            except KeyboardInterrupt:
                pass
            orch.sweep_expired()   # close out cases whose ASKs ran out unanswered
        orch.join_background(timeout=600)   # let approval follow-ups and backward finish before exiting
        return
    try:
        orch.run_forever(stop)
    except KeyboardInterrupt:
        stop.set()


if __name__ == "__main__":
    main()
