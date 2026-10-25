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

    if a.replay:
        from ice.fixtures.gate_cases import CASES
        wanted = [n.strip() for n in a.replay.split(",") if n.strip()]
        entries = [e for name, _, e in CASES if name in wanted]
        missing = set(wanted) - {name for name, _, _ in CASES}
        if missing:
            raise SystemExit(f"unknown fixtures: {sorted(missing)}")
        orch.inject(entries)
        rt.audit.write("replay", fixtures=wanted)
        log.info("replaying %d synthetic entries: %s", len(entries), wanted)

    if a.once:
        import time
        started = time.time()
        orch.cycle()

        def waiting() -> bool:   # this run's ASKs only, until the approval TTL runs out
            return any(p.status == "pending" and p.created >= started and time.time() - p.created < 600
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
