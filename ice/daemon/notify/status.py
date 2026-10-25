"""Service status messages to Slack, so startup order and failures are visible in one place.

Used by the systemd units (ExecStartPre / ExecStartPost / OnFailure) and by the daemon itself:

  python -m ice.daemon.notify.status <component> <starting|ready|failed|stopping|degraded|recovered> [detail]

Standard library only, so it works before any other ICE service is up. English text (Slack rule).
Never raises: a status message must not change whether a service starts.
"""
from __future__ import annotations

import json
import socket
import sys
import urllib.request

from ice.daemon.config import load, secret

ICON = {"starting": ":hourglass_flowing_sand:", "ready": ":large_green_circle:", "online": ":white_check_mark:",
        "failed": ":red_circle:", "stopping": ":black_square_for_stop:", "degraded": ":warning:",
        "recovered": ":large_green_circle:", "waiting": ":hourglass_flowing_sand:"}


def post(component: str, event: str, detail: str = "") -> bool:
    try:
        conf = load()
        token = secret("slack-bot-token", "SLACK_BOT_TOKEN")
        if not token or not conf.slack_alert_channel:
            return False
        text = f"{ICON.get(event, ':information_source:')} *ICE status* · `{socket.gethostname()}` · *{component}* {event}"
        if detail:
            text += f" — {detail}"
        body = json.dumps({"channel": conf.slack_alert_channel, "text": text, "unfurl_links": False}).encode()
        req = urllib.request.Request("https://slack.com/api/chat.postMessage", data=body, method="POST",
                                     headers={"content-type": "application/json; charset=utf-8",
                                              "authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return bool(json.load(r).get("ok"))
    except Exception:  # noqa: BLE001
        return False


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) < 2:
        print("usage: python -m ice.daemon.notify.status <component> <event> [detail]", file=sys.stderr)
        sys.exit(0)
    post(a[0].removesuffix(".service"), a[1], " ".join(a[2:]))
