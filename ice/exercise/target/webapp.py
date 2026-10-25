"""Exercise target: a deliberately vulnerable "internal web app" (plan §5 / §8.2 靶机).

It runs as the low-privilege service account `websvc`, binds 127.0.0.1 ONLY, and executes
whatever a client sends it — a stand-in for an RCE/webshell. This exists so an authorized
drill can make a *service account* (not the developer) perform the intrusion, giving ICE
realistic provenance: the malicious cron / SSH key / shell are created by websvc, whose
parent process is this app, with no `sudo`/developer/`ice.exercise.*` fingerprint.

Loopback-only and torn down after the drill. Never expose this off the host.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys

HOST = "127.0.0.1"
PORT = int(os.environ.get("VICTIM_PORT", "9009"))


def serve() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(4)
    sys.stderr.write(f"[webapp] listening on {HOST}:{PORT} as uid={os.getuid()}\n")
    sys.stderr.flush()
    while True:
        conn, _ = srv.accept()
        with conn:
            data = conn.recv(65536).decode(errors="replace")
            for line in data.splitlines():
                line = line.strip()
                if not line:
                    continue
                # The "vulnerability": the app runs attacker-supplied input in a shell.
                p = subprocess.run(line, shell=True, capture_output=True, text=True)
                conn.sendall((p.stdout + p.stderr).encode()[:65536])


if __name__ == "__main__":
    serve()
