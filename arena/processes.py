"""Identity-bound process control for controller-owned, benign test workers only.

No arbitrary PID, shell command or malware sample is accepted. This tests process-control
semantics and restart verification; it is not a host malware detector or a QEMU backend.
"""
from __future__ import annotations

import math
from pathlib import Path
import subprocess
import sys
import threading
import time
import uuid


class StaleIdentity(ValueError):
    pass


class ManagedWorker:
    def __init__(self, lifetime_seconds=3.0, restart=True):
        if not math.isfinite(lifetime_seconds) or not 0 < lifetime_seconds <= 10:
            raise ValueError("test-worker lifetime must be in (0, 10] seconds")
        self.lock = threading.RLock()
        self.deadline = time.monotonic() + lifetime_seconds
        self.restart = bool(restart)
        self.generation = 0
        self.process = None
        self.identity = None
        self.done = threading.Event()
        self._spawn()
        self.thread = threading.Thread(target=self._watch, daemon=True)
        self.thread.start()

    def _spawn(self):
        # Bounded arithmetic work, no network, filesystem mutation, fork or imported sample.
        code = "import time\nend=time.monotonic()+10\nwhile time.monotonic()<end:\n sum(i*i for i in range(20000))\n time.sleep(.01)\n"
        self.process = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.DEVNULL,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        start_new_session=True)
        self.generation += 1
        self.identity = uuid.uuid4().hex

    def _watch(self):
        while not self.done.wait(.02):
            with self.lock:
                if time.monotonic() >= self.deadline:
                    self.restart = False
                    self._terminate()
                    self.done.set()
                    return
                if self.process.poll() is not None and self.restart:
                    self._spawn()

    def snapshot(self):
        with self.lock:
            alive = self.process.poll() is None
            start_ticks = cpu_ticks = None
            if alive:
                try:
                    fields = Path(f"/proc/{self.process.pid}/stat").read_text().rsplit(")", 1)[1].split()
                    start_ticks = int(fields[19])
                    cpu_ticks = int(fields[11]) + int(fields[12])
                except (OSError, ValueError, IndexError):
                    pass
            return {"identity": self.identity, "pid": self.process.pid, "alive": alive,
                    "start_ticks": start_ticks, "cpu_ticks": cpu_ticks,
                    "generation": self.generation, "restart_enabled": self.restart,
                    "scope": "controller-owned benign fixture process"}

    def _check(self, observed_identity):
        if observed_identity != self.identity:
            raise StaleIdentity("process generation changed; collect a fresh identity")

    def _terminate(self):
        # This Popen child remains ours; polling/reaping and signalling are serialized.
        # An arbitrary historical PID cannot enter this path.
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=.5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=.5)

    def stop(self, observed_identity):
        with self.lock:
            self._check(observed_identity)
            self._terminate()
            return self.snapshot()

    def disable_restart(self, observed_identity):
        with self.lock:
            self._check(observed_identity)
            self.restart = False
            return self.snapshot()

    def close(self):
        self.done.set()
        self.thread.join(timeout=1)
        with self.lock:
            self.restart = False
            self._terminate()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
