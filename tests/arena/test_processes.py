import time

import pytest

from arena.processes import ManagedWorker, StaleIdentity


def test_stop_restart_disable_and_verify_real_owned_process():
    with ManagedWorker(lifetime_seconds=4) as worker:
        first = worker.snapshot()
        assert first["alive"]
        assert first["start_ticks"] is not None
        assert not worker.stop(first["identity"])["alive"]
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline and worker.snapshot()["generation"] == first["generation"]:
            time.sleep(.02)
        second = worker.snapshot()
        assert second["alive"] and second["generation"] > first["generation"]
        with pytest.raises(StaleIdentity):worker.stop(first["identity"])
        assert worker.snapshot()["alive"]
        worker.disable_restart(second["identity"])
        worker.stop(second["identity"])
        time.sleep(.15)
        final = worker.snapshot()
        assert not final["alive"] and final["generation"] == second["generation"]


def test_worker_has_a_hard_lifetime_and_rejects_arbitrary_pid():
    with ManagedWorker(lifetime_seconds=.15) as worker:
        with pytest.raises(StaleIdentity):worker.stop("1")
        time.sleep(.3)
        assert not worker.snapshot()["alive"]
        assert not worker.snapshot()["restart_enabled"]
