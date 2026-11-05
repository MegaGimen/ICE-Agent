"""Addressing "the VM" has to mean this episode's VM, not the first one the process booted.

    python3 -m pytest tests/test_vm_ports.py

The failure: `_PORT` is a module-level dict that accumulates across the episodes of one run, and
`ssh_port("")` answered with `next(iter(_PORT.values()))` -- the FIRST entry, by dict insertion
order. So every episode after the first in a batch was probed on the previous episode's port, on a
machine that had just been shut down. `wait_for_ssh` then timed out at 480s against a VM that was up
and answering ssh (I logged into it by hand afterwards), the episode aborted as "target lost", and a
run of three recorded one.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ice.exercise import vm  # noqa: E402

A, B = "ep-one-live", "ep-two-live"


def _two(monkeypatch) -> None:
    monkeypatch.setattr(vm, "_PORT", {A: 2222, B: 2223})


def test_the_vm_with_no_label_is_the_newest_one(monkeypatch) -> None:
    _two(monkeypatch)
    assert vm.ssh_port() == 2223
    assert vm.ssh_port(A) == 2222          # named, it is still whatever it was
    assert vm._current_label() == B


def test_the_live_vm_is_the_newest_live_one(monkeypatch) -> None:
    _two(monkeypatch)
    assert vm.live_label() == B


def test_an_ssh_command_goes_to_the_vm_it_names(monkeypatch) -> None:
    _two(monkeypatch)
    assert "-p" in vm._ssh_base(A) and vm._ssh_base(A)[vm._ssh_base(A).index("-p") + 1] == "2222"
    base_b = vm._ssh_base(B)
    assert base_b[base_b.index("-p") + 1] == "2223"


def test_the_boot_probe_asks_the_machine_it_is_waiting_for() -> None:
    """Read as text: wait_for_ssh's probe must carry the label, or it polls the wrong port."""
    src = (Path(__file__).resolve().parents[1] / "ice" / "exercise" / "vm.py").read_text()
    body = src[src.index("def wait_for_ssh"):src.index("def ssh(")]
    assert "label=label" in body


def test_a_dropped_vm_can_no_longer_be_addressed(monkeypatch) -> None:
    _two(monkeypatch)
    vm.forget_port(B)
    assert vm.ssh_port() == 2222
    assert vm._PORT == {A: 2222}


def test_no_vm_at_all_falls_back_to_the_module_default(monkeypatch) -> None:
    monkeypatch.setattr(vm, "_PORT", {})
    assert vm.ssh_port() == vm.SSH_PORT
    assert vm._current_label() == "vm"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
