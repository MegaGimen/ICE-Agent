"""ICE must not be able to take itself apart.

    python3 -m pytest tests/test_selfaware.py        (or run this file directly)

The case this exists for: seeing sustained outbound HTTPS to an address with no history on the box,
ICE concluded C2 and ran `iptables -I OUTPUT -d 43.161.253.230 -j DROP`, auto-approved. That address
serves its own model. It did it twice.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ice.daemon import selfaware                      # noqa: E402
from ice.daemon.safety.gate import SafetyGate, SafetyPolicy  # noqa: E402

RELAY = "https://api.ideastead.com/v1"


def _configured(**extra):
    os.environ["ICE_AGENT_BASE_URL"] = RELAY
    os.environ.update(extra)


def test_footprint_comes_from_the_configuration() -> None:
    _configured(ICE_MCP_PORT="8083")
    assets = selfaware.assets()
    assert "api.ideastead.com" in assets           # the host it was configured with
    assert "8083" in assets                        # its own port
    assert "openclaw" in assets and "osqueryd" in assets
    assert any(a.startswith("/") for a in assets)  # where it lives, derived from what is running
    # The addresses are resolved, so a command naming the IP rather than the name is also covered.
    e = [x for x in selfaware.endpoints() if x["host"] == "api.ideastead.com"]
    assert e and e[0]["addresses"], "the endpoint resolved to nothing"


def test_prompt_states_it_and_is_not_hand_written() -> None:
    _configured()
    from ice.daemon.investigate import prompts
    role = prompts.role()
    assert "api.ideastead.com" in role
    assert "not a C2 beacon" in role
    # The paragraph this replaced named an nginx proxy, a vLLM server and /home/dell paths that
    # exist nowhere in this deployment, and never mentioned the model endpoints at all.
    assert "/home/dell" not in role and "nginx" not in role
    # Rule 5 recommends an iptables DROP as a good remediation form; it now carries the caveat.
    assert "blocking it ends this investigation" in role


def test_gate_refuses_blocking_its_own_model() -> None:
    """The deterministic backstop. The gate matches assets against every argument of a command."""
    _configured()
    policy = SafetyPolicy(authorized_targets=("ice-target",), bound_target="ice-target",
                          critical_assets=selfaware.assets(), deny_critical_assets=True)
    gate = SafetyGate(policy)

    # The address is taken from what the configuration resolves to now, not written down. The
    # incident's own IP was hardcoded here and the test passed only while DNS still returned it:
    # api.ideastead.com moved, and this started failing on a change that had nothing to do with it.
    resolved = [a for e in selfaware.endpoints() for a in (e.get("addresses") or [])]
    assert resolved, "the configured endpoint resolved to nothing, so there is nothing to protect"
    suicide = gate.safety_gate(
        {"command": f"iptables -I OUTPUT -d {resolved[0]} -j DROP", "target": "ice-target"},
        "block the C2 address")
    assert suicide.decision == "DENY", suicide
    assert "critical asset" in (suicide.reason or "").lower()

    # By name as well as by address.
    by_name = gate.safety_gate(
        {"command": "iptables -I OUTPUT -d api.ideastead.com -j DROP", "target": "ice-target"},
        "block the C2 host")
    assert by_name.decision == "DENY"

    # And killing its own agent.
    kill = gate.safety_gate({"command": "pkill openclaw", "target": "ice-target"},
                            "kill the suspicious process")
    assert kill.decision == "DENY"

    # Remediation that has nothing to do with ICE must not be caught by this: a gate that refuses
    # everything is the same as ICE doing nothing. It still needs approval, and this bare gate has
    # no approval channel, so the test is on *why* it was refused rather than on whether it was.
    real = gate.safety_gate({"command": "rm -f /etc/cron.d/persistevil", "target": "ice-target"},
                            "remove the persistence")
    assert "critical asset" not in (real.reason or "").lower(), real
    assert real.reason == "Approval channel is unavailable"   # it got as far as needing a human


if __name__ == "__main__":
    test_footprint_comes_from_the_configuration()
    test_prompt_states_it_and_is_not_hand_written()
    test_gate_refuses_blocking_its_own_model()
    print("ok: footprint derived, stated in the prompt, and refused by the gate")
