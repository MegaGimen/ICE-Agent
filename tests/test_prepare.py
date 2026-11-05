"""The golden image has to come up with a working daemon, which turns on one gitignored file.

    python3 -m pytest tests/test_prepare.py

The failure this is about: `deploy/local-secrets/mcp.token` is machine-local and gitignored. A
`--delete` repo sync from a host that does not have it removes it from the image; the daemon then
raises FileNotFoundError in `mcp_token()` before it has logged anything, systemd records exit 1, and
the episode aborts with "the daemon did not come up with the machine" -- which reads like a boot
problem, not like a missing secret.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

REC = (Path(__file__).resolve().parents[1] / "ice" / "exercise" / "record.py").read_text()


def _body(start: str, end: str) -> str:
    i = REC.index(start)
    return REC[i:REC.index(end, i)]


def test_a_repo_sync_cannot_delete_the_images_own_secrets() -> None:
    body = _body("def sync_repo", "def refuse_host_daemon")
    assert '"--delete"' in body                      # still a mirror of the code under test
    assert '"deploy/local-secrets"' in body          # minus the one thing the host does not own


def test_preparing_the_image_reconciles_the_token() -> None:
    prep = _body("def prepare_image", "def push_posture")
    assert "ensure_mcp_token()" in prep
    assert prep.index("sync_repo()") < prep.index("ensure_mcp_token()")


def test_the_token_comes_from_what_the_agent_already_sends() -> None:
    """Minting a fresh one on its own would leave the agent's literal Authorization header behind
    and every tool call would come back 401 -- an agent with no tools, recorded as a trajectory."""
    body = _body("def ensure_mcp_token", "def _mcp_port")
    assert "Authorization" in body and "openclaw.json" in body
    assert "secrets.token_urlsafe" in body           # only as the fallback
    assert body.index("Authorization") < body.index("secrets.token_urlsafe")
    # and when it mints one, it writes it back to the agent's config too
    assert "'Bearer ' + tok" in body


def test_the_token_value_never_reaches_the_host() -> None:
    body = _body("def ensure_mcp_token", "def _mcp_port")
    assert "print('mcp token: %d bytes" in body      # a length and a provenance, not the value


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
    print("ok: the image carries a token the daemon and the agent agree on")
