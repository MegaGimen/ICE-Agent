"""An attacker-created account can be pointed at somebody else's home.

    python3 -m pytest tests/test_shared_home.py

`useradd -g 0 -M -d /root butter` is the whole trick. osquery then reads /root/.ssh/authorized_keys
for butter too and reports root's one key under both names, so a change entry about "butter's SSH
key" names a file that belongs to root and holds root's key. Deterministic containment used to turn
that into `rm -f /root/.ssh/authorized_keys` and `userdel -r butter` -- the first deletes the real
owner's key, the second deletes the real owner's home -- with no model in the loop to blame.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ice.daemon import remediate                                  # noqa: E402
from ice.daemon.contracts import ChangeEntry, ChangeType, Provenance  # noqa: E402

KEY = "549e2b4f3859"


def _fake_osquery(monkey, *, accounts, keyed_users):
    """Stand in for osquery: `accounts` maps username -> home, `keyed_users` have authorized keys."""
    def run_query(sql: str):
        s = " ".join(sql.split())
        if "FROM users u JOIN authorized_keys" in s:
            return [{"1": 1}] if any(f"'{u}'" in s for u in keyed_users) else []
        if "SELECT directory FROM users WHERE username=" in s:
            for u, home in accounts.items():
                if f"'{u}'" in s:
                    return [{"directory": home}]
            return []
        if "SELECT username FROM users WHERE directory =" in s:
            return [{"username": u} for u, home in accounts.items() if f"'{home}'" in s]
        if "SELECT 1 FROM users WHERE username =" in s:
            return [{"1": 1}] if any(f"'{u}'" in s for u in accounts) else []
        return []
    monkey.setattr(remediate, "run_query", run_query)


def _ssh_entry() -> ChangeEntry:
    return ChangeEntry(type=ChangeType.SSH_KEY, table="ssh_keys", field=f"butter#{KEY}",
                       value=f"added: SSH authorized key for butter", provenance=Provenance(user="butter"),
                       untrusted={"key_file": "/root/.ssh/authorized_keys", "comment": "ice-vm"})


def _account_entry() -> ChangeEntry:
    return ChangeEntry(type=ChangeType.ACCOUNT, table="accounts", field="butter",
                       value="added: account butter uid=1001", provenance=Provenance(user="root"))


def test_a_key_file_in_somebody_elses_home_is_left_alone(monkeypatch) -> None:
    _fake_osquery(monkeypatch, accounts={"butter": "/root", "root": "/root"}, keyed_users={"butter"})
    assert remediate._containment(_ssh_entry()) is None


def test_the_account_still_goes_but_without_r(monkeypatch) -> None:
    _fake_osquery(monkeypatch, accounts={"butter": "/root", "root": "/root"}, keyed_users={"butter"})
    a = remediate._containment(_account_entry())
    assert a is not None and a.command == "userdel butter"
    assert "-r" not in a.command.split()
    assert "/root" in a.intent                       # the human is told what was left behind


def test_an_account_with_its_own_home_is_removed_whole(monkeypatch) -> None:
    _fake_osquery(monkeypatch, accounts={"evil": "/home/evil", "root": "/root"}, keyed_users={"evil"})
    a = remediate._containment(_account_entry().__class__(
        type=ChangeType.ACCOUNT, table="accounts", field="evil", value="added: account evil",
        provenance=Provenance(user="root")))
    assert a is not None and a.command == "userdel -r evil"


def test_a_key_file_in_the_accounts_own_home_is_removed(monkeypatch) -> None:
    _fake_osquery(monkeypatch, accounts={"evil": "/home/evil", "root": "/root"}, keyed_users={"evil"})
    e = ChangeEntry(type=ChangeType.SSH_KEY, table="ssh_keys", field=f"evil#{KEY}",
                    value="added: SSH authorized key for evil", provenance=Provenance(user="evil"),
                    untrusted={"key_file": "/home/evil/.ssh/authorized_keys"})
    a = remediate._containment(e)
    assert a is not None and a.command == "rm -f /home/evil/.ssh/authorized_keys"


def test_the_prompt_says_what_two_rows_with_one_hash_mean() -> None:
    src = (Path(__file__).resolve().parents[1]
           / "ice" / "daemon" / "investigate" / "prompts.py").read_text()
    assert "one key in one file" in src
    assert "never remove a key file that holds a key" in src


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
