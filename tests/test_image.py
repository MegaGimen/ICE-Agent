"""Diffing and reading two whole-filesystem snapshots, on synthetic trees.

    python3 -m pytest tests/test_image.py        (or run this file directly)

Everything here was a real bug or a real requirement:
  * directories cannot be hardlinked, so comparing them by inode called all 21,054 directories on
    the box modified;
  * `rsync -a` copies the source's timestamps, so a snapshot's mtime is the source's, not its own;
  * a deleted file has a diff but no present-day existence, so the change list is the union of
    before and after with `exists_now` read off the live machine;
  * binary files are a change like any other, as in git, not a path quietly dropped.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ice.exercise import image  # noqa: E402


def _tree(root: Path, files: dict) -> None:
    """files maps a relative path to bytes/str content, or to ("symlink", target)."""
    for rel, content in files.items():
        fp = root / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, tuple) and content[0] == "symlink":
            fp.symlink_to(content[1])
        elif isinstance(content, bytes):
            fp.write_bytes(content)
        else:
            fp.write_text(content)


def _snapshots(tmp_path: Path, before: dict, after: dict, link: bool = True) -> None:
    """Build two snapshot trees and point the module at them.

    With link=True, files identical in both are hardlinked, as --link-dest does on the real thing,
    so the inode fast path is exercised. link=False is for the cases that need two distinct inodes
    with the same content -- a hardlink shares one timestamp, so touching "the B copy" of a linked
    file changes both and there is no mtime difference left to test.
    """
    image.SNAP_ROOT = tmp_path
    for label in ("A", "B"):
        (tmp_path / label).mkdir(parents=True, exist_ok=True)
    _tree(tmp_path / "A", before)
    _tree(tmp_path / "B", after)
    if link:
        for rel, content in before.items():
            if rel in after and after[rel] == content and not isinstance(content, tuple):
                dst = tmp_path / "B" / rel
                dst.unlink()
                os.link(tmp_path / "A" / rel, dst)
    for label in ("A", "B"):
        (tmp_path / f"{label}.meta.json").write_text(json.dumps(
            {"label": label, "taken": 100.0 if label == "A" else 200.0}))


def test_diff_classifies_each_kind_of_change(tmp_path: Path) -> None:
    _snapshots(tmp_path, {
        "same.txt": "unchanged",
        "grows.txt": "small",
        "gone.txt": "deleted later",
        "deep/nested/kept.txt": "unchanged",
        "link": ("symlink", "/old/target"),
    }, {
        "same.txt": "unchanged",
        "grows.txt": "small plus more",
        "new.txt": "added later",
        "deep/nested/kept.txt": "unchanged",
        "link": ("symlink", "/new/target"),
    })
    d = image.diff("A", "B")
    assert d["added"] == ["/new.txt"]
    assert d["removed"] == ["/gone.txt"]
    assert sorted(d["modified"]) == ["/grows.txt", "/link"]
    # Directories are never reported as modified in their own right: /deep and /deep/nested get a
    # fresh inode in every snapshot because a directory cannot be hardlinked.
    assert not any(p.startswith("/deep") for p in d["modified"])
    assert d["counts"]["mtime_only"] == 0


def test_same_size_different_mtime_is_not_guessed(tmp_path: Path) -> None:
    """Equal size with a different timestamp is reported as its own group, not as modified.

    hash_check decides it by reading both copies -- the only way to tell a rewrite from a touch.
    """
    _snapshots(tmp_path, {"a.txt": "12345", "b.txt": "12345"},
               {"a.txt": "12345", "b.txt": "54321"}, link=False)
    for rel in ("a.txt", "b.txt"):
        os.utime(tmp_path / "B" / rel, (500, 500))

    d = image.diff("A", "B")
    assert sorted(d["mtime_only"]) == ["/a.txt", "/b.txt"] and d["modified"] == []

    d = image.diff("A", "B", hash_check=True)
    assert d["retouched"] == ["/a.txt"]        # same bytes, new timestamp
    assert d["modified"] == ["/b.txt"]         # same length, different bytes
    assert d["mtime_only"] == []


def test_changes_is_the_union_and_says_what_exists_now(tmp_path: Path) -> None:
    # /etc/hostname exists on the live machine; /gone.txt does not. The listing reports both, which
    # is the point of taking the union: a deletion has a diff but nothing left to look at.
    _snapshots(tmp_path, {"gone.txt": "x", "etc/hostname": "before"},
               {"etc/hostname": "after"})
    rows = {r["path"]: r for r in image.changes("A", "B")}
    assert rows["/gone.txt"]["status"] == "removed"
    assert rows["/gone.txt"]["exists_now"] is False
    assert rows["/gone.txt"]["size_before"] == 1 and rows["/gone.txt"]["size_after"] is None
    assert rows["/etc/hostname"]["status"] == "modified"
    assert rows["/etc/hostname"]["exists_now"] is os.path.lexists("/etc/hostname")


def test_show_returns_the_change_not_the_file(tmp_path: Path) -> None:
    _snapshots(tmp_path, {"conf.txt": "keep\nold line\n", "blob.bin": b"\x00\x01\xff\xfe"},
               {"conf.txt": "keep\nnew line\n", "blob.bin": b"\x00\x01\xff\x00"})

    out = image.show("A", "B", "/conf.txt")
    assert out["status"] == "modified"
    assert "-old line" in out["diff"] and "+new line" in out["diff"]
    assert "keep" in out["diff"]
    assert "text" not in out["A"]              # metadata only: the diff is the answer, not the file
    assert out["A"]["size"] == len("keep\nold line\n")

    # Binary is a change like any other: reported, with both sides' hashes, and said to be binary.
    out = image.show("A", "B", "/blob.bin")
    assert out["binary"] is True and "differ" in out["diff"]
    assert out["A"]["sha256"] != out["B"]["sha256"]


def test_show_handles_a_deletion_and_an_absent_path(tmp_path: Path) -> None:
    _snapshots(tmp_path, {"gone.txt": "line one\nline two\n"}, {})
    out = image.show("A", "B", "/gone.txt")
    assert out["status"] == "removed" and out["B"]["kind"] == "absent"
    assert "-line one" in out["diff"] and "-line two" in out["diff"]
    assert image.show("A", "B", "/never")["status"] == "absent from both"


def test_content_reads_either_snapshot_or_the_live_machine(tmp_path: Path) -> None:
    _snapshots(tmp_path, {"gone.txt": "the before bytes\n"}, {})
    # The bytes of a deleted file are still available, without restoring anything.
    before = image.content("A", "/gone.txt")
    assert before["exists"] and before["text"] == "the before bytes\n"
    assert image.content("B", "/gone.txt") == {"path": "/gone.txt", "label": "B", "exists": False}
    assert image.content("current", "/gone.txt")["exists"] is False
    assert image.content("nope", "/gone.txt")["error"].startswith("no snapshot")
    # Truncation is stated rather than silently applied.
    capped = image.content("A", "/gone.txt", max_bytes=4)
    assert capped["truncated"] is True and capped["text"] == "the "
    assert capped["size"] == 17                      # the real size, not the truncated length


def test_snapshots_are_ordered_by_when_they_were_taken(tmp_path: Path) -> None:
    """rsync -a copies the source's timestamps, so directory mtime is not take order."""
    _snapshots(tmp_path, {"a": "x"}, {"a": "x"})
    os.utime(tmp_path / "A", (900, 900))             # make A look newer on disk than B
    os.utime(tmp_path / "B", (800, 800))
    assert image.snapshots() == ["A", "B"]
    assert image.taken_at("A") == 100.0


if __name__ == "__main__":
    import tempfile
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        with tempfile.TemporaryDirectory() as d:
            fn(Path(d))
    print(f"ok: {len(tests)} image tests")


def test_file_score_separates_the_attack_from_the_agent(tmp_path: Path) -> None:
    """The attack's footprint is derived from the armed image, so it is never charged to the agent.

    Three images: healthy, the machine with the attack on it, and what the agent left behind.
    """
    from ice.exercise import snapshot_reward as sr

    image.SNAP_ROOT = tmp_path
    trees = {
        "S0": {"etc/passwd": "root\n", "etc/legal": "banner\n", "var/log/auth.log": "old\n"},
        "A1": {"etc/passwd": "root\nbutter\n", "etc/legal": "banner\n",
               "etc/cron.d/evil": "* * * * * root sh\n", "var/log/auth.log": "old\nuseradd\n"},
        # The agent removed the attack's cron file and the butter line, but also deleted
        # /etc/legal, which the attack never touched, and left a file of its own behind.
        "T2": {"etc/passwd": "root\n", "quarantine/evil.bak": "* * * * * root sh\n",
               "var/log/auth.log": "old\nuseradd\nuserdel\n"},
    }
    for label, files in trees.items():
        for rel, content in files.items():
            fp = tmp_path / label / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(content)
        (tmp_path / f"{label}.meta.json").write_text(json.dumps({"label": label, "taken": 1.0}))

    sc = sr.file_score("S0", "A1", "T2")
    # /var/log/auth.log records the attack's own useradd and can never be unwritten, so it is not
    # footprint; counting it would cap threat_cleared below 1.0 for a perfect episode.
    assert set(sc["footprint"]) == {"/etc/passwd", "/etc/cron.d/evil"}
    assert sorted(sc["cleared"]) == ["/etc/cron.d/evil", "/etc/passwd"]
    assert sc["not_cleared"] == {}
    assert list(sc["collateral"]) == ["/etc/legal"]          # untouched by the attack, gone now
    # /etc/shadow- is rewritten by any legitimate account change and is *supposed* to still name a
    # deleted user, so it is not damage. Counting these four took a correct episode from 1.0 to 0.0.
    assert sr.volatile("/etc/shadow-") and not sr.volatile("/etc/shadow")
    assert sc["side_effects"] == ["/quarantine/evil.bak"]    # new, and not the attack's doing

    r = sr.reward(sc)
    assert r["threat_cleared"] == 1.0 and r["damaged_count"] == 1
    assert r["footprint_files"] == 2 and r["value"] == 0.0   # cleared in full, but it broke something


def test_runtime_score_covers_what_has_no_file(tmp_path: Path) -> None:
    """A listening port is the case the filesystem cannot answer: nothing on disk changes."""
    from ice.exercise import snapshot_reward as sr

    def snap(ports, units=()):
        return {"data": {"stable": {
            "listening_ports": {p: {"port": p} for p in ports},
            "autostart": {u: {"id": u} for u in units},
            # A file table, which must be ignored now: the images cover these paths exactly.
            "critical_files": {"/etc/passwd": {"sha256": "deadbeef"}}}}}

    t0 = snap(["tcp/22"], ["ssh.service"])
    t1 = snap(["tcp/22", "tcp/4444"], ["ssh.service", "evil.service"])
    t2 = snap(["tcp/22"], ["ssh.service", "evil.service"])     # port closed, unit still enabled

    sc = sr.runtime_score(t0, t1, t2)
    assert sc["counts"]["footprint"] == 2 and sc["counts"]["cleared"] == 1
    assert [x["artifact"] for x in sc["not_cleared"]] == ["stable.autostart::evil.service"]
    assert not any("critical_files" in a for a in sc["footprint"])

    # Both footprints are added, not averaged: a closed port must not pay for the unit left enabled.
    files = {"counts": {"footprint": 0, "cleared": 0, "not_cleared": 0, "collateral": 0,
                        "side_effects": 0, "changed_during_agent": 0},
             "footprint": {}, "cleared": [], "not_cleared": {}, "collateral": {}, "side_effects": []}
    r = sr.reward(files, sc)
    assert r["threat_cleared"] == 0.5 and r["footprint_runtime"] == 2
