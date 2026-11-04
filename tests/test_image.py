"""Diffing and reading two snapshots of an episode's machine, on synthetic trees.

    python3 -m pytest tests/test_image.py        (or run this file directly)

In the rig a snapshot is a qcow2 overlay the host mounts read-only, which yields a directory tree.
These tests supply the trees directly and substitute `image.root`, so the comparison logic is
covered without needing qemu, kvm or a 4 GB image to boot.

Everything here was a real bug or a real requirement:
  * two snapshots of one machine give a directory different inodes, so comparing directories by
    inode once reported all 21,054 directories on the box as modified;
  * a deleted file has a diff but nothing left to look at, so the change list is the union of before
    and after, with `exists_now` answered separately;
  * binary files are a change like any other, as in git, not a path quietly dropped;
  * the attack's own footprint is derived from the armed snapshot, so nothing the attack did is
    ever charged to the agent -- the judge is told which snapshot is which and reads it itself.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ice.exercise import image  # noqa: E402

# _use() below replaces image.exists_now for the tests that supply their own trees, so the real one
# is captured here for the test that is about exists_now itself.
REAL_EXISTS_NOW = image.exists_now


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


def _use(tmp_path: Path, labels) -> None:
    """Serve these labels from directories under tmp_path instead of mounting a disk image."""
    roots = {label: tmp_path / label for label in labels}
    for d in roots.values():
        d.mkdir(parents=True, exist_ok=True)
    image.root = lambda label: roots[label]                      # type: ignore[assignment]
    image.exists_now = lambda path, fallback: (                   # type: ignore[assignment]
        (roots[fallback] / path.lstrip("/")).exists(), f"snapshot:{fallback}")


def _snapshots(tmp_path: Path, before: dict, after: dict, link: bool = True) -> None:
    """Build two snapshot trees, A and B, and serve them as labels.

    With link=True, files identical in both are hardlinked, so the inode fast path is exercised as
    it is on a real overlay chain. link=False is for the cases that need two distinct inodes holding
    the same content -- a hardlink shares one timestamp, so touching "the B copy" of a linked file
    changes both and leaves no mtime difference to test.
    """
    _use(tmp_path, ("A", "B"))
    _tree(tmp_path / "A", before)
    _tree(tmp_path / "B", after)
    if link:
        for rel, content in before.items():
            if rel in after and after[rel] == content and not isinstance(content, tuple):
                dst = tmp_path / "B" / rel
                dst.unlink()
                os.link(tmp_path / "A" / rel, dst)


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


def test_content_reads_either_snapshot(tmp_path: Path) -> None:
    _snapshots(tmp_path, {"gone.txt": "the before bytes\n"}, {})
    from ice.exercise import vm
    vm.overlay_path = lambda label: tmp_path / label            # type: ignore[assignment]
    # The bytes of a deleted file are still available, without restoring anything.
    before = image.content("A", "/gone.txt")
    assert before["exists"] and before["text"] == "the before bytes\n"
    assert image.content("B", "/gone.txt") == {"path": "/gone.txt", "label": "B", "exists": False}
    # Truncation is stated rather than silently applied.
    capped = image.content("A", "/gone.txt", max_bytes=4)
    assert capped["truncated"] is True and capped["text"] == "the "
    assert capped["size"] == 17                      # the real size, not the truncated length


def _three(tmp_path: Path, t0: dict, t1: dict, t2: dict) -> None:
    """Three snapshot trees under the names the judge is given: healthy, attacked, and the end."""
    _use(tmp_path, ("T0", "T1", "T2"))
    for label, files in (("T0", t0), ("T1", t1), ("T2", t2)):
        _tree(tmp_path / label, files)


def test_listdir_is_the_union_so_a_deletion_is_visible(tmp_path: Path) -> None:
    """A listing of the live machine cannot show what was deleted from it, and a deletion is the
    change most worth seeing -- both the attack's drop that the agent removed and the agent's own
    mistake look like nothing at all on T2."""
    _three(tmp_path,
           {"etc/cron.d/keep": "legit\n"},
           {"etc/cron.d/keep": "legit\n", "etc/cron.d/evil": "* * * * * root /opt/x\n"},
           {"etc/cron.d/evil": "* * * * * root /opt/x\n"})
    out = image.listdir("/etc/cron.d", {"T0": "T0", "T1": "T1", "T2": "T2"})
    by = {e["name"]: e for e in out["entries"]}
    assert out["count"] == 2 and out["directory_in"] == ["T0", "T1", "T2"]
    # The attack's cron job: never in T0, and still there at the end.
    assert by["evil"]["in"] == ["T1", "T2"] and by["evil"]["gone"] == ["T0"]
    # The machine's own cron job, deleted during the episode. Nothing on T2 shows it.
    assert by["keep"]["in"] == ["T0", "T1"] and by["keep"]["gone"] == ["T2"]
    assert by["keep"]["kind"]["T0"] == "file" and by["keep"]["size"]["T0"] == len("legit\n")
    # A path that is not a directory anywhere says so rather than returning an empty listing.
    assert "error" in image.listdir("/nowhere", {"T0": "T0", "T1": "T1", "T2": "T2"})


def test_named_diffs_keep_the_attack_and_the_outcome_apart(tmp_path: Path) -> None:
    """T2 - T0 alone cannot score an episode. It cannot tell an artifact the agent failed to clear
    from one it never had, and it is empty for a file the attack modified and the agent restored
    exactly -- the case most worth crediting. So both diffs are computed and named."""
    # /tmp exists on the machine before the attack, as it does on a real one: a directory that
    # only appears in T1 would itself be reported as added, which says nothing beyond the file in it.
    _three(tmp_path,
           {"etc/crontab": "healthy\n", "etc/legal": "notice\n", "tmp/.keep": ""},
           {"etc/crontab": "healthy\nattacked\n", "etc/legal": "notice\n", "tmp/.keep": "",
            "tmp/drop.sh": "payload\n"},
           {"etc/crontab": "healthy\n", "tmp/.keep": "", "tmp/drop.sh": "payload\n"})
    d = image.named_diffs("T0", "T1", "T2")
    before = {r["path"]: r for r in d["before"]}
    after = {r["path"]: r for r in d["after"]}

    # The attack: it edited crontab and dropped a payload. That is all of it, and none of it is the
    # agent's doing.
    assert set(before) == {"/etc/crontab", "/tmp/drop.sh"}
    assert before["/tmp/drop.sh"]["status"] == "added"
    # exists_now on the attack's own list is answered against T2, so each of its paths carries
    # whether it survived the episode. The payload did; nothing else needs looking up to see that.
    assert before["/tmp/drop.sh"]["exists_now"] is True
    assert before["/etc/crontab"]["exists_now"] is True

    # The outcome: the payload is still there, and /etc/legal is gone -- which the attack never
    # touched, so it is the agent's. The restored crontab appears in neither, which is the point:
    # a file put back exactly is not a change at the end.
    assert set(after) == {"/tmp/drop.sh", "/etc/legal"}
    assert after["/etc/legal"]["status"] == "removed"
    assert "/etc/crontab" not in after


def test_only_this_episodes_vm_answers_for_the_live_machine(tmp_path: Path) -> None:
    """"Is it there now" is a question about this episode's machine. A VM from another episode is a
    different machine, and there is usually one around -- a leftover from an aborted run was up on
    the box while this episode's snapshots were being re-read."""
    from ice.exercise import vm

    asked = []
    vm.overlays = lambda: ["other-episode-live", "mine-final"]     # type: ignore[assignment]
    vm.running = lambda label: label.endswith("-live")             # type: ignore[assignment]

    def ssh(argv, **kw):
        asked.append(argv)
        raise AssertionError("the other episode's VM was asked about this episode's machine")

    vm.ssh = ssh                                                   # type: ignore[assignment]
    (tmp_path / "mine-final").mkdir()
    (tmp_path / "mine-final" / "there").write_text("x")
    image.root = lambda label: tmp_path / label                    # type: ignore[assignment]

    assert REAL_EXISTS_NOW("/there", "mine-final") == (True, "snapshot:mine-final")
    assert REAL_EXISTS_NOW("/gone", "mine-final") == (False, "snapshot:mine-final")
    assert asked == []
    assert image.episode_of("mine-final") == image.episode_of("mine-live") == "mine"


if __name__ == "__main__":
    import tempfile
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        with tempfile.TemporaryDirectory() as d:
            fn(Path(d))
    print(f"ok: {len(tests)} image tests")
