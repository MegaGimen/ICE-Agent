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


if __name__ == "__main__":
    import tempfile
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in tests:
        with tempfile.TemporaryDirectory() as d:
            fn(Path(d))
    print(f"ok: {len(tests)} image tests")
