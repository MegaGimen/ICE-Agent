"""Reading the machine an episode ran on, from snapshots of its disk.

Each episode runs inside its own VM (ice.exercise.vm) and the host reads that VM's disk afterwards,
so every file on the machine has a before and an after without anything being listed in advance.

This replaced an rsync copy of the host's own filesystem. That version needed an exclude list for
the pseudo-filesystems and for everything the rig itself wrote, and the list was wrong twice: once
when /root/ice-state was excluded after the baseline had already been taken, which reported its 15
paths as deleted in every later episode, and once when the agent's own sqlite cache churned through
8 of the 21 paths that changed while it worked. Neither can arise now -- the rig is outside the VM,
and /proc, /sys, /dev and /run are mount points rather than files, so a disk image does not contain
them at all.

What still has to be ignored is the product's own state: ICE's state directory, openclaw's install.
Those live on the machine under test by design and their churn is not that machine's health. That is
a much smaller claim than the old list, and it belongs to scoring (snapshot_reward) rather than here.

Snapshots are qcow2 overlays, so unchanged blocks are shared with the golden image rather than
copied -- a snapshot of a 4 GB machine costs the few megabytes that really changed. Reading one is a
read-only nbd mount, which yields an ordinary directory tree, so the comparison below and the three
tools a judge drives it with are the same code they were when the trees came from rsync.

    python -m ice.exercise.image changes base <episode>-final
    python -m ice.exercise.image diff    base <episode>-final
    python -m ice.exercise.image show    base <episode>-final /etc/crontab
    python -m ice.exercise.image content base /etc/legal
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def root(label: str) -> Path:
    """Where this snapshot's filesystem can be read on the host; mounts it if it is not already."""
    from ice.exercise import vm
    return vm.mount(label)


def release() -> None:
    """Unmount everything. Safe to call more than once."""
    from ice.exercise import vm
    vm.umount_all()


def exists_now(path: str, fallback: str) -> Tuple[bool, str]:
    """Is this path on the machine at this moment, and what did we ask?

    While the VM is up the question is answered inside it. Once it is shut down -- which is when a
    snapshot is taken -- the final snapshot *is* the machine as it last was, so that is the honest
    source and the result says so rather than implying a live check.
    """
    from ice.exercise import vm
    for label in vm.overlays():
        if vm.running(label):
            p = vm.ssh(["test", "-e", path], check=False, timeout=15)
            return p.returncode == 0, f"live:{label}"
    return (root(fallback) / path.lstrip("/")).exists(), f"snapshot:{fallback}"


FILE, DIR, LINK = 0, 1, 2
Entry = Tuple[int, int, int, int, str]   # kind, size, mtime_ns, inode, symlink target


def index(label: str) -> Dict[str, Entry]:
    """{path as it appears on that machine: entry} for one snapshot."""
    base_dir = root(label)
    out: Dict[str, Entry] = {}
    cut = len(str(base_dir))
    for dirpath, dirnames, filenames in os.walk(base_dir, followlinks=False):
        for name in dirnames + filenames:
            fp = os.path.join(dirpath, name)
            try:
                st = os.lstat(fp)
            except OSError:
                continue
            if os.path.islink(fp):
                kind, target = LINK, os.readlink(fp)
            elif os.path.isdir(fp):
                kind, target = DIR, ""
            else:
                kind, target = FILE, ""
            out[fp[cut:] or "/"] = (kind, st.st_size, st.st_mtime_ns, st.st_ino, target)
    return out


def _sha256(p: Path) -> Optional[str]:
    h = hashlib.sha256()
    try:
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except (OSError, IsADirectoryError):
        return None
    return h.hexdigest()


def diff(a: str, b: str, hash_check: bool = False) -> Dict[str, Any]:
    """Every path that differs between two snapshots, grouped by what the evidence shows.

      added / removed   present in only one of the two
      modified          different kind, different size, or a symlink pointing somewhere else
      mtime_only        same size, different timestamp -- contents not compared
      retouched         rewritten with identical bytes (only found with hash_check)

    Directories are deliberately not compared. Two snapshots of the same machine give a directory
    different inodes, and treating that as a change once reported all 21,054 directories on the box
    as modified. What a directory holds is already reported as the entries inside it.

    hash_check decides mtime_only cases by reading both copies, which is the only way to tell a
    rewrite from a touch; without it they are reported as their own group rather than guessed at.
    """
    ia, ib = index(a), index(b)
    added = sorted(p for p in ib if p not in ia)
    removed = sorted(p for p in ia if p not in ib)
    modified: List[str] = []
    mtime_only: List[str] = []
    retouched: List[str] = []
    for p in sorted(ia.keys() & ib.keys()):
        ea, eb = ia[p], ib[p]
        if ea[0] != eb[0]:                          # file became a directory, or a symlink, ...
            modified.append(p)
            continue
        if ea[0] == DIR:
            continue
        if ea[0] == LINK:
            if ea[4] != eb[4]:
                modified.append(p)
            continue
        if ea[1] != eb[1]:                          # different size: provably different
            modified.append(p)
            continue
        if ea[2] == eb[2]:                          # same size and same mtime to the nanosecond
            continue
        if not hash_check:
            mtime_only.append(p)
            continue
        if _sha256(root(a) / p.lstrip("/")) == _sha256(root(b) / p.lstrip("/")):
            retouched.append(p)
        else:
            modified.append(p)
    return {"a": a, "b": b,
            "counts": {"added": len(added), "removed": len(removed), "modified": len(modified),
                       "mtime_only": len(mtime_only), "retouched": len(retouched),
                       "entries_a": len(ia), "entries_b": len(ib)},
            "added": added, "removed": removed, "modified": modified,
            "mtime_only": mtime_only, "retouched": retouched}


def changes(a: str, b: str, hash_check: bool = False, live: bool = True) -> List[Dict[str, Any]]:
    """The union of paths from before and after, each annotated with whether it is there now.

    The union is the point for deletions: a file the episode removed has a diff but nothing left to
    look at, so a list built from the machine's present contents would hide exactly the changes most
    worth seeing.
    """
    d = diff(a, b, hash_check=hash_check)
    ia, ib = index(a), index(b)
    kinds = {FILE: "file", DIR: "dir", LINK: "symlink"}
    out: List[Dict[str, Any]] = []
    for group in ("removed", "added", "modified", "mtime_only", "retouched"):
        for path in d[group]:
            ea, eb = ia.get(path), ib.get(path)
            row = {"path": path, "status": group,
                   "kind": kinds.get((eb or ea)[0], "?"),
                   "size_before": ea[1] if ea else None,
                   "size_after": eb[1] if eb else None}
            if live:
                row["exists_now"], row["exists_now_source"] = exists_now(path, b)
            out.append(row)
    return out


def _read(fp: Path, max_bytes: int) -> Dict[str, Any]:
    """One side of a file: text when it decodes, otherwise an honest binary record."""
    if fp.is_symlink():
        return {"kind": "symlink", "target": os.readlink(fp)}
    if fp.is_dir():
        return {"kind": "dir"}
    try:
        size = fp.stat().st_size
        raw = fp.open("rb").read(max_bytes + 1)
    except OSError as e:
        return {"kind": "unreadable", "error": str(e)}
    truncated = len(raw) > max_bytes
    raw = raw[:max_bytes]
    rec: Dict[str, Any] = {"kind": "file", "size": size, "sha256": _sha256(fp),
                           "truncated": truncated}
    try:
        rec["text"] = raw.decode()
    except UnicodeDecodeError:
        rec["binary"] = True
        rec["head_hex"] = raw[:64].hex()
    return rec


def content(label: str, path: str, max_bytes: int = 100_000) -> Dict[str, Any]:
    """The bytes of one path out of one snapshot.

    Reading a snapshot never touches the machine, so the before-bytes of something the episode
    deleted are available without restoring or booting anything.
    """
    from ice.exercise import vm
    if not vm.overlay_path(label).exists():
        return {"path": path, "error": f"no snapshot named {label!r}"}
    fp = root(label) / path.lstrip("/")
    if not (fp.exists() or fp.is_symlink()):
        return {"path": path, "label": label, "exists": False}
    return {"path": path, "label": label, "exists": True, **_read(fp, max_bytes)}


def show(a: str, b: str, path: str, context: int = 3, max_diff_bytes: int = 200_000) -> Dict[str, Any]:
    """What changed in one path: a unified diff, or a binary record when it is not text.

    This is what a judge is handed when it asks about a path -- the change, not the file. A snapshot
    holds the whole machine, including material the episode never touched, so answering with a diff
    keeps the answer to the question actually asked; the bytes stay reachable through content().

    Binary files are a change like any other, as in git: the entry is reported with both sides' size
    and sha256 and a diff that says it is binary, rather than the path being dropped as unavailable.
    """
    fa, fb = root(a) / path.lstrip("/"), root(b) / path.lstrip("/")
    ea, eb = fa.exists() or fa.is_symlink(), fb.exists() or fb.is_symlink()
    out: Dict[str, Any] = {"path": path, f"in_{a}": ea, f"in_{b}": eb}
    if not ea and not eb:
        out["status"] = "absent from both"
        return out
    out["status"] = "added" if not ea else "removed" if not eb else "modified"
    sides = {}
    for side, fp, present in ((a, fa, ea), (b, fb, eb)):
        sides[side] = _read(fp, max_diff_bytes) if present else {"kind": "absent"}
        out[side] = {k: v for k, v in sides[side].items() if k != "text"}

    def lines(side: str) -> Optional[List[str]]:
        rec = sides[side]
        if rec["kind"] in ("absent", "dir"):
            return []
        if rec["kind"] == "symlink":
            return [rec["target"] + "\n"]
        if "text" not in rec:
            return None                       # binary
        return rec["text"].splitlines(keepends=True)

    la, lb = lines(a), lines(b)
    if la is None or lb is None:
        out["binary"] = True
        out["diff"] = "Binary files %s%s and %s%s differ" % (a, path, b, path)
        return out
    out["diff"] = "".join(difflib.unified_diff(la, lb, fromfile=a + path, tofile=b + path,
                                               n=context))
    if any(sides[k].get("truncated") for k in sides):
        out["diff_truncated_at_bytes"] = max_diff_bytes
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="read and compare two snapshots of an episode's machine")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("diff", help="what differs between two snapshots")
    d.add_argument("a")
    d.add_argument("b")
    d.add_argument("--hash-check", action="store_true", help="hash the same-size, new-mtime cases")
    d.add_argument("--limit", type=int, default=40)
    ch = sub.add_parser("changes", help="the union of changed paths, with present-day existence")
    ch.add_argument("a")
    ch.add_argument("b")
    ch.add_argument("--hash-check", action="store_true")
    sh_ = sub.add_parser("show", help="the change in one path")
    sh_.add_argument("a")
    sh_.add_argument("b")
    sh_.add_argument("path")
    ct = sub.add_parser("content", help="the bytes of one path out of one snapshot")
    ct.add_argument("label")
    ct.add_argument("path")
    ct.add_argument("--max-bytes", type=int, default=100_000)
    a = ap.parse_args()

    try:
        if a.cmd == "diff":
            res = diff(a.a, a.b, hash_check=a.hash_check)
            print(json.dumps(res["counts"], indent=1))
            for group in ("removed", "modified", "added", "mtime_only"):
                items = res[group]
                if items:
                    print(f"\n{group} ({len(items)}):")
                    for p in items[:a.limit]:
                        print("  ", p)
                    if len(items) > a.limit:
                        print(f"   ... and {len(items) - a.limit} more")
        elif a.cmd == "changes":
            rows = changes(a.a, a.b, hash_check=a.hash_check)
            print(f"{'status':<12}{'now':<5}{'kind':<8}path")
            for r in rows:
                print(f"{r['status']:<12}{'yes' if r.get('exists_now') else 'NO':<5}"
                      f"{r['kind']:<8}{r['path']}")
            print(f"\n{len(rows)} changed paths")
        elif a.cmd == "show":
            res = show(a.a, a.b, a.path)
            body = res.pop("diff", None)
            print(json.dumps(res, indent=1, ensure_ascii=False))
            if body:
                print(body)
        elif a.cmd == "content":
            print(json.dumps(content(a.label, a.path, a.max_bytes), indent=1,
                             ensure_ascii=False)[:8000])
    finally:
        release()


if __name__ == "__main__":
    main()
