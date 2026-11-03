"""Whole-filesystem content snapshots, so every file on the machine has a before and an after.

The point is to stop guessing where an episode might do damage. Earlier the evidence was three
partial records -- a tarball of 19 declared paths, osquery's 177, and a filename listing of /tmp --
and the set of paths they covered was chosen by looking at one attack. Anything outside it was
invisible: a deletion there could be neither proven nor ruled out. Widening that set by hand, one
observed attack at a time, is not a method.

A watch list and an ignore list are not the same kind of thing. What this excludes is a short,
checkable set of directories the rig itself writes -- the snapshot store, the dataset, the repo, the
interpreter, the agent's install. Everything else on the machine is covered, so an unlisted path now
shows up as a change rather than being silently unseen.

Snapshots are real content, not hashes, so the before-bytes of any file can be read back. Space is
not the problem it sounds like: with --link-dest, a file that did not change is hardlinked to the
previous snapshot rather than copied, so a second snapshot of a 17 GB machine costs only what
actually changed. That same trick makes diffing almost free -- two entries sharing an inode are
provably identical, so a full comparison reads no file contents at all.

    python -m ice.exercise.image take S0
    python -m ice.exercise.image diff S0 T2
    python -m ice.exercise.image show S0 T2 /etc/crontab
    python -m ice.exercise.image restore S0
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SNAP_ROOT = Path(os.environ.get("ICE_IMAGE_ROOT", "/root/ice-images"))

# Directories the rig itself owns. Restoring them would undo the recorder's own code and data, and
# snapshotting them would make each snapshot contain the previous ones. `-x` keeps rsync on the root
# filesystem, which already excludes /proc, /sys, /dev and /run.
EXCLUDES: Tuple[str, ...] = (
    # Pseudo-filesystems. `-x` already keeps rsync off them, on both sides, but --delete against an
    # empty /run would take a running system apart if that ever stopped holding, and a guess is not
    # worth it: these hold no episode evidence and must never be restored.
    "/proc", "/sys", "/dev", "/run",
    "/lost+found",
    "/root/ice-images",          # the snapshot store (see SNAP_ROOT)
    "/root/ice-dataset",         # recorded episodes
    "/root/ICE",                 # this repository
    "/root/ice-envs",            # the daemon's interpreter
    "/root/node24",              # node, for the agent
    "/root/.openclaw",           # the agent's own install and state
    "/root/ice-build",           # daemon logs
    "/root/ice-state",           # the daemon's own state dir, rebuilt every episode
)


def _excludes(extra: Iterable[str] = ()) -> List[str]:
    out: List[str] = []
    for e in tuple(EXCLUDES) + tuple(extra) + (str(SNAP_ROOT),):
        out += ["--exclude", e]
    return out


def _run(cmd: List[str], label: str = "") -> subprocess.CompletedProcess:
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True)
    if label:
        tag = "ok" if p.returncode == 0 else f"rc={p.returncode} {p.stderr.strip()[:200]}"
        print(f"  [{label}] {tag} ({time.time() - t0:.1f}s)")
    return p


def taken_at(label: str) -> float:
    """When a snapshot was taken, from the sidecar metadata rather than the directory's mtime.

    `rsync -a` copies the source's timestamps, so a snapshot directory carries the mtime of `/`,
    not the moment it was made. Ordering by that put a later snapshot first, which made `take`
    hardlink against an older one than it should and reported each snapshot's size wrongly.
    """
    try:
        return float(json.loads((SNAP_ROOT / f"{label}.meta.json").read_text())["taken"])
    except (OSError, KeyError, ValueError):
        try:
            return (SNAP_ROOT / label).stat().st_mtime
        except OSError:
            return 0.0


def snapshots() -> List[str]:
    """Snapshot labels, oldest first."""
    if not SNAP_ROOT.exists():
        return []
    return sorted((d.name for d in SNAP_ROOT.iterdir() if d.is_dir()), key=taken_at)


def take(label: str, link_from: Optional[str] = None) -> Dict[str, Any]:
    """Copy the whole root filesystem into SNAP_ROOT/<label>.

    link_from names an existing snapshot to hardlink unchanged files against; by default the newest
    one, which is what keeps a second snapshot cheap. rsync is given the trailing-slash form so the
    root's contents land directly in the snapshot directory.
    """
    SNAP_ROOT.mkdir(parents=True, exist_ok=True)
    dst = SNAP_ROOT / label
    if dst.exists():
        raise SystemExit(f"{dst} already exists; pick another label or remove it")
    if link_from is None:
        existing = [s for s in snapshots() if s != label]
        link_from = existing[-1] if existing else None
    cmd = ["rsync", "-aHAX", "-x", "--numeric-ids", "--delete", "--stats"]
    if link_from:
        cmd += ["--link-dest", str(SNAP_ROOT / link_from)]
    cmd += _excludes() + ["/", str(dst) + "/"]
    p = _run(cmd, f"take {label}" + (f" (linked to {link_from})" if link_from else " (full)"))
    # rsync exits 24 when a file vanished mid-copy, which is normal on a live machine.
    if p.returncode not in (0, 24):
        raise SystemExit(f"rsync failed: {p.stderr.strip()[:400]}")
    meta = {"label": label, "taken": time.time(), "link_from": link_from,
            "rsync_rc": p.returncode, "excludes": list(EXCLUDES)}
    (dst.parent / f"{label}.meta.json").write_text(json.dumps(meta, indent=1))
    return meta


FILE, DIR, LINK = 0, 1, 2
Entry = Tuple[int, int, int, int, str]   # kind, size, mtime_ns, inode, symlink target


def index(label: str) -> Dict[str, Entry]:
    """{path as it appears on the real machine: entry} for one snapshot."""
    root = SNAP_ROOT / label
    out: Dict[str, Entry] = {}
    base = len(str(root))
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
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
            out[fp[base:] or "/"] = (kind, st.st_size, st.st_mtime_ns, st.st_ino, target)
    return out


def _sha256(p: Path) -> Optional[str]:
    h = hashlib.sha256()
    try:
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def diff(a: str, b: str, hash_check: bool = False) -> Dict[str, Any]:
    """Every path that differs between two snapshots, grouped by what the evidence shows.

      added / removed   present in only one of the two
      modified          different kind, different size, or a symlink pointing somewhere else
      mtime_only        same size, different timestamp -- content not compared
      retouched         rewritten with identical bytes (only found with hash_check)

    An unchanged file is a hardlink into the older snapshot, so an equal inode *proves* equal
    content and no file is read. Directories are deliberately not compared: a directory gets a new
    inode in every snapshot because it cannot be hardlinked, and treating that as a change reported
    all 21,054 of this machine's directories as modified. What a directory holds is already reported
    as the added, removed and modified entries inside it.

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
        if ea[3] == eb[3]:                          # same inode: provably identical
            continue
        if ea[1] != eb[1]:                          # different size: provably different
            modified.append(p)
            continue
        if ea[2] == eb[2]:                          # same size and same mtime to the nanosecond
            continue
        if not hash_check:
            mtime_only.append(p)
            continue
        if _sha256(SNAP_ROOT / a / p.lstrip("/")) == _sha256(SNAP_ROOT / b / p.lstrip("/")):
            retouched.append(p)
        else:
            modified.append(p)
    return {"a": a, "b": b,
            "counts": {"added": len(added), "removed": len(removed), "modified": len(modified),
                       "mtime_only": len(mtime_only), "retouched": len(retouched),
                       "entries_a": len(ia), "entries_b": len(ib)},
            "added": added, "removed": removed, "modified": modified,
            "mtime_only": mtime_only, "retouched": retouched}


def changes(a: str, b: str, hash_check: bool = False) -> List[Dict[str, Any]]:
    """The union of paths from before and after, each annotated with whether it exists right now.

    The union is the point: a file the episode deleted has a diff but no present-day existence, so
    listing only what is on the machine would hide exactly the changes most worth looking at.
    `exists_now` is read off the live filesystem rather than off the later snapshot, because the
    machine is not rolled back for anyone to inspect -- the snapshots are the history, the machine
    is the present, and a judge should be able to see when those two disagree.
    """
    d = diff(a, b, hash_check=hash_check)
    ia, ib = index(a), index(b)
    kinds = {FILE: "file", DIR: "dir", LINK: "symlink"}
    out: List[Dict[str, Any]] = []
    for group in ("removed", "added", "modified", "mtime_only", "retouched"):
        for path in d[group]:
            ea, eb = ia.get(path), ib.get(path)
            out.append({
                "path": path,
                "status": group,
                "kind": kinds.get((eb or ea)[0], "?"),
                "size_before": ea[1] if ea else None,
                "size_after": eb[1] if eb else None,
                "exists_now": os.path.lexists(path),
            })
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
    """The bytes of one path, from a snapshot or from the machine as it is now.

    label is a snapshot name, or "current" to read the live filesystem. Reading a snapshot never
    touches the machine, so the before-bytes of something the episode deleted are still available
    without restoring anything.
    """
    if label == "current":
        fp = Path(path)
    else:
        if not (SNAP_ROOT / label).is_dir():
            return {"path": path, "error": f"no snapshot named {label!r}"}
        fp = SNAP_ROOT / label / path.lstrip("/")
    if not (fp.exists() or fp.is_symlink()):
        return {"path": path, "label": label, "exists": False}
    return {"path": path, "label": label, "exists": True, **_read(fp, max_bytes)}


def show(a: str, b: str, path: str, context: int = 3, max_diff_bytes: int = 200_000) -> Dict[str, Any]:
    """What changed in one path: a unified diff, or a binary record when it is not text.

    This is what a judge is handed when it asks about a path -- the change, not the file. A snapshot
    holds the whole machine, including material the episode never touched, so answering with a diff
    keeps the answer to the question actually asked; the bytes are still available through content()
    when the diff is not enough.

    Binary files are a change like any other, as in git: the entry is reported, both sides' size and
    sha256 are given, and the diff says it is binary instead of the path being quietly dropped.
    """
    fa, fb = SNAP_ROOT / a / path.lstrip("/"), SNAP_ROOT / b / path.lstrip("/")
    ea, eb = fa.exists() or fa.is_symlink(), fb.exists() or fb.is_symlink()
    out: Dict[str, Any] = {"path": path, "exists_now": os.path.lexists(path),
                           f"in_{a}": ea, f"in_{b}": eb}
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


def restore(label: str, dry_run: bool = False) -> None:
    """Put the machine back to a snapshot: the whole filesystem, not a list of paths."""
    src = SNAP_ROOT / label
    if not src.is_dir():
        raise SystemExit(f"no snapshot at {src}")
    cmd = ["rsync", "-aHAX", "-x", "--numeric-ids", "--delete"]
    if dry_run:
        cmd += ["--dry-run", "--itemize-changes"]
    cmd += _excludes() + [str(src) + "/", "/"]
    p = _run(cmd, f"restore {label}" + (" (dry run)" if dry_run else ""))
    if dry_run:
        lines = [l for l in p.stdout.splitlines() if l.strip()]
        print(f"  would change {len(lines)} paths")
        for l in lines[:40]:
            print("   ", l)
    elif p.returncode not in (0, 24):
        raise SystemExit(f"rsync failed: {p.stderr.strip()[:400]}")


def main() -> None:
    ap = argparse.ArgumentParser(description="whole-filesystem snapshots for episode scoring")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("take", help="snapshot the machine")
    t.add_argument("label")
    t.add_argument("--link-from", default=None, help="hardlink unchanged files against this snapshot")
    sub.add_parser("list", help="list snapshots")
    d = sub.add_parser("diff", help="what differs between two snapshots")
    d.add_argument("a")
    d.add_argument("b")
    d.add_argument("--hash-check", action="store_true", help="hash when inodes differ")
    d.add_argument("--limit", type=int, default=40)
    s = sub.add_parser("show", help="the change in one path")
    s.add_argument("a")
    s.add_argument("b")
    s.add_argument("path")
    ch = sub.add_parser("changes", help="the union of changed paths, with present-day existence")
    ch.add_argument("a")
    ch.add_argument("b")
    ch.add_argument("--hash-check", action="store_true")
    ct_ = sub.add_parser("content", help="the bytes of one path, from a snapshot or from 'current'")
    ct_.add_argument("label")
    ct_.add_argument("path")
    ct_.add_argument("--max-bytes", type=int, default=100_000)
    r = sub.add_parser("restore", help="put the machine back to a snapshot")
    r.add_argument("label")
    r.add_argument("--dry-run", action="store_true")
    rm = sub.add_parser("rm", help="delete a snapshot")
    rm.add_argument("label")
    a = ap.parse_args()

    if a.cmd == "take":
        print(json.dumps(take(a.label, a.link_from), indent=1))
    elif a.cmd == "list":
        labels = snapshots()
        # One du over every snapshot at once, oldest first: du counts a hardlinked file only on its
        # first appearance, so the oldest shows the full tree and each later one shows what it alone
        # added. Measuring them one call at a time reported 16G four times for a 17G store.
        dirs = [str(SNAP_ROOT / l) for l in labels]
        sizes = {}
        if dirs:
            for line in _run(["du", "-sh"] + dirs).stdout.splitlines():
                kb, _, path = line.partition("\t")
                sizes[Path(path.strip()).name] = kb.strip()
        for label in labels:
            d_ = SNAP_ROOT / label
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(taken_at(label)))
            print(f"  {label:<12} {sizes.get(label, '?'):>7} new   {when}")
        if dirs:
            print(f"  {'(store)':<12} {_run(['du', '-sh', str(SNAP_ROOT)]).stdout.split(chr(9))[0]:>7} total")
    elif a.cmd == "diff":
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
            print(f"{r['status']:<12}{'yes' if r['exists_now'] else 'NO':<5}{r['kind']:<8}{r['path']}")
        print(f"\n{len(rows)} changed paths")
    elif a.cmd == "content":
        print(json.dumps(content(a.label, a.path, a.max_bytes), indent=1, ensure_ascii=False)[:8000])
    elif a.cmd == "show":
        res = show(a.a, a.b, a.path)
        d_ = res.pop("diff", None)
        print(json.dumps(res, indent=1, ensure_ascii=False))
        if d_:
            print(d_)
    elif a.cmd == "restore":
        restore(a.label, a.dry_run)
    elif a.cmd == "rm":
        import shutil
        shutil.rmtree(SNAP_ROOT / a.label)
        (SNAP_ROOT / f"{a.label}.meta.json").unlink(missing_ok=True)
        print(f">>> removed {a.label}")


if __name__ == "__main__":
    main()
