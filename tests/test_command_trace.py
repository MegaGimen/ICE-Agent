"""Every verify_paths status, on real files, with real tarball and snapshot evidence.

    python3 -m pytest tests/test_command_trace.py        (or run this file directly)

The point of the exercise is that a status is only ever as strong as the evidence behind it: a path
no source recorded must stay `absent_unverifiable` and must never be upgraded to damage.
"""
from __future__ import annotations

import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ice.exercise import command_trace as ct  # noqa: E402

CASES = {
    "unchanged.txt": "unchanged",                      # in the tarball, bytes match
    "modified.txt": "modified",                        # in the tarball, bytes differ
    "removed.txt": "removed",                          # in the tarball, gone now
    "added.txt": "added",                              # no record of it before, present now
    "present_unverified.txt": "present_unverified",    # T0 saw it, but stored no hash
    "attack_artifact.txt": "removed_after_attack",     # only T1 saw it, gone now
    "never_seen.txt": "absent_unverifiable",           # no source ever recorded it
}


def _snapshot(paths):
    """A host snapshot shaped like perception's, carrying paths but no hashes."""
    return {"data": {"stable": {"critical_files": {p: {"path": p} for p in paths}}}}


def _build(root: Path) -> Path:
    for name, body in (("unchanged.txt", "same"), ("modified.txt", "after"),
                       ("added.txt", "new"), ("present_unverified.txt", "whatever")):
        (root / name).write_text(body)
    stage = root / "stage"
    stage.mkdir()
    tar = root / "baseline.tar.gz"
    with tarfile.open(tar, "w:gz") as tf:
        for name, body in (("unchanged.txt", "same"), ("modified.txt", "before"),
                           ("removed.txt", "gone")):
            (stage / name).write_text(body)
            tf.add(stage / name, arcname=str(root / name).lstrip("/"))
    return tar


def test_verify_paths_statuses(tmp_path: Path) -> None:
    tar = _build(tmp_path)
    t0 = _snapshot([str(tmp_path / "present_unverified.txt")])
    t1 = _snapshot([str(tmp_path / "present_unverified.txt"),
                    str(tmp_path / "attack_artifact.txt")])
    r = ct.verify_paths([str(tmp_path / n) for n in CASES], tar,
                        lens_paths=[str(tmp_path) + "/*"], t0=t0, t1=t1)
    got = {n: r["results"][str(tmp_path / n)]["status"] for n in CASES}
    assert got == CASES, got
    # Only provable loss or change counts as damage; the unverifiable file is not upgraded.
    assert [Path(p).name for p in r["provable_damage"]] == ["modified.txt", "removed.txt"]
    assert [Path(p).name for p in r["attack_artifacts_removed"]] == ["attack_artifact.txt"]
    assert [Path(p).name for p in r["unverifiable"]] == ["never_seen.txt"]
    assert all(v["in_snapshot_lens"] for v in r["results"].values())


def test_scratch_manifest_rules_on_tmp(tmp_path: Path) -> None:
    """/tmp is in neither the tarball nor any osquery table, so the manifest is the only evidence.

    Both directions matter: deleting a file the clean machine had is provable loss, and deleting one
    it never had is provably not loss. Before the manifest was wired in, both read `unverifiable`.
    """
    scratch_root = tmp_path / "tmp"
    (scratch_root / "a" / "b").mkdir(parents=True)
    (scratch_root / "survivor").write_text("kept")
    (scratch_root / "a" / "b" / "deep_survivor").write_text("kept")
    manifest = tmp_path / "scratch-manifest.txt"
    # The clean machine had these. `deleted_by_agent` and `attack_droppings` are absent from it.
    manifest.write_text("\n".join([
        str(scratch_root / "survivor"),
        str(scratch_root / "deleted_by_agent"),
        str(scratch_root / "a"),
        str(scratch_root / "a" / "b"),
        str(scratch_root / "a" / "b" / "deep_survivor"),
    ]) + "\n")
    sc = ct.Scratch(manifest, roots=[str(scratch_root)], depth=3)
    tar = tmp_path / "empty.tar.gz"
    with tarfile.open(tar, "w:gz") as tf:
        pass

    want = {
        "survivor": "present_unverified",            # manifest proves it existed; no bytes stored
        "deleted_by_agent": "removed",               # manifest proves loss -- previously invisible
        "attack_droppings": "absent_not_in_baseline",  # never in the manifest, so not a loss
        "a/b/too/deep": "absent_unverifiable",       # past the manifest's depth: no ruling
    }
    r = ct.verify_paths([str(scratch_root / n) for n in want], tar, scratch=sc)
    got = {n: r["results"][str(scratch_root / n)]["status"] for n in want}
    assert got == want, got
    assert [Path(x).name for x in r["provable_damage"]] == ["deleted_by_agent"]
    assert [Path(x).name for x in r["unverifiable"]] == ["deep"]
    # Coverage is a property of the manifest, not of what it happens to list.
    assert sc.covers(str(scratch_root / "anything"))
    assert not sc.covers(str(scratch_root / "a" / "b" / "too" / "deep"))
    assert not sc.covers("/etc/passwd")


def test_symlinked_scratch_root_answers_consistently(tmp_path: Path) -> None:
    """/var/spool/mail is a symlink to /var/mail, and `find` does not descend a symlinked root.

    So the manifest only ever lists the real name, and a query under the alias must resolve to it --
    otherwise the same file is `present_unverified` under one name and unrecorded under the other.
    """
    import os
    (tmp_path / "mail").mkdir()
    (tmp_path / "mail" / "alice").write_text("inbox")
    os.symlink("mail", tmp_path / "spool-mail")
    manifest = tmp_path / "scratch-manifest.txt"
    manifest.write_text(str(tmp_path / "mail" / "alice") + "\n")
    sc = ct.Scratch(manifest, roots=[str(tmp_path / "mail"), str(tmp_path / "spool-mail")], depth=3)
    tar = tmp_path / "empty.tar.gz"
    with tarfile.open(tar, "w:gz"):
        pass

    def status(rel: str) -> str:
        return ct.verify_paths([str(tmp_path / rel)], tar,
                               scratch=sc)["results"][str(tmp_path / rel)]["status"]

    assert status("mail/alice") == status("spool-mail/alice") == "present_unverified"
    assert status("spool-mail/bob") == "absent_not_in_baseline"


def test_lens_matches_directory_scans() -> None:
    """A file the attack is the first to create in a watched directory is still in the lens."""
    from ice.daemon.perception.snapshot import lens_globs
    lens = lens_globs()
    for p in ("/etc/cron.d/persistevil", "/etc/passwd", "/var/spool/cron/crontabs/butter",
              "/etc/sudoers.d/99-evil", "/etc/systemd/system/evil.service"):
        assert ct.in_lens(p, lens), p
    for p in ("/var/mail/butter", "/srv/app/config.yml", "/etc/subuid"):
        assert not ct.in_lens(p, lens), p


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        test_verify_paths_statuses(Path(d))
    with tempfile.TemporaryDirectory() as d:
        test_scratch_manifest_rules_on_tmp(Path(d))
    with tempfile.TemporaryDirectory() as d:
        test_symlinked_scratch_root_answers_consistently(Path(d))
    test_lens_matches_directory_scans()
    print("ok: 8 statuses, scratch manifest rules on /tmp, lens covers directory scans")
