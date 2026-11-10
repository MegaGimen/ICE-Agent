"""Local evidence case bundles. Collection never executes samples or follows links.

Raw evidence is private and byte-preserving. Summaries are not a substitute for proof,
and importing a historical report does not certify its claims or current host state.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import tarfile
import uuid

from .storage import read_journal, write_json


def _hash(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _raise(error):
    raise error


def _open_regular(root: Path, relative: Path):
    """Walk through pinned directory descriptors, rejecting symlink components."""
    if relative.is_absolute() or any(p in ("", ".", "..") for p in relative.parts):
        raise ValueError("invalid evidence path")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    finally:
        os.close(directory)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError("evidence is not a regular file")
    return os.fdopen(fd, "rb")


def package_case(source: Path, output: Path, report: dict | None = None,
                 *, max_bytes=512 * 1024 * 1024, max_files=10000):
    source, output = Path(source).resolve(strict=True), Path(output).absolute()
    if not source.is_dir():
        raise ValueError("source must be a directory")
    resolved_out = output.resolve()
    if source == resolved_out or source in resolved_out.parents or resolved_out in source.parents:
        raise ValueError("source and destination must be separate trees")
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    output.chmod(0o700)
    write_json(output / "status.json", {"state": "collecting"}, private=True)
    raw = output / "private/raw"
    raw.mkdir(parents=True, mode=0o700)
    raw.parent.chmod(0o700)
    artifacts, skipped, total = [], [], 0
    try:
        for base, directories, files in os.walk(source, followlinks=False, onerror=_raise):
            directories.sort()
            for name in list(directories):
                p = Path(base) / name
                if p.is_symlink():
                    skipped.append({"path": str(p.relative_to(source)), "reason": "symlink directory not followed"})
                    directories.remove(name)
            for name in sorted(files):
                p = Path(base) / name
                relative = p.relative_to(source)
                mode = p.lstat().st_mode
                if not stat.S_ISREG(mode):
                    skipped.append({"path": str(relative), "reason": "symlink or non-regular object not copied"})
                    continue
                if len(artifacts) >= max_files:
                    raise ValueError("evidence file limit exceeded")
                destination = raw / relative
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with _open_regular(source, relative) as original:
                    before = os.fstat(original.fileno())
                    h, size, head = hashlib.sha256(), 0, b""
                    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "wb") as copied:
                        for block in iter(lambda: original.read(1024 * 1024), b""):
                            if not head:
                                head = block[:16]
                            total += len(block)
                            size += len(block)
                            if total > max_bytes:
                                raise ValueError("evidence byte limit exceeded")
                            h.update(block)
                            copied.write(block)
                    after = os.fstat(original.fileno())
                if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
                    raise ValueError(f"source changed during collection: {relative}")
                if size != before.st_size or _hash(destination) != h.hexdigest():
                    raise ValueError(f"evidence verification failed: {relative}")
                sample = head.startswith((b"\x7fELF", b"MZ", b"#!")) or ".php" in relative.name.lower()
                artifacts.append({"id": f"E{len(artifacts)+1:05d}", "source_path": str(relative),
                                  "copy_path": str(destination.relative_to(output)), "size": size,
                                  "sha256": h.hexdigest(), "source_mode": oct(stat.S_IMODE(before.st_mode)),
                                  "source_mtime_ns": before.st_mtime_ns,
                                  "potentially_executable_content": sample,
                                  "copy_mode": "0o600", "bytes_verified": True})
        evidence_refs = {a["source_path"] for a in artifacts}
        report = dict(report or {})
        for item in report.get("findings", []):
            if any(ref not in evidence_refs for ref in item.get("evidence_refs", [])):
                raise ValueError("finding refers to evidence not in the bundle")
        case = {"schema": "arena.case.v1", "case_id": uuid.uuid4().hex,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "source_root": str(source), "title": report.get("title", source.name),
                "summary": report.get("summary", "Imported evidence; report claims and current host state have not been independently re-verified."),
                "evidence_context": report.get("evidence_context", "historical_or_mixed_unclassified"),
                "findings": report.get("findings", []), "timeline": report.get("timeline", []),
                "actions": report.get("actions", []), "verification": report.get("verification", []),
                "limitations": report.get("limitations", []),
                "artifact_count": len(artifacts), "raw_bytes": total,
                "privacy": "Local restricted bundle; raw logs, credentials and malware may be present. Not a sanitized public export.",
                "samples_executed_by_collector": False}
        write_json(output / "case.json", case, private=True)
        write_json(output / "evidence/manifest.json", {"artifacts": artifacts, "skipped": skipped}, private=True)
        write_json(output / "samples/manifest.json", {"artifacts": [a for a in artifacts if a["potentially_executable_content"]],
                   "note": "Potential executable content is a file-format label, not a malware verdict. Originals remain only under private/raw."}, private=True)
        lines = [f"# {case['title']}", "", case["summary"], "",
                 f"Case ID: `{case['case_id']}`", f"Evidence context: `{case['evidence_context']}`", "",
                 f"Collected {len(artifacts)} files ({total} bytes), with verified SHA256 copies.",
                 "Raw evidence is under private/raw; source files were not modified or executed.", "",
                 "## Findings", ""]
        for finding in case["findings"]:
            lines.append(f"- [{finding.get('basis', 'unspecified')}] {finding.get('summary', '')}")
        if not case["findings"]:
            lines.append("No analysis claims were inferred from filenames or directory names.")
        lines += ["", "## Actions and verification", "",
                  "See case.json for actions actually recorded, their results, and pending checks. Importing a report does not repeat its actions.",
                  "", "## Limitations", "", *[f"- {x}" for x in case["limitations"]], "",
                  "This bundle may contain sensitive raw evidence. Private file permissions do not make malware safe to execute."]
        (output / "README.md").write_text("\n".join(lines) + "\n")
        (output / "README.md").chmod(0o600)
        sealed_files = {str(p.relative_to(output)): _hash(p) for p in output.rglob('*') if p.is_file()
                        and p not in (output / "status.json", output / "bundle-manifest.json")}
        write_json(output / "bundle-manifest.json", {"files": sealed_files}, private=True)
        write_json(output / "status.json", {"state": "complete", "skipped_count": len(skipped)}, private=True)
        return case
    except Exception as error:
        write_json(output / "status.json", {"state": "incomplete", "error": str(error)}, private=True)
        raise


def verify_case(directory: Path):
    root = Path(directory)
    status = json.loads((root / "status.json").read_text())
    if status.get("state") != "complete":
        raise ValueError("case is incomplete")
    manifest = json.loads((root / "bundle-manifest.json").read_text())
    present = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() or p.is_symlink()}
    if present != set(manifest["files"]) | {"status.json", "bundle-manifest.json"}:
        raise ValueError("case file set differs from manifest")
    for relative, expected in manifest["files"].items():
        path = Path(relative)
        with _open_regular(root.resolve(), path) as stream:
            h = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(block)
        if h.hexdigest() != expected:
            raise ValueError(f"case artifact changed: {relative}")
    return {"verified": True, "files": len(manifest["files"])}


def archive_case(directory: Path, destination: Path):
    root, destination = Path(directory).resolve(), Path(destination).absolute()
    if root == destination.resolve() or root in destination.resolve().parents:
        raise ValueError("archive must be outside the case tree")
    verify_case(root)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream, tarfile.open(fileobj=stream, mode="w:gz") as tar:
        for path in sorted(root.rglob('*')):
            if path.is_symlink():
                raise ValueError("case contains a symlink")
            if path.is_file():
                relative = path.relative_to(root)
                with _open_regular(root, relative) as item:
                    info = tarfile.TarInfo(str(Path(root.name) / relative))
                    info.size = os.fstat(item.fileno()).st_size
                    info.mode = 0o600
                    tar.addfile(info, item)
    checksum = _hash(destination)
    return {"archive": str(destination), "sha256": checksum, "bytes": destination.stat().st_size}


def package_match(directory: Path):
    root = Path(directory)
    scored = json.loads((root / "score.json").read_text())
    findings = [{"basis": "verified_outcome", "summary": f"{name}: observed loss {row['loss']}",
                 "evidence_refs": ["score.json", "effects.jsonl"]}
                for name, row in (scored.get("components") or {}).items() if row["loss"] > 0]
    timeline = [{"relative_seconds": row["elapsed"], "event": row["data"]["phase"], "basis": "controller_event"}
                for row in read_journal(root / "effects.jsonl") if row["kind"] == "match.phase"]
    actions = [{"relative_seconds": row["elapsed"], **row["data"]}
               for row in read_journal(root / "blue_trajectory.jsonl")
               if row["kind"] == "tool" and row["data"]["name"] != "observe"]
    report = {"title": f"Arena case: {root.name}", "summary": f"Scored: {scored.get('scored')}; protection reward: {scored.get('blue_reward')}",
              "evidence_context": "controlled_application_match", "findings": findings,
              "timeline": timeline, "actions": actions,
              "verification": [{"scored": scored.get("scored"), "evidence_refs": ["score.json"]}],
              "limitations": ["Application-level fixture, not an OS malware or N-day reproduction.",
                              "Raw evidence includes private synthetic assets and must not be exposed as agent input."]}
    return package_case(root, root.with_name(root.name + ".case"), report)
