import hashlib
import json
from pathlib import Path
import tarfile

import pytest

from arena.cases import archive_case, package_case, verify_case


def test_case_preserves_bytes_without_executing_samples_or_following_links(tmp_path):
    source = tmp_path / "original"
    source.mkdir()
    marker = tmp_path / "executed"
    sample = source / "sample.sh"
    sample.write_text(f"#!/bin/sh\ntouch {marker}\n")
    sample.chmod(0o755)
    (source / "evidence").mkdir()
    (source / "evidence/status.json").write_text('{"original":true}')
    outside = tmp_path / "outside-secret"
    outside.write_text("must not be copied")
    (source / "outside-link").symlink_to(outside)
    before = hashlib.sha256(sample.read_bytes()).hexdigest()
    out = tmp_path / "case"
    result = package_case(source, out)
    assert result["artifact_count"] == 2
    assert not marker.exists()
    assert not (out / "private/raw/outside-link").exists()
    assert (out / "private/raw/sample.sh").read_bytes() == sample.read_bytes()
    assert (out / "private/raw/sample.sh").stat().st_mode & 0o111 == 0
    assert sample.stat().st_mode & 0o111
    assert hashlib.sha256(sample.read_bytes()).hexdigest() == before
    assert verify_case(out)["verified"]
    archive = archive_case(out, tmp_path / "case.tar.gz")
    with tarfile.open(archive["archive"]) as tar:
        assert all(not m.issym() and not m.islnk() and not m.mode & 0o111 for m in tar.getmembers())


def test_mutation_of_nested_status_file_is_detected(tmp_path):
    source = tmp_path / "source";source.mkdir()
    (source / "status.json").write_text("original")
    out = tmp_path / "case";package_case(source, out)
    (out / "private/raw/status.json").write_text("changed")
    with pytest.raises(ValueError):verify_case(out)


def test_added_files_and_uncollected_evidence_references_are_rejected(tmp_path):
    source = tmp_path / "source";source.mkdir();(source / "log").write_text("data")
    with pytest.raises(ValueError):
        package_case(source, tmp_path / "bad", {"findings": [{"evidence_refs": ["does-not-exist"]}]})
    assert json.loads((tmp_path / "bad/status.json").read_text())["state"] == "incomplete"
    out = tmp_path / "good";package_case(source, out)
    (out / "injected").write_text("unexpected")
    with pytest.raises(ValueError):verify_case(out)


def test_collection_budget_and_nested_destination_fail_explicitly(tmp_path):
    source = tmp_path / "source";source.mkdir();(source / "log").write_text("0123456789")
    with pytest.raises(ValueError):package_case(source, source / "nested")
    with pytest.raises(ValueError):package_case(source, tmp_path / "limited", max_bytes=4)
    assert (source / "log").read_text() == "0123456789"


def test_case_defaults_do_not_assert_compromise_from_names(tmp_path):
    source = tmp_path / "CVE-2099-12345_miner";source.mkdir()
    (source / "malware.txt").write_text("this is only a claim")
    case = package_case(source, tmp_path / "case")
    assert case["findings"] == []
    assert case["samples_executed_by_collector"] is False
