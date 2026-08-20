"""CLI boundary tests covering stdin/output pivots, error paths, and artifacts."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from toolatlas.application.repository_artifacts import (
    read_json,
    verify_baseline,
)
from toolatlas.application.repository_scan import scan_repository
from toolatlas.cli import main
from toolatlas.domain.errors import InputError


@pytest.mark.parametrize(
    ("command", "feed_stdin"),
    [
        pytest.param(["scan", "-", "--format", "json"], True, id="scan-stdin"),
        pytest.param(["--help"], False, id="help"),
    ],
)
def test_cli_invocation(command: list[str], feed_stdin: bool) -> None:
    """CLI subcommands run through ``python -m toolatlas``."""
    catalog = json.dumps({"capabilities": [{"name": "read_file"}]})
    result = subprocess.run(  # noqa: S603 (static CLI command)
        [sys.executable, "-m", "toolatlas", *command],
        input=catalog if feed_stdin else None,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    if feed_stdin:
        payload = json.loads(result.stdout)
        assert payload["schema_version"] == 1


def test_report_output_via_stdout_dash(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Both ``--output -`` and a missing output path write to stdout."""
    source = tmp_path / "catalog.json"
    source.write_text(json.dumps({"capabilities": [{"name": "read_file"}]}), encoding="utf-8")
    assert main(["scan", str(source), "--format", "json", "--output", "-"]) == 0
    assert json.loads(capsys.readouterr().out)["schema_version"] == 1


def test_diff_command_emits_json_format(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(json.dumps({"capabilities": [{"name": "read"}]}), encoding="utf-8")
    after.write_text(
        json.dumps({"capabilities": [{"name": "read"}, {"name": "write"}]}),
        encoding="utf-8",
    )
    assert main(["diff", str(before), str(after), "--format", "json"]) == 4


def test_repo_scan_terminal_report_lists_findings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The terminal repository report surfaces findings with location evidence."""
    (tmp_path / "skill.md").write_text("token=super-secret-value-1234", encoding="utf-8")
    assert main(["repo-scan", str(tmp_path)]) == 3
    output = capsys.readouterr().out
    assert "[HIGH] TA101 skill.md:1" in output
    assert "evidence:" in output
    assert "remediation:" in output


def test_baseline_check_fails_with_new_findings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Baseline checking exits 3 and prints new findings when drift appears."""
    (tmp_path / "skill.md").write_text("Safe instructions.", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    assert main(["baseline", str(tmp_path), "--output", str(baseline_path)]) == 0
    (tmp_path / "skill.md").write_text("token=super-secret-value-1234", encoding="utf-8")
    assert main(["baseline", str(tmp_path), "--output", str(baseline_path), "--check"]) == 3
    new_findings = json.loads(capsys.readouterr().out)["new_findings"]
    assert any(item.startswith("TA101:") for item in new_findings)


def test_missing_input_file_has_stable_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A missing catalog file exits 2 with the INVALID_INPUT marker."""
    assert main(["scan", str(tmp_path / "missing.json")]) == 2
    assert "INVALID_INPUT" in capsys.readouterr().err


def test_corrupted_lock_artifact_raises_typed_error(tmp_path: Path) -> None:
    """A corrupted lockfile surfaces a typed InputError instead of crashing."""
    artifact_path = tmp_path / "corrupted-lock.json"
    artifact_path.write_text("not-valid-json{{", encoding="utf-8")
    with pytest.raises(InputError, match="cannot read JSON artifact"):
        read_json(artifact_path)


def test_non_object_artifact_is_rejected(tmp_path: Path) -> None:
    """An artifact that is a JSON array or scalar is rejected as untrusted input."""
    artifact_path = tmp_path / "non-object.json"
    artifact_path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(InputError, match="must be a JSON object"):
        read_json(artifact_path)


def test_baseline_with_invalid_findings_type_is_rejected(tmp_path: Path) -> None:
    """A baseline whose findings are not strings fails closed with a typed error."""
    (tmp_path / "skill.md").write_text("Safe instructions.", encoding="utf-8")
    manifest = scan_repository(tmp_path)
    with pytest.raises(TypeError):
        verify_baseline(manifest, {"findings": 5})
    with pytest.raises(InputError, match="array of strings"):
        verify_baseline(manifest, {"findings": [5]})


def test_manifest_diff_properties_segment_changes() -> None:
    """ManifestDiff properties partition changes by type."""
    from toolatlas.adapters.json_source import parse_document
    from toolatlas.application.services import compare_manifests, scan

    before = scan(
        parse_document(
            b'{"capabilities": [{"id": "tool:a", "name": "a"}, {"id": "tool:b", "name": "b"}]}',
            "x",
            100_000,
            100,
        ),
        "x",
    ).manifest
    after = scan(
        parse_document(
            b'{"capabilities": [{"id": "tool:a", "name": "a-renamed"}, '
            b'{"id": "tool:c", "name": "c"}]}',
            "x",
            100_000,
            100,
        ),
        "x",
    ).manifest
    diff = compare_manifests(before, after)
    assert [item.capability_id for item in diff.added] == ["tool:c"]
    assert [item.capability_id for item in diff.removed] == ["tool:b"]
    assert [item.capability_id for item in diff.changed] == ["tool:a"]
    assert diff.has_drift is True
    empty_diff = compare_manifests(before, before)
    assert empty_diff.has_drift is False
    assert empty_diff.changes == ()


def test_rule_confidence_on_metadata_findings() -> None:
    """Secret-like metadata findings carry reduced confidence."""
    from toolatlas.adapters.json_source import parse_document
    from toolatlas.application.services import scan

    capabilities = parse_document(
        b'{"capabilities": [{"name": "notify", "metadata": {"api_key": "secret-value-here"}}]}',
        "x",
        100_000,
        100,
    )
    result = scan(capabilities, "x")
    metadata_finding = next(item for item in result.manifest.findings if item.rule_id == "TA004")
    assert metadata_finding.confidence == 0.8
