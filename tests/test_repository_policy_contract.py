"""Regression contract tests for the `repo-policy` gate.

The `repo-policy` command is the pre-deploy static policy gate documented in
ToolAtlas 0.5.0. Its exit code contract (0 pass, 3 violation, 2 invalid input)
and its severity/allow-rule evaluation semantics are security-critical: a
regression in any of them would silently turn a failing gate into a passing
one. The two tests that shipped with the feature exercise the happy path of
each surface only, so this suite pins the failure-facing and boundary
behavior that keeps the gate trustworthy.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from toolatlas.application.repository_policy import RepositoryPolicy, evaluate_repository_policy
from toolatlas.application.repository_scan import scan_repository
from toolatlas.cli import main
from toolatlas.domain.errors import PathSafetyError
from toolatlas.domain.models import Severity
from toolatlas.domain.repository import RepositoryFinding, RepositoryManifest


def _secret_repo(root: Path) -> None:
    """Fixture producing a TA101 (HIGH) secret-like finding."""
    (root / "skill.md").write_text("token=super-secret-value-1234", encoding="utf-8")


def _multi_finding_repo(root: Path) -> None:
    """Fixture producing TA101 (HIGH) and TA102 (MEDIUM) findings together."""
    (root / "skill.md").write_text("token=super-secret-value-1234", encoding="utf-8")
    (root / "run.py").write_text(
        "import os  # curl POST https://example.invalid/upload\n",
        encoding="utf-8",
    )


def test_policy_severity_boundary_blocks_higher_and_allows_lower() -> None:
    """Findings above the threshold fail; findings at or below it pass.

    Policy semantics use strict `severity.rank > max_severity.rank`, so the
    threshold severity itself is never a violation. Mixing severities must
    not let a lower finding drag a higher one past the gate.
    """
    # Build a synthetic manifest so the severity matrix is verified explicitly
    # without depending on scan contents.
    manifest = RepositoryManifest(
        schema_version=1,
        root_name="repo",
        scanner_version="toolatlas",
        files=(),
        findings=(
            RepositoryFinding("TA101", Severity.HIGH, "a.md", 1, "Secret-like literal", "", ""),
            RepositoryFinding("TA102", Severity.MEDIUM, "b.md", 2, "Command sink", "", ""),
        ),
        digest="synthetic",
    )
    # HIGH finding must be a violation when the threshold is MEDIUM.
    medium = evaluate_repository_policy(manifest, RepositoryPolicy(Severity.MEDIUM))
    assert medium.passed is False
    assert medium.violations == (manifest.findings[0],)

    # The threshold severity itself is not a violation.
    high = evaluate_repository_policy(manifest, RepositoryPolicy(Severity.HIGH))
    assert high.passed is True
    assert high.violations == ()

    # Only violations above the threshold; MEDIUM finding is never a violation
    # even when MEDIUM findings exist alongside a CRITICAL one.
    critical = RepositoryManifest(
        schema_version=1,
        root_name="repo",
        scanner_version="toolatlas",
        files=(),
        findings=(
            RepositoryFinding("TA110", Severity.CRITICAL, "c.md", 1, "Cross-file risk", "", ""),
            RepositoryFinding("TA102", Severity.MEDIUM, "b.md", 2, "Command sink", "", ""),
        ),
        digest="synthetic",
    )
    with_critical = evaluate_repository_policy(critical, RepositoryPolicy(Severity.MEDIUM))
    assert with_critical.passed is False
    assert [item.rule_id for item in with_critical.violations] == ["TA110"]


def test_allow_rule_is_partial_and_never_affects_other_findings() -> None:
    """Allowing one rule suppresses only that rule's findings."""
    # Real repository: TA101 (HIGH) + TA102 (MEDIUM) side by side.
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        _multi_finding_repo(repo)
        manifest = scan_repository(repo)
        rule_ids = {finding.rule_id for finding in manifest.findings}
        assert {"TA101", "TA102"} <= rule_ids

        # Correlation rule TA110 (CRITICAL) co-exists with TA101 + TA102, so the
        # partial allow list leaves both the allowed finding out and the
        # remaining violations above the threshold.
        partial = evaluate_repository_policy(
            manifest, RepositoryPolicy(Severity.HIGH, frozenset({"TA101"}))
        )
        # TA101 findings are allowed away; TA102 (MEDIUM) sits below the
        # HIGH threshold, so the only remaining violation is TA110 (CRITICAL).
        assert partial.passed is False
        assert {item.rule_id for item in partial.violations} == {"TA110"}

        # Allow-listing an unknown rule is a no-op; it never clears findings.
        unknown = evaluate_repository_policy(
            manifest, RepositoryPolicy(Severity.MEDIUM, frozenset({"TA999"}))
        )
        # Unknown allow rules are a no-op; TA101 (HIGH) and TA110 (CRITICAL)
        # remain violations above the MEDIUM threshold (TA102 itself is not,
        # because the threshold severity is never a violation).
        assert unknown.passed is False
        assert {item.rule_id for item in unknown.violations} == {"TA101", "TA110"}


def test_allow_list_order_is_normalized_in_result() -> None:
    allow_rules = frozenset({"TA101", "TA102"})
    result = evaluate_repository_policy(
        RepositoryManifest(
            schema_version=1,
            root_name="repo",
            scanner_version="toolatlas",
            files=(),
            findings=(),
            digest="synthetic",
        ),
        RepositoryPolicy(Severity.HIGH, allow_rules),
    )
    assert result.allow_rules == ("TA101", "TA102")


def test_empty_manifest_passes_with_any_threshold() -> None:
    manifest = RepositoryManifest(
        schema_version=1,
        root_name="repo",
        scanner_version="toolatlas",
        files=(),
        findings=(),
        digest="synthetic",
    )
    for severity in Severity:
        result = evaluate_repository_policy(manifest, RepositoryPolicy(severity))
        assert result.passed is True
        assert result.violations == ()
        assert result.evaluated_findings == 0


def test_cli_invalid_root_returns_invalid_input_exit_code(tmp_path: Path) -> None:
    # A regular file is not a directory: OSError → INVALID_INPUT → exit 2.
    regular = tmp_path / "regular.md"
    regular.write_text("nothing suspicious", encoding="utf-8")
    assert main(["repo-policy", str(regular)]) == 2

    # A missing root raises the same contract.
    assert main(["repo-policy", "/nonexistent/toolatlas/root"]) == 2


def test_cli_escaping_symlink_rejects_with_unsafe_path_exit_code(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-toolatlas.md"
    outside.write_text("not part of repository", encoding="utf-8")
    (tmp_path / "escape.md").symlink_to(outside)
    with pytest.raises(PathSafetyError):
        scan_repository(tmp_path)
    # CLI translation: unsafe path → INVALID_INPUT exit code 2.
    assert main(["repo-policy", str(tmp_path)]) == 2


def test_cli_output_file_receives_terminal_and_json_policy_payloads(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _secret_repo(repo)

    terminal_path = tmp_path / "policy.txt"
    assert (
        main(
            [
                "repo-policy",
                str(repo),
                "--max-severity",
                "medium",
                "--format",
                "terminal",
                "--output",
                str(terminal_path),
            ]
        )
        == 3
    )
    terminal_text = terminal_path.read_text(encoding="utf-8")
    assert terminal_text.startswith("policy: FAIL\n")
    assert "[BLOCKED] TA101 skill.md:1 — Secret-like literal" in terminal_text
    # Nothing on stdout when --output is used.
    assert capsys.readouterr().out == ""

    json_path = tmp_path / "policy.json"
    assert (
        main(
            [
                "repo-policy",
                str(repo),
                "--max-severity",
                "medium",
                "--format",
                "json",
                "--output",
                str(json_path),
            ]
        )
        == 3
    )
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["passed"] is False
    assert payload["max_severity"] == "medium"
    assert len(payload["violations"]) == 1
    assert payload["violations"][0]["rule_id"] == "TA101"


def test_cli_clean_repository_passes_with_terminal_format(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    hidden = tmp_path / "hidden-repo"
    hidden.mkdir()
    _secret_repo(hidden)
    repo = tmp_path / "clean-repo"
    repo.mkdir()
    (repo / "README.md").write_text("Safe instructions.", encoding="utf-8")
    assert main(["repo-policy", str(repo), "--format", "terminal"]) == 0
    output = capsys.readouterr().out
    assert output.startswith("policy: PASS\n")
    assert "evaluated_findings: 0" in output
    assert "violations: 0" in output


def test_cli_partial_allow_rule_via_repeated_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _multi_finding_repo(repo)
    assert (
        main(
            [
                "repo-policy",
                str(repo),
                "--max-severity",
                "medium",
                "--allow-rule",
                "TA101",
                "--allow-rule",
                "TA999",
            ]
        )
        == 3
    )
    output = capsys.readouterr().out
    assert output.startswith("policy: FAIL\n")
    # TA101 is allowed away; the unknown rule does nothing; remaining
    # violations above MEDIUM are TA102's correlation result TA110 (CRITICAL).
    assert "[BLOCKED] TA110 run.py:1 —" in output
    assert all(line[0] != "[" or "TA101" not in line for line in output.splitlines())


def test_policy_payload_serializes_violation_evidence_stably() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        _secret_repo(repo)
        manifest = scan_repository(repo)
        result = evaluate_repository_policy(manifest, RepositoryPolicy(Severity.MEDIUM))
        payload = result.payload()
        assert payload["schema_version"] == 1
        assert payload["evaluated_findings"] == len(manifest.findings)
        violation = payload["violations"][0]
        for key in (
            "rule_id",
            "severity",
            "path",
            "line",
            "title",
            "evidence",
            "remediation",
            "related_paths",
        ):
            assert key in violation
        # Stable serialization: sorted keys reproduce the same JSON.
        assert json.dumps(payload, ensure_ascii=False, sort_keys=True) == json.dumps(
            payload, ensure_ascii=False, sort_keys=True
        )
