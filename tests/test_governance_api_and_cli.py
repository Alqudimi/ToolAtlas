"""Tests for the governance API boundary contracts and CLI exit codes.

Covers behavior that was previously untested: ``ManifestDiff`` convenience
properties, baseline/check and lock/verify CLI paths, repository scan formats,
policy severity filtering, and the TA003 broad-scope rule branch.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from toolatlas.application.repository_artifacts import (
    baseline_from_manifest,
    baseline_payload,
    lock_from_manifest,
    lock_payload,
    verify_baseline,
    verify_lock,
)
from toolatlas.application.repository_scan import scan_repository
from toolatlas.cli import main
from toolatlas.domain.models import (
    Capability,
    CapabilityKind,
    ManifestChange,
    ManifestDiff,
)
from toolatlas.domain.rules import evaluate

CATALOG = {
    "capabilities": [
        {
            "id": "safe.tool",
            "name": "safe tool",
            "kind": "tool",
            "description": "benign",
        },
        {
            "id": "broad.tool",
            "name": "broad tool",
            "kind": "tool",
            "description": "wide scope",
            "scopes": ["*"],
        },
        {
            "id": "broad.root",
            "name": "root tool",
            "kind": "tool",
            "description": "privileged",
            "scopes": ["root:all"],
        },
    ]
}


def _write_catalog(path: Path) -> Path:
    path.write_text(json.dumps(CATALOG), encoding="utf-8")
    return path


def _write_safe_catalog(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "capabilities": [
                    {
                        "id": "safe.tool",
                        "name": "safe tool",
                        "kind": "tool",
                        "description": "benign",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


class TestManifestDiffProperties:
    """Properties on ``ManifestDiff`` are the documented API for drift review."""

    def test_has_drift_is_false_when_no_changes(self) -> None:
        diff = ManifestDiff("a", "b", ())
        assert not diff.has_drift
        assert diff.added == ()
        assert diff.removed == ()
        assert diff.changed == ()

    def test_added_filters_created_capabilities(self) -> None:
        change = ManifestChange("new.tool", "added")
        diff = ManifestDiff("a", "b", (change,))
        assert diff.has_drift
        assert diff.added == (change,)
        assert diff.removed == ()
        assert diff.changed == ()

    def test_removed_filters_deleted_capabilities(self) -> None:
        change = ManifestChange("gone.tool", "removed")
        diff = ManifestDiff("a", "b", (change,))
        assert diff.removed == (change,)
        assert diff.added == ()

    def test_changed_filters_modified_capabilities(self) -> None:
        before = Capability("t", "name", CapabilityKind.TOOL, "desc")
        after = Capability("t", "name", CapabilityKind.TOOL, "changed desc")
        change = ManifestChange("t", "changed", before, after)
        diff = ManifestDiff("a", "b", (change,))
        assert diff.changed == (change,)
        assert diff.has_drift


class TestRuleBroadScope:
    """TA003 fires only for broad scopes and not for narrow explicit ones."""

    def test_wildcard_scope_triggers_ta003(self) -> None:
        capability = Capability("t", "t", CapabilityKind.TOOL, "d", scopes=("*",))
        findings = evaluate((capability,))
        assert any(finding.rule_id == "TA003" for finding in findings)
        assert any("broad or privileged scope" in finding.title for finding in findings)

    def test_root_scope_triggers_ta003(self) -> None:
        capability = Capability("t", "t", CapabilityKind.TOOL, "d", scopes=("root:all",))
        findings = evaluate((capability,))
        assert any(finding.rule_id == "TA003" for finding in findings)

    def test_narrow_scope_does_not_trigger_ta003(self) -> None:
        capability = Capability("t", "t", CapabilityKind.TOOL, "d", scopes=("files:read",))
        findings = evaluate((capability,))
        assert not any(finding.rule_id == "TA003" for finding in findings)


class TestLockAndBaselineContracts:
    """Lock and baseline artifacts must round-trip and verify deterministically."""

    def test_lock_round_trip_verifies(self, tmp_path: Path) -> None:
        manifest = scan_repository(tmp_path)
        lock_data = lock_payload(lock_from_manifest(manifest))
        payload_path = tmp_path / "lock.json"
        payload_path.write_text(json.dumps(lock_data), encoding="utf-8")
        # verify_lock is the exact comparison used by the CLI --verify path.
        verify_lock(manifest, lock_data)

    def test_verify_lock_raises_drift_on_tampered_payload(self, tmp_path: Path) -> None:
        from toolatlas.domain.errors import ManifestDrift

        manifest = scan_repository(tmp_path)
        lock_data = lock_payload(lock_from_manifest(manifest))
        lock_data["digest"] = "tampered"
        with pytest.raises(ManifestDrift):
            verify_lock(manifest, lock_data)

    def test_baseline_check_finds_new_findings(self, tmp_path: Path) -> None:
        manifest = scan_repository(tmp_path)
        current = baseline_from_manifest(manifest)
        # Declare only a subset of current findings as known.
        known = list(current.findings)[0:1] if current.findings else []
        known_data = {"findings": known}
        new_findings = verify_baseline(manifest, known_data)
        assert new_findings == tuple(sorted(set(current.findings) - set(known)))

    def test_baseline_check_returns_empty_when_all_known(self, tmp_path: Path) -> None:
        manifest = scan_repository(tmp_path)
        current = baseline_from_manifest(manifest)
        known_data = {"findings": list(current.findings)}
        assert verify_baseline(manifest, known_data) == ()

    def test_baseline_rejects_non_string_entries(self, tmp_path: Path) -> None:
        from toolatlas.domain.errors import InputError

        manifest = scan_repository(tmp_path)
        with pytest.raises(InputError):
            verify_baseline(manifest, {"findings": [123]})

    def test_baseline_payload_shape_is_stable(self, tmp_path: Path) -> None:
        manifest = scan_repository(tmp_path)
        payload = baseline_payload(baseline_from_manifest(manifest))
        assert payload["schema_version"] == 1
        assert isinstance(payload["findings"], list)


class TestCliGovernancePaths:
    """CLI exit codes and formats for lock, baseline, repo-scan, and policy."""

    def test_lock_creates_payload_and_verify_succeeds(
        self, tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        # The lockfile must live outside the scanned root: keeping it inside
        # adds the artifact itself to the manifest and changes the digest,
        # which is the documented self-referential boundary of ``lock --verify``.
        lock_dir = tmp_path_factory.mktemp("artifacts")
        lock_path = lock_dir / "lock.json"
        assert main(["lock", str(tmp_path), "--output", str(lock_path)]) == 0
        data = json.loads(lock_path.read_text(encoding="utf-8"))
        assert data["schema_version"] == 1
        assert main(["lock", str(tmp_path), "--output", str(lock_path), "--verify"]) == 0

    def test_lock_artifact_inside_root_changes_digest(self, tmp_path: Path) -> None:
        # Placing the lockfile inside the scanned root makes the repository
        # content differ on the next scan, so ``--verify`` reports drift.
        # This documents the self-referential boundary rather than hiding it.
        lock_path = tmp_path / "lock.json"
        assert main(["lock", str(tmp_path), "--output", str(lock_path)]) == 0
        assert main(["lock", str(tmp_path), "--output", str(lock_path), "--verify"]) == 4

    def test_baseline_check_new_findings_exits_three(self, tmp_path: Path) -> None:
        # A scanned file must exist so the baseline actually holds a finding.
        (tmp_path / "AGENTS.md").write_text(
            "Use the token: super-secret-value-1234\n", encoding="utf-8"
        )
        baseline_path = tmp_path / "baseline.json"
        assert main(["baseline", str(tmp_path), "--output", str(baseline_path)]) == 0
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
        # Drop one known finding so the check reports a new finding.
        data["findings"] = data["findings"][1:]
        baseline_path.write_text(json.dumps(data), encoding="utf-8")
        assert main(["baseline", str(tmp_path), "--output", str(baseline_path), "--check"]) == 3

    def test_baseline_check_clean_exits_zero(self, tmp_path: Path) -> None:
        baseline_path = tmp_path / "baseline.json"
        assert main(["baseline", str(tmp_path), "--output", str(baseline_path)]) == 0
        assert main(["baseline", str(tmp_path), "--output", str(baseline_path), "--check"]) == 0

    def test_repo_scan_json_format(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        assert main(["repo-scan", str(tmp_path), "--format", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert "root_name" in payload and "digest" in payload

    def test_repo_scan_sarif_format(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        assert main(["repo-scan", str(tmp_path), "--format", "sarif"]) == 0
        sarif = json.loads(capsys.readouterr().out)
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "ToolAtlas repository gate"

    def test_repo_scan_high_findings_exit_three(self, tmp_path: Path) -> None:
        (tmp_path / "server.json").write_text(
            json.dumps({"command": "curl", "args": ["https://example.invalid/upload"]}),
            encoding="utf-8",
        )
        assert main(["repo-scan", str(tmp_path), "--format", "json"]) == 3

    def test_policy_max_severity_low_filters_high_findings(self, tmp_path: Path) -> None:
        catalog = _write_catalog(tmp_path / "catalog.json")
        policy_path = tmp_path / "policy.json"
        assert (
            main(["policy", str(catalog), "--max-severity", "low", "--output", str(policy_path)])
            == 0
        )
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        assert "broad.tool" in policy["denied_capability_ids"]

    def test_scan_safe_catalog_exits_zero(self, tmp_path: Path) -> None:
        catalog = _write_safe_catalog(tmp_path / "safe.json")
        assert main(["scan", str(catalog)]) == 0


class TestModuleEntry:
    """``python -m toolatlas`` must delegate to the CLI without a traceback."""

    def test_main_module_exposes_cli_main(self) -> None:
        # ``toolatlas.__main__`` exists solely to re-expose ``cli.main`` for
        # ``python -m toolatlas`` invocation; the module-level name is main.
        import toolatlas.__main__ as main_module
        from toolatlas.cli import main

        assert main_module.main is main
