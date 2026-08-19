"""Adversarial schema validation and CLI boundary coverage for ToolAtlas.

Exercises the previously uncovered error-rendering, input-validation, and
boundary branches of the adapter, domain, application, and CLI layers.
All tests run fully offline with no network access.
"""

from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
from unittest import mock

import pytest

from toolatlas.adapters.json_source import parse_document
from toolatlas.application.repository_artifacts import (
    InputError,
    manifest_payload,
    read_json,
    verify_baseline,
    verify_lock,
)
from toolatlas.application.repository_scan import scan_repository
from toolatlas.application.services import compare_manifests, scan
from toolatlas.cli import main
from toolatlas.domain.errors import InputTooLargeError, ManifestDrift, SchemaError
from toolatlas.domain.models import CapabilityKind, ScanOptions, Severity
from toolatlas.domain.repository import FileKind


def _good_catalog() -> dict:
    return {"capabilities": [{"name": "read_file", "description": "Read a file"}]}


def _encode(document: dict) -> bytes:
    return json.dumps(document).encode("utf-8")


class TestJsonSourceAdversarialInputs:
    def test_root_document_must_be_an_object(self) -> None:
        with pytest.raises(SchemaError, match="root document must be an object"):
            parse_document(b"[]", "list.json", 10_000, 100)

    def test_invalid_utf8_is_rejected(self) -> None:
        with pytest.raises(SchemaError, match="valid UTF-8 JSON"):
            parse_document(b"\xff\xfe", "broken.bin", 10_000, 100)

    def test_malformed_json_is_rejected(self) -> None:
        with pytest.raises(SchemaError, match="valid UTF-8 JSON"):
            parse_document(b"{not json", "broken.json", 10_000, 100)

    def test_raw_bytes_exceeding_limit_are_rejected(self) -> None:
        with pytest.raises(InputTooLargeError, match="maximum"):
            parse_document(b"x" * 200, "big.json", 100, 100)

    def test_capabilities_list_with_non_object_raises(self) -> None:
        document = {"tools": ["not-an-object"]}
        with pytest.raises(SchemaError, match="must be an object"):
            parse_document(_encode(document), "x", 10_000, 100)

    def test_document_exceeding_capability_limit_is_rejected(self) -> None:
        document = {"capabilities": [{"name": f"cap{i}"} for i in range(6)]}
        with pytest.raises(InputTooLargeError, match="capabilities"):
            parse_document(_encode(document), "many.json", 100_000, 5)

    def test_record_must_be_an_object(self) -> None:
        document = {"capabilities": ["not-an-object"]}
        with pytest.raises(SchemaError, match="must be an object"):
            parse_document(_encode(document), "x", 10_000, 100)

    def test_empty_name_is_rejected(self) -> None:
        document = {"capabilities": [{"name": "   "}]}
        with pytest.raises(SchemaError, match="name is required"):
            parse_document(_encode(document), "x", 10_000, 100)

    def test_name_exceeding_text_limit_is_rejected(self) -> None:
        document = {"capabilities": [{"name": "c" * 10_001}]}
        with pytest.raises(SchemaError, match="exceeds"):
            parse_document(_encode(document), "x", 100_000, 100)

    def test_non_string_name_is_rejected(self) -> None:
        document = {"capabilities": [{"name": 123}]}
        with pytest.raises(SchemaError, match="must be a string"):
            parse_document(_encode(document), "x", 10_000, 100)

    def test_invalid_scope_array_is_rejected(self) -> None:
        document = {"capabilities": [{"name": "cap", "scopes": "repo:read"}]}
        with pytest.raises(SchemaError, match="array of strings"):
            parse_document(_encode(document), "x", 10_000, 100)

    def test_invalid_metadata_shape_is_rejected(self) -> None:
        document = {"capabilities": [{"name": "cap", "metadata": "not-an-object"}]}
        with pytest.raises(SchemaError, match="must be an object"):
            parse_document(_encode(document), "x", 10_000, 100)

    def test_section_must_be_an_array(self) -> None:
        document = {"tools": "not-an-array"}
        with pytest.raises(SchemaError, match="must be an array"):
            parse_document(_encode(document), "x", 10_000, 100)

    def test_invalid_kind_is_rejected(self) -> None:
        document = {"capabilities": [{"name": "cap", "kind": "plugin"}]}
        with pytest.raises(SchemaError, match="kind is invalid"):
            parse_document(_encode(document), "x", 10_000, 100)

    def test_empty_document_is_rejected(self) -> None:
        with pytest.raises(SchemaError, match="no capabilities"):
            parse_document(b"{}", "empty.json", 10_000, 100)

    def test_duplicate_ids_are_rejected(self) -> None:
        document = {"capabilities": [{"id": "dup", "name": "a"}, {"id": "dup", "name": "b"}]}
        with pytest.raises(SchemaError, match="unique"):
            parse_document(_encode(document), "x", 10_000, 100)

    def test_camel_case_input_names_are_normalized(self) -> None:
        document = {"capabilities": [{"name": "cap", "inputNames": ["token"]}]}
        capabilities = parse_document(_encode(document), "x", 10_000, 100)
        assert capabilities[0].input_names == ("token",)

    def test_stable_id_fallback_uses_kind_and_name(self) -> None:
        document = {"capabilities": [{"name": "untitled"}]}
        capabilities = parse_document(_encode(document), "x", 10_000, 100)
        assert capabilities[0].id == f"{CapabilityKind.TOOL.value}:untitled"


class TestDomainRulesAdversarialBranches:
    def test_broad_scope_is_flagged_ta003(self) -> None:
        document = {"capabilities": [{"name": "danger", "scopes": ["root"]}]}
        capabilities = parse_document(_encode(document), "x", 10_000, 100)
        from toolatlas.application.services import scan

        result = scan(capabilities, "x")
        assert any(finding.rule_id == "TA003" for finding in result.manifest.findings)

    def test_secret_like_metadata_is_flagged_ta004(self) -> None:
        document = {"capabilities": [{"name": "cap", "metadata": {"token": "secret-value"}}]}
        capabilities = parse_document(_encode(document), "x", 10_000, 100)
        from toolatlas.application.services import scan

        result = scan(capabilities, "x")
        finding = next(f for f in result.manifest.findings if f.rule_id == "TA004")
        assert finding.severity == Severity.MEDIUM

    def test_diff_properties_classify_changes(self) -> None:
        from toolatlas.application.services import scan

        catalog = {"capabilities": [{"name": "a"}]}
        before = scan(parse_document(_encode(catalog), "x", 100_000, 100), "x").manifest
        catalog["capabilities"][0]["description"] = "new"
        after = scan(parse_document(_encode(catalog), "x", 100_000, 100), "x").manifest
        diff = compare_manifests(before, after)
        assert diff.has_drift
        assert len(diff.added) == 0
        assert len(diff.removed) == 0
        assert any(item.change_type == "changed" for item in diff.changed)


class TestApplicationBoundaryConditions:
    def test_capability_limit_is_enforced(self) -> None:
        catalog = {"capabilities": [{"name": f"c{i}"} for i in range(3)]}
        capabilities = parse_document(_encode(catalog), "x", 10_000, 100)
        with pytest.raises(ValueError, match="capability limit exceeded"):
            scan(capabilities, "x", ScanOptions(max_capabilities=2))

    def test_scan_of_safe_capabilities_returns_clean_exit(self) -> None:
        catalog = {"capabilities": [{"name": "read"}]}
        capabilities = parse_document(_encode(catalog), "x", 10_000, 100)
        result = scan(capabilities, "x")
        assert not result.manifest.findings
        assert result.manifest.digest

    def test_read_json_rejects_missing_path(self) -> None:
        with pytest.raises(InputError, match="cannot read JSON artifact"):
            read_json("/nonexistent/path/lock.json")

    def test_read_json_rejects_invalid_json(self, tmp_path: Path) -> None:
        broken = tmp_path / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        with pytest.raises(InputError, match="cannot read JSON artifact"):
            read_json(broken)

    def test_read_json_rejects_non_object(self, tmp_path: Path) -> None:
        payload = tmp_path / "array.json"
        payload.write_text("[]", encoding="utf-8")
        with pytest.raises(InputError, match="must be a JSON object"):
            read_json(payload)

    def test_verify_lock_rejects_tampered_lockfile(self, tmp_path: Path) -> None:
        (tmp_path / "AGENTS.md").write_text("instructions", encoding="utf-8")
        manifest = scan_repository(tmp_path)
        from toolatlas.application.repository_artifacts import lock_payload
        from toolatlas.application.repository_scan import lock_from_manifest

        lock_data = lock_payload(lock_from_manifest(manifest))
        lock_data["manifest_digest"] = "0" * 64
        with pytest.raises(ManifestDrift):
            verify_lock(manifest, lock_data)

    def test_verify_baseline_rejects_malformed_findings(self, tmp_path: Path) -> None:
        (tmp_path / "AGENTS.md").write_text("safe", encoding="utf-8")
        manifest = scan_repository(tmp_path)
        from toolatlas.application.repository_scan import baseline_from_manifest

        current = baseline_from_manifest(manifest)
        with pytest.raises(InputError, match="array of strings"):
            verify_baseline(manifest, {"findings": "not-a-list"})
        with pytest.raises(InputError, match="array of strings"):
            verify_baseline(manifest, {"findings": [1, 2]})
        # known finding is subtracted from the current set
        new = verify_baseline(manifest, {"findings": list(current.findings)})
        assert new == ()

    def test_manifest_payload_round_trips(self, tmp_path: Path) -> None:
        (tmp_path / "AGENTS.md").write_text("instructions", encoding="utf-8")
        manifest = scan_repository(tmp_path)
        payload = manifest_payload(manifest)
        assert payload["schema_version"] == 1
        assert payload["root_name"] == tmp_path.name
        assert payload["digest"] == manifest.digest


class TestCliBoundaryCoverage:
    def test_scan_with_stdin_input(self, capsys) -> None:
        payload = json.dumps({"capabilities": [{"name": "read"}]}).encode()
        stdin_mock = mock.MagicMock(buffer=BytesIO(payload))
        with mock.patch("sys.stdin", stdin_mock):
            assert main(["scan", "-", "--format", "json"]) == 0

    def test_scan_with_nonexistent_input_file(self) -> None:
        assert main(["scan", "/nonexistent/catalog.json"]) == 2

    def test_keyboard_interrupt_is_reported(self) -> None:
        with mock.patch("toolatlas.cli._parser", side_effect=KeyboardInterrupt):
            assert main(["scan", "/dev/null"]) == 130

    def test_policy_command_compiles_and_writes(self, tmp_path: Path) -> None:
        source = tmp_path / "catalog.json"
        catalog = {"capabilities": [{"name": "read", "scopes": ["repo:read"]}]}
        source.write_text(_encode(catalog).decode(), encoding="utf-8")
        policy = tmp_path / "policy.json"
        assert main(["policy", str(source), "--output", str(policy)]) == 0
        data = json.loads(policy.read_text(encoding="utf-8"))
        assert data["schema_version"] == 1

    def test_diff_json_format_reports_changes(self, tmp_path: Path) -> None:
        before = tmp_path / "before.json"
        before.write_text(_encode({"capabilities": [{"name": "a"}]}).decode(), encoding="utf-8")
        after = tmp_path / "after.json"
        after.write_text(_encode({"capabilities": [{"name": "b"}]}).decode(), encoding="utf-8")
        assert main(["diff", str(before), str(after), "--format", "json"]) == 4

    def test_diff_terminal_format_reports_drift(self, tmp_path: Path, capsys) -> None:
        before = tmp_path / "before.json"
        before.write_text(_encode({"capabilities": [{"name": "a"}]}).decode(), encoding="utf-8")
        after = tmp_path / "after.json"
        after.write_text(_encode({"capabilities": [{"name": "b"}]}).decode(), encoding="utf-8")
        assert main(["diff", str(before), str(after)]) == 4
        output = capsys.readouterr().out
        assert output

    def test_repo_scan_json_format(self, tmp_path: Path) -> None:
        (tmp_path / "AGENTS.md").write_text("instructions", encoding="utf-8")
        out = tmp_path / "manifest.json"
        assert main(["repo-scan", str(tmp_path), "--format", "json", "--output", str(out)]) == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["schema_version"] == 1
        assert data["root_name"] == tmp_path.name

    def test_repo_scan_terminal_format_lists_findings(self, tmp_path: Path, capsys) -> None:
        (tmp_path / "AGENTS.md").write_text("safe instructions", encoding="utf-8")
        assert main(["repo-scan", str(tmp_path)]) == 0
        output = capsys.readouterr().out
        assert "repository:" in output

    def test_repo_scan_drift_exit_code_on_high_findings(self, tmp_path: Path) -> None:
        (tmp_path / "secrets.txt").write_text("token=super-secret-value-1234", encoding="utf-8")
        assert main(["repo-scan", str(tmp_path), "--format", "terminal"]) == 3

    def test_baseline_check_reports_new_findings(self, tmp_path: Path, capsys) -> None:
        (tmp_path / "AGENTS.md").write_text("safe instructions", encoding="utf-8")
        baseline = tmp_path / "baseline.json"
        assert main(["baseline", str(tmp_path), "--output", str(baseline)]) == 0
        (tmp_path / "secrets.txt").write_text("token=super-secret-value-1234", encoding="utf-8")
        assert main(["baseline", str(tmp_path), "--output", str(baseline), "--check"]) == 3
        data = json.loads(capsys.readouterr().out)
        assert data["new_findings"]

    def test_unknown_command_exits_with_invalid_input(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["unknown-command"])
        assert exc_info.value.code == 2

    def test_missing_subcommand_exits_with_invalid_input(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main([])
        assert exc_info.value.code == 2

    def test_module_entry_raises_system_exit(self) -> None:
        import runpy

        with mock.patch("toolatlas.cli.main", return_value=130):
            with pytest.raises(SystemExit):
                runpy.run_path(
                    str(Path(__file__).parent.parent / "src" / "toolatlas" / "__main__.py"),
                    run_name="__main__",
                )

    def test_file_count_limit_is_rejected_with_correct_error(self, tmp_path: Path) -> None:
        for index in range(4):
            (tmp_path / f"file{index}.md").write_text("content", encoding="utf-8")
        with pytest.raises(InputTooLargeError, match="scannable files"):
            scan_repository(tmp_path, max_files=2)


class TestFileClassificationBranches:
    def test_classify_mcp_config(self) -> None:
        from toolatlas.application.repository_scan import _kind

        assert _kind(Path("mcp_servers.json"), '{"servers": {"mcp": {}}}') == FileKind.MCP_CONFIG

    def test_classify_source_and_document(self) -> None:
        from toolatlas.application.repository_scan import _kind

        assert _kind(Path("tool.py"), "print(1)") == FileKind.SOURCE
        assert _kind(Path("README.md"), "# readme") == FileKind.DOCUMENT

    def test_classify_other(self) -> None:
        from toolatlas.application.repository_scan import _kind

        assert _kind(Path("icon.png"), "") == FileKind.OTHER

    def test_ignored_directories_are_skipped(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text("data", encoding="utf-8")
        (tmp_path / "AGENTS.md").write_text("safe", encoding="utf-8")
        manifest = scan_repository(tmp_path)
        assert not any(".git" in str(item) for item in manifest.files)

    def test_file_count_limit_is_enforced(self, tmp_path: Path) -> None:
        for index in range(5):
            (tmp_path / f"file{index}.md").write_text("content", encoding="utf-8")
        with pytest.raises(InputTooLargeError, match="scannable files"):
            scan_repository(tmp_path, max_files=3)

    def test_manifest_payload_embeds_scan_results(self, tmp_path: Path) -> None:
        from toolatlas.application.repository_scan import _manifest_payload

        (tmp_path / "AGENTS.md").write_text("instructions", encoding="utf-8")
        manifest = scan_repository(tmp_path)
        payload = _manifest_payload(manifest)
        assert payload["root_name"] == tmp_path.name
        assert payload["scanner_version"] == manifest.scanner_version
        assert len(payload["files"]) == len(manifest.files)

    def test_escaping_symlink_rejected_explicitly(self, tmp_path: Path) -> None:
        outside = tmp_path.parent / "outside-secret.txt"
        outside.write_text("secret", encoding="utf-8")
        (tmp_path / "escape").symlink_to(outside)
        with pytest.raises(Exception, match="symlink escapes"):
            scan_repository(tmp_path)

    def test_non_directory_root_is_rejected(self, tmp_path: Path) -> None:
        file_root = tmp_path / "file.txt"
        file_root.write_text("not a directory", encoding="utf-8")
        with pytest.raises(Exception, match="not a directory"):
            scan_repository(file_root)

    def test_internal_symlink_is_accepted(self, tmp_path: Path) -> None:
        target = tmp_path / "target.md"
        target.write_text("target content", encoding="utf-8")
        (tmp_path / "link.md").symlink_to(target)
        manifest = scan_repository(tmp_path)
        assert any(item.path == "target.md" or item.path == "link.md" for item in manifest.files)
