"""Command-line interface for ToolAtlas."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from toolatlas.adapters.json_source import parse_document
from toolatlas.application.repository_artifacts import (
    baseline_payload,
    lock_payload,
    manifest_payload,
    read_json,
    verify_baseline,
    verify_lock,
    write_json,
)
from toolatlas.application.repository_scan import (
    baseline_from_manifest,
    lock_from_manifest,
    scan_repository,
)
from toolatlas.application.services import compare_manifests, compile_policy, scan
from toolatlas.domain.errors import ToolAtlasError
from toolatlas.domain.models import PolicyOptions, ScanOptions, ScanResult, Severity
from toolatlas.domain.repository import RepositoryManifest
from toolatlas.reporting.renderers import (
    diff_report,
    json_policy,
    json_report,
    repository_sarif_report,
    sarif_report,
    terminal_report,
)


def _read(path: str, max_bytes: int) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read(max_bytes + 1)
    candidate = Path(path)
    if not candidate.is_file():
        raise ValueError(f"input file does not exist: {path}")
    return candidate.read_bytes()


def _write(path: str | None, content: str) -> None:
    if path is None or path == "-":
        sys.stdout.write(content)
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _scan(path: str) -> ScanResult:
    options = ScanOptions()
    raw = _read(path, options.max_bytes)
    capabilities = parse_document(raw, path, options.max_bytes, options.max_capabilities)
    return scan(capabilities, path, options)


def _repository_json(manifest: RepositoryManifest) -> str:
    return (
        json.dumps(manifest_payload(manifest), ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    )


def _repository_terminal(manifest: RepositoryManifest) -> str:
    lines = [
        f"repository: {manifest.root_name}",
        f"files: {len(manifest.files)}",
        f"digest: {manifest.digest}",
        f"findings: {len(manifest.findings)}",
    ]
    for finding in manifest.findings:
        lines.append(
            f"[{finding.severity.value.upper()}] {finding.rule_id} "
            f"{finding.path}:{finding.line} — {finding.title}"
        )
        lines.append(f"  evidence: {finding.evidence}")
        lines.append(f"  remediation: {finding.remediation}")
    return "\n".join(lines) + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="toolatlas", description="Inventory and govern agent capabilities and repositories."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="scan a JSON capability catalog")
    scan_parser.add_argument("input")
    scan_parser.add_argument("--format", choices=("terminal", "json", "sarif"), default="terminal")
    scan_parser.add_argument("--output", default=None)
    policy_parser = subparsers.add_parser("policy", help="compile a least-privilege policy")
    policy_parser.add_argument("input")
    policy_parser.add_argument(
        "--max-severity", choices=tuple(item.value for item in Severity), default="medium"
    )
    policy_parser.add_argument("--output", default=None)
    diff_parser = subparsers.add_parser("diff", help="compare two capability catalogs")
    diff_parser.add_argument("before")
    diff_parser.add_argument("after")
    diff_parser.add_argument("--format", choices=("terminal", "json"), default="terminal")
    diff_parser.add_argument("--output", default=None)
    repo_parser = subparsers.add_parser(
        "repo-scan", help="scan a repository without executing its content"
    )
    repo_parser.add_argument("root")
    repo_parser.add_argument("--format", choices=("terminal", "json", "sarif"), default="terminal")
    repo_parser.add_argument("--output", default=None)
    repo_parser.add_argument("--max-files", type=int, default=2000)
    repo_parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    lock_parser = subparsers.add_parser(
        "lock", help="create or verify a deterministic repository lockfile"
    )
    lock_parser.add_argument("root")
    lock_parser.add_argument("--output", default="toolatlas.lock.json")
    lock_parser.add_argument("--verify", action="store_true")
    lock_parser.add_argument("--max-files", type=int, default=2000)
    lock_parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    baseline_parser = subparsers.add_parser("baseline", help="create or check a finding baseline")
    baseline_parser.add_argument("root")
    baseline_parser.add_argument("--output", default="toolatlas.baseline.json")
    baseline_parser.add_argument("--check", action="store_true")
    baseline_parser.add_argument("--max-files", type=int, default=2000)
    baseline_parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    return parser


def _run(arguments: argparse.Namespace) -> int:
    if arguments.command == "scan":
        result = _scan(arguments.input)
        content = {"terminal": terminal_report, "json": json_report, "sarif": sarif_report}[
            arguments.format
        ](result)
        _write(arguments.output, content)
        return (
            3
            if any(item.severity.rank >= Severity.HIGH.rank for item in result.manifest.findings)
            else 0
        )
    if arguments.command == "policy":
        result = _scan(arguments.input)
        policy = compile_policy(result, PolicyOptions(Severity(arguments.max_severity)))
        _write(arguments.output, json_policy(policy))
        return 0
    if arguments.command == "diff":
        before = _scan(arguments.before).manifest
        after = _scan(arguments.after).manifest
        diff = compare_manifests(before, after)
        if arguments.format == "json":
            content = (
                json.dumps(
                    {
                        "before_digest": diff.before_digest,
                        "after_digest": diff.after_digest,
                        "changes": [
                            {"id": change.capability_id, "type": change.change_type}
                            for change in diff.changes
                        ],
                    },
                    indent=2,
                )
                + "\n"
            )
        else:
            content = diff_report(diff)
        _write(arguments.output, content)
        return 4 if diff.has_drift else 0
    manifest = scan_repository(
        arguments.root,
        max_files=getattr(arguments, "max_files", 2000),
        max_file_bytes=getattr(arguments, "max_file_bytes", 1_000_000),
    )
    if arguments.command == "repo-scan":
        content = (
            _repository_terminal(manifest)
            if arguments.format == "terminal"
            else _repository_json(manifest)
            if arguments.format == "json"
            else repository_sarif_report(manifest)
        )
        _write(arguments.output, content)
        return (
            3 if any(item.severity.rank >= Severity.HIGH.rank for item in manifest.findings) else 0
        )
    if arguments.command == "lock":
        if arguments.verify:
            verify_lock(manifest, read_json(arguments.output))
            return 0
        write_json(arguments.output, lock_payload(lock_from_manifest(manifest)))
        return 0
    if arguments.check:
        new_findings = verify_baseline(manifest, read_json(arguments.output))
        if new_findings:
            _write(None, json.dumps({"new_findings": list(new_findings)}, indent=2) + "\n")
            return 3
        return 0
    write_json(arguments.output, baseline_payload(baseline_from_manifest(manifest)))
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return _run(_parser().parse_args(argv))
    except ToolAtlasError as exc:
        print(f"{exc.code}: {exc}", file=sys.stderr)
        return exc.exit_code
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"INVALID_INPUT: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("INTERRUPTED", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
