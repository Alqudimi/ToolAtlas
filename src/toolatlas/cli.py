"""Command-line interface for ToolAtlas."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from toolatlas.adapters.json_source import parse_document
from toolatlas.application.services import compare_manifests, compile_policy, scan
from toolatlas.domain.errors import ToolAtlasError
from toolatlas.domain.models import PolicyOptions, ScanOptions, ScanResult, Severity
from toolatlas.reporting.renderers import (
    diff_report,
    json_policy,
    json_report,
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="toolatlas", description="Inventory and govern agent capabilities."
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
    before = _scan(arguments.before).manifest
    after = _scan(arguments.after).manifest
    diff = compare_manifests(before, after)
    if arguments.format == "json":
        content = (
            __import__("json").dumps(
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


def main(argv: list[str] | None = None) -> int:
    try:
        return _run(_parser().parse_args(argv))
    except ToolAtlasError as exc:
        print(f"{exc.code}: {exc}", file=sys.stderr)
        return exc.exit_code
    except (OSError, ValueError) as exc:
        print(f"INVALID_INPUT: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("INTERRUPTED", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
