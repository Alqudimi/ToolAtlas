"""Bounded, offline repository scanner for agent supply-chain signals."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path

from toolatlas.domain.errors import InputTooLargeError, PathSafetyError
from toolatlas.domain.models import Severity
from toolatlas.domain.repository import (
    Baseline,
    FileKind,
    LockEntry,
    RepositoryFinding,
    RepositoryLock,
    RepositoryManifest,
    SourceFile,
)

SCANNER_VERSION = "1.0.0"
_TEXT_EXTENSIONS = {
    ".md",
    ".mdx",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".py",
    ".js",
    ".ts",
    ".sh",
    ".ps1",
}
_CONTEXT_NAMES = {"agents.md", "claude.md", "instructions.md", "skill.md", "system.md"}
_IGNORED_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__"}
_IGNORED_NAMES = {"toolatlas.lock.json", "toolatlas.baseline.json", "toolatlas.sarif"}
_HIDDEN = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0001-\U000e007f\U000e0100-\U000e01ef]"
)
_SECRET = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|token|private[_-]?key)\b\s*[:=]\s*[\"']?[^\s\"']{8,}"
)
_DANGEROUS = re.compile(
    r"(?i)\b(curl|wget|Invoke-WebRequest|powershell|bash|sh|python|node)\b.{0,100}\b(POST|upload|eval|exec|base64|/etc/|\.ssh|webhook)\b"
)
_MCP_MARKERS = re.compile(r"(?i)(mcp|command|args|env|server|tools|resources|prompts)")


def _kind(path: Path, content: str) -> FileKind:
    lower = path.name.casefold()
    if lower in _CONTEXT_NAMES or "/.claude/" in path.as_posix() or "/.github/" in path.as_posix():
        return FileKind.AGENT_CONTEXT
    if path.suffix.casefold() in {".json", ".yaml", ".yml", ".toml"} and _MCP_MARKERS.search(
        content
    ):
        return FileKind.MCP_CONFIG
    if path.suffix.casefold() in {".py", ".js", ".ts", ".sh", ".ps1"}:
        return FileKind.SOURCE
    if path.suffix.casefold() in {".md", ".mdx", ".txt"}:
        return FileKind.DOCUMENT
    return FileKind.OTHER


def _safe_files(root: Path, max_files: int, max_file_bytes: int) -> tuple[Path, ...]:
    root = root.resolve()
    if not root.is_dir():
        raise PathSafetyError(f"repository root is not a directory: {root}")
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        relative_parts = path.relative_to(root).parts
        if any(part in _IGNORED_DIRS for part in relative_parts):
            continue
        if path.name in _IGNORED_NAMES:
            continue
        if path.is_symlink():
            target = path.resolve()
            if root not in target.parents:
                raise PathSafetyError(f"symlink escapes repository root: {path.relative_to(root)}")
            continue
        if not path.is_file() or path.suffix.casefold() not in _TEXT_EXTENSIONS:
            continue
        if path.stat().st_size > max_file_bytes:
            raise InputTooLargeError(f"file exceeds limit: {path.relative_to(root)}")
        files.append(path)
        if len(files) > max_files:
            raise InputTooLargeError(f"repository contains more than {max_files} scannable files")
    return tuple(files)


def _finding(
    rule_id: str,
    severity: Severity,
    path: str,
    line: int,
    title: str,
    evidence: str,
    remediation: str,
    related: Iterable[str] = (),
) -> RepositoryFinding:
    return RepositoryFinding(
        rule_id,
        severity,
        path,
        line,
        title,
        evidence,
        remediation,
        related_paths=tuple(sorted(set(related))),
    )


def _scan_content(path: str, kind: FileKind, content: str) -> list[RepositoryFinding]:
    findings: list[RepositoryFinding] = []
    for line_number, line in enumerate(content.splitlines(), 1):
        if _HIDDEN.search(line):
            findings.append(
                _finding(
                    "TA100",
                    Severity.HIGH,
                    path,
                    line_number,
                    "Hidden Unicode control characters",
                    "invisible or directional Unicode appears in repository content",
                    "Remove hidden Unicode and review the visible text before trusting it.",
                )
            )
        if _SECRET.search(line):
            findings.append(
                _finding(
                    "TA101",
                    Severity.HIGH,
                    path,
                    line_number,
                    "Secret-like literal",
                    "a credential-shaped value appears in tracked content",
                    "Replace the value with a secret reference and rotate any exposed credential.",
                )
            )
        if _DANGEROUS.search(line):
            findings.append(
                _finding(
                    "TA102",
                    Severity.MEDIUM,
                    path,
                    line_number,
                    "Command and external sink combination",
                    "a command-like token is combined with a network, shell, or sensitive sink",
                    "Require explicit review and isolate execution from agent context.",
                )
            )
    if (
        kind == FileKind.MCP_CONFIG
        and "command" in content.casefold()
        and any(token in content.casefold() for token in ("curl", "wget", "powershell"))
    ):
        findings.append(
            _finding(
                "TA103",
                Severity.HIGH,
                path,
                1,
                "MCP configuration launches network-capable command",
                "MCP server configuration combines a command declaration with a network fetcher",
                (
                    "Pin the server source, remove network bootstrap code, or require "
                    "an explicit reviewed exception."
                ),
            )
        )
    return findings


def _manifest_payload(manifest: RepositoryManifest) -> dict[str, object]:
    return {
        "schema_version": manifest.schema_version,
        "root_name": manifest.root_name,
        "scanner_version": manifest.scanner_version,
        "files": [
            {
                "path": item.path,
                "kind": item.kind.value,
                "size": item.size,
                "digest": item.digest,
                "line_count": item.line_count,
            }
            for item in manifest.files
        ],
        "findings": [
            {
                "rule_id": item.rule_id,
                "severity": item.severity.value,
                "path": item.path,
                "line": item.line,
                "title": item.title,
                "evidence": item.evidence,
                "remediation": item.remediation,
                "confidence": item.confidence,
                "related_paths": list(item.related_paths),
            }
            for item in manifest.findings
        ],
    }


def scan_repository(
    root: str | Path, max_files: int = 2_000, max_file_bytes: int = 1_000_000
) -> RepositoryManifest:
    target = Path(root).resolve()
    files: list[SourceFile] = []
    findings: list[RepositoryFinding] = []
    for path in _safe_files(target, max_files, max_file_bytes):
        raw = path.read_bytes()
        content = raw.decode("utf-8", errors="strict")
        relative = path.relative_to(target).as_posix()
        digest = hashlib.sha256(raw).hexdigest()
        kind = _kind(path, content)
        files.append(SourceFile(relative, kind, len(raw), digest, len(content.splitlines())))
        findings.extend(_scan_content(relative, kind, content))
    has_secret = any(item.rule_id == "TA101" for item in findings)
    has_network = any(item.rule_id in {"TA102", "TA103"} for item in findings)
    if has_secret and has_network:
        secret_paths = [item.path for item in findings if item.rule_id == "TA101"]
        network_paths = [item.path for item in findings if item.rule_id in {"TA102", "TA103"}]
        findings.append(
            _finding(
                "TA110",
                Severity.CRITICAL,
                network_paths[0],
                1,
                "Cross-file secret-to-network risk",
                (
                    "secret-like material and network-capable behavior co-exist "
                    "in the scanned repository"
                ),
                (
                    "Remove the secret, isolate network behavior, and review all "
                    "related files before deployment."
                ),
                secret_paths + network_paths,
            )
        )
    files_tuple = tuple(sorted(files, key=lambda item: item.path))
    findings_tuple = tuple(sorted(findings, key=lambda item: (item.path, item.line, item.rule_id)))
    payload = json.dumps(
        {
            "schema_version": 1,
            "root_name": target.name,
            "scanner_version": SCANNER_VERSION,
            "files": [
                item.__dict__
                if hasattr(item, "__dict__")
                else {
                    "path": item.path,
                    "kind": item.kind.value,
                    "size": item.size,
                    "digest": item.digest,
                    "line_count": item.line_count,
                }
                for item in files_tuple
            ],
            "findings": [
                {
                    "rule_id": item.rule_id,
                    "severity": item.severity.value,
                    "path": item.path,
                    "line": item.line,
                    "title": item.title,
                    "evidence": item.evidence,
                    "remediation": item.remediation,
                    "confidence": item.confidence,
                    "related_paths": list(item.related_paths),
                }
                for item in findings_tuple
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return RepositoryManifest(
        1,
        target.name,
        SCANNER_VERSION,
        files_tuple,
        findings_tuple,
        hashlib.sha256(payload).hexdigest(),
    )


def lock_from_manifest(manifest: RepositoryManifest) -> RepositoryLock:
    return RepositoryLock(
        1,
        manifest.scanner_version,
        manifest.root_name,
        tuple(
            LockEntry(item.path, item.size, item.digest, item.kind, item.line_count)
            for item in manifest.files
        ),
        manifest.digest,
    )


def baseline_from_manifest(manifest: RepositoryManifest) -> Baseline:
    keys = tuple(sorted(f"{item.rule_id}:{item.path}:{item.line}" for item in manifest.findings))
    return Baseline(1, manifest.digest, keys)
