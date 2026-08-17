"""Domain contracts for repository supply-chain scanning."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from toolatlas.domain.models import Severity


class FileKind(StrEnum):
    AGENT_CONTEXT = "agent_context"
    MCP_CONFIG = "mcp_config"
    SOURCE = "source"
    DOCUMENT = "document"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class SourceFile:
    path: str
    kind: FileKind
    size: int
    digest: str
    line_count: int


@dataclass(frozen=True, slots=True)
class RepositoryFinding:
    rule_id: str
    severity: Severity
    path: str
    line: int
    title: str
    evidence: str
    remediation: str
    confidence: float = 1.0
    related_paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RepositoryManifest:
    schema_version: int
    root_name: str
    scanner_version: str
    files: tuple[SourceFile, ...]
    findings: tuple[RepositoryFinding, ...]
    digest: str


@dataclass(frozen=True, slots=True)
class LockEntry:
    path: str
    size: int
    digest: str
    kind: FileKind
    line_count: int


@dataclass(frozen=True, slots=True)
class RepositoryLock:
    schema_version: int
    scanner_version: str
    root_name: str
    entries: tuple[LockEntry, ...]
    manifest_digest: str


@dataclass(frozen=True, slots=True)
class Baseline:
    schema_version: int
    manifest_digest: str
    findings: tuple[str, ...]
