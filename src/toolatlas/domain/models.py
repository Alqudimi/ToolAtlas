"""Immutable domain contracts for ToolAtlas."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class CapabilityKind(StrEnum):
    TOOL = "tool"
    RESOURCE = "resource"
    PROMPT = "prompt"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


@dataclass(frozen=True, slots=True)
class Capability:
    id: str
    name: str
    kind: CapabilityKind
    description: str
    input_names: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()
    source: str = "unknown"
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    capability_id: str
    title: str
    evidence: str
    remediation: str
    confidence: float = 1.0


@dataclass(frozen=True, slots=True)
class Manifest:
    schema_version: int
    source: str
    capabilities: tuple[Capability, ...]
    findings: tuple[Finding, ...]
    digest: str


@dataclass(frozen=True, slots=True)
class ScanOptions:
    max_bytes: int = 2_000_000
    max_capabilities: int = 10_000


@dataclass(frozen=True, slots=True)
class ScanResult:
    manifest: Manifest


@dataclass(frozen=True, slots=True)
class PolicyOptions:
    max_severity: Severity = Severity.HIGH
    allow_ids: frozenset[str] = frozenset()
    deny_ids: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    schema_version: int
    max_severity: Severity
    allowed_capability_ids: tuple[str, ...]
    denied_capability_ids: tuple[str, ...]
    source_digest: str


@dataclass(frozen=True, slots=True)
class ManifestChange:
    capability_id: str
    change_type: str
    before: Capability | None = None
    after: Capability | None = None


@dataclass(frozen=True, slots=True)
class ManifestDiff:
    before_digest: str
    after_digest: str
    changes: tuple[ManifestChange, ...]

    @property
    def has_drift(self) -> bool:
        return bool(self.changes)

    @property
    def added(self) -> tuple[ManifestChange, ...]:
        return tuple(c for c in self.changes if c.change_type == "added")

    @property
    def removed(self) -> tuple[ManifestChange, ...]:
        return tuple(c for c in self.changes if c.change_type == "removed")

    @property
    def changed(self) -> tuple[ManifestChange, ...]:
        return tuple(c for c in self.changes if c.change_type == "changed")
