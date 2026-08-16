"""Application services coordinating domain operations."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from toolatlas.domain.models import (
    Capability,
    CompiledPolicy,
    Manifest,
    ManifestChange,
    ManifestDiff,
    PolicyOptions,
    ScanOptions,
    ScanResult,
)
from toolatlas.domain.rules import evaluate

_DEFAULT_SCAN_OPTIONS = ScanOptions()
_DEFAULT_POLICY_OPTIONS = PolicyOptions()


def _capability_dict(capability: Capability) -> dict[str, Any]:
    return {
        "id": capability.id,
        "name": capability.name,
        "kind": capability.kind.value,
        "description": capability.description,
        "input_names": list(capability.input_names),
        "scopes": list(capability.scopes),
        "source": capability.source,
    }


def _finding_dict(finding: Any) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "capability_id": finding.capability_id,
        "title": finding.title,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "confidence": finding.confidence,
    }


def manifest_payload(manifest: Manifest) -> dict[str, Any]:
    return {
        "schema_version": manifest.schema_version,
        "source": manifest.source,
        "capabilities": [_capability_dict(item) for item in manifest.capabilities],
        "findings": [_finding_dict(item) for item in manifest.findings],
        "digest": manifest.digest,
    }


def _digest_payload(
    source: str, capabilities: tuple[Capability, ...], findings: tuple[Any, ...]
) -> bytes:
    payload = {
        "schema_version": 1,
        "source": source,
        "capabilities": [_capability_dict(item) for item in capabilities],
        "findings": [_finding_dict(item) for item in findings],
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def scan(
    capabilities: tuple[Capability, ...], source: str, options: ScanOptions = _DEFAULT_SCAN_OPTIONS
) -> ScanResult:
    if len(capabilities) > options.max_capabilities:
        raise ValueError("capability limit exceeded")
    findings = evaluate(capabilities)
    digest = hashlib.sha256(_digest_payload(source, capabilities, findings)).hexdigest()
    return ScanResult(Manifest(1, source, capabilities, findings, digest))


def compile_policy(
    result: ScanResult, options: PolicyOptions = _DEFAULT_POLICY_OPTIONS
) -> CompiledPolicy:
    findings_by_capability = {
        finding.capability_id
        for finding in result.manifest.findings
        if finding.severity.rank > options.max_severity.rank
    }
    all_ids = {capability.id for capability in result.manifest.capabilities}
    denied = (findings_by_capability | set(options.deny_ids)) - set(options.allow_ids)
    allowed = all_ids - denied
    return CompiledPolicy(
        schema_version=1,
        max_severity=options.max_severity,
        allowed_capability_ids=tuple(sorted(allowed)),
        denied_capability_ids=tuple(sorted(denied)),
        source_digest=result.manifest.digest,
    )


def compare_manifests(before: Manifest, after: Manifest) -> ManifestDiff:
    old = {item.id: item for item in before.capabilities}
    new = {item.id: item for item in after.capabilities}
    changes: list[ManifestChange] = []
    for identifier in sorted(new.keys() - old.keys()):
        changes.append(ManifestChange(identifier, "added", after=new[identifier]))
    for identifier in sorted(old.keys() - new.keys()):
        changes.append(ManifestChange(identifier, "removed", before=old[identifier]))
    for identifier in sorted(old.keys() & new.keys()):
        if _capability_dict(old[identifier]) != _capability_dict(new[identifier]):
            changes.append(
                ManifestChange(identifier, "changed", before=old[identifier], after=new[identifier])
            )
    return ManifestDiff(before.digest, after.digest, tuple(changes))


def policy_payload(policy: CompiledPolicy) -> dict[str, Any]:
    return {
        "schema_version": policy.schema_version,
        "max_severity": policy.max_severity.value,
        "allowed_capability_ids": list(policy.allowed_capability_ids),
        "denied_capability_ids": list(policy.denied_capability_ids),
        "source_digest": policy.source_digest,
    }
