"""Deterministic report renderers."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from toolatlas.application.services import manifest_payload, policy_payload
from toolatlas.domain.models import CompiledPolicy, ManifestDiff, ScanResult
from toolatlas.domain.repository import RepositoryManifest


def _fingerprint(*parts: object) -> str:
    value = "|".join(str(part) for part in parts).encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def json_report(result: ScanResult) -> str:
    return json.dumps(manifest_payload(result.manifest), ensure_ascii=False, indent=2) + "\n"


def json_policy(policy: CompiledPolicy) -> str:
    return json.dumps(policy_payload(policy), ensure_ascii=False, indent=2) + "\n"


def terminal_report(result: ScanResult) -> str:
    manifest = result.manifest
    lines = [
        f"ToolAtlas manifest {manifest.digest[:12]} ({len(manifest.capabilities)} capabilities)",
        f"source: {manifest.source}",
        f"findings: {len(manifest.findings)}",
    ]
    for finding in manifest.findings:
        lines.append(f"[{finding.severity.value.upper()}] {finding.capability_id}: {finding.title}")
        lines.append(f"  evidence: {finding.evidence}")
        lines.append(f"  remediation: {finding.remediation}")
    return "\n".join(lines) + "\n"


def diff_report(diff: ManifestDiff) -> str:
    lines = [f"manifest drift: {'yes' if diff.has_drift else 'no'}"]
    for change in diff.changes:
        lines.append(f"{change.change_type.upper():7} {change.capability_id}")
    return "\n".join(lines) + "\n"


def sarif_report(result: ScanResult) -> str:
    rules: dict[str, dict[str, str]] = {}
    results: list[dict[str, Any]] = []
    for finding in result.manifest.findings:
        rules.setdefault(finding.rule_id, {"id": finding.rule_id, "name": finding.title})
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": "error" if finding.severity.rank >= 3 else "warning",
                "message": {"text": f"{finding.evidence}. Remediation: {finding.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": result.manifest.source},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [{"name": finding.capability_id}],
                    }
                ],
                "partialFingerprints": {
                    "toolatlas/v1": _fingerprint(
                        finding.rule_id,
                        finding.capability_id,
                        finding.evidence,
                    )
                },
                "properties": {
                    "severity": finding.severity.value,
                    "confidence": finding.confidence,
                },
            }
        )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ToolAtlas",
                        "informationUri": "https://github.com/Alqudimi/ToolAtlas",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {"manifestDigest": result.manifest.digest},
            }
        ],
    }
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def repository_sarif_report(manifest: RepositoryManifest) -> str:
    rules: dict[str, dict[str, str]] = {}
    results: list[dict[str, Any]] = []
    for finding in manifest.findings:
        rules.setdefault(finding.rule_id, {"id": finding.rule_id, "name": finding.title})
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": "error" if finding.severity.rank >= 3 else "warning",
                "message": {"text": f"{finding.evidence}. Remediation: {finding.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {"startLine": finding.line},
                        }
                    }
                ],
                "partialFingerprints": {
                    "toolatlas/v1": _fingerprint(
                        finding.rule_id,
                        finding.path,
                        finding.line,
                        finding.evidence,
                    )
                },
                "properties": {
                    "severity": finding.severity.value,
                    "confidence": finding.confidence,
                    "relatedPaths": list(finding.related_paths),
                },
            }
        )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ToolAtlas repository gate",
                        "informationUri": "https://github.com/Alqudimi/ToolAtlas",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {"manifestDigest": manifest.digest},
            }
        ],
    }
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"
