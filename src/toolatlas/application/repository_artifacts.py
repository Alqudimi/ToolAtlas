"""Canonical repository artifacts and drift verification."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from toolatlas.application.repository_scan import baseline_from_manifest, lock_from_manifest
from toolatlas.domain.errors import InputError, ManifestDrift
from toolatlas.domain.repository import Baseline, RepositoryLock, RepositoryManifest


def _dump(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def manifest_payload(manifest: RepositoryManifest) -> dict[str, Any]:
    return {
        "schema_version": manifest.schema_version,
        "root_name": manifest.root_name,
        "scanner_version": manifest.scanner_version,
        "digest": manifest.digest,
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
                "id": f"{item.rule_id}:{item.path}:{item.line}",
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


def lock_payload(lock: RepositoryLock) -> dict[str, Any]:
    return {
        "schema_version": lock.schema_version,
        "scanner_version": lock.scanner_version,
        "root_name": lock.root_name,
        "manifest_digest": lock.manifest_digest,
        "entries": [
            {
                "path": item.path,
                "kind": item.kind.value,
                "size": item.size,
                "digest": item.digest,
                "line_count": item.line_count,
            }
            for item in lock.entries
        ],
    }


def baseline_payload(baseline: Baseline) -> dict[str, Any]:
    return {
        "schema_version": baseline.schema_version,
        "manifest_digest": baseline.manifest_digest,
        "findings": list(baseline.findings),
    }


def write_json(path: str | Path, value: object) -> None:
    Path(path).write_text(_dump(value), encoding="utf-8")


def read_json(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputError(f"cannot read JSON artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise InputError(f"artifact must be a JSON object: {path}")
    return value


def verify_lock(manifest: RepositoryManifest, lock_data: dict[str, Any]) -> None:
    expected = lock_payload(lock_from_manifest(manifest))
    if lock_data != expected:
        raise ManifestDrift("repository content differs from the lockfile")


def verify_baseline(manifest: RepositoryManifest, baseline_data: dict[str, Any]) -> tuple[str, ...]:
    current = baseline_from_manifest(manifest)
    known = set(baseline_data.get("findings", []))
    if not isinstance(baseline_data.get("findings", []), list) or not all(
        isinstance(item, str) for item in baseline_data.get("findings", [])
    ):
        raise InputError("baseline findings must be an array of strings")
    return tuple(sorted(set(current.findings) - known))
