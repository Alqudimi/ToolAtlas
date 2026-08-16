from __future__ import annotations

import json

import pytest

from toolatlas.adapters.json_source import parse_document
from toolatlas.application.services import compare_manifests, compile_policy, scan
from toolatlas.domain.errors import SchemaError
from toolatlas.domain.models import PolicyOptions, Severity

GOOD = {
    "tools": [
        {"name": "read_file", "description": "Read a project file", "scopes": ["repo:read"]},
        {"name": "delete_record", "description": "Delete a record", "input_names": ["record_id"]},
    ],
    "resources": [
        {"name": "project_docs", "description": "Documentation", "scopes": ["repo:read"]}
    ],
}


def make_result(document: dict):
    capabilities = parse_document(json.dumps(document).encode(), "fixture.json", 100_000, 100)
    return scan(capabilities, "fixture.json")


def test_normalizes_mcp_like_shape_and_detects_risk() -> None:
    result = make_result(GOOD)
    assert [item.id for item in result.manifest.capabilities] == [
        "resource:project_docs",
        "tool:delete_record",
        "tool:read_file",
    ]
    assert any(item.rule_id == "TA001" for item in result.manifest.findings)
    assert len(result.manifest.digest) == 64


def test_normalized_output_is_deterministic() -> None:
    first = make_result(GOOD).manifest
    second = make_result(
        {"resources": GOOD["resources"], "tools": list(reversed(GOOD["tools"]))}
    ).manifest
    assert first.digest == second.digest


def test_secret_input_is_reported_without_persisting_value() -> None:
    result = make_result({"capabilities": [{"name": "send", "input_names": ["api_key"]}]})
    assert any(item.rule_id == "TA002" for item in result.manifest.findings)
    assert "api_key" not in json.dumps(result.manifest.findings, default=str)


def test_schema_rejects_duplicate_ids() -> None:
    with pytest.raises(SchemaError, match="unique"):
        parse_document(
            json.dumps(
                {"capabilities": [{"id": "same", "name": "one"}, {"id": "same", "name": "two"}]}
            ).encode(),
            "x",
            1000,
            10,
        )


def test_policy_denies_high_findings_by_default() -> None:
    result = make_result(GOOD)
    policy = compile_policy(result, PolicyOptions(max_severity=Severity.MEDIUM))
    assert "tool:delete_record" in policy.denied_capability_ids
    assert "tool:read_file" in policy.allowed_capability_ids


def test_manifest_diff_reports_added_changed_and_removed() -> None:
    before = make_result(
        {
            "capabilities": [
                {"id": "tool:a", "name": "a", "description": "old"},
                {"id": "tool:b", "name": "b"},
            ]
        }
    ).manifest
    after = make_result(
        {
            "capabilities": [
                {"id": "tool:a", "name": "a", "description": "new"},
                {"id": "tool:c", "name": "c"},
            ]
        }
    ).manifest
    diff = compare_manifests(before, after)
    assert [item.change_type for item in diff.changes] == ["added", "removed", "changed"]
    assert diff.has_drift
