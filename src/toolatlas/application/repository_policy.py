from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from toolatlas.domain.errors import InputError
from toolatlas.domain.models import Severity
from toolatlas.domain.repository import RepositoryFinding, RepositoryManifest


@dataclass(frozen=True, slots=True)
class RepositoryPolicy:
    max_severity: Severity = Severity.HIGH
    allow_rules: frozenset[str] = frozenset()


def policy_from_payload(payload: dict[str, Any]) -> RepositoryPolicy:
    if payload.get("schema_version") != 1:
        raise InputError("repository policy schema_version must be 1")
    raw_severity = payload.get("max_severity", Severity.HIGH.value)
    if not isinstance(raw_severity, str) or raw_severity not in {item.value for item in Severity}:
        raise InputError("repository policy max_severity must be a valid severity")
    raw_allow_rules = payload.get("allow_rules", [])
    if not isinstance(raw_allow_rules, list) or not all(
        isinstance(item, str) and item for item in raw_allow_rules
    ):
        raise InputError("repository policy allow_rules must be an array of non-empty strings")
    return RepositoryPolicy(Severity(raw_severity), frozenset(raw_allow_rules))


@dataclass(frozen=True, slots=True)
class RepositoryPolicyResult:
    passed: bool
    max_severity: Severity
    allow_rules: tuple[str, ...]
    evaluated_findings: int
    violations: tuple[RepositoryFinding, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "passed": self.passed,
            "max_severity": self.max_severity.value,
            "allow_rules": list(self.allow_rules),
            "evaluated_findings": self.evaluated_findings,
            "violations": [
                {
                    "rule_id": item.rule_id,
                    "severity": item.severity.value,
                    "path": item.path,
                    "line": item.line,
                    "title": item.title,
                    "evidence": item.evidence,
                    "remediation": item.remediation,
                    "related_paths": list(item.related_paths),
                }
                for item in self.violations
            ],
        }


def evaluate_repository_policy(
    manifest: RepositoryManifest, policy: RepositoryPolicy
) -> RepositoryPolicyResult:
    violations = tuple(
        item
        for item in manifest.findings
        if item.rule_id not in policy.allow_rules and item.severity.rank > policy.max_severity.rank
    )
    return RepositoryPolicyResult(
        passed=not violations,
        max_severity=policy.max_severity,
        allow_rules=tuple(sorted(policy.allow_rules)),
        evaluated_findings=len(manifest.findings),
        violations=violations,
    )
