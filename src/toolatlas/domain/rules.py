"""Explainable, deterministic capability risk rules."""

from __future__ import annotations

import re
from collections.abc import Iterable

from toolatlas.domain.models import Capability, Finding, Severity

_DESTRUCTIVE = re.compile(
    r"(delete|destroy|drop|remove|shutdown|terminate|execute|write|update|admin)", re.I
)
_SECRET = re.compile(
    r"\b(token|secret|password|passwd|api[_-]?key|credential|private[_-]?key)\b", re.I
)
_BROAD_SCOPE = re.compile(
    r"(^|[:/ ])(\*|root|all|filesystem|network|shell|subprocess)([:/ ]|$)", re.I
)


def evaluate(capabilities: Iterable[Capability]) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for capability in capabilities:
        searchable = f"{capability.name} {capability.description}"
        if _DESTRUCTIVE.search(searchable):
            findings.append(
                Finding(
                    rule_id="TA001",
                    severity=Severity.HIGH,
                    capability_id=capability.id,
                    title="Capability appears able to mutate or execute",
                    evidence=f"name/description matched destructive verb in {capability.name!r}",
                    remediation=(
                        "Require explicit review and narrow the operation "
                        "to the smallest safe action."
                    ),
                )
            )
        if any(_SECRET.search(name) for name in capability.input_names):
            findings.append(
                Finding(
                    rule_id="TA002",
                    severity=Severity.HIGH,
                    capability_id=capability.id,
                    title="Capability accepts secret-like input",
                    evidence="an input name resembles a credential or secret",
                    remediation=(
                        "Use a secret reference or scoped runtime identity; "
                        "never persist the value in a manifest."
                    ),
                )
            )
        if any(_BROAD_SCOPE.search(scope) for scope in capability.scopes):
            findings.append(
                Finding(
                    rule_id="TA003",
                    severity=Severity.CRITICAL,
                    capability_id=capability.id,
                    title="Capability declares a broad or privileged scope",
                    evidence=f"scope list contains a broad scope: {', '.join(capability.scopes)}",
                    remediation=(
                        "Replace wildcard or root scopes with an explicit "
                        "least-privilege allowlist."
                    ),
                )
            )
        if capability.kind.value == "tool" and any(
            _SECRET.search(value)
            for value in capability.metadata.values()
            if isinstance(value, str)
        ):
            findings.append(
                Finding(
                    rule_id="TA004",
                    severity=Severity.MEDIUM,
                    capability_id=capability.id,
                    title="Metadata contains secret-like text",
                    evidence="metadata value matched a secret keyword",
                    remediation=(
                        "Remove secret material and keep only a reference or classification label."
                    ),
                    confidence=0.8,
                )
            )
    return tuple(sorted(findings, key=lambda item: (item.capability_id, item.rule_id)))
