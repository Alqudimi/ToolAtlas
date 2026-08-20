from __future__ import annotations

import json
from pathlib import Path

from toolatlas.application.repository_policy import RepositoryPolicy, evaluate_repository_policy
from toolatlas.application.repository_scan import scan_repository
from toolatlas.cli import main
from toolatlas.domain.models import Severity


def test_repository_policy_blocks_high_and_allows_explicit_rule(tmp_path: Path) -> None:
    (tmp_path / "skill.md").write_text("token=super-secret-value-1234", encoding="utf-8")
    manifest = scan_repository(tmp_path)
    blocked = evaluate_repository_policy(manifest, RepositoryPolicy(Severity.MEDIUM))
    assert blocked.passed is False
    assert [item.rule_id for item in blocked.violations] == ["TA101"]
    allowed = evaluate_repository_policy(
        manifest, RepositoryPolicy(Severity.MEDIUM, frozenset({"TA101"}))
    )
    assert allowed.passed is True
    assert allowed.violations == ()


def test_repo_policy_cli_json_and_exit_code(tmp_path: Path, capsys) -> None:
    (tmp_path / "skill.md").write_text("token=super-secret-value-1234", encoding="utf-8")
    assert main(["repo-policy", str(tmp_path), "--max-severity", "medium", "--format", "json"]) == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is False
    assert payload["violations"][0]["rule_id"] == "TA101"
    assert (
        main(
            [
                "repo-policy",
                str(tmp_path),
                "--max-severity",
                "medium",
                "--allow-rule",
                "TA101",
            ]
        )
        == 0
    )
    assert "policy: PASS" in capsys.readouterr().out
