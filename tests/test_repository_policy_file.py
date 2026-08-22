from __future__ import annotations

import json
from pathlib import Path

from toolatlas.cli import main


def test_policy_file_controls_threshold_and_allow_rules(tmp_path: Path, capsys) -> None:
    (tmp_path / "skill.md").write_text("token=super-secret-value-1234", encoding="utf-8")
    policy = tmp_path / "toolatlas.policy.json"
    policy.write_text(
        json.dumps({"schema_version": 1, "max_severity": "medium", "allow_rules": ["TA101"]}),
        encoding="utf-8",
    )
    assert main(["repo-policy", str(tmp_path), "--policy-file", str(policy)]) == 0
    assert "policy: PASS" in capsys.readouterr().out


def test_policy_file_invalid_schema_fails_closed(tmp_path: Path, capsys) -> None:
    (tmp_path / "toolatlas.policy.json").write_text(
        json.dumps({"schema_version": 99, "max_severity": "high"}), encoding="utf-8"
    )
    assert (
        main(
            ["repo-policy", str(tmp_path), "--policy-file", str(tmp_path / "toolatlas.policy.json")]
        )
        == 2
    )
    assert "INVALID_INPUT" in capsys.readouterr().err


def test_policy_file_invalid_allow_rules_fails_closed(tmp_path: Path, capsys) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps({"schema_version": 1, "max_severity": "high", "allow_rules": [""]}),
        encoding="utf-8",
    )
    assert main(["repo-policy", str(tmp_path), "--policy-file", str(policy)]) == 2
    assert "INVALID_INPUT" in capsys.readouterr().err
