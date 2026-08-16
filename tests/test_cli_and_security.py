from __future__ import annotations

import json
from pathlib import Path

from toolatlas.cli import main


def test_cli_json_and_sarif_outputs(tmp_path: Path, capsys) -> None:
    source = tmp_path / "catalog.json"
    source.write_text(
        json.dumps({"capabilities": [{"name": "delete_user", "description": "Delete a user"}]}),
        encoding="utf-8",
    )
    assert main(["scan", str(source), "--format", "json"]) == 3
    assert json.loads(capsys.readouterr().out)["schema_version"] == 1
    assert main(["scan", str(source), "--format", "sarif"]) == 3
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    assert "physicalLocation" in sarif["runs"][0]["results"][0]["locations"][0]


def test_cli_risk_exit_code_and_policy_file(tmp_path: Path, capsys) -> None:
    source = tmp_path / "catalog.json"
    policy = tmp_path / "policy.json"
    source.write_text(json.dumps({"capabilities": [{"name": "delete_user"}]}), encoding="utf-8")
    assert main(["scan", str(source)]) == 3
    capsys.readouterr()
    assert main(["policy", str(source), "--output", str(policy)]) == 0
    assert json.loads(policy.read_text(encoding="utf-8"))["denied_capability_ids"] == [
        "tool:delete_user"
    ]


def test_cli_diff_exit_code(tmp_path: Path, capsys) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(json.dumps({"capabilities": [{"name": "read"}]}), encoding="utf-8")
    after.write_text(
        json.dumps({"capabilities": [{"name": "read"}, {"name": "write"}]}), encoding="utf-8"
    )
    assert main(["diff", str(before), str(after)]) == 4
    assert "ADDED" in capsys.readouterr().out


def test_invalid_input_has_stable_exit_code(tmp_path: Path, capsys) -> None:
    source = tmp_path / "broken.json"
    source.write_text("not-json", encoding="utf-8")
    assert main(["scan", str(source)]) == 2
    assert "SCHEMA_ERROR" in capsys.readouterr().err
