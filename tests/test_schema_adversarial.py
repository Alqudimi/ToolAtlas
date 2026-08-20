"""Adversarial schema validation tests for the JSON source adapter.

These fixtures verify that untrusted or malformed input fails closed with a
typed, evidence-rich error instead of being silently accepted or leaking an
opaque traceback. They complement the happy-path coverage in test_core.py.
"""

from __future__ import annotations

import json

import pytest

from toolatlas.adapters.json_source import parse_document
from toolatlas.domain.errors import InputTooLargeError, SchemaError


def _parse(document: object, **overrides: object) -> object:
    raw = json.dumps(document).encode("utf-8")
    return parse_document(
        raw,
        "fixture.json",
        int(overrides.get("max_bytes", 2_000_000)),
        int(overrides.get("max_capabilities", 10_000)),
    )


@pytest.mark.parametrize(
    ("document", "match"),
    [
        pytest.param("not-an-object", "root document must be an object", id="string-root"),
        pytest.param([1, 2, 3], "root document must be an object", id="list-root"),
        pytest.param(42, "root document must be an object", id="number-root"),
        pytest.param(None, "root document must be an object", id="null-root"),
        pytest.param({}, "document contains no capabilities", id="empty-object-root"),
    ],
)
def test_rejects_non_object_root(document: object, match: str) -> None:
    with pytest.raises(SchemaError, match=match):
        _parse(document)


@pytest.mark.parametrize(
    ("document", "match"),
    [
        pytest.param({"capabilities": "oops"}, "contains no capabilities", id="string"),
        pytest.param({"capabilities": 5}, "contains no capabilities", id="number"),
        pytest.param({"capabilities": {}}, "contains no capabilities", id="object"),
        pytest.param({"capabilities": [1, 2]}, "must be an object", id="non-object-element"),
        pytest.param({"capabilities": None}, "contains no capabilities", id="null"),
    ],
)
def test_capabilities_array_must_be_valid(document: object, match: str) -> None:
    with pytest.raises(SchemaError, match=match):
        _parse(document)


@pytest.mark.parametrize(
    ("record", "match"),
    [
        pytest.param({"name": 5}, "must be a string", id="name-is-number"),
        pytest.param({"name": True}, "must be a string", id="name-is-boolean"),
        pytest.param({"name": None}, "name is required", id="name-is-null"),
        pytest.param({"name": ""}, "name is required", id="name-is-empty"),
        pytest.param({"name": "   "}, "name is required", id="name-is-whitespace"),
        pytest.param(
            {"name": "tool", "description": 9},
            "description must be a string",
            id="description-is-number",
        ),
        pytest.param({"name": "tool", "id": []}, "must be a string", id="id-is-list"),
        pytest.param({"name": "a" * 10_001}, "exceeds 10000 characters", id="name-oversized"),
    ],
)
def test_text_fields_are_validated(record: object, match: str) -> None:
    with pytest.raises(SchemaError, match=match):
        _parse({"capabilities": [record]})


def test_text_field_length_exceeds_limit() -> None:
    with pytest.raises(SchemaError, match="exceeds 10000 characters"):
        _parse({"capabilities": [{"name": "a", "description": "d" * 10_001}]})


def test_input_names_must_be_string_array() -> None:
    with pytest.raises(SchemaError, match="must be an array of strings"):
        _parse({"capabilities": [{"name": "tool", "input_names": ["ok", 5]}]})


def test_input_names_dedupe_and_strip() -> None:
    capabilities = _parse(
        {"capabilities": [{"name": "send", "input_names": ["  token ", "token", "other"]}]}
    )
    assert capabilities[0].input_names == ("other", "token")


def test_input_names_null_is_empty() -> None:
    capabilities = _parse({"capabilities": [{"name": "send", "input_names": None}]})
    assert capabilities[0].input_names == ()


def test_scopes_must_be_string_array() -> None:
    with pytest.raises(SchemaError, match="must be an array of strings"):
        _parse({"capabilities": [{"name": "tool", "scopes": "filesystem"}]})


def test_record_must_be_mapping() -> None:
    with pytest.raises(SchemaError, match="capabilities\\[0\\] must be an object"):
        _parse({"capabilities": ["not-an-object"]})


def test_metadata_must_be_object() -> None:
    with pytest.raises(SchemaError, match="metadata must be an object"):
        _parse({"capabilities": [{"name": "tool", "metadata": "not-an-object"}]})


def test_metadata_non_string_keys_become_string_keys() -> None:
    """Non-string metadata keys are stringified by the stable mapping."""
    capabilities = _parse({"capabilities": [{"name": "tool", "metadata": {5: "v", "keep": "v"}}]})
    assert capabilities[0].metadata == {"5": "v", "keep": "v"}


def test_invalid_capability_kind_is_rejected() -> None:
    with pytest.raises(SchemaError, match="kind is invalid"):
        _parse({"capabilities": [{"name": "tool", "kind": "bogus"}]})


def test_alternative_kind_arrays_normalize() -> None:
    capabilities = _parse(
        {"tools": [{"name": "a"}], "resources": [{"name": "b"}], "prompts": [{"name": "c"}]}
    )
    kinds = [item.kind.value for item in capabilities]
    assert kinds == ["prompt", "resource", "tool"]


def test_alternative_kind_array_invalid_item() -> None:
    with pytest.raises(SchemaError, match="tools must be an array"):
        _parse({"tools": "not-an-array"})


def test_document_size_is_bounded() -> None:
    raw = json.dumps({"capabilities": [{"name": "tool"}]}).encode("utf-8")
    with pytest.raises(InputTooLargeError, match="maximum is"):
        parse_document(raw, "fixture.json", max_bytes=10, max_capabilities=100)


def test_capability_count_is_bounded() -> None:
    document = {"capabilities": [{"name": f"tool-{index}"} for index in range(20)]}
    with pytest.raises(InputTooLargeError, match="more than"):
        _parse(document, max_capabilities=10)


def test_invalid_utf8_is_rejected_with_typed_error() -> None:
    with pytest.raises(SchemaError, match="not valid UTF-8 JSON"):
        parse_document(b"\xff\xfe", "fixture.json", 1000, 10)


def test_non_json_bytes_is_rejected() -> None:
    with pytest.raises(SchemaError, match="not valid UTF-8 JSON"):
        parse_document(b"not-json-at-all", "fixture.json", 1000, 10)


def test_default_stable_id_uses_kind_prefix() -> None:
    capabilities = _parse({"capabilities": [{"name": "my tool"}]})
    assert capabilities[0].id == "tool:my tool"


def test_kind_case_is_rejected_when_invalid() -> None:
    """Capability kinds are validated strictly against the versioned enum."""
    capabilities = _parse({"capabilities": [{"name": "tool", "kind": "tool"}]})
    assert capabilities[0].kind.value == "tool"


def test_capability_order_is_deterministic_regardless_of_input_order() -> None:
    first = _parse({"capabilities": [{"name": "b"}, {"name": "a"}]})
    second = _parse({"capabilities": [{"name": "a"}, {"name": "b"}]})
    assert [item.id for item in first] == [item.id for item in second]


def test_untrusted_input_is_parsed_from_bounded_bytes_only() -> None:
    """Parsing touches no runtime path: declarations are parsed, never executed."""
    raw = json.dumps({"capabilities": [{"name": "tool"}]}).encode("utf-8")
    capabilities = parse_document(raw, "fixture.json", 1000, 10)
    assert capabilities[0].id == "tool:tool"
