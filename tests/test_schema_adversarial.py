"""Adversarial and boundary tests for the JSON source adapter.

Locks in the fail-closed contract: malformed input must surface as a typed
``SchemaError`` or ``InputTooLargeError`` instead of silently coercing values,
crashing with opaque tracebacks, or exposing unintended code paths.
"""

import json

import pytest

from toolatlas.adapters.json_source import parse_document
from toolatlas.domain.errors import InputTooLargeError, SchemaError

MAX_BYTES = 2_000_000
MAX_CAPABILITIES = 10_000


def _parse(raw: bytes | str, source: str = "adversarial.json") -> None:
    data = raw if isinstance(raw, bytes) else raw.encode("utf-8")
    parse_document(data, source, MAX_BYTES, MAX_CAPABILITIES)


def _raises(exc: type[Exception], *cases: bytes | str) -> None:
    for case in cases:
        with pytest.raises(exc):
            _parse(case)


# ---------------------------------------------------------------- root level


def test_root_must_be_object() -> None:
    _raises(SchemaError, "[]", "null", "true", "42", '"string"')


def test_invalid_utf8_rejected() -> None:
    _raises(SchemaError, b'{"capabilities": [{"name": "\xff\xfe"}]}')


def test_invalid_json_rejected() -> None:
    _raises(SchemaError, "{this is not json", "", "   ")


def test_oversized_input_rejected() -> None:
    payload = json.dumps({"capabilities": [{"name": "t", "kind": "tool"}]}).encode("utf-8")
    with pytest.raises(InputTooLargeError):
        parse_document(payload * 2, "large.json", len(payload) - 1, MAX_CAPABILITIES)


def test_document_without_capabilities_rejected() -> None:
    _raises(SchemaError, "{}", '{"tools": []}', '{"tools": "not-array"}')


def test_non_array_capability_sections_rejected() -> None:
    _raises(SchemaError, '{"tools": "all"}', '{"resources": 7}')


def test_duplicate_capability_ids_rejected() -> None:
    doc = json.dumps(
        {"capabilities": [{"name": "a", "kind": "tool"}, {"name": "a", "kind": "tool"}]}
    )
    _raises(SchemaError, doc)


# --------------------------------------------------------------- capabilities


def test_capabilities_entry_must_be_object() -> None:
    _raises(SchemaError, '{"capabilities": [null, "x"]}')


def test_invalid_kind_value_rejected() -> None:
    _raises(SchemaError, '{"capabilities": [{"name": "t", "kind": "virus"}]}')


def test_missing_name_rejected() -> None:
    _raises(
        SchemaError,
        '{"capabilities": [{"kind": "tool"}]}',
        '{"capabilities": [{"name": "", "kind": "tool"}]}',
        '{"capabilities": [{"name": "   ", "kind": "tool"}]}',
    )


def test_non_string_name_rejected() -> None:
    _raises(SchemaError, '{"capabilities": [{"name": 5, "kind": "tool"}]}')


def test_oversized_name_rejected() -> None:
    _raises(SchemaError, json.dumps({"capabilities": [{"name": "a" * 10001}]}))


def test_non_string_description_rejected() -> None:
    _raises(SchemaError, json.dumps({"capabilities": [{"name": "t", "description": []}]}))


def test_oversized_description_rejected() -> None:
    _raises(SchemaError, json.dumps({"capabilities": [{"name": "t", "description": "a" * 10001}]}))


def test_null_description_normalized_to_empty_string() -> None:
    doc = json.dumps({"capabilities": [{"name": "t", "description": None, "kind": "tool"}]})
    (capability,) = _normal() and parse_document(  # type: ignore[unreachable]
        doc.encode("utf-8"), "src", MAX_BYTES, MAX_CAPABILITIES
    )
    assert capability.description == ""


def _normal() -> bool:
    return True


def test_non_string_input_names_rejected() -> None:
    _raises(
        SchemaError,
        json.dumps({"capabilities": [{"name": "t", "input_names": "password"}]}),
        json.dumps({"capabilities": [{"name": "t", "input_names": [7]}]}),
    )


def test_camelcase_input_names_accepted() -> None:
    doc = json.dumps({"capabilities": [{"name": "t", "inputNames": ["secret"], "kind": "tool"}]})
    (capability,) = parse_document(doc.encode("utf-8"), "src", MAX_BYTES, MAX_CAPABILITIES)
    assert capability.input_names == ("secret",)


def test_empty_strings_and_duplicates_deduplicated() -> None:
    doc = json.dumps(
        {"capabilities": [{"name": "t", "input_names": [" a ", "", "a", "b"], "kind": "tool"}]}
    )
    (capability,) = parse_document(doc.encode("utf-8"), "src", MAX_BYTES, MAX_CAPABILITIES)
    assert capability.input_names == ("a", "b")


def test_non_string_scopes_rejected() -> None:
    _raises(SchemaError, json.dumps({"capabilities": [{"name": "t", "scopes": ["*", 1]}]}))


def test_non_object_metadata_rejected() -> None:
    _raises(SchemaError, json.dumps({"capabilities": [{"name": "t", "metadata": "bad"}]}))


def test_oversized_id_rejected() -> None:
    _raises(SchemaError, json.dumps({"capabilities": [{"name": "t", "id": "a" * 10001}]}))


def test_explicit_id_used_for_stability() -> None:
    doc = json.dumps({"capabilities": [{"name": "t", "id": "stable-id", "kind": "tool"}]})
    (capability,) = parse_document(doc.encode("utf-8"), "src", MAX_BYTES, MAX_CAPABILITIES)
    assert capability.id == "stable-id"


def test_default_id_derived_from_kind_and_name() -> None:
    doc = json.dumps({"tools": [{"name": "my-tool", "description": "d"}]})
    (capability,) = parse_document(doc.encode("utf-8"), "src", MAX_BYTES, MAX_CAPABILITIES)
    assert capability.id == "tool:my-tool"


def test_unbounded_documents_rejected() -> None:
    huge = json.dumps({"capabilities": [{"name": f"c{i}", "kind": "tool"} for i in range(10_001)]})
    with pytest.raises(InputTooLargeError):
        parse_document(huge.encode("utf-8"), "src", MAX_BYTES, max_capabilities=10_000)


def test_unbounded_capability_counts_rejected() -> None:
    huge = json.dumps({"capabilities": [{"name": f"c{i}", "kind": "tool"} for i in range(10_001)]})
    with pytest.raises(InputTooLargeError):
        parse_document(huge.encode("utf-8"), "src", MAX_BYTES, max_capabilities=10_000)


def test_output_sorted_and_stable() -> None:
    doc = json.dumps(
        {
            "capabilities": [
                {"name": "beta", "kind": "tool"},
                {"name": "alpha", "kind": "prompt"},
                {"name": "Alpha", "kind": "tool"},
            ]
        }
    )
    capabilities = parse_document(doc.encode("utf-8"), "src", MAX_BYTES, MAX_CAPABILITIES)
    ids = [capability.id for capability in capabilities]
    assert ids == sorted(ids)
    ids_again = [
        capability.id
        for capability in parse_document(doc.encode("utf-8"), "src", MAX_BYTES, MAX_CAPABILITIES)
    ]
    assert ids == ids_again


def test_secret_like_metadata_finding_reduced_confidence() -> None:
    from toolatlas.application.services import evaluate

    doc = json.dumps(
        {
            "capabilities": [
                {
                    "name": "deploy",
                    "kind": "tool",
                    "metadata": {"api_key_hint": "token: my-secret-token-value"},
                }
            ]
        }
    )
    capabilities = parse_document(doc.encode("utf-8"), "src", MAX_BYTES, MAX_CAPABILITIES)
    findings = evaluate(capabilities)
    secret_finding = next(item for item in findings if item.rule_id == "TA004")
    assert secret_finding.confidence == 0.8


def test_metadata_keys_coerced_to_strings() -> None:
    """JSON object keys are always strings at the wire level; the adapter keeps
    them as strings so no information is silently lost when round-tripping."""
    doc = json.dumps({"capabilities": [{"name": "t", "metadata": {"ok": "v", "5": "x"}}]})
    (capability,) = parse_document(doc.encode("utf-8"), "src", MAX_BYTES, MAX_CAPABILITIES)
    assert capability.metadata == {"ok": "v", "5": "x"}


def test_object_metadata_keys_only() -> None:
    """Non-object metadata must fail closed with a typed schema error."""
    _raises(SchemaError, json.dumps({"capabilities": [{"name": "t", "metadata": []}]}))


def test_all_capability_kinds_parsed() -> None:
    doc = json.dumps(
        {
            "tools": [{"name": "t", "description": "a tool"}],
            "resources": [{"name": "r", "description": "a resource"}],
            "prompts": [{"name": "p", "description": "a prompt"}],
        }
    )
    capabilities = parse_document(doc.encode("utf-8"), "src", MAX_BYTES, MAX_CAPABILITIES)
    assert {capability.kind.value for capability in capabilities} == {"tool", "resource", "prompt"}


def test_non_integer_list_entries_still_rejected_after_kind_check() -> None:
    """A boolean name is a non-string field and must be typed as a schema error."""
    _raises(SchemaError, json.dumps({"capabilities": [{"name": True, "kind": "tool"}]}))
