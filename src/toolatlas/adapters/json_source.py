"""Safe JSON source adapter; it only parses data and never executes declarations."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from toolatlas.domain.errors import InputTooLargeError, SchemaError
from toolatlas.domain.models import Capability, CapabilityKind

_MAX_TEXT = 10_000


def _text(value: Any, field: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise SchemaError(f"{field} must be a string")
    if len(value) > _MAX_TEXT:
        raise SchemaError(f"{field} exceeds {_MAX_TEXT} characters")
    return value


def _strings(value: Any, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SchemaError(f"{field} must be an array of strings")
    return tuple(sorted(set(item.strip() for item in value if item.strip())))


def _record(raw: Any, kind: CapabilityKind, source: str, index: int) -> Capability:
    if not isinstance(raw, Mapping):
        raise SchemaError(f"{kind.value}[{index}] must be an object")
    name = _text(raw.get("name"), f"{kind.value}[{index}].name").strip()
    if not name:
        raise SchemaError(f"{kind.value}[{index}].name is required")
    description = _text(raw.get("description"), f"{kind.value}[{index}].description")
    input_names = _strings(raw.get("input_names", raw.get("inputNames")), f"{name}.input_names")
    scopes = _strings(raw.get("scopes"), f"{name}.scopes")
    stable_id = _text(raw.get("id"), f"{name}.id").strip() or f"{kind.value}:{name}"
    metadata = raw.get("metadata", {})
    if not isinstance(metadata, Mapping):
        raise SchemaError(f"{name}.metadata must be an object")
    return Capability(
        id=stable_id,
        name=name,
        kind=kind,
        description=description,
        input_names=input_names,
        scopes=scopes,
        source=source,
        metadata={str(key): value for key, value in metadata.items() if isinstance(key, str)},
    )


def parse_document(
    raw_bytes: bytes, source: str, max_bytes: int, max_capabilities: int
) -> tuple[Capability, ...]:
    if len(raw_bytes) > max_bytes:
        raise InputTooLargeError(f"input is {len(raw_bytes)} bytes; maximum is {max_bytes}")
    try:
        document = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SchemaError(f"input is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(document, Mapping):
        raise SchemaError("root document must be an object")

    records: list[Capability] = []
    if isinstance(document.get("capabilities"), list):
        for index, raw in enumerate(document["capabilities"]):
            if not isinstance(raw, Mapping):
                raise SchemaError(f"capabilities[{index}] must be an object")
            kind_value = raw.get("kind", "tool")
            try:
                kind = CapabilityKind(str(kind_value))
            except ValueError as exc:
                raise SchemaError(f"capabilities[{index}].kind is invalid") from exc
            records.append(_record(raw, kind, source, index))
    else:
        for kind in CapabilityKind:
            values = document.get(f"{kind.value}s", [])
            if not isinstance(values, list):
                raise SchemaError(f"{kind.value}s must be an array")
            records.extend(_record(raw, kind, source, index) for index, raw in enumerate(values))
    if not records:
        raise SchemaError("document contains no capabilities")
    if len(records) > max_capabilities:
        raise InputTooLargeError(f"document contains more than {max_capabilities} capabilities")
    ids = [record.id for record in records]
    if len(ids) != len(set(ids)):
        raise SchemaError("capability IDs must be unique")
    return tuple(sorted(records, key=lambda item: (item.kind.value, item.name.casefold(), item.id)))
