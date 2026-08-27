from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, RootModel

from avo_correlate.domain.structured_schema import (
    StructuredSchemaError,
    compile_strict_output_schema,
)


class Nested(BaseModel):
    required_value: str
    default_value: int = 3
    nullable_value: str | None = None


class Payload(BaseModel):
    nested: Nested
    values: list[Nested]
    nullable: int | None = None


def test_compiles_nested_arrays_and_nullable_defaults() -> None:
    compiled = compile_strict_output_schema(Payload)
    root = compiled.wire_schema
    nested = root["$defs"]["Nested"]

    assert root["additionalProperties"] is False
    assert root["required"] == ["nested", "values", "nullable"]
    assert nested["additionalProperties"] is False
    assert nested["required"] == ["required_value", "default_value", "nullable_value"]
    assert compiled.source_schema["$defs"]["Nested"]["properties"]["default_value"]["default"] == 3
    assert "default" not in nested["properties"]["default_value"]
    assert (
        compiled.source_schema["$defs"]["Nested"]["properties"]["nullable_value"]["default"]
        is None
    )
    assert "default" not in nested["properties"]["nullable_value"]
    assert nested["properties"]["nullable_value"]["anyOf"] == [
        {"type": "string"},
        {"type": "null"},
    ]
    assert compiled.source_schema["properties"]["nullable"]["default"] is None
    assert "default" not in root["properties"]["nullable"]
    assert root["properties"]["values"]["items"] == {"$ref": "#/$defs/Nested"}


def test_compilation_is_stable_and_does_not_mutate_source_schema() -> None:
    before = Payload.model_json_schema()
    first = compile_strict_output_schema(Payload)
    second = compile_strict_output_schema(Payload)

    assert Payload.model_json_schema() == before
    assert first.source_schema == before
    assert first.source_digest == second.source_digest
    assert first.wire_digest == second.wire_digest
    assert first.source_digest != first.wire_digest


def test_empty_object_is_closed() -> None:
    class Empty(BaseModel):
        model_config = ConfigDict(extra="forbid")

    schema = compile_strict_output_schema(Empty).wire_schema
    assert schema["type"] == "object"
    assert schema["properties"] == {}
    assert schema["required"] == []
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize(
    "model_type",
    [
        RootModel[list[str]],
        RootModel[dict[str, Any]],
    ],
)
def test_rejects_non_object_root_and_unconstrained_dicts(model_type: type[BaseModel]) -> None:
    with pytest.raises(StructuredSchemaError):
        compile_strict_output_schema(model_type)


def test_rejects_schema_valued_additional_properties() -> None:
    class OpenMap(BaseModel):
        values: dict[str, int]

    with pytest.raises(StructuredSchemaError, match="additionalProperties"):
        compile_strict_output_schema(OpenMap)


def test_rejects_external_and_missing_refs(monkeypatch: pytest.MonkeyPatch) -> None:
    class Model(BaseModel):
        value: str

    def external_ref() -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {"value": {"$ref": "https://example.test/schema.json"}},
        }

    monkeypatch.setattr(Model, "model_json_schema", external_ref)
    with pytest.raises(StructuredSchemaError, match="external"):
        compile_strict_output_schema(Model)

    def missing_ref() -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {"value": {"$ref": "#/$defs/Missing"}},
            "$defs": {},
        }

    monkeypatch.setattr(Model, "model_json_schema", missing_ref)
    with pytest.raises(StructuredSchemaError, match="target"):
        compile_strict_output_schema(Model)


def test_rejects_malformed_schema_nodes(monkeypatch: pytest.MonkeyPatch) -> None:
    class Model(BaseModel):
        value: str

    def malformed() -> dict[str, Any]:
        return {"type": "object", "properties": {"value": ["not a schema"]}}

    monkeypatch.setattr(Model, "model_json_schema", malformed)
    with pytest.raises(StructuredSchemaError, match="schema node"):
        compile_strict_output_schema(Model)
