"""Compilation of Pydantic schemas for strict structured model output."""

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, cast

from pydantic import BaseModel

from avo_correlate.domain.canonical import CanonicalizationError, canonical_digest


class StructuredSchemaError(ValueError):
    """Raised when a Pydantic schema cannot be made strict and self-contained."""


@dataclass(frozen=True)
class CompiledStructuredSchema:
    """The source schema and its strict-output wire representation."""

    source_schema: dict[str, Any]
    wire_schema: dict[str, Any]
    source_digest: str
    wire_digest: str


_JSON_TYPES = frozenset({"array", "boolean", "integer", "null", "number", "object", "string"})
_COMPOSITIONS = ("anyOf", "oneOf", "allOf")


def compile_strict_output_schema(
    model_type: type[BaseModel],
) -> CompiledStructuredSchema:
    """Compile a Pydantic model schema into a strict, closed JSON Schema.

    OpenAI-compatible structured output requires every object property to be
    required and every object to disallow additional properties.  Pydantic
    intentionally leaves defaulted fields out of ``required``; this compiler
    adds them back while retaining nullable unions. Defaults remain in the
    provenance source schema but are removed from the provider wire schema.
    """

    try:
        generated: Any = model_type.model_json_schema()
        if not isinstance(generated, dict):
            raise StructuredSchemaError("model_json_schema() must return a JSON object")
        generated_schema = cast(dict[Any, Any], generated)
        source_schema = cast(dict[str, Any], deepcopy(generated_schema))
        source_digest = canonical_digest(source_schema)
    except StructuredSchemaError:
        raise
    except (CanonicalizationError, TypeError, ValueError) as exc:
        raise StructuredSchemaError(f"invalid source schema: {exc}") from exc

    wire_schema = deepcopy(source_schema)
    _require_object_root(wire_schema)
    _compile_node(wire_schema, root=wire_schema, path="$", seen=set())

    try:
        wire_digest = canonical_digest(wire_schema)
    except (CanonicalizationError, TypeError, ValueError) as exc:
        raise StructuredSchemaError(f"invalid compiled schema: {exc}") from exc

    return CompiledStructuredSchema(
        source_schema=source_schema,
        wire_schema=wire_schema,
        source_digest=source_digest,
        wire_digest=wire_digest,
    )


def _require_object_root(schema: dict[str, Any]) -> None:
    schema_type = schema.get("type")
    if schema_type != "object":
        raise StructuredSchemaError("strict output schema root must have type 'object'")


def _compile_node(
    node: Any,
    *,
    root: dict[str, Any],
    path: str,
    seen: set[int],
) -> None:
    if not isinstance(node, dict):
        raise StructuredSchemaError(f"schema node at {path} must be an object")
    schema = cast(dict[str, Any], node)

    # A Pydantic schema is a JSON tree, but a defensive identity guard avoids
    # looping forever if a custom model_json_schema implementation returns a
    # cyclic Python object.
    identity = id(schema)
    if identity in seen:
        return
    seen.add(identity)

    # Defaults describe Pydantic validation, but strict provider schemas have
    # every property required and should not carry default keywords.  The
    # untouched source_schema retains them for provenance and local use.
    schema.pop("default", None)

    schema_type: Any = schema.get("type")
    if "type" in schema and (
        not isinstance(schema_type, str) or schema_type not in _JSON_TYPES
    ):
        raise StructuredSchemaError(f"invalid type at {path}")

    if "$ref" in schema:
        _validate_ref(schema["$ref"], root=root, path=f"{path}.$ref")

    properties_raw: Any = schema.get("properties")
    properties: dict[Any, Any] | None = None
    if "properties" in schema:
        if not isinstance(properties_raw, dict):
            raise StructuredSchemaError(f"properties at {path} must be an object")
        properties = cast(dict[Any, Any], properties_raw)
    if properties is not None:
        if schema_type not in (None, "object"):
            raise StructuredSchemaError(f"properties at {path} require an object schema")
        for name, child in properties.items():
            if not isinstance(name, str):
                raise StructuredSchemaError(f"property names at {path} must be strings")
            _compile_node(child, root=root, path=f"{path}.properties.{name}", seen=seen)

    required_raw: Any = schema.get("required")
    required: list[Any] | None = None
    if "required" in schema:
        if not isinstance(required_raw, list):
            raise StructuredSchemaError(f"required at {path} must be a list of property names")
        required = cast(list[Any], required_raw)
    if required is not None:
        if any(not isinstance(name, str) for name in required):
            raise StructuredSchemaError(f"required at {path} must be a list of property names")
        if properties is None and required:
            raise StructuredSchemaError(
                f"required at {path} references an absent properties object"
            )
        if len(required) != len(set(required)):
            raise StructuredSchemaError(f"required at {path} contains duplicate names")
        if properties is not None and any(name not in properties for name in required):
            raise StructuredSchemaError(f"required at {path} references an undeclared property")

    additional_properties: Any = schema.get("additionalProperties")
    if "additionalProperties" in schema:
        if additional_properties is not False:
            raise StructuredSchemaError(
                f"schema-valued or open additionalProperties are unsupported at {path}"
            )
        if schema_type not in (None, "object"):
            raise StructuredSchemaError(f"additionalProperties at {path} require an object schema")

    is_declared_object = schema_type == "object" or properties is not None
    if is_declared_object:
        schema["additionalProperties"] = False
        if properties is not None:
            # Preserve Pydantic's declaration order.  In particular, nullable
            # default fields remain anyOf(..., null), but become required.
            schema["required"] = list(properties)
        elif required is not None:
            schema["required"] = []

    if "items" in schema:
        items = schema["items"]
        _compile_node(items, root=root, path=f"{path}.items", seen=seen)

    definitions_raw: Any = schema.get("$defs")
    definitions: dict[Any, Any] | None = None
    if "$defs" in schema:
        if not isinstance(definitions_raw, dict):
            raise StructuredSchemaError(f"$defs at {path} must be an object")
        definitions = cast(dict[Any, Any], definitions_raw)
    if definitions is not None:
        for name, definition in definitions.items():
            if not isinstance(name, str):
                raise StructuredSchemaError(f"$defs names at {path} must be strings")
            _compile_node(definition, root=root, path=f"{path}.$defs.{name}", seen=seen)

    for keyword in _COMPOSITIONS:
        alternatives_raw: Any = schema.get(keyword)
        alternatives: list[Any] | None = None
        if keyword in schema:
            if not isinstance(alternatives_raw, list):
                raise StructuredSchemaError(f"{keyword} at {path} must be a non-empty list")
            alternatives = cast(list[Any], alternatives_raw)
        if alternatives is None:
            continue
        if not alternatives:
            raise StructuredSchemaError(f"{keyword} at {path} must be a non-empty list")
        for index, alternative in enumerate(alternatives):
            _compile_node(alternative, root=root, path=f"{path}.{keyword}[{index}]", seen=seen)

    # These keywords describe open/dynamic object shapes and are not safe to
    # pass through strict structured output.  Pydantic does not emit them for
    # ordinary models, but custom schema hooks can.
    for keyword in ("patternProperties", "unevaluatedProperties"):
        if keyword in schema:
            raise StructuredSchemaError(f"unsupported open-object keyword {keyword} at {path}")


def _validate_ref(ref: Any, *, root: dict[str, Any], path: str) -> None:
    if not isinstance(ref, str):
        raise StructuredSchemaError(f"$ref at {path} must be a string")
    if not ref.startswith("#/"):
        raise StructuredSchemaError(f"external $ref is unsupported at {path}")

    current: Any = root
    segments = ref[2:].split("/")
    if not segments or segments[0] != "$defs" or len(segments) < 2:
        raise StructuredSchemaError(f"unsupported local $ref at {path}")
    for raw_segment in segments:
        if not isinstance(current, dict):
            raise StructuredSchemaError(f"$ref target does not exist at {path}")
        current_mapping = cast(dict[Any, Any], current)
        segment = raw_segment.replace("~1", "/").replace("~0", "~")
        if segment not in current_mapping:
            raise StructuredSchemaError(f"$ref target does not exist at {path}")
        current = current_mapping[segment]
    if not isinstance(current, dict):
        raise StructuredSchemaError(f"$ref target at {path} is not a schema object")
