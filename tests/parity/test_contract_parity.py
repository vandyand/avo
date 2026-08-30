import hashlib
from pathlib import Path

from avo_correlate.devtools.export_schemas import export
from avo_correlate.domain.canonical import canonical_bytes


def test_rfc8785_fixture_is_host_independent() -> None:
    payload = canonical_bytes({"unicode": "é", "values": [1, True, None]})
    assert payload == b'{"unicode":"\xc3\xa9","values":[1,true,null]}'
    assert hashlib.sha256(payload).hexdigest() == (
        "44c4ab637da447823c8e47f518c8b6647d0fe1ae303a46184c2b7d859326b448"
    )


def test_checked_in_schemas_match_generation(tmp_path: Path) -> None:
    export(tmp_path)
    checked_in = Path("schemas")
    generated = {item.name: item.read_bytes() for item in tmp_path.glob("*.json")}
    # MainCompletionPackage.v1 is retained as an immutable historical wire
    # contract.  It is intentionally not regenerated after the breaking C4
    # v2 bump and must never be accepted by the v2 model.
    committed = {
        item.name: item.read_bytes()
        for item in checked_in.glob("*.json")
        if item.name != "MainCompletionPackage.v1.schema.json"
    }
    assert generated == committed


def test_main_completion_historical_schema_is_retained_and_distinct() -> None:
    import json

    v1_path = Path("schemas/MainCompletionPackage.v1.schema.json")
    v1 = json.loads(v1_path.read_text())
    v2 = json.loads(Path("schemas/MainCompletionPackage.v2.schema.json").read_text())
    assert hashlib.sha256(v1_path.read_bytes()).hexdigest() == (
        "ba01db4f0bbef230b56c36f270a5587f4a68e69c54a534c6f2a0010489d53669"
    )
    assert v1["properties"]["schema_version"]["const"] == 1
    assert v2["properties"]["schema_version"]["const"] == 2
