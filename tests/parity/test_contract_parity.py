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
    committed = {item.name: item.read_bytes() for item in checked_in.glob("*.json")}
    assert generated == committed
