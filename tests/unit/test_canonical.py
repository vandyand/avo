from pathlib import Path

import pytest

from avo_correlate.domain.canonical import (
    CanonicalizationError,
    canonical_bytes,
    canonical_digest,
    source_tree_digest,
)


def test_canonical_json_is_order_independent() -> None:
    left = {"z": 1, "a": ["value", True]}
    right = {"a": ["value", True], "z": 1}
    assert canonical_bytes(left) == canonical_bytes(right)
    assert canonical_digest(left) == canonical_digest(right)


def test_canonical_json_rejects_non_nfc_string() -> None:
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"value": "e\u0301"})


def test_source_tree_digest_changes_with_content(tmp_path: Path) -> None:
    file = tmp_path / "hello.txt"
    file.write_text("first", encoding="utf-8")
    first = source_tree_digest(tmp_path)
    file.write_text("second", encoding="utf-8")
    assert first != source_tree_digest(tmp_path)


def test_source_tree_digest_rejects_symlink_when_supported(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("target", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(CanonicalizationError):
        source_tree_digest(tmp_path)
