import json
from pathlib import Path

import pytest

from scripts.run_codex_pilot import (
    remove_generated_python_caches,
    verify_pilot_lock,
)


def test_pilot_cache_normalization_removes_only_pyc_files(tmp_path: Path) -> None:
    cache = tmp_path / "src" / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "module.cpython-312.pyc").write_bytes(b"generated")
    nested = tmp_path / "tests" / "__pycache__"
    nested.mkdir(parents=True)
    (nested / "test.cpython-312.pyc").write_bytes(b"generated")

    assert remove_generated_python_caches(tmp_path) == 2
    assert not cache.exists()
    assert not nested.exists()


def test_pilot_cache_normalization_fails_on_unexpected_content(tmp_path: Path) -> None:
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    unexpected = cache / "keep.txt"
    unexpected.write_text("candidate content", encoding="utf-8")

    with pytest.raises(RuntimeError, match="unexpected Python cache artifact"):
        remove_generated_python_caches(tmp_path)
    assert unexpected.read_text(encoding="utf-8") == "candidate content"


def test_codex_pilot_fixture_lock_is_current() -> None:
    root = Path("pilots/codex-v1").resolve(strict=True)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert verify_pilot_lock(root, manifest) == (
        "sha256:3ef992192adcf47a6bc1ab4021b236c585f2047a13394481c862e12f3ca601c2"
    )


def test_comparison_pilot_fixture_lock_is_current() -> None:
    root = Path("pilots/comparison-v1").resolve(strict=True)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert verify_pilot_lock(root, manifest) == (
        "sha256:19e60770f7741ec8dfad5cba7f1caf3bbc552ae0d48a946e0d714d097aceff04"
    )


def test_comparison_v2_pilot_fixture_lock_is_current() -> None:
    root = Path("pilots/comparison-v2").resolve(strict=True)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert verify_pilot_lock(root, manifest) == (
        "sha256:49191e7309957f122a8e67e2d18e6f82004da99b6147026aaef48b062accf680"
    )
