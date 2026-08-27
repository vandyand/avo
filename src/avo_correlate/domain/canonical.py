"""RFC 8785 record hashing and portable source-tree digests."""

import hashlib
import unicodedata
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import rfc8785
from pydantic import BaseModel


class CanonicalizationError(ValueError):
    """Raised for values that cannot be represented canonically."""


def _normalize(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _normalize(value.model_dump(mode="json"))
    if isinstance(value, str):
        if value != unicodedata.normalize("NFC", value):
            raise CanonicalizationError("strings must already be NFC-normalized")
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        mapping = cast(Mapping[object, object], value)
        for key, item in mapping.items():
            if not isinstance(key, str):
                raise CanonicalizationError("JSON object keys must be strings")
            normalized_key = _normalize(key)
            if normalized_key in result:
                raise CanonicalizationError("duplicate normalized JSON key")
            result[normalized_key] = _normalize(item)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        sequence = cast(Sequence[object], value)
        return [_normalize(item) for item in sequence]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise CanonicalizationError(f"unsupported canonical value: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    try:
        return rfc8785.dumps(_normalize(value))
    except (rfc8785.CanonicalizationError, rfc8785.FloatDomainError) as exc:
        raise CanonicalizationError(str(exc)) from exc


def canonical_digest(value: Any) -> str:
    return f"sha256:{hashlib.sha256(canonical_bytes(value)).hexdigest()}"


def file_digest(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def source_tree_digest(root: Path, *, symlinks: str = "deny") -> str:
    root = root.resolve(strict=True)
    records: list[bytes] = []
    normalized_seen: set[str] = set()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root)
        normalized_path = unicodedata.normalize("NFC", relative.as_posix())
        folded = normalized_path.casefold()
        if folded in normalized_seen:
            raise CanonicalizationError(f"case or Unicode path collision: {normalized_path}")
        normalized_seen.add(folded)
        if path.is_symlink():
            if symlinks != "internal_only":
                raise CanonicalizationError(f"symlink is not allowed: {normalized_path}")
            target = path.resolve(strict=True)
            if not target.is_relative_to(root):
                raise CanonicalizationError(f"symlink escapes tree: {normalized_path}")
            link_value = path.readlink().as_posix().encode()
            records.append(
                normalized_path.encode()
                + b"\0symlink\0symlink\0"
                + str(len(link_value)).encode()
                + b"\0sha256:"
                + hashlib.sha256(link_value).hexdigest().encode()
                + b"\n"
            )
            continue
        if path.is_dir():
            continue
        if not path.is_file():
            raise CanonicalizationError(f"unsupported file type: {normalized_path}")
        size = path.stat().st_size
        records.append(
            normalized_path.encode()
            + b"\0regular\0regular\0"
            + str(size).encode()
            + b"\0"
            + file_digest(path).encode()
            + b"\n"
        )
    return f"sha256:{hashlib.sha256(b''.join(records)).hexdigest()}"
