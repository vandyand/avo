"""Evaluate the frozen structured-inference advisory corpus offline.

This command intentionally has no provider, HTTP, or model-adapter dependency.
It verifies a frozen corpus before passing recorded cases to the deterministic
domain scorer, and writes only content-addressed evidence and deterministic
JSON summaries.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.contracts.advisory_evaluation import (
    AdvisoryEvaluationCaseDigest,
    AdvisoryEvaluationReport,
    AdvisoryEvaluationResultManifest,
)
from avo_correlate.domain.advisory_evaluation import evaluate_advisory_cases
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest, file_digest


class CorpusIntegrityError(ValueError):
    """Raised when a corpus is not the exact frozen suite."""


_JSON_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RELEASED_V2_SUITE_DIGEST = (
    "sha256:6138214c26c2f9eef8fba74d97978bb757d08e7e0a3d33c4f8c505d5acc412bd"
)
_SECRET = re.compile(
    r"(?:[A-Za-z0-9_-]*(?:(?:api|access|secret)[_-]?key|client[_-]?secret)"
    r"\s*[\"']?\s*[:=]|"
    r"bearer\s+[A-Za-z0-9._~-]{12,}|sk-[A-Za-z0-9_-]{12,})",
    re.IGNORECASE,
)
_SENSITIVE_KEY_SUFFIXES = ("apikey", "accesskey", "secretkey")
_SENSITIVE_KEYS = frozenset(
    {"authorization", "accesstoken", "password", "clientsecret", "bearertoken"}
)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CorpusIntegrityError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_bytes(),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_bad_constant,
        )
    except CorpusIntegrityError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CorpusIntegrityError(f"invalid JSON: {path.name}") from exc
    if not isinstance(value, dict):
        raise CorpusIntegrityError(f"JSON document must be an object: {path.name}")
    return cast(dict[str, Any], value)


def _bad_constant(value: str) -> Any:
    raise CorpusIntegrityError(f"non-standard JSON number: {value}")


def _json_bytes(value: Any) -> bytes:
    """Encode deterministic, UTF-8 JSON for the human-readable outputs."""

    return (
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, indent=2, separators=(",", ": ")
        ).encode(
            "utf-8"
        )
        + b"\n"
    )


def _assert_no_secrets(value: Any, location: str = "corpus") -> None:
    if isinstance(value, str) and _SECRET.search(value):
        raise CorpusIntegrityError(f"credential-like text is not allowed ({location})")
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        for key, item in mapping.items():
            key_text = str(key)
            normalized_key = re.sub(r"[^a-z0-9]", "", key_text.casefold())
            if normalized_key in _SENSITIVE_KEYS or normalized_key.endswith(
                _SENSITIVE_KEY_SUFFIXES
            ):
                raise CorpusIntegrityError(
                    f"credential-bearing field is not allowed ({location}.{key_text})"
                )
            _assert_no_secrets(key_text, f"{location}.{key_text}")
            _assert_no_secrets(item, f"{location}.{key_text}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        sequence = cast(Sequence[object], value)
        for index, item in enumerate(sequence):
            _assert_no_secrets(item, f"{location}[{index}]")


def _ensure_safe_tree(root: Path) -> None:
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise CorpusIntegrityError(f"corpus root is unavailable: {root}") from exc
    if not resolved.is_dir():
        raise CorpusIntegrityError("corpus root must be a directory")
    for path in resolved.rglob("*"):
        if path.is_symlink():
            raise CorpusIntegrityError(f"symlink is not allowed: {path.relative_to(resolved)}")
        try:
            path.resolve(strict=True).relative_to(resolved)
        except (OSError, ValueError) as exc:
            raise CorpusIntegrityError(f"path escapes corpus root: {path}") from exc
        if not path.is_file() and not path.is_dir():
            raise CorpusIntegrityError(f"unsupported corpus entry: {path.relative_to(resolved)}")


def _digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not _JSON_DIGEST.fullmatch(value):
        raise CorpusIntegrityError(f"{label} is not a SHA-256 digest")
    return value


def _manifest_case_entries(manifest: Mapping[str, Any]) -> list[tuple[str, str]]:
    case_directory = manifest.get("case_directory")
    if case_directory != "cases":
        raise CorpusIntegrityError("manifest case_directory must be cases")
    raw = manifest.get("task_order")
    if raw is None:
        raise CorpusIntegrityError("manifest must declare task_order")
    entries: list[tuple[str, str]] = []
    if isinstance(raw, list):
        for item in cast(list[object], raw):
            if isinstance(item, str):
                entries.append((item, f"{case_directory}/{item}.json"))
            else:
                raise CorpusIntegrityError("manifest task_order entries must be case IDs")
    else:
        raise CorpusIntegrityError("manifest task_order must be a list")
    ids = [case_id for case_id, _ in entries]
    if len(ids) != len(set(ids)):
        raise CorpusIntegrityError("duplicate case ID in manifest")
    return entries


def _declared_file_digests(digests: Mapping[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    cases = digests.get("cases")
    if isinstance(cases, Mapping):
        case_mapping = cast(Mapping[object, object], cases)
        for case_id, value in case_mapping.items():
            if not isinstance(case_id, str) or not isinstance(value, Mapping):
                raise CorpusIntegrityError("case digest lock is malformed")
            value_mapping = cast(Mapping[object, object], value)
            candidate = value_mapping.get("case_digest")
            path = value_mapping.get("path")
            if not isinstance(candidate, str) or not isinstance(path, str):
                raise CorpusIntegrityError(f"case digest lock is malformed: {case_id}")
            result[path] = candidate
    return result


def _verify_corpus(
    root: Path, *, expected_suite_digest: str
) -> tuple[dict[str, Any], list[dict[str, Any]], str, dict[str, str]]:
    _ensure_safe_tree(root)
    root = root.resolve(strict=True)
    manifest_path = root / "manifest.json"
    digests_path = root / "digests.json"
    manifest = _read_json(manifest_path)
    digests = _read_json(digests_path)
    _assert_no_secrets(manifest)
    _assert_no_secrets(digests)
    entries = _manifest_case_entries(manifest)

    case_directory = manifest.get("case_directory", "cases")
    if not isinstance(case_directory, str) or Path(case_directory).is_absolute():
        raise CorpusIntegrityError("manifest case_directory is unsafe")
    case_dir = root / case_directory
    if not case_dir.is_dir() or case_dir.is_symlink():
        raise CorpusIntegrityError("corpus must contain a cases directory")
    actual_paths = {
        path.relative_to(root).as_posix() for path in case_dir.glob("*.json") if path.is_file()
    }
    declared_paths = {path for _, path in entries}
    if actual_paths != declared_paths:
        missing = sorted(declared_paths - actual_paths)
        extra = sorted(actual_paths - declared_paths)
        raise CorpusIntegrityError(f"case set mismatch (missing={missing}, extra={extra})")

    declared = _declared_file_digests(digests)
    actual_digests: dict[str, str] = {}
    cases: list[dict[str, Any]] = []
    for case_id, relative in entries:
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise CorpusIntegrityError(f"case path escapes corpus: {relative}") from exc
        if candidate.is_symlink() or not candidate.is_file():
            raise CorpusIntegrityError(f"invalid case path: {relative}")
        raw = file_digest(candidate)
        actual_digests[relative] = raw
        expected = declared.get(relative)
        if expected is None:
            expected = declared.get(f"cases/{case_id}.json")
        if expected is None:
            raise CorpusIntegrityError(f"missing raw digest lock: {relative}")
        if _digest(expected, label=f"digest for {relative}") != raw:
            raise CorpusIntegrityError(f"raw digest mismatch: {relative}")
        case = _read_json(candidate)
        _assert_no_secrets(case, relative)
        embedded = case.get("case_id", case.get("id"))
        if embedded != case_id:
            raise CorpusIntegrityError(f"case ID/path mismatch: {relative}")
        cases.append(case)

    if manifest.get("pilot_id") != digests.get("pilot_id"):
        raise CorpusIntegrityError("corpus and digest lock IDs differ")
    if manifest.get("schema_version") != digests.get("schema_version"):
        raise CorpusIntegrityError("corpus and digest lock schema versions differ")
    lock_base = {
        "manifest_digest": file_digest(manifest_path),
        "pilot_id": manifest.get("pilot_id"),
        "schema_version": manifest.get("schema_version"),
        "cases": {
            case_id: {"path": relative, "case_digest": actual_digests[relative]}
            for case_id, relative in entries
        },
    }
    expected_lock = {**lock_base, "suite_digest": canonical_digest(lock_base)}
    if digests != expected_lock:
        raise CorpusIntegrityError("raw file digest lock mismatch")
    declared_suite = _digest(digests["suite_digest"], label="suite digest")
    if declared_suite != canonical_digest(lock_base):
        raise CorpusIntegrityError("canonical suite lock mismatch")
    trusted_suite = _digest(expected_suite_digest, label="expected suite digest")
    if declared_suite != trusted_suite:
        raise CorpusIntegrityError("corpus suite digest does not match the trust anchor")
    return manifest, cases, declared_suite, actual_digests


def evaluate(
    corpus_root: Path,
    output_dir: Path,
    *,
    expected_suite_digest: str = RELEASED_V2_SUITE_DIGEST,
) -> dict[str, Any]:
    _manifest, cases, suite_digest, raw_case_digests = _verify_corpus(
        corpus_root, expected_suite_digest=expected_suite_digest
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    store = FilesystemArtifactStore(output_dir / "artifacts")
    source_digests = {
        "manifest.json": file_digest(corpus_root / "manifest.json"),
        **raw_case_digests,
    }
    try:
        typed_report = evaluate_advisory_cases(
            cases, corpus_digest=suite_digest, source_digests=source_digests
        )
    except Exception as exc:
        raise CorpusIntegrityError("deterministic scorer failed for corpus") from exc
    corpus_ids = {cast(str, case["case_id"]) for case in cases}
    score_ids = {score.case_id for score in typed_report.case_scores}
    if score_ids != corpus_ids or len(typed_report.case_scores) != len(cases):
        raise CorpusIntegrityError("deterministic scorer returned the wrong case ID set")
    digest_by_id = {Path(relative).stem: digest for relative, digest in raw_case_digests.items()}
    case_digests: list[AdvisoryEvaluationCaseDigest] = []
    for score in typed_report.case_scores:
        scored = score.model_dump(mode="json")
        _assert_no_secrets(scored, score.case_id)
        result_bytes = canonical_bytes(score)
        result_ref = store.put_bytes(
            result_bytes,
            media_type="application/json",
            role="advisory-case-result",
            max_bytes=2_000_000,
        )
        case_digests.append(
            AdvisoryEvaluationCaseDigest(
                case_id=score.case_id,
                case_digest=digest_by_id[score.case_id],
                result_digest=result_ref.digest,
            )
        )
    # Keep the aggregate report exactly in the typed core contract.  The
    # per-case CAS objects and result manifest provide the extra linkage
    # without duplicating score records inside an untyped wrapper.
    report = AdvisoryEvaluationReport.model_validate(typed_report).model_dump(mode="json")
    if report.get("corpus_digest") != suite_digest:
        raise CorpusIntegrityError("scorer report corpus digest does not match corpus lock")
    report_bytes = canonical_bytes(report)
    report_ref = store.put_bytes(
        report_bytes,
        media_type="application/json",
        role="advisory-aggregate-report",
        max_bytes=10_000_000,
    )
    typed_manifest = AdvisoryEvaluationResultManifest(
        corpus_digest=suite_digest,
        report_digest=report_ref.digest,
        report_size_bytes=len(report_bytes),
        case_digests=case_digests,
    )
    # The self-digest is deliberately absent from the CAS payload to avoid a
    # circular hash; it is added only to the human-readable result document.
    manifest_document = typed_manifest.model_dump(mode="json", exclude_none=True)
    manifest_bytes = canonical_bytes(manifest_document)
    manifest_ref = store.put_bytes(
        manifest_bytes,
        media_type="application/json",
        role="advisory-evaluation-result",
        max_bytes=2_000_000,
    )
    result = AdvisoryEvaluationResultManifest(
        **manifest_document, result_manifest_digest=manifest_ref.digest
    ).model_dump(mode="json")
    (output_dir / "report.json").write_bytes(_json_bytes(report))
    (output_dir / "result.json").write_bytes(_json_bytes(result))
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--expected-suite-digest",
        default=RELEASED_V2_SUITE_DIGEST,
        help="Trusted SHA-256 suite digest (defaults to the released v2 corpus).",
    )
    return parser


def main() -> int:
    try:
        result = evaluate(**vars(_parser().parse_args()))
    except Exception as exc:
        print(f"advisory corpus evaluation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
