"""Integration checks for the offline advisory-corpus command."""

from __future__ import annotations

import hashlib
import json
import socket
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import pytest

import scripts.evaluate_advisory_corpus as cli
from avo_correlate.contracts.advisory_evaluation import AdvisoryEvaluationCase
from avo_correlate.domain.advisory_evaluation import evaluate_advisory_cases


def _case(case_id: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "case_id": case_id,
        "review_input": {
            "schema_version": 1,
            "candidate_id": f"candidate-{case_id}",
            "objective": "Exercise a synthetic offline boundary.",
            "patch": "",
            "changed_paths": ["src/example.py"],
            "evaluation_summaries": [],
            "evidence_catalog": [],
        },
        "observation": {
            "schema_version": 1,
            "kind": "refusal",
            "payload": "Synthetic provider refusal.",
        },
        "expected_stage": "provider_rejected",
        "themes": [],
        "forbidden_claims": [],
        "severity_expectations": [],
    }


def _relock(root: Path, ids: list[str]) -> str:
    base = {
        "schema_version": 1,
        "pilot_id": "structured-inference-v2-test",
        "manifest_digest": cli.file_digest(root / "manifest.json"),
        "cases": {
            case_id: {
                "path": f"cases/{case_id}.json",
                "case_digest": cli.file_digest(root / "cases" / f"{case_id}.json"),
            }
            for case_id in ids
        },
    }
    suite_digest = cli.canonical_digest(base)
    (root / "digests.json").write_bytes(
        cli.canonical_bytes({**base, "suite_digest": suite_digest})
    )
    return suite_digest


def _write_corpus(root: Path, order: list[str] | None = None) -> str:
    (root / "cases").mkdir(parents=True)
    ids = order or ["case-b", "case-a"]
    for case_id in ids:
        (root / "cases" / f"{case_id}.json").write_bytes(cli.canonical_bytes(_case(case_id)))
    manifest = {
        "schema_version": 1,
        "pilot_id": "structured-inference-v2-test",
        "case_directory": "cases",
        "task_order": ids,
    }
    (root / "manifest.json").write_bytes(cli.canonical_bytes(manifest))
    return _relock(root, ids)


def _evaluate(corpus: Path, output: Path, suite_digest: str) -> dict[str, Any]:
    return cli.evaluate(corpus, output, expected_suite_digest=suite_digest)


def _object_path(output: Path, digest: str) -> Path:
    value = digest.removeprefix("sha256:")
    return output / "artifacts" / "objects" / "sha256" / value[:2] / value[2:]


def test_success_is_offline_and_links_every_cas_object(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    suite_digest = _write_corpus(corpus)
    output = tmp_path / "out"
    result = _evaluate(corpus, output, suite_digest)
    assert result["corpus_digest"] == suite_digest
    assert result["report_digest"].startswith("sha256:")
    assert len(result["case_digests"]) == 2
    for item in result["case_digests"]:
        path = _object_path(output, item["result_digest"])
        assert path.is_file()
        assert "OPENROUTER" not in path.read_text(encoding="utf-8", errors="ignore")
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["result_digest"][7:]


def test_repeated_runs_are_byte_identical(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    suite_digest = _write_corpus(corpus)
    _evaluate(corpus, tmp_path / "one", suite_digest)
    _evaluate(corpus, tmp_path / "two", suite_digest)
    assert (tmp_path / "one" / "report.json").read_bytes() == (
        tmp_path / "two" / "report.json"
    ).read_bytes()
    assert (tmp_path / "one" / "result.json").read_bytes() == (
        tmp_path / "two" / "result.json"
    ).read_bytes()


def test_output_order_is_canonical_case_id_order(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    suite_digest = _write_corpus(corpus, ["case-b", "case-a"])
    result = _evaluate(corpus, tmp_path / "out", suite_digest)
    assert [item["case_id"] for item in result["case_digests"]] == ["case-a", "case-b"]


def test_released_digest_is_a_required_trust_anchor(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    suite_digest = _write_corpus(corpus)
    with pytest.raises(cli.CorpusIntegrityError, match="trust anchor"):
        cli.evaluate(corpus, tmp_path / "default-anchor")
    _evaluate(corpus, tmp_path / "explicit-anchor", suite_digest)


@pytest.mark.parametrize("mutation", ["lock", "extra", "missing"])
def test_lock_and_case_set_drift_is_rejected(tmp_path: Path, mutation: str) -> None:
    corpus = tmp_path / "corpus"
    suite_digest = _write_corpus(corpus)
    if mutation == "lock":
        document = json.loads((corpus / "digests.json").read_text())
        document["suite_digest"] = "sha256:" + "0" * 64
        (corpus / "digests.json").write_bytes(cli.canonical_bytes(document))
    elif mutation == "extra":
        (corpus / "cases" / "extra.json").write_text('{"case_id":"extra"}', encoding="utf-8")
    else:
        (corpus / "cases" / "case-a.json").unlink()
    with pytest.raises(cli.CorpusIntegrityError):
        _evaluate(corpus, tmp_path / "out", suite_digest)


def test_duplicate_keys_are_rejected(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    suite_digest = _write_corpus(corpus)
    manifest = corpus / "manifest.json"
    manifest.write_text('{"case_order":[],"case_order":[]}', encoding="utf-8")
    with pytest.raises(cli.CorpusIntegrityError, match="duplicate"):
        _evaluate(corpus, tmp_path / "out", suite_digest)


def test_symlinked_case_tree_is_rejected(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    suite_digest = _write_corpus(corpus)
    link = corpus / "cases" / "linked.json"
    try:
        link.symlink_to(corpus / "cases" / "case-a.json")
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(cli.CorpusIntegrityError, match="symlink"):
        _evaluate(corpus, tmp_path / "out", suite_digest)


@pytest.mark.parametrize("sensitive_key", ["api_key", "OPENROUTER_API_KEY", "client-secret"])
def test_credential_bearing_fields_are_rejected(tmp_path: Path, sensitive_key: str) -> None:
    corpus = tmp_path / "corpus"
    _write_corpus(corpus)
    case_path = corpus / "cases" / "case-a.json"
    case = json.loads(case_path.read_text(encoding="utf-8"))
    case[sensitive_key] = "A" * 32
    case_path.write_bytes(cli.canonical_bytes(case))
    suite_digest = _relock(corpus, ["case-b", "case-a"])
    with pytest.raises(cli.CorpusIntegrityError, match="credential-bearing"):
        _evaluate(corpus, tmp_path / "out", suite_digest)


def test_credential_field_embedded_in_recorded_payload_is_rejected(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    _write_corpus(corpus)
    case_path = corpus / "cases" / "case-a.json"
    case = json.loads(case_path.read_text(encoding="utf-8"))
    case["observation"]["payload"] = '{"api_key":"' + "A" * 32 + '"}'
    case_path.write_bytes(cli.canonical_bytes(case))
    suite_digest = _relock(corpus, ["case-b", "case-a"])
    with pytest.raises(cli.CorpusIntegrityError, match="credential-like"):
        _evaluate(corpus, tmp_path / "out", suite_digest)


def test_scorer_path_makes_no_network_call_or_provider_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus = tmp_path / "corpus"
    suite_digest = _write_corpus(corpus)
    before = set(sys.modules)

    def fail_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", fail_network)
    _evaluate(corpus, tmp_path / "out", suite_digest)
    imported = set(sys.modules) - before
    assert not {
        name
        for name in imported
        if "openrouter" in name.casefold() or name.startswith("avo_correlate.adapters.model")
    }


def test_partial_scorer_report_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus = tmp_path / "corpus"
    suite_digest = _write_corpus(corpus)

    def omit_one(
        cases: Iterable[AdvisoryEvaluationCase | Mapping[str, Any]],
        *,
        report_id: str = "offline-advisory-evaluation-v2",
        corpus_digest: str | None = None,
        source_digests: Mapping[str, str] | None = None,
    ) -> Any:
        values = list(cases)
        return evaluate_advisory_cases(
            values[:-1],
            report_id=report_id,
            corpus_digest=corpus_digest,
            source_digests=source_digests,
        )

    monkeypatch.setattr(cli, "evaluate_advisory_cases", omit_one)
    with pytest.raises(cli.CorpusIntegrityError, match="wrong case ID set"):
        _evaluate(corpus, tmp_path / "out", suite_digest)


def test_checked_in_corpus_and_published_evidence_are_reproducible(tmp_path: Path) -> None:
    corpus = Path("pilots/structured-inference-v2")
    if not corpus.is_dir():
        pytest.skip("v2 corpus is not checked out")
    output = tmp_path / "out"
    result = cli.evaluate(corpus, output)
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    expected_stages = {
        "correctness-invariant": "accepted",
        "missing-positive-tests": "accepted",
        "path-traversal-guard": "accepted",
        "compatibility-break": "accepted",
        "insufficient-evidence": "accepted",
        "fabricated-evidence-reference": "semantic_rejected",
        "omitted-required-strict-fields": "wire_rejected",
        "malformed-json": "parse_rejected",
        "provider-refusal": "provider_rejected",
        "truncated-output": "provider_rejected",
    }
    scores = {item["case_id"]: item for item in report["case_scores"]}
    assert {case_id: scores[case_id]["actual_stage"] for case_id in expected_stages} == (
        expected_stages
    )
    assert report["evaluator_id"] == "avo-advisory-evaluation"
    assert report["evaluator_version"] == 1
    assert report["wire_schema_digest"] == (
        "sha256:0b545c7e447cfa1f60ce395beb08614e4887330dff8f1ddf245169f44f080d96"
    )
    assert result["corpus_digest"] == cli.RELEASED_V2_SUITE_DIGEST
    assert result["report_digest"] == (
        "sha256:50bdb147e3ba77931daca5a76f231d75ae4ad44f16a09c63fddbe390c7b394a9"
    )
    assert result["result_manifest_digest"] == (
        "sha256:e6a675d4f5bce4d7dd6244b210c0caedb1495357ff165269ba63ac18d95cb4ed"
    )
    checked_in = corpus / "results" / "v1"
    assert (output / "report.json").read_bytes() == (checked_in / "report.json").read_bytes()
    assert (output / "result.json").read_bytes() == (checked_in / "result.json").read_bytes()
    for item in result["case_digests"]:
        assert _object_path(output, item["result_digest"]).is_file()
    assert _object_path(output, result["report_digest"]).is_file()
    assert _object_path(output, result["result_manifest_digest"]).is_file()
