from typing import Any

import pytest
from pydantic import ValidationError

from avo_correlate.contracts.advisory import (
    MAX_INPUT_BYTES,
    MAX_PATCH_BYTES,
    AdvisoryEvaluationSummary,
    AdvisoryEvidenceItem,
    AdvisoryFinding,
    AdvisoryFindingCategory,
    AdvisoryFindingSeverity,
    AdvisoryPatchReview,
    AdvisoryPatchReviewInput,
    AdvisoryRecommendation,
)
from avo_correlate.domain.advisory import (
    AdvisoryPackagingError,
    AdvisoryReviewValidationError,
    package_advisory_review_input,
    validate_advisory_review,
)

DIGEST = "sha256:" + ("a" * 64)


def evidence(evidence_id: str = "patch") -> AdvisoryEvidenceItem:
    return AdvisoryEvidenceItem(evidence_id=evidence_id, content_digest=DIGEST, label="patch")


def review_input(**overrides: object) -> AdvisoryPatchReviewInput:
    values: dict[str, Any] = {
        "candidate_id": "candidate-1",
        "objective": "Improve the bounded review path",
        "patch": "diff --git a/a.py b/a.py\n",
        "changed_paths": ["src/a.py"],
        "evidence_catalog": [evidence()],
    }
    values.update(overrides)
    return AdvisoryPatchReviewInput(**values)


def review(**overrides: object) -> AdvisoryPatchReview:
    values: dict[str, Any] = {
        "candidate_id": "candidate-1",
        "recommendation": AdvisoryRecommendation.ACCEPT_WITH_FOLLOW_UP,
        "summary": "The patch is directionally sound.",
        "rationale": "The changed behavior is bounded and covered by the supplied evidence.",
        "confidence_micros": 850_000,
    }
    values.update(overrides)
    return AdvisoryPatchReview(**values)


def test_contracts_are_frozen_extra_forbidden_and_versioned() -> None:
    value = review_input()
    assert value.schema_version == 1
    with pytest.raises(ValidationError):
        AdvisoryPatchReviewInput.model_validate({**value.model_dump(), "unexpected": True})
    with pytest.raises(ValidationError):
        value.candidate_id = "other"  # type: ignore[misc]


@pytest.mark.parametrize(
    "path", ["../secret", "/etc/passwd", "C:/secret", r"folder\file", "a//b", "./a"]
)
def test_changed_paths_reject_escape_and_non_posix_forms(path: str) -> None:
    with pytest.raises(ValidationError):
        review_input(changed_paths=[path])


def test_changed_paths_reject_case_collisions() -> None:
    with pytest.raises(ValidationError, match="changed paths"):
        review_input(changed_paths=["src/A.py", "src/a.py"])


def test_evidence_catalog_rejects_duplicate_ids_and_unbound_evaluation_refs() -> None:
    with pytest.raises(ValidationError, match="evidence IDs"):
        review_input(evidence_catalog=[evidence("same"), evidence("SAME")])
    summary = AdvisoryEvaluationSummary(
        evaluation_id="eval-1",
        outcome="passed",
        summary="Tests passed",
        evidence_refs=["missing"],
    )
    with pytest.raises(ValidationError, match="outside the catalog"):
        review_input(evaluation_summaries=[summary])


def test_packager_accepts_utf8_bytes_and_does_not_mutate_inputs() -> None:
    paths = ["src/a.py"]
    result = package_advisory_review_input(
        candidate_id="candidate-1",
        objective="Review",
        patch="é".encode(),
        changed_paths=paths,
        evidence_catalog=[evidence()],
    )
    assert result.patch == "é"
    assert paths == ["src/a.py"]


def test_packager_rejects_malformed_utf8_and_oversized_patch_without_truncation() -> None:
    with pytest.raises(AdvisoryPackagingError, match="UTF-8"):
        package_advisory_review_input(
            candidate_id="candidate-1",
            objective="Review",
            patch=b"\xff",
            changed_paths=["src/a.py"],
        )
    with pytest.raises(AdvisoryPackagingError, match="patch"):
        package_advisory_review_input(
            candidate_id="candidate-1",
            objective="Review",
            patch=b"x" * (MAX_PATCH_BYTES + 1),
            changed_paths=["src/a.py"],
        )
    with pytest.raises(AdvisoryPackagingError, match="text or UTF-8"):
        package_advisory_review_input(
            candidate_id="candidate-1",
            objective="Review",
            patch=object(),  # type: ignore[arg-type]
            changed_paths=["src/a.py"],
        )


def test_packager_rejects_duplicate_paths_and_duplicate_evidence() -> None:
    with pytest.raises(AdvisoryPackagingError, match="changed paths"):
        package_advisory_review_input(
            candidate_id="candidate-1",
            objective="Review",
            patch="diff",
            changed_paths=["src/a.py", "src/A.py"],
        )
    with pytest.raises(AdvisoryPackagingError, match="evidence IDs"):
        package_advisory_review_input(
            candidate_id="candidate-1",
            objective="Review",
            patch="diff",
            changed_paths=["src/a.py"],
            evidence_catalog=[evidence("x"), evidence("X")],
        )


def test_input_is_bounded_before_any_inference() -> None:
    with pytest.raises(ValidationError):
        review_input(objective="x" * MAX_INPUT_BYTES)


def test_finding_enumerations_and_confidence_bounds() -> None:
    finding = AdvisoryFinding(
        category=AdvisoryFindingCategory.SECURITY,
        severity=AdvisoryFindingSeverity.HIGH,
        summary="A security concern",
        rationale="The boundary needs an explicit check.",
        evidence_refs=["patch"],
    )
    assert finding.category.value == "security"
    with pytest.raises(ValidationError):
        review(confidence_micros=1_000_001)
    with pytest.raises(ValidationError):
        review(confidence_micros=-1)


def test_semantic_validator_binds_candidate_and_evidence() -> None:
    context = review_input()
    finding = AdvisoryFinding(
        category=AdvisoryFindingCategory.CORRECTNESS,
        severity=AdvisoryFindingSeverity.MEDIUM,
        summary="Check the guard",
        rationale="The guard is covered by the patch evidence.",
        evidence_refs=["patch"],
    )
    assert (
        validate_advisory_review(review(findings=[finding]), context).candidate_id
        == "candidate-1"
    )
    reused = finding.model_copy(update={"summary": "A second observation"})
    assert validate_advisory_review(review(findings=[finding, reused]), context) == review(
        findings=[finding, reused]
    )

    with pytest.raises(AdvisoryReviewValidationError, match="does not match"):
        validate_advisory_review(review(candidate_id="other"), context)
    unbound = finding.model_copy(update={"evidence_refs": ["missing"]})
    with pytest.raises(AdvisoryReviewValidationError, match="outside the catalog"):
        validate_advisory_review(review(findings=[unbound]), context)
    duplicate = finding.model_copy(update={"evidence_refs": ["patch", "patch"]})
    with pytest.raises(AdvisoryReviewValidationError, match=r"finding.*duplicate"):
        validate_advisory_review(review(findings=[duplicate]), context)

    outside_path = finding.model_copy(update={"affected_paths": ["src/other.py"]})
    with pytest.raises(AdvisoryReviewValidationError, match="changed paths"):
        validate_advisory_review(review(findings=[outside_path]), context)


def test_advisory_contract_exposes_no_authority_fields() -> None:
    fields = set(AdvisoryPatchReview.model_fields)
    assert not fields.intersection({"outcome", "admit", "policy", "state", "transition"})
    assert len(AdvisoryPatchReviewInput.model_dump_json(review_input()).encode()) <= MAX_INPUT_BYTES
