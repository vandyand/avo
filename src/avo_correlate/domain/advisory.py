"""Pure packaging and semantic validation for advisory patch reviews."""

from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import ValidationError

from avo_correlate.contracts.advisory import (
    MAX_INPUT_BYTES,
    MAX_PATCH_BYTES,
    AdvisoryEvaluationSummary,
    AdvisoryEvidenceItem,
    AdvisoryPatchReview,
    AdvisoryPatchReviewInput,
)


class AdvisoryPackagingError(ValueError):
    """The bounded advisory input could not be packaged without loss."""


class AdvisoryReviewValidationError(ValueError):
    """The model output is syntactically valid but not valid for its input."""


def package_advisory_review_input(
    *,
    candidate_id: str,
    objective: str,
    patch: object,
    changed_paths: Sequence[str],
    evaluation_summaries: Sequence[AdvisoryEvaluationSummary | Mapping[str, Any]] = (),
    evidence_catalog: Sequence[AdvisoryEvidenceItem | Mapping[str, Any]] = (),
) -> AdvisoryPatchReviewInput:
    """Build a deterministic review input and reject oversized data.

    No field is truncated. Bytes patches must be UTF-8, because the wire contract
    is JSON text and silently replacing malformed bytes would change the reviewed
    candidate.
    """

    if not isinstance(patch, (str, bytes)):
        raise AdvisoryPackagingError("advisory patch must be text or UTF-8 bytes")
    if isinstance(patch, bytes):
        if len(patch) > MAX_PATCH_BYTES:
            raise AdvisoryPackagingError("advisory patch exceeds byte limit")
        try:
            patch_text = patch.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AdvisoryPackagingError("advisory patch is not valid UTF-8") from exc
    else:
        patch_text = patch
        if len(patch_text.encode("utf-8")) > MAX_PATCH_BYTES:
            raise AdvisoryPackagingError("advisory patch exceeds byte limit")

    try:
        packaged = AdvisoryPatchReviewInput(
            candidate_id=candidate_id,
            objective=objective,
            patch=patch_text,
            changed_paths=list(changed_paths),
            evaluation_summaries=[
                item
                if isinstance(item, AdvisoryEvaluationSummary)
                else AdvisoryEvaluationSummary.model_validate(item)
                for item in evaluation_summaries
            ],
            evidence_catalog=[
                item
                if isinstance(item, AdvisoryEvidenceItem)
                else AdvisoryEvidenceItem.model_validate(item)
                for item in evidence_catalog
            ],
        )
    except (ValidationError, UnicodeEncodeError, TypeError, ValueError) as exc:
        raise AdvisoryPackagingError(f"invalid advisory review input: {exc}") from exc

    # The model checks the serialized representation too. Keep this explicit at
    # the domain boundary so this invariant remains visible to service callers.
    if len(packaged.model_dump_json().encode("utf-8")) > MAX_INPUT_BYTES:
        raise AdvisoryPackagingError("advisory review input exceeds byte limit")
    return packaged


def validate_advisory_review(
    review: AdvisoryPatchReview,
    review_input: AdvisoryPatchReviewInput,
) -> AdvisoryPatchReview:
    """Validate candidate and evidence binding without granting authority.

    The returned value is the same immutable object. This function does not call
    policy, admission, persistence, or lifecycle services.
    """

    if review.candidate_id != review_input.candidate_id:
        raise AdvisoryReviewValidationError("review candidate does not match review input")

    catalog_ids = {item.evidence_id for item in review_input.evidence_catalog}
    changed_path_keys = {path.casefold() for path in review_input.changed_paths}
    for finding in review.findings:
        if len(finding.evidence_refs) != len(set(finding.evidence_refs)):
            raise AdvisoryReviewValidationError(
                "finding contains duplicate evidence references"
            )
        missing_evidence = sorted(set(finding.evidence_refs) - catalog_ids)
        if missing_evidence:
            raise AdvisoryReviewValidationError(
                "review cites evidence outside the catalog: " + ", ".join(missing_evidence)
            )
        missing_paths = sorted(
            {
                path
                for path in finding.affected_paths
                if path.casefold() not in changed_path_keys
            }
        )
        if missing_paths:
            raise AdvisoryReviewValidationError(
                "finding cites changed paths outside the input: " + ", ".join(missing_paths)
            )
    return review


# Explicit names for callers that prefer operation-oriented terminology.
package_review_input = package_advisory_review_input
validate_review = validate_advisory_review


__all__ = [
    "AdvisoryPackagingError",
    "AdvisoryReviewValidationError",
    "package_advisory_review_input",
    "package_review_input",
    "validate_advisory_review",
    "validate_review",
]
