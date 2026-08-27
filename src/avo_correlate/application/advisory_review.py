"""Application service for one explicit, advisory structured patch review."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.contracts.advisory import (
    MAX_INPUT_BYTES,
    MAX_PATCH_BYTES,
    AdvisoryEvaluationSummary,
    AdvisoryEvidenceItem,
    AdvisoryPatchReview,
    AdvisoryPatchReviewInput,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.inference import (
    StructuredInferenceContext,
    StructuredInferenceResult,
)
from avo_correlate.domain.advisory import (
    AdvisoryReviewValidationError,
    package_advisory_review_input,
    validate_advisory_review,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

ArtifactSink = Callable[[bytes, str], str]


class AdvisoryInferencer(Protocol):
    async def infer(
        self, context: StructuredInferenceContext, input: AdvisoryPatchReviewInput
    ) -> StructuredInferenceResult[AdvisoryPatchReview]: ...


@dataclass(frozen=True)
class AdvisoryReviewExecution:
    """Successful review plus immutable evidence-bundle linkage."""

    review_input: AdvisoryPatchReviewInput
    review: AdvisoryPatchReview
    inference_result: StructuredInferenceResult[AdvisoryPatchReview]
    input_digest: str
    bundle_digest: str
    bundle_bytes: bytes


class AdvisoryReviewService:
    """Run exactly one bounded advisory inference and persist its evidence bundle.

    This service intentionally has no policy, admission, lifecycle, database, or
    campaign dependencies. The returned recommendation is informational only.
    """

    def __init__(self, inferencer: AdvisoryInferencer, artifact_sink: ArtifactSink) -> None:
        self._inferencer = inferencer
        self._artifact_sink = artifact_sink

    async def review(
        self,
        context: StructuredInferenceContext,
        *,
        candidate_id: str,
        objective: str,
        patch: str | bytes,
        changed_paths: Sequence[str],
        evaluation_summaries: Sequence[
            AdvisoryEvaluationSummary | Mapping[str, Any]
        ] = (),
        evidence_catalog: Sequence[AdvisoryEvidenceItem | Mapping[str, Any]] = (),
    ) -> AdvisoryReviewExecution:
        """Package, infer once, semantically validate, and persist evidence."""

        review_input = package_advisory_review_input(
            candidate_id=candidate_id,
            objective=objective,
            patch=patch,
            changed_paths=changed_paths,
            evaluation_summaries=evaluation_summaries,
            evidence_catalog=evidence_catalog,
        )
        input_digest = canonical_digest(review_input)
        result = await self._inferencer.infer(context, review_input)
        try:
            validated_review = validate_advisory_review(result.output, review_input)
        except AdvisoryReviewValidationError as exc:
            # Preserve the original domain error for callers while retaining a
            # deterministic diagnostic bundle for audit and test evidence.
            self._persist_bundle(
                context=context,
                review_input=review_input,
                input_digest=input_digest,
                result=result,
                review=None,
                semantic_error=str(exc),
            )
            raise
        bundle_bytes, bundle_digest = self._persist_bundle(
            context=context,
            review_input=review_input,
            input_digest=input_digest,
            result=result,
            review=validated_review,
            semantic_error=None,
        )
        return AdvisoryReviewExecution(
            review_input=review_input,
            review=validated_review,
            inference_result=result,
            input_digest=input_digest,
            bundle_digest=bundle_digest,
            bundle_bytes=bundle_bytes,
        )

    async def execute(
        self,
        context: StructuredInferenceContext,
        **kwargs: Any,
    ) -> AdvisoryReviewExecution:
        """Operation-oriented alias for :meth:`review`."""

        return await self.review(context, **kwargs)

    def _persist_bundle(
        self,
        *,
        context: StructuredInferenceContext,
        review_input: AdvisoryPatchReviewInput,
        input_digest: str,
        result: StructuredInferenceResult[AdvisoryPatchReview],
        review: AdvisoryPatchReview | None,
        semantic_error: str | None,
    ) -> tuple[bytes, str]:
        document: dict[str, Any] = {
            "schema_version": 1,
            "bundle_type": "advisory_patch_review",
            "context": context.model_dump(mode="json"),
            "input_digest": input_digest,
            "input": review_input.model_dump(mode="json"),
            "result": {
                "invocation_id": result.invocation_id,
                "provider_request_id": result.provider_request_id,
                "provider_model_revision": result.provider_model_revision,
                "finish_reason": result.finish_reason,
                "output_artifact_digest": result.output_artifact_digest,
                "usage": result.usage.model_dump(mode="json"),
            },
            "review": review.model_dump(mode="json") if review is not None else None,
            "semantic_error": semantic_error,
        }
        bundle_bytes = canonical_bytes(document)
        if len(bundle_bytes) > MAX_INPUT_BYTES + MAX_PATCH_BYTES:
            raise ValueError("advisory evidence bundle exceeds byte limit")
        expected_digest = canonical_digest(document)
        bundle_digest = self._artifact_sink(bundle_bytes, "advisory-review-bundle")
        if bundle_digest != expected_digest:
            raise ValueError("advisory evidence sink returned the wrong digest")
        return bundle_bytes, bundle_digest


def filesystem_artifact_sink(root: Path) -> ArtifactSink:
    """Create a content-addressed sink suitable for the standalone CLI."""

    store = FilesystemArtifactStore(root)

    def sink(payload: bytes, role: str) -> str:
        reference: ArtifactRef = store.put_bytes(
            payload,
            media_type=(
                "text/plain"
                if role in {"model-system", "model-developer"}
                else "application/json"
            ),
            role=role,
            max_bytes=MAX_INPUT_BYTES + MAX_PATCH_BYTES,
        )
        return reference.digest

    return sink


__all__ = [
    "AdvisoryInferencer",
    "AdvisoryReviewExecution",
    "AdvisoryReviewService",
    "filesystem_artifact_sink",
]
