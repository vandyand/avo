import asyncio
import hashlib
from datetime import UTC, datetime
from typing import Any

import pytest

from avo_correlate.application.advisory_review import AdvisoryReviewService
from avo_correlate.contracts.advisory import (
    AdvisoryEvidenceItem,
    AdvisoryFindingCategory,
    AdvisoryFindingSeverity,
    AdvisoryPatchReview,
    AdvisoryPatchReviewInput,
    AdvisoryRecommendation,
)
from avo_correlate.contracts.budgets import UsageRecord
from avo_correlate.contracts.inference import StructuredInferenceContext, StructuredInferenceResult
from avo_correlate.contracts.model import ModelInvocationRecord
from avo_correlate.domain.advisory import AdvisoryReviewValidationError
from scripts.run_advisory_review import InvocationEvidenceRecorder, inference_parameters

DIGEST = "sha256:" + ("a" * 64)


def context() -> StructuredInferenceContext:
    return StructuredInferenceContext(
        run_id="run-1",
        session_id="session-1",
        activity_id="activity-1",
        operation_id="advisory_patch_review",
        operation_version="1",
    )


def output(
    candidate_id: str = "candidate-1", evidence_refs: list[str] | None = None
) -> AdvisoryPatchReview:
    from avo_correlate.contracts.advisory import AdvisoryFinding

    findings: list[AdvisoryFinding] = []
    if evidence_refs is not None:
        findings.append(
            AdvisoryFinding(
                category=AdvisoryFindingCategory.CORRECTNESS,
                severity=AdvisoryFindingSeverity.MEDIUM,
                summary="A bounded observation",
                rationale="The supplied evidence supports checking this behavior.",
                evidence_refs=evidence_refs,
            )
        )
    return AdvisoryPatchReview(
        candidate_id=candidate_id,
        recommendation=AdvisoryRecommendation.ACCEPT_WITH_FOLLOW_UP,
        summary="The patch is reviewable.",
        rationale="The bounded evidence is sufficient for advisory feedback.",
        findings=findings,
        confidence_micros=800_000,
    )


class FakeInferencer:
    def __init__(self, review: AdvisoryPatchReview) -> None:
        self.review = review
        self.calls = 0
        self.inputs: list[AdvisoryPatchReviewInput] = []

    async def infer(
        self, context: StructuredInferenceContext, input: AdvisoryPatchReviewInput
    ) -> StructuredInferenceResult[AdvisoryPatchReview]:
        self.calls += 1
        self.inputs.append(input)
        return StructuredInferenceResult(
            output=self.review,
            usage=UsageRecord.zero(),
            invocation_id="invocation-1",
            provider_request_id="request-1",
            provider_model_revision="openai/gpt-5.6-luna-2026-08-01",
            finish_reason="stop",
            output_artifact_digest=DIGEST,
        )


def run(service: AdvisoryReviewService, **kwargs: Any) -> Any:
    return asyncio.run(service.review(context(), **kwargs))


def test_success_calls_inference_once_and_persists_canonical_bundle() -> None:
    artifacts: dict[str, bytes] = {}

    def sink(payload: bytes, role: str) -> str:
        digest = f"sha256:{hashlib.sha256(payload).hexdigest()}"
        artifacts[role] = payload
        return digest

    inferencer = FakeInferencer(output(evidence_refs=["patch"]))
    service = AdvisoryReviewService(inferencer, sink)
    execution = run(
        service,
        candidate_id="candidate-1",
        objective="Review this patch",
        patch="diff --git a/a.py b/a.py\n",
        changed_paths=["src/a.py"],
        evidence_catalog=[
            AdvisoryEvidenceItem(evidence_id="patch", content_digest=DIGEST, label="patch")
        ],
    )
    assert inferencer.calls == 1
    assert inferencer.inputs[0].candidate_id == "candidate-1"
    assert execution.bundle_digest == f"sha256:{hashlib.sha256(execution.bundle_bytes).hexdigest()}"
    assert "advisory-review-bundle" in artifacts
    assert execution.inference_result.invocation_id.encode() in execution.bundle_bytes
    assert b"OPENROUTER_API_KEY" not in execution.bundle_bytes


def test_semantic_rejection_persists_bundle_and_makes_no_second_call() -> None:
    artifacts: dict[str, bytes] = {}

    def sink(payload: bytes, role: str) -> str:
        artifacts[role] = payload
        return f"sha256:{hashlib.sha256(payload).hexdigest()}"

    inferencer = FakeInferencer(output(evidence_refs=["not-in-catalog"]))
    service = AdvisoryReviewService(inferencer, sink)
    with pytest.raises(AdvisoryReviewValidationError, match="outside the catalog"):
        run(
            service,
            candidate_id="candidate-1",
            objective="Review this patch",
            patch="diff",
            changed_paths=["src/a.py"],
        )
    assert inferencer.calls == 1
    assert b"semantic_error" in artifacts["advisory-review-bundle"]


def test_bundle_contains_input_and_result_linkage_but_not_secret_text() -> None:
    artifacts: dict[str, bytes] = {}

    def sink(payload: bytes, role: str) -> str:
        artifacts[role] = payload
        return f"sha256:{hashlib.sha256(payload).hexdigest()}"

    service = AdvisoryReviewService(FakeInferencer(output()), sink)
    run(
        service,
        candidate_id="candidate-1",
        objective="Keep provider credentials out of evidence bundles",
        patch="diff",
        changed_paths=["src/a.py"],
    )
    bundle = artifacts["advisory-review-bundle"]
    assert b"candidate-1" in bundle
    assert b"invocation-1" in bundle
    assert b"OPENROUTER_API_KEY" not in bundle


def test_cli_uses_nested_reasoning_effort_wire_parameters() -> None:
    assert inference_parameters("medium", 2048) == {
        "reasoning": {"effort": "medium"},
        "max_tokens": 2048,
    }


def test_cli_invocation_recorder_persists_exactly_one_matching_record() -> None:
    stored: dict[str, bytes] = {}

    def sink(payload: bytes, role: str) -> str:
        stored[role] = payload
        return f"sha256:{hashlib.sha256(payload).hexdigest()}"

    now = datetime.now(UTC)
    record = ModelInvocationRecord(
        invocation_id="invocation-1",
        activity_id="activity-1",
        session_id="session-1",
        provider="openrouter",
        endpoint_class="openai_chat_completions_structured",
        requested_model="openai/gpt-5.6-luna",
        system_artifact_digest=DIGEST,
        developer_artifact_digest=DIGEST,
        user_artifact_digest=DIGEST,
        tool_schema_digest=DIGEST,
        parameters=inference_parameters("medium", 2048),
        usage=UsageRecord.zero(),
        request_artifact_digest=DIGEST,
        cost_source="price_table",
        started_at=now,
        completed_at=now,
    )
    recorder = InvocationEvidenceRecorder("run-1", sink)
    recorder("run-1", record)
    assert len(recorder.records) == 1
    assert recorder.require_one("invocation-1").startswith("sha256:")
    assert "model-invocation-record" in stored
    with pytest.raises(ValueError, match="does not match"):
        recorder.require_one("another-invocation")
    with pytest.raises(ValueError, match="run"):
        recorder("other-run", record)
