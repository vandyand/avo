"""Run one explicit OpenRouter strict-JSON advisory patch review.

The command is intentionally standalone and has no campaign or admission side
effects. It stores all adapter and review evidence below ``--output-dir``.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, cast

from avo_correlate.adapters.model.openrouter import OpenRouterStructuredInference
from avo_correlate.application.advisory_review import (
    AdvisoryReviewService,
    filesystem_artifact_sink,
)
from avo_correlate.contracts.advisory import (
    AdvisoryEvaluationSummary,
    AdvisoryEvidenceItem,
    AdvisoryPatchReview,
    AdvisoryPatchReviewInput,
)
from avo_correlate.contracts.base import StrictModel
from avo_correlate.contracts.inference import StructuredInferenceContext
from avo_correlate.contracts.model import ModelInvocationRecord
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

DEFAULT_MODEL = "openai/gpt-5.6-luna"
DEFAULT_REASONING_EFFORT = "medium"
MAX_TOKENS = 16_384


def inference_parameters(reasoning_effort: str, max_tokens: int) -> dict[str, Any]:
    """Return the OpenAI-compatible reasoning and output-limit parameters."""

    return {"reasoning": {"effort": reasoning_effort}, "max_tokens": max_tokens}


class InvocationEvidenceRecorder:
    """Persist and retain the single invocation record for one CLI run."""

    def __init__(self, run_id: str, artifact_sink: Any) -> None:
        self._run_id = run_id
        self._artifact_sink = artifact_sink
        self.records: list[tuple[ModelInvocationRecord, str]] = []

    def __call__(self, run_id: str, record: ModelInvocationRecord) -> None:
        if run_id != self._run_id:
            raise ValueError("invocation record run does not match CLI context")
        payload = canonical_bytes(record)
        digest = self._artifact_sink(payload, "model-invocation-record")
        if digest != canonical_digest(record):
            raise ValueError("invocation evidence sink returned the wrong digest")
        self.records.append((record, digest))

    def require_one(self, invocation_id: str) -> str:
        if len(self.records) != 1:
            raise ValueError("advisory review must retain exactly one invocation record")
        record, digest = self.records[0]
        if record.invocation_id != invocation_id:
            raise ValueError("invocation record does not match structured result")
        return digest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--objective", required=True)
    parser.add_argument("--patch", required=True, help="Patch text or path to a patch file")
    parser.add_argument("--changed-paths", nargs="+", required=True)
    parser.add_argument(
        "--evidence-json",
        type=Path,
        help="JSON file containing evidence_catalog and optional evaluation_summaries",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--reasoning-effort", default=DEFAULT_REASONING_EFFORT)
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--activity-id", required=True)
    parser.add_argument("--operation-id", default="advisory_patch_review")
    parser.add_argument("--operation-version", default="1")
    return parser


def _read_patch(value: str) -> str:
    path = Path(value)
    return path.read_text(encoding="utf-8") if path.is_file() else value


def _read_evidence(
    path: Path | None,
) -> tuple[list[AdvisoryEvaluationSummary], list[AdvisoryEvidenceItem]]:
    if path is None:
        return [], []
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("evidence JSON must be an object")
    typed = cast(dict[str, Any], document)
    evaluations = [
        AdvisoryEvaluationSummary.model_validate(item)
        for item in typed.get("evaluation_summaries", [])
    ]
    evidence = [
        AdvisoryEvidenceItem.model_validate(item) for item in typed.get("evidence_catalog", [])
    ]
    return evaluations, evidence


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    if args.max_tokens < 1 or args.max_tokens > MAX_TOKENS:
        raise ValueError(f"--max-tokens must be between 1 and {MAX_TOKENS}")
    if args.reasoning_effort not in {"low", "medium", "high"}:
        raise ValueError("--reasoning-effort must be low, medium, or high")
    evaluations, evidence = _read_evidence(args.evidence_json)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    sink = filesystem_artifact_sink(args.output_dir / "artifacts")
    invocation_recorder = InvocationEvidenceRecorder(args.run_id, sink)
    inferencer = OpenRouterStructuredInference(
        model=args.model,
        system_prompt=(
            "You are an advisory code reviewer. Return only the requested strict JSON. "
            "Your recommendation is informational and cannot authorize changes."
        ),
        developer_prompt=(
            "Review the supplied bounded candidate patch against its objective and evidence. "
            "Cite only evidence IDs in the input catalog. Do not invent evidence."
        ),
        parameters=inference_parameters(args.reasoning_effort, args.max_tokens),
        input_model=cast(type[StrictModel], AdvisoryPatchReviewInput),
        output_model=cast(type[StrictModel], AdvisoryPatchReview),
        schema_name="AdvisoryPatchReview",
        artifact_sink=sink,
        invocation_sink=invocation_recorder,
    )
    service = AdvisoryReviewService(cast(Any, inferencer), sink)
    context = StructuredInferenceContext(
        run_id=args.run_id,
        session_id=args.session_id,
        activity_id=args.activity_id,
        operation_id=args.operation_id,
        operation_version=args.operation_version,
    )
    execution = await service.review(
        context,
        candidate_id=args.candidate_id,
        objective=args.objective,
        patch=_read_patch(args.patch),
        changed_paths=args.changed_paths,
        evaluation_summaries=evaluations,
        evidence_catalog=evidence,
    )
    invocation_record_digest = invocation_recorder.require_one(
        execution.inference_result.invocation_id
    )
    result_document = {
        "schema_version": 1,
        "manifest_type": "advisory_review_result",
        "bundle_digest": execution.bundle_digest,
        "input_digest": execution.input_digest,
        "invocation_id": execution.inference_result.invocation_id,
        "invocation_record_digest": invocation_record_digest,
        "review": execution.review.model_dump(mode="json"),
    }
    result_manifest_bytes = canonical_bytes(result_document)
    result_manifest_digest = sink(result_manifest_bytes, "advisory-review-result")
    if result_manifest_digest != canonical_digest(result_document):
        raise ValueError("result manifest sink returned the wrong digest")
    result = {
        "schema_version": 1,
        "bundle_digest": execution.bundle_digest,
        "input_digest": execution.input_digest,
        "invocation_id": execution.inference_result.invocation_id,
        "invocation_record_digest": invocation_record_digest,
        "result_manifest_digest": result_manifest_digest,
        "review": execution.review.model_dump(mode="json"),
    }
    (args.output_dir / "review-result.json").write_bytes(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return result


def main() -> int:
    args = _parser().parse_args()
    try:
        result = asyncio.run(_run(args))
    except Exception as exc:  # pragma: no cover - exercised through CLI integration
        print(f"advisory review failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
