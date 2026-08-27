from datetime import UTC, datetime
from pathlib import Path

import pytest

from avo_correlate.adapters.persistence import Database
from avo_correlate.application.invocation_service import (
    InvocationConflictError,
    InvocationService,
)
from avo_correlate.application.run_service import RunService
from avo_correlate.application.session_service import SessionService
from avo_correlate.contracts.budgets import UsageRecord
from avo_correlate.contracts.model import ModelInvocationRecord
from avo_correlate.contracts.tools import ToolInvocationRecord
from avo_correlate.contracts.variation import CandidateRef, VariationSessionRequest
from tests.conftest import DIGEST_A, DIGEST_B, component, experiment_spec


def _service_with_session(tmp_path: Path) -> InvocationService:
    database = Database(tmp_path / "state.db")
    database.initialize()
    runs = RunService(database)
    runs.create_experiment(experiment_spec())
    runs.create_run("experiment-1", actor_id="tester", run_id="run-1")
    champion = runs.get_run("run-1").champion_id
    assert champion is not None
    SessionService(database).enqueue(
        VariationSessionRequest(
            session_id="session-1",
            run_id="run-1",
            champion=CandidateRef(
                candidate_id=champion,
                source_tree_digest=DIGEST_A,
                lineage_sequence=0,
            ),
            lineage_index_digest=DIGEST_A,
            initial_context_digest=DIGEST_B,
            tool_capability_token="signed-capability",
            development_evaluator_refs=[component("development")],
            budget_reservation_id="reservation-1",
            random_seed=7,
        )
    )
    return InvocationService(database)


def test_tool_and_model_invocation_evidence_is_idempotent_and_immutable(tmp_path: Path) -> None:
    service = _service_with_session(tmp_path)
    now = datetime.now(UTC)
    usage = UsageRecord.zero().model_copy(update={"tool_calls": 1})
    tool = ToolInvocationRecord(
        invocation_id="tool-1",
        activity_id="activity-1",
        session_id="session-1",
        actor_id="harness",
        tool_id="read_file",
        tool_version="1.0.0",
        arguments_digest=DIGEST_A,
        policy_decision_id="policy-1",
        outcome="succeeded",
        output_artifact_digests=[DIGEST_B],
        input_bytes=10,
        output_bytes=20,
        usage=usage,
        redaction_profile="default",
        started_at=now,
        completed_at=now,
    )
    tool_digest = service.record_tool("run-1", tool)
    assert service.record_tool("run-1", tool) == tool_digest
    with pytest.raises(InvocationConflictError, match="tool invocation"):
        service.record_tool("run-1", tool.model_copy(update={"outcome": "failed"}))

    model = ModelInvocationRecord(
        invocation_id="model-1",
        activity_id="activity-1",
        session_id="session-1",
        provider="recorded",
        endpoint_class="structured",
        requested_model="reference-model",
        system_artifact_digest=DIGEST_A,
        developer_artifact_digest=DIGEST_A,
        user_artifact_digest=DIGEST_A,
        tool_schema_digest=DIGEST_B,
        usage=UsageRecord.zero().model_copy(
            update={"model_input_tokens": 5, "model_output_tokens": 2}
        ),
        request_artifact_digest=DIGEST_A,
        response_artifact_digest=DIGEST_B,
        cost_source="provider",
        started_at=now,
        completed_at=now,
    )
    model_digest = service.record_model("run-1", model)
    assert service.record_model("run-1", model) == model_digest
    with pytest.raises(InvocationConflictError, match="model invocation"):
        service.record_model(
            "run-1", model.model_copy(update={"finish_reason": "different"})
        )
