import asyncio

from avo_correlate.adapters.harness.native import NativeAgentHarness
from avo_correlate.adapters.model.recorded import RecordedModelGateway
from avo_correlate.contracts.agent import AgentObservation, AgentTurn
from avo_correlate.contracts.budgets import UsageRecord
from avo_correlate.contracts.variation import CandidateRef, VariationSessionRequest
from tests.conftest import DIGEST_A, DIGEST_B, component


class FakeTools:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object], str]] = []

    async def invoke(
        self, tool_id: str, arguments: dict[str, object], *, capability_token: str
    ) -> AgentObservation:
        self.calls.append((tool_id, arguments, capability_token))
        return AgentObservation(
            tool_id=tool_id,
            outcome="succeeded",
            result_digest=DIGEST_B,
            summary="development evaluator passed",
        )


def request() -> VariationSessionRequest:
    return VariationSessionRequest(
        session_id="session-1",
        run_id="run-1",
        champion=CandidateRef(
            candidate_id="seed-1", source_tree_digest=DIGEST_A, lineage_sequence=0
        ),
        lineage_index_digest=DIGEST_A,
        initial_context_digest=DIGEST_B,
        tool_capability_token="signed-token",
        development_evaluator_refs=[component("development")],
        budget_reservation_id="reservation-1",
        random_seed=1,
    )


def test_native_harness_runs_multiple_agentic_turns_then_proposes() -> None:
    model_usage = UsageRecord.zero().model_copy(
        update={"model_input_tokens": 10, "model_output_tokens": 5}
    )
    gateway = RecordedModelGateway(
        [
            AgentTurn(
                action="tool",
                rationale="test the working hypothesis",
                tool_id="run_development_evaluator",
                arguments={"suite": "development"},
                usage=model_usage,
            ),
            AgentTurn(
                action="propose",
                rationale="the bounded change passes development evaluation",
                proposed_workspace_digest=DIGEST_B,
                proposed_patch_digest=DIGEST_A,
                usage=model_usage,
            ),
        ]
    )
    tools = FakeTools()
    result = asyncio.run(NativeAgentHarness(gateway, tools, max_turns=4).run_session(request()))
    assert result.outcome == "proposal_ready"
    assert result.proposed_workspace_digest == DIGEST_B
    assert result.usage.variation_sessions == 1
    assert result.usage.model_input_tokens == 20
    assert result.usage.tool_calls == 1
    assert tools.calls == [
        ("run_development_evaluator", {"suite": "development"}, "signed-token")
    ]
    assert len(gateway.contexts) == 2
    assert len(gateway.contexts[1].observations) == 1
