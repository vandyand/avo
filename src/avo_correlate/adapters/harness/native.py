"""Native agentic variation loop with structured, capability-brokered actions."""

from collections.abc import Callable
from typing import Protocol

from avo_correlate.contracts.agent import AgentContext, AgentObservation, AgentTurn
from avo_correlate.contracts.budgets import UsageRecord
from avo_correlate.contracts.variation import VariationSessionRequest, VariationSessionResult
from avo_correlate.domain.canonical import canonical_digest


class StructuredModelGateway(Protocol):
    async def next_turn(self, context: AgentContext) -> AgentTurn: ...


class ToolDispatcher(Protocol):
    async def invoke(
        self, tool_id: str, arguments: dict[str, object], *, capability_token: str
    ) -> AgentObservation: ...


class NativeAgentHarness:
    def __init__(
        self,
        gateway: StructuredModelGateway,
        tools: ToolDispatcher,
        *,
        max_turns: int,
        cancelled: Callable[[], bool] | None = None,
    ) -> None:
        if max_turns <= 0:
            raise ValueError("max_turns must be positive")
        self._gateway = gateway
        self._tools = tools
        self._max_turns = max_turns
        self._cancelled = cancelled or (lambda: False)

    async def run_session(self, request: VariationSessionRequest) -> VariationSessionResult:
        observations: list[AgentObservation] = []
        usage = UsageRecord.zero().model_copy(update={"variation_sessions": 1})
        usage = UsageRecord.model_validate(usage)
        for turn_number in range(1, self._max_turns + 1):
            if self._cancelled():
                return self._result(request, "cancelled", observations, usage)
            context = AgentContext(
                run_id=request.run_id,
                session_id=request.session_id,
                champion_workspace_digest=request.champion.source_tree_digest,
                initial_context_digest=request.initial_context_digest,
                observations=observations,
                turn_number=turn_number,
                turns_remaining=self._max_turns - turn_number,
            )
            turn = await self._gateway.next_turn(context)
            usage = usage.plus(turn.usage)
            if turn.action == "tool":
                assert turn.tool_id is not None and turn.arguments is not None
                observation = await self._tools.invoke(
                    turn.tool_id,
                    turn.arguments,
                    capability_token=request.tool_capability_token,
                )
                observations.append(observation)
                usage = usage.plus(
                    UsageRecord.zero().model_copy(update={"tool_calls": 1})
                )
                continue
            if turn.action == "propose":
                return VariationSessionResult(
                    session_id=request.session_id,
                    outcome="proposal_ready",
                    proposed_workspace_digest=turn.proposed_workspace_digest,
                    proposed_patch_digest=turn.proposed_patch_digest,
                    rationale_artifact=None,
                    attempt_index_digest=canonical_digest(observations),
                    usage=usage,
                )
            assert turn.stop_reason is not None
            return self._result(request, turn.stop_reason, observations, usage)
        return self._result(request, "exhausted", observations, usage)

    @staticmethod
    def _result(
        request: VariationSessionRequest,
        outcome: str,
        observations: list[AgentObservation],
        usage: UsageRecord,
    ) -> VariationSessionResult:
        return VariationSessionResult(
            session_id=request.session_id,
            outcome=outcome,  # type: ignore[arg-type]
            proposed_workspace_digest=None,
            proposed_patch_digest=None,
            rationale_artifact=None,
            attempt_index_digest=canonical_digest(observations),
            usage=usage,
        )
