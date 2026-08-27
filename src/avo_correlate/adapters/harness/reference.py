"""Executable deterministic reference harness used by the end-to-end fixture."""

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from avo_correlate.adapters.tools.workspace import WorkspaceToolBroker
from avo_correlate.contracts.agent import AgentContext, AgentObservation, AgentTurn
from avo_correlate.contracts.budgets import UsageRecord
from avo_correlate.domain.canonical import canonical_digest, source_tree_digest


class ReferenceModelGateway:
    """A recorded hypothesis/edit/test/propose sequence with dynamic evidence wiring."""

    def __init__(self, patch_digest: str) -> None:
        self._patch_digest = patch_digest

    async def next_turn(self, context: AgentContext) -> AgentTurn:
        usage = UsageRecord.zero().model_copy(
            update={"model_input_tokens": 100, "model_output_tokens": 50}
        )
        if context.turn_number == 1:
            return AgentTurn(
                action="tool",
                rationale="inspect the bounded target before editing",
                tool_id="read_file",
                arguments={"path": "src/reference_target/optimizer.py"},
                usage=usage,
            )
        if context.turn_number == 2:
            return AgentTurn(
                action="tool",
                rationale="apply the sliding-window hypothesis",
                tool_id="apply_patch",
                arguments={"patch_id": "successful"},
                usage=usage,
            )
        if context.turn_number == 3:
            return AgentTurn(
                action="tool",
                rationale="verify the working revision against development cases",
                tool_id="run_development_evaluator",
                arguments={"evaluator_id": "reference-development"},
                usage=usage,
            )
        if not context.observations:
            return AgentTurn(
                action="stop",
                rationale="no development evidence is available",
                stop_reason="failed",
                usage=usage,
            )
        return AgentTurn(
            action="propose",
            rationale="the patch passes development evaluation and is ready to freeze",
            proposed_workspace_digest=context.observations[-1].result_digest,
            proposed_patch_digest=self._patch_digest,
            usage=usage,
        )


class ReferenceToolDispatcher:
    def __init__(
        self,
        broker: WorkspaceToolBroker,
        workspace: Path,
        *,
        patches: dict[str, bytes],
        development_evaluator: Callable[[], bool],
    ) -> None:
        self._broker = broker
        self._workspace = workspace
        self._patches = patches
        self._development_evaluator = development_evaluator
        self.observations: list[AgentObservation] = []
        self.started_at = datetime.now(UTC)

    async def invoke(
        self, tool_id: str, arguments: dict[str, object], *, capability_token: str
    ) -> AgentObservation:
        if tool_id == "read_file":
            value = self._broker.read_file(capability_token, str(arguments["path"]))
            observation = AgentObservation(
                tool_id=tool_id,
                outcome="succeeded",
                result_digest=canonical_digest({"bytes": value.hex()}),
                summary="target source inspected within byte limit",
            )
        elif tool_id == "apply_patch":
            patch = self._patches[str(arguments["patch_id"])]
            self._broker.apply_patch(capability_token, patch)
            observation = AgentObservation(
                tool_id=tool_id,
                outcome="succeeded",
                result_digest=source_tree_digest(self._workspace),
                summary="validated patch applied and workspace rescanned",
            )
        elif tool_id == "run_development_evaluator":
            passed = bool(self._development_evaluator())
            observation = AgentObservation(
                tool_id=tool_id,
                outcome="succeeded" if passed else "failed",
                result_digest=source_tree_digest(self._workspace),
                summary=(
                    "development evaluator passed"
                    if passed
                    else "development evaluator failed"
                ),
            )
        else:
            raise ValueError(f"unsupported reference tool: {tool_id}")
        self.observations.append(observation)
        return observation
