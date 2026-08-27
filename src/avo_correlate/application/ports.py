"""Stable application ports; adapters must pass shared contract suites."""

from collections.abc import AsyncIterator
from typing import Protocol, TypeVar

from avo_correlate.contracts.base import ArtifactRef, StrictModel
from avo_correlate.contracts.evaluation import EvaluationRecord
from avo_correlate.contracts.inference import (
    StructuredInferenceContext,
    StructuredInferenceResult,
)
from avo_correlate.contracts.policy import PolicyDecision, PolicyRequest
from avo_correlate.contracts.runtime import (
    AgentCompletion,
    HarnessRuntimeProfile,
    RuntimeCapabilityReport,
    RuntimeEvent,
    RuntimeInspection,
    RuntimeSessionRef,
)
from avo_correlate.contracts.variation import VariationSessionRequest, VariationSessionResult

InputT = TypeVar("InputT", contravariant=True)
OutputT = TypeVar("OutputT", bound=StrictModel)


class AgentHarness(Protocol):
    async def run_session(self, request: VariationSessionRequest) -> VariationSessionResult: ...


class StructuredInference(Protocol[InputT, OutputT]):
    """Provider-neutral port for one bounded strict-JSON operation."""

    async def infer(
        self, context: StructuredInferenceContext, input: InputT
    ) -> StructuredInferenceResult[OutputT]: ...


class CodingAgentRuntime(Protocol):
    """Provider-neutral lifecycle for long-running coding-agent sessions."""

    async def preflight(self, profile: HarnessRuntimeProfile) -> RuntimeCapabilityReport: ...

    async def prepare(
        self,
        profile: HarnessRuntimeProfile,
        request: VariationSessionRequest,
        workspace_path: str,
        *,
        invocation_id: str,
    ) -> RuntimeSessionRef: ...

    async def start_turn(
        self,
        profile: HarnessRuntimeProfile,
        request: VariationSessionRequest,
        session: RuntimeSessionRef,
    ) -> RuntimeSessionRef: ...

    def events(self, session: RuntimeSessionRef) -> AsyncIterator[RuntimeEvent]: ...

    async def wait(self, session: RuntimeSessionRef) -> AgentCompletion: ...

    async def cancel(self, session: RuntimeSessionRef) -> None: ...

    async def inspect(
        self,
        profile: HarnessRuntimeProfile,
        session: RuntimeSessionRef,
        workspace_path: str,
    ) -> RuntimeInspection: ...


class EvaluationRequest(Protocol):
    candidate_id: str


class DevelopmentEvaluator(Protocol):
    async def evaluate(self, request: EvaluationRequest) -> EvaluationRecord: ...


class AuthoritativeEvaluator(Protocol):
    async def evaluate(self, request: EvaluationRequest) -> EvaluationRecord: ...


class PolicyEngine(Protocol):
    def decide(self, request: PolicyRequest) -> PolicyDecision: ...


class PutMetadata(Protocol):
    media_type: str
    role: str
    max_bytes: int


class ArtifactStore(Protocol):
    async def put(
        self, stream: AsyncIterator[bytes], metadata: PutMetadata
    ) -> ArtifactRef: ...
