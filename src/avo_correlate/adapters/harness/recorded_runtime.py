"""Deterministic coding-agent runtime used by contract and recovery tests."""

from collections.abc import AsyncIterator
from dataclasses import dataclass

from avo_correlate.contracts.operations import CheckStatus, DoctorCheck
from avo_correlate.contracts.runtime import (
    AgentCompletion,
    HarnessRuntimeProfile,
    RuntimeCapabilityReport,
    RuntimeEvent,
    RuntimeInspection,
    RuntimeSessionRef,
)
from avo_correlate.contracts.variation import VariationSessionRequest
from avo_correlate.domain.canonical import canonical_digest


@dataclass(frozen=True)
class RecordedRuntimeEntry:
    request_digest: str
    events: tuple[RuntimeEvent, ...]
    completion: AgentCompletion


class RecordedCodingAgentRuntime:
    adapter_id = "recorded-runtime-v1"
    adapter_version = "1.0.0"
    runtime_version = "recorded-v1"

    def __init__(self, entries: list[RecordedRuntimeEntry]) -> None:
        self._entries = {entry.request_digest: entry for entry in entries}
        self._sessions: dict[str, RecordedRuntimeEntry] = {}
        self._session_refs: dict[str, RuntimeSessionRef] = {}
        self._cancelled: set[str] = set()
        self._completed: set[str] = set()

    async def preflight(self, profile: HarnessRuntimeProfile) -> RuntimeCapabilityReport:
        return RuntimeCapabilityReport(
            profile_digest=canonical_digest(profile),
            compatible=True,
            checks=[
                DoctorCheck(
                    name="recording",
                    status=CheckStatus.PASS,
                    detail="deterministic runtime recording is available",
                )
            ],
        )

    async def prepare(
        self,
        profile: HarnessRuntimeProfile,
        request: VariationSessionRequest,
        workspace_path: str,
        *,
        invocation_id: str,
    ) -> RuntimeSessionRef:
        del profile, workspace_path
        digest = canonical_digest(request)
        entry = self._entries.get(digest)
        if entry is None:
            raise LookupError(f"no runtime recording for {digest}")
        native_id = f"recorded:{request.session_id}"
        self._sessions[native_id] = entry
        reference = RuntimeSessionRef(
            adapter_id=self.adapter_id,
            native_session_id=native_id,
            invocation_id=invocation_id,
            storage_class="memory",
            checkpoint=0,
        )
        self._session_refs[native_id] = reference
        return reference

    async def start_turn(
        self,
        profile: HarnessRuntimeProfile,
        request: VariationSessionRequest,
        session: RuntimeSessionRef,
    ) -> RuntimeSessionRef:
        del profile, request
        self._entry(session)
        reference = session.model_copy(update={"native_operation_id": "recorded-turn-1"})
        self._session_refs[session.native_session_id] = reference
        return reference

    async def start(
        self,
        profile: HarnessRuntimeProfile,
        request: VariationSessionRequest,
        workspace_path: str,
    ) -> RuntimeSessionRef:
        """Compatibility wrapper for bounded benchmark callers."""
        prepared = await self.prepare(
            profile,
            request,
            workspace_path,
            invocation_id=f"recorded:{request.session_id}",
        )
        return await self.start_turn(profile, request, prepared)

    async def events(self, session: RuntimeSessionRef) -> AsyncIterator[RuntimeEvent]:
        entry = self._entry(session)
        for event in entry.events:
            if session.native_session_id in self._cancelled:
                return
            yield event

    async def wait(self, session: RuntimeSessionRef) -> AgentCompletion:
        if session.native_session_id in self._cancelled:
            return AgentCompletion(outcome="stop", rationale="cancelled")
        self._completed.add(session.native_session_id)
        return self._entry(session).completion

    async def cancel(self, session: RuntimeSessionRef) -> None:
        self._entry(session)
        self._cancelled.add(session.native_session_id)

    async def recover(self, native_session_id: str) -> RuntimeSessionRef | None:
        if native_session_id not in self._sessions:
            return None
        return self._session_refs[native_session_id]

    async def inspect(
        self,
        profile: HarnessRuntimeProfile,
        session: RuntimeSessionRef,
        workspace_path: str,
    ) -> RuntimeInspection:
        del profile, workspace_path
        if session.native_session_id not in self._sessions:
            return RuntimeInspection(state="missing", session=session)
        if session.native_operation_id is None:
            return RuntimeInspection(state="not_started", session=session)
        if session.native_session_id in self._cancelled:
            return RuntimeInspection(state="interrupted", session=session)
        if session.native_session_id not in self._completed:
            return RuntimeInspection(state="running", session=session)
        return RuntimeInspection(
            state="completed",
            session=session,
            completion=self._entry(session).completion,
        )

    def _entry(self, session: RuntimeSessionRef) -> RecordedRuntimeEntry:
        if session.adapter_id != self.adapter_id:
            raise ValueError("session belongs to another adapter")
        try:
            return self._sessions[session.native_session_id]
        except KeyError as exc:
            raise LookupError("recorded session is unknown") from exc
