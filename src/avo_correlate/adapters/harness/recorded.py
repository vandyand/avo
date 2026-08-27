"""Deterministic harness replay for tests, demos, and crash recovery."""

from dataclasses import dataclass

from avo_correlate.contracts.variation import VariationSessionRequest, VariationSessionResult
from avo_correlate.domain.canonical import canonical_digest


class RecordingMismatchError(ValueError):
    pass


@dataclass(frozen=True)
class RecordedHarnessEntry:
    request_digest: str
    result: VariationSessionResult


class RecordedHarness:
    def __init__(self, entries: list[RecordedHarnessEntry]) -> None:
        self._entries = {entry.request_digest: entry.result for entry in entries}

    async def run_session(self, request: VariationSessionRequest) -> VariationSessionResult:
        digest = canonical_digest(request)
        result = self._entries.get(digest)
        if result is None:
            raise RecordingMismatchError(f"no recording for request {digest}")
        if result.session_id != request.session_id:
            raise RecordingMismatchError("recorded result belongs to another session")
        return result
