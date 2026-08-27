"""Immutable tool and model invocation provenance."""

from avo_correlate.adapters.persistence.database import Database
from avo_correlate.adapters.persistence.models import ModelInvocationRow, ToolInvocationRow
from avo_correlate.contracts.model import ModelInvocationRecord
from avo_correlate.contracts.tools import ToolInvocationRecord
from avo_correlate.domain.canonical import canonical_digest


class InvocationConflictError(RuntimeError):
    pass


class InvocationService:
    def __init__(self, database: Database) -> None:
        self._database = database

    def record_tool(self, run_id: str, record: ToolInvocationRecord) -> str:
        digest = canonical_digest(record)
        with self._database.session() as session:
            prior = session.get(ToolInvocationRow, record.invocation_id)
            if prior is not None:
                if prior.record_digest != digest:
                    raise InvocationConflictError("tool invocation has conflicting evidence")
                return digest
            session.add(
                ToolInvocationRow(
                    invocation_id=record.invocation_id,
                    run_id=run_id,
                    session_id=record.session_id,
                    record_digest=digest,
                    record_json=record.model_dump_json(),
                    created_at=record.completed_at,
                )
            )
        return digest

    def record_model(self, run_id: str, record: ModelInvocationRecord) -> str:
        digest = canonical_digest(record)
        with self._database.session() as session:
            prior = session.get(ModelInvocationRow, record.invocation_id)
            if prior is not None:
                if prior.record_digest != digest:
                    raise InvocationConflictError("model invocation has conflicting evidence")
                return digest
            session.add(
                ModelInvocationRow(
                    invocation_id=record.invocation_id,
                    run_id=run_id,
                    session_id=record.session_id,
                    record_digest=digest,
                    record_json=record.model_dump_json(),
                    created_at=record.completed_at,
                )
            )
        return digest
