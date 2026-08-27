"""Complete lineage export and evidence-integrity verification."""

import json
from typing import Any, cast

from sqlalchemy import select

from avo_correlate.adapters.persistence.database import Database
from avo_correlate.adapters.persistence.models import (
    AdmissionRow,
    BudgetLedgerRow,
    CandidateRow,
    EvaluationRow,
    EventRow,
    ExperimentRow,
    HarnessInvocationRow,
    LineageRow,
    ModelInvocationRow,
    PolicyDecisionRow,
    ReconciliationCaseRow,
    ReviewDecisionRow,
    ReviewRequestRow,
    RunRow,
    ToolInvocationRow,
    VariationSessionRow,
)
from avo_correlate.contracts.provenance import ProvenanceExport, VerificationReport
from avo_correlate.domain.canonical import canonical_digest


class ProvenanceService:
    def __init__(self, database: Database) -> None:
        self._database = database

    def export_run(self, run_id: str) -> ProvenanceExport:
        with self._database.session() as session:
            run = session.get(RunRow, run_id)
            if run is None:
                raise LookupError(f"run not found: {run_id}")
            experiment = session.get(ExperimentRow, run.experiment_id)
            budget = session.get(BudgetLedgerRow, run_id)
            if experiment is None or budget is None:
                raise LookupError("run envelope is incomplete")
            manifest: dict[str, Any] = {
                "schema_version": 1,
                "run": {
                    "run_id": run.run_id,
                    "experiment_id": run.experiment_id,
                    "state": run.state,
                    "revision": run.revision,
                    "event_sequence": run.event_sequence,
                    "champion_id": run.champion_id,
                },
                "experiment": {
                    "spec_digest": experiment.spec_digest,
                    "spec": _load(experiment.spec_json),
                },
                "budget": {
                    "limit": _load(budget.limit_json),
                    "used": _load(budget.used_json),
                    "reserved": _load(budget.reserved_json),
                    "revision": budget.revision,
                },
                "events": [
                    {
                        "event_id": item.event_id,
                        "sequence": item.sequence,
                        "event_type": item.event_type,
                        "actor_id": item.actor_id,
                        "payload": _load(item.payload_json),
                        "created_at": item.created_at.isoformat(),
                    }
                    for item in session.scalars(
                        select(EventRow)
                        .where(EventRow.run_id == run_id)
                        .order_by(EventRow.sequence)
                    )
                ],
                "lineage": [
                    {
                        "sequence": item.sequence,
                        "candidate_id": item.candidate_id,
                        "source_tree_digest": item.source_tree_digest,
                        "admission_id": item.admission_id,
                        "committed_at": item.committed_at.isoformat(),
                    }
                    for item in session.scalars(
                        select(LineageRow)
                        .where(LineageRow.run_id == run_id)
                        .order_by(LineageRow.sequence)
                    )
                ],
                "sessions": self._records(session, VariationSessionRow, run_id),
                "candidates": self._records(session, CandidateRow, run_id),
                "evaluations": self._candidate_records(session, EvaluationRow, run_id),
                "policy_decisions": self._records(session, PolicyDecisionRow, run_id),
                "admissions": self._records(session, AdmissionRow, run_id),
                "tool_invocations": self._records(session, ToolInvocationRow, run_id),
                "model_invocations": self._records(session, ModelInvocationRow, run_id),
                "harness_invocations": self._records(
                    session, HarnessInvocationRow, run_id
                ),
                "reconciliations": self._records(
                    session, ReconciliationCaseRow, run_id
                ),
                "reviews": [
                    {
                        "review_id": review.review_id,
                        "candidate_id": review.candidate_id,
                        "action": review.action,
                        "state": review.state,
                        "approvals_required": review.approvals_required,
                        "expires_at": review.expires_at.isoformat(),
                        "decisions": [
                            _load(item.decision_json)
                            for item in session.scalars(
                                select(ReviewDecisionRow).where(
                                    ReviewDecisionRow.review_id == review.review_id
                                )
                            )
                        ],
                    }
                    for review in session.scalars(
                        select(ReviewRequestRow).where(ReviewRequestRow.run_id == run_id)
                    )
                ],
            }
        return ProvenanceExport(
            run_id=run_id,
            manifest=manifest,
            manifest_digest=canonical_digest(manifest),
        )

    def verify(self, exported: ProvenanceExport) -> VerificationReport:
        checks = [
            "manifest_digest",
            "event_sequence",
            "lineage_sequence",
            "champion",
            "terminal_reconciliation",
        ]
        errors: list[str] = []
        if canonical_digest(exported.manifest) != exported.manifest_digest:
            errors.append("manifest_digest_mismatch")
        events = cast(list[dict[str, Any]], exported.manifest.get("events", []))
        event_numbers = [cast(int, item.get("sequence")) for item in events]
        if event_numbers != list(range(1, len(event_numbers) + 1)):
            errors.append("event_sequence_gap")
        lineage = cast(list[dict[str, Any]], exported.manifest.get("lineage", []))
        lineage_numbers = [cast(int, item.get("sequence")) for item in lineage]
        if lineage_numbers != list(range(len(lineage_numbers))):
            errors.append("lineage_sequence_gap")
        run = cast(dict[str, Any], exported.manifest.get("run", {}))
        if not lineage or run.get("champion_id") != lineage[-1].get("candidate_id"):
            errors.append("champion_lineage_mismatch")
        reconciliations = cast(
            list[dict[str, Any]], exported.manifest.get("reconciliations", [])
        )
        if run.get("state") in {"completed", "cancelled", "failed"} and any(
            item.get("state") == "open" for item in reconciliations
        ):
            errors.append("terminal_run_has_open_reconciliation")
        return VerificationReport(verified=not errors, checks=checks, errors=errors)

    @staticmethod
    def _records(session: Any, row_type: Any, run_id: str) -> list[dict[str, Any]]:
        rows = session.scalars(select(row_type).where(row_type.run_id == run_id))
        records: list[dict[str, Any]] = []
        for item in rows:
            if hasattr(item, "record_json"):
                record = _load(cast(str, item.record_json))
                record["record_digest"] = cast(str, item.record_digest)
            elif hasattr(item, "decision_json"):
                record = _load(cast(str, item.decision_json))
                record["decision_digest"] = cast(str, item.decision_digest)
            elif isinstance(item, VariationSessionRow):
                record = {
                    "session_id": item.session_id,
                    "state": item.state,
                    "request": _load(item.request_json),
                    "result": None if item.result_json is None else _load(item.result_json),
                }
            elif isinstance(item, CandidateRow):
                record = _load(item.manifest_json)
                record["manifest_digest"] = item.manifest_digest
                record["state"] = item.state
            else:
                continue
            records.append(record)
        return records

    @staticmethod
    def _candidate_records(session: Any, row_type: Any, run_id: str) -> list[dict[str, Any]]:
        rows = session.scalars(
            select(row_type)
            .join(CandidateRow, row_type.candidate_id == CandidateRow.candidate_id)
            .where(CandidateRow.run_id == run_id)
        )
        records: list[dict[str, Any]] = []
        for item in rows:
            record = _load(cast(str, item.record_json))
            record["record_digest"] = cast(str, item.record_digest)
            records.append(record)
        return records


def _load(payload: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(payload))
