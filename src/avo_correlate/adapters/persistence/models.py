"""Relational persistence models for the local durable runtime."""

from datetime import datetime

from sqlalchemy import ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ExperimentRow(Base):
    __tablename__ = "experiments"

    experiment_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    spec_digest: Mapped[str] = mapped_column(String(71), unique=True, nullable=False)
    spec_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)


class RunRow(Base):
    __tablename__ = "runs"

    run_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    experiment_id: Mapped[str] = mapped_column(
        ForeignKey("experiments.experiment_id"), nullable=False
    )
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    event_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    champion_id: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    updated_at: Mapped[datetime] = mapped_column(nullable=False)


class EventRow(Base):
    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint("run_id", "sequence", name="uq_events_run_sequence"),
        Index("ix_events_run_sequence", "run_id", "sequence"),
    )

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)


class OutboxRow(Base):
    __tablename__ = "outbox"

    outbox_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("events.event_id"), unique=True, nullable=False
    )
    topic: Mapped[str] = mapped_column(String(128), nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    published_at: Mapped[datetime | None] = mapped_column()


class BudgetLedgerRow(Base):
    __tablename__ = "budget_ledgers"

    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), primary_key=True)
    limit_json: Mapped[str] = mapped_column(Text, nullable=False)
    used_json: Mapped[str] = mapped_column(Text, nullable=False)
    reserved_json: Mapped[str] = mapped_column(Text, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class BudgetReservationRow(Base):
    __tablename__ = "budget_reservations"
    __table_args__ = (
        UniqueConstraint("run_id", "activity_key", name="uq_budget_run_activity"),
    )

    reservation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), nullable=False)
    activity_key: Mapped[str] = mapped_column(String(256), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    estimated_json: Mapped[str] = mapped_column(Text, nullable=False)
    actual_json: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    reconciled_at: Mapped[datetime | None] = mapped_column()


class ActivityRow(Base):
    __tablename__ = "activities"
    __table_args__ = (UniqueConstraint("run_id", "activity_key", name="uq_activity_key"),)

    activity_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), nullable=False)
    session_id: Mapped[str | None] = mapped_column(
        ForeignKey("variation_sessions.session_id")
    )
    budget_reservation_id: Mapped[str | None] = mapped_column(
        ForeignKey("budget_reservations.reservation_id")
    )
    activity_key: Mapped[str] = mapped_column(String(256), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lease_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lease_owner: Mapped[str | None] = mapped_column(String(256))
    lease_expires_at: Mapped[datetime | None] = mapped_column()
    input_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    result_digest: Mapped[str | None] = mapped_column(String(71))
    error_json: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    updated_at: Mapped[datetime] = mapped_column(nullable=False)


class ArtifactMetadataRow(Base):
    __tablename__ = "artifact_metadata"

    digest: Mapped[str] = mapped_column(String(71), primary_key=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    media_type: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    verified_at: Mapped[datetime] = mapped_column(nullable=False)


class IdempotencyRow(Base):
    __tablename__ = "idempotency_keys"
    __table_args__ = (
        UniqueConstraint(
            "actor_id", "endpoint_scope", "idempotency_key", name="uq_idempotency_scope"
        ),
    )

    record_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False)
    endpoint_scope: Mapped[str] = mapped_column(String(256), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(256), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)


class VariationSessionRow(Base):
    __tablename__ = "variation_sessions"
    __table_args__ = (
        UniqueConstraint("run_id", "session_number", name="uq_session_run_number"),
    )

    session_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), nullable=False)
    session_number: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    request_json: Mapped[str] = mapped_column(Text, nullable=False)
    result_json: Mapped[str | None] = mapped_column(Text)
    usage_json: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    updated_at: Mapped[datetime] = mapped_column(nullable=False)


class AttemptRow(Base):
    __tablename__ = "variation_attempts"
    __table_args__ = (
        UniqueConstraint("session_id", "attempt_number", name="uq_attempt_session_number"),
    )

    attempt_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("variation_sessions.session_id"), nullable=False
    )
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    record_json: Mapped[str] = mapped_column(Text, nullable=False)
    record_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)


class CandidateRow(Base):
    __tablename__ = "candidates"
    __table_args__ = (
        UniqueConstraint("run_id", "source_tree_digest", name="uq_candidate_run_tree"),
    )

    candidate_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), nullable=False)
    session_id: Mapped[str | None] = mapped_column(
        ForeignKey("variation_sessions.session_id")
    )
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    source_tree_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    manifest_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    manifest_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)


class EvaluationRow(Base):
    __tablename__ = "evaluations"
    __table_args__ = (
        UniqueConstraint("candidate_id", "evaluator_key", name="uq_evaluation_activity"),
    )

    evaluation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    candidate_id: Mapped[str] = mapped_column(
        ForeignKey("candidates.candidate_id"), nullable=False
    )
    evaluator_key: Mapped[str] = mapped_column(String(256), nullable=False)
    tier: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    record_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    record_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)


class PolicyDecisionRow(Base):
    __tablename__ = "policy_decisions"

    decision_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), nullable=False)
    candidate_id: Mapped[str | None] = mapped_column(ForeignKey("candidates.candidate_id"))
    decision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    decision_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)


class AdmissionRow(Base):
    __tablename__ = "admissions"
    __table_args__ = (
        Index(
            "uq_admission_success_candidate",
            "candidate_id",
            unique=True,
            sqlite_where=text("outcome = 'admit'"),
        ),
    )

    admission_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), nullable=False)
    candidate_id: Mapped[str] = mapped_column(
        ForeignKey("candidates.candidate_id"), nullable=False
    )
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    decision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    decision_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)


class LineageRow(Base):
    __tablename__ = "lineage"
    __table_args__ = (
        UniqueConstraint("run_id", "sequence", name="uq_lineage_run_sequence"),
        UniqueConstraint("run_id", "candidate_id", name="uq_lineage_run_candidate"),
        UniqueConstraint("run_id", "source_tree_digest", name="uq_lineage_run_tree"),
    )

    lineage_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    candidate_id: Mapped[str] = mapped_column(
        ForeignKey("candidates.candidate_id"), nullable=False
    )
    source_tree_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    admission_id: Mapped[str | None] = mapped_column(ForeignKey("admissions.admission_id"))
    committed_at: Mapped[datetime] = mapped_column(nullable=False)


class ToolInvocationRow(Base):
    __tablename__ = "tool_invocations"

    invocation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), nullable=False)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("variation_sessions.session_id"), nullable=False
    )
    record_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    record_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)


class ModelInvocationRow(Base):
    __tablename__ = "model_invocations"

    invocation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), nullable=False)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("variation_sessions.session_id"), nullable=False
    )
    record_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    record_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)


class HarnessInvocationRow(Base):
    __tablename__ = "harness_invocations"

    invocation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), nullable=False)
    activity_id: Mapped[str] = mapped_column(
        ForeignKey("activities.activity_id"), nullable=False
    )
    session_id: Mapped[str | None] = mapped_column(
        ForeignKey("variation_sessions.session_id")
    )
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    record_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    record_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    updated_at: Mapped[datetime] = mapped_column(nullable=False)


class ReconciliationCaseRow(Base):
    __tablename__ = "reconciliation_cases"

    reconciliation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), nullable=False)
    activity_id: Mapped[str] = mapped_column(
        ForeignKey("activities.activity_id"), nullable=False
    )
    session_id: Mapped[str | None] = mapped_column(
        ForeignKey("variation_sessions.session_id")
    )
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    record_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    record_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    updated_at: Mapped[datetime] = mapped_column(nullable=False)


class ArtifactReferenceRow(Base):
    __tablename__ = "artifact_references"
    __table_args__ = (
        UniqueConstraint(
            "digest", "owner_type", "owner_id", "role", name="uq_artifact_reference"
        ),
    )

    reference_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    digest: Mapped[str] = mapped_column(
        ForeignKey("artifact_metadata.digest"), nullable=False
    )
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), nullable=False)
    owner_type: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_id: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[str] = mapped_column(String(128), nullable=False)
    retention_class: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)


class DeletionTombstoneRow(Base):
    __tablename__ = "deletion_tombstones"

    tombstone_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    digest: Mapped[str] = mapped_column(String(71), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)


class ReviewRequestRow(Base):
    __tablename__ = "review_requests"

    review_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id"), nullable=False)
    candidate_id: Mapped[str] = mapped_column(
        ForeignKey("candidates.candidate_id"), nullable=False
    )
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    proposer_id: Mapped[str] = mapped_column(String(256), nullable=False)
    eligible_roles_json: Mapped[str] = mapped_column(Text, nullable=False)
    approvals_required: Mapped[int] = mapped_column(Integer, nullable=False)
    proposer_may_review: Mapped[bool] = mapped_column(nullable=False)
    required_evidence_json: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)


class ReviewDecisionRow(Base):
    __tablename__ = "review_decisions"
    __table_args__ = (
        UniqueConstraint("review_id", "reviewer_id", name="uq_review_reviewer"),
    )

    decision_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    review_id: Mapped[str] = mapped_column(
        ForeignKey("review_requests.review_id"), nullable=False
    )
    reviewer_id: Mapped[str] = mapped_column(String(256), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    decision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    decision_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
