"""Authoritative lifecycle state values."""

from enum import StrEnum


class RunState(StrEnum):
    CREATED = "created"
    VALIDATING = "validating"
    READY = "ready"
    RUNNING = "running"
    PAUSING = "pausing"
    PAUSED = "paused"
    CANCELLING = "cancelling"
    BLOCKED_REVIEW = "blocked_review"
    BLOCKED_RECONCILIATION = "blocked_reconciliation"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class VariationSessionState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PROPOSAL_READY = "proposal_ready"
    EXHAUSTED = "exhausted"
    POLICY_BLOCKED = "policy_blocked"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    CANCELLED = "cancelled"
    FAILED = "failed"


class CandidateState(StrEnum):
    STAGED = "staged"
    EVALUATING = "evaluating"
    REVIEW_REQUIRED = "review_required"
    ADMITTED = "admitted"
    REJECTED = "rejected"
    QUARANTINED = "quarantined"
    POLICY_BLOCKED = "policy_blocked"
    CANCELLED = "cancelled"


class EvaluationState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    ERRORED = "errored"
    TIMED_OUT = "timed_out"
    POLICY_BLOCKED = "policy_blocked"
    INVALID_REPORT = "invalid_report"


class ReviewState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    WITHDRAWN = "withdrawn"
