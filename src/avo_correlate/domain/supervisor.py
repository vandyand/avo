"""Versioned deterministic supervisor rules."""

from avo_correlate.contracts.supervisor import (
    SupervisorDirective,
    SupervisorObservation,
)


class DeterministicSupervisor:
    version = "1.0.0"

    def decide(self, observation: SupervisorObservation) -> SupervisorDirective:
        if observation.run_state in {"completed", "cancelled", "failed", "cancelling"}:
            return SupervisorDirective(
                directive="terminate", reason_codes=["RUN_NOT_SCHEDULABLE"]
            )
        if observation.budget_fraction_micros >= 950_000:
            return SupervisorDirective(
                directive="pause", reason_codes=["HARD_BUDGET_BOUND_APPROACHING"]
            )
        if observation.quarantine_count >= 2:
            return SupervisorDirective(
                directive="request_review",
                reason_codes=["REPEATED_AUTHORITATIVE_QUARANTINE"],
                payload={"required_evidence": "evaluator-integrity-summary"},
            )
        if observation.policy_denial_count >= 3:
            return SupervisorDirective(
                directive="pause", reason_codes=["REPEATED_POLICY_DENIAL"]
            )
        if observation.duplicate_patch_count >= 2:
            return SupervisorDirective(
                directive="change_hypothesis", reason_codes=["DUPLICATE_OR_NOOP_PATCHES"]
            )
        if observation.repeated_failure_count >= 3:
            return SupervisorDirective(
                directive="reduce_scope", reason_codes=["REPEATED_DEVELOPMENT_FAILURE"]
            )
        if observation.sessions_without_admission >= 3:
            return SupervisorDirective(
                directive="revisit_lineage", reason_codes=["NO_RECENT_ADMISSION"]
            )
        if observation.diversity_fraction_micros < 100_000:
            return SupervisorDirective(
                directive="change_hypothesis", reason_codes=["ATTEMPT_DIVERSITY_COLLAPSE"]
            )
        return SupervisorDirective(directive="continue", reason_codes=["WITHIN_BOUNDS"])
