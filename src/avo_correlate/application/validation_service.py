"""Side-effect-free experiment capability and policy validation."""

from dataclasses import dataclass

from avo_correlate.contracts.experiment import ExperimentSpec
from avo_correlate.contracts.operations import DryRunReport, ValidationCheck
from avo_correlate.domain.canonical import canonical_digest


@dataclass(frozen=True)
class RuntimeCapabilities:
    sandbox_profiles: frozenset[str]
    component_ids: frozenset[str]
    policy_bundle_digests: frozenset[str]


class ValidationService:
    def __init__(self, capabilities: RuntimeCapabilities) -> None:
        self._capabilities = capabilities

    def dry_run(self, spec: ExperimentSpec) -> DryRunReport:
        checks = [
            self._present(
                "sandbox_profile",
                spec.sandbox_profile_id,
                self._capabilities.sandbox_profiles,
            ),
            self._present(
                "harness",
                spec.harness.component.component_id,
                self._capabilities.component_ids,
            ),
            self._present(
                "policy_bundle",
                spec.policy_bundle_digest,
                self._capabilities.policy_bundle_digests,
            ),
        ]
        for evaluator in (
            spec.development_evaluators
            + spec.admission_evaluators
            + spec.audit_evaluators
        ):
            checks.append(
                self._present(
                    f"evaluator:{evaluator.tier}:{evaluator.component.component_id}",
                    evaluator.component.component_id,
                    self._capabilities.component_ids,
                )
            )
        checks.append(
            ValidationCheck(
                check_id="network_policy",
                outcome="pass",
                detail="v1 tool and evaluator profiles default to network denied",
            )
        )
        outcome = "blocked" if any(item.outcome == "fail" for item in checks) else "ready"
        return DryRunReport(
            experiment_id=spec.experiment_id,
            spec_digest=canonical_digest(spec),
            outcome=outcome,
            checks=checks,
        )

    @staticmethod
    def _present(check_id: str, value: str, available: frozenset[str]) -> ValidationCheck:
        found = value in available
        return ValidationCheck(
            check_id=check_id,
            outcome="pass" if found else "fail",
            detail=(f"available: {value}" if found else f"not registered: {value}"),
        )
