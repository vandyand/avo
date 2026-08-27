"""Small deterministic, fail-closed v1 policy interpreter."""

from datetime import UTC, datetime
from fnmatch import fnmatchcase
from uuid import uuid4

from avo_correlate.contracts.policy import PolicyDecision, PolicyRequest
from avo_correlate.contracts.policy_bundle import PolicyBundle, PolicyRule
from avo_correlate.domain.canonical import canonical_digest

_EFFECT_PRIORITY = {"deny": 0, "review": 1, "allow": 2}


class BuiltinPolicyEngine:
    def __init__(self, bundle: PolicyBundle) -> None:
        self.bundle = bundle
        self.bundle_digest = canonical_digest(bundle)

    def decide(self, request: PolicyRequest) -> PolicyDecision:
        matches = [rule for rule in self.bundle.rules if self._matches(rule, request)]
        if matches:
            selected = min(matches, key=lambda rule: (_EFFECT_PRIORITY[rule.effect], rule.rule_id))
            outcome = selected.effect
            reason_codes = [selected.reason_code]
            obligations = selected.obligations
        else:
            outcome = "deny"
            reason_codes = ["POLICY_DEFAULT_DENY"]
            obligations = []
        return PolicyDecision(
            decision_id=str(uuid4()),
            policy_engine_id=self.bundle.policy_engine_id,
            policy_bundle_digest=self.bundle_digest,
            action=request.action,
            resource=request.resource,
            input_digest=canonical_digest(request),
            outcome=outcome,
            reason_codes=reason_codes,
            obligations=obligations,
            decided_at=datetime.now(UTC),
        )

    @staticmethod
    def _matches(rule: PolicyRule, request: PolicyRequest) -> bool:
        return (
            ("*" in rule.actors or request.actor_id in rule.actors)
            and ("*" in rule.actions or request.action in rule.actions)
            and any(fnmatchcase(request.resource, pattern) for pattern in rule.resource_patterns)
        )
