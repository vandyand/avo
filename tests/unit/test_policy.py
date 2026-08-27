from avo_correlate.adapters.policy import BuiltinPolicyEngine
from avo_correlate.contracts.policy import PolicyRequest
from avo_correlate.contracts.policy_bundle import PolicyBundle, PolicyRule


def test_policy_is_default_deny() -> None:
    engine = BuiltinPolicyEngine(PolicyBundle(policy_engine_id="builtin-v1", rules=[]))
    decision = engine.decide(
        PolicyRequest(action="tool.read", resource="workspace/src/a.py", actor_id="harness")
    )
    assert decision.outcome == "deny"
    assert decision.reason_codes == ["POLICY_DEFAULT_DENY"]


def test_explicit_deny_wins_over_allow() -> None:
    engine = BuiltinPolicyEngine(
        PolicyBundle(
            policy_engine_id="builtin-v1",
            rules=[
                PolicyRule(
                    rule_id="allow-source",
                    effect="allow",
                    actors=["harness"],
                    actions=["tool.read"],
                    resource_patterns=["workspace/*"],
                    reason_code="ALLOW_WORKSPACE",
                ),
                PolicyRule(
                    rule_id="deny-private",
                    effect="deny",
                    actors=["*"],
                    actions=["tool.read"],
                    resource_patterns=["workspace/private/*"],
                    reason_code="DENY_PRIVATE",
                ),
            ],
        )
    )
    allowed = engine.decide(
        PolicyRequest(action="tool.read", resource="workspace/src/a.py", actor_id="harness")
    )
    denied = engine.decide(
        PolicyRequest(action="tool.read", resource="workspace/private/test.py", actor_id="harness")
    )
    assert allowed.outcome == "allow"
    assert denied.outcome == "deny"
    assert denied.reason_codes == ["DENY_PRIVATE"]
