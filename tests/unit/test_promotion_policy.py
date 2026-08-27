import hashlib
import json

import pytest
from pydantic import ValidationError

from avo_correlate.contracts.promotion_policy import (
    GateAttestation,
    PathManifestAttestation,
    PromotionConfig,
    PromotionOutcome,
    PromotionPolicy,
    PromotionRequest,
    ReviewerAttestation,
    RiskClass,
    RollbackAttestation,
)

CANDIDATE = "sha256:" + "a" * 64
BASE = "sha256:" + "b" * 64
OTHER = "sha256:" + "c" * 64


def attestation(kind: str, **overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "candidate_digest": CANDIDATE,
        "base_digest": BASE,
        "evidence_digest": OTHER,
        "issuer_id": "ci",
        "valid_from_epoch": 1,
        "valid_until_epoch": 3,
    }
    if kind == "gate":
        data.update({"gate_name": "deterministic", "passed": True})
    elif kind == "review":
        data.update({"reviewer_id": "r1", "approved": True, "issuer_id": "reviewer"})
    elif kind == "rollback":
        data.update({"rollback_count": 0, "available": True, "issuer_id": "rollback"})
    else:
        raise ValueError(f"unknown kind: {kind}")
    data.update(overrides)
    return data


def policy_config() -> PromotionConfig:
    return PromotionConfig(
        evaluation_epoch=2,
        trusted_gate_issuers={
            "deterministic": ["ci"],
            "provenance": ["ci"],
            "trusted_ci": ["ci"],
            "private_evaluation": ["private"],
            "integration_soak": ["ci"],
        },
        trusted_base_issuers=["base"],
        trusted_reviewer_issuers=["reviewer"],
        trusted_path_issuers=["diff"],
        rollback_issuer_ids=["rollback"],
        rollback_limit=1,
        reviewer_domains={"r1": "d1", "r2": "d2", "r3": "d2", "agent": "agent-domain"},
        proposer_domains={"agent": "agent-domain"},
        candidate_proposers={CANDIDATE: "agent"},
    )


def path_manifest(paths: list[str], **overrides: object) -> dict[str, object]:
    canonical = json.dumps(
        sorted(path.casefold() for path in paths),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    data: dict[str, object] = {
        "candidate_digest": CANDIDATE,
        "base_digest": BASE,
        "evidence_digest": OTHER,
        "path_manifest_digest": "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "issuer_id": "diff",
        "valid_from_epoch": 1,
        "valid_until_epoch": 3,
    }
    data.update(overrides)
    return data


def required_gates(paths: list[str]) -> list[dict[str, object]]:
    try:
        risk = PromotionPolicy.derive_risk(paths)
    except ValueError:
        # Path validation belongs to PromotionRequest; these values only let its
        # model validator run without the fixture helper masking that error.
        risk = RiskClass.LOW
    if risk is RiskClass.LOW:
        return [
            attestation("gate", gate_name="deterministic"),
            attestation("gate", gate_name="provenance"),
        ]
    return [
        attestation("gate", gate_name="trusted_ci"),
        attestation("gate", gate_name="private_evaluation", issuer_id="private"),
        attestation("gate", gate_name="provenance"),
        attestation("gate", gate_name="integration_soak"),
    ]


def request(paths: list[str] | None = None, **overrides: object) -> PromotionRequest:
    changed_paths = ["docs/guide.md"] if paths is None else paths
    data: dict[str, object] = {
        "candidate_id": "candidate",
        "proposer_id": "agent",
        "candidate_digest": CANDIDATE,
        "base_digest": BASE,
        "changed_paths": changed_paths,
        "path_manifest_attestation": path_manifest(changed_paths),
        "base_attestation": attestation("gate", gate_name="base", issuer_id="base"),
        "gate_attestations": required_gates(changed_paths),
        "reviewer_attestations": [attestation("review")],
        "rollback_attestation": attestation("rollback"),
    }
    data.update(overrides)
    return PromotionRequest.model_validate(data)


def outcome(request_: PromotionRequest) -> PromotionOutcome:
    return PromotionPolicy().classify(request_, policy_config()).outcome


def test_low_allow_and_ordinary_allow_with_independent_domains() -> None:
    assert outcome(request()) is PromotionOutcome.ALLOW
    ordinary = request(
        ["src/avo_correlate/feature.py"],
        reviewer_attestations=[
            attestation("review", reviewer_id="r1"),
            attestation("review", reviewer_id="r2"),
        ],
    )
    decision = PromotionPolicy().classify(ordinary, policy_config())
    assert decision.outcome is PromotionOutcome.ALLOW
    assert decision.risk_class is RiskClass.ORDINARY
    assert decision.required_quorum == 2


@pytest.mark.parametrize(
    ("paths", "risk"),
    [
        (["DOCS/guide.md", "TESTS/test_feature.py"], RiskClass.LOW),
        (["README.md", "src/feature.py"], RiskClass.ORDINARY),
        ([".AGENTS/SKILLS/AVO-ROADMAP/SKILL.md"], RiskClass.CONSTITUTIONAL),
        (["UV.LOCK"], RiskClass.CONSTITUTIONAL),
        (["services/api/requirements-dev.txt"], RiskClass.CONSTITUTIONAL),
        (["frontend/package.json"], RiskClass.CONSTITUTIONAL),
        (["rust/Cargo.toml"], RiskClass.CONSTITUTIONAL),
        (["go/go.mod"], RiskClass.CONSTITUTIONAL),
        (["ruby/Gemfile"], RiskClass.CONSTITUTIONAL),
        (["frontend/package-lock.json"], RiskClass.CONSTITUTIONAL),
        (["python/poetry.lock"], RiskClass.CONSTITUTIONAL),
        (["ruby/Gemfile.lock"], RiskClass.CONSTITUTIONAL),
        (["python/Pipfile.lock"], RiskClass.CONSTITUTIONAL),
        (["python/requirements.in"], RiskClass.CONSTITUTIONAL),
        (["frontend/npm-shrinkwrap.json"], RiskClass.CONSTITUTIONAL),
        (["nix/flake.lock"], RiskClass.CONSTITUTIONAL),
        (["java/build.gradle.kts"], RiskClass.CONSTITUTIONAL),
        (["evaluators/private/corpus.json"], RiskClass.CONSTITUTIONAL),
        (["src/avo_correlate/contracts/promotion_policy.py"], RiskClass.CONSTITUTIONAL),
        (["DEPLOY/service.yml"], RiskClass.PRODUCTION),
    ],
)
def test_risk_classification_is_case_insensitive(paths: list[str], risk: RiskClass) -> None:
    assert PromotionPolicy.derive_risk(paths) is risk


@pytest.mark.parametrize(
    "path",
    [
        "C:/unsafe",
        "a:b",
        "a\\b",
        "/absolute",
        "../unsafe",
        "a/./b",
        "a//b",
        "docs/CON.txt",
        "docs/file. ",
        "docs/file.",
        "docs/a?.txt",
    ],
)
def test_unsafe_paths_are_invalid(path: str) -> None:
    with pytest.raises(ValidationError):
        request([path])
    with pytest.raises(ValueError):
        PromotionPolicy.derive_risk([path])


@pytest.mark.parametrize(
    "paths",
    [
        ["src/A.py", "src/a.py"],
        [
            "docs/caf\N{LATIN SMALL LETTER E WITH ACUTE}.md",
            "docs/cafe\N{COMBINING ACUTE ACCENT}.md",
        ],
    ],
)
def test_case_and_unicode_path_collisions_are_invalid(paths: list[str]) -> None:
    with pytest.raises(ValidationError):
        request(paths)
    with pytest.raises(ValueError):
        PromotionPolicy.derive_risk(paths)


@pytest.mark.parametrize(
    "override",
    [
        {"issuer_id": "unknown"},
        {"candidate_digest": OTHER},
        {"base_digest": OTHER},
        {"path_manifest_digest": OTHER},
        {"valid_until_epoch": 1},
    ],
)
def test_changed_paths_require_a_bound_trusted_manifest(override: dict[str, object]) -> None:
    paths = ["docs/guide.md"]
    assert (
        outcome(request(paths, path_manifest_attestation=path_manifest(paths, **override)))
        is PromotionOutcome.QUARANTINE
    )


def test_manifest_cannot_hide_a_constitutional_path() -> None:
    actual_paths = ["docs/guide.md", "src/avo_correlate/contracts/promotion_policy.py"]
    incomplete = path_manifest(["docs/guide.md"])
    decision = PromotionPolicy().classify(
        request(actual_paths, path_manifest_attestation=incomplete), policy_config()
    )
    assert decision.outcome is PromotionOutcome.QUARANTINE
    assert decision.risk_class is RiskClass.CONSTITUTIONAL


def test_proposer_identity_is_controller_bound_to_candidate() -> None:
    unknown = request(proposer_id="unregistered")
    assert outcome(unknown) is PromotionOutcome.QUARANTINE
    wrong_binding = policy_config().model_copy(
        update={"candidate_proposers": {CANDIDATE: "someone-else"}}
    )
    assert (
        PromotionPolicy().classify(request(), wrong_binding).outcome is PromotionOutcome.QUARANTINE
    )


def test_constitutional_docs_cannot_be_downgraded_to_low() -> None:
    decision = PromotionPolicy().classify(request(["docs/roadmap.md"]), policy_config())
    assert decision.outcome is PromotionOutcome.ESCALATE
    assert decision.risk_class is RiskClass.CONSTITUTIONAL


def test_production_denies_before_ordinary_evidence_reconciliation() -> None:
    assert (
        outcome(request(["production/service.yml"], rollback_attestation=None))
        is PromotionOutcome.DENY
    )


@pytest.mark.parametrize(
    "base",
    [
        attestation("gate", gate_name="base", issuer_id="base", passed=False),
        attestation("gate", gate_name="wrong", issuer_id="base"),
        attestation("gate", gate_name="base", issuer_id="base", candidate_digest=OTHER),
        attestation("gate", gate_name="base", issuer_id="base", base_digest=OTHER),
        attestation("gate", gate_name="base", issuer_id="unknown"),
        attestation("gate", gate_name="base", issuer_id="base", valid_until_epoch=1),
    ],
)
def test_base_attestation_requires_trusted_base_semantics(base: dict[str, object]) -> None:
    assert outcome(request(base_attestation=base)) is PromotionOutcome.QUARANTINE


@pytest.mark.parametrize(
    ("rollback", "expected"),
    [
        (None, PromotionOutcome.QUARANTINE),
        (attestation("rollback", issuer_id="unknown"), PromotionOutcome.QUARANTINE),
        (attestation("rollback", candidate_digest=OTHER), PromotionOutcome.QUARANTINE),
        (attestation("rollback", base_digest=OTHER), PromotionOutcome.QUARANTINE),
        (attestation("rollback", available=False), PromotionOutcome.DENY),
        (attestation("rollback", rollback_count=2), PromotionOutcome.DENY),
        (attestation("rollback", rollback_count=1), PromotionOutcome.ALLOW),
    ],
)
def test_rollback_uses_configured_limit_and_trusted_evidence(
    rollback: dict[str, object] | None, expected: PromotionOutcome
) -> None:
    assert outcome(request(rollback_attestation=rollback)) is expected


def test_trusted_failed_gate_denies_before_disagreement() -> None:
    gates = required_gates(["docs/guide.md"])
    gates[0] = attestation("gate", gate_name="deterministic", passed=False)
    assert (
        outcome(
            request(
                gate_attestations=gates,
                reviewer_attestations=[attestation("review", approved=False)],
            )
        )
        is PromotionOutcome.DENY
    )


def test_trusted_failed_gate_denies_before_base_reconciliation() -> None:
    gates = required_gates(["docs/guide.md"])
    gates[0] = attestation("gate", gate_name="deterministic", passed=False)
    assert (
        outcome(
            request(
                base_attestation=attestation("gate", gate_name="wrong", issuer_id="base"),
                gate_attestations=gates,
            )
        )
        is PromotionOutcome.DENY
    )


def test_conflicting_trusted_gate_evidence_quarantines() -> None:
    gates = required_gates(["docs/guide.md"])
    gates.append(attestation("gate", gate_name="deterministic", passed=False))
    assert outcome(request(gate_attestations=gates)) is PromotionOutcome.QUARANTINE


def test_duplicate_trusted_gate_evidence_quarantines() -> None:
    gates = required_gates(["docs/guide.md"])
    gates.append(attestation("gate", gate_name="deterministic"))
    assert outcome(request(gate_attestations=gates)) is PromotionOutcome.QUARANTINE


def test_trusted_rollback_hard_failure_denies_before_base_reconciliation() -> None:
    assert (
        outcome(
            request(
                base_attestation=attestation("gate", gate_name="wrong", issuer_id="base"),
                rollback_attestation=attestation("rollback", available=False),
            )
        )
        is PromotionOutcome.DENY
    )


@pytest.mark.parametrize(
    "gates",
    [
        [
            attestation("gate", gate_name="deterministic"),
            attestation("gate", gate_name="provenance", candidate_digest=OTHER),
        ],
        [
            attestation("gate", gate_name="deterministic"),
            attestation("gate", gate_name="provenance", base_digest=OTHER),
        ],
        [
            attestation("gate", gate_name="deterministic"),
            attestation("gate", gate_name="provenance", issuer_id="unknown"),
        ],
        [attestation("gate", gate_name="deterministic")],
    ],
)
def test_missing_or_invalid_required_gate_quarantines(gates: list[dict[str, object]]) -> None:
    assert outcome(request(gate_attestations=gates)) is PromotionOutcome.QUARANTINE


@pytest.mark.parametrize(
    "reviewers",
    [
        [attestation("review", reviewer_id="unknown")],
        [attestation("review", issuer_id="unknown")],
        [attestation("review", candidate_digest=OTHER)],
        [attestation("review", base_digest=OTHER)],
        [attestation("review", valid_until_epoch=1)],
        [attestation("review"), attestation("review")],
    ],
)
def test_invalid_or_duplicate_reviewer_evidence_quarantines(
    reviewers: list[dict[str, object]],
) -> None:
    assert outcome(request(reviewer_attestations=reviewers)) is PromotionOutcome.QUARANTINE


def test_missing_reviewer_evidence_quarantines() -> None:
    assert outcome(request(reviewer_attestations=[])) is PromotionOutcome.QUARANTINE


def test_only_trusted_self_approval_is_a_hard_denial() -> None:
    trusted = attestation("review", reviewer_id="agent")
    untrusted = attestation("review", reviewer_id="agent", issuer_id="unknown")
    assert outcome(request(reviewer_attestations=[trusted])) is PromotionOutcome.DENY
    assert outcome(request(reviewer_attestations=[untrusted])) is PromotionOutcome.QUARANTINE


def test_unknown_reviewer_issuer_cannot_be_hidden_by_valid_independent_approvals() -> None:
    reviewers = [
        attestation("review", reviewer_id="r1"),
        attestation("review", reviewer_id="r2"),
        attestation("review", reviewer_id="r3", issuer_id="unknown"),
    ]
    assert (
        outcome(request(["src/feature.py"], reviewer_attestations=reviewers))
        is PromotionOutcome.QUARANTINE
    )


def test_duplicate_reviewer_cannot_be_hidden_by_sufficient_other_domains() -> None:
    reviewers = [
        attestation("review", reviewer_id="r1"),
        attestation("review", reviewer_id="r1"),
        attestation("review", reviewer_id="r2"),
    ]
    assert (
        outcome(request(["src/feature.py"], reviewer_attestations=reviewers))
        is PromotionOutcome.QUARANTINE
    )


def test_same_domain_reviewers_do_not_form_ordinary_quorum() -> None:
    reviewers = [attestation("review", reviewer_id="r2"), attestation("review", reviewer_id="r3")]
    assert (
        outcome(request(["src/feature.py"], reviewer_attestations=reviewers))
        is PromotionOutcome.DENY
    )


def test_extra_same_domain_approval_does_not_invalidate_sufficient_quorum() -> None:
    reviewers = [
        attestation("review", reviewer_id="r1"),
        attestation("review", reviewer_id="r2"),
        attestation("review", reviewer_id="r3"),
    ]
    assert (
        outcome(request(["src/feature.py"], reviewer_attestations=reviewers))
        is PromotionOutcome.ALLOW
    )


@pytest.mark.parametrize("paths", [["docs/guide.md"], ["docs/roadmap.md"]])
def test_self_approval_always_denies(paths: list[str]) -> None:
    assert (
        outcome(request(paths, reviewer_attestations=[attestation("review", reviewer_id="agent")]))
        is PromotionOutcome.DENY
    )


@pytest.mark.parametrize("exception_requested", [True, False])
def test_exception_and_trusted_disagreement_escalate(exception_requested: bool) -> None:
    evidence = [] if exception_requested else [attestation("review", approved=False)]
    assert (
        outcome(
            request(
                exception_requested=exception_requested,
                reviewer_attestations=evidence or [attestation("review")],
            )
        )
        is PromotionOutcome.ESCALATE
    )


@pytest.mark.parametrize(
    ("model", "data"),
    [
        (GateAttestation, attestation("gate", passed=1)),
        (ReviewerAttestation, attestation("review", approved="true")),
        (RollbackAttestation, attestation("rollback", available=0)),
        (GateAttestation, attestation("gate", valid_until_epoch="3")),
        (GateAttestation, attestation("gate", valid_from_epoch=3, valid_until_epoch=2)),
        (ReviewerAttestation, attestation("review", valid_from_epoch=3, valid_until_epoch=2)),
        (RollbackAttestation, attestation("rollback", valid_from_epoch=3, valid_until_epoch=2)),
        (
            PathManifestAttestation,
            path_manifest(["docs/guide.md"], valid_from_epoch=3, valid_until_epoch=2),
        ),
    ],
)
def test_attestation_booleans_and_windows_are_strict(
    model: type[object], data: dict[str, object]
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(data)  # type: ignore[attr-defined]
