"""Side-effect-free, controller-owned promotion classification."""

import hashlib
import json
import unicodedata
from enum import StrEnum
from typing import Literal

from pydantic import Field, StrictBool, StrictInt, field_validator

from avo_correlate.contracts.base import NonEmptyString, Sha256Digest, StrictModel


def _validate_window(value: int, info: object) -> int:
    if value < getattr(info, "data", {}).get("valid_from_epoch", value):
        raise ValueError("validity window is reversed")
    return value


_WINDOWS_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)


def is_valid_promotion_path(path: str) -> bool:
    """Return whether *path* is a normalized, relative POSIX repository path."""
    parts = path.split("/")
    return not (
        unicodedata.normalize("NFC", path) != path
        or any(ord(character) < 32 for character in path)
        or "\\" in path
        or ":" in path
        or any(character in '<>"|?*' for character in path)
        or path.startswith(("/", "~"))
        or any(part in {"", ".", ".."} or part.endswith((" ", ".")) for part in parts)
        or any(
            part.split(".", maxsplit=1)[0].casefold() in _WINDOWS_RESERVED_NAMES for part in parts
        )
    )


def path_manifest_digest(paths: list[str]) -> str:
    canonical = json.dumps(
        sorted(path.casefold() for path in paths),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# Kept as a private compatibility alias for callers of the original helper.
_path_manifest_digest = path_manifest_digest


def _validate_paths(paths: list[str]) -> list[str]:
    if not paths:
        raise ValueError("changed paths cannot be empty")
    if any(not is_valid_promotion_path(path) for path in paths):
        raise ValueError("paths must be normalized relative paths")
    canonical = [path.casefold() for path in paths]
    if len(canonical) != len(set(canonical)):
        raise ValueError("changed paths must not contain case or Unicode collisions")
    return paths


class RiskClass(StrEnum):
    LOW = "low"
    ORDINARY = "ordinary"
    CONSTITUTIONAL = "constitutional"
    PRODUCTION = "production"


class PromotionOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    QUARANTINE = "quarantine"
    ESCALATE = "escalate"


class GateAttestation(StrictModel):
    gate_name: NonEmptyString
    candidate_digest: Sha256Digest
    base_digest: Sha256Digest
    evidence_digest: Sha256Digest
    issuer_id: NonEmptyString
    passed: StrictBool
    valid_from_epoch: StrictInt = Field(ge=0)
    valid_until_epoch: StrictInt = Field(ge=0)

    @field_validator("valid_until_epoch")
    @classmethod
    def ordered_window(cls, value: int, info: object) -> int:
        return _validate_window(value, info)


class ReviewerAttestation(StrictModel):
    reviewer_id: NonEmptyString
    candidate_digest: Sha256Digest
    base_digest: Sha256Digest
    evidence_digest: Sha256Digest
    issuer_id: NonEmptyString
    approved: StrictBool
    valid_from_epoch: StrictInt = Field(ge=0)
    valid_until_epoch: StrictInt = Field(ge=0)

    _ordered_window = field_validator("valid_until_epoch")(_validate_window)


class RollbackAttestation(StrictModel):
    rollback_count: StrictInt = Field(ge=0)
    candidate_digest: Sha256Digest
    base_digest: Sha256Digest
    evidence_digest: Sha256Digest
    issuer_id: NonEmptyString
    available: StrictBool
    valid_from_epoch: StrictInt = Field(ge=0)
    valid_until_epoch: StrictInt = Field(ge=0)

    _ordered_window = field_validator("valid_until_epoch")(_validate_window)


class PathManifestAttestation(StrictModel):
    candidate_digest: Sha256Digest
    base_digest: Sha256Digest
    evidence_digest: Sha256Digest
    path_manifest_digest: Sha256Digest
    issuer_id: NonEmptyString
    valid_from_epoch: StrictInt = Field(ge=0)
    valid_until_epoch: StrictInt = Field(ge=0)

    _ordered_window = field_validator("valid_until_epoch")(_validate_window)


class PromotionConfig(StrictModel):
    evaluation_epoch: StrictInt = Field(ge=0)
    trusted_gate_issuers: dict[NonEmptyString, list[NonEmptyString]] = Field(default_factory=dict)
    trusted_base_issuers: list[NonEmptyString] = Field(min_length=1)
    trusted_reviewer_issuers: list[NonEmptyString] = Field(min_length=1)
    trusted_path_issuers: list[NonEmptyString] = Field(min_length=1)
    rollback_issuer_ids: list[NonEmptyString] = Field(min_length=1)
    rollback_limit: StrictInt = Field(ge=0)
    reviewer_domains: dict[NonEmptyString, NonEmptyString] = Field(min_length=1)
    proposer_domains: dict[NonEmptyString, NonEmptyString] = Field(min_length=1)
    candidate_proposers: dict[Sha256Digest, NonEmptyString] = Field(min_length=1)
    low_gates: frozenset[NonEmptyString] = frozenset({"deterministic", "provenance"})
    ordinary_gates: frozenset[NonEmptyString] = frozenset(
        {"trusted_ci", "private_evaluation", "provenance", "integration_soak"}
    )


class PromotionRequest(StrictModel):
    schema_version: Literal[1] = 1
    candidate_id: NonEmptyString
    proposer_id: NonEmptyString
    candidate_digest: Sha256Digest
    base_digest: Sha256Digest
    changed_paths: list[NonEmptyString] = Field(min_length=1)
    path_manifest_attestation: PathManifestAttestation
    base_attestation: GateAttestation
    gate_attestations: list[GateAttestation] = Field(default_factory=list[GateAttestation])
    reviewer_attestations: list[ReviewerAttestation] = Field(
        default_factory=list[ReviewerAttestation]
    )
    rollback_attestation: RollbackAttestation | None = None
    exception_requested: StrictBool = False

    @field_validator("changed_paths")
    @classmethod
    def normalized_paths(cls, paths: list[str]) -> list[str]:
        return _validate_paths(paths)


class PromotionDecision(StrictModel):
    schema_version: Literal[1] = 1
    candidate_id: NonEmptyString
    outcome: PromotionOutcome
    risk_class: RiskClass
    reason_codes: list[NonEmptyString] = Field(min_length=1)
    required_quorum: StrictInt = Field(ge=0)


class PromotionPolicy:
    """Apply a conservative, controller-owned promotion decision.

    Production is denied first; self-approval and trusted failed gates then deny.
    Constitutional changes otherwise escalate. Promotable scope continues through
    hard deny, reconciliation quarantine, operator escalation, and quorum allow.
    """

    CONSTITUTIONAL_EXACT = frozenset(
        {
            "pyproject.toml",
            "docs/roadmap.md",
            "uv.lock",
            "poetry.lock",
            "pdm.lock",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "bun.lockb",
            "cargo.lock",
            "gemfile.lock",
            "composer.lock",
            "go.sum",
        }
    )
    CONSTITUTIONAL_PREFIXES = (
        ".agents/skills/avo-roadmap/",
        ".github/",
        "schemas/",
        "migrations/",
        "evaluators/private/",
        "sandbox/",
        "credentials/",
        ".credentials/",
        "secrets/",
        ".secrets/",
        "src/avo_correlate/adapters/policy/",
        "src/avo_correlate/adapters/persistence/migrations/",
    )
    # The campaign/promotion controller plane is authority-bearing even when
    # a filename does not contain a constitutional keyword. Keep this list
    # explicit so unrelated application code remains ordinary-risk.
    CONSTITUTIONAL_AUTHORITY_PATHS = frozenset(
        {
            "scripts/run_sanitized_integration_campaign.py",
            "src/avo_correlate/application/campaign.py",
            "src/avo_correlate/application/integration_campaign_service.py",
            "src/avo_correlate/application/integration_attester_drill_service.py",
            "src/avo_correlate/application/integration_drill_service.py",
            "src/avo_correlate/application/integration_promotion_service.py",
            "src/avo_correlate/application/integration_rollback_service.py",
            "src/avo_correlate/application/promotion_service.py",
            "src/avo_correlate/application/synthetic_validation_service.py",
            "src/avo_correlate/adapters/artifacts/campaign_journal.py",
            "src/avo_correlate/adapters/artifacts/drill_journal.py",
            "src/avo_correlate/adapters/artifacts/promotion_journal.py",
            "src/avo_correlate/adapters/artifacts/synthetic_validation_journal.py",
            "src/avo_correlate/contracts/integration_campaign.py",
            "src/avo_correlate/contracts/integration_drill.py",
            "src/avo_correlate/contracts/integration_promotion.py",
            "src/avo_correlate/contracts/policy.py",
            "src/avo_correlate/contracts/policy_bundle.py",
            "src/avo_correlate/contracts/promotion_bundle.py",
            "src/avo_correlate/contracts/synthetic_validation.py",
            "scripts/run_avo0046_drills.py",
        }
    )
    CONSTITUTIONAL_AUTHORITY_PREFIXES = (
        "src/avo_correlate/adapters/hosted_git/",
    )
    CONSTITUTIONAL_TERMS = (
        "admission",
        "budget",
        "controller",
        "lifecycle",
        "policy",
        "promotion",
        "provenance",
    )
    DEPENDENCY_FILENAMES = frozenset(
        {
            "bun.lockb",
            "cargo.lock",
            "cargo.toml",
            "composer.lock",
            "composer.json",
            "deno.json",
            "deno.jsonc",
            "deno.lock",
            "deps.edn",
            "flake.lock",
            "flake.nix",
            "gemfile",
            "gemfile.lock",
            "go.mod",
            "go.sum",
            "gradle.lockfile",
            "gradle.properties",
            "mix.exs",
            "mix.lock",
            "npm-shrinkwrap.json",
            "package.json",
            "package-lock.json",
            "package.resolved",
            "package.swift",
            "pdm.lock",
            "pipfile",
            "pipfile.lock",
            "pnpm-lock.yaml",
            "poetry.lock",
            "pom.xml",
            "project.clj",
            "pubspec.lock",
            "pubspec.yaml",
            "pyproject.toml",
            "uv.lock",
            "yarn.lock",
        }
    )
    PRODUCTION_PREFIXES = ("deploy/", "production/", "infra/", "ops/")

    def classify(self, request: PromotionRequest, config: PromotionConfig) -> PromotionDecision:
        risk = self.derive_risk(request.changed_paths)
        quorum = 1 if risk is RiskClass.LOW else 2
        if risk is RiskClass.PRODUCTION:
            return self._d(
                request, PromotionOutcome.DENY, risk, ["production_out_of_scope"], quorum
            )
        if not self._path_manifest_valid(request, config):
            return self._d(
                request, PromotionOutcome.QUARANTINE, risk, ["invalid_path_manifest"], quorum
            )
        if (
            request.proposer_id not in config.proposer_domains
            or config.candidate_proposers.get(request.candidate_digest) != request.proposer_id
        ):
            return self._d(
                request, PromotionOutcome.QUARANTINE, risk, ["invalid_proposer_identity"], quorum
            )

        required_gates = config.low_gates if risk is RiskClass.LOW else config.ordinary_gates
        conflicting_gates = sorted(
            gate for gate in required_gates if self._conflicting_gate(request, gate, config)
        )
        if conflicting_gates:
            return self._d(
                request,
                PromotionOutcome.QUARANTINE,
                risk,
                [f"conflicting_gate:{gate}" for gate in conflicting_gates],
                quorum,
            )
        duplicate_gates = sorted(
            gate for gate in required_gates if self._duplicate_gate(request, gate, config)
        )
        if duplicate_gates:
            return self._d(
                request,
                PromotionOutcome.QUARANTINE,
                risk,
                [f"duplicate_gate:{gate}" for gate in duplicate_gates],
                quorum,
            )
        failed_gates = sorted(
            gate for gate in required_gates if self._failed_gate(request, gate, config)
        )
        if failed_gates:
            return self._d(
                request,
                PromotionOutcome.DENY,
                risk,
                [f"failed_gate:{gate}" for gate in failed_gates],
                quorum,
            )
        if any(
            reviewer.reviewer_id == request.proposer_id
            and self._reviewer_valid(reviewer, request, config)
            for reviewer in request.reviewer_attestations
        ):
            return self._d(request, PromotionOutcome.DENY, risk, ["self_approval"], quorum)
        if risk is RiskClass.CONSTITUTIONAL:
            return self._d(request, PromotionOutcome.ESCALATE, risk, ["constitutional_change"], 2)

        rollback = request.rollback_attestation
        if rollback is not None and self._bound(
            rollback, request, config.evaluation_epoch, config.rollback_issuer_ids
        ):
            if not rollback.available:
                return self._d(
                    request, PromotionOutcome.DENY, risk, ["rollback_unavailable"], quorum
                )
            if rollback.rollback_count > config.rollback_limit:
                return self._d(
                    request,
                    PromotionOutcome.DENY,
                    risk,
                    ["rollback_limit_exceeded"],
                    quorum,
                )
        if not self._base_valid(request.base_attestation, request, config):
            return self._d(
                request, PromotionOutcome.QUARANTINE, risk, ["untrusted_or_stale_base"], quorum
            )
        if rollback is None:
            return self._d(
                request, PromotionOutcome.QUARANTINE, risk, ["missing_rollback_evidence"], quorum
            )
        if not self._bound(rollback, request, config.evaluation_epoch, config.rollback_issuer_ids):
            return self._d(
                request, PromotionOutcome.QUARANTINE, risk, ["invalid_rollback_evidence"], quorum
            )

        invalid_gates = sorted(
            gate
            for gate in required_gates
            if self._has_invalid_gate_evidence(request, gate, config)
        )
        if invalid_gates:
            return self._d(
                request,
                PromotionOutcome.QUARANTINE,
                risk,
                [f"invalid_gate:{gate}" for gate in invalid_gates],
                quorum,
            )
        missing_gates = sorted(
            gate for gate in required_gates if not self._gate(request, gate, config)
        )
        if missing_gates:
            return self._d(
                request,
                PromotionOutcome.QUARANTINE,
                risk,
                [f"missing_gate:{gate}" for gate in missing_gates],
                quorum,
            )

        reviewer_ids = [reviewer.reviewer_id for reviewer in request.reviewer_attestations]
        if not reviewer_ids:
            return self._d(
                request, PromotionOutcome.QUARANTINE, risk, ["missing_reviewer_evidence"], quorum
            )
        if len(reviewer_ids) != len(set(reviewer_ids)):
            return self._d(
                request, PromotionOutcome.QUARANTINE, risk, ["duplicate_reviewer_evidence"], quorum
            )
        if any(
            not self._reviewer_valid(reviewer, request, config)
            for reviewer in request.reviewer_attestations
        ):
            return self._d(
                request, PromotionOutcome.QUARANTINE, risk, ["invalid_reviewer_evidence"], quorum
            )
        if request.exception_requested:
            return self._d(request, PromotionOutcome.ESCALATE, risk, ["operator_exception"], quorum)
        if any(not reviewer.approved for reviewer in request.reviewer_attestations):
            return self._d(
                request, PromotionOutcome.ESCALATE, risk, ["reviewer_disagreement"], quorum
            )

        approvals = [
            reviewer
            for reviewer in request.reviewer_attestations
            if reviewer.approved
            and config.proposer_domains.get(request.proposer_id)
            != config.reviewer_domains[reviewer.reviewer_id]
        ]
        domains = {config.reviewer_domains[reviewer.reviewer_id] for reviewer in approvals}
        if len(approvals) < quorum or len(domains) < quorum:
            return self._d(request, PromotionOutcome.DENY, risk, ["review_quorum_not_met"], quorum)
        return self._d(request, PromotionOutcome.ALLOW, risk, ["requirements_satisfied"], quorum)

    evaluate = classify

    @classmethod
    def derive_risk(cls, paths: list[str]) -> RiskClass:
        _validate_paths(paths)
        normalized = [path.casefold() for path in paths]
        if any(path.startswith(cls.PRODUCTION_PREFIXES) for path in normalized):
            return RiskClass.PRODUCTION
        if any(cls._constitutional_path(path) for path in normalized):
            return RiskClass.CONSTITUTIONAL
        return (
            RiskClass.LOW
            if all(path.startswith(("docs/", "tests/")) for path in normalized)
            else RiskClass.ORDINARY
        )

    @classmethod
    def _constitutional_path(cls, path: str) -> bool:
        filename = path.rsplit("/", maxsplit=1)[-1]
        return (
            path in cls.CONSTITUTIONAL_EXACT
            or path in cls.CONSTITUTIONAL_AUTHORITY_PATHS
            or path.startswith(cls.CONSTITUTIONAL_PREFIXES)
            or path.startswith(cls.CONSTITUTIONAL_AUTHORITY_PREFIXES)
            or filename in cls.DEPENDENCY_FILENAMES
            or filename.endswith((".lock", ".lockb", "-lock.json"))
            or (filename.startswith("requirements") and filename.endswith((".in", ".txt")))
            or filename.startswith(("build.gradle", "settings.gradle"))
            or filename == ".env"
            or any(term in path for term in cls.CONSTITUTIONAL_TERMS)
        )

    @staticmethod
    def _bound(
        attestation: GateAttestation | PathManifestAttestation | RollbackAttestation,
        request: PromotionRequest,
        epoch: int,
        issuers: list[str],
    ) -> bool:
        return (
            attestation.candidate_digest == request.candidate_digest
            and attestation.base_digest == request.base_digest
            and attestation.issuer_id in issuers
            and attestation.valid_from_epoch <= epoch <= attestation.valid_until_epoch
        )

    @classmethod
    def _path_manifest_valid(cls, request: PromotionRequest, config: PromotionConfig) -> bool:
        attestation = request.path_manifest_attestation
        return attestation.path_manifest_digest == path_manifest_digest(
            request.changed_paths
        ) and cls._bound(
            attestation,
            request,
            config.evaluation_epoch,
            config.trusted_path_issuers,
        )

    @classmethod
    def _base_valid(
        cls, attestation: GateAttestation, request: PromotionRequest, config: PromotionConfig
    ) -> bool:
        return (
            attestation.gate_name == "base"
            and attestation.passed
            and cls._bound(
                attestation, request, config.evaluation_epoch, config.trusted_base_issuers
            )
        )

    @classmethod
    def _gate_valid(
        cls,
        attestation: GateAttestation,
        request: PromotionRequest,
        gate: str,
        config: PromotionConfig,
    ) -> bool:
        return attestation.gate_name == gate and cls._bound(
            attestation, request, config.evaluation_epoch, config.trusted_gate_issuers.get(gate, [])
        )

    @classmethod
    def _gate(cls, request: PromotionRequest, gate: str, config: PromotionConfig) -> bool:
        return any(
            attestation.passed and cls._gate_valid(attestation, request, gate, config)
            for attestation in request.gate_attestations
        )

    @classmethod
    def _failed_gate(cls, request: PromotionRequest, gate: str, config: PromotionConfig) -> bool:
        return any(
            not attestation.passed and cls._gate_valid(attestation, request, gate, config)
            for attestation in request.gate_attestations
        )

    @classmethod
    def _conflicting_gate(
        cls, request: PromotionRequest, gate: str, config: PromotionConfig
    ) -> bool:
        trusted = [
            attestation
            for attestation in request.gate_attestations
            if cls._gate_valid(attestation, request, gate, config)
        ]
        return any(attestation.passed for attestation in trusted) and any(
            not attestation.passed for attestation in trusted
        )

    @classmethod
    def _duplicate_gate(cls, request: PromotionRequest, gate: str, config: PromotionConfig) -> bool:
        return (
            sum(
                cls._gate_valid(attestation, request, gate, config)
                for attestation in request.gate_attestations
            )
            > 1
        )

    @classmethod
    def _has_invalid_gate_evidence(
        cls, request: PromotionRequest, gate: str, config: PromotionConfig
    ) -> bool:
        return any(
            attestation.gate_name == gate
            and not cls._gate_valid(attestation, request, gate, config)
            for attestation in request.gate_attestations
        )

    @staticmethod
    def _reviewer_valid(
        attestation: ReviewerAttestation, request: PromotionRequest, config: PromotionConfig
    ) -> bool:
        return (
            attestation.reviewer_id in config.reviewer_domains
            and attestation.issuer_id in config.trusted_reviewer_issuers
            and attestation.candidate_digest == request.candidate_digest
            and attestation.base_digest == request.base_digest
            and attestation.valid_from_epoch
            <= config.evaluation_epoch
            <= attestation.valid_until_epoch
        )

    @staticmethod
    def _d(
        request: PromotionRequest,
        outcome: PromotionOutcome,
        risk: RiskClass,
        reasons: list[str],
        quorum: int,
    ) -> PromotionDecision:
        return PromotionDecision(
            candidate_id=request.candidate_id,
            outcome=outcome,
            risk_class=risk,
            reason_codes=reasons,
            required_quorum=quorum,
        )


__all__ = [
    "GateAttestation",
    "PathManifestAttestation",
    "PromotionConfig",
    "PromotionDecision",
    "PromotionOutcome",
    "PromotionPolicy",
    "PromotionRequest",
    "ReviewerAttestation",
    "RiskClass",
    "RollbackAttestation",
    "is_valid_promotion_path",
    "path_manifest_digest",
]
