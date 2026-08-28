"""Run the one-shot AVO-004.5 sanitized integration campaign.

The command is intentionally conservative.  Configuration and evidence are
controller-owned files; the candidate is an ordinary VCS-free directory.  A
preflight (and ``--dry-run``) performs local validation only.  The live path
is kept in this script so the operator has one explicit, resumable entrypoint
while the application ports continue to evolve.

No GitHub credential is ever written to the state root or included in result
JSON.  Git receives it in memory through ``GITHUB_TOKEN`` and an askpass
helper.  The helper contains no secret.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.campaign_journal import CampaignCompletionJournal
from avo_correlate.adapters.artifacts.promotion_journal import IntegrationPromotionJournal
from avo_correlate.adapters.artifacts.synthetic_validation_journal import (
    SyntheticValidationJournal,
)
from avo_correlate.adapters.evidence.campaign_quality import TrustedCampaignQualityAdapter
from avo_correlate.adapters.git import GitCandidatePublisher, GitRepositoryReader
from avo_correlate.adapters.hosted_git import GitHubCampaignProvider, GitHubIntegrationProvider
from avo_correlate.application.integration_campaign_service import (
    CampaignOpened,
    IntegrationCampaignRequest,
    IntegrationCampaignResult,
    IntegrationCampaignService,
    campaign_open_identity,
)
from avo_correlate.application.integration_promotion_service import IntegrationPromotionService
from avo_correlate.application.promotion_service import PromotionController
from avo_correlate.application.synthetic_validation_service import SyntheticValidationService
from avo_correlate.contracts.base import ArtifactRef, Sha256Digest
from avo_correlate.contracts.integration_campaign import IntegrationCampaignEvidencePackage
from avo_correlate.contracts.integration_promotion import CandidatePublicationBinding
from avo_correlate.contracts.promotion_bundle import (
    GitRefSnapshot,
    PromotionBundle,
    PromotionControllerConfig,
    PromotionDryRunInput,
)
from avo_correlate.contracts.promotion_policy import (
    PromotionPolicy,
    RiskClass,
    path_manifest_digest,
)
from avo_correlate.contracts.synthetic_validation import (
    SyntheticValidationCompletionProof,
    SyntheticValidationOutcome,
    SyntheticValidationPlan,
)
from avo_correlate.domain.canonical import canonical_bytes

REMOTE = "https://github.com/vandyand/avo.git"
TARGET_REF = "refs/heads/integration"
MAIN_REF = "refs/heads/main"
MAX_WAIT_SECONDS = 30 * 60
MAX_POLL_SECONDS = 60
TRUSTED_SYNTHETIC_CHECKS: tuple[tuple[str, int], ...] = (
    ("avo synthetic validate (ubuntu-latest)", 15368),
    ("avo synthetic validate (windows-latest)", 15368),
)
# These are GitHub's required status checks on the protected integration head.
# They are intentionally distinct from the exact synthetic-SHA checks above.
PROTECTION_CHECKS: tuple[tuple[str, int], ...] = (
    ("validate (ubuntu-latest)", 15368),
    ("validate (windows-latest)", 15368),
)
# Descriptive alias for callers/tests that refer to the provider boundary.
TRUSTED_PROTECTION_CHECKS = PROTECTION_CHECKS
SYNTHETIC_VALIDATION_MAX_AGE = timedelta(hours=1)
EVIDENCE_ROLES = (
    "private-regression",
    "provenance-reconstruction",
    "integration-soak",
    "reviewer-decision-1",
    "reviewer-decision-2",
    "rollback-proof",
)


class CampaignRunnerError(RuntimeError):
    """A bounded, fail-closed runner error."""


@dataclass(frozen=True, slots=True)
class CampaignRunnerConfig:
    state_root: Path
    repository_root: Path
    candidate_root: Path
    evidence_root: Path
    controller_config: Path
    candidate_id: str
    proposer_id: str
    trusted_checks: tuple[tuple[str, int], ...] = field(
        default=TRUSTED_SYNTHETIC_CHECKS, init=False
    )
    protection_checks: tuple[tuple[str, int], ...] = field(
        default=PROTECTION_CHECKS, init=False
    )
    freshness_cutoff: datetime = field(init=False)
    wait_seconds: int = MAX_WAIT_SECONDS
    poll_seconds: int = 15
    dry_run: bool = False
    preflight: bool = False
    remote: str = REMOTE
    target_ref: str = TARGET_REF
    _trusted_clock: Callable[[], datetime] = field(
        default=lambda: datetime.now(UTC), repr=False, compare=False
    )

    def __post_init__(self) -> None:
        now = self._trusted_clock()
        if now.tzinfo is None:
            raise CampaignRunnerError("trusted clock must be timezone-aware")
        object.__setattr__(self, "freshness_cutoff", now - SYNTHETIC_VALIDATION_MAX_AGE)

    def validate(self) -> None:
        if self.remote != REMOTE:
            raise CampaignRunnerError("remote is fixed to the public AVO repository")
        if self.target_ref != TARGET_REF:
            raise CampaignRunnerError("target is fixed to refs/heads/integration")
        if not self.candidate_id.strip() or not self.proposer_id.strip():
            raise CampaignRunnerError("candidate and proposer IDs are required")
        if self.trusted_checks != TRUSTED_SYNTHETIC_CHECKS:
            raise CampaignRunnerError("trusted synthetic checks are controller-pinned")
        if self.protection_checks != PROTECTION_CHECKS:
            raise CampaignRunnerError("protected head checks are controller-pinned")
        if self.wait_seconds < 0 or self.wait_seconds > MAX_WAIT_SECONDS:
            raise CampaignRunnerError("wait_seconds is outside the bounded limit")
        if self.poll_seconds <= 0 or self.poll_seconds > MAX_POLL_SECONDS:
            raise CampaignRunnerError("poll_seconds is outside the bounded limit")
        if self.freshness_cutoff.tzinfo is None:
            raise CampaignRunnerError("derived freshness cutoff must be timezone-aware")
        roots = {
            "state": self.state_root.resolve(),
            "repository": self.repository_root.resolve(),
            "candidate": self.candidate_root.resolve(),
            "evidence": self.evidence_root.resolve(),
        }
        if roots["state"] == roots["repository"] or roots["state"].is_relative_to(
            roots["repository"]
        ):
            raise CampaignRunnerError("state root must not be inside the trusted repository")
        if roots["candidate"] == roots["repository"] or roots["candidate"].is_relative_to(
            roots["repository"]
        ):
            raise CampaignRunnerError("candidate must not be inside the trusted repository")
        if roots["candidate"] == roots["state"] or roots["candidate"].is_relative_to(
            roots["state"]
        ):
            raise CampaignRunnerError("candidate must not be inside the controller state root")
        if roots["evidence"] == roots["candidate"] or roots["evidence"].is_relative_to(
            roots["candidate"]
        ):
            raise CampaignRunnerError("evidence must not be inside the candidate")


@dataclass(frozen=True, slots=True)
class PreflightResult:
    candidate_digest: Sha256Digest
    base_digest: Sha256Digest
    base_commit: str
    base_tree: str
    changed_paths: tuple[str, ...]
    evidence_files: tuple[str, ...]
    remote_mutations: tuple[str, ...] = ()

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "state": "preflight",
            "remote": REMOTE,
            "target_ref": TARGET_REF,
            "candidate_digest": self.candidate_digest,
            "base_digest": self.base_digest,
            "base_commit": self.base_commit,
            "base_tree": self.base_tree,
            "changed_paths": list(self.changed_paths),
            "evidence_files": list(self.evidence_files),
            "remote_mutations": list(self.remote_mutations),
        }


class _TokenPublisher(GitCandidatePublisher):
    """Publisher wiring that keeps the token in memory only.

    The lower-level publisher deliberately uses a minimal subprocess
    environment.  This subclass supplies the process-local token required by
    the generated askpass helper without changing the shared adapter API.
    """

    def _environment(self) -> dict[str, str]:
        environment = super()._environment()
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            raise CampaignRunnerError("GITHUB_TOKEN is required for live publication")
        environment["GITHUB_TOKEN"] = token
        return environment


class _EvidenceResolver:
    """Resolve controller evidence plus artifacts emitted by the controller."""

    def __init__(self, known: Mapping[str, ArtifactRef], store: FilesystemArtifactStore) -> None:
        self._known = dict(known)
        self._store = store

    def add(self, reference: ArtifactRef, data: bytes | None = None) -> None:
        self._known[reference.digest] = reference
        if data is not None:
            stored = self._store.put_bytes(
                data,
                media_type=reference.media_type,
                role=reference.role,
                max_bytes=128 * 1024,
            )
            if stored.digest != reference.digest or stored.size_bytes != reference.size_bytes:
                raise CampaignRunnerError("evidence artifact was not durably materialized")

    def read(self, reference: ArtifactRef) -> bytes:
        data = self._store.read_bytes(reference)
        if _digest_bytes(data) != reference.digest or len(data) != reference.size_bytes:
            raise CampaignRunnerError("evidence artifact bytes do not match its reference")
        return data

    def resolve(self, digests: Sequence[str]) -> tuple[ArtifactRef, ...]:
        if tuple(digests) != tuple(sorted(set(digests))):
            raise CampaignRunnerError("evidence digest list is not sorted and unique")
        result: list[ArtifactRef] = []
        for digest in digests:
            reference = self._known.get(digest)
            if reference is None:
                path = self._store.path_for_digest(digest)
                if not path.is_file():
                    raise CampaignRunnerError(f"evidence artifact is unavailable: {digest}")
                data = path.read_bytes()
                reference = ArtifactRef(
                    digest=digest,
                    size_bytes=len(data),
                    media_type="application/json",
                    role="controller-derived-evidence",
                    created_at=datetime.now(UTC),
                )
            self.read(reference)
            result.append(reference)
        return tuple(result)


def _store_derived_artifact(
    store: FilesystemArtifactStore, data: bytes, *, expected_digest: str, role: str
) -> ArtifactRef:
    if _digest_bytes(data) != expected_digest:
        raise CampaignRunnerError(f"derived {role} digest does not match trusted observation")
    reference = store.put_bytes(
        data,
        media_type="application/json",
        role=role,
        max_bytes=128 * 1024,
    )
    if reference.digest != expected_digest:
        raise CampaignRunnerError(f"derived {role} was not content-addressed")
    return reference


def _materialize_controller_evidence(
    store: FilesystemArtifactStore,
    snapshot: GitRefSnapshot,
    candidate_digest: str,
    changed_paths: Sequence[str],
) -> tuple[ArtifactRef, ArtifactRef]:
    base_payload = {
        "candidate_digest": candidate_digest,
        "snapshot": snapshot.model_dump(mode="json"),
    }
    base_data = canonical_bytes(base_payload)
    base_ref = _store_derived_artifact(
        store,
        base_data,
        expected_digest=_digest_bytes(base_data),
        role="controller-base-evidence",
    )
    path_payload = {
        "candidate_digest": candidate_digest,
        "base_digest": snapshot.source_tree_digest,
        "path_manifest_digest": path_manifest_digest(list(changed_paths)),
    }
    path_data = canonical_bytes(path_payload)
    path_ref = _store_derived_artifact(
        store,
        path_data,
        expected_digest=_digest_bytes(path_data),
        role="controller-path-evidence",
    )
    return base_ref, path_ref


def _digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def redact_secret(value: str, secret: str | None = None) -> str:
    """Remove a process credential from diagnostics before they leave memory."""

    if secret:
        return value.replace(secret, "[REDACTED]")
    return value


def _artifact_from_bytes(data: bytes, role: str) -> ArtifactRef:
    return ArtifactRef(
        digest=_digest_bytes(data),
        size_bytes=len(data),
        media_type="application/json",
        role=role,
        created_at=datetime.now(UTC),
    )


def load_evidence(root: Path) -> tuple[dict[str, tuple[ArtifactRef, bytes]], tuple[str, ...]]:
    """Load exactly one canonical JSON artifact for each ordinary gate role."""

    if not root.is_dir():
        raise CampaignRunnerError(f"evidence root is not a directory: {root}")
    files: dict[str, tuple[ArtifactRef, bytes]] = {}
    names: list[str] = []
    for role in EVIDENCE_ROLES:
        matches = sorted(root.glob(f"{role}.json"))
        if len(matches) != 1:
            raise CampaignRunnerError(f"expected exactly one evidence file named {role}.json")
        path = matches[0]
        data = path.read_bytes()
        if len(data) > 128 * 1024:
            raise CampaignRunnerError(f"evidence file exceeds bounded size: {path.name}")
        try:
            parsed = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CampaignRunnerError(f"evidence file is not UTF-8 JSON: {path.name}") from exc
        if not isinstance(parsed, dict) or canonical_bytes(parsed) != data:
            raise CampaignRunnerError(f"evidence file is not canonical JSON: {path.name}")
        reference = _artifact_from_bytes(data, role)
        files[reference.digest] = (reference, data)
        names.append(path.name)
    return files, tuple(names)


def _askpass_path(state_root: Path) -> Path:
    """Create a secret-free askpass helper in the controller state root."""

    state_root.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        path = state_root / "github-askpass.cmd"
        data = (
            "@echo off\r\n"
            "set \"AVO_ASKPASS_PROMPT=%~1\"\r\n"
            "powershell.exe -NoProfile -NonInteractive -Command \"$p = "
            "[Environment]::GetEnvironmentVariable('AVO_ASKPASS_PROMPT'); if ($p "
            "-match '(?i)username') { [Console]::Out.WriteLine('x-access-token'); "
            "exit 0 }; if ($p -match '(?i)password') { "
            "[Console]::Out.WriteLine([Environment]::GetEnvironmentVariable('GITHUB_TOKEN')); "
            "exit 0 }; exit 1\"\r\n"
            "exit /b %errorlevel%\r\n"
        )
    else:
        path = state_root / "github-askpass.sh"
        data = (
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  *[Uu]sername*) printf '%s\\n' 'x-access-token' ;;\n"
            "  *[Pp]assword*) printf '%s\\n' \"$GITHUB_TOKEN\" ;;\n"
            "  *) exit 1 ;;\n"
            "esac\n"
        )
    path.write_text(data, encoding="utf-8", newline="")
    if os.name != "nt":
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return path


def askpass_path(state_root: Path) -> Path:
    """Public test/operator hook for creating the secret-free askpass path."""

    return _askpass_path(state_root)


def preflight(config: CampaignRunnerConfig) -> PreflightResult:
    """Perform bounded local checks; this function cannot call GitHub writes."""

    config.validate()
    if not config.repository_root.is_dir():
        raise CampaignRunnerError("repository root does not exist")
    if not config.candidate_root.is_dir():
        raise CampaignRunnerError("candidate root does not exist")
    if not config.controller_config.is_file():
        raise CampaignRunnerError("controller config does not exist")
    if not config.dry_run and not config.preflight and not os.environ.get("GITHUB_TOKEN"):
        raise CampaignRunnerError("GITHUB_TOKEN is required for live execution")
    reader = GitRepositoryReader(
        config.repository_root,
        TARGET_REF,
        REMOTE,
        "sha256:" + "0" * 64,
        10 * 1024 * 1024,
        100 * 1024 * 1024,
    )
    snapshot = reader.snapshot()
    comparison = reader.compare_candidate(config.candidate_root, snapshot)
    comparison_any = cast(Any, comparison)
    try:
        risk = PromotionPolicy.derive_risk(list(comparison_any.changed_paths))
    except ValueError as exc:
        raise CampaignRunnerError("candidate changed paths failed canonical validation") from exc
    if risk in {RiskClass.CONSTITUTIONAL, RiskClass.PRODUCTION}:
        raise CampaignRunnerError(
            "candidate changes trusted authority paths; live campaign is blocked "
            f"before hosted writes (risk={risk.value})"
        )
    return PreflightResult(
        candidate_digest=comparison_any.candidate_digest,
        base_digest=snapshot.source_tree_digest,
        base_commit=snapshot.commit,
        base_tree=snapshot.tree,
        changed_paths=tuple(comparison_any.changed_paths),
        evidence_files=(),
    )


def _load_config(path: Path) -> PromotionControllerConfig:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or canonical_bytes(raw) != path.read_bytes():
            raise CampaignRunnerError("controller config must be canonical JSON")
        return PromotionControllerConfig.model_validate(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CampaignRunnerError("controller config is invalid") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--controller-config", type=Path, required=True)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--proposer-id", required=True)
    parser.add_argument("--wait-seconds", type=int, default=MAX_WAIT_SECONDS)
    parser.add_argument("--poll-seconds", type=int, default=15)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    return parser


def _config_from_args(args: argparse.Namespace) -> CampaignRunnerConfig:
    return CampaignRunnerConfig(
        state_root=args.state_root,
        repository_root=args.repository_root,
        candidate_root=args.candidate_root,
        evidence_root=args.evidence_root,
        controller_config=args.controller_config,
        candidate_id=args.candidate_id,
        proposer_id=args.proposer_id,
        wait_seconds=args.wait_seconds,
        poll_seconds=args.poll_seconds,
        dry_run=args.dry_run,
        preflight=args.preflight,
    )


def _write_result(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(dict(payload)))


def write_result(path: Path, payload: Mapping[str, object]) -> None:
    """Write one canonical local result record."""

    _write_result(path, payload)


def _wait_static_evidence(
    config: CampaignRunnerConfig, context: Mapping[str, object]
) -> tuple[dict[str, tuple[ArtifactRef, bytes]], tuple[str, ...]]:
    context_path = config.state_root / "discovery-context.json"
    _write_result(context_path, context)
    deadline = time.monotonic() + config.wait_seconds
    last_error: Exception | None = None
    while True:
        try:
            return load_evidence(config.evidence_root)
        except (CampaignRunnerError, OSError) as exc:
            last_error = exc
            if time.monotonic() >= deadline:
                raise CampaignRunnerError(
                    "controller-owned static evidence did not become ready within the bound"
                ) from last_error
            time.sleep(min(config.poll_seconds, max(0.0, deadline - time.monotonic())))


def _result_payload(
    result: IntegrationCampaignResult,
    cleanup: SyntheticValidationOutcome | Mapping[str, object] | None = None,
) -> dict[str, object]:
    result_any = cast(Any, result)
    payload: dict[str, object] = {
        "schema_version": 1,
        "state": "completed" if result_any.package is not None else "report",
        "report": result_any.report.model_dump(mode="json"),
    }
    if result_any.package is not None:
        payload["operation_id"] = result_any.package.intent.operation_id
        payload["package_digest"] = (
            result_any.package_artifact.digest if result_any.package_artifact else None
        )
    if cleanup is not None:
        payload["synthetic_validation_cleanup"] = (
            cast(Any, cleanup).model_dump(mode="json")
            if isinstance(cleanup, SyntheticValidationOutcome)
            else dict(cleanup)
        )
    return payload


def _record_cleanup_state(
    config: CampaignRunnerConfig, cleanup: SyntheticValidationOutcome | Mapping[str, object]
) -> None:
    cleanup_any = cast(Any, cleanup)
    _write_result(
        config.state_root / "synthetic-validation-cleanup.json",
        {
            "schema_version": 1,
            "synthetic_validation_cleanup": (
                cleanup_any.model_dump(mode="json")
                if isinstance(cleanup, SyntheticValidationOutcome)
                else dict(cleanup)
            ),
        },
    )


def _read_cleanup_state(config: CampaignRunnerConfig) -> Mapping[str, object] | None:
    path = config.state_root / "synthetic-validation-cleanup.json"
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise CampaignRunnerError("synthetic validation cleanup state is malformed") from exc
    if not isinstance(raw, dict):
        raise CampaignRunnerError("synthetic validation cleanup state is malformed")
    raw_mapping = cast(dict[str, object], raw)
    if not isinstance(raw_mapping.get("synthetic_validation_cleanup"), dict):
        raise CampaignRunnerError("synthetic validation cleanup state is malformed")
    return cast(Mapping[str, object], raw_mapping["synthetic_validation_cleanup"])


def _validation_plan_for_package(
    journal: SyntheticValidationJournal, package: Any
) -> SyntheticValidationPlan | None:
    """Find the one validation plan bound to a durable campaign package."""
    plan_root = journal.root / "synthetic-validation-index" / "plan"
    if not plan_root.is_dir():
        return None
    matches: list[SyntheticValidationPlan] = []
    package_any = package
    observation = package_any.observation
    expected_identity = campaign_open_identity(
        package_any.publication,
        CampaignOpened(
            pull_request_number=observation.pull_request_number,
            pull_request_url=observation.pull_request_url,
            target_ref=observation.base_ref,
            base_commit=observation.base_commit,
            base_tree=observation.base_tree,
            open_identity="sha256:" + "0" * 64,
        ),
    )
    for index in plan_root.glob("*.json"):
        operation_id = "sha256:" + index.stem
        if len(index.stem) != 64:
            continue
        try:
            loaded = journal.read_plan(operation_id)
        except (ValueError, RuntimeError, OSError):
            continue
        if loaded is None:
            continue
        plan, _reference = loaded
        plan_any = cast(Any, plan)
        request = plan_any.request
        observed = request.observation
        if (
            observed.repository_digest == package_any.publication.repository_digest
            and observed.base_ref == observation.base_ref
            and observed.base_commit == observation.base_commit
            and observed.base_tree == observation.base_tree
            and observed.head_ref == observation.head_ref
            and observed.head_commit == observation.head_commit
            and observed.head_tree == observation.candidate_tree
            and observed.synthetic_commit == observation.synthetic_merge_commit
            and observed.synthetic_tree == observation.synthetic_merge_tree
            and request.target_ref == observation.base_ref
            and request.target_identity == expected_identity
        ):
            matches.append(plan)
    if len(matches) > 1:
        raise CampaignRunnerError("multiple synthetic validation plans match completed campaign")
    return matches[0] if matches else None


class _DurableCompletionProofVerifier:
    """Bind validation cleanup to a verified campaign package artifact."""

    def __init__(self, journal: CampaignCompletionJournal) -> None:
        self._journal = journal

    def verify(
        self,
        plan: SyntheticValidationPlan,
        proof: SyntheticValidationCompletionProof,
    ) -> None:
        matches: list[IntegrationCampaignEvidencePackage] = []
        for operation_id in self._journal.list_plan_operations():
            loaded = self._journal.read_package(operation_id)
            if loaded is None:
                continue
            package, package_ref = loaded
            if package_ref.digest != proof.completion_digest:
                continue
            if _package_binds_validation_plan(package, plan):
                matches.append(package)
        if len(matches) != 1:
            raise CampaignRunnerError(
                "completion proof does not identify exactly one matching durable package"
            )


def _package_binds_validation_plan(
    package: IntegrationCampaignEvidencePackage, plan: SyntheticValidationPlan
) -> bool:
    observation = package.observation
    expected = plan.request.observation
    if (
        observation.repository_digest != plan.request.target_repository_digest
        or observation.base_ref != plan.request.target_ref
        or observation.base_commit != expected.base_commit
        or observation.base_tree != expected.base_tree
        or observation.head_ref != expected.head_ref
        or observation.head_commit != expected.head_commit
        or observation.candidate_tree != expected.head_tree
        or observation.synthetic_merge_commit != plan.expected_commit
        or observation.synthetic_merge_tree != plan.expected_tree
        or package.publication.repository_digest != plan.request.target_repository_digest
        or package.publication.base_commit != expected.base_commit
        or package.publication.base_tree != expected.base_tree
        or package.publication.candidate_ref != expected.head_ref
        or package.publication.candidate_commit != expected.head_commit
        or package.publication.candidate_tree != expected.head_tree
        or package.intent.target_ref != plan.request.target_ref
        or package.intent.synthetic_merge_commit != plan.expected_commit
        or package.intent.synthetic_merge_tree != plan.expected_tree
    ):
        return False
    opened = CampaignOpened(
        pull_request_number=package.intent.pull_request_number,
        pull_request_url=package.intent.pull_request_url,
        target_ref=package.intent.target_ref,
        base_commit=package.intent.base_commit,
        base_tree=package.intent.base_tree,
        open_identity="sha256:" + "0" * 64,
    )
    return plan.request.target_identity == campaign_open_identity(package.publication, opened)


def _cleanup_completed_validation(
    config: CampaignRunnerConfig,
    validation_service: SyntheticValidationService,
    plan: SyntheticValidationPlan | None,
    result: IntegrationCampaignResult,
) -> SyntheticValidationOutcome | Mapping[str, object] | None:
    """Clean only after the package artifact is durably indexed."""
    result_any = cast(Any, result)
    if result_any.package is None or result_any.package_artifact is None or plan is None:
        return None
    proof = SyntheticValidationCompletionProof(
        operation_id=plan.operation_id,
        plan_digest=plan.plan_digest,
        completion_digest=result_any.package_artifact.digest,
    )
    try:
        cleanup = validation_service.cleanup(plan, proof)
    except (ValueError, RuntimeError, OSError) as exc:
        cleanup = {
            "state": "cleanup_required",
            "operation_id": plan.operation_id,
            "plan_digest": plan.plan_digest,
            "error": str(exc),
        }
        _record_cleanup_state(config, cleanup)
        return cleanup
    _record_cleanup_state(config, cleanup)
    return cleanup


def _cleanup_recovered_validation(
    config: CampaignRunnerConfig,
    service: IntegrationCampaignService,
    result: IntegrationCampaignResult,
) -> SyntheticValidationOutcome | Mapping[str, object] | None:
    wiring = cast(
        tuple[object, object] | None, getattr(service, "_synthetic_validation", None)
    )
    if not isinstance(wiring, tuple) or len(wiring) != 2:
        return None
    validation_service, validation_journal = wiring
    if not isinstance(validation_service, SyntheticValidationService) or not isinstance(
        validation_journal, SyntheticValidationJournal
    ):
        raise CampaignRunnerError("synthetic validation recovery wiring is malformed")
    result_any = cast(Any, result)
    plan = (
        _validation_plan_for_package(validation_journal, result_any.package)
        if result_any.package
        else None
    )
    return _cleanup_completed_validation(config, validation_service, plan, result)


def _build_recovery_service(
    config: CampaignRunnerConfig,
) -> IntegrationCampaignService:
    """Build only the read/reconciliation wiring for a durable campaign.

    This function intentionally does not construct a publisher or campaign
    provider.  It is called before preflight, because the trusted integration
    base may already have advanced after the hosted merge.
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise CampaignRunnerError("GITHUB_TOKEN is required for live recovery")
    artifact_store = FilesystemArtifactStore(config.state_root / "artifacts")
    journal = IntegrationPromotionJournal(
        config.state_root / "promotion", artifact_store=artifact_store
    )
    completion = CampaignCompletionJournal(
        config.state_root / "completion", artifact_store=artifact_store
    )
    provider = GitHubIntegrationProvider(
        owner="vandyand",
        repo="avo",
        repository_digest=preflight_repository_digest(),
        target_ref=TARGET_REF,
        trusted_checks=config.trusted_checks,
        protection_checks=config.protection_checks,
        freshness_cutoff=config.freshness_cutoff,
        token=token,
    )
    validation_journal = SyntheticValidationJournal(
        config.state_root / "synthetic-validation", artifact_store=artifact_store
    )
    validation_service = SyntheticValidationService(
        provider,
        validation_journal,
        completion_proof_verifier=_DurableCompletionProofVerifier(completion),
    )
    campaign_provider = GitHubCampaignProvider(
        provider, validation_service=validation_service
    )

    def recovery_publication_verifier(
        binding: CandidatePublicationBinding, bundle: PromotionBundle
    ) -> bool:
        return (
            binding.repository_digest == preflight_repository_digest()
            and bundle.snapshot.repository_digest == binding.repository_digest
            and bundle.snapshot.target_ref == TARGET_REF
            and bundle.request.candidate_digest == binding.candidate_digest
        )

    promotion = IntegrationPromotionService(
        cast(Any, object()),
        cast(Any, object()),
        provider,
        cast(Any, journal),
        recovery_publication_verifier,
    )
    service = IntegrationCampaignService(
        controller=cast(Any, object()),
        promotion=promotion,
        journal=cast(Any, journal),
        intake=cast(Any, object()),
        quality=cast(Any, object()),
        provider=campaign_provider,
        publication_verifier=cast(Any, recovery_publication_verifier),
        evidence_resolver=cast(Any, object()),
        artifact_writer=artifact_store,
        main_state=_GithubMainState(provider),
        trusted_config=cast(Any, object()),
        completion_journal=completion,
    )
    # Recovery has no PR-open stage from which to recover the plan in memory;
    # the runner resolves it from the durable validation journal after package
    # finalization.  Keep the read-only cleanup wiring beside the service.
    cast(Any, service)._synthetic_validation = validation_service, validation_journal
    return service


def _recover_before_preflight(config: CampaignRunnerConfig) -> IntegrationCampaignResult | None:
    """Recover the one durable campaign before reading the mutable checkout."""
    artifact_store = FilesystemArtifactStore(config.state_root / "artifacts")
    completion = CampaignCompletionJournal(
        config.state_root / "completion", artifact_store=artifact_store
    )
    operations = completion.list_plan_operations()
    if not operations:
        return None
    if len(operations) != 1:
        raise CampaignRunnerError(
            "multiple durable campaign plans require manual reconciliation"
        )
    service = _build_recovery_service(config)
    operation_id = operations[0]
    if completion.read_package(operation_id) is not None:
        # Finalize revalidates the package against its durable plan and releases
        # a lease left behind by a crash after package indexing.  It performs no
        # hosted mutation for an already-completed operation.
        result = service.finalize(operation_id)
        _cleanup_recovered_validation(config, service, result)
        return result
    if completion.read_final_evidence(operation_id) is not None:
        # Final evidence is written before the package index.  A crash in that
        # interval is a normal recovery state, and finalize() deliberately
        # reuses the durable evidence without another hosted mutation.
        result = service.finalize(operation_id)
        _cleanup_recovered_validation(config, service, result)
        return result
    result = service.resume(operation_id)
    _cleanup_recovered_validation(config, service, result)
    return result


recover_before_preflight = _recover_before_preflight


def _build_live(config: CampaignRunnerConfig, pre: PreflightResult) -> IntegrationCampaignResult:
    """Build and execute the real application wiring after local preflight."""

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise CampaignRunnerError("GITHUB_TOKEN is required for live execution")
    askpass = _askpass_path(config.state_root)
    controller_config = _load_config(config.controller_config)
    artifact_store = FilesystemArtifactStore(config.state_root / "artifacts")
    repository = GitRepositoryReader(
        config.repository_root,
        TARGET_REF,
        REMOTE,
        "sha256:" + "0" * 64,
        10 * 1024 * 1024,
        100 * 1024 * 1024,
    )
    publication_journal = __import__(
        "avo_correlate.adapters.git", fromlist=["FilesystemPublicationJournal"]
    ).FilesystemPublicationJournal(config.state_root / "publication")
    publisher = _TokenPublisher(
        expected_remote=REMOTE,
        repository_digest=preflight_repository_digest(),
        controller_publisher_identity=controller_config.controller_identity,
        publication_journal=publication_journal,
        credential_helper=askpass,
    )
    publication_result = publisher.publish_result(
        config.candidate_root, pre.base_commit, pre.base_tree, pre.candidate_digest
    )
    publication = publication_result.binding

    def publication_verifier(
        binding: CandidatePublicationBinding, bundle: PromotionBundle
    ) -> bool:
        return (
            binding == publication
            and binding.verified
            and bundle.request.candidate_digest == binding.candidate_digest
        )

    provider = GitHubIntegrationProvider(
        owner="vandyand",
        repo="avo",
        repository_digest=preflight_repository_digest(),
        target_ref=TARGET_REF,
        trusted_checks=config.trusted_checks,
        protection_checks=config.protection_checks,
        freshness_cutoff=config.freshness_cutoff,
        token=token,
    )
    validation_journal = SyntheticValidationJournal(
        config.state_root / "synthetic-validation", artifact_store=artifact_store
    )
    completion = CampaignCompletionJournal(
        config.state_root / "completion", artifact_store=artifact_store
    )
    validation_service = SyntheticValidationService(
        provider,
        validation_journal,
        completion_proof_verifier=_DurableCompletionProofVerifier(completion),
    )
    campaign_provider = GitHubCampaignProvider(
        provider, validation_service=validation_service
    )
    bounded_provider = _BoundedCampaignProvider(campaign_provider, config, artifact_store)
    authorized_evidence: set[str] = set()
    protection_digest: str | None = None
    resolver_for_service = _EvidenceResolver(
        {publication_result.evidence_artifact.digest: publication_result.evidence_artifact},
        artifact_store,
    )
    resolver_for_service.add(
        publication_result.evidence_artifact, publication_result.evidence_bytes
    )

    class LazyQuality:
        """Construct quality validation only after hosted discovery is exact."""

        def evaluate(
            self,
            request: IntegrationCampaignRequest,
            intake: PromotionDryRunInput,
            discovery: Any,
        ) -> Any:
            nonlocal protection_digest
            if bounded_provider.trusted_ci_artifact is None:
                raise CampaignRunnerError("provider trusted-CI evidence was not captured")
            if bounded_provider.protection_artifact is None:
                raise CampaignRunnerError("provider protection evidence was not captured")
            protection_digest = discovery.observation.protection_evidence_digest
            repository.protection_evidence_digest = discovery.observation.protection_evidence_digest
            static_evidence, _names = _wait_static_evidence(
                config,
                {
                    "schema_version": 1,
                    "candidate_digest": publication.candidate_digest,
                    "base_digest": pre.base_digest,
                    "pull_request_number": discovery.observation.pull_request_number,
                    "synthetic_merge_commit": discovery.observation.synthetic_merge_commit,
                    "synthetic_merge_tree": discovery.observation.synthetic_merge_tree,
                    "protection_evidence_digest": protection_digest,
                    "check_evidence_manifest_digest": (
                        discovery.observation.check_evidence_manifest_digest
                    ),
                },
            )
            static_refs = tuple(reference for reference, _ in static_evidence.values())
            for reference, data in static_evidence.values():
                resolver_for_service.add(reference, data)
            ci_ref, ci_data = bounded_provider.trusted_ci_artifact
            authorized_evidence.add(ci_ref.digest)
            resolver_for_service.add(ci_ref, ci_data)
            resolver_for_service.add(bounded_provider.protection_artifact)
            authorized_evidence.update(reference.digest for reference in static_refs)
            authorized_evidence.add(bounded_provider.protection_artifact.digest)
            base_ref, path_ref = _materialize_controller_evidence(
                artifact_store,
                repository.snapshot(),
                publication.candidate_digest,
                pre.changed_paths,
            )
            resolver_for_service.add(base_ref)
            resolver_for_service.add(path_ref)
            adapter = TrustedCampaignQualityAdapter(
                resolver=resolver_for_service,
                trusted_config=controller_config,
                evidence_artifacts=(*static_refs, ci_ref),
                base_digest=pre.base_digest,
            )
            return adapter.evaluate(request, intake, discovery)

    quality = LazyQuality()
    controller = PromotionController(
        repository,
        lambda digest, candidate, base: digest == publication.publication_evidence_digest
        and candidate == publication.candidate_digest,
        lambda digest, issuer, candidate, base: (
            digest in authorized_evidence
            or digest == protection_digest
        )
        and bool(issuer and candidate and base),
        artifact_store,
        trusted_config=controller_config,
        trusted_repository_root=config.repository_root,
        trusted_artifact_root=artifact_store.root,
    )
    journal = IntegrationPromotionJournal(
        config.state_root / "promotion", artifact_store=artifact_store
    )
    completion = CampaignCompletionJournal(
        config.state_root / "completion", artifact_store=artifact_store
    )
    promotion = IntegrationPromotionService(
        controller,
        repository,
        provider,
        cast(Any, journal),
        publication_verifier,
    )

    class Intake:
        def collect(self, request: IntegrationCampaignRequest) -> PromotionDryRunInput:
            return PromotionDryRunInput(
                candidate_id=request.candidate_id,
                proposer_id=request.proposer_id,
                candidate_digest=publication.candidate_digest,
                source_provenance_digest=publication.publication_evidence_digest,
                evidence_digests=[publication.publication_evidence_digest],
            )

    service = IntegrationCampaignService(
        controller=controller,
        promotion=promotion,
        journal=cast(Any, journal),
        intake=Intake(),
        quality=quality,
        provider=bounded_provider,
        publication_verifier=cast(Any, publication_verifier),
        evidence_resolver=resolver_for_service,
        artifact_writer=artifact_store,
        main_state=_GithubMainState(provider),
        trusted_config=controller_config,
        completion_journal=completion,
    )
    request = IntegrationCampaignRequest(
        candidate_root=config.candidate_root,
        candidate_id=config.candidate_id,
        proposer_id=config.proposer_id,
        source_provenance_digest=publication.publication_evidence_digest,
    )
    result = service.run(request, publication=publication)
    _cleanup_completed_validation(
        config,
        validation_service,
        cast(SyntheticValidationPlan | None, getattr(campaign_provider, "validation_plan", None)),
        result,
    )
    return result


class _BoundedCampaignProvider:
    """Keep hosted discovery inside the service while adding a hard timeout."""

    def __init__(
        self,
        provider: GitHubCampaignProvider,
        config: CampaignRunnerConfig,
        artifact_store: FilesystemArtifactStore,
    ) -> None:
        self._provider = provider
        self._config = config
        self._artifact_store = artifact_store
        self.trusted_ci_artifact: tuple[ArtifactRef, bytes] | None = None
        self.protection_artifact: ArtifactRef | None = None

    def open_or_reconcile(self, publication: CandidatePublicationBinding) -> Any:
        return self._provider.open_or_reconcile(publication)

    def discover(self, opened: Any, publication: CandidatePublicationBinding) -> Any:
        deadline = time.monotonic() + self._config.wait_seconds
        last_error: Exception | None = None
        while True:
            try:
                discovery, evidence = self._provider.discover_with_evidence(
                    opened, publication
                )
                evidence_any = cast(Any, evidence)
                check_data = canonical_bytes(evidence_any.check_evidence_manifest)
                protection_data = canonical_bytes(evidence_any.protection_evidence)
                check_ref = _artifact_from_bytes(check_data, "trusted-ci-check-manifest")
                if check_ref.digest != discovery.observation.check_evidence_manifest_digest:
                    raise CampaignRunnerError(
                        "provider check manifest digest changed during discovery"
                    )
                protection_ref = _store_derived_artifact(
                    self._artifact_store,
                    protection_data,
                    expected_digest=discovery.observation.protection_evidence_digest,
                    role="provider-protection-evidence",
                )
                self.trusted_ci_artifact = (check_ref, check_data)
                self.protection_artifact = protection_ref
                return discovery
            except (ValueError, RuntimeError, OSError) as exc:
                last_error = exc
                if time.monotonic() >= deadline:
                    raise CampaignRunnerError(
                        "trusted hosted checks did not become ready within the bound"
                    ) from last_error
                time.sleep(min(self._config.poll_seconds, max(0.0, deadline - time.monotonic())))

    def bind(
        self,
        publication: CandidatePublicationBinding,
        bundle: PromotionBundle,
        bundle_digest: str,
        opened: Any,
        discovery: Any,
    ) -> Any:
        return self._provider.bind(publication, bundle, bundle_digest, opened, discovery)

    def final_evidence(
        self, intent: Any, report: Any, observation: Any
    ) -> Any:
        return self._provider.final_evidence(intent, report, observation)


def _wait_discovery(
    campaign_provider: GitHubCampaignProvider,
    opened: Any,
    publication: CandidatePublicationBinding,
    config: CampaignRunnerConfig,
) -> Any:
    deadline = time.monotonic() + config.wait_seconds
    last_error: Exception | None = None
    while True:
        try:
            return campaign_provider.discover(opened, publication)
        except (ValueError, RuntimeError, OSError) as exc:
            last_error = exc
            if time.monotonic() >= deadline:
                raise CampaignRunnerError(
                    "trusted hosted checks did not become ready within the bound"
                ) from last_error
            time.sleep(min(config.poll_seconds, max(0.0, deadline - time.monotonic())))


wait_discovery = _wait_discovery


def preflight_repository_digest() -> str:
    return "sha256:" + hashlib.sha256(REMOTE.encode("utf-8")).hexdigest()


class _GithubMainState:
    def __init__(self, provider: GitHubIntegrationProvider) -> None:
        self._provider = provider

    def head_commit(self) -> str:
        provider = cast(Any, self._provider)
        raw_value = provider._call("GET", provider._path("git/ref/heads/main"))
        raw = cast(dict[str, object], raw_value)
        if not isinstance(raw.get("object"), dict):
            raise CampaignRunnerError("malformed main ref response")
        sha = cast(dict[str, object], raw["object"]).get("sha")
        if not isinstance(sha, str):
            raise CampaignRunnerError("malformed main SHA")
        return sha


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        config = _config_from_args(args)
        config.validate()
        if not config.preflight and not config.dry_run:
            recovered = _recover_before_preflight(config)
            if recovered is not None:
                payload = _result_payload(recovered, _read_cleanup_state(config))
                _write_result(config.state_root / "result.json", payload)
                print(json.dumps(payload, sort_keys=True))
                return 0
        pre = preflight(config)
        result_path = config.state_root / "result.json"
        if config.preflight or config.dry_run:
            _write_result(result_path, pre.payload())
            print(json.dumps(pre.payload(), sort_keys=True))
            return 0
        result = _build_live(config, pre)
        payload = _result_payload(result, _read_cleanup_state(config))
        _write_result(result_path, payload)
        print(json.dumps(payload, sort_keys=True))
        return 0
    except (CampaignRunnerError, ValueError, OSError) as exc:
        message = str(exc)
        message = redact_secret(message, os.environ.get("GITHUB_TOKEN"))
        print(f"campaign blocked: {message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
