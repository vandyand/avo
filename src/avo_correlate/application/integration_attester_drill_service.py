"""Deterministic AVO-004.6 case-8 attester boundary drill.

Case 8 is intentionally a leaf of the integration drill.  It does not invoke
the promotion controller or mutate a protected branch.  Instead it joins the
two boundaries that must agree before a hosted check can be trusted:

* :class:`SyntheticValidationService` creates and reconciles one exact
  synthetic-validation ref; and
* :class:`GitHubIntegrationProvider` validates checks attached to that exact
  synthetic SHA, app identity, and freshness window.

The transport is deterministic and offline, but the decisions are made by the
production services and adapter.  The resulting case record is content
addressed through ``IntegrationDrillJournal`` and can be replayed read-only.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from avo_correlate.adapters.artifacts.drill_journal import IntegrationDrillJournal
from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.synthetic_validation_journal import (
    SyntheticValidationJournal,
)
from avo_correlate.adapters.hosted_git.github import (
    GitHubIntegrationProvider,
    GitHubProtectionPolicy,
    JsonBody,
    JsonValue,
    github_repository_digest,
)
from avo_correlate.application.synthetic_validation_service import (
    SyntheticValidationService,
)
from avo_correlate.contracts.base import ArtifactRef, Sha256Digest
from avo_correlate.contracts.integration_drill import IntegrationDrillCaseResult
from avo_correlate.contracts.synthetic_validation import (
    SyntheticValidationObservation,
    SyntheticValidationRequest,
    synthetic_validation_operation_id,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

TARGET_REF = "refs/heads/integration"
REPOSITORY_DIGEST: Sha256Digest = github_repository_digest("acme", "widget")  # type: ignore[assignment]
MAIN_BEFORE_COMMIT = "1" * 40
MAIN_BEFORE_TREE = "2" * 40
SYNTHETIC_COMMIT = "5" * 40
SYNTHETIC_TREE = "6" * 40
HEAD_COMMIT = "7" * 40
HEAD_TREE = "8" * 40
ATTESTER_IDENTITY = "avo-004.6-case-8-base-controlled-attester-v1"
FIXED_TIME = datetime(2026, 1, 1, tzinfo=UTC)
TRUSTED_CONTEXT = "avo synthetic validate (ubuntu-latest)"
TRUSTED_APP_ID = 15368
CASE_ID = 8


class AttesterDrillTransport:
    """Bounded transport fixture for both exact-ref and check evidence calls."""

    def __init__(
        self,
        *,
        check_mode: str = "exact",
        synthetic_commit: str = SYNTHETIC_COMMIT,
        synthetic_tree: str = SYNTHETIC_TREE,
    ) -> None:
        self.check_mode = check_mode
        self.synthetic_commit = synthetic_commit
        self.synthetic_tree = synthetic_tree
        self.validation_ref_commit: str | None = None
        self.validation_ref: str | None = None
        self.create_calls = 0
        self.calls: list[tuple[str, str]] = []

    def __call__(
        self,
        method: str,
        url: str,
        body: JsonBody | None,
        headers: Mapping[str, str],
    ) -> tuple[int, JsonValue]:
        del headers
        self.calls.append((method, url))
        if method == "POST" and url.endswith("/git/refs"):
            self.create_calls += 1
            # GitHub receives the exact operation-derived ref in the request.
            # Keep it as transport state so the adapter can verify response
            # identity rather than accepting a fixture constant.
            if not isinstance(body, Mapping):
                raise AssertionError("validation create did not include a typed ref")
            raw_ref = body.get("ref")
            if not isinstance(raw_ref, str):
                raise AssertionError("validation create did not include a typed ref")
            self.validation_ref = raw_ref
            self.validation_ref_commit = self.synthetic_commit
            return 201, {
                "ref": self.validation_ref,
                "object": {"type": "commit", "sha": self.synthetic_commit},
            }
        if method == "GET" and "/git/ref/heads/avo%2Fvalidation%2F" in url:
            if self.validation_ref_commit is None:
                return 404, {}
            return 200, {
                "ref": self.validation_ref or "",
                "object": {"type": "commit", "sha": self.validation_ref_commit},
            }
        if method == "GET" and "/git/commits/" in url:
            return 200, {
                "sha": self.synthetic_commit,
                "tree": {"sha": self.synthetic_tree},
                "parents": [{"sha": MAIN_BEFORE_COMMIT}],
            }
        if method == "GET" and "/protection" in url:
            return 200, self._protection()
        if method == "GET" and "/check-runs" in url:
            return 200, self._checks()
        raise AssertionError(f"unexpected controlled transport call: {method} {url}")

    def _protection(self) -> dict[str, JsonValue]:
        return {
            "required_status_checks": {
                "strict": True,
                "contexts": [TRUSTED_CONTEXT],
                "checks": [{"context": TRUSTED_CONTEXT, "app_id": TRUSTED_APP_ID}],
            },
            "required_pull_request_reviews": {
                "required_approving_review_count": 0,
                "dismiss_stale_reviews": True,
                "require_last_push_approval": False,
            },
            "enforce_admins": {"enabled": True},
            "required_linear_history": {"enabled": True},
            "required_conversation_resolution": {"enabled": True},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
            "lock_branch": {"enabled": False},
        }

    def _checks(self) -> dict[str, JsonValue]:
        head_sha = self.synthetic_commit
        app_id = TRUSTED_APP_ID
        status = "completed"
        conclusion = "success"
        completed_at = "2026-01-01T00:00:00Z"
        if self.check_mode == "head_only":
            head_sha = HEAD_COMMIT
        elif self.check_mode == "wrong_app":
            app_id = TRUSTED_APP_ID + 1
        elif self.check_mode == "wrong_sha":
            head_sha = HEAD_COMMIT
        elif self.check_mode == "stale":
            completed_at = "2025-12-31T23:59:59Z"
        elif self.check_mode == "incomplete":
            status = "in_progress"
            conclusion = ""
        return {
            "total_count": 1,
            "check_runs": [
                {
                    "id": 8001,
                    "name": TRUSTED_CONTEXT,
                    "app": {"id": app_id, "slug": "avo"},
                    "head_sha": head_sha,
                    "status": status,
                    "conclusion": conclusion,
                    "completed_at": completed_at,
                }
            ],
        }


@dataclass(frozen=True, slots=True)
class AttesterScenario:
    """One parser outcome retained in case-8 evidence."""

    name: str
    expected: Literal["accepted", "rejected"]
    observed: Literal["accepted", "rejected"]
    error: str | None = None


@dataclass(frozen=True, slots=True)
class IntegrationAttesterDrillRun:
    """Case result plus the typed scenario outcomes used to produce it."""

    case: IntegrationDrillCaseResult
    scenarios: tuple[AttesterScenario, ...]
    validation_outcome: str
    create_calls: int

    def __getattr__(self, name: str) -> object:
        return getattr(self.case, name)


class IntegrationAttesterDrillService:
    """Run and durably record deterministic AVO-004.6 case 8."""

    def __init__(
        self,
        journal_or_root: IntegrationDrillJournal | Path,
        *,
        repository_digest: Sha256Digest = REPOSITORY_DIGEST,
        attester_identity: str = ATTESTER_IDENTITY,
        root_operation_id: Sha256Digest | None = None,
    ) -> None:
        if not attester_identity.strip():
            raise ValueError("attester_identity must be non-empty")
        if not attester_identity.startswith("avo-004.6-case-8-base-controlled-attester-"):
            raise ValueError("case-8 attester identity must be base-controlled")
        self._journal = (
            journal_or_root
            if isinstance(journal_or_root, IntegrationDrillJournal)
            else IntegrationDrillJournal(Path(journal_or_root))
        )
        self._repository_digest = repository_digest
        self._attester_identity = attester_identity
        self._root_operation_id = root_operation_id
        self._last_transport: AttesterDrillTransport | None = None

    @property
    def journal(self) -> IntegrationDrillJournal:
        return self._journal

    @property
    def attester_identity(self) -> str:
        return self._attester_identity

    @property
    def last_transport(self) -> AttesterDrillTransport | None:
        return self._last_transport

    @staticmethod
    def operation_id(
        repository_digest: Sha256Digest = REPOSITORY_DIGEST,
        attester_identity: str = ATTESTER_IDENTITY,
    ) -> Sha256Digest:
        return canonical_digest(
            {
                "kind": "avo-004.6-case-8-exact-sha-attester",
                "case_id": CASE_ID,
                "repository_digest": repository_digest,
                "target_ref": TARGET_REF,
                "synthetic_commit": SYNTHETIC_COMMIT,
                "synthetic_tree": SYNTHETIC_TREE,
                "attester_identity": attester_identity,
            }
        )

    @staticmethod
    def synthetic_operation_id(
        repository_digest: Sha256Digest = REPOSITORY_DIGEST,
        attester_identity: str = ATTESTER_IDENTITY,
    ) -> Sha256Digest:
        """Return the operation identity used by SyntheticValidationService."""
        observation = SyntheticValidationObservation(
            repository_digest=repository_digest,
            base_ref=TARGET_REF,
            base_commit=MAIN_BEFORE_COMMIT,
            base_tree=MAIN_BEFORE_TREE,
            head_ref="refs/heads/avo/candidate-case-8",
            head_commit=HEAD_COMMIT,
            head_tree=HEAD_TREE,
            synthetic_commit=SYNTHETIC_COMMIT,
            synthetic_tree=SYNTHETIC_TREE,
        )
        request = SyntheticValidationRequest(
            observation=observation,
            target_repository_digest=repository_digest,
            target_ref=TARGET_REF,
            target_identity=attester_identity,
            trusted_check_contexts=[TRUSTED_CONTEXT],
            provider_identity="avo-base-controlled-attester",
            provider_api_version="2026-01",
        )
        return synthetic_validation_operation_id(request)

    def run(self) -> IntegrationAttesterDrillRun:
        operation_id = self._root_operation_id or self.operation_id(
            self._repository_digest, self._attester_identity
        )
        existing = self._journal.read_case_result(operation_id, CASE_ID)
        if existing is not None:
            return IntegrationAttesterDrillRun(
                case=existing[0],
                scenarios=(),
                validation_outcome="replayed",
                create_calls=0,
            )

        validation_transport = AttesterDrillTransport()
        self._last_transport = validation_transport
        github = self._github(validation_transport, check_mode="exact")
        validation = SyntheticValidationService(
            github,
            SyntheticValidationJournal(self._journal.root / "synthetic-validation"),
        )
        plan = validation.prepare(
            self._observation(),
            target_repository_digest=self._repository_digest,
            target_ref=TARGET_REF,
            target_identity=self._attester_identity,
            trusted_check_contexts=(TRUSTED_CONTEXT,),
            provider_identity=github.provider_identity,
            provider_api_version=github.provider_api_version,
        )
        first = validation.trigger(plan)
        replay = validation.trigger(plan)
        exact_outcomes = {"created", "already_present", "reconciled"}
        if first.outcome not in exact_outcomes or replay.outcome not in exact_outcomes:
            raise RuntimeError(
                "case-8 synthetic validation did not produce an exact typed outcome: "
                f"{first.outcome}/{replay.outcome}"
            )
        if validation_transport.create_calls != 1:
            raise RuntimeError("case-8 exact-ref replay issued a duplicate create")

        scenarios = self._check_scenarios()
        if any(item.observed != item.expected for item in scenarios):
            raise RuntimeError("case-8 exact-SHA attester returned a wrong typed result")
        evidence = self._evidence(
            operation_id,
            plan.operation_id,
            plan.plan_digest,
            first.outcome,
            replay.outcome,
            scenarios,
        )
        case = IntegrationDrillCaseResult(
            case_id=CASE_ID,
            operation_id=operation_id,
            outcome="passed",
            attester_identity=self._attester_identity,
            repository_digest=self._repository_digest,
            target_ref=TARGET_REF,
            main_before_commit=MAIN_BEFORE_COMMIT,
            main_after_commit=MAIN_BEFORE_COMMIT,
            target_head_commit=MAIN_BEFORE_COMMIT,
            target_head_tree=MAIN_BEFORE_TREE,
            target_parents=[],
            deploy_performed=False,
            evidence_artifacts=[evidence],
        )
        self._journal.record_case_result(case)
        return IntegrationAttesterDrillRun(
            case=case,
            scenarios=tuple(scenarios),
            validation_outcome=first.outcome,
            create_calls=validation_transport.create_calls,
        )

    execute = run
    drill = run

    def _observation(self) -> SyntheticValidationObservation:
        return SyntheticValidationObservation(
            repository_digest=self._repository_digest,
            base_ref=TARGET_REF,
            base_commit=MAIN_BEFORE_COMMIT,
            base_tree=MAIN_BEFORE_TREE,
            head_ref="refs/heads/avo/candidate-case-8",
            head_commit=HEAD_COMMIT,
            head_tree=HEAD_TREE,
            synthetic_commit=SYNTHETIC_COMMIT,
            synthetic_tree=SYNTHETIC_TREE,
        )

    def _github(
        self, transport: AttesterDrillTransport, *, check_mode: str
    ) -> GitHubIntegrationProvider:
        transport.check_mode = check_mode
        return GitHubIntegrationProvider(
            owner="acme",
            repo="widget",
            repository_digest=self._repository_digest,
            target_ref=TARGET_REF,
            trusted_checks=((TRUSTED_CONTEXT, TRUSTED_APP_ID),),
            protection_checks=((TRUSTED_CONTEXT, TRUSTED_APP_ID),),
            freshness_cutoff=FIXED_TIME,
            protection_policy=GitHubProtectionPolicy(),
            provider_identity="avo-base-controlled-attester",
            provider_api_version="2026-01",
            transport=transport,
        )

    def _check_scenarios(self) -> list[AttesterScenario]:
        scenarios: list[AttesterScenario] = []
        scenario_specs: tuple[tuple[str, str, Literal["accepted", "rejected"]], ...] = (
            ("exact_synthetic_success", "exact", "accepted"),
            ("head_only_check", "head_only", "rejected"),
            ("wrong_app_identity", "wrong_app", "rejected"),
            ("wrong_synthetic_sha", "wrong_sha", "rejected"),
            ("stale_check", "stale", "rejected"),
            ("incomplete_check", "incomplete", "rejected"),
        )
        for name, mode, expected in scenario_specs:
            transport = AttesterDrillTransport(check_mode=mode)
            provider = self._github(transport, check_mode=mode)
            try:
                provider._evidence_snapshot(  # pyright: ignore[reportPrivateUsage]
                    SYNTHETIC_COMMIT, SYNTHETIC_TREE
                )
            except (ValueError, RuntimeError) as exc:
                scenarios.append(
                    AttesterScenario(name, expected, "rejected", str(exc))
                )
            else:
                scenarios.append(AttesterScenario(name, expected, "accepted"))

        # Duplicate trusted contexts are rejected by the provider's typed
        # configuration boundary before any transport or parser call.
        duplicate = AttesterDrillTransport(check_mode="exact")
        try:
            GitHubIntegrationProvider(
                owner="acme",
                repo="widget",
                repository_digest=self._repository_digest,
                target_ref=TARGET_REF,
                trusted_checks=(
                    (TRUSTED_CONTEXT, TRUSTED_APP_ID),
                    (TRUSTED_CONTEXT, TRUSTED_APP_ID),
                ),
                protection_checks=((TRUSTED_CONTEXT, TRUSTED_APP_ID),),
                freshness_cutoff=FIXED_TIME,
                protection_policy=GitHubProtectionPolicy(),
                transport=duplicate,
            )
        except ValueError as exc:
            scenarios.append(
                AttesterScenario("duplicate_trusted_context", "rejected", "rejected", str(exc))
            )
        else:
            scenarios.append(AttesterScenario("duplicate_trusted_context", "rejected", "accepted"))
        return scenarios

    def _evidence(
        self,
        operation_id: Sha256Digest,
        validation_operation_id: Sha256Digest,
        plan_digest: Sha256Digest,
        first_outcome: str,
        replay_outcome: str,
        scenarios: list[AttesterScenario],
    ) -> ArtifactRef:
        payload = {
            "schema_version": 1,
            "case_id": CASE_ID,
            "operation_id": operation_id,
            "validation_operation_id": validation_operation_id,
            "plan_digest": plan_digest,
            "attester_identity": self._attester_identity,
            "base_control": "avo-base-controlled-attester",
            "synthetic_commit": SYNTHETIC_COMMIT,
            "synthetic_tree": SYNTHETIC_TREE,
            "validation_first_outcome": first_outcome,
            "validation_replay_outcome": replay_outcome,
            "validation_create_calls": 1,
            "scenarios": [
                {
                    "name": item.name,
                    "expected": item.expected,
                    "observed": item.observed,
                    "error": item.error,
                }
                for item in scenarios
            ],
            "main_before_commit": MAIN_BEFORE_COMMIT,
            "main_after_commit": MAIN_BEFORE_COMMIT,
            "deploy_performed": False,
            "observed_at": FIXED_TIME.isoformat().replace("+00:00", "Z"),
        }
        data = canonical_bytes(payload)
        stored = FilesystemArtifactStore(self._journal.root / "artifacts").put_bytes(
            data,
            media_type="application/vnd.avo.integration-drill-case-8-attestation+json",
            role="integration-drill-case-8-attestation-evidence",
            max_bytes=2 * 1024 * 1024,
        )
        return stored.model_copy(update={"created_at": FIXED_TIME})


__all__ = [
    "ATTESTER_IDENTITY",
    "CASE_ID",
    "TRUSTED_APP_ID",
    "TRUSTED_CONTEXT",
    "AttesterDrillTransport",
    "AttesterScenario",
    "IntegrationAttesterDrillRun",
    "IntegrationAttesterDrillService",
]
