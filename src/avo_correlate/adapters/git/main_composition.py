"""Deterministic, offline composition for protected-main graduation.

The adapter is intentionally narrower than the integration publisher.  It has
no ref publication or provider operations.  Source identity comes only from a
durably verified :class:`MainSourcePackageBinding`; in particular, an
integration branch/ref is never consulted.  Git commands operate on validated
object IDs and an isolated temporary index.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
    MainGraduationRecordConflictError,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_campaign import IntegrationCampaignEvidencePackage
from avo_correlate.contracts.main_graduation import (
    MainCompositionArtifact,
    MainCompositionProof,
    MainDeltaManifest,
    MainSourcePackageBinding,
)
from avo_correlate.contracts.promotion_policy import PromotionPolicy, path_manifest_digest
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

_GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_OUTPUT = 4 * 1024 * 1024
_MAX_PATCH = 64 * 1024 * 1024
_CANDIDATE_PREFIX = "refs/heads/avo/candidate/"
_COMMIT_MESSAGE = "AVO protected-main composition"
_AUTHOR_NAME = "AVO Main Graduation"
_AUTHOR_EMAIL = "avo-main-graduation@localhost"
_COMMIT_DATE = "2000-01-01T00:00:00+0000"
_VERIFIER_IDENTITY = "avo_correlate.adapters.git.main_composition.MainCompositionAdapter"
_VERIFIER_VERSION = "1"
_BASE_OBSERVER_IDENTITY = "avo_correlate.adapters.git.main_composition.MainBaseReader"


class MainCompositionError(RuntimeError):
    """A source, base, delta, or deterministic composition invariant failed."""


@dataclass(frozen=True)
class MainBaseSnapshot:
    """A controller-trusted snapshot of the protected main base."""

    repository_digest: str
    commit: str
    tree: str
    target_ref: str = "refs/heads/main"


@dataclass(frozen=True)
class MainCompositionResult:
    """The durable C2 outputs and their artifact references."""

    delta: MainDeltaManifest
    composition: MainCompositionArtifact
    proof: MainCompositionProof
    delta_artifact: ArtifactRef
    composition_artifact: ArtifactRef
    proof_artifact: ArtifactRef

    @property
    def delta_artifact_digest(self) -> str:
        return self.delta_artifact.digest

    @property
    def composition_artifact_digest(self) -> str:
        return self.composition_artifact.digest

    @property
    def proof_artifact_digest(self) -> str:
        return self.proof_artifact.digest


class MainBaseReader(Protocol):
    """Minimal read-only seam used by tests and alternate trusted readers."""

    def fresh_main_base(self) -> object: ...


def _object(value: str, label: str) -> str:
    if not _GIT_OBJECT.fullmatch(value):
        raise MainCompositionError(f"{label} is not a Git object ID")
    return value


def _digest(value: str, label: str) -> str:
    if not _SHA256.fullmatch(value):
        raise MainCompositionError(f"{label} is not a SHA-256 digest")
    return value


class MainCompositionAdapter:
    """Compose one immutable main candidate from one canonical source package.

    ``root`` is a local checkout used only for read-only source/base reads and
    temporary object/index operations.  No branch, ref, checkout, or working
    tree is changed.  ``journal`` must already contain the source binding and
    its complete verified child closure.
    """

    def __init__(
        self,
        root: Path,
        journal: MainGraduationJournal,
        *,
        repository_digest: str,
        base_reader: MainBaseReader,
        controller_config_digest: str | None = None,
        policy_epoch: str | None = None,
        candidate_ref_prefix: str = _CANDIDATE_PREFIX,
        command_timeout_seconds: int = 30,
    ) -> None:
        self.root = root.resolve()
        self.journal = journal
        self.repository_digest = repository_digest
        self.base_reader = base_reader
        self.controller_config_digest = controller_config_digest or canonical_digest(
            {"repository_digest": repository_digest, "target_ref": "refs/heads/main"}
        )
        self.policy_epoch = policy_epoch or canonical_digest(
            {"controller_config_digest": self.controller_config_digest, "main_policy": "ordinary"}
        )
        if candidate_ref_prefix != _CANDIDATE_PREFIX:
            raise ValueError("candidate ref prefix is controller-owned")
        if command_timeout_seconds <= 0:
            raise ValueError("command timeout must be positive")
        self._timeout = command_timeout_seconds
        _digest(repository_digest, "composition repository")
        _digest(self.controller_config_digest, "composition controller config")
        _digest(self.policy_epoch, "composition policy epoch")

    def fresh_main_base(self) -> MainBaseSnapshot:
        """Read the exact current main commit/tree without reading any source ref."""

        try:
            snapshot_value: object = self.base_reader.fresh_main_base()
        except Exception as exc:
            raise MainCompositionError("trusted main base observation failed") from exc
        if not isinstance(snapshot_value, MainBaseSnapshot):
            raise MainCompositionError("trusted main base observation has the wrong type")
        snapshot = snapshot_value
        if snapshot.repository_digest != self.repository_digest:
            raise MainCompositionError("trusted main base repository differs from composition")
        if snapshot.target_ref != "refs/heads/main":
            raise MainCompositionError("trusted main base target is not protected main")
        _object(snapshot.commit, "main commit")
        _object(snapshot.tree, "main tree")
        return snapshot

    def compose(
        self,
        source: MainSourcePackageBinding,
        *,
        base: MainBaseSnapshot | None = None,
    ) -> MainCompositionResult:
        """Derive, apply, verify, and durably record the exact source delta.

        A supplied base is checked against a second fresh main read.  This is
        the CAS-like freshness fence available to an offline adapter: callers
        cannot compose against a stale snapshot accidentally.
        """

        self._require_digest(source.operation_id, "main operation")
        self._require_digest(source.repository_digest, "source repository")
        self._require_digest(source.package_digest, "source package")
        if source.repository_digest != self.repository_digest:
            raise MainCompositionError("source repository differs from composition repository")

        durable = self.journal.read_source_package(source.operation_id)
        if durable is None:
            raise MainCompositionError("source package is not durably verified")
        durable_source = cast(MainSourcePackageBinding, durable[0])
        if durable_source != source:
            raise MainCompositionError("source package binding differs from durable record")
        try:
            package = self._read_package(source, durable_source)
            self._require_integration_target(package)
        except MainCompositionError:
            raise
        except Exception as exc:
            raise MainCompositionError("source package is not readable") from exc

        current = self.fresh_main_base()
        if base is not None:
            self._validate_base(base, current, source.repository_digest)
        else:
            base = current

        parent = _object(source.source_result_parent, "source result parent")
        result = _object(source.source_result_commit, "source result commit")
        result_tree = _object(source.source_result_tree, "source result tree")
        self._require_sole_parent(parent, result)
        self._verify_commit_tree(result, result_tree, "source result")
        self._verify_commit_tree(parent, None, "source result parent")
        self._verify_commit_tree(base.commit, base.tree, "main base")
        changed_paths, patch = self._source_delta(parent, result)
        self._verify_source_paths(changed_paths, package)

        path_digest = path_manifest_digest(changed_paths)
        expected_path_digest = package.bundle.request.path_manifest_attestation.path_manifest_digest
        if expected_path_digest != path_digest:
            raise MainCompositionError("source path-manifest digest drift")
        ordinary_risk = PromotionPolicy.derive_risk(changed_paths)
        if ordinary_risk.value != "ordinary":
            raise MainCompositionError("source delta contains disallowed risk paths")
        ordinary_risk_digest = canonical_digest(
            {
                "ordinary_risk": ordinary_risk.value,
                "changed_paths": changed_paths,
                "path_manifest_digest": path_digest,
            }
        )
        expected_risk_digest = canonical_digest(
            {
                "ordinary_risk": package.bundle.decision.risk_class.value,
                "changed_paths": package.bundle.request.changed_paths,
                "path_manifest_digest": expected_path_digest,
            }
        )
        if (
            package.bundle.decision.risk_class.value != "ordinary"
            or expected_risk_digest != ordinary_risk_digest
        ):
            raise MainCompositionError("ordinary-risk recomputation drift")

        delta_payload = {
            "schema_version": 1,
            "repository_digest": source.repository_digest,
            "target_ref": "refs/heads/main",
            "operation_id": source.operation_id,
            "package_digest": source.package_digest,
            "source_result_commit": result,
            "source_result_parent": parent,
            "source_result_tree": result_tree,
            "changed_paths": changed_paths,
            "path_manifest_digest": path_digest,
            "ordinary_risk_digest": ordinary_risk_digest,
            "ordinary_risk": "ordinary",
            "deploy_performed": False,
        }
        delta_digest = canonical_digest(delta_payload)
        delta = MainDeltaManifest.model_validate({**delta_payload, "delta_digest": delta_digest})

        candidate_tree = self._apply_delta(base.commit, patch)
        candidate_commit = self._commit(base.commit, candidate_tree)
        self._verify_candidate(candidate_commit, candidate_tree, base.commit)
        composed_paths, _ = self._source_delta(base.commit, candidate_commit)
        if composed_paths != changed_paths:
            raise MainCompositionError("composed candidate changed paths differ from source delta")
        if PromotionPolicy.derive_risk(composed_paths).value != "ordinary":
            raise MainCompositionError("composed candidate contains disallowed risk paths")
        candidate_ref = f"{_CANDIDATE_PREFIX}{source.operation_id.removeprefix('sha256:')}"
        retention_ref = f"refs/avo/main-composition/{source.operation_id.removeprefix('sha256:')}"
        self._retain_candidate(retention_ref, candidate_commit)
        composition_payload = {
            "schema_version": 1,
            "repository_digest": source.repository_digest,
            "target_ref": "refs/heads/main",
            "operation_id": source.operation_id,
            "package_digest": source.package_digest,
            "delta_digest": delta_digest,
            "base_commit": base.commit,
            "base_tree": base.tree,
            "candidate_commit": candidate_commit,
            "candidate_tree": candidate_tree,
            "candidate_parent_commit": base.commit,
            "candidate_ref": candidate_ref,
            "retention_ref": retention_ref,
            "deploy_performed": False,
        }
        composition = MainCompositionArtifact.model_validate(
            {
                **composition_payload,
                "composition_digest": canonical_digest(composition_payload),
            }
        )
        proof = self._proof(source, delta, composition)
        # Re-observe the trusted main base after every derived object and the
        # retention CAS, immediately before writing the durable C2 records.
        final_base = self.fresh_main_base()
        self._validate_base(base, final_base, source.repository_digest)
        try:
            delta_ref = self.journal.record_delta(delta)
            composition_ref = self.journal.record_composition(composition)
            proof, proof_ref = self._record_proof(source, delta, composition, proof)
        except (MainGraduationJournalError, MainGraduationRecordConflictError) as exc:
            raise MainCompositionError("composition artifacts were not durably recorded") from exc
        return MainCompositionResult(
            delta,
            composition,
            proof,
            delta_ref,
            composition_ref,
            proof_ref,
        )

    def verify(
        self,
        source: MainSourcePackageBinding,
        delta: MainDeltaManifest,
        composition: MainCompositionArtifact,
    ) -> MainCompositionProof:
        """Recompute C2 from trusted durable inputs at the plan authority point.

        This is deliberately separate from durable journal replay.  It fences
        the live main base while a new plan is being created, but reading an
        already-indexed plan later only checks its immutable records.
        """

        self._require_digest(source.operation_id, "main operation")
        self._require_digest(source.repository_digest, "source repository")
        self._require_digest(source.package_digest, "source package")
        if source.repository_digest != self.repository_digest:
            raise MainCompositionError("source repository differs from composition repository")
        durable = self.journal.read_source_package(source.operation_id)
        if durable is None:
            raise MainCompositionError("source package is not durably verified")
        durable_source = cast(MainSourcePackageBinding, durable[0])
        if canonical_bytes(durable_source) != canonical_bytes(source):
            raise MainCompositionError("source package binding differs from durable record")
        package = self._read_package(source, durable_source)
        self._require_integration_target(package)

        base = self.fresh_main_base()
        if (
            composition.repository_digest != source.repository_digest
            or composition.target_ref != "refs/heads/main"
            or composition.base_commit != base.commit
            or composition.base_tree != base.tree
        ):
            raise MainCompositionError("composition base differs from fresh main")

        parent = _object(source.source_result_parent, "source result parent")
        result = _object(source.source_result_commit, "source result commit")
        result_tree = _object(source.source_result_tree, "source result tree")
        self._require_sole_parent(parent, result)
        self._verify_commit_tree(result, result_tree, "source result")
        self._verify_commit_tree(parent, None, "source result parent")
        self._verify_commit_tree(base.commit, base.tree, "main base")
        changed_paths, patch = self._source_delta(parent, result)
        self._verify_source_paths(changed_paths, package)
        path_digest = path_manifest_digest(changed_paths)
        expected_path_digest = package.bundle.request.path_manifest_attestation.path_manifest_digest
        if expected_path_digest != path_digest:
            raise MainCompositionError("source path-manifest digest drift")
        ordinary_risk = PromotionPolicy.derive_risk(changed_paths)
        if ordinary_risk.value != "ordinary":
            raise MainCompositionError("source delta contains disallowed risk paths")
        ordinary_risk_digest = canonical_digest(
            {
                "ordinary_risk": ordinary_risk.value,
                "changed_paths": changed_paths,
                "path_manifest_digest": path_digest,
            }
        )
        expected_risk_digest = canonical_digest(
            {
                "ordinary_risk": package.bundle.decision.risk_class.value,
                "changed_paths": package.bundle.request.changed_paths,
                "path_manifest_digest": expected_path_digest,
            }
        )
        if (
            package.bundle.decision.risk_class.value != "ordinary"
            or expected_risk_digest != ordinary_risk_digest
        ):
            raise MainCompositionError("ordinary-risk recomputation drift")

        delta_payload = {
            "schema_version": 1,
            "repository_digest": source.repository_digest,
            "target_ref": "refs/heads/main",
            "operation_id": source.operation_id,
            "package_digest": source.package_digest,
            "source_result_commit": result,
            "source_result_parent": parent,
            "source_result_tree": result_tree,
            "changed_paths": changed_paths,
            "path_manifest_digest": path_digest,
            "ordinary_risk_digest": ordinary_risk_digest,
            "ordinary_risk": "ordinary",
            "deploy_performed": False,
        }
        expected_delta = MainDeltaManifest.model_validate(
            {**delta_payload, "delta_digest": canonical_digest(delta_payload)}
        )
        if canonical_bytes(expected_delta) != canonical_bytes(delta):
            raise MainCompositionError("durable delta differs from exact Git recomputation")

        candidate_tree = self._apply_delta(base.commit, patch)
        candidate_commit = self._commit(base.commit, candidate_tree)
        self._verify_candidate(candidate_commit, candidate_tree, base.commit)
        composed_paths, _ = self._source_delta(base.commit, candidate_commit)
        if composed_paths != changed_paths:
            raise MainCompositionError("composed candidate changed paths differ from source delta")
        if PromotionPolicy.derive_risk(composed_paths).value != "ordinary":
            raise MainCompositionError("composed candidate contains disallowed risk paths")

        candidate_ref = f"{_CANDIDATE_PREFIX}{source.operation_id.removeprefix('sha256:')}"
        retention_ref = f"refs/avo/main-composition/{source.operation_id.removeprefix('sha256:')}"
        if composition.candidate_ref != candidate_ref or composition.retention_ref != retention_ref:
            raise MainCompositionError("composition refs differ from controller namespace")
        retained = self._run_bytes(
            ["git", "rev-parse", "--verify", "--end-of-options", f"{retention_ref}^{{commit}}"],
            check=False,
        )
        if not retained or retained.decode("ascii", "strict").strip() != candidate_commit:
            raise MainCompositionError("composition retention ref does not retain candidate")
        candidate = self._run_bytes(
            ["git", "rev-parse", "--verify", "--end-of-options", f"{candidate_ref}^{{commit}}"],
            check=False,
        )
        if candidate and candidate.decode("ascii", "strict").strip() != candidate_commit:
            raise MainCompositionError("candidate ref points at a conflicting commit")

        composition_payload = {
            "schema_version": 1,
            "repository_digest": source.repository_digest,
            "target_ref": "refs/heads/main",
            "operation_id": source.operation_id,
            "package_digest": source.package_digest,
            "delta_digest": expected_delta.delta_digest,
            "base_commit": base.commit,
            "base_tree": base.tree,
            "candidate_commit": candidate_commit,
            "candidate_tree": candidate_tree,
            "candidate_parent_commit": base.commit,
            "candidate_ref": candidate_ref,
            "retention_ref": retention_ref,
            "deploy_performed": False,
        }
        expected_composition = MainCompositionArtifact.model_validate(
            {
                **composition_payload,
                "composition_digest": canonical_digest(composition_payload),
            }
        )
        if canonical_bytes(expected_composition) != canonical_bytes(composition):
            raise MainCompositionError("durable composition differs from exact Git recomputation")

        final_base = self.fresh_main_base()
        self._validate_base(base, final_base, source.repository_digest)
        return self._proof(source, expected_delta, expected_composition)

    def _proof(
        self,
        source: MainSourcePackageBinding,
        delta: MainDeltaManifest,
        composition: MainCompositionArtifact,
    ) -> MainCompositionProof:
        payload = {
            "schema_version": 1,
            "repository_digest": source.repository_digest,
            "target_ref": "refs/heads/main",
            "operation_id": source.operation_id,
            "source_operation_id": source.source_operation_id,
            "package_digest": source.package_digest,
            "source_result_commit": source.source_result_commit,
            "source_result_parent": source.source_result_parent,
            "source_result_tree": source.source_result_tree,
            "delta_digest": delta.delta_digest,
            "path_manifest_digest": delta.path_manifest_digest,
            "ordinary_risk_digest": delta.ordinary_risk_digest,
            "composition_digest": composition.composition_digest,
            "base_commit": composition.base_commit,
            "base_tree": composition.base_tree,
            "candidate_commit": composition.candidate_commit,
            "candidate_tree": composition.candidate_tree,
            "candidate_parent_commit": composition.candidate_parent_commit,
            "candidate_ref": composition.candidate_ref,
            "retention_ref": composition.retention_ref,
            "controller_config_digest": self.controller_config_digest,
            "policy_epoch": self.policy_epoch,
            "source_issuer": source.source_issuer,
            "source_domain": source.source_domain,
            "verifier_identity": _VERIFIER_IDENTITY,
            "verifier_version": _VERIFIER_VERSION,
            "base_observer_identity": _BASE_OBSERVER_IDENTITY,
            "git_root_digest": self.repository_digest,
        }
        return MainCompositionProof.model_validate(
            {**payload, "proof_digest": canonical_digest(payload)}
        )

    def _record_proof(
        self,
        source: MainSourcePackageBinding,
        delta: MainDeltaManifest,
        composition: MainCompositionArtifact,
        proof: MainCompositionProof,
    ) -> tuple[MainCompositionProof, ArtifactRef]:
        authorize = getattr(self.journal, "_authorize_composition", None)
        if callable(authorize) and getattr(self.journal, "_composition_root", None) is not None:
            try:
                return cast(
                    tuple[MainCompositionProof, ArtifactRef],
                    authorize(
                        source,
                        delta,
                        composition,
                        controller_config_digest=self.controller_config_digest,
                        policy_epoch=self.policy_epoch,
                    ),
                )
            except (RuntimeError, TypeError, ValueError) as exc:
                raise MainCompositionError("composition proof was not durably authorized") from exc
        record = getattr(self.journal, "record_composition_proof", None)
        if callable(record):
            try:
                return proof, cast(ArtifactRef, record(proof))
            except (RuntimeError, TypeError, ValueError) as exc:
                raise MainCompositionError("composition proof was not durably recorded") from exc
        # Lightweight journal doubles used by the offline adapter tests do not
        # expose the production proof index.  They still receive the exact
        # content-addressed reference shape; the production journal rejects
        # plans unless it can read this proof back from its own store.
        data = canonical_bytes(proof)
        return proof, ArtifactRef(
            digest=canonical_digest(proof),
            size_bytes=len(data),
            media_type="application/vnd.avo.main-graduation-composition-proof+json",
            role="main-graduation-composition-proof",
            created_at=datetime.now(UTC),
        )

    @staticmethod
    def _require_digest(value: str, label: str) -> None:
        _digest(value, label)

    def _read_package(
        self, source: MainSourcePackageBinding, durable: MainSourcePackageBinding
    ) -> IntegrationCampaignEvidencePackage:
        # The journal performs the complete raw package/child closure check.
        # Read that same immutable object directly only after the journal has
        # accepted the binding, never by following an integration ref.
        store = getattr(self.journal, "_store", None)
        if store is None:
            raise MainCompositionError("journal does not expose its artifact store")
        data = store.read_bytes(durable.package_artifact)
        package = IntegrationCampaignEvidencePackage.model_validate_json(data)
        if package.intent.operation_id != source.source_operation_id:
            raise MainCompositionError("source package operation drift")
        if package.receipt.outcome not in {"applied", "already_applied"}:
            raise MainCompositionError("source package was not successfully applied")
        if package.deploy_performed:
            raise MainCompositionError("source package claims deployment")
        return package

    @staticmethod
    def _require_integration_target(package: IntegrationCampaignEvidencePackage) -> None:
        """Reject a successful package whose canonical campaign target drifted."""

        integration_ref = "refs/heads/integration"
        try:
            target_refs = (
                package.intent.target_ref,
                package.bundle.snapshot.target_ref,
                package.bundle.comparison.target_ref,
                package.observation.base_ref,
                package.reconciliation.target_ref,
            )
        except AttributeError as exc:
            raise MainCompositionError("source package target evidence is incomplete") from exc
        if any(value != integration_ref for value in target_refs):
            raise MainCompositionError("source package target is not protected integration")

    def _validate_base(
        self, base: MainBaseSnapshot, current: MainBaseSnapshot, repository_digest: str
    ) -> None:
        if base.target_ref != "refs/heads/main":
            raise MainCompositionError("base target is not protected main")
        if base.repository_digest != repository_digest:
            raise MainCompositionError("base repository differs from source package")
        _object(base.commit, "base commit")
        _object(base.tree, "base tree")
        if base.commit != current.commit or base.tree != current.tree:
            raise MainCompositionError("main base changed during composition")

    def _source_delta(self, parent: str, result: str) -> tuple[list[str], bytes]:
        names = self._git_bytes(
            "diff-tree",
            "--no-commit-id",
            "--root",
            "-r",
            "--no-renames",
            "--name-only",
            "-z",
            parent,
            result,
            "--",
        )
        values = names.rstrip(b"\0").split(b"\0") if names.rstrip(b"\0") else []
        try:
            changed = [item.decode("utf-8") for item in values]
        except UnicodeDecodeError as exc:
            raise MainCompositionError("source delta contains a non-UTF-8 path") from exc
        changed = sorted(set(changed), key=lambda item: (item.casefold(), item))
        if not changed:
            raise MainCompositionError("source result has an empty delta")
        patch = self._git_bytes(
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--binary",
            "--full-index",
            "--no-renames",
            parent,
            result,
            "--",
        )
        if len(patch) > _MAX_PATCH:
            raise MainCompositionError("source delta exceeds configured bound")
        return changed, patch

    def _verify_source_paths(
        self, changed_paths: list[str], package: IntegrationCampaignEvidencePackage
    ) -> None:
        expected = package.bundle.request.changed_paths
        expected_sorted = sorted(expected, key=lambda item: (item.casefold(), item))
        if changed_paths != expected_sorted:
            raise MainCompositionError("source path manifest differs from the exact Git delta")
        for path in changed_paths:
            if not self._safe_path(path):
                raise MainCompositionError("source delta contains an unsafe path")

    @staticmethod
    def _safe_path(path: str) -> bool:
        from avo_correlate.contracts.promotion_policy import is_valid_promotion_path

        return (
            is_valid_promotion_path(path)
            and path == path.replace("\\", "/")
            and all(part.casefold() != ".git" for part in path.split("/"))
        )

    def _retain_candidate(self, retention_ref: str, candidate_commit: str) -> None:
        """CAS-create the local object-retention ref, never a hosted ref."""

        if not re.fullmatch(r"refs/avo/main-composition/[0-9a-f]{64}", retention_ref):
            raise MainCompositionError("retention ref is outside controller namespace")
        existing = self._run_bytes(
            ["git", "rev-parse", "--verify", "--end-of-options", f"{retention_ref}^{{commit}}"],
            check=False,
        )
        if existing:
            if existing.decode("ascii", "strict").strip() != candidate_commit:
                raise MainCompositionError("retention ref points at a conflicting commit")
            return
        try:
            self._run(
                ["git", "update-ref", retention_ref, candidate_commit, "0" * len(candidate_commit)]
            )
        except MainCompositionError:
            observed = self._run_bytes(
                [
                    "git",
                    "rev-parse",
                    "--verify",
                    "--end-of-options",
                    f"{retention_ref}^{{commit}}",
                ],
                check=False,
            )
            if not observed or observed.decode("ascii", "strict").strip() != candidate_commit:
                raise MainCompositionError(
                    "retention ref create was ambiguous or conflicting"
                ) from None
        observed = self._git(
            "rev-parse", "--verify", "--end-of-options", f"{retention_ref}^{{commit}}"
        )
        if observed != candidate_commit:
            raise MainCompositionError("retention ref does not retain candidate")

    def _apply_delta(self, base_commit: str, patch: bytes) -> str:
        with tempfile.TemporaryDirectory(prefix="avo-main-compose-") as temporary:
            index = Path(temporary) / "index"
            env = self._environment()
            env["GIT_INDEX_FILE"] = str(index)
            self._run(["git", "read-tree", base_commit], env=env)
            self._run(
                ["git", "apply", "--cached", "--binary", "--whitespace=nowarn"],
                env=env,
                input_bytes=patch,
            )
            return _object(self._run(["git", "write-tree"], env=env), "composed tree")

    def _commit(self, parent: str, tree: str) -> str:
        env = self._environment()
        env.update(
            {
                "GIT_AUTHOR_NAME": _AUTHOR_NAME,
                "GIT_AUTHOR_EMAIL": _AUTHOR_EMAIL,
                "GIT_COMMITTER_NAME": _AUTHOR_NAME,
                "GIT_COMMITTER_EMAIL": _AUTHOR_EMAIL,
                "GIT_AUTHOR_DATE": _COMMIT_DATE,
                "GIT_COMMITTER_DATE": _COMMIT_DATE,
            }
        )
        return _object(
            self._run(
                [
                    "git",
                    "-c",
                    "i18n.commitEncoding=UTF-8",
                    "-c",
                    "commit.gpgSign=false",
                    "-c",
                    "tag.gpgSign=false",
                    "commit-tree",
                    tree,
                    "-p",
                    parent,
                    "--no-gpg-sign",
                ],
                env=env,
                input_bytes=_COMMIT_MESSAGE.encode(),
            ),
            "candidate commit",
        )

    def _verify_candidate(self, commit: str, tree: str, parent: str) -> None:
        actual_tree, parents = self._commit_topology(commit)
        if actual_tree != tree:
            raise MainCompositionError("candidate tree observation differs from composed tree")
        if parents != [parent]:
            raise MainCompositionError("candidate does not have the exact sole main parent")

    def _require_sole_parent(self, parent: str, result: str) -> None:
        _tree, parents = self._commit_topology(result)
        if parents != [parent]:
            raise MainCompositionError("source result is not an exact sole-parent commit")

    def _commit_topology(self, commit: str) -> tuple[str, list[str]]:
        raw = self._git_bytes("cat-file", "-p", commit)
        headers = raw.split(b"\n\n", 1)[0].splitlines()
        try:
            tree_header = b"tree "
            parent_header = b"parent "
            trees = [
                line[len(tree_header) :].decode("ascii")
                for line in headers
                if line.startswith(tree_header)
            ]
            parents = [
                line[len(parent_header) :].decode("ascii")
                for line in headers
                if line.startswith(parent_header)
            ]
        except UnicodeDecodeError as exc:
            raise MainCompositionError("Git commit headers are not ASCII") from exc
        if len(trees) != 1 or any(
            not _GIT_OBJECT.fullmatch(item) for item in [trees[0], *parents]
        ):
            raise MainCompositionError("Git commit object topology is malformed")
        return trees[0], parents

    def _verify_commit_tree(self, commit: str, expected_tree: str | None, label: str) -> None:
        actual, _parents = self._commit_topology(commit)
        if expected_tree is not None and actual != expected_tree:
            raise MainCompositionError(f"{label} tree differs from trusted package")
        entries = self._git_bytes("ls-tree", "-r", "-z", commit)
        seen_paths: set[str] = set()
        for entry in entries.rstrip(b"\0").split(b"\0"):
            if not entry:
                continue
            metadata, separator, raw_path = entry.partition(b"\t")
            if not separator:
                raise MainCompositionError(f"{label} tree entry is malformed")
            mode_type = metadata.decode("ascii", "strict").split(" ")
            if (
                len(mode_type) != 3
                or mode_type[1] != "blob"
                or mode_type[0] not in {"100644", "100755"}
            ):
                raise MainCompositionError(f"{label} tree contains a VCS/reparse hazard")
            path = raw_path.decode("utf-8", "strict")
            if (
                not self._safe_path(path)
                or unicodedata.normalize("NFC", path) != path
                or path.casefold() in seen_paths
            ):
                raise MainCompositionError(f"{label} tree contains an unsafe path")
            seen_paths.add(path.casefold())

    def _environment(self) -> dict[str, str]:
        environment = {
            key: os.environ[key]
            for key in (
                "PATH",
                "HOME",
                "USERPROFILE",
                "SYSTEMROOT",
                "TEMP",
                "TMP",
                "LANG",
                "LC_ALL",
            )
            if key in os.environ
        }
        environment.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_NO_REPLACE_OBJECTS": "1",
            }
        )
        return environment

    def _git(self, *arguments: str) -> str:
        return self._run(["git", *arguments])

    def _git_bytes(self, *arguments: str) -> bytes:
        return self._run_bytes(["git", *arguments])

    def _run(
        self,
        command: list[str],
        *,
        env: dict[str, str] | None = None,
        input_bytes: bytes | None = None,
        check: bool = True,
    ) -> str:
        return (
            self._run_bytes(command, env=env, input_bytes=input_bytes, check=check)
            .decode("utf-8", "strict")
            .strip()
        )

    def _run_bytes(
        self,
        command: list[str],
        *,
        env: dict[str, str] | None = None,
        input_bytes: bytes | None = None,
        check: bool = True,
    ) -> bytes:
        try:
            result = subprocess.run(
                command,
                cwd=self.root,
                check=check,
                capture_output=True,
                input=input_bytes,
                timeout=self._timeout,
                shell=False,
                env=env or self._environment(),
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise MainCompositionError("safe Git composition command failed") from exc
        if len(result.stdout) > _MAX_OUTPUT or len(result.stderr) > _MAX_OUTPUT:
            raise MainCompositionError("Git composition output exceeded configured bound")
        return result.stdout


DeterministicMainCompositionAdapter = MainCompositionAdapter
DeterministicCompositionAdapter = MainCompositionAdapter


def compose_main_candidate(
    root: Path,
    journal: MainGraduationJournal,
    source: MainSourcePackageBinding,
    *,
    base: MainBaseSnapshot | None = None,
    repository_digest: str,
    base_reader: MainBaseReader,
) -> MainCompositionResult:
    """Small functional entry point for one-shot offline composition."""

    return MainCompositionAdapter(
        root,
        journal,
        repository_digest=repository_digest,
        base_reader=base_reader,
    ).compose(source, base=base)

__all__ = [
    "DeterministicCompositionAdapter",
    "DeterministicMainCompositionAdapter",
    "MainBaseReader",
    "MainBaseSnapshot",
    "MainCompositionAdapter",
    "MainCompositionError",
    "MainCompositionResult",
    "compose_main_candidate",
]
