"""Controller-owned, append-only publication of evaluated Git candidates.

This adapter is deliberately narrower than a normal Git client.  It treats the
candidate directory as untrusted input, builds the publication in a private
clone, and performs one non-forced push only after the resulting commit has
been independently checked against the candidate tree digest.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from urllib.parse import urlsplit, urlunsplit

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.git.repository import GitRepositoryError, GitRepositoryReader
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_promotion import CandidatePublicationBinding
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest


class GitCommandRunner(Protocol):
    """Injected command runner used by tests and controlled deployments."""

    def __call__(
        self,
        arguments: list[str],
        cwd: Path,
        environment: Mapping[str, str],
        timeout: float,
    ) -> subprocess.CompletedProcess[str]: ...


@dataclass(frozen=True, slots=True)
class PublicationPlan:
    """Immutable, content-addressed publication intent written before push."""

    publication_id: str
    repository_digest: str
    expected_remote: str
    base_commit: str
    base_tree: str
    candidate_digest: str
    candidate_ref: str
    candidate_commit: str
    candidate_tree: str
    controller_publisher_identity: str

    def identity_payload(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "repository_digest": self.repository_digest,
            "expected_remote": self.expected_remote,
            "base_commit": self.base_commit,
            "base_tree": self.base_tree,
            "candidate_digest": self.candidate_digest,
            "candidate_ref": self.candidate_ref,
            "candidate_commit": self.candidate_commit,
            "candidate_tree": self.candidate_tree,
            "controller_publisher_identity": self.controller_publisher_identity,
        }

    def payload(self) -> dict[str, Any]:
        return {"publication_id": self.publication_id, **self.identity_payload()}


@dataclass(frozen=True, slots=True)
class PublicationResult:
    """Verified publication plus the exact stored evidence artifact."""

    binding: CandidatePublicationBinding
    evidence_bytes: bytes
    evidence_artifact: ArtifactRef


@dataclass(frozen=True, slots=True)
class PublicationOutcome:
    publication_id: str
    state: Literal["pushed", "verified", "ambiguous"]
    candidate_ref: str
    candidate_commit: str
    candidate_tree: str
    error: str | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "publication_id": self.publication_id,
            "state": self.state,
            "candidate_ref": self.candidate_ref,
            "candidate_commit": self.candidate_commit,
            "candidate_tree": self.candidate_tree,
            "error": self.error,
        }


class PublicationJournal(Protocol):
    """Durable journal used to fence publication retries and store evidence."""

    def record_plan(self, plan: PublicationPlan) -> ArtifactRef: ...

    def read_plan(self, publication_id: str) -> PublicationPlan | None: ...

    def find_matching_plan(
        self, repository_digest: str, expected_remote: str, base_commit: str,
        base_tree: str, candidate_digest: str, controller_publisher_identity: str
    ) -> PublicationPlan | None: ...

    def record_outcome(self, outcome: PublicationOutcome) -> ArtifactRef: ...

    def record_evidence(self, data: bytes) -> ArtifactRef: ...


class PublicationAmbiguousError(GitRepositoryError):
    """The remote may have accepted a push; reconcile before any retry."""

    def __init__(self, publication_id: str, candidate_ref: str, message: str) -> None:
        super().__init__(message)
        self.publication_id = publication_id
        self.candidate_ref = candidate_ref


class FilesystemPublicationJournal:
    """Small durable publication journal backed by the artifact store."""

    def __init__(self, root: Path, *, max_record_bytes: int = 2_000_000) -> None:
        if max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        self.root = root.resolve()
        self._store = FilesystemArtifactStore(self.root / "artifacts")
        self._plans = self.root / "plans"
        self._outcomes = self.root / "outcomes"
        self._max_record_bytes = max_record_bytes

    def record_plan(self, plan: PublicationPlan) -> ArtifactRef:
        return self._record("plan", plan.publication_id, plan.payload(), self._plans)

    def read_plan(self, publication_id: str) -> PublicationPlan | None:
        data = self._read_index(self._plans, publication_id)
        if data is None:
            return None
        payload = json.loads(data.decode("utf-8"))
        if canonical_bytes(payload) != data:
            raise GitRepositoryError("publication plan is not canonical JSON")
        return self._plan_from_payload(payload)

    def find_matching_plan(
        self, repository_digest: str, expected_remote: str, base_commit: str,
        base_tree: str, candidate_digest: str, controller_publisher_identity: str
    ) -> PublicationPlan | None:
        matches: list[PublicationPlan] = []
        if not self._plans.is_dir():
            return None
        for index in sorted(self._plans.glob("*.json")):
            reference = ArtifactRef.model_validate(json.loads(index.read_text(encoding="utf-8")))
            if reference.role != "candidate-publication-plan":
                raise GitRepositoryError("publication plan index role is malformed")
            plan = self._plan_from_payload(json.loads(self._store.read_bytes(reference)))
            if index.stem != plan.publication_id.removeprefix("sha256:"):
                raise GitRepositoryError("publication plan index identity is malformed")
            if (
                plan.repository_digest == repository_digest
                and plan.expected_remote == expected_remote
                and plan.base_commit == base_commit
                and plan.base_tree == base_tree
                and plan.candidate_digest == candidate_digest
                and plan.controller_publisher_identity == controller_publisher_identity
            ):
                matches.append(plan)
        if len(matches) > 1:
            raise GitRepositoryError("multiple matching publication plans require reconciliation")
        return matches[0] if matches else None

    def record_outcome(self, outcome: PublicationOutcome) -> ArtifactRef:
        key = f"{outcome.publication_id.removeprefix('sha256:')}-{outcome.state}"
        return self._record("outcome", key, outcome.payload(), self._outcomes)

    def record_evidence(self, data: bytes) -> ArtifactRef:
        if len(data) > self._max_record_bytes:
            raise GitRepositoryError("publication evidence exceeds configured bound")
        artifact = self._store.put_bytes(
            data,
            media_type="application/vnd.avo.candidate-publication+json",
            role="candidate-publication-evidence",
            max_bytes=self._max_record_bytes,
        )
        _sync_directory(self._store.path_for_digest(artifact.digest).parent)
        return artifact

    def _record(
        self, kind: str, identifier: str, payload: dict[str, Any], directory: Path
    ) -> ArtifactRef:
        identifier = self._safe_identifier(identifier)
        data = canonical_bytes(payload)
        if len(data) > self._max_record_bytes:
            raise GitRepositoryError(f"publication {kind} exceeds configured bound")
        artifact = self._store.put_bytes(
            data,
            media_type="application/vnd.avo.candidate-publication+json",
            role=f"candidate-publication-{kind}",
            max_bytes=self._max_record_bytes,
        )
        _sync_directory(self._store.path_for_digest(artifact.digest).parent)
        index = directory / f"{identifier.removeprefix('sha256:')}.json"
        directory.mkdir(parents=True, exist_ok=True)
        reference = canonical_bytes(artifact.model_dump(mode="json"))
        try:
            with index.open("xb") as handle:
                handle.write(reference)
                handle.flush()
                os.fsync(handle.fileno())
            _sync_directory(directory)
        except FileExistsError:
            old = json.loads(index.read_text(encoding="utf-8"))
            old_ref = ArtifactRef.model_validate(old)
            old_data = self._store.read_bytes(old_ref)
            if old_ref.digest != artifact.digest or old_data != data:
                raise GitRepositoryError(f"conflicting publication {kind}") from None
            return old_ref
        return artifact

    def _read_index(self, directory: Path, identifier: str) -> bytes | None:
        identifier = self._safe_identifier(identifier)
        index = directory / f"{identifier.removeprefix('sha256:')}.json"
        if not index.is_file():
            return None
        reference = ArtifactRef.model_validate(json.loads(index.read_text(encoding="utf-8")))
        return self._store.read_bytes(reference)

    @staticmethod
    def _safe_identifier(identifier: str) -> str:
        if not re.fullmatch(
            r"(?:sha256:)?[0-9a-f]{64}(?:-[a-z]+)?", identifier
        ):
            raise GitRepositoryError("publication journal identifier is malformed")
        return identifier

    @staticmethod
    def _plan_from_payload(payload: Mapping[str, Any]) -> PublicationPlan:
        if payload.get("schema_version") != 1:
            raise GitRepositoryError("unsupported publication plan schema")
        expected = {"schema_version", *PublicationPlan.__dataclass_fields__}
        if set(payload) != expected:
            raise GitRepositoryError("publication plan fields are malformed")
        values = {key: payload[key] for key in PublicationPlan.__dataclass_fields__}
        plan = PublicationPlan(**values)
        if canonical_digest(plan.identity_payload()) != plan.publication_id:
            raise GitRepositoryError("publication plan digest mismatch")
        return plan


class GitCandidatePublisher:
    """Publish one candidate commit to a fresh controller-owned ref.

    ``expected_remote`` and ``repository_digest`` are configuration, never
    candidate input.  A local/file remote is accepted for hermetic tests; live
    deployments should use an HTTPS remote.
    """

    _MAX_OUTPUT = 1024 * 1024
    _OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")

    def __init__(
        self,
        *,
        expected_remote: str,
        repository_digest: str,
        controller_publisher_identity: str,
        publication_journal: PublicationJournal | None = None,
        max_file_bytes: int = 10 * 1024 * 1024,
        max_tree_bytes: int = 100 * 1024 * 1024,
        max_entries: int = 100_000,
        git_executable: str = "git",
        command_timeout_seconds: float = 30.0,
        max_output_bytes: int = 1024 * 1024,
        credential_helper: Path | None = None,
        allow_local_remote_for_tests: bool = False,
        runner: GitCommandRunner | None = None,
    ) -> None:
        if not expected_remote.strip():
            raise ValueError("expected_remote is required")
        if not repository_digest.startswith("sha256:"):
            raise ValueError("repository_digest must be a sha256 digest")
        if not controller_publisher_identity.strip():
            raise ValueError("controller_publisher_identity is required")
        if any(char in controller_publisher_identity for char in "\r\n\x00"):
            raise ValueError("publisher identity contains a forbidden character")
        if max_file_bytes <= 0 or max_tree_bytes <= 0 or max_entries <= 0:
            raise ValueError("Git publication bounds must be positive")
        if command_timeout_seconds <= 0:
            raise ValueError("command timeout must be positive")
        if max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        self.expected_remote = self._safe_remote(
            expected_remote, allow_local_remote=allow_local_remote_for_tests
        )
        self.repository_digest = repository_digest
        calculated = self._remote_digest(self.expected_remote)
        if calculated != repository_digest:
            raise ValueError("repository_digest does not match expected_remote")
        self.controller_publisher_identity = controller_publisher_identity.strip()
        self.max_file_bytes = max_file_bytes
        self.max_tree_bytes = max_tree_bytes
        self.max_entries = max_entries
        self.git_executable = git_executable
        self.command_timeout_seconds = command_timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.publication_journal = publication_journal
        self.allow_local_remote_for_tests = allow_local_remote_for_tests
        self.credential_helper = self._validate_credential_helper(credential_helper)
        self._runner = runner

    def publish(
        self,
        candidate_root: Path,
        base_commit: str,
        base_tree: str,
        expected_candidate_digest: str,
    ) -> CandidatePublicationBinding:
        return self.publish_result(
            candidate_root, base_commit, base_tree, expected_candidate_digest
        ).binding

    def publish_result(
        self,
        candidate_root: Path,
        base_commit: str,
        base_tree: str,
        expected_candidate_digest: str,
    ) -> PublicationResult:
        """Create and publish a verified candidate commit.

        Every failure before ``git push`` is local and therefore leaves the
        remote untouched.  The push itself is a single ordinary (non-force)
        update to a newly generated ref.
        """
        if self.publication_journal is None:
            raise GitRepositoryError("a durable publication journal is required")
        self._validate_object(base_commit, "base_commit")
        self._validate_object(base_tree, "base_tree")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_candidate_digest):
            raise GitRepositoryError("candidate digest is malformed")

        existing = self.publication_journal.find_matching_plan(
            self.repository_digest,
            self.expected_remote,
            base_commit,
            base_tree,
            expected_candidate_digest,
            self.controller_publisher_identity,
        )
        if existing is not None:
            recovered = self.reconcile(existing.publication_id)
            if recovered is not None:
                return recovered
            raise PublicationAmbiguousError(
                existing.publication_id,
                existing.candidate_ref,
                "matching publication plan exists without a provider-visible ref; "
                "reconcile manually",
            )

        candidate = Path(candidate_root)
        reader = GitRepositoryReader(
            Path.cwd(),
            base_commit,
            self.expected_remote,
            "sha256:" + "0" * 64,
            self.max_file_bytes,
            self.max_tree_bytes,
            self.max_entries,
        )
        initial = self._scan_candidate(reader, candidate)
        if initial.digest != expected_candidate_digest:
            raise GitRepositoryError("candidate digest does not match evaluated digest")

        with tempfile.TemporaryDirectory(prefix="avo-candidate-publish-") as directory:
            clone = Path(directory) / "clone"
            candidate_resolved = candidate.resolve(strict=True)
            temporary_root = Path(directory).resolve(strict=True)
            if self._paths_overlap(candidate_resolved, temporary_root):
                raise GitRepositoryError("candidate root overlaps publication workspace")
            self._run(
                [
                    "clone", "--no-checkout", "--no-recurse-submodules", "--",
                    self.expected_remote, str(clone),
                ]
            )
            self._verify_remote(clone)
            self._verify_base(clone, base_commit, base_tree)
            self._run(["checkout", "--detach", "--force", base_commit], cwd=clone)
            self._run(["clean", "-ffdx"], cwd=clone)
            self._remove_worktree_contents(clone)
            self._copy_candidate(candidate, clone)

            # Scan both sides again.  This catches a candidate that changed
            # during clone/copy, including changes made by a concurrent writer.
            final_source = self._scan_candidate(reader, candidate)
            if (
                final_source.digest != initial.digest
                or final_source.digest != expected_candidate_digest
            ):
                raise GitRepositoryError("candidate changed during publication")
            self._run(
                ["add", "--all", "--", "."],
                cwd=clone,
            )
            environment = self._environment()
            base_date = self._run(
                ["show", "-s", "--format=%cI", base_commit], cwd=clone
            ).stdout.strip()
            if not base_date:
                raise GitRepositoryError("trusted base has no deterministic commit timestamp")
            environment.update(
                {
                    "GIT_AUTHOR_DATE": base_date,
                    "GIT_COMMITTER_DATE": base_date,
                }
            )
            self._run(
                [
                    "-c", f"user.name={self.controller_publisher_identity}",
                    "-c", "user.email=avo-controller@invalid",
                    "-c", "commit.gpgSign=false",
                    "commit", "--no-gpg-sign", "--allow-empty", "-m",
                    "AVO candidate publication",
                ],
                cwd=clone,
                environment=environment,
            )
            candidate_commit = self._run(["rev-parse", "HEAD"], cwd=clone).stdout.strip()
            candidate_tree = self._run(["rev-parse", "HEAD^{tree}"], cwd=clone).stdout.strip()
            parent_line = self._run(
                ["rev-list", "--parents", "-n", "1", "HEAD"], cwd=clone
            ).stdout.strip()
            parents = parent_line.split()[1:]
            if len(parents) != 1 or parents[0] != base_commit:
                raise GitRepositoryError("published commit does not have the expected sole parent")

            # The archive is an independent materialization of the Git object;
            # it must hash to the same digest as the VCS-free input.
            archive_reader = GitRepositoryReader(
                clone,
                "HEAD",
                self.expected_remote,
                "sha256:" + "0" * 64,
                self.max_file_bytes,
                self.max_tree_bytes,
                self.max_entries,
            )
            archive_name = "_materialized_archive"
            scan_name = "_scan_tree"
            archive = cast(Callable[[str], Any], getattr(archive_reader, archive_name))
            scan_tree = cast(Callable[[Path], Any], getattr(archive_reader, scan_name))
            with archive(candidate_commit) as materialized:
                published = scan_tree(Path(materialized))
            if published.digest != expected_candidate_digest:
                raise GitRepositoryError("published commit tree does not match candidate digest")

            self._validate_object(candidate_commit, "candidate_commit")
            self._validate_object(candidate_tree, "candidate_tree")
            candidate_ref = self._new_candidate_ref()
            plan = self._new_plan(
                base_commit,
                base_tree,
                expected_candidate_digest,
                candidate_ref,
                candidate_commit,
                candidate_tree,
            )
            try:
                self.publication_journal.record_plan(plan)
            except Exception as exc:
                raise GitRepositoryError("publication plan was not durably recorded") from exc
            if self._remote_ref_exists(clone, candidate_ref):
                raise GitRepositoryError("generated candidate ref already exists")
            try:
                self._run(
                    ["push", "--no-follow-tags", "origin", f"{candidate_commit}:{candidate_ref}"],
                    cwd=clone,
                )
            except Exception as exc:
                self._record_ambiguous(plan, str(exc))
                raise PublicationAmbiguousError(
                    plan.publication_id,
                    candidate_ref,
                    "candidate push outcome is ambiguous; reconcile before retrying",
                ) from exc
            self._record_outcome(
                PublicationOutcome(
                    plan.publication_id, "pushed", candidate_ref, candidate_commit, candidate_tree
                )
            )
            try:
                # Verify the provider-visible ref points at exactly this commit.
                remote_commit = self._remote_ref_commit(clone, candidate_ref)
                if remote_commit != candidate_commit:
                    raise GitRepositoryError("published candidate ref does not point at commit")
            except Exception as exc:
                self._record_ambiguous(plan, str(exc))
                raise PublicationAmbiguousError(
                    plan.publication_id,
                    candidate_ref,
                    "candidate publication observation is ambiguous; reconcile before retrying",
                ) from exc

        evidence_payload = {
            "schema_version": 1,
            "publication_id": plan.publication_id,
            "repository_digest": self.repository_digest,
            "base_commit": base_commit,
            "base_tree": base_tree,
            "candidate_digest": expected_candidate_digest,
            "candidate_ref": candidate_ref,
            "candidate_commit": candidate_commit,
            "candidate_tree": candidate_tree,
            "controller_publisher_identity": self.controller_publisher_identity,
            "verified": True,
        }
        evidence_bytes = canonical_bytes(evidence_payload)
        evidence_digest = canonical_digest(evidence_payload)
        try:
            evidence_artifact = self.publication_journal.record_evidence(evidence_bytes)
        except Exception as exc:
            raise PublicationAmbiguousError(
                plan.publication_id,
                plan.candidate_ref,
                "candidate was pushed but publication evidence was not durable; "
                "reconcile before retrying",
            ) from exc
        if evidence_artifact.digest != evidence_digest or evidence_artifact.size_bytes != len(
            evidence_bytes
        ):
            raise PublicationAmbiguousError(
                plan.publication_id,
                candidate_ref,
                "publication evidence was not durably content-addressed",
            )
        binding_payload = {
            key: value for key, value in evidence_payload.items() if key != "publication_id"
        }
        binding = CandidatePublicationBinding.model_validate(
            binding_payload | {"publication_evidence_digest": evidence_digest}
        )
        self._record_outcome(
            PublicationOutcome(
                plan.publication_id, "verified", candidate_ref, candidate_commit, candidate_tree
            )
        )
        return PublicationResult(binding, evidence_bytes, evidence_artifact)

    def reconcile(self, publication_id: str) -> PublicationResult | None:
        """Reconcile a previously planned/pushed publication without retrying push."""

        if self.publication_journal is None:
            raise GitRepositoryError("a durable publication journal is required")
        plan = self.publication_journal.read_plan(publication_id)
        if plan is None:
            raise GitRepositoryError("publication plan was not found")
        if (
            plan.repository_digest != self.repository_digest
            or plan.expected_remote != self.expected_remote
        ):
            raise GitRepositoryError("publication plan belongs to a different repository")
        with tempfile.TemporaryDirectory(prefix="avo-candidate-reconcile-") as directory:
            clone = Path(directory) / "clone"
            self._run(
                [
                    "clone", "--no-checkout", "--no-recurse-submodules", "--",
                    self.expected_remote, str(clone),
                ]
            )
            self._verify_remote(clone)
            remote_commit = self._remote_ref_commit_optional(clone, plan.candidate_ref)
            if remote_commit is None:
                return None
            if remote_commit != plan.candidate_commit:
                raise GitRepositoryError("reconciled candidate ref points at an unexpected commit")
            remote_tree = self._run(
                ["rev-parse", f"{remote_commit}^{{tree}}"], cwd=clone
            ).stdout.strip()
            parents = self._run(
                ["rev-list", "--parents", "-n", "1", remote_commit], cwd=clone
            ).stdout.strip().split()[1:]
            if remote_tree != plan.candidate_tree or parents != [plan.base_commit]:
                raise GitRepositoryError("reconciled candidate commit binding differs from plan")
        evidence_payload = {
            "schema_version": 1,
            "publication_id": plan.publication_id,
            "repository_digest": plan.repository_digest,
            "base_commit": plan.base_commit,
            "base_tree": plan.base_tree,
            "candidate_digest": plan.candidate_digest,
            "candidate_ref": plan.candidate_ref,
            "candidate_commit": plan.candidate_commit,
            "candidate_tree": plan.candidate_tree,
            "controller_publisher_identity": plan.controller_publisher_identity,
            "verified": True,
        }
        evidence_bytes = canonical_bytes(evidence_payload)
        evidence_digest = canonical_digest(evidence_payload)
        evidence_artifact = self.publication_journal.record_evidence(evidence_bytes)
        if (
            evidence_artifact.digest != evidence_digest
            or evidence_artifact.size_bytes != len(evidence_bytes)
        ):
            raise GitRepositoryError("reconciled publication evidence is not content-addressed")
        binding_payload = {
            key: value for key, value in evidence_payload.items() if key != "publication_id"
        }
        binding = CandidatePublicationBinding.model_validate(
            binding_payload | {"publication_evidence_digest": evidence_digest}
        )
        self._record_outcome(
            PublicationOutcome(
                plan.publication_id,
                "verified",
                plan.candidate_ref,
                plan.candidate_commit,
                plan.candidate_tree,
            )
        )
        return PublicationResult(binding, evidence_bytes, evidence_artifact)

    def _new_plan(
        self,
        base_commit: str,
        base_tree: str,
        candidate_digest: str,
        candidate_ref: str,
        candidate_commit: str,
        candidate_tree: str,
    ) -> PublicationPlan:
        values = {
            "schema_version": 1,
            "repository_digest": self.repository_digest,
            "expected_remote": self.expected_remote,
            "base_commit": base_commit,
            "base_tree": base_tree,
            "candidate_digest": candidate_digest,
            "candidate_ref": candidate_ref,
            "candidate_commit": candidate_commit,
            "candidate_tree": candidate_tree,
            "controller_publisher_identity": self.controller_publisher_identity,
        }
        return PublicationPlan(
            publication_id=canonical_digest(values),
            repository_digest=self.repository_digest,
            expected_remote=self.expected_remote,
            base_commit=base_commit,
            base_tree=base_tree,
            candidate_digest=candidate_digest,
            candidate_ref=candidate_ref,
            candidate_commit=candidate_commit,
            candidate_tree=candidate_tree,
            controller_publisher_identity=self.controller_publisher_identity,
        )

    def _record_outcome(self, outcome: PublicationOutcome) -> None:
        try:
            self._journal().record_outcome(outcome)
        except Exception as exc:
            raise PublicationAmbiguousError(
                outcome.publication_id,
                outcome.candidate_ref,
                "publication outcome was not durably recorded; reconcile before retrying",
            ) from exc

    def _record_ambiguous(self, plan: PublicationPlan, error: str) -> None:
        with suppress(Exception):
            self._journal().record_outcome(
                PublicationOutcome(
                    plan.publication_id,
                    "ambiguous",
                    plan.candidate_ref,
                    plan.candidate_commit,
                    plan.candidate_tree,
                    self._safe_error(error),
                )
            )
            # The original operation is already ambiguous.  Preserve that fact even
            # if the journal itself is unavailable; callers must reconcile manually.

    def _journal(self) -> PublicationJournal:
        if self.publication_journal is None:
            raise GitRepositoryError("a durable publication journal is required")
        return self.publication_journal

    @staticmethod
    def _scan_candidate(reader: GitRepositoryReader, candidate: Path) -> Any:
        scanner_name = "_scan_candidate"
        scanner = cast(Callable[[Path], Any], getattr(reader, scanner_name))
        return scanner(candidate)

    def _verify_remote(self, clone: Path) -> None:
        actual = self._safe_remote(
            self._run(["remote", "get-url", "origin"], cwd=clone).stdout,
            allow_local_remote=self.allow_local_remote_for_tests,
        )
        if actual != self.expected_remote:
            raise GitRepositoryError("origin remote identity mismatch")

    def _verify_base(self, clone: Path, commit: str, tree: str) -> None:
        actual_commit = self._run(
            ["rev-parse", "--verify", f"{commit}^{{commit}}"], cwd=clone
        ).stdout.strip()
        actual_tree = self._run(
            ["rev-parse", "--verify", f"{actual_commit}^{{tree}}"], cwd=clone
        ).stdout.strip()
        if actual_commit != commit or actual_tree != tree:
            raise GitRepositoryError("trusted base commit or tree mismatch")

    def _copy_candidate(self, source: Path, destination: Path) -> None:
        for item in sorted(source.iterdir(), key=lambda path: path.name):
            if item.name == ".git":
                raise GitRepositoryError("candidate contains .git")
            self._copy_entry(item, destination / item.name)

    def _copy_entry(self, source: Path, destination: Path) -> None:
        metadata = os.lstat(source)
        if stat.S_ISLNK(metadata.st_mode) or self._is_reparse(metadata):
            raise GitRepositoryError("candidate contains symlink or reparse point")
        if stat.S_ISDIR(metadata.st_mode):
            destination.mkdir()
            for child in sorted(source.iterdir(), key=lambda path: path.name):
                if child.name == ".git":
                    raise GitRepositoryError("candidate contains .git")
                self._copy_entry(child, destination / child.name)
            destination.chmod(stat.S_IMODE(metadata.st_mode))
            return
        if not stat.S_ISREG(metadata.st_mode):
            raise GitRepositoryError("candidate contains unsupported file type")
        if metadata.st_nlink != 1:
            raise GitRepositoryError("candidate contains a hard-linked file")
        if metadata.st_size > self.max_file_bytes:
            raise GitRepositoryError("candidate file exceeds configured bound")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
        try:
            opened = os.fstat(descriptor)
            if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
                raise GitRepositoryError("candidate changed while being copied")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with os.fdopen(descriptor, "rb", closefd=True) as source_handle:
                descriptor = -1
                with destination.open("xb") as target:
                    copied = 0
                    while chunk := source_handle.read(
                        min(1024 * 1024, self.max_file_bytes - copied + 1)
                    ):
                        copied += len(chunk)
                        if copied > self.max_file_bytes:
                            raise GitRepositoryError("candidate file exceeds configured bound")
                        target.write(chunk)
                    target.flush()
            final = os.fstat(descriptor) if descriptor != -1 else os.lstat(source)
            if descriptor == -1 and not self._same_source_metadata(metadata, final):
                raise GitRepositoryError("candidate changed while being copied")
            destination.chmod(stat.S_IMODE(metadata.st_mode))
        finally:
            if descriptor != -1:
                os.close(descriptor)

    @staticmethod
    def _remove_worktree_contents(clone: Path) -> None:
        for item in clone.iterdir():
            if item.name == ".git":
                continue
            if item.is_dir() and not item.is_symlink():
                shutil.rmtree(item)
            else:
                item.unlink()

    def _remote_ref_exists(self, clone: Path, ref: str) -> bool:
        result = self._run(["ls-remote", "--exit-code", "origin", ref], cwd=clone, check=False)
        if result.returncode not in (0, 2):
            raise GitRepositoryError("unable to inspect candidate ref")
        return bool(result.stdout.strip())

    def _remote_ref_commit(self, clone: Path, ref: str) -> str:
        commit = self._remote_ref_commit_optional(clone, ref)
        if commit is None:
            raise GitRepositoryError("candidate ref was not found")
        return commit

    def _remote_ref_commit_optional(self, clone: Path, ref: str) -> str | None:
        result = self._run(
            ["ls-remote", "--exit-code", "origin", ref], cwd=clone, check=False
        )
        if result.returncode == 2:
            return None
        if result.returncode != 0:
            detail = result.stderr or result.stdout or "Git remote observation failed"
            raise GitRepositoryError(self._safe_error(detail))
        line = result.stdout.strip().splitlines()
        if len(line) != 1:
            raise GitRepositoryError("candidate ref observation is invalid")
        return line[0].split()[0]

    def _new_candidate_ref(self) -> str:
        return f"refs/heads/avo/candidate/{secrets.token_hex(16)}"

    def _run(
        self,
        arguments: list[str],
        *,
        cwd: Path | None = None,
        environment: Mapping[str, str] | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        workdir = cwd or Path.cwd()
        env = dict(self._environment())
        if environment:
            env.update(environment)
        try:
            if self._runner is not None:
                result = self._runner(
                    [self.git_executable, *arguments],
                    workdir,
                    env,
                    self.command_timeout_seconds,
                )
            else:
                process = subprocess.Popen(
                    [self.git_executable, *arguments],
                    cwd=workdir,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                )
                try:
                    stdout, stderr = process.communicate(
                        timeout=self.command_timeout_seconds
                    )
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                    raise
                if len(stdout) > self.max_output_bytes or len(stderr) > self.max_output_bytes:
                    process.kill() if process.poll() is None else None
                    raise GitRepositoryError("Git command output exceeded configured bound")
                result = subprocess.CompletedProcess(
                    [self.git_executable, *arguments],
                    process.returncode,
                    stdout.decode("utf-8", "replace"),
                    stderr.decode("utf-8", "replace"),
                )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitRepositoryError(self._safe_error(str(exc))) from exc
        if len(result.stdout.encode("utf-8")) > self.max_output_bytes or len(
            result.stderr.encode("utf-8")
        ) > self.max_output_bytes:
            raise GitRepositoryError("Git command output exceeded configured bound")
        if check and result.returncode != 0:
            detail = result.stderr or result.stdout or "Git command failed"
            raise GitRepositoryError(self._safe_error(detail))
        return result

    def _environment(self) -> dict[str, str]:
        environment = {
            key: os.environ[key]
            for key in (
                "PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "TEMP", "TMP", "LANG", "LC_ALL"
            )
            if key in os.environ
        }
        environment.update({
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
        })
        if self.credential_helper is not None:
            environment["GIT_ASKPASS"] = str(self.credential_helper)
            environment["SSH_ASKPASS"] = str(self.credential_helper)
            # An explicitly configured controller-owned askpass helper may
            # read the token at execution time.  Keep the allowlist narrow:
            # do not expose GITHUB_TOKEN to Git unless such a helper is in use.
            token = os.environ.get("GITHUB_TOKEN")
            if token:
                environment["GITHUB_TOKEN"] = token
        return environment

    @staticmethod
    def _validate_object(value: str, label: str) -> None:
        if not GitCandidatePublisher._OBJECT.fullmatch(value):
            raise GitRepositoryError(f"{label} is malformed")

    @staticmethod
    def _is_reparse(metadata: os.stat_result) -> bool:
        return bool((getattr(metadata, "st_file_attributes", 0) or 0) & 0x400)

    @staticmethod
    def _safe_remote(raw: str, *, allow_local_remote: bool = False) -> str:
        value = raw.strip()
        if not value or value.startswith("-"):
            raise ValueError("remote must not be empty or option-like")
        if "://" not in value:
            raise ValueError("remote must be an explicit HTTPS or test file URL")
        parsed = urlsplit(value)
        if parsed.username or parsed.password:
            raise ValueError("remote credentials are not permitted")
        host = parsed.hostname or ""
        if parsed.port:
            host += f":{parsed.port}"
        scheme = parsed.scheme.lower()
        if scheme == "https":
            if host != "github.com" or parsed.port or parsed.query or parsed.fragment:
                raise ValueError("live remote must be an HTTPS github.com URL")
        elif not (allow_local_remote and scheme == "file" and not parsed.netloc):
            raise ValueError("remote transport is not allowed")
        return urlunsplit((scheme, host, parsed.path.rstrip("/"), "", ""))

    @staticmethod
    def _validate_credential_helper(helper: Path | None) -> Path | None:
        if helper is None:
            return None
        path = Path(helper)
        try:
            metadata = os.lstat(path)
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise ValueError("credential helper cannot be inspected") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("credential helper must be a regular non-symlink file")
        return resolved

    @staticmethod
    def _paths_overlap(left: Path, right: Path) -> bool:
        return left == right or left.is_relative_to(right) or right.is_relative_to(left)

    @staticmethod
    def _same_source_metadata(left: os.stat_result, right: os.stat_result) -> bool:
        return (
            left.st_dev == right.st_dev
            and left.st_ino == right.st_ino
            and left.st_size == right.st_size
            and stat.S_IMODE(left.st_mode) == stat.S_IMODE(right.st_mode)
            and left.st_mtime_ns == right.st_mtime_ns
        )

    @staticmethod
    def _remote_digest(remote: str) -> str:
        return "sha256:" + hashlib.sha256(remote.encode("utf-8")).hexdigest()

    @staticmethod
    def _safe_error(value: str) -> str:
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            value = value.replace(token, "[REDACTED]")
        return re.sub(r"([A-Za-z][A-Za-z0-9+.-]*://)[^\s/@]+@", r"\1", value)[:1024 * 1024]


__all__ = [
    "FilesystemPublicationJournal",
    "GitCandidatePublisher",
    "GitCommandRunner",
    "PublicationAmbiguousError",
    "PublicationJournal",
    "PublicationOutcome",
    "PublicationPlan",
    "PublicationResult",
]


def _sync_directory(path: Path) -> None:
    """Durably publish journal directory entries where supported."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        unsupported = {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EACCES}
        if os.name == "nt" and exc.errno in unsupported:
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
