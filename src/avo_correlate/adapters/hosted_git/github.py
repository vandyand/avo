"""Small, fail-closed GitHub REST adapter for protected integration promotion."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from math import ceil
from typing import Literal, Protocol, cast
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from avo_correlate.contracts.integration_campaign import campaign_marker_digest
from avo_correlate.contracts.integration_live_rollback_completion import (
    LiveRollbackCheckEntry,
    LiveRollbackManifestEvidence,
    LiveRollbackProtectionEntry,
    LiveRollbackWorkflowEvidence,
)
from avo_correlate.contracts.integration_promotion import (
    IntegrationMergeResult,
    IntegrationPromotionIntent,
    IntegrationPromotionPreconditionError,
    IntegrationProviderObservation,
    IntegrationProviderReconciliation,
)
from avo_correlate.contracts.integration_soak import (
    SOAK_APP_ID,
    SOAK_CONTEXT,
    SOAK_MARKER_BLOB_DIGEST,
    SOAK_MARKER_PATH,
    SOAK_WORKFLOW_PATH,
    SOAK_WORKFLOW_VARIABLE,
    FailedSoakAttestation,
)
from avo_correlate.contracts.synthetic_validation import SyntheticValidationObservation
from avo_correlate.domain.canonical import canonical_digest

type JsonPrimitive = str | int | float | bool | None
type JsonValue = JsonPrimitive | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]
type JsonBody = Mapping[str, JsonValue]

_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class GitHubTransportError(RuntimeError):
    """Failure where the server's result is not authoritative."""


class GitHubRejected(RuntimeError):
    """Authoritative, non-success response from GitHub."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class IntegrationTargetObservation:
    target_ref: str
    commit: str
    tree: str
    first_parent_commit: str
    protection_evidence_digest: str
    provider_identity: str
    provider_api_version: str
    parent_commits: tuple[str, ...] = ()


@dataclass(frozen=True)
class GitHubPullRequestBinding:
    """Sanitized identity returned by the controller-owned PR lifecycle."""

    number: int
    url: str
    base_ref: str
    base_commit: str
    head_ref: str
    head_commit: str
    body: str
    state: Literal["open", "closed"]
    draft: bool


@dataclass(frozen=True)
class GitHubEvidenceSnapshot:
    """Allowlisted, content-addressable evidence for one synthetic merge.

    The two evidence objects intentionally contain only fields that AVO validates;
    arbitrary GitHub response fields (including user-controlled text) are dropped.
    This makes the snapshot safe to persist as an evidence artifact without turning
    the provider response into an authority boundary.
    """

    synthetic_merge_commit: str
    synthetic_merge_tree: str
    protection_evidence_digest: str
    check_evidence_manifest_digest: str
    protection_evidence: JsonObject
    check_evidence_manifest: JsonObject

    @property
    def raw_evidence(self) -> JsonObject:
        return cast(
            JsonObject,
            _json_value(
                {
                    "synthetic_merge_commit": self.synthetic_merge_commit,
                    "synthetic_merge_tree": self.synthetic_merge_tree,
                    "protection": self.protection_evidence,
                    "check_manifest": self.check_evidence_manifest,
                }
            ),
        )


@dataclass(frozen=True)
class GitHubPullRequestDiscovery:
    """Exact PR identity plus its synthetic merge and sanitized evidence."""

    pull_request: GitHubPullRequestBinding
    synthetic_merge_commit: str
    synthetic_merge_tree: str
    evidence: GitHubEvidenceSnapshot


@dataclass(frozen=True)
class GitHubRefObservation:
    """Authenticated, exact ref and complete commit topology."""

    repository_digest: str
    ref: str
    commit: str
    tree: str
    parents: tuple[str, ...]


@dataclass(frozen=True)
class GitHubRollbackTopology:
    """All immutable Git identities required to attest a live rollback."""

    repository_digest: str
    target_ref: str
    main: GitHubRefObservation
    target: GitHubRefObservation
    failed_head: GitHubRefObservation
    restore: GitHubRefObservation
    rollback_candidate: GitHubRefObservation


class JsonTransport(Protocol):
    def __call__(
        self, method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]: ...


@dataclass(frozen=True)
class GitHubProtectionPolicy:
    """The exact branch-protection semantics trusted by the promotion controller."""

    required_approving_review_count: int = 0
    required_status_checks_strict: bool = True
    dismiss_stale_reviews: bool = True
    require_last_push_approval: bool = False
    enforce_admins: bool = True
    required_linear_history: bool = True
    required_conversation_resolution: bool = True
    allow_force_pushes: bool = False
    allow_deletions: bool = False
    lock_branch: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.required_approving_review_count, bool) or (
            self.required_approving_review_count < 0
        ):
            raise ValueError("required approving review count must be a non-negative integer")


def github_repository_digest(owner: str, repo: str) -> str:
    """Match the trusted Git reader's sanitized HTTPS remote identity."""

    remote = f"https://github.com/{owner}/{repo}.git"
    return "sha256:" + hashlib.sha256(remote.encode("utf-8")).hexdigest()


def _json_value(value: object) -> JsonValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        raw_list = cast(list[object], value)
        return [_json_value(item) for item in raw_list]
    if isinstance(value, dict):
        result: JsonObject = {}
        raw_dict = cast(dict[object, object], value)
        for raw_key, raw_item in raw_dict.items():
            key = raw_key
            if not isinstance(key, str):
                raise ValueError("malformed JSON response")
            result[key] = _json_value(raw_item)
        return result
    raise ValueError("malformed JSON response")


def _default_transport(
    method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
) -> tuple[int, JsonValue]:
    data = json.dumps(body).encode() if body is not None else None
    req = Request(
        url, data=data, method=method, headers=dict(headers) | {"Content-Type": "application/json"}
    )
    try:
        with urlopen(req, timeout=30) as response:
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(raw) > _MAX_RESPONSE_BYTES:
                raise GitHubTransportError("GitHub response exceeded configured bound")
            parsed: object = json.loads(raw) if raw else {}
            return int(response.status), _json_value(parsed)
    except Exception as exc:  # urllib's HTTPError may carry an authoritative status
        status = getattr(exc, "code", None)
        if isinstance(status, int) and 400 <= status < 500:
            raise GitHubRejected(f"GitHub request rejected ({status})", status=status) from exc
        raise GitHubTransportError("GitHub transport failure") from exc


def _object(value: JsonValue, context: str) -> JsonObject:
    if not isinstance(value, dict):
        raise ValueError(f"malformed {context} response")
    return value


def _required_string(value: JsonObject, key: str, context: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise ValueError(f"malformed {context}: missing {key}")
    return item


def _required_int(value: JsonObject, key: str, context: str) -> int:
    item = value.get(key)
    if isinstance(item, bool) or not isinstance(item, int):
        raise ValueError(f"malformed {context}: missing {key}")
    return item


def _required_bool(value: JsonObject, key: str, context: str) -> bool:
    item = value.get(key)
    if not isinstance(item, bool):
        raise ValueError(f"malformed {context}: missing {key}")
    return item


def _nested_object(value: JsonObject, key: str, context: str) -> JsonObject:
    return _object(value.get(key), f"{context}.{key}")


_GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_VALIDATION_REF = re.compile(r"^refs/heads/avo/validation/[0-9a-f]{64}$")
_WORKFLOW_PATH = ".github/workflows/synthetic-validation.yml"
_WORKFLOW_VARIABLE = "AVO_TRUSTED_WORKFLOW_SHA256"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOAK_WORKFLOW_FILENAME = "integration-soak.yml"
_SOAK_WORKFLOW_RUN_PATH = re.compile(
    r"^\.github/workflows/integration-soak\.yml(?:@[^@%\x00-\x20~^:?*\\\[\]]+)?$"
)


def _is_soak_workflow_run_path(value: str) -> bool:
    """Accept GitHub's exact workflow path, optionally annotated with a ref."""
    if _SOAK_WORKFLOW_RUN_PATH.fullmatch(value) is None:
        return False
    if "@" not in value:
        return True
    ref = value.rsplit("@", 1)[1]
    return (
        bool(ref)
        and ".." not in ref
        and not ref.startswith(("/", "."))
        and not ref.endswith(("/", "."))
    )


def _git_object(value: str, context: str) -> str:
    if not _GIT_OBJECT.fullmatch(value):
        raise ValueError(f"malformed {context}")
    return value


@dataclass(frozen=True)
class GitHubIntegrationProvider:
    owner: str
    repo: str
    repository_digest: str
    target_ref: str
    trusted_checks: tuple[tuple[str, int], ...]
    freshness_cutoff: datetime
    # ``trusted_checks`` are the controller-enforced exact synthetic-SHA
    # checks.  ``protection_checks`` are the provider-enforced required checks
    # on the protected branch head.  They must be supplied independently.
    protection_checks: tuple[tuple[str, int], ...]
    protection_policy: GitHubProtectionPolicy = field(default_factory=GitHubProtectionPolicy)
    token: str | None = field(default=None, repr=False, compare=False)
    api_base: str = "https://api.github.com"
    provider_identity: str = "github"
    provider_api_version: str = "2022-11-28"
    transport: JsonTransport = _default_transport

    def __post_init__(self) -> None:
        if not self.owner or not self.repo or any(c in self.owner + self.repo for c in "/\\"):
            raise ValueError("invalid GitHub repository binding")
        if self.repository_digest != github_repository_digest(self.owner, self.repo):
            raise ValueError("repository digest does not match configured GitHub repository")
        self._authority_ref(self.target_ref, "target ref")
        parsed = urlparse(self.api_base)
        if parsed.scheme != "https" or parsed.netloc != "api.github.com":
            raise ValueError("GitHub API base must be https://api.github.com")
        self._validate_checks(self.trusted_checks, "trusted")
        self._validate_checks(self.protection_checks, "protection")
        if self.freshness_cutoff.tzinfo is None:
            raise ValueError("freshness cutoff must be timezone-aware")

    @staticmethod
    def _validate_checks(checks: tuple[tuple[str, int], ...], label: str) -> None:
        candidate: object = checks
        if not isinstance(candidate, tuple) or not candidate:  # pyright: ignore[reportUnnecessaryIsInstance]
            raise ValueError(f"{label} checks must be non-empty")
        seen: set[tuple[str, int]] = set()
        for raw_check in candidate:
            check: object = raw_check
            if not isinstance(check, tuple) or len(check) != 2:  # pyright: ignore[reportUnnecessaryIsInstance]
                raise ValueError(f"{label} checks must contain name/app ID pairs")
            name, app_id = check
            if not isinstance(name, str) or not name:  # pyright: ignore[reportUnnecessaryIsInstance]
                raise ValueError(f"{label} check contexts must be non-empty strings")
            if not isinstance(app_id, int) or isinstance(app_id, bool) or app_id < 0:  # pyright: ignore[reportUnnecessaryIsInstance]
                raise ValueError(f"{label} check app IDs must be non-negative integers")
            if check in seen:
                raise ValueError(f"{label} checks must be unique")
            seen.add(check)

    def _call(self, method: str, path: str, body: JsonBody | None = None) -> JsonValue:
        url = self.api_base.rstrip("/") + "/" + path.lstrip("/")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.provider_api_version,
        }
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        try:
            status, payload = self.transport(method, url, body, headers)
        except (GitHubRejected, GitHubTransportError):
            raise
        except Exception as exc:
            raise GitHubTransportError("GitHub transport failure") from exc
        if status >= 500:
            raise GitHubTransportError(f"GitHub server failure ({status})")
        if status >= 400:
            raise GitHubRejected(f"GitHub rejected request ({status})", status=status)
        if status < 200 or status >= 300:
            raise GitHubTransportError(f"GitHub returned unexpected status ({status})")
        return payload

    def _require_authenticated(self) -> None:
        """Live authority reads must never silently use anonymous GitHub API."""
        if not self.token:
            raise GitHubRejected("authenticated GitHub token is required")

    def _paged_items(
        self, path: str, key: str, label: str, *, max_items: int = 10_000
    ) -> list[JsonObject]:
        """Read a bounded REST collection, rejecting pagination drift/replays."""

        page = 1
        total: int | None = None
        seen_ids: set[int] = set()
        result: list[JsonObject] = []
        while True:
            suffix = "&" if "?" in path else "?"
            payload = _object(
                self._call("GET", f"{path}{suffix}per_page=100&page={page}"), label
            )
            declared = _required_int(payload, "total_count", label)
            if declared < 0 or declared > max_items:
                raise ValueError(f"{label} total count exceeds bounded pagination")
            if total is None:
                total = declared
            elif total != declared:
                raise ValueError(f"{label} total count changed during pagination")
            items = payload.get(key)
            if not isinstance(items, list) or len(items) > 100:
                raise ValueError(f"{label} page is malformed or oversized")
            for item in items:
                parsed = _object(item, label[:-1] if label.endswith("s") else label)
                raw_id = parsed.get("id")
                if isinstance(raw_id, int) and not isinstance(raw_id, bool):
                    if raw_id in seen_ids:
                        raise ValueError(f"duplicate {label} ID across pages")
                    seen_ids.add(raw_id)
                result.append(parsed)
            expected_pages = max(1, ceil(declared / 100))
            if page > expected_pages or page > 100:
                raise ValueError(f"{label} pagination exceeded declared bounds")
            expected_items = declared - ((page - 1) * 100) if page == expected_pages else 100
            if len(items) != expected_items:
                raise ValueError(f"{label} page is inconsistent with total_count")
            if page == expected_pages:
                break
            page += 1
        assert total is not None
        if len(result) != total:
            raise ValueError(f"{label} pagination did not collect total_count items")
        return result

    @staticmethod
    def _authority_ref(value: str, context: str, *, allow_protected: bool = False) -> str:
        if (
            not value.startswith("refs/heads/")
            or value == "refs/heads/"
            or value.endswith(("/", "."))
        ):
            raise ValueError(f"{context} must be a full heads ref")
        branch = value.removeprefix("refs/heads/")
        lowered = branch.casefold()
        if (
            any(char in branch for char in "\x00\r\n ~^:?*[\\")
            or ".." in branch
            or (
                not allow_protected
                and (
                    lowered in {"main", "master"}
                    or any(term in lowered for term in ("production", "deploy"))
                )
            )
        ):
            raise ValueError(f"malformed {context}")
        return value

    def verify_repository_binding(self) -> str:
        """Authenticate and verify the exact configured GitHub repository."""
        self._require_authenticated()
        raw = _object(self._call("GET", self._path("").rstrip("/")), "repository")
        full_name = _required_string(raw, "full_name", "repository")
        name = _required_string(raw, "name", "repository")
        owner = _nested_object(raw, "owner", "repository")
        login = _required_string(owner, "login", "repository owner")
        if full_name != f"{self.owner}/{self.repo}" or name != self.repo or login != self.owner:
            raise ValueError("GitHub repository identity mismatch")
        return self.repository_digest

    def _read_authority_commit(self, sha: str, context: str) -> tuple[str, str, tuple[str, ...]]:
        expected = _git_object(sha, context)
        actual, tree, parents = self._commit_topology(self._commit(expected))
        if actual != expected:
            raise ValueError(f"{context} response mismatch")
        _git_object(tree, f"{context} tree")
        for parent in parents:
            _git_object(parent, f"{context} parent")
        return actual, tree, parents

    def read_authority_ref(
        self, ref: str, *, allow_protected: bool = False
    ) -> GitHubRefObservation:
        """Read one authenticated heads ref and its complete commit topology."""
        self._require_authenticated()
        exact_ref = self._authority_ref(ref, "authority ref", allow_protected=allow_protected)
        branch = exact_ref.removeprefix("refs/heads/")
        raw = _object(
            self._call("GET", self._path(f"git/ref/heads/{quote(branch, safe='')}")),
            "Git ref",
        )
        if _required_string(raw, "ref", "Git ref") != exact_ref:
            raise ValueError("Git ref identity mismatch")
        obj = _nested_object(raw, "object", "Git ref")
        if _required_string(obj, "type", "Git ref object") != "commit":
            raise ValueError("Git ref does not point to a commit")
        commit = _git_object(_required_string(obj, "sha", "Git ref object"), "Git ref commit")
        actual, tree, parents = self._read_authority_commit(commit, "Git ref commit")
        return GitHubRefObservation(self.repository_digest, exact_ref, actual, tree, parents)

    # Short aliases keep application wiring readable while the explicit name
    # documents that this read is an authority boundary.
    observe_authority_ref = read_authority_ref

    def verify_current_target(
        self,
        *,
        expected_commit: str,
        expected_tree: str,
        expected_parents: tuple[str, ...] | list[str],
    ) -> GitHubRefObservation:
        """Verify current target ref against an exact commit/tree/parent tuple."""
        self._require_authenticated()
        self.verify_repository_binding()
        observation = self.read_authority_ref(self.target_ref)
        expected = (
            _git_object(expected_commit, "expected target commit"),
            _git_object(expected_tree, "expected target tree"),
            tuple(_git_object(item, "expected target parent") for item in expected_parents),
        )
        if (observation.commit, observation.tree, observation.parents) != expected:
            raise ValueError("current target topology mismatch")
        return observation

    def verify_live_rollback_topology(
        self,
        *,
        failed_integration_head_commit: str,
        failed_integration_head_tree: str,
        restore_to_commit: str,
        restore_to_tree: str,
        rollback_candidate_commit: str,
        rollback_candidate_tree: str,
        rollback_candidate_parent_commit: str,
        current_target_commit: str,
        current_target_tree: str,
        current_target_parents: tuple[str, ...] | list[str],
        main_commit: str,
    ) -> GitHubRollbackTopology:
        """Verify all rollback identities plus current target and main heads.

        This performs only authenticated GETs. Every supplied identity is checked
        against GitHub's commit and tree response, including the candidate's
        single-parent topology and the exact post-merge target topology.
        """
        self._require_authenticated()
        self.verify_repository_binding()
        target = self.read_authority_ref(self.target_ref)
        main = self.read_authority_ref("refs/heads/main", allow_protected=True)
        if main.commit != _git_object(main_commit, "expected main commit"):
            raise ValueError("current main topology mismatch")
        expected_target = (
            _git_object(current_target_commit, "expected target commit"),
            _git_object(current_target_tree, "expected target tree"),
            tuple(_git_object(item, "expected target parent") for item in current_target_parents),
        )
        if (target.commit, target.tree, target.parents) != expected_target:
            raise ValueError("current target topology mismatch")

        def historical(sha: str, tree: str, label: str) -> GitHubRefObservation:
            actual, actual_tree, parents = self._read_authority_commit(sha, label)
            if actual_tree != _git_object(tree, f"expected {label} tree"):
                raise ValueError(f"{label} tree mismatch")
            return GitHubRefObservation(
                self.repository_digest, self.target_ref, actual, actual_tree, parents
            )

        failed = historical(
            failed_integration_head_commit, failed_integration_head_tree, "failed integration head"
        )
        restore = historical(restore_to_commit, restore_to_tree, "restore commit")
        candidate = historical(
            rollback_candidate_commit, rollback_candidate_tree, "rollback candidate"
        )
        if candidate.parents != (
            _git_object(rollback_candidate_parent_commit, "rollback candidate parent"),
        ):
            raise ValueError("rollback candidate parent topology mismatch")
        return GitHubRollbackTopology(
            self.repository_digest, self.target_ref, main, target, failed, restore, candidate
        )

    def observe_workflow_authority(
        self, source_commit: str, *, workflow_path: str = _WORKFLOW_PATH
    ) -> LiveRollbackWorkflowEvidence:
        """Read and verify the base-pinned validation workflow and repository pin.

        GitHub's contents endpoint is queried with the full source commit, so a
        branch or moving tag cannot silently select the workflow. The response's
        base64 bytes are hashed exactly as returned by GitHub; no text decoding or
        newline normalization occurs before hashing.
        """
        self._require_authenticated()
        self.verify_repository_binding()
        source = _git_object(source_commit, "workflow source commit")
        if workflow_path != _WORKFLOW_PATH:
            raise ValueError("workflow path is outside the trusted validation scope")
        content_path = quote(workflow_path, safe="/")
        raw = _object(
            self._call(
                "GET",
                self._path(f"contents/{content_path}?ref={quote(source, safe='')}"),
            ),
            "workflow content",
        )
        if (
            _required_string(raw, "type", "workflow content") != "file"
            or _required_string(raw, "path", "workflow content") != workflow_path
            or _required_string(raw, "encoding", "workflow content") != "base64"
        ):
            raise ValueError("workflow content identity or encoding mismatch")
        encoded = _required_string(raw, "content", "workflow content")
        try:
            # GitHub wraps base64 content in newlines. Whitespace is transport
            # formatting, while every non-whitespace byte remains significant.
            compact = "".join(encoded.split())
            blob = base64.b64decode(compact.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError) as exc:
            raise ValueError("workflow content is not valid base64") from exc
        workflow_hash = "sha256:" + hashlib.sha256(blob).hexdigest()

        variable = _object(
            self._call("GET", self._path(f"actions/variables/{_WORKFLOW_VARIABLE}")),
            "repository variable",
        )
        if _required_string(variable, "name", "repository variable") != _WORKFLOW_VARIABLE:
            raise ValueError("trusted workflow variable identity mismatch")
        expected = _required_string(variable, "value", "repository variable")
        if _SHA256.fullmatch(expected) is None:
            raise ValueError("trusted workflow variable is not lowercase SHA-256")
        variable_digest = "sha256:" + expected
        if workflow_hash != variable_digest:
            raise ValueError("workflow blob does not match trusted repository variable")
        return LiveRollbackWorkflowEvidence.model_validate(
            {
                "repository_digest": self.repository_digest,
                "target_ref": self.target_ref,
                "source_commit": source,
                "workflow_path": workflow_path,
                "workflow_blob_digest": workflow_hash,
                "repository_variables_digest": variable_digest,
                "repository_variables_match": True,
                "provider_identity": self.provider_identity,
                "provider_api_version": self.provider_api_version,
            }
        )

    observe_workflow_evidence = observe_workflow_authority

    def observe_failed_soak(
        self,
        integration_ref: str = "refs/heads/integration",
        *,
        now: datetime | None = None,
    ) -> FailedSoakAttestation:
        """Observe the one deterministic failed soak from GitHub authority.

        The integration ref, its exact parent/tree, main ref, check run, workflow
        run, and workflow blob are all read here.  Restore identity is deliberately
        derived from the integration commit's sole parent and is never accepted
        from a caller.
        """
        self._require_authenticated()
        if integration_ref != "refs/heads/integration" or integration_ref != self.target_ref:
            raise ValueError("failed soak must target refs/heads/integration")
        integration = self.read_authority_ref(integration_ref)
        if len(integration.parents) != 1:
            raise ValueError("failed soak integration commit must have exactly one parent")
        restore_commit = integration.parents[0]
        restore_actual, restore_tree, _restore_parents = self._read_authority_commit(
            restore_commit, "failed soak restore commit"
        )
        if restore_actual != restore_commit:
            raise ValueError("failed soak restore commit identity mismatch")
        main = self.read_authority_ref("refs/heads/main", allow_protected=True)

        # The trigger is a content-addressed candidate-tree fact.  Commit
        # messages are not stable through GitHub squash merges and therefore
        # must not be used as the authority for a failed soak.
        marker_raw = _object(
            self._call(
                "GET",
                self._path(
                    "contents/"
                    f"{quote(SOAK_MARKER_PATH, safe='/')}?ref="
                    f"{quote(integration.commit, safe='')}"
                ),
            ),
            "integration soak marker content",
        )
        if (
            _required_string(marker_raw, "type", "integration soak marker content") != "file"
            or _required_string(marker_raw, "path", "integration soak marker content")
            != SOAK_MARKER_PATH
            or _required_string(marker_raw, "encoding", "integration soak marker content")
            != "base64"
        ):
            raise ValueError("integration soak marker identity or encoding mismatch")
        try:
            marker_encoded = "".join(
                _required_string(marker_raw, "content", "integration soak marker content").split()
            )
            marker_blob = base64.b64decode(marker_encoded.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError) as exc:
            raise ValueError("integration soak marker content is not valid base64") from exc
        marker_digest = "sha256:" + hashlib.sha256(marker_blob).hexdigest()
        if marker_digest != SOAK_MARKER_BLOB_DIGEST:
            raise ValueError("integration soak marker content does not match trusted bytes")

        # The workflow and repository variable are pinned independently from the
        # candidate. Hash the exact bytes returned by GitHub without normalization.
        workflow_raw = _object(
            self._call(
                "GET",
                self._path(
                    "contents/"
                    f"{quote(SOAK_WORKFLOW_PATH, safe='/')}?ref="
                    f"{quote(integration.commit, safe='')}"
                ),
            ),
            "integration soak workflow content",
        )
        if (
            _required_string(workflow_raw, "type", "integration soak workflow content") != "file"
            or _required_string(workflow_raw, "path", "integration soak workflow content")
            != SOAK_WORKFLOW_PATH
            or _required_string(workflow_raw, "encoding", "integration soak workflow content")
            != "base64"
        ):
            raise ValueError("integration soak workflow identity or encoding mismatch")
        try:
            encoded = "".join(
                _required_string(
                    workflow_raw, "content", "integration soak workflow content"
                ).split()
            )
            blob = base64.b64decode(encoded.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError) as exc:
            raise ValueError("integration soak workflow content is not valid base64") from exc
        workflow_digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        variable = _object(
            self._call("GET", self._path(f"actions/variables/{SOAK_WORKFLOW_VARIABLE}")),
            "integration soak repository variable",
        )
        if (
            _required_string(variable, "name", "integration soak repository variable")
            != SOAK_WORKFLOW_VARIABLE
        ):
            raise ValueError("integration soak trusted variable identity mismatch")
        variable_value = _required_string(variable, "value", "integration soak repository variable")
        if _SHA256.fullmatch(variable_value) is None:
            raise ValueError("integration soak trusted variable is not lowercase SHA-256")
        variable_digest = "sha256:" + variable_value
        if workflow_digest != variable_digest:
            raise ValueError("integration soak workflow blob does not match trusted variable")

        runs = self._paged_items(
            self._path(
                "actions/workflows/"
                f"{quote(_SOAK_WORKFLOW_FILENAME, safe='')}/runs?head_sha="
                f"{quote(integration.commit, safe='')}&event=push"
            ),
            "workflow_runs",
            "integration soak workflow runs",
        )
        candidates: list[JsonObject] = []
        for run in runs:
            if (
                _is_soak_workflow_run_path(
                    _required_string(run, "path", "integration soak workflow run")
                )
                and _required_string(run, "head_sha", "integration soak workflow run")
                == integration.commit
            ):
                candidates.append(run)
        if len(candidates) != 1:
            raise ValueError("integration soak must have exactly one matching workflow run")
        workflow_run = candidates[0]
        workflow_run_id = _required_int(workflow_run, "id", "integration soak workflow run")
        workflow_id = _required_int(workflow_run, "workflow_id", "integration soak workflow run")
        if workflow_run_id <= 0 or workflow_id <= 0:
            raise ValueError("integration soak workflow IDs must be positive")
        if (
            _required_string(workflow_run, "status", "integration soak workflow run") != "completed"
            or _required_string(workflow_run, "conclusion", "integration soak workflow run")
            != "failure"
            or _required_string(workflow_run, "event", "integration soak workflow run") != "push"
        ):
            raise ValueError("integration soak workflow did not deterministically fail")
        completed_value = workflow_run.get("completed_at") or workflow_run.get("updated_at")
        if not isinstance(completed_value, str):
            raise ValueError("integration soak workflow run completed_at is required")
        try:
            completed_at = datetime.fromisoformat(completed_value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("integration soak completed_at is malformed") from exc
        if completed_at.tzinfo is None:
            raise ValueError("integration soak completed_at must be timezone-aware")
        current = (now or datetime.now(UTC)).astimezone(UTC)
        if completed_at > current or completed_at < self.freshness_cutoff:
            raise ValueError("integration soak workflow run is stale or future-dated")

        check_runs = self._paged_items(
            self._path(f"commits/{integration.commit}/check-runs"),
            "check_runs",
            "integration soak check runs",
        )
        matches: list[JsonObject] = []
        for check in check_runs:
            app = _nested_object(check, "app", "integration soak check run")
            if (
                _required_string(check, "name", "integration soak check run") == SOAK_CONTEXT
                and _required_int(app, "id", "integration soak check app") == SOAK_APP_ID
                and _required_string(check, "head_sha", "integration soak check run")
                == integration.commit
            ):
                matches.append(check)
        if len(matches) != 1:
            raise ValueError("integration soak must have exactly one matching check run")
        check = matches[0]
        if (
            _required_string(check, "status", "integration soak check run") != "completed"
            or _required_string(check, "conclusion", "integration soak check run") != "failure"
        ):
            raise ValueError("integration soak check is not a completed failure")
        check_id = _required_int(check, "id", "integration soak check run")
        if check_id <= 0:
            raise ValueError("integration soak check run ID must be positive")
        check_completed_value = _required_string(
            check, "completed_at", "integration soak check run"
        )
        try:
            check_completed_at = datetime.fromisoformat(
                check_completed_value.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError("integration soak check completed_at is malformed") from exc
        if check_completed_at.tzinfo is None:
            raise ValueError("integration soak check completed_at must be timezone-aware")
        if check_completed_at > current or check_completed_at < self.freshness_cutoff:
            raise ValueError("integration soak check is stale or future-dated")

        completed_stamp = check_completed_at.astimezone(UTC).isoformat()
        completed_stamp = completed_stamp.replace("+00:00", "Z")
        values = {
            "schema_version": 1,
            "repository_digest": self.repository_digest,
            "integration_ref": "refs/heads/integration",
            "integration_commit": integration.commit,
            "integration_tree": integration.tree,
            "integration_parent_commit": restore_commit,
            "restore_commit": restore_commit,
            "restore_tree": restore_tree,
            "main_commit": main.commit,
            "main_ref": "refs/heads/main",
            "check_run_id": check_id,
            "workflow_id": workflow_id,
            "workflow_run_id": workflow_run_id,
            "completed_at": completed_stamp,
            "freshness_cutoff": self.freshness_cutoff.astimezone(UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            "workflow_blob_digest": workflow_digest,
            "repository_variables_digest": variable_digest,
            "marker_path": SOAK_MARKER_PATH,
            "marker_blob_digest": marker_digest,
            "context": SOAK_CONTEXT,
            "app_id": SOAK_APP_ID,
            "status": "completed",
            "conclusion": "failure",
            "workflow_path": SOAK_WORKFLOW_PATH,
        }
        values["attestation_id"] = canonical_digest(values)
        return FailedSoakAttestation.model_validate(values)

    observe_failed_integration_soak = observe_failed_soak
    observe_failed_soak_attestation = observe_failed_soak

    def live_rollback_manifests(
        self,
        snapshot: GitHubEvidenceSnapshot,
        *,
        protection_source_commit: str,
        target_ref: str | None = None,
    ) -> tuple[LiveRollbackManifestEvidence, LiveRollbackManifestEvidence]:
        """Convert sanitized provider evidence into canonical Phase B records."""
        self._require_authenticated()
        target = self.target_ref if target_ref is None else target_ref
        if target != self.target_ref:
            raise ValueError("manifest target ref is not configured integration ref")
        synthetic = _git_object(snapshot.synthetic_merge_commit, "synthetic merge commit")
        _git_object(snapshot.synthetic_merge_tree, "synthetic merge tree")
        protection_source = _git_object(protection_source_commit, "protection source commit")

        manifest = snapshot.check_evidence_manifest
        if canonical_digest(manifest) != snapshot.check_evidence_manifest_digest:
            raise ValueError("trusted check manifest digest is not canonical")
        expected_protection_payload: JsonObject = {
            "required_status_checks": {
                "strict": self.protection_policy.required_status_checks_strict,
                "checks": [
                    {"context": context, "app_id": app_id}
                    for context, app_id in sorted(self.protection_checks)
                ],
            },
            "required_pull_request_reviews": {
                "required_approving_review_count": (
                    self.protection_policy.required_approving_review_count
                ),
                "dismiss_stale_reviews": self.protection_policy.dismiss_stale_reviews,
                "require_last_push_approval": self.protection_policy.require_last_push_approval,
            },
            "enforce_admins": self.protection_policy.enforce_admins,
            "required_linear_history": self.protection_policy.required_linear_history,
            "required_conversation_resolution": (
                self.protection_policy.required_conversation_resolution
            ),
            "allow_force_pushes": self.protection_policy.allow_force_pushes,
            "allow_deletions": self.protection_policy.allow_deletions,
            "lock_branch": self.protection_policy.lock_branch,
        }
        if (
            snapshot.protection_evidence != expected_protection_payload
            or canonical_digest(snapshot.protection_evidence) != snapshot.protection_evidence_digest
        ):
            raise ValueError("branch protection evidence is not canonical or semantic")
        trusted = manifest.get("trusted_checks")
        runs = manifest.get("runs")
        if not isinstance(trusted, list) or not isinstance(runs, list):
            raise ValueError("malformed trusted check manifest")
        expected_checks: set[tuple[str, int]] = set()
        for item in trusted:
            check = _object(item, "trusted check declaration")
            context = _required_string(check, "context", "trusted check declaration")
            app_id = _required_int(check, "app_id", "trusted check declaration")
            expected_checks.add((context, app_id))
        if len(expected_checks) != len(trusted):
            raise ValueError("duplicate trusted check declaration")
        if expected_checks != set(self.trusted_checks):
            raise ValueError("trusted check declarations differ from configured checks")

        check_entries: list[LiveRollbackCheckEntry] = []
        seen: set[tuple[str, int]] = set()
        for item in runs:
            run = _object(item, "trusted check run")
            name = _required_string(run, "name", "trusted check run")
            app_id = _required_int(run, "app_id", "trusted check run")
            key = (name, app_id)
            if key not in expected_checks:
                raise ValueError("unexpected trusted check entry")
            if key in seen:
                raise ValueError("duplicate trusted check entry")
            if (
                _required_string(run, "head_sha", "trusted check run") != synthetic
                or _required_string(run, "status", "trusted check run") != "completed"
                or _required_string(run, "conclusion", "trusted check run") != "success"
            ):
                raise ValueError("trusted check entry is not completed successfully")
            completed_at = _required_string(run, "completed_at", "trusted check run")
            try:
                completed = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("trusted check timestamp is malformed") from exc
            if completed.tzinfo is None:
                raise ValueError("trusted check timestamp must be timezone-aware")
            if completed > datetime.now(UTC):
                raise ValueError("trusted check entry is future-dated")
            if completed < self.freshness_cutoff:
                raise ValueError("trusted check entry is stale")
            seen.add(key)
            check_entries.append(
                LiveRollbackCheckEntry.model_validate(
                    {
                        "name": name,
                        "app_id": app_id,
                        "context": name,
                        "sha": synthetic,
                        "status": "completed",
                        "conclusion": "success",
                        "completed_at": completed,
                    }
                )
            )
        if seen != expected_checks:
            raise ValueError("trusted check entries are missing or substituted")
        check_entries.sort(key=lambda item: (item.context, item.app_id))
        check_manifest = LiveRollbackManifestEvidence.model_validate(
            {
                "kind": "trusted-check-manifest",
                "repository_digest": self.repository_digest,
                "target_ref": target,
                "source_commit": synthetic,
                "manifest_digest": snapshot.check_evidence_manifest_digest,
                "provider_identity": self.provider_identity,
                "provider_api_version": self.provider_api_version,
                "entries": [item.context for item in check_entries],
                "check_entries": [item.model_dump(mode="json") for item in check_entries],
                "freshness_cutoff": self.freshness_cutoff,
                "observed_at": datetime.now(UTC),
                "source_pinned": True,
            }
        )

        protection = snapshot.protection_evidence
        status = _nested_object(protection, "required_status_checks", "branch protection")
        raw_checks = status.get("checks")
        if not isinstance(raw_checks, list):
            raise ValueError("branch protection checks are malformed")
        protection_entries: list[LiveRollbackProtectionEntry] = []
        protection_set: set[tuple[str, int]] = set()
        for item in raw_checks:
            check = _object(item, "required status check")
            context = _required_string(check, "context", "required status check")
            app_id = _required_int(check, "app_id", "required status check")
            protection_set.add((context, app_id))
            protection_entries.append(
                LiveRollbackProtectionEntry.model_validate(
                    {
                        "app_id": app_id,
                        "context": context,
                        "required": True,
                        "enforced": True,
                    }
                )
            )
        if protection_set != set(self.protection_checks) or len(protection_entries) != len(
            protection_set
        ):
            raise ValueError("branch protection checks are not exact")
        protection_entries.sort(key=lambda item: item.context)
        protection_manifest = LiveRollbackManifestEvidence.model_validate(
            {
                "kind": "protection-manifest",
                "repository_digest": self.repository_digest,
                "target_ref": target,
                "source_commit": protection_source,
                "manifest_digest": snapshot.protection_evidence_digest,
                "provider_identity": self.provider_identity,
                "provider_api_version": self.provider_api_version,
                "entries": [item.context for item in protection_entries],
                "protection_entries": [item.model_dump(mode="json") for item in protection_entries],
                "freshness_cutoff": self.freshness_cutoff,
                "observed_at": datetime.now(UTC),
                "source_pinned": True,
            }
        )
        return check_manifest, protection_manifest

    build_live_rollback_manifests = live_rollback_manifests

    def _path(self, suffix: str) -> str:
        return f"repos/{quote(self.owner, safe='')}/{quote(self.repo, safe='')}/{suffix}"

    def _assert_intent(self, intent: IntegrationPromotionIntent) -> None:
        if (
            intent.repository_digest != self.repository_digest
            or intent.target_ref != self.target_ref
            or intent.provider_identity != self.provider_identity
            or intent.provider_api_version != self.provider_api_version
        ):
            raise ValueError("intent/provider binding mismatch")

    def _pr(self, number: int) -> JsonObject:
        return _object(self._call("GET", self._path(f"pulls/{number}")), "pull request")

    def _commit(self, sha: str) -> JsonObject:
        return _object(self._call("GET", self._path(f"git/commits/{sha}")), "commit")

    def _branch(self, value: str, context: str) -> str:
        """Return a GitHub API branch name only for an exact heads ref."""
        if not value.startswith("refs/heads/") or value == "refs/heads/":
            raise ValueError(f"{context} must be a full refs/heads ref")
        branch = value.removeprefix("refs/heads/")
        if branch.casefold() in {"main", "master"} or any(
            term in branch.casefold() for term in ("production", "deploy")
        ):
            raise ValueError(f"{context} is outside the integration scope")
        if any(char in branch for char in "\x00\r\n~^:?*[\\") or ".." in branch:
            raise ValueError(f"malformed {context}")
        return branch

    def _pull_binding(
        self,
        raw: JsonObject,
        *,
        number: int,
        candidate_ref: str,
        candidate_commit: str,
        base_commit: str | None = None,
        require_open: bool = True,
    ) -> GitHubPullRequestBinding:
        """Validate the complete same-repository PR identity and return safe fields."""
        candidate_branch = self._branch(candidate_ref, "candidate ref")
        target_branch = self._branch(self.target_ref, "target ref")
        actual_number = _required_int(raw, "number", "pull request")
        url = _required_string(raw, "html_url", "pull request")
        expected_url = f"https://github.com/{self.owner}/{self.repo}/pull/{number}"
        body = _required_string(raw, "body", "pull request")
        state = _required_string(raw, "state", "pull request")
        draft = _required_bool(raw, "draft", "pull request")
        if actual_number != number or url != expected_url:
            raise ValueError("pull request identity mismatch")
        if require_open and (state != "open" or draft):
            raise ValueError("pull request must be open and non-draft")
        if state not in {"open", "closed"}:
            raise ValueError("malformed pull request state")
        base = _nested_object(raw, "base", "pull request")
        head = _nested_object(raw, "head", "pull request")
        base_repo = _nested_object(base, "repo", "pull request base")
        head_repo = _nested_object(head, "repo", "pull request head")
        actual_base_ref = _required_string(base, "ref", "pull request base")
        actual_head_ref = _required_string(head, "ref", "pull request head")
        actual_base_commit = _git_object(
            _required_string(base, "sha", "pull request base"), "base commit"
        )
        actual_head_commit = _git_object(
            _required_string(head, "sha", "pull request head"), "head commit"
        )
        if (
            actual_base_ref != target_branch
            or actual_head_ref != candidate_branch
            or _required_string(base_repo, "full_name", "base repository")
            != f"{self.owner}/{self.repo}"
            or _required_string(head_repo, "full_name", "head repository")
            != f"{self.owner}/{self.repo}"
            or actual_head_commit != _git_object(candidate_commit, "candidate commit")
            or (
                base_commit is not None
                and actual_base_commit != _git_object(base_commit, "base commit")
            )
        ):
            raise ValueError("pull request repository/ref/commit mismatch")
        return GitHubPullRequestBinding(
            number=actual_number,
            url=url,
            base_ref=self.target_ref,
            base_commit=actual_base_commit,
            head_ref=candidate_ref,
            head_commit=actual_head_commit,
            body=body,
            state=cast(Literal["open", "closed"], state),
            draft=draft,
        )

    def create_pull_request(
        self,
        candidate_ref: str,
        candidate_commit: str,
        *,
        base_commit: str,
        title: str,
        body: str,
    ) -> GitHubPullRequestBinding:
        """Create exactly one controller-owned PR into the configured integration ref.

        GitHub's API accepts short branch names for ``head`` and ``base``.  The
        adapter accepts full refs at its boundary so callers cannot accidentally
        target a tag, fork, main, or deployment ref.  No retry is performed.
        """
        candidate_branch = self._branch(candidate_ref, "candidate ref")
        target_branch = self._branch(self.target_ref, "target ref")
        if candidate_ref == self.target_ref or (
            candidate_ref.casefold() == self.target_ref.casefold()
        ):
            raise ValueError("candidate and target refs must differ")
        _git_object(candidate_commit, "candidate commit")
        _git_object(base_commit, "base commit")
        if not title.strip() or any(char in title for char in "\x00\r\n"):
            raise ValueError("pull request title is malformed")
        if "\x00" in body:
            raise ValueError("pull request body is malformed")
        response = self._call(
            "POST",
            self._path("pulls"),
            {
                "title": title,
                "head": candidate_branch,
                "base": target_branch,
                "body": body,
                "draft": False,
            },
        )
        raw = _object(response, "pull request")
        number = _required_int(raw, "number", "pull request")
        if number <= 0:
            raise ValueError("malformed pull request number")
        return self._pull_binding(
            raw,
            number=number,
            candidate_ref=candidate_ref,
            candidate_commit=candidate_commit,
            base_commit=base_commit,
            require_open=True,
        )

    create_campaign_pull_request = create_pull_request

    def _find_open_pull_request(
        self,
        candidate_ref: str,
        candidate_commit: str,
        base_commit: str,
    ) -> GitHubPullRequestBinding | None:
        """Find the sole exact open PR for a controller-owned high-entropy ref."""
        candidate_branch = self._branch(candidate_ref, "candidate ref")
        target_branch = self._branch(self.target_ref, "target ref")
        _git_object(candidate_commit, "candidate commit")
        _git_object(base_commit, "base commit")
        query = (
            "pulls?state=open&per_page=100"
            f"&head={quote(f'{self.owner}:{candidate_branch}', safe='')}"
            f"&base={quote(target_branch, safe='')}"
        )
        value = self._call("GET", self._path(query))
        if not isinstance(value, list) or len(value) > 100:
            raise ValueError("malformed or oversized pull request discovery")
        if not value:
            return None
        if len(value) != 1:
            raise ValueError("candidate ref has multiple open pull requests")
        raw = _object(value[0], "pull request")
        number = _required_int(raw, "number", "pull request")
        if number <= 0:
            raise ValueError("malformed pull request number")
        return self._pull_binding(
            raw,
            number=number,
            candidate_ref=candidate_ref,
            candidate_commit=candidate_commit,
            base_commit=base_commit,
            require_open=True,
        )

    def open_or_reconcile_pull_request(
        self,
        candidate_ref: str,
        candidate_commit: str,
        *,
        base_commit: str,
        title: str,
        body: str,
    ) -> GitHubPullRequestBinding:
        """Open once or recover the exact PR after a crash/ambiguous POST.

        The high-entropy candidate ref is the durable idempotency key. A restart
        first searches for its sole exact open PR. A transport/rejection response
        after POST is observed once; the POST is never blindly repeated.
        """
        existing = self._find_open_pull_request(candidate_ref, candidate_commit, base_commit)
        if existing is not None:
            return existing
        try:
            return self.create_pull_request(
                candidate_ref,
                candidate_commit,
                base_commit=base_commit,
                title=title,
                body=body,
            )
        except (GitHubTransportError, GitHubRejected):
            recovered = self._find_open_pull_request(candidate_ref, candidate_commit, base_commit)
            if recovered is None:
                raise
            return recovered

    open_or_reconcile_campaign_pull_request = open_or_reconcile_pull_request

    @staticmethod
    def _marker_line(marker: str) -> str:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", marker):
            raise ValueError("campaign marker digest is malformed")
        return f"AVO-Campaign-Marker: {marker}"

    def verify_campaign_marker(
        self, intent: IntegrationPromotionIntent
    ) -> GitHubPullRequestBinding:
        """Read and verify the exact deterministic marker and PR identity."""
        self._assert_intent(intent)
        binding = self._pull_binding(
            self._pr(intent.pull_request_number),
            number=intent.pull_request_number,
            candidate_ref=intent.candidate_ref,
            candidate_commit=intent.candidate_commit,
            base_commit=intent.base_commit,
        )
        marker = self._marker_line(campaign_marker_digest(intent))
        if marker not in {line.strip() for line in binding.body.splitlines()}:
            raise ValueError("campaign marker is missing or does not match intent")
        return binding

    def update_campaign_marker(
        self, intent: IntegrationPromotionIntent, *, body: str | None = None
    ) -> GitHubPullRequestBinding:
        """Set the deterministic marker with one bounded PR-body update.

        The current PR is read first and its identity is checked.  If ``body`` is
        omitted, the existing body is used; callers that need to add a marker to a
        custom body must provide the complete desired body explicitly.  The PATCH
        response is validated again and no retry is attempted.
        """
        self._assert_intent(intent)
        current = self._pull_binding(
            self._pr(intent.pull_request_number),
            number=intent.pull_request_number,
            candidate_ref=intent.candidate_ref,
            candidate_commit=intent.candidate_commit,
            base_commit=intent.base_commit,
        )
        marker = self._marker_line(campaign_marker_digest(intent))
        desired = current.body if body is None else body
        if "\x00" in desired:
            raise ValueError("pull request body is malformed")
        lines = [
            line
            for line in desired.splitlines()
            if not line.strip().startswith("AVO-Campaign-Marker:")
        ]
        lines.append(marker)
        desired = "\n".join(lines)
        response = self._call(
            "PATCH",
            self._path(f"pulls/{intent.pull_request_number}"),
            {"body": desired},
        )
        updated = self._pull_binding(
            _object(response, "pull request"),
            number=intent.pull_request_number,
            candidate_ref=intent.candidate_ref,
            candidate_commit=intent.candidate_commit,
            base_commit=intent.base_commit,
        )
        if marker not in {line.strip() for line in updated.body.splitlines()}:
            raise ValueError("GitHub did not persist the campaign marker")
        return updated

    def discover_pull_request_evidence(
        self,
        pull_request_number: int,
        *,
        candidate_ref: str,
        candidate_commit: str,
        base_commit: str,
        campaign_marker: str | None = None,
    ) -> GitHubPullRequestDiscovery:
        """Discover one exact PR and its bounded synthetic/check/protection evidence.

        This method is intentionally usable before an ``IntegrationPromotionIntent``
        exists.  It binds the controller-owned candidate ref and commit, and can
        additionally require the already-computed campaign marker.  GitHub's
        ``merge_commit_sha`` is preferred; the mergeable SHA is accepted only when
        that is the sole synthetic merge object exposed by the API.  All check-run
        pagination remains bounded by ``_evidence_snapshot``.
        """
        if pull_request_number <= 0:
            raise ValueError("pull request number must be positive")
        raw = self._pr(pull_request_number)
        binding = self._pull_binding(
            raw,
            number=pull_request_number,
            candidate_ref=candidate_ref,
            candidate_commit=candidate_commit,
            base_commit=base_commit,
        )
        if campaign_marker is not None:
            marker = self._marker_line(campaign_marker)
            if marker not in {line.strip() for line in binding.body.splitlines()}:
                raise ValueError("campaign marker is missing or does not match expected digest")
        synthetic_value = raw.get("merge_commit_sha")
        if not isinstance(synthetic_value, str) or not synthetic_value:
            synthetic_value = raw.get("mergeable_commit_sha")
        synthetic = _git_object(
            synthetic_value if isinstance(synthetic_value, str) else "", "synthetic merge commit"
        )
        _, synthetic_tree, _ = self._commit_parts(self._commit(synthetic))
        evidence = self._evidence_snapshot(synthetic, synthetic_tree)
        return GitHubPullRequestDiscovery(
            pull_request=binding,
            synthetic_merge_commit=synthetic,
            synthetic_merge_tree=synthetic_tree,
            evidence=evidence,
        )

    discover_campaign_evidence = discover_pull_request_evidence

    def observe_synthetic_validation(
        self,
        pull_request_number: int,
        *,
        candidate_ref: str,
        candidate_commit: str,
        base_commit: str,
    ) -> SyntheticValidationObservation:
        """Read the exact PR/synthetic merge binding without reading checks.

        This is deliberately separate from ``discover_pull_request_evidence``:
        creating the validation ref is what causes the trusted workflow to run,
        so check discovery must happen only after this observation and trigger.
        """
        if pull_request_number <= 0:
            raise ValueError("pull request number must be positive")
        raw = self._pr(pull_request_number)
        binding = self._pull_binding(
            raw,
            number=pull_request_number,
            candidate_ref=candidate_ref,
            candidate_commit=candidate_commit,
            base_commit=base_commit,
        )
        actual_base_commit, base_tree, _ = self._commit_parts(self._commit(binding.base_commit))
        actual_head_commit, head_tree, _ = self._commit_parts(self._commit(binding.head_commit))
        if actual_base_commit != binding.base_commit or actual_head_commit != binding.head_commit:
            raise ValueError("pull request commit response mismatch")
        synthetic_value = raw.get("merge_commit_sha")
        if not isinstance(synthetic_value, str) or not synthetic_value:
            synthetic_value = raw.get("mergeable_commit_sha")
        synthetic = _git_object(
            synthetic_value if isinstance(synthetic_value, str) else "",
            "synthetic merge commit",
        )
        synthetic_commit, synthetic_tree, _ = self._commit_parts(self._commit(synthetic))
        if synthetic_commit != synthetic:
            raise ValueError("synthetic merge commit response mismatch")
        return SyntheticValidationObservation(
            repository_digest=self.repository_digest,
            base_ref=binding.base_ref,
            base_commit=actual_base_commit,
            base_tree=base_tree,
            head_ref=binding.head_ref,
            head_commit=actual_head_commit,
            head_tree=head_tree,
            synthetic_commit=synthetic_commit,
            synthetic_tree=synthetic_tree,
        )

    # Keep the adapter discoverable under the concise names used by provider
    # integrations while retaining one implementation and one read sequence.
    observe_validation = observe_synthetic_validation
    observe_campaign_validation = observe_synthetic_validation

    @staticmethod
    def _utc_stamp(value: datetime) -> str:
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

    def _protection_payload(self, raw: JsonValue) -> JsonObject:
        """Validate and retain only the protection fields trusted by AVO.

        IntegrationPromotionIntent has one protection digest and no separate raw
        response digest. Consequently the raw GitHub payload is deliberately not
        retained in the contract; this normalized digest is the contract-bound
        evidence, while every trusted field is checked on every read.
        """
        protection = _object(raw, "branch protection")
        status = _nested_object(protection, "required_status_checks", "branch protection")
        if (
            _required_bool(status, "strict", "required status checks") is not True
            or self.protection_policy.required_status_checks_strict is not True
        ):
            raise ValueError("branch protection strictness is not trusted")
        raw_checks = status.get("checks")
        if not isinstance(raw_checks, list):
            raise ValueError("branch protection is missing typed required checks")
        actual_checks: list[tuple[str, int]] = []
        for raw_check in raw_checks:
            check = _object(raw_check, "required status check")
            context = _required_string(check, "context", "required status check")
            app_id = _required_int(check, "app_id", "required status check")
            actual_checks.append((context, app_id))
        expected_checks = set(self.protection_checks)
        if len(actual_checks) != len(set(actual_checks)) or set(actual_checks) != expected_checks:
            raise ValueError("branch protection required checks differ from protection checks")
        contexts = status.get("contexts")
        if not isinstance(contexts, list) or any(not isinstance(x, str) for x in contexts):
            raise ValueError("branch protection contexts are malformed")
        if set(contexts) != {context for context, _ in expected_checks}:
            raise ValueError("branch protection contexts differ from protection checks")

        reviews = _nested_object(protection, "required_pull_request_reviews", "branch protection")
        if (
            _required_int(reviews, "required_approving_review_count", "pull request reviews")
            != self.protection_policy.required_approving_review_count
        ):
            raise ValueError("branch protection approval count is not trusted")
        if (
            _required_bool(reviews, "dismiss_stale_reviews", "pull request reviews")
            is not self.protection_policy.dismiss_stale_reviews
        ):
            raise ValueError("branch protection stale-review policy is not trusted")
        if (
            _required_bool(reviews, "require_last_push_approval", "pull request reviews")
            is not self.protection_policy.require_last_push_approval
        ):
            raise ValueError("branch protection last-push approval policy is not trusted")

        def enabled(key: str) -> bool:
            return _required_bool(
                _nested_object(protection, key, "branch protection"), "enabled", key
            )

        if enabled("enforce_admins") is not self.protection_policy.enforce_admins:
            raise ValueError("branch protection admin enforcement is not trusted")
        if enabled("required_linear_history") is not self.protection_policy.required_linear_history:
            raise ValueError("branch protection linear-history policy is not trusted")
        if (
            enabled("required_conversation_resolution")
            is not self.protection_policy.required_conversation_resolution
        ):
            raise ValueError("branch protection conversation policy is not trusted")
        if enabled("allow_force_pushes") is not self.protection_policy.allow_force_pushes:
            raise ValueError("branch protection force-push policy is not trusted")
        if enabled("allow_deletions") is not self.protection_policy.allow_deletions:
            raise ValueError("branch protection deletion policy is not trusted")
        if enabled("lock_branch") is not self.protection_policy.lock_branch:
            raise ValueError("branch protection lock policy is not trusted")

        normalized = {
            "required_status_checks": {
                "strict": self.protection_policy.required_status_checks_strict,
                "checks": [
                    {"context": context, "app_id": app_id}
                    for context, app_id in sorted(expected_checks)
                ],
            },
            "required_pull_request_reviews": {
                "required_approving_review_count": (
                    self.protection_policy.required_approving_review_count
                ),
                "dismiss_stale_reviews": self.protection_policy.dismiss_stale_reviews,
                "require_last_push_approval": self.protection_policy.require_last_push_approval,
            },
            "enforce_admins": self.protection_policy.enforce_admins,
            "required_linear_history": self.protection_policy.required_linear_history,
            "required_conversation_resolution": (
                self.protection_policy.required_conversation_resolution
            ),
            "allow_force_pushes": self.protection_policy.allow_force_pushes,
            "allow_deletions": self.protection_policy.allow_deletions,
            "lock_branch": self.protection_policy.lock_branch,
        }
        return cast(JsonObject, _json_value(normalized))

    def _protection_evidence(self, raw: JsonValue) -> str:
        return canonical_digest(self._protection_payload(raw))

    @staticmethod
    def _commit_topology(value: JsonObject) -> tuple[str, str, tuple[str, ...]]:
        commit = _required_string(value, "sha", "Git commit")
        tree = _required_string(_nested_object(value, "tree", "Git commit"), "sha", "Git tree")
        parents_value = value.get("parents")
        if not isinstance(parents_value, list):
            raise ValueError("malformed Git commit: missing parents")
        parents: list[str] = []
        for raw_parent in parents_value:
            parents.append(_required_string(_object(raw_parent, "Git parent"), "sha", "Git parent"))
        return commit, tree, tuple(parents)

    @classmethod
    def _commit_parts(cls, value: JsonObject) -> tuple[str, str, str]:
        """Return the historical three-part view while retaining topology internally."""
        commit, tree, parents = cls._commit_topology(value)
        return commit, tree, parents[0] if parents else "0" * 40

    def _main_protection_evidence(self) -> str:
        """Read the pinned main protection immediately before a merge.

        The controller's own identity must not be able to bypass the race
        containment review on ``main``.  GitHub's ``enforce_admins`` flag is
        the provider's non-bypass guarantee; one or more required approvals is
        the independent human gate.  Keep this evidence small and canonical so
        it can be carried by the durable reconciliation record.
        """
        raw = _object(
            self._call("GET", self._path("branches/main/protection")),
            "main branch protection",
        )
        reviews = _nested_object(raw, "required_pull_request_reviews", "main branch protection")
        approvals = _required_int(
            reviews, "required_approving_review_count", "main pull request reviews"
        )
        admins = _nested_object(raw, "enforce_admins", "main branch protection")
        if approvals < 1:
            raise ValueError("main branch protection requires at least one approval")
        if not _required_bool(admins, "enabled", "main admin enforcement"):
            raise ValueError("main branch protection does not enforce administrators")
        return canonical_digest(
            {
                "ref": "refs/heads/main",
                "required_approving_review_count": approvals,
                "enforce_admins": True,
            }
        )

    def _evidence_snapshot(self, synthetic: str, synthetic_tree: str) -> GitHubEvidenceSnapshot:
        protection = self._call(
            "GET",
            self._path(
                f"branches/{quote(self.target_ref.removeprefix('refs/heads/'), safe='')}/protection"
            ),
        )
        protection_payload = self._protection_payload(protection)
        protection_digest = canonical_digest(protection_payload)
        expected = set(self.trusted_checks)
        found: list[JsonObject] = []
        seen: set[tuple[str, int]] = set()
        run_ids: set[int] = set()
        total_count: int | None = None
        all_items: list[JsonObject] = []
        max_pages = 100
        max_items = 10_000
        page = 1
        while True:
            runs = _object(
                self._call(
                    "GET",
                    self._path(f"commits/{synthetic}/check-runs?per_page=100&page={page}"),
                ),
                "check runs",
            )
            page_total = _required_int(runs, "total_count", "check runs")
            if page_total < 0 or page_total > max_items:
                raise ValueError("check run total count exceeds bounded pagination")
            if total_count is None:
                total_count = page_total
            elif page_total != total_count:
                raise ValueError("check run total count changed during pagination")
            items = runs.get("check_runs")
            if not isinstance(items, list) or len(items) > 100:
                raise ValueError("malformed or oversized check run page")
            for raw_run in items:
                run = _object(raw_run, "check run")
                run_id = _required_int(run, "id", "check run")
                if run_id in run_ids:
                    raise ValueError("duplicate check run ID across pages")
                run_ids.add(run_id)
                all_items.append(run)
            expected_pages = max(1, ceil(page_total / 100))
            if page > expected_pages or page > max_pages:
                raise ValueError("check run pagination exceeded declared bounds")
            expected_page_items = page_total - ((page - 1) * 100) if page == expected_pages else 100
            if len(items) != expected_page_items:
                raise ValueError("check run page is inconsistent with total_count")
            if page == expected_pages:
                break
            page += 1
        assert total_count is not None
        if len(all_items) != total_count:
            raise ValueError("check run pagination did not collect total_count items")
        for run in all_items:
            name = _required_string(run, "name", "check run")
            app = _nested_object(run, "app", "check run")
            app_id = _required_int(app, "id", "check app")
            head_sha = _required_string(run, "head_sha", "check run")
            key = (name, app_id)
            if key in expected:
                if (
                    key in seen
                    or head_sha != synthetic
                    or _required_string(run, "status", "check run") != "completed"
                    or _required_string(run, "conclusion", "check run") != "success"
                ):
                    raise ValueError("duplicate, incomplete, or unsuccessful trusted check")
                stamp = run.get("completed_at")
                if not isinstance(stamp, str):
                    raise ValueError("trusted check is stale: completed_at is required")
                try:
                    completed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                except ValueError as exc:
                    raise ValueError("trusted check timestamp is malformed") from exc
                if completed.tzinfo is None:
                    raise ValueError("trusted check timestamp must be timezone-aware")
                if completed > datetime.now(UTC):
                    raise ValueError("trusted check is future-dated")
                if completed < self.freshness_cutoff:
                    raise ValueError("trusted check is stale")
                seen.add(key)
                app_slug = _required_string(app, "slug", "check app")
                found.append(
                    {
                        "id": _required_int(run, "id", "check run"),
                        "name": name,
                        "app_id": app_id,
                        "head_sha": head_sha,
                        "app_slug": app_slug,
                        "status": "completed",
                        "conclusion": "success",
                        "completed_at": self._utc_stamp(completed),
                    }
                )
        if seen != expected:
            raise ValueError("required trusted checks missing or substituted")
        ordered = sorted(
            found,
            key=lambda x: (
                _required_string(x, "name", "check manifest"),
                _required_int(x, "app_id", "check manifest"),
            ),
        )
        manifest = {
            "schema_version": 1,
            "synthetic_sha": synthetic,
            "synthetic_tree": synthetic_tree,
            "protection_evidence_digest": protection_digest,
            "provider_identity": self.provider_identity,
            "provider_api_version": self.provider_api_version,
            "trusted_checks": [
                {"context": name, "app_id": app_id} for name, app_id in sorted(expected)
            ],
            "freshness_cutoff": self._utc_stamp(self.freshness_cutoff),
            "total_count": total_count,
            "page_count": page,
            "runs": ordered,
        }
        check_digest = canonical_digest(manifest)
        return GitHubEvidenceSnapshot(
            synthetic_merge_commit=synthetic,
            synthetic_merge_tree=synthetic_tree,
            protection_evidence_digest=protection_digest,
            check_evidence_manifest_digest=check_digest,
            protection_evidence=protection_payload,
            check_evidence_manifest=cast(JsonObject, _json_value(manifest)),
        )

    def _evidence(self, synthetic: str, synthetic_tree: str | None = None) -> tuple[str, str]:
        if synthetic_tree is None:
            _, synthetic_tree, _ = self._commit_parts(self._commit(synthetic))
        snapshot = self._evidence_snapshot(synthetic, synthetic_tree)
        return snapshot.protection_evidence_digest, snapshot.check_evidence_manifest_digest

    def observe(self, intent: IntegrationPromotionIntent) -> IntegrationProviderObservation:
        self._assert_intent(intent)
        pr = self._pr(intent.pull_request_number)
        url = _required_string(pr, "html_url", "pull request")
        base = _nested_object(pr, "base", "pull request")
        head = _nested_object(pr, "head", "pull request")
        expected_url = (
            f"https://github.com/{self.owner}/{self.repo}/pull/{intent.pull_request_number}"
        )
        pr_number = _required_int(pr, "number", "pull request")
        marker = f"AVO-Campaign-Marker: {campaign_marker_digest(intent)}"
        body = _required_string(pr, "body", "pull request")
        if (
            pr_number != intent.pull_request_number
            or url != intent.pull_request_url
            or _required_string(pr, "state", "pull request") != "open"
            or not isinstance(pr.get("draft"), bool)
            or _required_bool(pr, "draft", "pull request") is not False
            or marker not in {line.strip() for line in body.splitlines()}
        ):
            raise ValueError("pull request identity/state mismatch")
        if url != expected_url:
            raise ValueError("pull request URL is not bound to configured repository")
        base_repo = _nested_object(base, "repo", "pull request base")
        head_repo = _nested_object(head, "repo", "pull request head")
        if (
            "refs/heads/" + _required_string(base, "ref", "pull request base") != intent.target_ref
            or "refs/heads/" + _required_string(head, "ref", "pull request head")
            != intent.candidate_ref
            or _required_string(base_repo, "full_name", "base repository")
            != f"{self.owner}/{self.repo}"
            or _required_string(head_repo, "full_name", "head repository")
            != f"{self.owner}/{self.repo}"
        ):
            raise ValueError("pull request repository/ref mismatch")
        base_sha = _required_string(base, "sha", "pull request base")
        head_sha = _required_string(head, "sha", "pull request head")
        if base_sha != intent.base_commit or head_sha != intent.candidate_commit:
            raise ValueError("pull request commit drift")
        bc, bt, _ = self._commit_parts(self._commit(base_sha))
        hc, ht, _ = self._commit_parts(self._commit(head_sha))
        synthetic = pr.get("merge_commit_sha") or pr.get("mergeable_commit_sha")
        if not isinstance(synthetic, str) or not synthetic:
            raise ValueError("GitHub did not expose synthetic merge SHA")
        sc, st, _ = self._commit_parts(self._commit(synthetic))
        protection, checks = self._evidence(sc)
        if (
            sc != intent.synthetic_merge_commit
            or st != intent.synthetic_merge_tree
            or bt != intent.base_tree
            or ht != intent.candidate_tree
            or protection != intent.protection_evidence_digest
            or checks != intent.check_evidence_manifest_digest
        ):
            raise ValueError("provider evidence or synthetic merge binding drifted")
        return IntegrationProviderObservation(
            repository_digest=self.repository_digest,
            pull_request_number=pr_number,
            pull_request_url=url,
            candidate_repository_digest=self.repository_digest,
            target_repository_digest=self.repository_digest,
            base_ref=intent.target_ref,
            base_commit=bc,
            base_tree=bt,
            head_ref=intent.candidate_ref,
            head_commit=hc,
            candidate_tree=ht,
            synthetic_merge_commit=sc,
            synthetic_merge_tree=st,
            protection_evidence_digest=protection,
            check_evidence_manifest_digest=checks,
            provider_identity=self.provider_identity,
            provider_api_version=self.provider_api_version,
            open_state="open",
            draft=False,
        )

    observe_pull_request = observe

    def merge(
        self,
        intent: IntegrationPromotionIntent,
        *,
        lease_guard: Callable[[], None],
        mutation_authorize: Callable[[], None] | None = None,
    ) -> IntegrationMergeResult:
        try:
            self._assert_intent(intent)
            # Re-read every PR, synthetic-merge, protection, and check binding directly
            # before the single mutation. The service's earlier observation is not enough.
            self.observe(intent)
            target = self.observe_integration(intent.target_ref)
            base_parent = self._commit_parts(self._commit(intent.base_commit))[2]
            if (
                target.commit != intent.base_commit
                or target.tree != intent.base_tree
                or target.first_parent_commit != base_parent
                or target.protection_evidence_digest != intent.protection_evidence_digest
            ):
                raise ValueError("integration target head or protection drifted")
            # This read is deliberately the last provider observation before the
            # controller lease guard and the single mutating PUT.  It contains the
            # pinned main-branch race containment evidence.
            main_protection_digest = self._main_protection_evidence()
            if intent.expected_main_commit is not None:
                # The main ref SHA is intentionally the final provider read
                # before lease authorization and the one mutating PUT.
                main = self.read_authority_ref("refs/heads/main", allow_protected=True)
                if main.commit != intent.expected_main_commit:
                    raise ValueError("current main commit differs from expected main commit")
        except (ValueError, GitHubRejected, GitHubTransportError) as exc:
            # These checks all precede the lease guard and PUT.  Preserve their
            # fail-closed meaning for the promotion service; do not let a generic
            # precondition or observation failure become transport ambiguity and
            # trigger reconciliation.
            raise IntegrationPromotionPreconditionError(str(exc)) from exc
        # This is intentionally the final operation before the one mutating PUT.
        try:
            lease_guard()
            if mutation_authorize is not None:
                mutation_authorize()
        except (ValueError, RuntimeError, OSError) as exc:
            # The final fence is still before the PUT.  A lost lease cannot be
            # treated as an ambiguous submission because no provider mutation
            # was attempted.
            raise IntegrationPromotionPreconditionError(str(exc)) from exc
        try:
            response = _object(
                self._call(
                    "PUT",
                    self._path(f"pulls/{intent.pull_request_number}/merge"),
                    {"sha": intent.candidate_commit, "merge_method": "squash"},
                ),
                "merge response",
            )
        except GitHubRejected as exc:
            return IntegrationMergeResult(
                outcome="rejected",
                response_digest=canonical_digest({"error": str(exc)}),
                error=str(exc),
            )
        except GitHubTransportError as exc:
            return IntegrationMergeResult(
                outcome="ambiguous",
                response_digest=canonical_digest({"error": str(exc)}),
                error=str(exc),
            )
        if not _required_bool(response, "merged", "merge response"):
            return IntegrationMergeResult(
                outcome="rejected",
                response_digest=canonical_digest(response),
                error=str(response.get("message", "merge rejected")),
            )
        sha = _required_string(response, "sha", "merge response")
        commit, tree, parents = self._commit_topology(self._commit(sha))
        if len(parents) != 1 or parents[0] != intent.base_commit:
            raise ValueError("merge result has unexpected parent topology")
        return IntegrationMergeResult(
            outcome="applied",
            result_commit=commit,
            result_tree=tree,
            first_parent_commit=parents[0],
            response_digest=canonical_digest(response),
            main_protection_evidence_digest=main_protection_digest,
        )

    merge_pull_request = merge

    def reconcile(self, intent: IntegrationPromotionIntent) -> IntegrationProviderReconciliation:
        self._assert_intent(intent)
        pr = self._pr(intent.pull_request_number)
        base = _nested_object(pr, "base", "pull request")
        base_repo = _nested_object(base, "repo", "pull request base")
        pr_number = _required_int(pr, "number", "pull request")
        state = _required_string(pr, "state", "pull request")
        marker = f"AVO-Campaign-Marker: {campaign_marker_digest(intent)}"
        body = _required_string(pr, "body", "pull request")
        if (
            pr_number != intent.pull_request_number
            or _required_string(pr, "html_url", "pull request") != intent.pull_request_url
            or _required_string(base, "ref", "pull request base")
            != self.target_ref.removeprefix("refs/heads/")
            or _required_string(base_repo, "full_name", "base repository")
            != f"{self.owner}/{self.repo}"
            or marker not in {line.strip() for line in body.splitlines()}
        ):
            raise ValueError("pull request reconciliation binding mismatch")
        if state not in {"open", "closed"}:
            raise ValueError("malformed pull request state")
        state_literal = cast(Literal["open", "closed"], state)
        merged = _required_bool(pr, "merged", "pull request")
        head = _nested_object(pr, "head", "pull request")
        head_repo = _nested_object(head, "repo", "pull request head")
        if (
            _required_string(head_repo, "full_name", "head repository")
            != f"{self.owner}/{self.repo}"
            or "refs/heads/" + _required_string(head, "ref", "pull request head")
            != intent.candidate_ref
            or _required_string(head, "sha", "pull request head") != intent.candidate_commit
        ):
            raise ValueError("pull request head reconciliation binding mismatch")
        ref = _object(
            self._call(
                "GET",
                self._path(
                    f"git/ref/heads/{quote(self.target_ref.removeprefix('refs/heads/'), safe='')}"
                ),
            ),
            "Git ref",
        )
        sha = _required_string(_nested_object(ref, "object", "Git ref"), "sha", "Git ref")
        commit, tree, parents = self._commit_topology(self._commit(sha))
        parent = parents[0] if parents else "0" * 40
        protection = self._call(
            "GET",
            self._path(
                f"branches/{quote(self.target_ref.removeprefix('refs/heads/'), safe='')}/protection"
            ),
        )
        merge_commit = pr.get("merge_commit_sha") if merged else None
        if merge_commit is not None and not isinstance(merge_commit, str):
            raise ValueError("malformed merge commit")
        if merged and (len(parents) != 1 or parents[0] != intent.base_commit):
            raise ValueError("merged target has unexpected parent topology")
        return IntegrationProviderReconciliation(
            repository_digest=self.repository_digest,
            pull_request_number=pr_number,
            pull_request_url=_required_string(pr, "html_url", "pull request"),
            provider_identity=self.provider_identity,
            provider_api_version=self.provider_api_version,
            state=state_literal,
            merged=merged,
            merge_commit=merge_commit,
            target_ref=self.target_ref,
            target_head_commit=commit,
            target_head_tree=tree,
            target_first_parent=parent,
            target_parents=list(parents),
            protection_evidence_digest=self._protection_evidence(protection),
        )

    def observe_integration(self, target_ref: str) -> IntegrationTargetObservation:
        """Read-only target observation used by the promotion service."""
        if target_ref != self.target_ref:
            raise ValueError("target ref is not configured integration ref")
        ref = _object(
            self._call(
                "GET",
                self._path(
                    f"git/ref/heads/{quote(target_ref.removeprefix('refs/heads/'), safe='')}"
                ),
            ),
            "Git ref",
        )
        sha = _required_string(_nested_object(ref, "object", "Git ref"), "sha", "Git ref")
        commit, tree, parents = self._commit_topology(self._commit(sha))
        parent = parents[0] if parents else "0" * 40
        protection = self._call(
            "GET",
            self._path(
                f"branches/{quote(target_ref.removeprefix('refs/heads/'), safe='')}/protection"
            ),
        )
        return IntegrationTargetObservation(
            target_ref=target_ref,
            commit=commit,
            tree=tree,
            first_parent_commit=parent,
            protection_evidence_digest=self._protection_evidence(protection),
            provider_identity=self.provider_identity,
            provider_api_version=self.provider_api_version,
            parent_commits=parents,
        )

    def _validation_ref_path(self, repository_digest: str, ref: str) -> str:
        """Validate the complete synthetic-validation binding before I/O."""
        if repository_digest != self.repository_digest:
            raise ValueError("repository digest does not match configured GitHub repository")
        if _VALIDATION_REF.fullmatch(ref) is None:
            raise ValueError("validation ref is outside the synthetic validation scope")
        branch = ref.removeprefix("refs/heads/")
        return f"git/ref/heads/{quote(branch, safe='')}"

    def read_validation_ref(self, repository_digest: str, ref: str) -> JsonObject | None:
        """Read one exact validation ref and resolve its commit tree."""
        path = self._validation_ref_path(repository_digest, ref)
        try:
            response = self._call("GET", self._path(path))
        except GitHubRejected as exc:
            if exc.status == 404:
                return None
            raise
        raw = _object(response, "Git ref")
        if _required_string(raw, "ref", "Git ref") != ref:
            raise ValueError("Git ref identity mismatch")
        obj = _nested_object(raw, "object", "Git ref")
        if _required_string(obj, "type", "Git ref object") != "commit":
            raise ValueError("Git ref does not point to a commit")
        ref_commit = _git_object(_required_string(obj, "sha", "Git ref object"), "Git ref commit")
        commit, tree, _ = self._commit_topology(self._commit(ref_commit))
        _git_object(commit, "Git commit")
        _git_object(tree, "Git tree")
        if commit != ref_commit:
            raise ValueError("Git ref commit response mismatch")
        return {"commit": commit, "tree": tree}

    def create_validation_ref(self, repository_digest: str, ref: str, commit: str) -> JsonObject:
        """Create exactly one immutable validation ref; never update or retry."""
        self._validation_ref_path(repository_digest, ref)
        expected = _git_object(commit, "validation commit")
        response = _object(
            self._call("POST", self._path("git/refs"), {"ref": ref, "sha": expected}),
            "Git ref",
        )
        if _required_string(response, "ref", "Git ref") != ref:
            raise ValueError("Git ref identity mismatch")
        obj = _nested_object(response, "object", "Git ref")
        if _required_string(obj, "type", "Git ref object") != "commit":
            raise ValueError("Git ref does not point to a commit")
        if (
            _git_object(_required_string(obj, "sha", "Git ref object"), "Git ref commit")
            != expected
        ):
            raise ValueError("Git ref commit response mismatch")
        return {"commit": expected}

    def delete_validation_ref(self, repository_digest: str, ref: str) -> JsonValue:
        """Delete exactly one validation ref."""
        # Reads use GitHub's singular ``git/ref/heads/...`` route, while the
        # delete endpoint is the plural ``git/refs/{ref}`` route.  Reuse the
        # validator for the complete repository/ref binding, then construct
        # the endpoint required by GitHub's DELETE API.
        self._validation_ref_path(repository_digest, ref)
        branch = ref.removeprefix("refs/heads/")
        path = f"git/refs/heads/{quote(branch, safe='')}"
        return self._call("DELETE", self._path(path))


GitHubProvider = GitHubIntegrationProvider
GitHubRESTProvider = GitHubIntegrationProvider

__all__ = [
    "GitHubEvidenceSnapshot",
    "GitHubIntegrationProvider",
    "GitHubProtectionPolicy",
    "GitHubProvider",
    "GitHubPullRequestBinding",
    "GitHubPullRequestDiscovery",
    "GitHubRESTProvider",
    "GitHubRefObservation",
    "GitHubRejected",
    "GitHubRollbackTopology",
    "GitHubTransportError",
    "JsonBody",
    "JsonObject",
    "JsonTransport",
    "JsonValue",
    "github_repository_digest",
]
