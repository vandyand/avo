"""Read-only protected-main provider and attestation boundary.

This adapter intentionally has a smaller authority surface than the integration
provider.  It observes GitHub state and turns only allow-listed, exact identities
into the C1 main-graduation contracts.  There are no POST, PUT, PATCH, DELETE,
ref-update, enqueue, or merge methods here; preparation and the isolated release
issuer are separate stages.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, cast
from urllib.parse import quote

from avo_correlate.adapters.hosted_git.github import (
    GitHubRejected,
    GitHubTransportError,
    JsonBody,
    JsonObject,
    JsonTransport,
    JsonValue,
    github_repository_digest,
)
from avo_correlate.contracts.main_graduation import (
    MainCheckObservation,
    MainMergeGroupChecks,
    MainMergeGroupWebhookReceipt,
    MainProtectionManifest,
    MainProviderReceipt,
    MainQueueAdmissionObservation,
    MainQueueObservation,
    MainReleaseAuthorization,
    MainReleaseHoldObservation,
    MainReleaseTransitionReceipt,
)
from avo_correlate.domain.canonical import canonical_digest

_GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CANDIDATE_HEAD = re.compile(r"^(?:refs/heads/)?avo/candidate/[0-9a-f]{64}$")

# GitHub exposes merge queues through GraphQL.  There is no supported REST
# ``/merge-queue`` or ``/merge-queue/groups`` resource.  Keep the query
# deliberately small and literal so a fake transport cannot silently turn a
# different endpoint/shape into queue authority.
_MERGE_QUEUE_QUERY = """
query ProtectedMainMergeQueue($owner: String!, $name: String!, $branch: String!) {
  repository(owner: $owner, name: $name) {
    mergeQueue(branch: $branch) {
      id
      configuration {
        maximumEntriesToBuild
        maximumEntriesToMerge
        mergeMethod
        mergingStrategy
      }
      entries(first: 100) {
        totalCount
        nodes {
          id
          position
          state
          solo
          pullRequest { number }
          baseCommit { oid }
          headCommit { oid }
        }
      }
    }
  }
}
"""


class ProtectedMainProviderError(RuntimeError):
    """An observation was malformed, stale, or failed a protected-main gate."""


class ProtectedMainRejected(ProtectedMainProviderError):
    """GitHub authoritatively rejected a read."""


@dataclass(frozen=True, slots=True)
class MainRepositoryObservation:
    repository_digest: str
    owner: str
    repo: str
    target_ref: str
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class MainRefObservation:
    repository_digest: str
    ref: str
    commit: str
    tree: str
    parents: tuple[str, ...]
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class MainPullRequestObservation:
    repository_digest: str
    number: int
    url: str
    base_ref: str
    base_commit: str
    base_tree: str
    head_ref: str
    head_commit: str
    head_tree: str
    state: str
    draft: bool
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class MainMergeGroupObservation:
    repository_digest: str
    group_sha: str
    group_tree: str
    group_parents: tuple[str, ...]
    pull_request_numbers: tuple[int, ...]
    queue_generation_digest: str
    observed_at: datetime
    webhook_receipt: MainMergeGroupWebhookReceipt


@dataclass(frozen=True, slots=True)
class ProtectedMainSnapshot:
    """All read observations for one protected-main attempt."""

    repository: MainRepositoryObservation
    main: MainRefObservation
    pull_request: MainPullRequestObservation
    queue: MainQueueObservation
    protection: MainProtectionManifest
    group: MainMergeGroupObservation | None = None


def _object(value: JsonValue, context: str) -> JsonObject:
    if not isinstance(value, dict):
        raise ProtectedMainProviderError(f"malformed {context}")
    return value


def _str(value: JsonObject, key: str, context: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item or "\x00" in item:
        raise ProtectedMainProviderError(f"malformed {context}: missing {key}")
    return item


def _int(value: JsonObject, key: str, context: str) -> int:
    item = value.get(key)
    if isinstance(item, bool) or not isinstance(item, int):
        raise ProtectedMainProviderError(f"malformed {context}: missing {key}")
    return item


def _bool(value: JsonObject, key: str, context: str) -> bool:
    item = value.get(key)
    if not isinstance(item, bool):
        raise ProtectedMainProviderError(f"malformed {context}: missing {key}")
    return item


def _items(value: JsonValue, context: str) -> list[JsonObject]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ProtectedMainProviderError(f"malformed {context}")
    return cast(list[JsonObject], value)


def _git(value: str, context: str) -> str:
    if not _GIT_OBJECT.fullmatch(value):
        raise ProtectedMainProviderError(f"malformed {context}")
    return value


def _digest(value: str, context: str) -> str:
    if not _DIGEST.fullmatch(value):
        raise ProtectedMainProviderError(f"malformed {context}")
    return value


def _nested(value: JsonObject, key: str, context: str) -> JsonObject:
    return _object(value.get(key), f"{context}.{key}")


def _parse_timestamp(value: object, context: str) -> datetime:
    if not isinstance(value, str):
        raise ProtectedMainProviderError(f"malformed {context} timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtectedMainProviderError(f"malformed {context} timestamp") from exc
    if parsed.tzinfo is None:
        raise ProtectedMainProviderError(f"{context} timestamp is not timezone-aware")
    return parsed.astimezone(UTC)


def _json_digest(value: object) -> str:
    return canonical_digest(value)


def _stable_observation(value: JsonValue) -> JsonValue:
    """Drop provider timestamps before deriving configuration identities."""
    if isinstance(value, list):
        return [_stable_observation(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _stable_observation(item)
            for key, item in value.items()
            if key.casefold() not in {"observed_at", "updated_at", "created_at", "timestamp"}
        }
    return value


class ProtectedMainProvider:
    """Controller-configured, authenticated, read-only GitHub observer."""

    def __init__(
        self,
        owner: str,
        repo: str,
        repository_digest: str,
        *,
        release_issuer_identity: str,
        release_issuer_app_id: int,
        issuer_isolation_digest: str,
        trusted_check_contexts: tuple[str, ...] = (),
        trusted_validation_app_id: int = 15368,
        api_base: str = "https://api.github.com",
        provider_identity: str = "github-protected-main",
        provider_api_version: str = "2022-11-28",
        token: str | None = None,
        transport: JsonTransport | None = None,
        webhook_secret: str | None = None,
    ) -> None:
        if not owner or not repo or any(char in owner + repo for char in "/\\"):
            raise ValueError("invalid GitHub repository binding")
        if repository_digest != github_repository_digest(owner, repo):
            raise ValueError("repository digest does not match configured GitHub repository")
        if not release_issuer_identity.strip() or release_issuer_app_id <= 0:
            raise ValueError("isolated release issuer is required")
        if trusted_validation_app_id != 15368:
            raise ValueError("protected-main validation identity is fixed to App 15368")
        if release_issuer_app_id == 15368:
            raise ValueError("validation App 15368 cannot be the release issuer")
        if token is None or not token.strip():
            raise ValueError("protected-main provider requires an authenticated token")
        _digest(repository_digest, "repository digest")
        _digest(issuer_isolation_digest, "issuer isolation digest")
        if not api_base.startswith("https://"):
            raise ValueError("provider API base must use HTTPS")
        contexts = tuple(trusted_check_contexts)
        if (
            not contexts
            or len(set(contexts)) != len(contexts)
            or any(not item for item in contexts)
        ):
            raise ValueError("trusted check contexts must be non-empty and unique")
        self.owner = owner
        self.repo = repo
        self.repository_digest = repository_digest
        self.release_issuer_identity = release_issuer_identity
        self.release_issuer_app_id = release_issuer_app_id
        self.issuer_isolation_digest = issuer_isolation_digest
        self.validation_app_id = trusted_validation_app_id
        self.trusted_check_contexts = contexts
        self.api_base = api_base.rstrip("/")
        self.provider_identity = provider_identity
        self.provider_api_version = provider_api_version
        self.token = token
        self.transport = transport or self._missing_transport
        # Credentials are process-local verification material only.  They are
        # never copied into C1 evidence, manifests, or receipts.
        self._webhook_secret = webhook_secret
        self._seen_webhook_deliveries: set[str] = set()

    @staticmethod
    def _missing_transport(
        _method: str,
        _url: str,
        _body: JsonBody | None,
        _headers: Mapping[str, str],
    ) -> tuple[int, JsonValue]:
        raise ProtectedMainProviderError("a fake or explicitly configured transport is required")

    @property
    def repository_path(self) -> str:
        return f"/repos/{quote(self.owner, safe='')}/{quote(self.repo, safe='')}"

    def _call(self, path: str) -> JsonValue:
        if not path.startswith("/"):
            raise ProtectedMainProviderError("provider path must be absolute")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.provider_api_version,
        }
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        try:
            status, payload = self.transport("GET", self.api_base + path, None, headers)
        except (GitHubRejected, GitHubTransportError) as exc:
            raise ProtectedMainProviderError(str(exc)) from exc
        except Exception as exc:
            raise ProtectedMainProviderError("provider transport failure") from exc
        if status >= 400:
            raise ProtectedMainRejected(f"provider rejected observation ({status})")
        if status < 200 or status >= 300:
            raise ProtectedMainProviderError(f"provider returned unexpected status ({status})")
        return payload

    def _graphql(self, query: str, variables: JsonObject) -> JsonObject:
        """Execute one authenticated GitHub GraphQL read.

        Queue state is only authoritative when returned by the documented
        ``Repository.mergeQueue`` field.  GraphQL errors and missing ``data``
        are deliberately not treated as an empty queue.
        """
        headers = {
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": self.provider_api_version,
        }
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        try:
            status, payload = self.transport(
                "POST",
                self.api_base + "/graphql",
                {"query": query, "variables": variables},
                headers,
            )
        except (GitHubRejected, GitHubTransportError) as exc:
            raise ProtectedMainProviderError(str(exc)) from exc
        except Exception as exc:
            raise ProtectedMainProviderError("provider transport failure") from exc
        if status >= 400:
            raise ProtectedMainRejected(f"provider rejected observation ({status})")
        if status < 200 or status >= 300:
            raise ProtectedMainProviderError(f"provider returned unexpected status ({status})")
        raw = _object(payload, "GraphQL response")
        errors = raw.get("errors")
        if errors is not None and (not isinstance(errors, list) or errors):
            raise ProtectedMainProviderError("GitHub GraphQL query failed")
        return _object(raw.get("data"), "GraphQL data")

    def _read_effective_rules(self) -> list[JsonObject]:
        """Read GitHub's authoritative, already-evaluated rules for main."""
        raw = self._call(self.repository_path + "/rules/branches/main")
        rules = _items(raw, "effective branch rules")
        if not rules or len(rules) > 100:
            raise ProtectedMainProviderError("effective main rules are missing or oversized")
        seen: set[tuple[str, str, int, str]] = set()
        for rule in rules:
            source_type = _str(rule, "ruleset_source_type", "effective branch rule")
            source = _str(rule, "ruleset_source", "effective branch rule")
            ident = _int(rule, "ruleset_id", "effective branch rule")
            rule_type = _str(rule, "type", "effective branch rule")
            key = (source_type.casefold(), source.casefold(), ident, rule_type)
            if ident <= 0 or key in seen:
                raise ProtectedMainProviderError(
                    "effective ruleset identity is duplicated or invalid"
                )
            seen.add(key)
            _nested(rule, "parameters", "effective branch rule")
        return rules

    def _queue_configuration(self, config: JsonObject | None = None) -> JsonObject:
        if config is None:
            data = self._graphql(
                _MERGE_QUEUE_QUERY,
                {"owner": self.owner, "name": self.repo, "branch": "main"},
            )
            repository = _nested(data, "repository", "GraphQL data")
            queue = _object(repository.get("mergeQueue"), "merge queue")
            config = _nested(queue, "configuration", "merge queue")
        return config

    def _ruleset_protection_epoch(self, queue_config: JsonObject) -> str:
        """Require the official active merge-queue ruleset, including no bypass."""
        applicable: list[JsonObject] = []
        merge_rules: list[tuple[JsonObject, JsonObject]] = []
        effective_rules = self._read_effective_rules()
        resolved: dict[tuple[str, str, int], JsonObject] = {}
        for rule in effective_rules:
            source_type = _str(rule, "ruleset_source_type", "effective branch rule")
            source = _str(rule, "ruleset_source", "effective branch rule")
            ident = _int(rule, "ruleset_id", "effective branch rule")
            key = (source_type.casefold(), source.casefold(), ident)
            if key in resolved:
                continue
            if source_type.casefold() == "organization":
                path = f"/orgs/{quote(source, safe='')}/rulesets/{ident}"
            elif source_type.casefold() == "repository":
                path = self.repository_path + f"/rulesets/{ident}"
            else:
                raise ProtectedMainProviderError("effective ruleset source type is unsupported")
            full = _object(self._call(path), "ruleset")
            if _int(full, "id", "ruleset") != ident:
                raise ProtectedMainProviderError("ruleset response identity differs from request")
            if _str(full, "source_type", "ruleset").casefold() != source_type.casefold():
                raise ProtectedMainProviderError("ruleset source type differs from applied rule")
            if _str(full, "source", "ruleset").casefold() != source.casefold():
                raise ProtectedMainProviderError("ruleset source differs from applied rule")
            resolved[key] = full
            for field in ("name", "source_type", "source", "target", "enforcement"):
                _str(full, field, "ruleset")
            if _str(full, "target", "ruleset") != "branch":
                raise ProtectedMainProviderError("main ruleset target is not branch")
            if _str(full, "enforcement", "ruleset").casefold() != "active":
                raise ProtectedMainProviderError("main ruleset is not active")
            bypass = full.get("bypass_actors")
            if not isinstance(bypass, list):
                raise ProtectedMainProviderError("ruleset bypass actors are unavailable")
            if bypass:
                raise ProtectedMainProviderError("main ruleset permits bypass actors")
            rules = _items(full.get("rules"), "ruleset rules")
            for full_rule in rules:
                if _str(full_rule, "type", "ruleset rule") == "merge_queue":
                    merge_rules.append((full, _nested(full_rule, "parameters", "merge queue rule")))
        applicable = list(resolved.values())
        if len(merge_rules) != 1 or not applicable:
            raise ProtectedMainProviderError(
                "active main merge_queue ruleset is missing or conflicting"
            )
        _, parameters = merge_rules[0]
        if (
            _int(parameters, "max_entries_to_merge", "merge queue rule")
            != _int(queue_config, "maximumEntriesToMerge", "merge queue configuration")
            or _str(parameters, "merge_method", "merge queue rule").casefold()
            != _str(queue_config, "mergeMethod", "merge queue configuration").casefold()
            or _str(parameters, "grouping_strategy", "merge queue rule").casefold()
            != _str(queue_config, "mergingStrategy", "merge queue configuration").casefold()
        ):
            raise ProtectedMainProviderError("ruleset and GraphQL merge queue configuration drift")
        normalized = [
            {
                key: value
                for key, value in ruleset.items()
                if key
                in {
                    "id",
                    "name",
                    "source_type",
                    "source",
                    "target",
                    "enforcement",
                    "conditions",
                    "rules",
                    "bypass_actors",
                }
            }
            for ruleset in applicable
        ]
        return _json_digest({"rulesets": normalized, "graphql_queue_configuration": queue_config})

    def _read_commit(self, sha: str, context: str) -> tuple[str, str, tuple[str, ...]]:
        raw = _object(
            self._call(self.repository_path + "/git/commits/" + _git(sha, context)), context
        )
        response_sha = _git(_str(raw, "sha", context), context + " response SHA")
        if response_sha != sha:
            raise ProtectedMainProviderError(f"{context} response SHA differs from request")
        tree = _git(
            _str(_nested(raw, "tree", context), "sha", context + ".tree"), context + " tree"
        )
        parents_raw = raw.get("parents")
        parents = tuple(
            _git(_str(parent, "sha", context + ".parent"), context + " parent")
            for parent in _items(parents_raw, context + ".parents")
        )
        return sha, tree, parents

    def observe_repository(self) -> MainRepositoryObservation:
        raw = _object(self._call(self.repository_path), "repository")
        full_name = _str(raw, "full_name", "repository")
        if full_name.casefold() != f"{self.owner}/{self.repo}".casefold():
            raise ProtectedMainProviderError("repository identity differs from controller binding")
        return MainRepositoryObservation(
            self.repository_digest,
            self.owner,
            self.repo,
            "refs/heads/main",
            datetime.now(UTC),
        )

    def observe_ref(self, ref: str = "refs/heads/main") -> MainRefObservation:
        if ref != "refs/heads/main":
            raise ProtectedMainProviderError("provider target is exactly protected main")
        branch = quote(ref.removeprefix("refs/heads/"), safe="")
        raw = _object(self._call(self.repository_path + "/git/ref/heads/" + branch), "main ref")
        if raw.get("ref") != "refs/heads/main":
            raise ProtectedMainProviderError("main ref response differs from requested ref")
        obj = _nested(raw, "object", "main ref")
        if _str(obj, "type", "main ref object") != "commit":
            raise ProtectedMainProviderError("main ref does not resolve to a commit")
        commit = _git(_str(obj, "sha", "main ref object"), "main ref commit")
        commit, tree, parents = self._read_commit(commit, "main commit")
        return MainRefObservation(
            self.repository_digest, ref, commit, tree, parents, datetime.now(UTC)
        )

    def observe_main(self) -> MainRefObservation:
        return self.observe_ref()

    def observe_pull_request(
        self,
        number: int,
        *,
        expected_base_commit: str | None = None,
        expected_head_ref: str | None = None,
        expected_head_commit: str | None = None,
        expected_url: str | None = None,
    ) -> MainPullRequestObservation:
        if isinstance(number, bool) or number <= 0:
            raise ProtectedMainProviderError("pull request number must be positive")
        raw = _object(self._call(self.repository_path + f"/pulls/{number}"), "pull request")
        if _int(raw, "number", "pull request") != number:
            raise ProtectedMainProviderError("pull request number differs from request")
        base = _nested(raw, "base", "pull request")
        head = _nested(raw, "head", "pull request")
        base_repo = _nested(base, "repo", "pull request base")
        head_repo = _nested(head, "repo", "pull request head")
        expected_name = f"{self.owner}/{self.repo}".casefold()
        if _str(base_repo, "full_name", "pull request base repo").casefold() != expected_name:
            raise ProtectedMainProviderError("pull request base is not same-repository")
        if _str(head_repo, "full_name", "pull request head repo").casefold() != expected_name:
            raise ProtectedMainProviderError("pull request head is not same-repository")
        base_ref = _str(base, "ref", "pull request base")
        if base_ref not in {"main", "refs/heads/main"}:
            raise ProtectedMainProviderError("pull request is retargeted")
        base_commit = _git(_str(base, "sha", "pull request base"), "pull request base SHA")
        head_commit = _git(_str(head, "sha", "pull request head"), "pull request head SHA")
        head_ref = _str(head, "ref", "pull request head")
        if not _CANDIDATE_HEAD.fullmatch(head_ref):
            raise ProtectedMainProviderError("pull request head is outside candidate namespace")
        _, base_tree, _ = self._read_commit(base_commit, "pull request base commit")
        _, head_tree, _ = self._read_commit(head_commit, "pull request head commit")
        if base_commit == head_commit:
            raise ProtectedMainProviderError("pull request head must differ from base")
        state = _str(raw, "state", "pull request")
        merged = raw.get("merged")
        if not isinstance(merged, bool):
            raise ProtectedMainProviderError("pull request merged flag is malformed")
        if state != "open" or merged:
            raise ProtectedMainProviderError("pull request is not open and unmerged")
        if _bool(raw, "draft", "pull request"):
            raise ProtectedMainProviderError("draft pull request cannot be admitted")
        url = _str(raw, "html_url", "pull request")
        expected_url_value = f"https://github.com/{self.owner}/{self.repo}/pull/{number}"
        if (
            url != expected_url_value
            or (expected_url is not None and url != expected_url)
        ):
            raise ProtectedMainProviderError("pull request URL is not exact")
        if expected_base_commit is not None and base_commit != _git(
            expected_base_commit, "expected base"
        ):
            raise ProtectedMainProviderError("pull request base SHA differs from authorization")
        if (
            expected_head_ref is not None
            and _str(head, "ref", "pull request head") != expected_head_ref
        ):
            raise ProtectedMainProviderError("pull request head ref differs from authorization")
        if expected_head_commit is not None and head_commit != _git(
            expected_head_commit, "expected head"
        ):
            raise ProtectedMainProviderError("pull request head SHA differs from authorization")
        return MainPullRequestObservation(
            self.repository_digest,
            number,
            url,
            "refs/heads/main",
            base_commit,
            base_tree,
            head_ref,
            head_commit,
            head_tree,
            state,
            False,
            datetime.now(UTC),
        )

    def observe_protection(self, queue_config: JsonObject | None = None) -> MainProtectionManifest:
        raw = _object(self._call(self.repository_path + "/branches/main/protection"), "protection")
        required = _nested(raw, "required_status_checks", "protection")
        contexts = required.get("contexts")
        checks = required.get("checks")
        if not isinstance(contexts, list) or any(not isinstance(item, str) for item in contexts):
            raise ProtectedMainProviderError("required check contexts are incomplete")
        names = cast(list[str], contexts)
        expected_contexts = {*self.trusted_check_contexts, "avo-main-release"}
        if len(names) != len(expected_contexts) or set(names) != expected_contexts:
            raise ProtectedMainProviderError("required checks differ from controller configuration")
        if not isinstance(checks, list) or len(checks) != len(names):
            raise ProtectedMainProviderError("required check App identities are incomplete")
        check_apps: dict[str, int] = {}
        for item in checks:
            check = _object(item, "required protection check")
            check_apps[_str(check, "context", "required protection check")] = _int(
                check, "app_id", "required protection check"
            )
        expected_apps = {
            **{name: self.validation_app_id for name in self.trusted_check_contexts},
            "avo-main-release": self.release_issuer_app_id,
        }
        if check_apps != expected_apps:
            raise ProtectedMainProviderError("required check App identities differ from controller")
        config = self._queue_configuration(queue_config)
        ruleset_epoch = self._ruleset_protection_epoch(config)
        protection_epoch = _json_digest(
            {"branch_protection": _stable_observation(raw), "ruleset_epoch": ruleset_epoch}
        )
        payload = {
            "repository_digest": self.repository_digest,
            "target_ref": "refs/heads/main",
            "operation_id": _json_digest(
                {"repository_digest": self.repository_digest, "protection_epoch": protection_epoch}
            ),
            "provider_identity": self.provider_identity,
            "provider_api_version": self.provider_api_version,
            "required": True,
            "queue_required": True,
            "max_entries_per_group": 1,
            "bypass_allowed": False,
            "direct_merge_allowed": False,
            "isolated_release_issuer": self.release_issuer_identity,
            "release_issuer_app_id": self.release_issuer_app_id,
            "issuer_isolation_digest": self.issuer_isolation_digest,
            "validation_app_id": self.validation_app_id,
            "release_context": "avo-main-release",
            "protection_epoch": protection_epoch,
            "observed_at": datetime.now(UTC).isoformat(),
        }
        manifest_digest = _json_digest(
            {key: value for key, value in payload.items() if key != "observed_at"}
        )
        return MainProtectionManifest.model_validate(
            {**payload, "manifest_digest": manifest_digest}
        )

    def observe_queue(self, base: MainRefObservation | None = None) -> MainQueueObservation:
        data = self._graphql(
            _MERGE_QUEUE_QUERY,
            {"owner": self.owner, "name": self.repo, "branch": "main"},
        )
        repository = _nested(data, "repository", "GraphQL data")
        raw = _object(repository.get("mergeQueue"), "merge queue")
        queue_id = _str(raw, "id", "merge queue")
        config = _nested(raw, "configuration", "merge queue")
        entries = _nested(raw, "entries", "merge queue")
        total = _int(entries, "totalCount", "merge queue entries")
        nodes = _items(entries.get("nodes"), "merge queue entries")
        if total < 0 or total != len(nodes) or total > 100:
            raise ProtectedMainProviderError("merge queue entries are incomplete")
        fresh_base = self.observe_main()
        if base is not None and (
            base.repository_digest != fresh_base.repository_digest
            or base.ref != fresh_base.ref
            or base.commit != fresh_base.commit
            or base.tree != fresh_base.tree
            or base.parents != fresh_base.parents
        ):
            raise ProtectedMainProviderError("supplied main base is stale")
        base = fresh_base
        max_entries = _int(config, "maximumEntriesToMerge", "merge queue configuration")
        if max_entries != 1:
            raise ProtectedMainProviderError("merge queue max entries per group is not one")
        method = _str(config, "mergeMethod", "merge queue configuration").casefold()
        if method != "squash":
            raise ProtectedMainProviderError("merge queue merge method is not squash")
        strategy = _str(config, "mergingStrategy", "merge queue configuration").casefold()
        if strategy != "allgreen":
            raise ProtectedMainProviderError("merge queue grouping strategy is not all-green")
        entry: JsonObject | None = nodes[0] if total == 1 else None
        if total > 1:
            raise ProtectedMainProviderError("merge queue has unrelated queued entries")
        entry_id = "empty"
        pr_number = 0
        entry_base = base.commit
        entry_head = base.commit
        state = "empty"
        solo = True
        parents = [base.commit]
        if entry is not None:
            pr = _nested(entry, "pullRequest", "merge queue entry")
            pr_number = _int(pr, "number", "merge queue entry pull request")
            if pr_number <= 0:
                raise ProtectedMainProviderError("merge queue entry PR is invalid")
            entry_base = _git(
                _str(
                    _nested(entry, "baseCommit", "merge queue entry"),
                    "oid",
                    "merge queue entry base",
                ),
                "merge queue entry base",
            )
            entry_head = _git(
                _str(
                    _nested(entry, "headCommit", "merge queue entry"),
                    "oid",
                    "merge queue entry head",
                ),
                "merge queue entry head",
            )
            if entry_base != base.commit or entry_head == base.commit:
                raise ProtectedMainProviderError("merge queue entry base/head drift")
            state = _str(entry, "state", "merge queue entry").casefold()
            if state not in {"queued", "awaiting_checks", "pending"}:
                raise ProtectedMainProviderError("merge queue entry is not pending")
            solo = _bool(entry, "solo", "merge queue entry")
            if not solo:
                raise ProtectedMainProviderError("merge queue entry is not singleton")
            entry_id = _str(entry, "id", "merge queue entry")
            parents = [base.commit, entry_head]
        protection = self.observe_protection(config)
        normalized_manifest = {
            "enabled": True,
            "max_entries_per_group": max_entries,
            "bypass_allowed": False,
            "direct_merge_allowed": False,
            "expected_base_commit": base.commit,
            "expected_base_tree": base.tree,
            "queue_id": queue_id,
            "entry_id": entry_id,
            "pull_request_number": pr_number,
            "entry_base": entry_base,
            "entry_head": entry_head,
            "entry_state": state,
            "entry_solo": solo,
            "merge_method": method,
            "merging_strategy": strategy,
            "protection_manifest_digest": protection.manifest_digest,
            "protection_epoch": protection.protection_epoch,
            "isolated_release_issuer": self.release_issuer_identity,
            "release_issuer_app_id": self.release_issuer_app_id,
            "issuer_isolation_digest": self.issuer_isolation_digest,
        }
        manifest = _json_digest(normalized_manifest)
        generation_identity = _json_digest(
            {"queue_id": queue_id, "entry_id": entry_id}
        )
        generation = _json_digest(
            {"queue_generation": generation_identity, "queue_manifest_digest": manifest}
        )
        topology = _json_digest(
            {
                "expected_group_parents": parents,
                "merge_method": method,
                "provider_identity": self.provider_identity,
                "provider_api_version": self.provider_api_version,
                "queue_manifest_digest": manifest,
            }
        )
        return MainQueueObservation(
            repository_digest=self.repository_digest,
            target_ref="refs/heads/main",
            operation_id=_json_digest(
                {"repository_digest": self.repository_digest, "queue_id": queue_id}
            ),
            queue_generation_digest=generation,
            queue_manifest_digest=manifest,
            expected_base_commit=base.commit,
            expected_base_tree=base.tree,
            protection_manifest_digest=protection.manifest_digest,
            protection_epoch=protection.protection_epoch,
            provider_identity=self.provider_identity,
            provider_api_version=self.provider_api_version,
            expected_group_parents=parents,
            group_topology_digest=topology,
            merge_method="squash",
            isolated_release_issuer=self.release_issuer_identity,
            release_issuer_app_id=self.release_issuer_app_id,
            issuer_isolation_digest=self.issuer_isolation_digest,
            observed_at=datetime.now(UTC),
        )

    def observe_merge_group(
        self,
        group_sha: str,
        *,
        webhook_body: bytes | None = None,
        webhook_headers: Mapping[str, str] | None = None,
        queue: MainQueueObservation | None = None,
        pull_request_number: int | None = None,
    ) -> MainMergeGroupObservation:
        """Observe one authenticated native GitHub ``merge_group`` webhook.

        Membership and generation are deliberately *not* accepted from the
        webhook (or its caller).  They are re-read from the documented
        GraphQL merge queue and the immutable commit object.
        """
        group_sha = _git(group_sha, "merge group SHA")
        secret = self._webhook_secret
        if secret is None or not secret:
            raise ProtectedMainProviderError("merge_group webhook secret is not configured")
        if not isinstance(webhook_body, bytes) or not webhook_body:
            raise ProtectedMainProviderError("raw merge_group webhook bytes are required")
        if len(webhook_body) > 1_048_576:
            raise ProtectedMainProviderError("merge_group webhook body is oversized")
        if webhook_headers is None:
            raise ProtectedMainProviderError("merge_group webhook headers are required")
        raw_headers = cast(Mapping[object, object], webhook_headers)
        normalized_headers: dict[str, str] = {}
        for key, value in raw_headers.items():
            if (
                not isinstance(key, str)
                or not isinstance(value, str)
                or len(key) > 256
                or len(value) > 4096
                or key.casefold() in normalized_headers
            ):
                raise ProtectedMainProviderError("merge_group webhook headers are malformed")
            normalized_headers[key.casefold()] = value
        if len(normalized_headers) > 64:
            raise ProtectedMainProviderError("merge_group webhook headers are oversized")

        def header(name: str) -> str:
            return normalized_headers.get(name.casefold(), "")

        if header("X-GitHub-Event") != "merge_group":
            raise ProtectedMainProviderError("webhook is not a merge_group event")
        delivery = header("X-GitHub-Delivery")
        signature = header("X-Hub-Signature-256")
        expected = "sha256=" + hmac.new(
            secret.encode("utf-8"), webhook_body, hashlib.sha256
        ).hexdigest()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", delivery) or not re.fullmatch(
            r"sha256=[0-9a-f]{64}", signature
        ):
            raise ProtectedMainProviderError(
                "merge_group webhook authentication headers are malformed"
            )
        if not hmac.compare_digest(signature, expected):
            raise ProtectedMainProviderError("merge_group webhook signature is invalid")
        if delivery in self._seen_webhook_deliveries:
            raise ProtectedMainProviderError("merge_group webhook delivery was already used")

        def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON object key")
                result[key] = value
            return result

        try:
            decoded = json.loads(
                webhook_body.decode("utf-8"),
                object_pairs_hook=unique_pairs,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"unsupported JSON constant: {value}")
                ),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ProtectedMainProviderError("merge_group webhook body is not valid JSON") from exc
        event = _object(cast(JsonValue, decoded), "merge_group webhook")
        if _str(event, "action", "merge_group webhook") != "checks_requested":
            raise ProtectedMainProviderError("merge_group webhook action is not checks_requested")
        repository = _nested(event, "repository", "merge_group webhook")
        if _str(repository, "full_name", "merge_group webhook repository").casefold() != (
            f"{self.owner}/{self.repo}".casefold()
        ):
            raise ProtectedMainProviderError("merge_group webhook repository differs from binding")
        event_group = _nested(event, "merge_group", "merge_group webhook")
        forbidden = {"pull_request_numbers", "queue_generation_digest", "tree_sha", "parents"}
        if forbidden.intersection(event_group):
            raise ProtectedMainProviderError(
                "merge_group webhook contains caller-derived provenance"
            )
        event_sha = _git(
            _str(event_group, "head_sha", "merge_group webhook"), "merge group event SHA"
        )
        if event_sha != group_sha:
            raise ProtectedMainProviderError("merge_group event SHA differs from request")
        head_ref = _str(event_group, "head_ref", "merge_group webhook")
        if not (
            head_ref.startswith("refs/heads/gh-readonly-queue/main/")
            or head_ref.startswith("gh-readonly-queue/main/")
        ):
            raise ProtectedMainProviderError(
                "merge_group webhook head ref is not GitHub's queue ref"
            )
        base_ref = _str(event_group, "base_ref", "merge_group webhook")
        if base_ref not in {"main", "refs/heads/main"}:
            raise ProtectedMainProviderError("merge_group webhook base ref differs from main")

        if queue is None:
            raise ProtectedMainProviderError(
                "durable authenticated queue observation is required for merge group"
            )
        current_queue = self.observe_queue()
        if (
            current_queue.queue_generation_digest != queue.queue_generation_digest
            or current_queue.expected_base_commit != queue.expected_base_commit
            or current_queue.expected_base_tree != queue.expected_base_tree
            or current_queue.expected_group_parents != queue.expected_group_parents
            or current_queue.group_topology_digest != queue.group_topology_digest
        ):
            raise ProtectedMainProviderError(
                "merge group queue snapshot is stale at webhook delivery"
            )
        queue = current_queue
        if pull_request_number is None or pull_request_number <= 0:
            raise ProtectedMainProviderError("merge group PR membership evidence is required")
        number = pull_request_number
        entry_head = queue.expected_group_parents[-1]
        entry_base = queue.expected_base_commit
        pr_observation = self.observe_pull_request(number, expected_base_commit=entry_base)
        if pr_observation.head_commit != entry_head:
            raise ProtectedMainProviderError("merge group queue entry does not match PR head")
        if entry_base != queue.expected_base_commit or queue.expected_group_parents != [
            entry_base,
            entry_head,
        ]:
            raise ProtectedMainProviderError("merge group topology differs from queue")
        event_base_sha = _git(
            _str(event_group, "base_sha", "merge_group webhook"), "merge group base SHA"
        )
        if event_base_sha != entry_base:
            raise ProtectedMainProviderError("merge_group webhook base SHA differs from queue")
        _, observed_tree, observed_parents = self._read_commit(group_sha, "merge group commit")
        if observed_parents != tuple(queue.expected_group_parents):
            raise ProtectedMainProviderError("merge group response topology differs from commit")
        self._seen_webhook_deliveries.add(delivery)
        body_digest = "sha256:" + hashlib.sha256(webhook_body).hexdigest()
        observed_at = datetime.now(UTC)
        receipt_payload = {
            "repository_digest": self.repository_digest,
            "target_ref": "refs/heads/main",
            "operation_id": queue.operation_id,
            "group_sha": group_sha,
            "group_tree": observed_tree,
            "group_parents": list(queue.expected_group_parents),
            "pull_request_number": number,
            "queue_generation_digest": queue.queue_generation_digest,
            "delivery_id": delivery,
            "body_digest": body_digest,
            "observed_at": observed_at,
        }
        receipt_probe = cast(
            MainMergeGroupWebhookReceipt,
            cast(Any, MainMergeGroupWebhookReceipt).model_construct(
                repository_digest=self.repository_digest,
                target_ref="refs/heads/main",
                operation_id=queue.operation_id,
                group_sha=group_sha,
                group_tree=observed_tree,
                group_parents=list(queue.expected_group_parents),
                pull_request_number=number,
                queue_generation_digest=queue.queue_generation_digest,
                delivery_id=delivery,
                body_digest=body_digest,
                observed_at=observed_at,
            ),
        )
        receipt = cast(
            MainMergeGroupWebhookReceipt,
            cast(Any, MainMergeGroupWebhookReceipt).model_validate(
                {
                    **receipt_payload,
                    "receipt_digest": canonical_digest(
                        cast(Any, receipt_probe).model_dump(
                            exclude={"receipt_digest"}, mode="json"
                        )
                    ),
                }
            ),
        )
        return MainMergeGroupObservation(
            self.repository_digest,
            group_sha,
            observed_tree,
            tuple(queue.expected_group_parents),
            (number,),
            queue.queue_generation_digest,
            receipt.observed_at,
            receipt,
        )

    def observe_snapshot(
        self,
        pull_request_number: int,
        *,
        group_sha: str | None = None,
        group_webhook_body: bytes | None = None,
        group_webhook_headers: Mapping[str, str] | None = None,
    ) -> ProtectedMainSnapshot:
        """Read repository, main, PR, queue, protection, and optional group together."""
        repository = self.observe_repository()
        main = self.observe_main()
        pull_request = self.observe_pull_request(
            pull_request_number,
            expected_base_commit=main.commit,
        )
        queue = self.observe_queue(main)
        protection = self.observe_protection()
        group = (
            self.observe_merge_group(
                group_sha,
                webhook_body=group_webhook_body,
                webhook_headers=group_webhook_headers,
                queue=queue,
                pull_request_number=pull_request.number,
            )
            if group_sha is not None
            else None
        )
        return ProtectedMainSnapshot(repository, main, pull_request, queue, protection, group)

    def observe_check_runs(self, sha: str) -> tuple[MainCheckObservation, ...]:
        """Read one SHA's complete check-run set; never infer checks from a PR."""
        sha = _git(sha, "check SHA")
        runs: list[JsonObject] = []
        total_count: int | None = None
        for page in range(1, 11):
            raw = _object(
                self._call(
                    self.repository_path
                    + "/commits/"
                    + sha
                    + f"/check-runs?per_page=100&page={page}"
                ),
                "check runs",
            )
            page_total = _int(raw, "total_count", "check runs")
            page_runs = _items(raw.get("check_runs"), "check runs")
            if page_total < 0 or page_total > 1000 or len(page_runs) > 100:
                raise ProtectedMainProviderError("check run response is oversized")
            if total_count is None:
                total_count = page_total
            elif total_count != page_total:
                raise ProtectedMainProviderError("check run total changed during pagination")
            runs.extend(page_runs)
            if len(runs) >= page_total:
                break
            if not page_runs:
                raise ProtectedMainProviderError("check run pagination is incomplete")
        if total_count is None or len(runs) != total_count:
            raise ProtectedMainProviderError("check run response is incomplete")
        result: list[MainCheckObservation] = []
        for run in runs:
            app = run.get("app")
            app_obj = _object(app, "check run app")
            app_id = _int(app_obj, "id", "check run app")
            status = _str(run, "status", "check run")
            conclusion_value = run.get("conclusion")
            conclusion = "pending" if conclusion_value is None else conclusion_value
            if status not in {"completed", "in_progress", "queued"} or conclusion not in {
                "success",
                "neutral",
                "failure",
                "pending",
            }:
                raise ProtectedMainProviderError("check run has an unsupported status")
            observed_value = (
                run.get("completed_at") or run.get("updated_at") or run.get("started_at")
            )
            observed_at = _parse_timestamp(observed_value, "check run")
            if observed_at > datetime.now(UTC):
                raise ProtectedMainProviderError("check run timestamp is in the future")
            run_id = _int(run, "id", "check run")
            if run_id <= 0:
                raise ProtectedMainProviderError("check run ID must be positive")
            try:
                result.append(
                    MainCheckObservation(
                        name=_str(run, "name", "check run"),
                        context=_str(run, "name", "check run"),
                        app_id=app_id,
                        sha=_git(_str(run, "head_sha", "check run"), "check run SHA"),
                        status=cast(Literal["completed", "in_progress", "queued"], status),
                        conclusion=cast(
                            Literal["success", "neutral", "failure", "pending"], conclusion
                        ),
                        run_id=str(run_id),
                        nonce=_str(run, "external_id", "check run")
                        if run.get("external_id")
                        else str(run_id),
                        observed_at=observed_at,
                    )
                )
            except Exception as exc:
                raise ProtectedMainProviderError("malformed check run observation") from exc
        if any(check.sha != sha for check in result):
            raise ProtectedMainProviderError("check run is attached to the wrong SHA")
        if len({check.context for check in result}) != len(result):
            raise ProtectedMainProviderError("duplicate check context or rerun observed")
        if len({check.run_id for check in result}) != len(result):
            raise ProtectedMainProviderError("check run ID was reused")
        if len({check.nonce for check in result}) != len(result):
            raise ProtectedMainProviderError("check run nonce was reused")
        return tuple(result)

    def observe_merge_group_checks(
        self,
        group_sha: str,
        *,
        operation_id: str,
        package_digest: str,
        composition_digest: str,
        config_digest: str,
        freshness_cutoff: datetime,
        allowlisted_contexts: tuple[str, ...] | None = None,
    ) -> MainMergeGroupChecks:
        group_sha = _git(group_sha, "merge group SHA")
        if freshness_cutoff.tzinfo is None:
            raise ProtectedMainProviderError("freshness cutoff must be timezone-aware")
        contexts = allowlisted_contexts or self.trusted_check_contexts
        if (
            not contexts
            or len(set(contexts)) != len(contexts)
            or any(not item or item == "avo-main-release" for item in contexts)
        ):
            raise ProtectedMainProviderError("allowlisted check contexts must be unique")
        all_checks = self.observe_check_runs(group_sha)
        release_checks = [check for check in all_checks if check.context == "avo-main-release"]
        checks = [check for check in all_checks if check.context != "avo-main-release"]
        if len(release_checks) != 1:
            raise ProtectedMainProviderError("merge-group release hold is missing or duplicated")
        release = release_checks[0]
        if (
            release.app_id != self.release_issuer_app_id
            or release.app_id == self.validation_app_id
            or release.status != "in_progress"
            or release.conclusion != "pending"
            or release.observed_at < freshness_cutoff
        ):
            raise ProtectedMainProviderError(
                "merge-group release hold is not isolated pending evidence"
            )
        if any(check.app_id != self.validation_app_id for check in checks):
            raise ProtectedMainProviderError("merge-group validation check has the wrong App")
        try:
            return MainMergeGroupChecks(
                repository_digest=self.repository_digest,
                target_ref="refs/heads/main",
                operation_id=_digest(operation_id, "check operation"),
                package_digest=_digest(package_digest, "check package"),
                composition_digest=_digest(composition_digest, "check composition"),
                group_sha=group_sha,
                checks=list(checks),
                allowlisted_contexts=list(contexts),
                config_digest=_digest(config_digest, "check config"),
                freshness_cutoff=freshness_cutoff,
                observed_at=datetime.now(UTC),
            )
        except Exception as exc:
            if isinstance(exc, ProtectedMainProviderError):
                raise
            raise ProtectedMainProviderError("merge-group checks are incomplete or stale") from exc

    def observe_pr_head_admission_check(
        self, head_sha: str, *, freshness_cutoff: datetime
    ) -> MainCheckObservation:
        """Return the one non-release admission success for an exact PR head."""
        checks = self.observe_check_runs(head_sha)
        matches = [check for check in checks if check.context == "avo-main-release"]
        if len(matches) != 1:
            raise ProtectedMainProviderError("PR head admission check is missing or duplicated")
        check = matches[0]
        if (
            check.sha != head_sha
            or check.app_id != self.release_issuer_app_id
            or check.app_id == self.validation_app_id
            or check.status != "completed"
            or check.conclusion != "success"
        ):
            raise ProtectedMainProviderError("PR head admission check has wrong SHA, App, or state")
        if freshness_cutoff.tzinfo is None:
            raise ProtectedMainProviderError("freshness cutoff must be timezone-aware")
        if check.observed_at < freshness_cutoff:
            raise ProtectedMainProviderError("PR head admission check is stale")
        return check

    observe_admission_check = observe_pr_head_admission_check

    def observe_group_hold_check(
        self, group_sha: str, *, freshness_cutoff: datetime
    ) -> MainCheckObservation:
        """Observe the single pending isolated release hold on an exact group SHA."""
        group_sha = _git(group_sha, "group hold SHA")
        checks = self.observe_check_runs(group_sha)
        matches = [check for check in checks if check.context == "avo-main-release"]
        if len(matches) != 1:
            raise ProtectedMainProviderError("group release hold is missing or duplicated")
        check = matches[0]
        if (
            check.sha != group_sha
            or check.app_id != self.release_issuer_app_id
            or check.app_id == self.validation_app_id
            or check.status != "in_progress"
            or check.conclusion != "pending"
        ):
            raise ProtectedMainProviderError("group release hold has wrong SHA, App, or state")
        if freshness_cutoff.tzinfo is None:
            raise ProtectedMainProviderError("freshness cutoff must be timezone-aware")
        if check.observed_at < freshness_cutoff:
            raise ProtectedMainProviderError("group release hold is stale")
        return check

    @staticmethod
    def _parse_contract(payload: JsonObject, model: Any, context: str) -> object:
        try:
            return model.model_validate(payload)
        except Exception as exc:
            raise ProtectedMainProviderError(f"malformed {context} observation") from exc

    def parse_admission(self, payload: JsonObject) -> MainQueueAdmissionObservation:
        value = cast(
            MainQueueAdmissionObservation,
            self._parse_contract(payload, MainQueueAdmissionObservation, "queue admission"),
        )
        if (
            value.issuer_identity != self.release_issuer_identity
            or value.release_issuer_app_id != self.release_issuer_app_id
            or value.issuer_isolation_digest != self.issuer_isolation_digest
            or value.validation_app_id != self.validation_app_id
            or value.release_transition
        ):
            raise ProtectedMainProviderError("queue admission issuer or state is invalid")
        return value

    def parse_hold(self, payload: JsonObject) -> MainReleaseHoldObservation:
        value = cast(
            MainReleaseHoldObservation,
            self._parse_contract(payload, MainReleaseHoldObservation, "release hold"),
        )
        if (
            value.issuer_identity != self.release_issuer_identity
            or value.release_issuer_app_id != self.release_issuer_app_id
            or value.issuer_isolation_digest != self.issuer_isolation_digest
            or value.validation_app_id != self.validation_app_id
        ):
            raise ProtectedMainProviderError("release hold issuer or state is invalid")
        return value

    def parse_release_transition(self, payload: JsonObject) -> MainReleaseTransitionReceipt:
        value = cast(
            MainReleaseTransitionReceipt,
            self._parse_contract(payload, MainReleaseTransitionReceipt, "release transition"),
        )
        if (
            value.issuer_identity != self.release_issuer_identity
            or value.release_issuer_app_id != self.release_issuer_app_id
            or value.issuer_isolation_digest != self.issuer_isolation_digest
            or value.outcome
            not in {"transitioned", "already_transitioned", "reconciliation_required"}
        ):
            raise ProtectedMainProviderError("release transition issuer or outcome is invalid")
        return value

    def parse_release_authorization(self, payload: JsonObject) -> MainReleaseAuthorization:
        value = cast(
            MainReleaseAuthorization,
            self._parse_contract(payload, MainReleaseAuthorization, "release authorization"),
        )
        if (
            value.release_issuer_identity != self.release_issuer_identity
            or value.release_issuer_app_id != self.release_issuer_app_id
            or value.issuer_isolation_digest != self.issuer_isolation_digest
            or value.used
        ):
            raise ProtectedMainProviderError(
                "release authorization issuer or one-use state is invalid"
            )
        return value

    def parse_provider_receipt(self, payload: JsonObject) -> MainProviderReceipt:
        value = cast(
            MainProviderReceipt,
            self._parse_contract(payload, MainProviderReceipt, "provider receipt"),
        )
        if (
            value.repository_digest != self.repository_digest
            or value.target_ref != "refs/heads/main"
        ):
            raise ProtectedMainProviderError("provider receipt target drift")
        return value

    # Explicit names make the stage boundary apparent to callers.
    observe_admission = parse_admission
    observe_hold = parse_hold
    observe_release_authorization = parse_release_authorization
    observe_release_transition = parse_release_transition
    observe_provider_receipt = parse_provider_receipt


class MainGraduationAttester:
    """Pure cross-observation checks for admission, hold, and release stages."""

    def __init__(self, provider: ProtectedMainProvider) -> None:
        self.provider = provider

    def attest_admission(
        self,
        observation: MainQueueAdmissionObservation,
        pull_request: MainPullRequestObservation,
        queue: MainQueueObservation,
        *,
        preparation_authorization_digest: str | None = None,
        admission_check: MainCheckObservation | None = None,
        freshness_cutoff: datetime,
    ) -> MainQueueAdmissionObservation:
        if (
            observation.repository_digest != self.provider.repository_digest
            or observation.target_ref != "refs/heads/main"
        ):
            raise ProtectedMainProviderError("admission repository or target drift")
        if (
            observation.pull_request_number != pull_request.number
            or observation.base_commit != pull_request.base_commit
            or observation.head_commit != pull_request.head_commit
        ):
            raise ProtectedMainProviderError("admission PR/base/head mismatch")
        if (
            observation.admission_sha != pull_request.head_commit
            or observation.head_tree != pull_request.head_tree
        ):
            raise ProtectedMainProviderError("admission success is not exact PR-head evidence")
        if (
            observation.queue_generation_digest != queue.queue_generation_digest
            or observation.protection_manifest_digest != queue.protection_manifest_digest
        ):
            raise ProtectedMainProviderError("admission queue/protection evidence drift")
        if observation.operation_id != queue.operation_id:
            raise ProtectedMainProviderError("admission operation differs from queue observation")
        if (
            observation.issuer_identity != self.provider.release_issuer_identity
            or observation.release_issuer_app_id != self.provider.release_issuer_app_id
            or observation.issuer_isolation_digest != self.provider.issuer_isolation_digest
        ):
            raise ProtectedMainProviderError("admission issuer is not isolated controller issuer")
        if observation.validation_app_id != 15368 or observation.release_transition:
            raise ProtectedMainProviderError("admission is not validation-only PR-head success")
        check = admission_check or self.provider.observe_pr_head_admission_check(
            pull_request.head_commit, freshness_cutoff=freshness_cutoff
        )
        if freshness_cutoff.tzinfo is None:
            raise ProtectedMainProviderError("freshness cutoff must be timezone-aware")
        if check.observed_at < freshness_cutoff or check.observed_at > datetime.now(UTC):
            raise ProtectedMainProviderError("admission check is stale or in the future")
        if (
            check.sha != pull_request.head_commit
            or check.context != "avo-main-release"
            or check.app_id != self.provider.release_issuer_app_id
            or check.app_id == self.provider.validation_app_id
            or check.status != "completed"
            or check.conclusion != "success"
            or check.run_id != observation.admission_run_id
            or check.nonce != observation.admission_nonce
        ):
            raise ProtectedMainProviderError(
                "admission check is not exact isolated PR-head success"
            )
        if (
            preparation_authorization_digest is not None
            and observation.preparation_authorization_digest != preparation_authorization_digest
        ):
            raise ProtectedMainProviderError("admission preparation authorization mismatch")
        return observation

    def attest_hold(
        self,
        hold: MainReleaseHoldObservation,
        admission: MainQueueAdmissionObservation,
        group: MainMergeGroupObservation,
        queue: MainQueueObservation,
        *,
        hold_check: MainCheckObservation | None = None,
        freshness_cutoff: datetime,
    ) -> MainReleaseHoldObservation:
        if (
            hold.repository_digest != self.provider.repository_digest
            or hold.target_ref != "refs/heads/main"
        ):
            raise ProtectedMainProviderError("hold repository or target drift")
        if (
            hold.admission_observation_digest != canonical_digest(admission)
            or hold.preparation_authorization_digest != admission.preparation_authorization_digest
        ):
            raise ProtectedMainProviderError("hold does not bind durable admission")
        if (
            hold.group_sha != group.group_sha
            or hold.group_tree != group.group_tree
            or tuple(hold.group_parents) != group.group_parents
            or hold.merge_group_receipt != group.webhook_receipt
        ):
            raise ProtectedMainProviderError("hold group identity, topology, or receipt mismatch")
        if (
            hold.queue_generation_digest != queue.queue_generation_digest
            or hold.queue_members != list(group.pull_request_numbers)
            or hold.pull_request_number != admission.pull_request_number
        ):
            raise ProtectedMainProviderError("hold group membership or queue generation mismatch")
        if (
            hold.check_state != "in_progress"
            or hold.check_conclusion != "pending"
            or hold.release_issuer_app_id != self.provider.release_issuer_app_id
            or hold.issuer_identity != self.provider.release_issuer_identity
            or hold.issuer_isolation_digest != self.provider.issuer_isolation_digest
        ):
            raise ProtectedMainProviderError("hold is not a new pending isolated release hold")
        if hold.validation_app_id != 15368:
            raise ProtectedMainProviderError("hold validation identity drift")
        if hold.operation_id != queue.operation_id:
            raise ProtectedMainProviderError("hold operation differs from queue observation")
        if (
            hold.hold_run_id == admission.admission_run_id
            or hold.hold_nonce == admission.admission_nonce
        ):
            raise ProtectedMainProviderError("group hold must use a new run ID and nonce")
        check = hold_check or self.provider.observe_group_hold_check(
            group.group_sha, freshness_cutoff=freshness_cutoff
        )
        if freshness_cutoff.tzinfo is None:
            raise ProtectedMainProviderError("freshness cutoff must be timezone-aware")
        if check.observed_at < freshness_cutoff or check.observed_at > datetime.now(UTC):
            raise ProtectedMainProviderError("hold check is stale or in the future")
        if (
            check.sha != group.group_sha
            or check.context != "avo-main-release"
            or check.app_id != self.provider.release_issuer_app_id
            or check.status != "in_progress"
            or check.conclusion != "pending"
            or check.run_id != hold.hold_run_id
            or check.nonce != hold.hold_nonce
        ):
            raise ProtectedMainProviderError("hold check is not exact isolated pending evidence")
        return hold

    def attest_merge_group_checks(
        self,
        checks: MainMergeGroupChecks,
        group: MainMergeGroupObservation,
        *,
        allowlisted_contexts: tuple[str, ...] | None = None,
    ) -> MainMergeGroupChecks:
        contexts = allowlisted_contexts or self.provider.trusted_check_contexts
        if (
            checks.repository_digest != self.provider.repository_digest
            or checks.target_ref != "refs/heads/main"
            or checks.group_sha != group.group_sha
            or checks.validation_app_id != self.provider.validation_app_id
            or tuple(checks.allowlisted_contexts) != contexts
            or "avo-main-release" in checks.allowlisted_contexts
        ):
            raise ProtectedMainProviderError("merge-group checks are not exact validation evidence")
        if any(
            check.sha != group.group_sha
            or check.app_id != self.provider.validation_app_id
            or check.status != "completed"
            or check.conclusion != "success"
            for check in checks.checks
        ):
            raise ProtectedMainProviderError("merge-group check has wrong SHA, App, or state")
        if len({check.context for check in checks.checks}) != len(checks.checks):
            raise ProtectedMainProviderError("merge-group checks contain a duplicate context")
        return checks

    def attest_release(
        self,
        authorization: MainReleaseAuthorization,
        hold: MainReleaseHoldObservation,
        transition_receipt: MainReleaseTransitionReceipt | None = None,
    ) -> MainReleaseTransitionReceipt:
        """Validate a post-transition receipt; this method grants no authority."""
        if not isinstance(transition_receipt, MainReleaseTransitionReceipt):
            raise ProtectedMainProviderError(
                "authenticated release transition receipt is required"
            )
        if (
            transition_receipt.repository_digest != self.provider.repository_digest
            or transition_receipt.target_ref != "refs/heads/main"
            or transition_receipt.issuer_identity != self.provider.release_issuer_identity
            or transition_receipt.release_issuer_app_id != self.provider.release_issuer_app_id
            or transition_receipt.release_issuer_app_id == self.provider.validation_app_id
            or transition_receipt.issuer_isolation_digest != self.provider.issuer_isolation_digest
            or transition_receipt.outcome not in {"transitioned", "already_transitioned"}
        ):
            raise ProtectedMainProviderError(
                "release transition receipt issuer or outcome is invalid"
            )
        if type(authorization) is not MainReleaseAuthorization or type(
            hold
        ) is not MainReleaseHoldObservation:
            raise ProtectedMainProviderError("release authorization and hold evidence are required")
        if (
            transition_receipt.operation_id != authorization.operation_id
            or transition_receipt.release_authorization_digest != canonical_digest(authorization)
            or transition_receipt.group_sha != hold.group_sha
            or transition_receipt.hold_run_id != hold.hold_run_id
            or transition_receipt.hold_nonce != hold.hold_nonce
            or transition_receipt.group_sha != authorization.group_sha
            or transition_receipt.hold_run_id != authorization.hold_run_id
            or transition_receipt.hold_nonce != authorization.hold_nonce
        ):
            raise ProtectedMainProviderError("release transition receipt evidence drift")
        checks = self.provider.observe_check_runs(transition_receipt.group_sha)
        matches = [check for check in checks if check.context == "avo-main-release"]
        if len(matches) != 1:
            raise ProtectedMainProviderError("release transition check is missing or duplicated")
        check = matches[0]
        if (
            check.sha != transition_receipt.group_sha
            or check.app_id != transition_receipt.release_issuer_app_id
            or check.status != "completed"
            or check.conclusion != "success"
            or check.run_id != transition_receipt.hold_run_id
            or check.nonce != transition_receipt.hold_nonce
        ):
            raise ProtectedMainProviderError(
                "release transition was not accepted by the isolated App"
            )
        return transition_receipt


# Names used by application adapters and external callers.
ProtectedMainGitHubProvider = ProtectedMainProvider
MainProtectedProvider = ProtectedMainProvider
ProtectedMainAttester = MainGraduationAttester
MainProviderAttester = MainGraduationAttester
ProtectedMainAttestationAdapter = MainGraduationAttester

__all__ = [
    "MainGraduationAttester",
    "MainMergeGroupObservation",
    "MainProtectedProvider",
    "MainProviderAttester",
    "MainPullRequestObservation",
    "MainRefObservation",
    "MainRepositoryObservation",
    "ProtectedMainAttestationAdapter",
    "ProtectedMainAttester",
    "ProtectedMainGitHubProvider",
    "ProtectedMainProvider",
    "ProtectedMainProviderError",
    "ProtectedMainRejected",
    "ProtectedMainSnapshot",
]
