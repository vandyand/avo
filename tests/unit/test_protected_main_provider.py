from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import cast

import pytest

from avo_correlate.adapters.hosted_git.github import (
    JsonBody,
    JsonTransport,
    JsonValue,
    github_repository_digest,
)
from avo_correlate.adapters.hosted_git.protected_main import (
    ProtectedMainProvider,
    ProtectedMainProviderError,
)

SHA = "a" * 40
OTHER = "b" * 40
ISOLATION = "sha256:" + "1" * 64


def provider(transport: JsonTransport) -> ProtectedMainProvider:
    return ProtectedMainProvider(
        "avo",
        "repo",
        github_repository_digest("avo", "repo"),
        release_issuer_identity="isolated-release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=ISOLATION,
        trusted_check_contexts=("unit-validation",),
        token="fake-token",
        transport=transport,
    )


def test_check_observation_is_exact_sha_app_and_unique() -> None:
    calls: list[str] = []

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        calls.append(method)
        assert method == "GET"
        assert headers["Authorization"] == "Bearer fake-token"
        return 200, cast(
            JsonValue,
                {
                    "total_count": 1,
                    "check_runs": [
                    {
                        "id": 1,
                        "name": "avo-main-release",
                        "head_sha": SHA,
                        "status": "completed",
                        "conclusion": "success",
                        "app": {"id": 9001},
                        "completed_at": "2026-08-29T12:00:00Z",
                    }
                ]
            },
        )

    check = provider(transport).observe_pr_head_admission_check(
        SHA, freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC)
    )
    assert check.sha == SHA
    assert check.app_id == 9001
    assert calls == ["GET"]


def test_wrong_sha_and_mutation_authority_fail_closed() -> None:
    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        return 200, cast(
            JsonValue,
            {
                "check_runs": [
                    {
                        "id": 1,
                        "name": "avo-main-release",
                        "head_sha": OTHER,
                        "status": "completed",
                        "conclusion": "success",
                        "app": {"id": 9001},
                        "completed_at": "2026-08-29T12:00:00Z",
                    }
                ]
            },
        )

    main = provider(transport)
    with pytest.raises(ProtectedMainProviderError):
        main.observe_pr_head_admission_check(SHA, freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC))
    assert not hasattr(main, "merge")
    assert not hasattr(main, "enqueue")
