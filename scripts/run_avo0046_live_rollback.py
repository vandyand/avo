"""Run one resumable, PR-native AVO-004.6 live rollback.

The hosted adapters are deliberately dependency-injected.  This keeps the CLI
from treating untrusted JSON as a soak or authorization and lets deployments
construct the existing GitCandidatePublisher/GitHub providers with their
trusted configuration before invoking :class:`LiveRollbackOperator`.
"""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from avo_correlate.adapters.git import GitCandidatePublisher
from avo_correlate.adapters.hosted_git import GitHubCampaignProvider
from avo_correlate.application.integration_live_rollback_completion_service import (
    LiveRollbackCompletionExecution,
    LiveRollbackCompletionInputs,
    LiveRollbackCompletionService,
)
from avo_correlate.application.integration_live_rollback_service import (
    LiveIntegrationRollbackService,
)
from avo_correlate.application.integration_promotion_service import IntegrationPromotionService
from avo_correlate.application.integration_rollback_service import IntegrationDrillRollbackService
from avo_correlate.application.synthetic_validation_service import SyntheticValidationService
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_campaign import IntegrationCampaignEvidencePackage
from avo_correlate.contracts.integration_drill import (
    IntegrationDrillRollbackAuthorization,
    IntegrationRollbackRequest,
)
from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    IntegrationPromotionIntent,
)
from avo_correlate.contracts.promotion_bundle import PromotionBundle


@dataclass(frozen=True, slots=True)
class LiveRollbackHostedWiring:
    """The existing hosted boundaries used by the live rollback operator."""

    publisher: GitCandidatePublisher
    campaign_provider: GitHubCampaignProvider
    promotion: IntegrationPromotionService
    drill: IntegrationDrillRollbackService
    core: LiveIntegrationRollbackService
    validation: SyntheticValidationService


class LiveRollbackOperator:
    """Small orchestration boundary; all provider mutations stay in services."""

    def __init__(
        self, wiring: LiveRollbackHostedWiring, completion: LiveRollbackCompletionService
    ) -> None:
        self.wiring = wiring
        self.completion = completion

    def execute(
        self,
        request: IntegrationRollbackRequest,
        *,
        canary_package: IntegrationCampaignEvidencePackage,
        canary_package_artifact: ArtifactRef,
        authorization: IntegrationDrillRollbackAuthorization,
        bundle: PromotionBundle,
        publication: CandidatePublicationBinding,
        bundle_digest: str,
        intent_factory: Callable[[Any], IntegrationPromotionIntent],
        inputs: LiveRollbackCompletionInputs,
    ) -> LiveRollbackCompletionExecution:
        """Execute or replay a fully typed, canary-bound rollback operation."""

        return self.completion.run(
            request,
            canary_package=canary_package,
            canary_package_artifact=canary_package_artifact,
            authorization=authorization,
            bundle=bundle,
            publication=publication,
            bundle_digest=bundle_digest,
            intent_factory=intent_factory,
            inputs=inputs,
        )


def run(
    operator: LiveRollbackOperator,
    request: IntegrationRollbackRequest,
    **kwargs: Any,
) -> LiveRollbackCompletionExecution:
    """Testable/operator embedding entrypoint for one resumable operation."""

    return operator.execute(request, **kwargs)


def redact_secret(value: str) -> str:
    """Return a stable non-secret representation for logs and CLI summaries."""

    return "<redacted>" if value else "<absent>"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    token = os.environ.get(args.token_env, "")
    if not token:
        print(json.dumps({"status": "blocked", "error": "GITHUB_TOKEN is required"}))
        return 2
    # A CLI cannot safely deserialize the canary, authorization, provider
    # observation, and failed-soak proof from caller JSON.  Hosted deployments
    # must construct LiveRollbackHostedWiring and typed inputs in-process.
    summary = {
        "schema_version": 1,
        "state_root": str(args.state_root),
        "operation_id": args.operation_id,
        "token": redact_secret(token),
        "token_env": args.token_env,
        "status": "trusted_state_construction_required",
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
