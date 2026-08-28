"""Hosted Git providers."""

from .campaign import GitHubCampaignProvider
from .github import (
    GitHubEvidenceSnapshot,
    GitHubIntegrationProvider,
    GitHubProtectionPolicy,
    GitHubProvider,
    GitHubPullRequestBinding,
    GitHubPullRequestDiscovery,
    GitHubRESTProvider,
    github_repository_digest,
)

__all__ = [
    "GitHubCampaignProvider",
    "GitHubEvidenceSnapshot",
    "GitHubIntegrationProvider",
    "GitHubProtectionPolicy",
    "GitHubProvider",
    "GitHubPullRequestBinding",
    "GitHubPullRequestDiscovery",
    "GitHubRESTProvider",
    "github_repository_digest",
]
