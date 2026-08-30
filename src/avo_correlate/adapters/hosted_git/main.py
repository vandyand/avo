"""Compatibility entrypoint for the protected-main provider.

The implementation lives in :mod:`protected_main` so the main-specific
authority is explicit at import sites.
"""

from .protected_main import (
    MainGraduationAttester,
    MainMergeGroupObservation,
    MainProtectedProvider,
    MainProviderAttester,
    MainPullRequestObservation,
    MainRefObservation,
    MainRepositoryObservation,
    ProtectedMainAttestationAdapter,
    ProtectedMainAttester,
    ProtectedMainGitHubProvider,
    ProtectedMainProvider,
    ProtectedMainProviderError,
    ProtectedMainRejected,
    ProtectedMainSnapshot,
)

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
