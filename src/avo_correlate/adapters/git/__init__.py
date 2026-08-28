"""Read-only adapters for trusted Git repository inspection."""

from avo_correlate.adapters.git.publisher import (
    FilesystemPublicationJournal,
    GitCandidatePublisher,
    GitCommandRunner,
    PreparedPublication,
    PrepublicationAuthorizationJournal,
    PublicationAmbiguousError,
    PublicationJournal,
    PublicationOutcome,
    PublicationPlan,
    PublicationResult,
)
from avo_correlate.adapters.git.repository import (
    GitRepository,
    GitRepositoryError,
    GitRepositoryReader,
    StaleGitSnapshotError,
)

__all__ = [
    "FilesystemPublicationJournal",
    "GitCandidatePublisher",
    "GitCommandRunner",
    "GitRepository",
    "GitRepositoryError",
    "GitRepositoryReader",
    "PreparedPublication",
    "PrepublicationAuthorizationJournal",
    "PublicationAmbiguousError",
    "PublicationJournal",
    "PublicationOutcome",
    "PublicationPlan",
    "PublicationResult",
    "StaleGitSnapshotError",
]
