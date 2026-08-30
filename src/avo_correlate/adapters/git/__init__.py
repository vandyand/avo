"""Read-only adapters for trusted Git repository inspection."""

from avo_correlate.adapters.git.main_composition import (
    DeterministicCompositionAdapter,
    DeterministicMainCompositionAdapter,
    MainBaseReader,
    MainBaseSnapshot,
    MainCompositionAdapter,
    MainCompositionError,
    MainCompositionResult,
    compose_main_candidate,
)
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
    "DeterministicCompositionAdapter",
    "DeterministicMainCompositionAdapter",
    "FilesystemPublicationJournal",
    "GitCandidatePublisher",
    "GitCommandRunner",
    "GitRepository",
    "GitRepositoryError",
    "GitRepositoryReader",
    "MainBaseReader",
    "MainBaseSnapshot",
    "MainCompositionAdapter",
    "MainCompositionError",
    "MainCompositionResult",
    "PreparedPublication",
    "PrepublicationAuthorizationJournal",
    "PublicationAmbiguousError",
    "PublicationJournal",
    "PublicationOutcome",
    "PublicationPlan",
    "PublicationResult",
    "StaleGitSnapshotError",
    "compose_main_candidate",
]
