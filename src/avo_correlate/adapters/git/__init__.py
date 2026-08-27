"""Read-only adapters for trusted Git repository inspection."""

from avo_correlate.adapters.git.repository import (
    GitRepository,
    GitRepositoryError,
    GitRepositoryReader,
    StaleGitSnapshotError,
)

__all__ = ["GitRepository", "GitRepositoryError", "GitRepositoryReader", "StaleGitSnapshotError"]
