"""Main-graduation attestation adapter entrypoint."""

from avo_correlate.adapters.hosted_git.protected_main import (
    MainGraduationAttester,
    MainProviderAttester,
    ProtectedMainAttestationAdapter,
    ProtectedMainAttester,
)

__all__ = [
    "MainGraduationAttester",
    "MainProviderAttester",
    "ProtectedMainAttestationAdapter",
    "ProtectedMainAttester",
]
