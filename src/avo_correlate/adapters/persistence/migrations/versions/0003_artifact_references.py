"""Add artifact references and deletion tombstones.

Revision ID: 0003_artifact_references
Revises: 0002_invocation_provenance
"""

from typing import cast

from alembic import op
from sqlalchemy import Table

from avo_correlate.adapters.persistence.models import (
    ArtifactReferenceRow,
    DeletionTombstoneRow,
)

revision = "0003_artifact_references"
down_revision = "0002_invocation_provenance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    cast(Table, ArtifactReferenceRow.__table__).create(bind=bind, checkfirst=True)
    cast(Table, DeletionTombstoneRow.__table__).create(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    cast(Table, DeletionTombstoneRow.__table__).drop(bind=bind, checkfirst=True)
    cast(Table, ArtifactReferenceRow.__table__).drop(bind=bind, checkfirst=True)
