"""Add immutable model and tool invocation evidence.

Revision ID: 0002_invocation_provenance
Revises: 0001_initial
"""

from typing import cast

from alembic import op
from sqlalchemy import Table

from avo_correlate.adapters.persistence.models import ModelInvocationRow, ToolInvocationRow

revision = "0002_invocation_provenance"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    cast(Table, ToolInvocationRow.__table__).create(bind=bind, checkfirst=True)
    cast(Table, ModelInvocationRow.__table__).create(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    cast(Table, ModelInvocationRow.__table__).drop(bind=bind, checkfirst=True)
    cast(Table, ToolInvocationRow.__table__).drop(bind=bind, checkfirst=True)
