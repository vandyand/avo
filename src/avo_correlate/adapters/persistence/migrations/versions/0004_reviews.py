"""Add review records and permit preliminary plus successful admission decisions.

Revision ID: 0004_reviews
Revises: 0003_artifact_references
"""

from typing import cast

from alembic import op
from sqlalchemy import Index, Table, inspect

from avo_correlate.adapters.persistence.models import (
    AdmissionRow,
    ReviewDecisionRow,
    ReviewRequestRow,
)

revision = "0004_reviews"
down_revision = "0003_artifact_references"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    unique_names = {
        item["name"] for item in inspect(bind).get_unique_constraints("admissions")
    }
    if "uq_admission_candidate" in unique_names:
        with op.batch_alter_table("admissions") as batch:
            batch.drop_constraint("uq_admission_candidate", type_="unique")
    admissions = cast(Table, AdmissionRow.__table__)
    success_index: Index = next(
        item
        for item in admissions.indexes
        if item.name == "uq_admission_success_candidate"
    )
    success_index.create(bind=bind, checkfirst=True)
    cast(Table, ReviewRequestRow.__table__).create(bind=bind, checkfirst=True)
    cast(Table, ReviewDecisionRow.__table__).create(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    cast(Table, ReviewDecisionRow.__table__).drop(bind=bind, checkfirst=True)
    cast(Table, ReviewRequestRow.__table__).drop(bind=bind, checkfirst=True)
