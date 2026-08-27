"""Add coding-agent invocations, reconciliation cases, and lease fencing.

Revision ID: 0005_coding_agent_runtime
Revises: 0004_reviews
"""

from typing import cast

import sqlalchemy as sa
from alembic import op
from sqlalchemy import Table, inspect

from avo_correlate.adapters.persistence.models import (
    HarnessInvocationRow,
    ReconciliationCaseRow,
)

revision = "0005_coding_agent_runtime"
down_revision = "0004_reviews"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = {item["name"] for item in inspect(bind).get_columns("activities")}
    if "lease_epoch" not in columns:
        with op.batch_alter_table("activities") as batch:
            batch.add_column(
                sa.Column("lease_epoch", sa.Integer(), nullable=False, server_default="0")
            )
    if "session_id" not in columns:
        with op.batch_alter_table("activities") as batch:
            batch.add_column(sa.Column("session_id", sa.String(length=128), nullable=True))
            batch.create_foreign_key(
                "fk_activities_session_id_variation_sessions",
                "variation_sessions",
                ["session_id"],
                ["session_id"],
            )
    if "budget_reservation_id" not in columns:
        with op.batch_alter_table("activities") as batch:
            batch.add_column(
                sa.Column("budget_reservation_id", sa.String(length=36), nullable=True)
            )
            batch.create_foreign_key(
                "fk_activities_budget_reservation_id",
                "budget_reservations",
                ["budget_reservation_id"],
                ["reservation_id"],
            )
    cast(Table, HarnessInvocationRow.__table__).create(bind=bind, checkfirst=True)
    cast(Table, ReconciliationCaseRow.__table__).create(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    cast(Table, ReconciliationCaseRow.__table__).drop(bind=bind, checkfirst=True)
    cast(Table, HarnessInvocationRow.__table__).drop(bind=bind, checkfirst=True)
    columns = {item["name"] for item in inspect(bind).get_columns("activities")}
    if "lease_epoch" in columns:
        with op.batch_alter_table("activities") as batch:
            batch.drop_column("lease_epoch")
    if "budget_reservation_id" in columns:
        with op.batch_alter_table("activities") as batch:
            batch.drop_constraint(
                "fk_activities_budget_reservation_id", type_="foreignkey"
            )
            batch.drop_column("budget_reservation_id")
    if "session_id" in columns:
        with op.batch_alter_table("activities") as batch:
            batch.drop_constraint(
                "fk_activities_session_id_variation_sessions", type_="foreignkey"
            )
            batch.drop_column("session_id")
