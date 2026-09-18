"""Add operator-only probe diagnostics.

Revision ID: 20260904_0003
Revises: 20260903_0002
Create Date: 2026-09-04 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260904_0003"
down_revision: str | None = "20260903_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "release_scan_runs",
        sa.Column("operator_details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.create_check_constraint(
        "ck_release_scan_runs_operator_details_candidate",
        "release_scan_runs",
        "operator_details IS NULL OR candidate_id IS NOT NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_release_scan_runs_operator_details_candidate", "release_scan_runs", type_="check"
    )
    op.drop_column("release_scan_runs", "operator_details")
