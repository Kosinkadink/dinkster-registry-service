"""Persist disputed publisher freezes without changing published releases."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261110_0007"
down_revision: str | None = "20261101_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "publisher_freezes",
        sa.Column("publisher_id", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("at", sa.String(64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["publisher_id"], ["publishers.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("publisher_id"),
    )


def downgrade() -> None:
    op.drop_table("publisher_freezes")
