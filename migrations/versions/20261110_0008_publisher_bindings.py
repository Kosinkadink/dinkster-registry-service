"""Bind publishers to immutable identity-service subjects."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261110_0008"
down_revision: str | None = "20261110_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "publisher_bindings",
        sa.Column("publisher_id", sa.String(64), nullable=False),
        sa.Column("identity_subject", sa.String(128), nullable=False),
        sa.ForeignKeyConstraint(["publisher_id"], ["publishers.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("publisher_id"),
        sa.UniqueConstraint("identity_subject"),
    )


def downgrade() -> None:
    op.drop_table("publisher_bindings")
