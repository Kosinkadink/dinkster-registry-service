"""Link catalog ownership and submissions to publishers.

Revision ID: 20260921_0005
Revises: 20260921_0004
Create Date: 2026-09-21 01:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260921_0005"
down_revision: str | None = "20260921_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("packs", sa.Column("publisher_id", sa.String(length=64), nullable=True))
    op.create_foreign_key(
        "fk_packs_publisher_id",
        "packs",
        "publishers",
        ["publisher_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.add_column(
        "namespace_grants", sa.Column("publisher_id", sa.String(length=64), nullable=True)
    )
    op.create_foreign_key(
        "fk_namespace_grants_publisher_id",
        "namespace_grants",
        "publishers",
        ["publisher_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.add_column(
        "release_candidates", sa.Column("publisher_id", sa.String(length=64), nullable=True)
    )
    op.create_foreign_key(
        "fk_release_candidates_publisher_id",
        "release_candidates",
        "publishers",
        ["publisher_id"],
        ["id"],
        ondelete="RESTRICT",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_release_candidates_publisher_id", "release_candidates", type_="foreignkey"
    )
    op.drop_column("release_candidates", "publisher_id")
    op.drop_constraint("fk_namespace_grants_publisher_id", "namespace_grants", type_="foreignkey")
    op.drop_column("namespace_grants", "publisher_id")
    op.drop_constraint("fk_packs_publisher_id", "packs", type_="foreignkey")
    op.drop_column("packs", "publisher_id")
