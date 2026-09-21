"""Add registry principals and publishing credentials.

Revision ID: 20260921_0004
Revises: 20260904_0003
Create Date: 2026-09-21 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260921_0004"
down_revision: str | None = "20260904_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "registry_users",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "publishers",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "principal_audit",
        sa.Column("sequence", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("subject", sa.String(length=128), nullable=False),
        sa.Column("at", sa.String(length=64), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("sequence"),
    )
    op.create_table(
        "registry_operators",
        sa.Column("user_id", sa.String(length=128), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["registry_users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )
    op.create_table(
        "publisher_memberships",
        sa.Column("publisher_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.CheckConstraint("role IN ('owner', 'member')", name="ck_publisher_memberships_role"),
        sa.ForeignKeyConstraint(["publisher_id"], ["publishers.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["registry_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("publisher_id", "user_id"),
    )
    op.create_table(
        "publisher_tokens",
        sa.Column("token_id", sa.String(length=12), nullable=False),
        sa.Column("publisher_id", sa.String(length=64), nullable=False),
        sa.Column("minted_by", sa.String(length=128), nullable=False),
        sa.Column("pack_name", sa.String(length=64), nullable=True),
        sa.Column("secret_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.String(length=64), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("revoked_reason", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["minted_by"], ["registry_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["publisher_id"], ["publishers.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("token_id"),
    )


def downgrade() -> None:
    op.drop_table("publisher_tokens")
    op.drop_table("publisher_memberships")
    op.drop_table("registry_operators")
    op.drop_table("principal_audit")
    op.drop_table("publishers")
    op.drop_table("registry_users")
