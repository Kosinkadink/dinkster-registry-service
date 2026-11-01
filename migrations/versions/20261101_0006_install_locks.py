"""Retain immutable per-base installation lock facts."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20261101_0006"
down_revision: str | None = "20260921_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    for table in ("release_candidates", "releases"):
        op.add_column(
            table,
            sa.Column("install_locks", postgresql.JSONB(), nullable=False, server_default="{}"),
        )
        op.alter_column(table, "install_locks", server_default=None)
        op.execute(
            f"CREATE TRIGGER {table}_install_locks_are_immutable "
            f"BEFORE UPDATE OF install_locks ON {table} FOR EACH ROW "
            "WHEN (NEW.install_locks IS DISTINCT FROM OLD.install_locks) "
            "EXECUTE FUNCTION reject_immutable_catalog_update()"
        )


def downgrade() -> None:
    for table in ("releases", "release_candidates"):
        op.execute(f"DROP TRIGGER {table}_install_locks_are_immutable ON {table}")
        op.drop_column(table, "install_locks")
