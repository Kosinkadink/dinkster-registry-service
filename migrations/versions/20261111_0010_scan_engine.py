"""Keep the exact engine used for admission attached to candidates and releases."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20261111_0010"
down_revision: str | None = "20261111_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    for table in ("release_candidates", "releases"):
        op.add_column(table, sa.Column("scan_engine", postgresql.JSONB(), nullable=True))
        op.execute(
            f"CREATE TRIGGER {table}_scan_engine_is_immutable "
            f"BEFORE UPDATE OF scan_engine ON {table} FOR EACH ROW "
            "WHEN (NEW.scan_engine IS DISTINCT FROM OLD.scan_engine) "
            "EXECUTE FUNCTION reject_immutable_catalog_update()"
        )


def downgrade() -> None:
    for table in ("releases", "release_candidates"):
        op.execute(f"DROP TRIGGER {table}_scan_engine_is_immutable ON {table}")
        op.drop_column(table, "scan_engine")
