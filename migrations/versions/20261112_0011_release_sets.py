"""Group scanned candidates for all-or-none database activation."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20261112_0011"
down_revision: str | None = "20261111_0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "release_sets",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("publisher_id", sa.String(64), nullable=False),
        sa.Column("binding_digest", sa.String(64), nullable=False),
        sa.Column("members", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("status_reason", sa.Text(), nullable=True),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["publisher_id"], ["publishers.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            "status IN ('queued', 'accepted', 'rejected', 'expired')",
            name="ck_release_sets_status",
        ),
    )
    op.create_index("ix_release_sets_replay", "release_sets", ["publisher_id", "binding_digest"])
    op.add_column("release_candidates", sa.Column("set_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        "fk_release_candidates_set",
        "release_candidates",
        "release_sets",
        ["set_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.execute(
        "CREATE TRIGGER release_candidate_set_is_immutable "
        "BEFORE UPDATE OF set_id ON release_candidates FOR EACH ROW "
        "WHEN (NEW.set_id IS DISTINCT FROM OLD.set_id) "
        "EXECUTE FUNCTION reject_immutable_catalog_update()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER release_candidate_set_is_immutable ON release_candidates")
    op.drop_constraint("fk_release_candidates_set", "release_candidates", type_="foreignkey")
    op.drop_column("release_candidates", "set_id")
    op.drop_table("release_sets")
