"""Allow candidates waiting for another scan after a stage timeout."""

from collections.abc import Sequence

from alembic import op

revision: str = "20261111_0009"
down_revision: str | None = "20261110_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("ck_release_candidates_status", "release_candidates", type_="check")
    op.create_check_constraint(
        "ck_release_candidates_status",
        "release_candidates",
        "status IN ('queued', 'retrying', 'scanning', 'review', "
        "'rejected', 'promoting', 'accepted')",
    )


def downgrade() -> None:
    op.execute("UPDATE release_candidates SET status = 'queued' WHERE status = 'retrying'")
    op.drop_constraint("ck_release_candidates_status", "release_candidates", type_="check")
    op.create_check_constraint(
        "ck_release_candidates_status",
        "release_candidates",
        "status IN ('queued', 'scanning', 'review', 'rejected', 'promoting', 'accepted')",
    )
