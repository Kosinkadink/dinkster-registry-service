"""Add quarantine release admission records.

Revision ID: 20260903_0002
Revises: 20260902_0001
Create Date: 2026-09-03 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260903_0002"
down_revision: str | None = "20260902_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("releases", sa.Column("next_scan_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        "release_candidates",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("release_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("pack_name", sa.String(length=64), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=False),
        sa.Column("version_key", sa.String(length=128), nullable=False),
        sa.Column("declared_digest", sa.String(length=71), nullable=False),
        sa.Column("declared_size", sa.BigInteger(), nullable=False),
        sa.Column("object_key", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("status_reason", sa.Text(), nullable=True),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("submitted_by", sa.String(length=128), nullable=False),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_token", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("lease_version", sa.Integer(), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("manifest", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("schemas", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("doctor", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("scan", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.CheckConstraint("kind IN ('upload', 'rescan')", name="ck_release_candidates_kind"),
        sa.CheckConstraint(
            "status IN ('queued', 'scanning', 'review', 'rejected', 'promoting', 'accepted')",
            name="ck_release_candidates_status",
        ),
        sa.CheckConstraint(
            "declared_digest ~ '^blake3:[0-9a-f]{64}$'",
            name="ck_release_candidates_blake3_digest",
        ),
        sa.CheckConstraint(
            "declared_size BETWEEN 1 AND 67108864",
            name="ck_release_candidates_size",
        ),
        sa.ForeignKeyConstraint(["release_id"], ["releases.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_release_candidates_claim",
        "release_candidates",
        ["status", "lease_expires_at", "submitted_at"],
        unique=False,
    )

    op.alter_column("release_scan_runs", "release_id", nullable=True)
    op.add_column(
        "release_scan_runs",
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "release_scan_runs",
        sa.Column("stage", sa.String(length=32), nullable=False, server_default="catalog_seed"),
    )
    op.add_column(
        "release_scan_runs",
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="1"),
    )
    op.add_column(
        "release_scan_runs",
        sa.Column(
            "policy_version",
            sa.String(length=128),
            nullable=False,
            server_default="registry-scan/1",
        ),
    )
    op.create_foreign_key(
        "fk_release_scan_runs_candidate_id",
        "release_scan_runs",
        "release_candidates",
        ["candidate_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        "ck_release_scan_runs_subject",
        "release_scan_runs",
        "(release_id IS NOT NULL) <> (candidate_id IS NOT NULL)",
    )
    op.create_index(
        "ix_release_scan_runs_candidate_created",
        "release_scan_runs",
        ["candidate_id", "created_at"],
        unique=False,
    )
    op.add_column(
        "release_findings",
        sa.Column("effect", sa.String(length=16), nullable=False, server_default="signal"),
    )
    op.create_check_constraint(
        "ck_release_findings_effect",
        "release_findings",
        "effect IN ('block', 'review', 'signal')",
    )

    op.create_table(
        "release_dependencies",
        sa.Column("release_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("pack_name", sa.String(length=64), nullable=False),
        sa.Column("version_range", sa.String(length=256), nullable=False),
        sa.ForeignKeyConstraint(["release_id"], ["releases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("release_id", "pack_name"),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("subject_type", sa.String(length=64), nullable=False),
        sa.Column("subject_id", sa.String(length=128), nullable=False),
        sa.Column("data", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "outbox",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("topic", sa.String(length=128), nullable=False),
        sa.Column("event_key", sa.String(length=128), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.CheckConstraint("state IN ('pending', 'delivered')", name="ck_outbox_state"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_key"),
    )
    op.create_index(
        "ix_outbox_pending", "outbox", ["state", "available_at", "created_at"], unique=False
    )

    op.execute(
        """
        CREATE FUNCTION protect_release_candidate_facts() RETURNS trigger AS $$
        BEGIN
            IF NEW.kind IS DISTINCT FROM OLD.kind
               OR (OLD.release_id IS NOT NULL AND NEW.release_id IS DISTINCT FROM OLD.release_id)
               OR NEW.pack_name IS DISTINCT FROM OLD.pack_name
               OR NEW.version IS DISTINCT FROM OLD.version
               OR NEW.version_key IS DISTINCT FROM OLD.version_key
               OR NEW.declared_digest IS DISTINCT FROM OLD.declared_digest
               OR NEW.declared_size IS DISTINCT FROM OLD.declared_size
               OR NEW.object_key IS DISTINCT FROM OLD.object_key
               OR NEW.submitted_at IS DISTINCT FROM OLD.submitted_at
               OR NEW.submitted_by IS DISTINCT FROM OLD.submitted_by THEN
                RAISE EXCEPTION 'immutable release candidate facts cannot be updated';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER release_candidate_facts_are_immutable
        BEFORE UPDATE ON release_candidates
        FOR EACH ROW EXECUTE FUNCTION protect_release_candidate_facts()
        """
    )
    op.execute(
        """
        CREATE TRIGGER release_candidates_cannot_be_deleted
        BEFORE DELETE ON release_candidates
        FOR EACH ROW EXECUTE FUNCTION reject_immutable_catalog_update()
        """
    )
    for table in ("release_dependencies", "audit_events"):
        op.execute(
            f"""
            CREATE TRIGGER {table}_are_append_only
            BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION reject_immutable_catalog_update()
            """
        )
    for table in ("release_candidates", "release_dependencies", "audit_events", "outbox"):
        op.execute(
            f"""
            CREATE TRIGGER {table}_cannot_be_truncated
            BEFORE TRUNCATE ON {table}
            FOR EACH STATEMENT EXECUTE FUNCTION reject_immutable_catalog_update()
            """
        )


def downgrade() -> None:
    op.drop_table("outbox")
    op.drop_table("audit_events")
    op.drop_table("release_dependencies")
    op.execute("DROP TRIGGER release_findings_are_append_only ON release_findings")
    op.execute("DROP TRIGGER release_scan_runs_are_append_only ON release_scan_runs")
    op.execute(
        "DELETE FROM release_findings WHERE scan_run_id IN "
        "(SELECT id FROM release_scan_runs WHERE candidate_id IS NOT NULL)"
    )
    op.execute("DELETE FROM release_scan_runs WHERE candidate_id IS NOT NULL")
    for table in ("release_scan_runs", "release_findings"):
        op.execute(
            f"""
            CREATE TRIGGER {table}_are_append_only
            BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION reject_immutable_catalog_update()
            """
        )
    op.drop_index("ix_release_scan_runs_candidate_created", table_name="release_scan_runs")
    op.drop_constraint("ck_release_scan_runs_subject", "release_scan_runs", type_="check")
    op.drop_constraint("fk_release_scan_runs_candidate_id", "release_scan_runs", type_="foreignkey")
    op.drop_column("release_scan_runs", "policy_version")
    op.drop_column("release_scan_runs", "attempt")
    op.drop_column("release_scan_runs", "stage")
    op.drop_column("release_scan_runs", "candidate_id")
    op.alter_column("release_scan_runs", "release_id", nullable=False)
    op.drop_constraint("ck_release_findings_effect", "release_findings", type_="check")
    op.drop_column("release_findings", "effect")
    op.drop_table("release_candidates")
    op.drop_column("releases", "next_scan_at")
    op.execute("DROP FUNCTION protect_release_candidate_facts()")
