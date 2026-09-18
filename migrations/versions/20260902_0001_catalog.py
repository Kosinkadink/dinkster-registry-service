"""Create the read-only catalog schema.

Revision ID: 20260902_0001
Revises:
Create Date: 2026-09-02 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260902_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "packs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=False),
        sa.Column("long_description", sa.Text(), nullable=False),
        sa.Column("owner_type", sa.String(length=8), nullable=False),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("owner_slug", sa.String(length=64), nullable=False),
        sa.Column("owner_display_name", sa.String(length=200), nullable=False),
        sa.Column("visibility", sa.String(length=16), nullable=False),
        sa.Column("homepage", sa.Text(), nullable=True),
        sa.Column("repository", sa.Text(), nullable=True),
        sa.Column("support", sa.Text(), nullable=True),
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("latest_version", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("download_count", sa.BigInteger(), nullable=False),
        sa.Column("pack_notice", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.CheckConstraint("name ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$'", name="ck_packs_name"),
        sa.CheckConstraint("owner_type IN ('user', 'org')", name="ck_packs_owner_type"),
        sa.CheckConstraint("visibility = 'public'", name="ck_packs_public_only"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "namespace_grants",
        sa.Column("claim", sa.String(length=64), nullable=False),
        sa.Column("pack_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(["pack_id"], ["packs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("claim"),
    )
    op.create_table(
        "artifacts",
        sa.Column("digest", sa.String(length=71), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("media_type", sa.String(length=64), nullable=False),
        sa.Column("manifest_digest", sa.String(length=71), nullable=False),
        sa.Column("object_key", sa.Text(), nullable=False),
        sa.CheckConstraint("digest ~ '^blake3:[0-9a-f]{64}$'", name="ck_artifacts_blake3_digest"),
        sa.CheckConstraint(
            "manifest_digest ~ '^blake3:[0-9a-f]{64}$'",
            name="ck_artifacts_blake3_manifest_digest",
        ),
        sa.CheckConstraint("size BETWEEN 1 AND 67108864", name="ck_artifacts_size"),
        sa.PrimaryKeyConstraint("digest"),
        sa.UniqueConstraint("object_key"),
    )
    op.create_table(
        "releases",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("pack_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=False),
        sa.Column("version_key", sa.String(length=128), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("state_reason", sa.Text(), nullable=True),
        sa.Column("state_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_by_kind", sa.String(length=32), nullable=False),
        sa.Column("published_by_principal_id", sa.String(length=128), nullable=False),
        sa.Column("artifact_digest", sa.String(length=71), nullable=False),
        sa.Column("manifest", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint(
            "state IN ('pending_scan', 'pending_review', 'active', 'yanked', "
            "'quarantined', 'blocked', 'rejected')",
            name="ck_releases_state",
        ),
        sa.ForeignKeyConstraint(["artifact_digest"], ["artifacts.digest"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["pack_id"], ["packs.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("pack_id", "version", name="uq_releases_pack_version"),
        sa.UniqueConstraint("pack_id", "version_key", name="uq_releases_pack_canonical_version"),
    )
    op.create_index("ix_releases_pack_id", "releases", ["pack_id"], unique=False)
    op.create_table(
        "release_nodes",
        sa.Column("release_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("node_type", sa.String(length=512), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("schema_wire_version", sa.Integer(), nullable=False),
        sa.Column("schema_signature", sa.String(length=512), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("schema", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint("role IN ('executing', 'schema-only')", name="ck_release_nodes_role"),
        sa.CheckConstraint("schema_version >= 1", name="ck_release_nodes_schema_version"),
        sa.CheckConstraint("schema_wire_version >= 1", name="ck_release_nodes_schema_wire_version"),
        sa.ForeignKeyConstraint(["release_id"], ["releases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("release_id", "node_type", "schema_version"),
    )
    op.create_index("ix_release_nodes_node_type", "release_nodes", ["node_type"], unique=False)

    op.create_table(
        "release_scan_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("release_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted", sa.Boolean(), nullable=False),
        sa.Column("doctor", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("scan", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("provenance", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("vulnerabilities", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(["release_id"], ["releases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_release_scan_runs_release_created",
        "release_scan_runs",
        ["release_id", "created_at"],
        unique=False,
    )
    op.create_table(
        "release_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("code", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.CheckConstraint(
            "severity IN ('info', 'warning', 'error', 'critical')",
            name="ck_release_findings_severity",
        ),
        sa.ForeignKeyConstraint(["scan_run_id"], ["release_scan_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_release_findings_scan_run",
        "release_findings",
        ["scan_run_id", "created_at"],
        unique=False,
    )
    op.create_table(
        "release_attestations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("release_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("statement_url", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "status IN ('verified', 'missing', 'invalid')",
            name="ck_release_attestations_status",
        ),
        sa.ForeignKeyConstraint(["release_id"], ["releases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_release_attestations_release_created",
        "release_attestations",
        ["release_id", "created_at"],
        unique=False,
    )
    op.create_table(
        "release_cloud_evaluations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("release_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("registry_eligible", sa.Boolean(), nullable=False),
        sa.Column("reason_codes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("policy_version", sa.String(length=128), nullable=False),
        sa.ForeignKeyConstraint(["release_id"], ["releases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_release_cloud_evaluations_release_created",
        "release_cloud_evaluations",
        ["release_id", "created_at"],
        unique=False,
    )

    op.execute(
        """
        CREATE FUNCTION reject_immutable_catalog_update() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'immutable catalog facts cannot be changed';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    for table in (
        "packs",
        "namespace_grants",
        "artifacts",
        "releases",
        "release_nodes",
        "release_scan_runs",
        "release_findings",
        "release_attestations",
        "release_cloud_evaluations",
    ):
        op.execute(
            f"""
            CREATE TRIGGER {table}_cannot_be_truncated
            BEFORE TRUNCATE ON {table}
            FOR EACH STATEMENT EXECUTE FUNCTION reject_immutable_catalog_update()
            """
        )
    op.execute(
        """
        CREATE TRIGGER artifacts_are_immutable
        BEFORE UPDATE OR DELETE ON artifacts
        FOR EACH ROW EXECUTE FUNCTION reject_immutable_catalog_update()
        """
    )
    op.execute(
        """
        CREATE TRIGGER release_nodes_are_immutable
        BEFORE UPDATE OR DELETE ON release_nodes
        FOR EACH ROW EXECUTE FUNCTION reject_immutable_catalog_update()
        """
    )
    for table in (
        "release_scan_runs",
        "release_findings",
        "release_attestations",
        "release_cloud_evaluations",
    ):
        op.execute(
            f"""
            CREATE TRIGGER {table}_are_append_only
            BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION reject_immutable_catalog_update()
            """
        )
    op.execute(
        """
        CREATE FUNCTION protect_release_facts() RETURNS trigger AS $$
        BEGIN
            IF NEW.pack_id IS DISTINCT FROM OLD.pack_id
               OR NEW.version IS DISTINCT FROM OLD.version
               OR NEW.published_at IS DISTINCT FROM OLD.published_at
               OR NEW.published_by_kind IS DISTINCT FROM OLD.published_by_kind
               OR NEW.published_by_principal_id IS DISTINCT FROM OLD.published_by_principal_id
               OR NEW.artifact_digest IS DISTINCT FROM OLD.artifact_digest
               OR NEW.manifest IS DISTINCT FROM OLD.manifest
               OR NEW.version_key IS DISTINCT FROM OLD.version_key THEN
                RAISE EXCEPTION 'immutable release facts cannot be updated';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER release_facts_are_immutable
        BEFORE UPDATE ON releases
        FOR EACH ROW EXECUTE FUNCTION protect_release_facts()
        """
    )
    op.execute(
        """
        CREATE TRIGGER releases_cannot_be_deleted
        BEFORE DELETE ON releases
        FOR EACH ROW EXECUTE FUNCTION reject_immutable_catalog_update()
        """
    )
    op.execute(
        """
        CREATE FUNCTION protect_pack_delete() RETURNS trigger AS $$
        BEGIN
            IF EXISTS (SELECT 1 FROM releases WHERE pack_id = OLD.id) THEN
                RAISE EXCEPTION 'packs with releases cannot be deleted';
            END IF;
            RETURN OLD;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER packs_with_releases_cannot_be_deleted
        BEFORE DELETE ON packs
        FOR EACH ROW EXECUTE FUNCTION protect_pack_delete()
        """
    )


def downgrade() -> None:
    op.drop_table("release_cloud_evaluations")
    op.drop_table("release_attestations")
    op.drop_table("release_findings")
    op.drop_table("release_scan_runs")
    op.drop_table("release_nodes")
    op.drop_index("ix_releases_pack_id", table_name="releases")
    op.drop_table("releases")
    op.drop_table("artifacts")
    op.drop_table("namespace_grants")
    op.drop_table("packs")
    op.execute("DROP FUNCTION protect_pack_delete()")
    op.execute("DROP FUNCTION protect_release_facts()")
    op.execute("DROP FUNCTION reject_immutable_catalog_update()")
