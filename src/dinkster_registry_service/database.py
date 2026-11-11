from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    Uuid,
    create_engine,
    event,
    inspect,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

JSON_STORAGE = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    pass


class RegistryUserRecord(Base):
    __tablename__ = "registry_users"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)


class RegistryOperatorRecord(Base):
    __tablename__ = "registry_operators"

    user_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("registry_users.id", ondelete="CASCADE"), primary_key=True
    )


class PublisherRecord(Base):
    __tablename__ = "publishers"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(200))


class PublisherMembershipRecord(Base):
    __tablename__ = "publisher_memberships"
    __table_args__ = (
        CheckConstraint("role IN ('owner', 'member')", name="ck_publisher_memberships_role"),
    )

    publisher_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("publishers.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("registry_users.id", ondelete="RESTRICT"), primary_key=True
    )
    role: Mapped[str] = mapped_column(String(16))


class PublisherTokenRecord(Base):
    __tablename__ = "publisher_tokens"

    token_id: Mapped[str] = mapped_column(String(12), primary_key=True)
    publisher_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("publishers.id", ondelete="CASCADE")
    )
    minted_by: Mapped[str] = mapped_column(
        String(128), ForeignKey("registry_users.id", ondelete="RESTRICT")
    )
    pack_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    secret_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[str] = mapped_column(String(64))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked_reason: Mapped[str] = mapped_column(Text, default="")


class PublisherFreezeRecord(Base):
    __tablename__ = "publisher_freezes"

    publisher_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("publishers.id", ondelete="RESTRICT"), primary_key=True
    )
    actor: Mapped[str] = mapped_column(String(128))
    at: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(Text)


class PublisherBindingRecord(Base):
    __tablename__ = "publisher_bindings"

    publisher_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("publishers.id", ondelete="RESTRICT"), primary_key=True
    )
    identity_subject: Mapped[str] = mapped_column(String(128), unique=True)


class PrincipalAuditRecord(Base):
    __tablename__ = "principal_audit"

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))
    subject: Mapped[str] = mapped_column(String(128))
    at: Mapped[str] = mapped_column(String(64))
    details: Mapped[str] = mapped_column(Text, default="")


class PackRecord(Base):
    __tablename__ = "packs"
    __table_args__ = (
        CheckConstraint("name ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$'", name="ck_packs_name").ddl_if(
            dialect="postgresql"
        ),
        CheckConstraint("owner_type IN ('user', 'org')", name="ck_packs_owner_type"),
        CheckConstraint("visibility = 'public'", name="ck_packs_public_only"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    publisher_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("publishers.id", ondelete="RESTRICT"), nullable=True
    )
    display_name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(String(500))
    long_description: Mapped[str] = mapped_column(Text)
    owner_type: Mapped[str] = mapped_column(String(8))
    owner_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))
    owner_slug: Mapped[str] = mapped_column(String(64))
    owner_display_name: Mapped[str] = mapped_column(String(200))
    visibility: Mapped[str] = mapped_column(String(16))
    homepage: Mapped[str | None] = mapped_column(Text, nullable=True)
    repository: Mapped[str | None] = mapped_column(Text, nullable=True)
    support: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSON_STORAGE)
    latest_version: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    download_count: Mapped[int] = mapped_column(BigInteger)
    pack_notice: Mapped[dict[str, Any] | None] = mapped_column(JSON_STORAGE, nullable=True)


class NamespaceGrantRecord(Base):
    __tablename__ = "namespace_grants"

    claim: Mapped[str] = mapped_column(String(64), primary_key=True)
    pack_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("packs.id", ondelete="CASCADE")
    )
    publisher_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("publishers.id", ondelete="RESTRICT"), nullable=True
    )
    owner_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True))


class ArtifactRecord(Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        CheckConstraint(
            "digest ~ '^blake3:[0-9a-f]{64}$'", name="ck_artifacts_blake3_digest"
        ).ddl_if(dialect="postgresql"),
        CheckConstraint(
            "manifest_digest ~ '^blake3:[0-9a-f]{64}$'",
            name="ck_artifacts_blake3_manifest_digest",
        ).ddl_if(dialect="postgresql"),
        CheckConstraint("size BETWEEN 1 AND 67108864", name="ck_artifacts_size"),
    )

    digest: Mapped[str] = mapped_column(String(71), primary_key=True)
    size: Mapped[int] = mapped_column(BigInteger)
    media_type: Mapped[str] = mapped_column(String(64))
    manifest_digest: Mapped[str] = mapped_column(String(71))
    object_key: Mapped[str] = mapped_column(Text, unique=True)


class ReleaseRecord(Base):
    __tablename__ = "releases"
    __table_args__ = (
        CheckConstraint(
            "state IN ('pending_scan', 'pending_review', 'active', 'yanked', "
            "'quarantined', 'blocked', 'rejected')",
            name="ck_releases_state",
        ),
        UniqueConstraint("pack_id", "version", name="uq_releases_pack_version"),
        UniqueConstraint("pack_id", "version_key", name="uq_releases_pack_canonical_version"),
        Index("ix_releases_pack_id", "pack_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    pack_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("packs.id", ondelete="RESTRICT")
    )
    version: Mapped[str] = mapped_column(String(128))
    version_key: Mapped[str] = mapped_column(String(128))
    state: Mapped[str] = mapped_column(String(24))
    state_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    state_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    published_by_kind: Mapped[str] = mapped_column(String(32))
    published_by_principal_id: Mapped[str] = mapped_column(String(128))
    artifact_digest: Mapped[str] = mapped_column(
        String(71), ForeignKey("artifacts.digest", ondelete="RESTRICT")
    )
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON_STORAGE)
    install_locks: Mapped[dict[str, Any]] = mapped_column(JSON_STORAGE, default=dict)
    next_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ReleaseNodeRecord(Base):
    __tablename__ = "release_nodes"
    __table_args__ = (
        CheckConstraint("role IN ('executing', 'schema-only')", name="ck_release_nodes_role"),
        CheckConstraint("schema_version >= 1", name="ck_release_nodes_schema_version"),
        CheckConstraint("schema_wire_version >= 1", name="ck_release_nodes_schema_wire_version"),
        Index("ix_release_nodes_node_type", "node_type"),
    )

    release_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("releases.id", ondelete="CASCADE"),
        primary_key=True,
    )
    node_type: Mapped[str] = mapped_column(String(512), primary_key=True)
    schema_version: Mapped[int] = mapped_column(Integer, primary_key=True)
    schema_wire_version: Mapped[int] = mapped_column(Integer)
    schema_signature: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(16))
    schema: Mapped[dict[str, Any]] = mapped_column(JSON_STORAGE)


class ReleaseScanRunRecord(Base):
    __tablename__ = "release_scan_runs"
    __table_args__ = (
        CheckConstraint(
            "(release_id IS NOT NULL) <> (candidate_id IS NOT NULL)",
            name="ck_release_scan_runs_subject",
        ),
        CheckConstraint(
            "operator_details IS NULL OR candidate_id IS NOT NULL",
            name="ck_release_scan_runs_operator_details_candidate",
        ),
        Index("ix_release_scan_runs_release_created", "release_id", "created_at"),
        Index("ix_release_scan_runs_candidate_created", "candidate_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    release_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("releases.id", ondelete="CASCADE"),
        nullable=True,
    )
    candidate_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("release_candidates.id", ondelete="RESTRICT"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted: Mapped[bool] = mapped_column(Boolean)
    stage: Mapped[str] = mapped_column(String(32), default="catalog_seed")
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    policy_version: Mapped[str] = mapped_column(String(128), default="registry-scan/1")
    operator_details: Mapped[dict[str, Any] | None] = mapped_column(JSON_STORAGE, nullable=True)
    doctor: Mapped[dict[str, Any]] = mapped_column(JSON_STORAGE)
    scan: Mapped[dict[str, Any]] = mapped_column(JSON_STORAGE)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON_STORAGE)
    vulnerabilities: Mapped[dict[str, Any]] = mapped_column(JSON_STORAGE)


class ReleaseFindingRecord(Base):
    __tablename__ = "release_findings"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('info', 'warning', 'error', 'critical')",
            name="ck_release_findings_severity",
        ),
        CheckConstraint(
            "effect IN ('block', 'review', 'signal')",
            name="ck_release_findings_effect",
        ),
        Index("ix_release_findings_scan_run", "scan_run_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    scan_run_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("release_scan_runs.id", ondelete="CASCADE")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    code: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(16))
    effect: Mapped[str] = mapped_column(String(16), default="signal")
    message: Mapped[str] = mapped_column(Text)


class ReleaseCandidateRecord(Base):
    __tablename__ = "release_candidates"
    __table_args__ = (
        CheckConstraint("kind IN ('upload', 'rescan')", name="ck_release_candidates_kind"),
        CheckConstraint(
            "status IN ('queued', 'scanning', 'review', 'rejected', 'promoting', 'accepted')",
            name="ck_release_candidates_status",
        ),
        CheckConstraint(
            "declared_digest ~ '^blake3:[0-9a-f]{64}$'",
            name="ck_release_candidates_blake3_digest",
        ).ddl_if(dialect="postgresql"),
        CheckConstraint(
            "declared_size BETWEEN 1 AND 67108864",
            name="ck_release_candidates_size",
        ),
        Index("ix_release_candidates_claim", "status", "lease_expires_at", "submitted_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))
    release_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("releases.id", ondelete="RESTRICT"),
        nullable=True,
    )
    publisher_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("publishers.id", ondelete="RESTRICT"), nullable=True
    )
    pack_name: Mapped[str] = mapped_column(String(64))
    version: Mapped[str] = mapped_column(String(128))
    version_key: Mapped[str] = mapped_column(String(128))
    declared_digest: Mapped[str] = mapped_column(String(71))
    declared_size: Mapped[int] = mapped_column(BigInteger)
    object_key: Mapped[str] = mapped_column(Text)
    install_locks: Mapped[dict[str, Any]] = mapped_column(JSON_STORAGE, default=dict)
    status: Mapped[str] = mapped_column(String(16))
    status_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    submitted_by: Mapped[str] = mapped_column(String(128))
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_token: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    lease_version: Mapped[int] = mapped_column(Integer, default=0)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    manifest: Mapped[dict[str, Any] | None] = mapped_column(JSON_STORAGE, nullable=True)
    schemas: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON_STORAGE, nullable=True)
    doctor: Mapped[dict[str, Any] | None] = mapped_column(JSON_STORAGE, nullable=True)
    scan: Mapped[dict[str, Any] | None] = mapped_column(JSON_STORAGE, nullable=True)


class ReleaseDependencyRecord(Base):
    __tablename__ = "release_dependencies"

    release_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("releases.id", ondelete="CASCADE"),
        primary_key=True,
    )
    pack_name: Mapped[str] = mapped_column(String(64), primary_key=True)
    version_range: Mapped[str] = mapped_column(String(256))


class AuditEventRecord(Base):
    __tablename__ = "audit_events"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_type: Mapped[str] = mapped_column(String(128))
    subject_type: Mapped[str] = mapped_column(String(64))
    subject_id: Mapped[str] = mapped_column(String(128))
    data: Mapped[dict[str, Any]] = mapped_column(JSON_STORAGE)


@event.listens_for(AuditEventRecord.__table__, "after_create")
def _protect_security_audit(_table: Table, connection: Connection, **_kwargs: Any) -> None:
    if connection.dialect.name != "sqlite":
        return
    for operation in ("UPDATE", "DELETE"):
        connection.exec_driver_sql(
            f"CREATE TRIGGER security_audit_{operation.lower()} "
            f"BEFORE {operation} ON audit_events FOR EACH ROW "
            "WHEN OLD.event_type LIKE 'security.%' "
            "BEGIN SELECT RAISE(ABORT, 'security audit records are immutable'); END"
        )


class OutboxRecord(Base):
    __tablename__ = "outbox"
    __table_args__ = (
        CheckConstraint("state IN ('pending', 'delivered')", name="ck_outbox_state"),
        Index("ix_outbox_pending", "state", "available_at", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    topic: Mapped[str] = mapped_column(String(128))
    event_key: Mapped[str] = mapped_column(String(128), unique=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON_STORAGE)
    state: Mapped[str] = mapped_column(String(16))
    attempts: Mapped[int] = mapped_column(Integer)


class ReleaseAttestationRecord(Base):
    __tablename__ = "release_attestations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('verified', 'missing', 'invalid')",
            name="ck_release_attestations_status",
        ),
        Index("ix_release_attestations_release_created", "release_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    release_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("releases.id", ondelete="CASCADE")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16))
    statement_url: Mapped[str | None] = mapped_column(Text, nullable=True)


class ReleaseCloudEvaluationRecord(Base):
    __tablename__ = "release_cloud_evaluations"
    __table_args__ = (
        Index("ix_release_cloud_evaluations_release_created", "release_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    release_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("releases.id", ondelete="CASCADE")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    registry_eligible: Mapped[bool] = mapped_column(Boolean)
    reason_codes: Mapped[list[str]] = mapped_column(JSON_STORAGE)
    policy_version: Mapped[str] = mapped_column(String(128))


class DatabaseConfigurationError(ValueError):
    """The service was configured with an unsupported database."""


def _enable_sqlite_foreign_keys(dbapi_connection: Any, connection_record: Any) -> None:
    del connection_record
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


def create_database_engine(database_url: str) -> Engine:
    engine = create_engine(database_url, pool_pre_ping=True)
    if engine.dialect.name not in {"postgresql", "sqlite"}:
        engine.dispose()
        raise DatabaseConfigurationError("DINKSTER_DATABASE_URL must select PostgreSQL or SQLite")
    if engine.dialect.name == "sqlite":
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    return engine


class Database:
    def __init__(self, database_url: str) -> None:
        self.engine = create_database_engine(database_url)
        if self.engine.dialect.name == "sqlite":
            Base.metadata.create_all(self.engine)
            with self.engine.begin() as connection:
                connection.exec_driver_sql("BEGIN IMMEDIATE")
                for table in ("release_candidates", "releases"):
                    columns = {column["name"] for column in inspect(connection).get_columns(table)}
                    if "install_locks" not in columns:
                        connection.exec_driver_sql(
                            f"ALTER TABLE {table} ADD COLUMN install_locks JSON NOT NULL "
                            "DEFAULT '{}'"
                        )
                for operation in ("UPDATE", "DELETE"):
                    connection.exec_driver_sql(
                        f"CREATE TRIGGER IF NOT EXISTS ownership_audit_no_{operation.lower()} "
                        f"BEFORE {operation} ON audit_events "
                        "WHEN OLD.event_type = 'ownership.transferred' "
                        "BEGIN SELECT RAISE(ABORT, 'ownership audit is append-only'); END"
                    )
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    @property
    def is_postgresql(self) -> bool:
        return self.engine.dialect.name == "postgresql"

    @contextmanager
    def session(self) -> Iterator[Session]:
        with self._sessions() as session:
            yield session

    def dispose(self) -> None:
        self.engine.dispose()


def default_object_root() -> Path:
    return Path(".data/objects")
