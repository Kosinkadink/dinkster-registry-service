from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.sql import Executable

from dinkster_registry_service.database import (
    ArtifactRecord,
    Database,
    NamespaceGrantRecord,
    PackRecord,
    ReleaseAttestationRecord,
    ReleaseCloudEvaluationRecord,
    ReleaseFindingRecord,
    ReleaseNodeRecord,
    ReleaseRecord,
    ReleaseScanRunRecord,
)
from dinkster_registry_service.object_store import LocalFilesystemObjectStore
from dinkster_registry_service.seed import seed_fixtures


def test_migration_round_trip_matches_sqlalchemy_metadata(
    database: Database, database_url: str
) -> None:
    del database
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    command.check(config)


def test_migration_and_fixture_seed_are_durable_and_idempotent(
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore],
) -> None:
    database, object_store = seeded_catalog
    with database.session() as session:
        assert session.scalar(select(func.count()).select_from(PackRecord)) == 2
        assert session.scalar(select(func.count()).select_from(NamespaceGrantRecord)) == 4
        assert session.scalar(select(func.count()).select_from(ArtifactRecord)) == 2
        assert session.scalar(select(func.count()).select_from(ReleaseRecord)) == 2
        assert session.scalar(select(func.count()).select_from(ReleaseNodeRecord)) == 3
        assert session.scalar(select(func.count()).select_from(ReleaseScanRunRecord)) == 2
        assert session.scalar(select(func.count()).select_from(ReleaseAttestationRecord)) == 2
        assert session.scalar(select(func.count()).select_from(ReleaseCloudEvaluationRecord)) == 2
        assert session.scalar(select(func.count()).select_from(ReleaseFindingRecord)) == 0
        artifacts = session.scalars(select(ArtifactRecord)).all()
        assert all(object_store.exists(artifact.object_key) for artifact in artifacts)

    result = seed_fixtures(database, object_store)
    assert result.packs_created == 0
    assert result.releases_created == 0
    assert result.artifacts_created == 0


def _assert_database_rejects(database: Database, statement: Executable, match: str) -> None:
    with database.session() as session, pytest.raises(SQLAlchemyError, match=match):
        with session.begin():
            session.execute(statement)


def test_accepted_catalog_facts_cannot_be_rewritten_or_erased(
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore],
) -> None:
    database, _ = seeded_catalog
    _assert_database_rejects(
        database, update(ReleaseRecord).values(version="9.9.9"), "immutable release facts"
    )
    immutable_operations = (
        update(ArtifactRecord).values(size=1),
        delete(ArtifactRecord),
        update(ReleaseRecord).values(install_locks={"linux-cpu": {"digest": "rewritten"}}),
        update(ReleaseRecord).values(
            scan_engine={"commit": "a" * 40, "manifestDigest": "sha256:" + "b" * 64}
        ),
        update(ReleaseNodeRecord).values(role="schema-only"),
        delete(ReleaseNodeRecord),
        delete(ReleaseRecord),
    )
    for statement in immutable_operations:
        _assert_database_rejects(database, statement, "immutable catalog facts")
    _assert_database_rejects(
        database,
        delete(PackRecord).where(PackRecord.name == "example-pack"),
        "packs with releases cannot be deleted",
    )
    protected_tables = (
        "packs",
        "namespace_grants",
        "artifacts",
        "releases",
        "release_nodes",
        "release_scan_runs",
        "release_findings",
        "release_attestations",
        "release_cloud_evaluations",
        "release_candidates",
        "release_dependencies",
        "audit_events",
        "outbox",
    )
    with database.session() as session:
        trigger_names = set(
            session.scalars(
                text(
                    "SELECT tgname FROM pg_trigger "
                    "WHERE NOT tgisinternal AND tgname LIKE '%_cannot_be_truncated'"
                )
            )
        )
    assert trigger_names == {f"{table}_cannot_be_truncated" for table in protected_tables}
    for table in protected_tables:
        _assert_database_rejects(
            database,
            text(f"TRUNCATE {table}"),
            "immutable catalog facts|cannot truncate a table referenced",
        )
        _assert_database_rejects(
            database, text(f"TRUNCATE {table} CASCADE"), "immutable catalog facts"
        )


def test_release_evidence_tables_are_append_only(
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore],
) -> None:
    database, _ = seeded_catalog
    with database.session() as session, session.begin():
        scan_run = session.scalar(select(ReleaseScanRunRecord).limit(1))
        assert scan_run is not None
        session.add(
            ReleaseFindingRecord(
                id=UUID("01990000-0000-7000-8000-000000000062"),
                scan_run_id=scan_run.id,
                created_at=scan_run.created_at,
                code="append-only-test",
                severity="info",
                message="Fixture evidence.",
            )
        )

    evidence_operations = (
        update(ReleaseScanRunRecord).values(accepted=False),
        delete(ReleaseScanRunRecord),
        update(ReleaseFindingRecord).values(message="rewritten"),
        delete(ReleaseFindingRecord),
        update(ReleaseAttestationRecord).values(status="invalid"),
        delete(ReleaseAttestationRecord),
        update(ReleaseCloudEvaluationRecord).values(policy_version="rewritten"),
        delete(ReleaseCloudEvaluationRecord),
    )
    for statement in evidence_operations:
        _assert_database_rejects(database, statement, "immutable catalog facts")


def test_artifact_size_and_canonical_version_collisions_are_database_enforced(
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore],
) -> None:
    database, _ = seeded_catalog
    oversized = ArtifactRecord(
        digest="blake3:" + "1" * 64,
        size=64 * 1024 * 1024 + 1,
        media_type="application/vnd.dinkster.pack+zip",
        manifest_digest="blake3:" + "2" * 64,
        object_key="artifacts/blake3/11/" + "1" * 64 + ".dinksterpack.zip",
    )
    with database.session() as session, pytest.raises(IntegrityError, match="ck_artifacts_size"):
        with session.begin():
            session.add(oversized)

    with database.session() as session:
        existing = session.scalar(select(ReleaseRecord).where(ReleaseRecord.version == "1.2.3"))
        assert existing is not None
        duplicate_values: dict[str, Any] = {
            "id": UUID("01990000-0000-7000-8000-000000000063"),
            "pack_id": existing.pack_id,
            "version": "1.2.3.0",
            "version_key": existing.version_key,
            "state": "active",
            "state_reason": None,
            "state_changed_at": existing.state_changed_at,
            "published_at": existing.published_at,
            "published_by_kind": existing.published_by_kind,
            "published_by_principal_id": existing.published_by_principal_id,
            "artifact_digest": existing.artifact_digest,
            "manifest": dict(existing.manifest),
        }
    with (
        database.session() as session,
        pytest.raises(IntegrityError, match="uq_releases_pack_canonical_version"),
    ):
        with session.begin():
            session.add(ReleaseRecord(**duplicate_values))
