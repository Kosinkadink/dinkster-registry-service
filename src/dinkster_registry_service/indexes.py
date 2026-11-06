from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .database import ArtifactRecord, Database, OutboxRecord, PackRecord, ReleaseRecord
from .ids import uuid7
from .object_store import ObjectStore, ObjectStoreError


def queue_index_rebuild(session: Session) -> None:
    event_id = uuid7()
    now = datetime.now(UTC)
    session.add(
        OutboxRecord(
            id=event_id,
            created_at=now,
            available_at=now,
            delivered_at=None,
            topic="indexes.rebuild",
            event_key=f"indexes:{event_id}",
            payload={},
            state="pending",
            attempts=0,
        )
    )


class StaticIndexes:
    def __init__(self, database: Database, object_store: ObjectStore, public_base_url: str) -> None:
        self.database = database
        self.object_store = object_store
        self.public_base_url = public_base_url.rstrip("/")

    @contextmanager
    def _locked_session(self) -> Iterator[Session]:
        with self.database.session() as session, session.begin():
            # Lock before reading the catalog, not just while writing objects:
            # a slower replica must never replace a newer snapshot with an older one.
            if self.database.is_postgresql:
                session.execute(
                    text("SELECT pg_advisory_xact_lock(hashtext('dinkster-registry-indexes'), 0)")
                )
            else:
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            yield session

    def _write(self, session: Session) -> int:
        rows = session.execute(
            select(PackRecord, ReleaseRecord, ArtifactRecord)
            .join(ReleaseRecord, ReleaseRecord.pack_id == PackRecord.id)
            .join(ArtifactRecord, ArtifactRecord.digest == ReleaseRecord.artifact_digest)
            .where(PackRecord.visibility == "public", ReleaseRecord.state == "active")
            .order_by(PackRecord.name, ReleaseRecord.version)
        ).all()
        packs = []
        locales = []
        for pack, release, artifact in rows:
            entry = {
                "name": pack.name,
                "version": release.version,
                "digest": artifact.digest,
                "size": artifact.size,
                "url": f"{self.public_base_url}/v1/artifacts/{artifact.digest}",
            }
            packs.append(entry)
            locales.append({**entry, "catalogs": release.manifest.get("localeCatalogs", [])})
        for key, items in (("packs/index.json", packs), ("locales/index.json", locales)):
            data = json.dumps(
                {"schemaVersion": 1, "items": items},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            self.object_store.replace_index(key, data)
        return len(packs)

    def rebuild(self) -> int:
        with self._locked_session() as session:
            return self._write(session)

    def deliver_one(self) -> bool:
        with self._locked_session() as session:
            event = session.scalar(
                select(OutboxRecord)
                .where(
                    OutboxRecord.topic == "indexes.rebuild",
                    OutboxRecord.state == "pending",
                    OutboxRecord.available_at <= datetime.now(UTC),
                )
                .order_by(OutboxRecord.created_at, OutboxRecord.id)
                .with_for_update()
                .limit(1)
            )
            if event is None:
                return False
            event.attempts += 1
            try:
                self._write(session)
            except ObjectStoreError:
                event.available_at = datetime.now(UTC) + timedelta(seconds=5)
            else:
                event.state = "delivered"
                event.delivered_at = datetime.now(UTC)
            return True
