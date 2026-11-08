from __future__ import annotations

import hashlib
import html
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from packaging.version import Version
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .database import ArtifactRecord, Database, OutboxRecord, PackRecord, ReleaseRecord
from .ids import uuid7
from .object_store import ObjectStore, ObjectStoreError
from .pack_locks import lock_object_key
from .repository import CatalogRepository


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
            .order_by(PackRecord.name, ReleaseRecord.version)
        ).all()
        packs = []
        locales = []
        translations = []
        schemas: dict[str, dict[str, object]] = {}
        variants = {
            "cpu",
            *(variant for _, release, _ in rows for variant in release.install_locks),
        }
        projects: dict[str, dict[str, list[str]]] = {
            variant: {pack.name: [] for pack, _, _ in rows} for variant in variants
        }
        for pack, release, artifact in rows:
            relative_schema_key = f"packs/{pack.name}/{release.version}/schemas.json"
            schema_key = f"static/{relative_schema_key}"
            if pack.visibility != "public" or release.state not in {"active", "yanked"}:
                self.object_store.remove(schema_key)
                continue
            body = (
                CatalogRepository.schema_response(session, pack, release)
                .model_dump_json(by_alias=True)
                .encode("utf-8")
            )
            self.object_store.put(schema_key, body)
            if release.state != "active":
                continue
            if pack.publisher_id == "dinkster":
                previous = schemas.get(pack.name)
                if previous is None or Version(release.version) > Version(str(previous["version"])):
                    schemas[pack.name] = {
                        "name": pack.name,
                        "publisher": pack.publisher_id,
                        "version": release.version,
                        "displayName": pack.display_name,
                        "platforms": release.manifest["platforms"],
                        "url": relative_schema_key,
                        "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
                    }
            wheel = release.manifest.get("wheel")
            if wheel is None:
                continue
            wheel_key = f"wheels/{wheel['sha256']}/{wheel['filename']}"
            data = self.object_store.read(artifact.object_key)
            if hashlib.sha256(data).hexdigest() != wheel["sha256"]:
                raise ObjectStoreError("Admitted wheel does not match its SHA-256.")
            self.object_store.put(f"static/{wheel_key}", data)
            link = f"../../../{wheel_key}#sha256={wheel['sha256']}"
            wheel_variants = (
                variants if wheel["tags"] == ["py3-none-any"] else release.install_locks
            )
            for variant in wheel_variants:
                projects[variant][pack.name].append(
                    f'<a href="{html.escape(link, quote=True)}">'
                    f"{html.escape(wheel['filename'])}</a>"
                )
            locks = {}
            for variant, lock in release.install_locks.items():
                lock_key = f"locks/{lock['digest'].replace(':', '/')}.json"
                self.object_store.put(
                    f"static/{lock_key}", self.object_store.read(lock_object_key(lock["digest"]))
                )
                locks[variant] = {**lock, "url": lock_key}
            entry = {
                "name": pack.name,
                "version": release.version,
                "digest": artifact.digest,
                "size": artifact.size,
                "url": wheel_key,
                "filename": wheel["filename"],
                "sha256": wheel["sha256"],
                "library": wheel["library"],
                "installLocks": locks,
                "requires": release.manifest.get("pythonRequirements", []),
            }
            packs.append(entry)
            locales.append({**entry, "catalogs": release.manifest.get("localeCatalogs", [])})
            if pack.publisher_id == "dinkster":
                translations.extend(release.manifest.get("translations", []))
        for variant in sorted(variants):
            root_links = []
            for name, links in sorted(projects[variant].items()):
                body = (
                    "<!doctype html>\n<html><body>\n"
                    + "\n".join(sorted(links))
                    + "\n</body></html>\n"
                ).encode("ascii")
                self.object_store.replace_index(f"static/{variant}/simple/{name}/index.html", body)
                if links:
                    root_links.append(f'<a href="{name}/">{name}</a>')
            root = (
                "<!doctype html>\n<html><body>\n" + "\n".join(root_links) + "\n</body></html>\n"
            ).encode("ascii")
            self.object_store.replace_index(f"static/{variant}/simple/index.html", root)
        for key, items in (
            ("packs/index.json", packs),
            ("locales/index.json", locales),
            ("schemas/index.json", list(schemas.values())),
            ("translations/index.json", translations),
        ):
            data = json.dumps(
                {"schemaVersion": 1, "items": items},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            self.object_store.replace_index(f"static/{key}", data)
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
