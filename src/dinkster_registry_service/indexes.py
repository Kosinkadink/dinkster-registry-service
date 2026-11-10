from __future__ import annotations

import hashlib
import html
import json
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from functools import partial

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

    def _copy_object(self, source: str, destination: str, sha256: str | None = None) -> None:
        data = self.object_store.read(source)
        if sha256 is not None and hashlib.sha256(data).hexdigest() != sha256:
            raise ObjectStoreError("Admitted wheel does not match its SHA-256.")
        self.object_store.put(destination, data)

    @staticmethod
    def _write_parallel(writes: list[Callable[[], None]]) -> None:
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(write) for write in writes]
            for future in futures:
                future.result()

    def _write(self, session: Session) -> int:
        rows = session.execute(
            select(PackRecord, ReleaseRecord, ArtifactRecord)
            .join(ReleaseRecord, ReleaseRecord.pack_id == PackRecord.id)
            .join(ArtifactRecord, ArtifactRecord.digest == ReleaseRecord.artifact_digest)
            .order_by(PackRecord.name, ReleaseRecord.version)
        ).all()
        packs = []
        locales = []
        schemas: dict[str, dict[str, object]] = {}
        replacements_by_pack: dict[str, list[dict[str, object]]] = {}
        variants = {
            "cpu",
            *(variant for _, release, _ in rows for variant in release.install_locks),
        }
        projects: dict[str, dict[str, list[str]]] = {
            variant: {pack.name: [] for pack, _, _ in rows} for variant in variants
        }
        object_writes: list[Callable[[], None]] = []
        for pack, release, artifact in rows:
            relative_schema_key = f"packs/{pack.name}/{release.version}/schemas.json"
            schema_key = f"static/{relative_schema_key}"
            wheel = release.manifest.get("wheel")
            library = wheel is not None and wheel["library"]
            if pack.visibility != "public" or release.state not in {"active", "yanked"}:
                object_writes.append(partial(self.object_store.remove, schema_key))
                continue
            if library:
                object_writes.append(partial(self.object_store.remove, schema_key))
            else:
                body = (
                    CatalogRepository.schema_response(session, pack, release)
                    .model_dump_json(by_alias=True)
                    .encode("utf-8")
                )
                object_writes.append(partial(self.object_store.put, schema_key, body))
            if release.state != "active":
                continue
            if pack.publisher_id == "dinkster" and not library:
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
                    rules = [
                        (rule["from"], item["nodeType"], rule)
                        for item in json.loads(body)["schemas"]
                        for rule in item["schema"].get("replacements", [])
                    ]
                    replacements_by_pack[pack.name] = [
                        {
                            "from": source,
                            "pack": pack.name,
                            "version": release.version,
                            "target": target,
                            "rule": rule,
                        }
                        for source, target, rule in rules
                    ]
            if wheel is None:
                continue
            wheel_key = f"wheels/{wheel['sha256']}/{wheel['filename']}"
            object_writes.append(
                partial(
                    self._copy_object, artifact.object_key, f"static/{wheel_key}", wheel["sha256"]
                )
            )
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
                object_writes.append(
                    partial(
                        self._copy_object, lock_object_key(lock["digest"]), f"static/{lock_key}"
                    )
                )
                locks[variant] = {**lock, "url": lock_key}
            entry = {
                "name": pack.name,
                "version": release.version,
                "publisher": pack.publisher_id,
                "engine": None if wheel["library"] else release.manifest["dinkster"],
                "wheels": [
                    {
                        "digest": artifact.digest,
                        "size": artifact.size,
                        "url": wheel_key,
                        "filename": wheel["filename"],
                        "sha256": wheel["sha256"],
                        "tags": wheel["tags"],
                    }
                ],
                "library": wheel["library"],
                "installLocks": locks,
                "requires": release.manifest.get("pythonRequirements", []),
            }
            packs.append(entry)
            if not library:
                locales.append({**entry, "catalogs": release.manifest.get("localeCatalogs", [])})
        # Finish immutable objects before publishing any index that points at them.
        self._write_parallel(object_writes)
        project_writes: list[Callable[[], None]] = []
        root_writes: list[Callable[[], None]] = []
        for variant in sorted(variants):
            root_links = []
            for name, links in sorted(projects[variant].items()):
                body = (
                    "<!doctype html>\n<html><body>\n"
                    + "\n".join(sorted(links))
                    + "\n</body></html>\n"
                ).encode("ascii")
                project_writes.append(
                    partial(
                        self.object_store.replace_index,
                        f"static/{variant}/simple/{name}/index.html",
                        body,
                    )
                )
                if links:
                    root_links.append(f'<a href="{name}/">{name}</a>')
            root = (
                "<!doctype html>\n<html><body>\n" + "\n".join(root_links) + "\n</body></html>\n"
            ).encode("ascii")
            root_writes.append(
                partial(
                    self.object_store.replace_index, f"static/{variant}/simple/index.html", root
                )
            )
        self._write_parallel(project_writes)
        self._write_parallel(root_writes)
        replacements: dict[str, list[dict[str, object]]] = {}
        for entries in replacements_by_pack.values():
            for entry in entries:
                source = str(entry["from"])
                candidate = {key: value for key, value in entry.items() if key != "from"}
                choices = replacements.setdefault(source, [])
                if candidate not in choices:
                    choices.append(candidate)
        for key, items in (
            ("packs/index.json", packs),
            ("locales/index.json", locales),
            ("schemas/index.json", list(schemas.values())),
            (
                "replacements/index.json",
                [
                    {"from": source, "candidates": choices}
                    for source, choices in sorted(replacements.items())
                ],
            ),
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
