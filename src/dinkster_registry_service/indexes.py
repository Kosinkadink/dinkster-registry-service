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

    def _replace_json(self, key: str, document: dict[str, object]) -> None:
        data = json.dumps(
            document, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        self.object_store.replace_index(f"static/{key}", data)

    def _write_pack_indexes(self, packs: list[dict[str, object]], names: set[str]) -> None:
        versions: dict[str, list[dict[str, object]]] = {name: [] for name in names}
        for entry in packs:
            versions[str(entry["name"])].append(entry)
        final = []
        intermediate = []
        for name, releases in sorted(versions.items()):
            if not releases:
                continue
            latest = max(releases, key=lambda row: Version(str(row["version"])))
            entry = {
                "name": name,
                "publisher": latest["publisher"],
                "latestVersion": latest["version"],
                "library": latest["library"],
                "url": f"packs/{name}/index.json",
            }
            final.append(entry)
            key = f"static/packs/{name}/index.json"
            if self.object_store.exists(key):
                old = json.loads(self.object_store.read(key))
                old_versions = {row["version"] for row in old["items"]}
                shared = [row for row in releases if row["version"] in old_versions]
                if shared:
                    safe = max(shared, key=lambda row: Version(str(row["version"])))
                    intermediate.append({**entry, "latestVersion": safe["version"]})
        # A disappearing latest must leave the catalog before its per-pack file.
        self._replace_json("packs/index.json", {"schemaVersion": 2, "items": intermediate})
        for name, releases in sorted(versions.items()):
            if not releases and not self.object_store.exists(f"static/packs/{name}/index.json"):
                continue
            self._replace_json(
                f"packs/{name}/index.json",
                {"schemaVersion": 2, "name": name, "items": releases},
            )
        self._replace_json("packs/index.json", {"schemaVersion": 2, "items": final})

    @contextmanager
    def _locked_session(self, *, blocking: bool = True) -> Iterator[Session | None]:
        with self.database.session() as session, session.begin():
            # Lock before reading the catalog, not just while writing objects:
            # a slower replica must never replace a newer snapshot with an older one.
            if self.database.is_postgresql:
                if blocking:
                    session.execute(
                        text(
                            "SELECT pg_advisory_xact_lock(hashtext('dinkster-registry-indexes'), 0)"
                        )
                    )
                elif not session.scalar(
                    text(
                        "SELECT pg_try_advisory_xact_lock(hashtext('dinkster-registry-indexes'), 0)"
                    )
                ):
                    yield None
                    return
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
                locales.append(
                    {
                        "name": pack.name,
                        "version": release.version,
                        "publisher": pack.publisher_id,
                        "url": f"packs/{pack.name}/index.json",
                        "catalogs": release.manifest.get("localeCatalogs", []),
                    }
                )
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
        self._write_pack_indexes(packs, {pack.name for pack, _, _ in rows})
        for key, items in (
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
            self._replace_json(
                key, {"schemaVersion": 2 if key == "locales/index.json" else 1, "items": items}
            )
        return len(packs)

    def rebuild(self) -> int:
        with self._locked_session() as session:
            assert session is not None
            return self._write(session)

    def deliver_one(self) -> bool:
        with self._locked_session(blocking=False) as session:
            if session is None:
                return False
            ready = session.scalar(
                select(OutboxRecord.id)
                .where(
                    OutboxRecord.topic == "indexes.rebuild",
                    OutboxRecord.state == "pending",
                    OutboxRecord.available_at <= datetime.now(UTC),
                )
                .limit(1)
            )
            if ready is None:
                return False
            events = list(
                session.scalars(
                    select(OutboxRecord)
                    .where(
                        OutboxRecord.topic == "indexes.rebuild",
                        OutboxRecord.state == "pending",
                    )
                    .order_by(OutboxRecord.created_at, OutboxRecord.id)
                    .with_for_update()
                )
            )
            for event in events:
                event.attempts += 1
            try:
                self._write(session)
            except ObjectStoreError:
                for event in events:
                    event.available_at = datetime.now(UTC) + timedelta(seconds=5)
            else:
                for event in events:
                    event.state = "delivered"
                    event.delivered_at = datetime.now(UTC)
            return True
