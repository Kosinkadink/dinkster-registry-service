from __future__ import annotations

import hashlib
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from dinkster_registry_service.cli import main
from dinkster_registry_service.database import (
    Database,
    OutboxRecord,
    PackRecord,
    PublisherRecord,
    ReleaseNodeRecord,
    ReleaseRecord,
)
from dinkster_registry_service.ids import uuid7
from dinkster_registry_service.indexes import StaticIndexes, queue_index_rebuild
from dinkster_registry_service.object_store import LocalFilesystemObjectStore, ObjectStoreError
from dinkster_registry_service.seed import seed_fixtures


def test_static_schemas_match_dynamic_routes_and_select_current_first_party_release(
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore], client: TestClient
) -> None:
    database, store = seeded_catalog
    assert client.get("/static/schemas/index.json").status_code == 404
    with database.session() as session, session.begin():
        session.add(PublisherRecord(id="dinkster", display_name="Dinkster"))
        session.flush()
        pack = session.scalar(select(PackRecord).where(PackRecord.name == "example-pack"))
        assert pack is not None
        pack.publisher_id = "dinkster"
        original = session.scalar(select(ReleaseRecord).where(ReleaseRecord.pack_id == pack.id))
        assert original is not None
        nodes = list(
            session.scalars(
                select(ReleaseNodeRecord).where(ReleaseNodeRecord.release_id == original.id)
            )
        )
        for version, state in (("1.10.0", "active"), ("1.9.0", "active"), ("2.0.0", "yanked")):
            release = ReleaseRecord(
                **{
                    column.name: getattr(original, column.name)
                    for column in ReleaseRecord.__table__.columns
                    if column.name not in {"id", "version", "version_key", "state"}
                },
                id=uuid7(),
                version=version,
                version_key=version,
                state=state,
            )
            session.add(release)
            session.flush()
            for node in nodes:
                session.add(
                    ReleaseNodeRecord(
                        **{
                            column.name: getattr(node, column.name)
                            for column in ReleaseNodeRecord.__table__.columns
                            if column.name not in {"release_id", "schema"}
                        },
                        release_id=release.id,
                        schema={
                            **node.schema,
                            "replacements": (
                                [
                                    {
                                        "from": "example.deprecated",
                                        "cases": [{"to": "example.resize"}],
                                    }
                                ]
                                if node.node_type == "example.resize"
                                else []
                            ),
                        },
                    )
                )
    indexes = StaticIndexes(database, store, "http://testserver")
    assert indexes.rebuild() == 4
    response = client.get(
        "/static/schemas/index.json", headers={"Origin": "https://editor.example"}
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "*"
    assert response.headers["access-control-expose-headers"] == "ETag"
    schema_body = store.read("static/packs/example-pack/1.10.0/schemas.json")
    assert response.json() == {
        "schemaVersion": 1,
        "items": [
            {
                "name": "example-pack",
                "publisher": "dinkster",
                "version": "1.10.0",
                "displayName": "Example Pack",
                "platforms": ["linux-x86_64", "macos-arm64"],
                "url": "packs/example-pack/1.10.0/schemas.json",
                "digest": "sha256:" + hashlib.sha256(schema_body).hexdigest(),
            }
        ],
    }
    replacement_items = client.get("/static/replacements/index.json").json()["items"]
    assert replacement_items == [
        {
            "from": "example.deprecated",
            "candidates": [
                {
                    "pack": "example-pack",
                    "version": "1.10.0",
                    "target": "example.resize",
                    "rule": {
                        "from": "example.deprecated",
                        "cases": [{"to": "example.resize"}],
                    },
                }
            ],
        }
    ]
    assert client.get("/static/replacements/index.json").content == (
        b'{"items":[{"candidates":[{"pack":"example-pack","rule":'
        b'{"cases":[{"to":"example.resize"}],"from":"example.deprecated"},'
        b'"target":"example.resize","version":"1.10.0"}],'
        b'"from":"example.deprecated"}],"schemaVersion":1}'
    )
    for version in ("1.2.3", "1.9.0", "1.10.0", "2.0.0"):
        path = f"/static/packs/example-pack/{version}/schemas.json"
        static = client.get(path)
        dynamic = client.get(f"/v1/packs/example-pack/versions/{version}/schemas")
        assert static.status_code == dynamic.status_code == 200
        assert static.content == dynamic.content == store.read(path.lstrip("/"))
        assert static.json()["schemas"][0]["schema"]["displayName"] == "Example Resize"
    # Third-party schemas are mirrored, but are not first-party search entries.
    third_party = client.get("/static/packs/color-tools/0.4.0/schemas.json")
    assert third_party.content == client.get("/v1/packs/color-tools/versions/0.4.0/schemas").content
    for path in (
        "/static/schemas/index.json",
        "/static/replacements/index.json",
        "/static/packs/example-pack/1.10.0/schemas.json",
    ):
        static = client.get(path)
        head = client.head(path)
        assert head.status_code == 200 and head.content == b""
        assert head.headers["content-length"] == str(len(static.content))
        assert head.headers["etag"] == static.headers["etag"]
        cached = client.get(path, headers={"If-None-Match": static.headers["etag"]})
        assert cached.status_code == 304 and cached.content == b""
        assert cached.headers["access-control-allow-origin"] == "*"
        preflight = client.options(
            path,
            headers={
                "Origin": "https://editor.example",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "If-None-Match",
            },
        )
        assert preflight.status_code == 204
        assert preflight.headers["access-control-allow-headers"] == "If-None-Match"
    before = response.content
    indexes.rebuild()
    assert client.get("/static/schemas/index.json").content == before
    with database.session() as session, session.begin():
        current = session.scalar(select(ReleaseRecord).where(ReleaseRecord.version == "1.10.0"))
        assert current is not None
        current.state = "quarantined"
    indexes.rebuild()
    assert client.get("/static/schemas/index.json").json()["items"][0]["version"] == "1.9.0"
    assert (
        client.get("/static/replacements/index.json").json()["items"][0]["candidates"][0]["version"]
        == "1.9.0"
    )
    assert client.get("/static/packs/example-pack/1.10.0/schemas.json").status_code == 404
    assert not store.exists("static/packs/example-pack/1.10.0/schemas.json")
    with database.session() as session, session.begin():
        for release in session.scalars(
            select(ReleaseRecord).where(ReleaseRecord.state == "active")
        ):
            release.state = "quarantined"
    indexes.rebuild()
    assert client.get("/static/schemas/index.json").json()["items"] == []
    assert client.get("/static/packs/example-pack/2.0.0/schemas.json").status_code == 200


def test_replacements_keep_first_party_alternatives_and_complete_schema_rules(
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore], client: TestClient
) -> None:
    database, store = seeded_catalog
    cases = [
        {
            "to": "example.resize",
            "when": {"kind": "valueEquals", "input": "mode", "value": "image"},
        },
        {
            "to": "example.resize",
            "when": {"kind": "valueEquals", "input": "mode", "value": "mask"},
        },
    ]
    rule = {"from": "deprecated.resize", "cases": cases}
    with database.session() as session, session.begin():
        session.add(PublisherRecord(id="dinkster", display_name="Dinkster"))
        session.flush()
        for pack in session.scalars(select(PackRecord)):
            release = session.scalar(select(ReleaseRecord).where(ReleaseRecord.pack_id == pack.id))
            assert release is not None
            target = "example.resize" if pack.name == "example-pack" else "color.adjust"
            node = session.scalar(
                select(ReleaseNodeRecord).where(
                    ReleaseNodeRecord.release_id == release.id,
                    ReleaseNodeRecord.node_type == target,
                )
            )
            assert node is not None
            newer = ReleaseRecord(
                **{
                    column.name: getattr(release, column.name)
                    for column in ReleaseRecord.__table__.columns
                    if column.name not in {"id", "version", "version_key"}
                },
                id=uuid7(),
                version="3.0.0",
                version_key="3.0.0",
            )
            session.add(newer)
            session.flush()
            session.add(
                ReleaseNodeRecord(
                    **{
                        column.name: getattr(node, column.name)
                        for column in ReleaseNodeRecord.__table__.columns
                        if column.name not in {"release_id", "schema"}
                    },
                    release_id=newer.id,
                    schema={
                        **node.schema,
                        "replacements": [
                            {**rule, "cases": [{**case, "to": target} for case in cases]}
                        ],
                    },
                )
            )
            if pack.name == "example-pack":
                pack.publisher_id = "dinkster"
    indexes = StaticIndexes(database, store, "http://testserver")
    indexes.rebuild()
    first = {
        "pack": "example-pack",
        "version": "3.0.0",
        "target": "example.resize",
        "rule": rule,
    }
    assert client.get("/static/replacements/index.json").json()["items"] == [
        {"from": "deprecated.resize", "candidates": [first]}
    ]
    with database.session() as session, session.begin():
        other_pack = session.scalar(select(PackRecord).where(PackRecord.name == "color-tools"))
        assert other_pack is not None
        other_pack.publisher_id = "dinkster"
    indexes.rebuild()
    assert client.get("/static/replacements/index.json").json()["items"] == [
        {
            "from": "deprecated.resize",
            "candidates": [
                {
                    **first,
                    "pack": "color-tools",
                    "target": "color.adjust",
                    "rule": {
                        "from": "deprecated.resize",
                        "cases": [
                            {
                                "to": "color.adjust",
                                "when": {"kind": "valueEquals", "input": "mode", "value": "image"},
                            },
                            {
                                "to": "color.adjust",
                                "when": {"kind": "valueEquals", "input": "mode", "value": "mask"},
                            },
                        ],
                    },
                },
                first,
            ],
        }
    ]


def test_unlisted_static_index_is_not_served_or_rewritten(
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore], client: TestClient
) -> None:
    database, store = seeded_catalog
    key = "static/translations/index.json"
    old = b'{"items":[],"schemaVersion":1}'
    store.put(key, old)
    StaticIndexes(database, store, "http://testserver").rebuild()
    for method in ("GET", "HEAD", "OPTIONS"):
        assert client.request(method, "/" + key).status_code == 404
    assert store.read(key) == old


def test_index_retry_repairs_partial_publication(database: Database, tmp_path: Path) -> None:
    class FailingStore(LocalFilesystemObjectStore):
        fail = True

        def replace_index(self, key: str, data: bytes) -> None:
            if self.fail and key == "static/locales/index.json":
                raise ObjectStoreError("synthetic index failure")
            super().replace_index(key, data)

    store = FailingStore(tmp_path / "objects")
    seed_fixtures(database, store)
    with database.session() as session, session.begin():
        queue_index_rebuild(session)
    indexes = StaticIndexes(database, store, "http://testserver")
    assert indexes.deliver_one()
    assert store.exists("static/packs/index.json")
    assert not store.exists("static/locales/index.json")
    with database.session() as session, session.begin():
        event = session.scalar(select(OutboxRecord).where(OutboxRecord.topic == "indexes.rebuild"))
        assert event is not None
        assert (event.state, event.attempts) == ("pending", 1)
        event.available_at = datetime.now(UTC)
    store.fail = False
    assert indexes.deliver_one()
    assert not indexes.deliver_one()
    for key in ("packs/index.json", "locales/index.json"):
        payload = json.loads(store.read(f"static/{key}"))
        assert {item["name"] for item in payload["items"]} == {"example-pack", "color-tools"}


def test_concurrent_rebuilds_cannot_overwrite_newer_catalog(
    database: Database, tmp_path: Path
) -> None:
    entered = threading.Event()
    release = threading.Event()

    class BlockingStore(LocalFilesystemObjectStore):
        block = True

        def replace_index(self, key: str, data: bytes) -> None:
            if self.block:
                self.block = False
                entered.set()
                assert release.wait(10)
            super().replace_index(key, data)

    store = BlockingStore(tmp_path / "objects")
    seed_fixtures(database, store)
    indexes = StaticIndexes(database, store, "http://testserver")
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(indexes.rebuild)
        try:
            assert entered.wait(10)
            with database.session() as session, session.begin():
                pack = session.scalar(select(PackRecord).where(PackRecord.name == "color-tools"))
                assert pack is not None
                catalog_release = session.scalar(
                    select(ReleaseRecord).where(ReleaseRecord.pack_id == pack.id)
                )
                assert catalog_release is not None
                catalog_release.state = "quarantined"
            second = executor.submit(indexes.rebuild)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                with database.session() as session:
                    waiting = session.scalar(
                        text(
                            "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' "
                            "AND NOT granted AND classid = "
                            "(hashtext('dinkster-registry-indexes')::bigint & 4294967295) "
                            "AND objid = 0)"
                        )
                    )
                if waiting:
                    break
                time.sleep(0.02)
            else:
                raise AssertionError("second index writer did not wait for the catalog lock")
        finally:
            release.set()
        assert first.result(timeout=10) == 2
        assert second.result(timeout=10) == 1
    for key in ("packs/index.json", "locales/index.json"):
        assert [item["name"] for item in json.loads(store.read(f"static/{key}"))["items"]] == [
            "example-pack"
        ]


def test_sqlite_rebuild_is_deterministic_and_excludes_quarantined_releases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    database = Database(f"sqlite:///{tmp_path / 'catalog.db'}")
    store = LocalFilesystemObjectStore(tmp_path / "objects")
    try:
        seed_fixtures(database, store)
        with database.session() as session, session.begin():
            pack = session.scalar(select(PackRecord).where(PackRecord.name == "color-tools"))
            assert pack is not None
            catalog_release = session.scalar(
                select(ReleaseRecord).where(ReleaseRecord.pack_id == pack.id)
            )
            assert catalog_release is not None
            catalog_release.state = "quarantined"
        indexes = StaticIndexes(database, store, "http://testserver")
        assert indexes.rebuild() == 1
        before = store.read("static/packs/index.json")
        monkeypatch.setenv("DINKSTER_PUBLIC_BASE_URL", "http://testserver")
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "dinkster-registry",
                "rebuild-indexes",
                "--database-url",
                f"sqlite:///{tmp_path / 'catalog.db'}",
                "--object-store-root",
                str(store.root),
            ],
        )
        main()
        assert capsys.readouterr().out == "Published pack and locale indexes for 1 releases.\n"
        assert store.read("static/packs/index.json") == before
        assert [item["name"] for item in json.loads(before)["items"]] == ["example-pack"]
    finally:
        database.dispose()


def test_pending_rebuilds_are_served_by_one_catalog_snapshot(
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore],
) -> None:
    database, store = seeded_catalog
    with database.session() as session, session.begin():
        for _ in range(3):
            queue_index_rebuild(session)
        session.flush()
        delayed = session.scalar(select(OutboxRecord).order_by(OutboxRecord.created_at).limit(1))
        assert delayed is not None
        delayed.available_at = datetime.now(UTC) + timedelta(minutes=1)
    indexes = StaticIndexes(database, store, "http://testserver")
    assert indexes.deliver_one()
    with database.session() as session:
        events = list(session.scalars(select(OutboxRecord)))
        assert len(events) == 3
        assert {event.state for event in events} == {"delivered"}
    assert not indexes.deliver_one()
    assert {
        (item["name"], item["version"])
        for item in json.loads(store.read("static/packs/index.json"))["items"]
    } == {("example-pack", "1.2.3"), ("color-tools", "0.4.0")}


@pytest.mark.parametrize("fail", (False, True), ids=("delivered", "retry"))
def test_rebuild_keeps_requests_committed_during_publication(
    database: Database, tmp_path: Path, fail: bool
) -> None:
    entered = threading.Event()
    finish = threading.Event()

    class BlockingStore(LocalFilesystemObjectStore):
        block = True
        fail_write = fail

        def replace_index(self, key: str, data: bytes) -> None:
            if key == "static/packs/index.json" and self.block:
                self.block = False
                entered.set()
                assert finish.wait(10)
                if self.fail_write:
                    raise ObjectStoreError("synthetic publication failure")
            super().replace_index(key, data)

    store = BlockingStore(tmp_path / "objects")
    seed_fixtures(database, store)
    with database.session() as session, session.begin():
        for _ in range(3):
            queue_index_rebuild(session)
    indexes = StaticIndexes(database, store, "http://testserver")
    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(indexes.deliver_one)
        try:
            assert entered.wait(5)
            with database.session() as session, session.begin():
                pack = session.scalar(select(PackRecord).where(PackRecord.name == "color-tools"))
                assert pack is not None
                release = session.scalar(
                    select(ReleaseRecord).where(ReleaseRecord.pack_id == pack.id)
                )
                assert release is not None
                release.state = "quarantined"
                queue_index_rebuild(session)
        finally:
            finish.set()
        assert first.result(timeout=5)
    with database.session() as session, session.begin():
        events = list(session.scalars(select(OutboxRecord).order_by(OutboxRecord.created_at)))
        assert len(events) == 4
        assert [event.state for event in events] == (
            ["pending"] * 4 if fail else ["delivered"] * 3 + ["pending"]
        )
        for event in events:
            event.available_at = datetime.now(UTC)
    assert indexes.deliver_one()
    assert not indexes.deliver_one()
    for name in ("packs", "locales"):
        assert {
            (item["name"], item["version"])
            for item in json.loads(store.read(f"static/{name}/index.json"))["items"]
        } == {("example-pack", "1.2.3")}
