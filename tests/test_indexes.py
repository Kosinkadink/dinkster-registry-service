from __future__ import annotations

import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select, text

from dinkster_registry_service.cli import main
from dinkster_registry_service.database import Database, OutboxRecord, PackRecord, ReleaseRecord
from dinkster_registry_service.indexes import StaticIndexes, queue_index_rebuild
from dinkster_registry_service.object_store import LocalFilesystemObjectStore, ObjectStoreError
from dinkster_registry_service.seed import seed_fixtures


def test_index_retry_repairs_partial_publication(database: Database, tmp_path: Path) -> None:
    class FailingStore(LocalFilesystemObjectStore):
        fail = True

        def replace_index(self, key: str, data: bytes) -> None:
            if self.fail and key == "locales/index.json":
                raise ObjectStoreError("synthetic index failure")
            super().replace_index(key, data)

    store = FailingStore(tmp_path / "objects")
    seed_fixtures(database, store)
    with database.session() as session, session.begin():
        queue_index_rebuild(session)
    indexes = StaticIndexes(database, store, "http://testserver")
    assert indexes.deliver_one()
    assert store.exists("packs/index.json")
    assert not store.exists("locales/index.json")
    with database.session() as session, session.begin():
        event = session.scalar(select(OutboxRecord).where(OutboxRecord.topic == "indexes.rebuild"))
        assert event is not None
        assert (event.state, event.attempts) == ("pending", 1)
        event.available_at = datetime.now(UTC)
    store.fail = False
    assert indexes.deliver_one()
    assert not indexes.deliver_one()
    for key in ("packs/index.json", "locales/index.json"):
        payload = json.loads(store.read(key))
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
        assert [item["name"] for item in json.loads(store.read(key))["items"]] == ["example-pack"]


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
        before = store.read("packs/index.json")
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
        assert store.read("packs/index.json") == before
        assert [item["name"] for item in json.loads(before)["items"]] == ["example-pack"]
    finally:
        database.dispose()
