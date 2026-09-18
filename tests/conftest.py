from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from dinkster_registry_service.app import create_app
from dinkster_registry_service.database import Database
from dinkster_registry_service.object_store import LocalFilesystemObjectStore
from dinkster_registry_service.seed import seed_fixtures
from dinkster_registry_service.settings import ServerSettings


@pytest.fixture(scope="session")
def database_url() -> str:
    value = os.getenv("TEST_POSTGRES_URL")
    if value is None:
        pytest.fail("TEST_POSTGRES_URL must point to a disposable PostgreSQL database")
    return value


@pytest.fixture
def database(database_url: str) -> Iterator[Database]:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    instance = Database(database_url)
    try:
        yield instance
    finally:
        instance.dispose()
        command.downgrade(config, "base")


@pytest.fixture
def seeded_catalog(
    database: Database, tmp_path: Path
) -> tuple[Database, LocalFilesystemObjectStore]:
    object_store = LocalFilesystemObjectStore(tmp_path / "objects")
    seed_fixtures(database, object_store)
    return database, object_store


@pytest.fixture
def client(
    database_url: str,
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore],
) -> Iterator[TestClient]:
    _, object_store = seeded_catalog
    app = create_app(
        ServerSettings(
            database_url=database_url,
            object_store_root=object_store.root,
            public_base_url="http://testserver",
            cursor_secret=b"test-cursor-secret",
        )
    )
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
