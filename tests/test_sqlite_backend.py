from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from blake3 import blake3
from fastapi.testclient import TestClient

from dinkster_registry_service.app import create_app
from dinkster_registry_service.artifacts import build_registry_fixture_archive
from dinkster_registry_service.database import Database
from dinkster_registry_service.digests import artifact_object_key
from dinkster_registry_service.indexes import StaticIndexes
from dinkster_registry_service.object_store import LocalFilesystemObjectStore
from dinkster_registry_service.seed import FIXTURE_ROOT, FIXTURES, seed_fixtures
from dinkster_registry_service.settings import ServerSettings


@contextmanager
def _sqlite_client(tmp_path: Path, *, legacy_schema: bool = False) -> Iterator[TestClient]:
    database_url = f"sqlite:///{tmp_path / 'registry.db'}"
    object_store = LocalFilesystemObjectStore(tmp_path / "objects")
    database = Database(database_url)
    try:
        seed_fixtures(database, object_store)
        if legacy_schema:
            with database.engine.begin() as connection:
                for table in ("release_candidates", "releases"):
                    connection.exec_driver_sql(f"ALTER TABLE {table} DROP COLUMN install_locks")
    finally:
        database.dispose()
    app = create_app(
        ServerSettings(
            database_url=database_url,
            object_store_root=object_store.root,
            public_base_url="http://testserver",
            cursor_secret=b"sqlite-test-cursor-secret",
        )
    )
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


@pytest.mark.parametrize("legacy_schema", (False, True))
def test_sqlite_serves_the_hosted_catalog_contract(tmp_path: Path, legacy_schema: bool) -> None:
    with _sqlite_client(tmp_path, legacy_schema=legacy_schema) as client:
        browse = client.get("/v1/packs")
        assert browse.status_code == 200
        assert [pack["name"] for pack in browse.json()["items"]] == [
            "example-pack",
            "color-tools",
        ]

        providers = client.get(
            "/v1/nodes/example.resize/providers", params={"dinksterVersion": "0.9.5"}
        )
        assert providers.status_code == 200
        assert [provider["packName"] for provider in providers.json()["providers"]] == [
            "example-pack"
        ]

        conditional = client.get("/v1/packs", headers={"If-None-Match": browse.headers["etag"]})
        assert conditional.status_code == 304
        assert conditional.content == b""
        assert conditional.headers["cache-control"] == browse.headers["cache-control"]

        ticket_response = client.post("/v1/packs/example-pack/versions/1.2.3/download-tickets")
        assert ticket_response.status_code == 200
        ticket = ticket_response.json()
        artifact = client.get(ticket["url"])
        assert artifact.status_code == 200
        assert "blake3:" + blake3(artifact.content).hexdigest() == ticket["artifactDigest"]
        assert len(artifact.content) == ticket["artifactSize"]

        templates = client.get("/index/templates?q=start&tag=intro&pack=example-pack")
        assert templates.status_code == 200
        assert templates.json()["templates"][0]["id"] == "starter"
        assert "path" not in templates.text
        document = client.get("/index/packs/example-pack/versions/1.2.3/templates/starter")
        assert document.status_code == 200
        assert (
            "sha256:" + hashlib.sha256(document.content).hexdigest()
            == templates.json()["templates"][0]["digest"]
        )
        detail = client.get("/v1/packs/example-pack/versions/1.2.3")
        assert detail.status_code == 200
        assert detail.json()["installLocks"] == {}


@pytest.mark.parametrize("fault", ("", "lock-digest", "locale-index", "artifact"))
def test_release_conformance_cli_checks_the_supplied_lock_over_http(
    tmp_path: Path, fault: str
) -> None:
    lock: dict[str, Any] = {
        "format": "dinkster.lock/1",
        "packs": [
            {
                "pack": fixture.name,
                "version": fixture.version,
                "artifactDigest": "blake3:"
                + blake3(build_registry_fixture_archive(FIXTURE_ROOT / fixture.name)).hexdigest(),
            }
            for fixture in FIXTURES
        ],
    }
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
        database = Database(f"sqlite:///{tmp_path / 'registry.db'}")
        store = LocalFilesystemObjectStore(tmp_path / "objects")
        try:
            seed_fixtures(database, store)
            StaticIndexes(database, store, origin).rebuild()
        finally:
            database.dispose()
        if fault == "lock-digest":
            lock["packs"][0]["artifactDigest"] = "blake3:" + "0" * 64
        elif fault == "locale-index":
            store.replace_index("static/locales/index.json", b'{"schemaVersion":2,"items":[]}')
        elif fault == "artifact":
            (store.root / artifact_object_key(lock["packs"][0]["artifactDigest"])).write_bytes(
                b"corrupted archive"
            )
        lock_path = tmp_path / "release.lock"
        lock_path.write_text(json.dumps(lock))
        app = create_app(
            ServerSettings(
                database_url=f"sqlite:///{tmp_path / 'registry.db'}",
                object_store_root=store.root,
                public_base_url=origin,
                cursor_secret=b"conformance-test-cursor-secret",
            )
        )
        server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while not server.started:
                assert thread.is_alive() and time.monotonic() < deadline, "HTTP startup failed"
                time.sleep(0.01)
            result = subprocess.run(
                [sys.executable, "conformance/run.py", origin, "--release-lock", str(lock_path)],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            assert (result.returncode == 0) == (not fault), result.stdout + result.stderr
            if fault in {"lock-digest", "locale-index"}:
                reason = (
                    "per-pack indexes lack a locked release and digest"
                    if fault == "lock-digest"
                    else "locale index lacks a locked release"
                )
                assert reason in result.stderr
            elif fault == "artifact":
                assert "downloaded bytes differ from locked release" in result.stderr
            else:
                assert result.stdout.count("PASS locked release, providers and artifact:") == 2
                assert (
                    "PASS release static index and conditional GET: /static/locales/index.json"
                    in (result.stdout)
                )
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            assert not thread.is_alive()
