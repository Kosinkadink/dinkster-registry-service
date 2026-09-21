from __future__ import annotations

import hashlib
import io
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from blake3 import blake3
from fastapi.testclient import TestClient
from sqlalchemy import select

from dinkster_registry_service.app import create_app
from dinkster_registry_service.database import ArtifactRecord, Database, ReleaseRecord
from dinkster_registry_service.object_store import LocalFilesystemObjectStore
from dinkster_registry_service.seed import seed_fixtures
from dinkster_registry_service.settings import ServerSettings


@contextmanager
def _sqlite_client(tmp_path: Path) -> Iterator[TestClient]:
    database_url = f"sqlite:///{tmp_path / 'registry.db'}"
    object_store = LocalFilesystemObjectStore(tmp_path / "objects")
    database = Database(database_url)
    try:
        seed_fixtures(database, object_store)
        with database.session() as session, session.begin():
            release = session.scalar(select(ReleaseRecord).where(ReleaseRecord.version == "1.2.3"))
            assert release is not None
            artifact = session.get(ArtifactRecord, release.artifact_digest)
            assert artifact is not None
            archive_bytes = object_store.read(artifact.object_key, max_size=artifact.size)
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
                body = archive.read("dinkster-pack.toml")
            manifest = dict(release.manifest)
            manifest["templates"] = [
                {
                    "id": "starter",
                    "name": "Starter",
                    "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
                    "path": "dinkster-pack.toml",
                    "description": "Start here",
                    "tags": ["intro"],
                    "family": "",
                    "models": [],
                    "assets": [],
                    "thumbnailDigest": "",
                    "thumbnailMediaType": "",
                    "thumbnailPath": "",
                }
            ]
            release.manifest = manifest
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


def test_sqlite_serves_the_hosted_catalog_contract(tmp_path: Path) -> None:
    with _sqlite_client(tmp_path) as client:
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
