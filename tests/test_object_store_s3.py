from __future__ import annotations

import hashlib
import os
import shutil
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import boto3  # type: ignore[import-untyped]
import pytest
from fastapi.testclient import TestClient
from moto.server import ThreadedMotoServer

from dinkster_registry_service.admission import AdmissionService
from dinkster_registry_service.app import create_app
from dinkster_registry_service.artifacts import build_registry_fixture_archive
from dinkster_registry_service.database import Database
from dinkster_registry_service.digests import artifact_digest
from dinkster_registry_service.object_store import (
    MAX_ARTIFACT_SIZE,
    ObjectStoreError,
    S3ObjectStore,
)
from dinkster_registry_service.principals import PrincipalRepository
from dinkster_registry_service.seed import FIXTURE_ROOT, seed_fixtures
from dinkster_registry_service.settings import ServerSettings

TEST_S3_REGION = os.getenv("TEST_S3_REGION", "us-east-1")
TEST_S3_ACCESS_KEY_ID = os.getenv("TEST_S3_ACCESS_KEY_ID", "test-access-key")
TEST_S3_SECRET_ACCESS_KEY = os.getenv("TEST_S3_SECRET_ACCESS_KEY", "test-secret-key")


@pytest.fixture(scope="session")
def s3_endpoint_url() -> Iterator[str]:
    endpoint_url = os.getenv("TEST_S3_ENDPOINT_URL")
    if endpoint_url is not None:
        yield endpoint_url
        return
    server = ThreadedMotoServer(ip_address="127.0.0.1", port=0, verbose=False)
    server.start()
    host, port = server.get_host_and_port()
    try:
        yield f"http://{host}:{port}"
    finally:
        server.stop()


@pytest.fixture
def s3_store(s3_endpoint_url: str) -> Iterator[S3ObjectStore]:
    bucket = f"dinkster-registry-test-{uuid4().hex}"
    client = boto3.client(
        "s3",
        endpoint_url=s3_endpoint_url,
        aws_access_key_id=TEST_S3_ACCESS_KEY_ID,
        aws_secret_access_key=TEST_S3_SECRET_ACCESS_KEY,
        region_name=TEST_S3_REGION,
    )
    if TEST_S3_REGION == "us-east-1":
        client.create_bucket(Bucket=bucket)
    else:
        client.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": TEST_S3_REGION},
        )
    try:
        yield S3ObjectStore(
            endpoint_url=s3_endpoint_url,
            bucket=bucket,
            access_key_id=TEST_S3_ACCESS_KEY_ID,
            secret_access_key=TEST_S3_SECRET_ACCESS_KEY,
            region=TEST_S3_REGION,
        )
    finally:
        response = client.list_objects_v2(Bucket=bucket)
        for item in response.get("Contents", []):
            client.delete_object(Bucket=bucket, Key=item["Key"])
        client.delete_bucket(Bucket=bucket)


def test_s3_store_is_immutable_and_streams_verified_objects(s3_store: S3ObjectStore) -> None:
    key = "artifacts/fixture.zip"
    data = b"fixture bytes"
    s3_store.put(key, data)
    s3_store.put(key, data)

    assert s3_store.exists(key)
    assert s3_store.read(key) == data
    stored = s3_store.open(key, expected_size=len(data), expected_digest=artifact_digest(data))
    assert b"".join(stored) == data
    assert stored.closed

    with pytest.raises(ObjectStoreError, match="different bytes"):
        s3_store.put(key, b"replacement bytes")
    s3_store.replace_index("static/packs/index.json", b'{"items":[]}')
    s3_store.replace_index("static/packs/index.json", b'{"items":[1]}')
    assert s3_store.read("static/packs/index.json") == b'{"items":[1]}'
    s3_store.replace_index("static/security/index.json", b'{"signed":{"revision":1}}')
    s3_store.replace_index("static/security/index.json", b'{"signed":{"revision":2}}')
    assert s3_store.read("static/security/index.json") == b'{"signed":{"revision":2}}'
    with pytest.raises(ObjectStoreError, match="only public static indexes"):
        s3_store.replace_index(key, b"replacement bytes")
    assert s3_store.read(key) == data
    with pytest.raises(ObjectStoreError, match="exceeds its declared size"):
        s3_store.open(key, expected_size=len(data) - 1, expected_digest=artifact_digest(data))
    with pytest.raises(ObjectStoreError, match="digest differs"):
        s3_store.open(key, expected_size=len(data), expected_digest=artifact_digest(b"other bytes"))
    with pytest.raises(ObjectStoreError, match="supported size range"):
        s3_store.open(
            key,
            expected_size=MAX_ARTIFACT_SIZE + 1,
            expected_digest=artifact_digest(data),
        )


def test_s3_store_translates_missing_objects(s3_store: S3ObjectStore) -> None:
    assert not s3_store.exists("missing")
    with pytest.raises(FileNotFoundError):
        s3_store.read("missing")
    with pytest.raises(FileNotFoundError):
        s3_store.open("missing", expected_size=1, expected_digest=artifact_digest(b"x"))


def test_production_api_downloads_from_s3_without_local_artifacts(
    database: Database,
    database_url: str,
    s3_store: S3ObjectStore,
    s3_endpoint_url: str,
    tmp_path: Path,
) -> None:
    seed_fixtures(database, s3_store)
    local_root = tmp_path / "unused-local-objects"
    settings = ServerSettings(
        database_url=database_url,
        environment="production",
        object_store_root=local_root,
        s3_endpoint_url=s3_endpoint_url,
        s3_bucket=s3_store.bucket,
        s3_access_key_id=TEST_S3_ACCESS_KEY_ID,
        s3_secret_access_key=TEST_S3_SECRET_ACCESS_KEY,
        s3_region=TEST_S3_REGION,
    )
    expected = build_registry_fixture_archive(FIXTURE_ROOT / "example-pack")
    with TestClient(create_app(settings)) as client:
        response = client.get(f"/v1/artifacts/{artifact_digest(expected)}")
    assert response.status_code == 200
    assert response.content == expected
    assert response.headers["X-Dinkster-Artifact-Digest"] == artifact_digest(expected)
    assert not local_root.exists()


@pytest.mark.parametrize("publisher", (None, "dinkster"))
def test_accepted_publish_updates_both_s3_indexes_with_conditional_get(
    database: Database,
    database_url: str,
    s3_store: S3ObjectStore,
    s3_endpoint_url: str,
    tmp_path: Path,
    publisher: str | None,
) -> None:
    source = tmp_path / "pack"
    shutil.copytree(FIXTURE_ROOT / "example-pack", source)
    manifest = source / "dinkster-pack.toml"
    manifest.write_text(
        manifest.read_text()
        .replace('publisher = "dinkster"\n', "")
        .replace('namespaces = ["example"]', 'namespaces = ["example-pack"]')
    )
    nodes = source / "nodes.py"
    nodes.write_text(nodes.read_text().replace("example.", "example-pack."))
    source.joinpath("locales").mkdir()
    catalog = b'{"nodes":{"example-pack.resize":{"displayName":"Resize"}}}'
    source.joinpath("locales/en.json").write_bytes(catalog)
    archive = build_registry_fixture_archive(source)
    settings = ServerSettings(
        database_url=database_url,
        environment="production",
        public_base_url="http://testserver",
        object_store_root=tmp_path / "unused-artifacts",
        s3_endpoint_url=s3_endpoint_url,
        s3_bucket=s3_store.bucket,
        s3_access_key_id=TEST_S3_ACCESS_KEY_ID,
        s3_secret_access_key=TEST_S3_SECRET_ACCESS_KEY,
        s3_region=TEST_S3_REGION,
    )
    if publisher is not None:
        principals = PrincipalRepository(database)
        principals.register_user("operator")
        principals.register_publisher(publisher, "operator", datetime.now(UTC).isoformat())
    service = AdmissionService(database, s3_store, settings=settings, require_isolation=False)
    with TestClient(create_app(settings)) as client:
        assert client.get("/static/packs/index.json").status_code == 404
        candidate = service.submit(
            archive, pack_name="example-pack", version="1.2.3", publisher=publisher
        )
        assert service.run_once()
        assert service.status(candidate).status == "accepted"
        assert service.run_once()
        schema_key = "static/packs/example-pack/1.2.3/schemas.json"
        schemas = client.get(f"/{schema_key}")
        assert schemas.status_code == 200
        assert schemas.content == s3_store.read(schema_key)
        assert (
            schemas.content == client.get("/v1/packs/example-pack/versions/1.2.3/schemas").content
        )
        assert client.head(f"/{schema_key}").headers["etag"] == schemas.headers["etag"]
        assert (
            client.get(
                f"/{schema_key}", headers={"If-None-Match": schemas.headers["etag"]}
            ).status_code
            == 304
        )
        metadata = s3_store._client.head_object(Bucket=s3_store.bucket, Key=schema_key)
        assert metadata["ContentType"] == "application/json"
        assert metadata["CacheControl"] == "public, max-age=60"
        discovery = client.get("/static/schemas/index.json")
        assert discovery.status_code == 200
        if publisher is None:
            assert discovery.json() == {"schemaVersion": 1, "items": []}
        else:
            assert discovery.json()["items"] == [
                {
                    "name": "example-pack",
                    "publisher": "dinkster",
                    "version": "1.2.3",
                    "displayName": "Example Pack",
                    "platforms": ["darwin", "linux"],
                    "url": schema_key.removeprefix("static/"),
                    "digest": "sha256:" + hashlib.sha256(schemas.content).hexdigest(),
                }
            ]
        etags = {}
        for key in ("packs/index.json", "packs/example-pack/index.json", "locales/index.json"):
            response = client.get(f"/static/{key}")
            assert response.status_code == 200
            assert response.content == s3_store.read(f"static/{key}")
            assert response.json()["schemaVersion"] == 2
            items = response.json()["items"]
            assert len(items) == 1
            release = client.get("/static/packs/example-pack/index.json").json()["items"][0]
            wheel = release["wheels"][0]
            assert (release["name"], release["version"], wheel["digest"]) == (
                "example-pack",
                "1.2.3",
                artifact_digest(archive),
            )
            assert client.get("/static/" + wheel["url"]).content == archive
            etags[key] = response.headers["ETag"]
            conditional = client.get(f"/static/{key}", headers={"If-None-Match": etags[key]})
            assert conditional.status_code == 304
            assert conditional.content == b""
            if key == "locales/index.json":
                assert items[0]["catalogs"] == [
                    {
                        "locale": "en",
                        "path": "locales/en.json",
                        "digest": "sha256:" + hashlib.sha256(catalog).hexdigest(),
                    }
                ]
        old_key = "translations/index.json"
        s3_store.put(old_key, s3_store.read("static/locales/index.json"))
        assert client.get(f"/{old_key}").status_code == 404
        manifest = source / "dinkster-pack.toml"
        manifest.write_text(
            manifest.read_text().replace("[pack]\n", '[pack]\nversion = "1.2.4"\nengine = ">=0"\n')
        )
        second = service.submit(
            build_registry_fixture_archive(source),
            pack_name="example-pack",
            version="1.2.4",
            publisher=publisher,
        )
        assert service.run_once()
        assert service.status(second).status == "accepted"
        assert service.run_once()
        for key, etag in etags.items():
            response = client.get(f"/static/{key}", headers={"If-None-Match": etag})
            assert response.status_code == 200
            if key == "packs/index.json":
                assert [item["latestVersion"] for item in response.json()["items"]] == ["1.2.4"]
            else:
                assert [item["version"] for item in response.json()["items"]] == ["1.2.3", "1.2.4"]
        refreshed = client.get(
            "/static/schemas/index.json", headers={"If-None-Match": discovery.headers["etag"]}
        )
        if publisher is None:
            assert refreshed.status_code == 304
        else:
            assert refreshed.status_code == 200
            assert [item["version"] for item in refreshed.json()["items"]] == ["1.2.4"]
    assert not settings.object_store_root.exists()
