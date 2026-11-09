from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import select

from dinkster_registry_service.admission import AdmissionService
from dinkster_registry_service.app import create_app
from dinkster_registry_service.artifacts import build_registry_fixture_archive
from dinkster_registry_service.database import NamespaceGrantRecord, OutboxRecord, PackRecord
from dinkster_registry_service.digests import artifact_digest
from dinkster_registry_service.object_store import LocalFilesystemObjectStore, ObjectStoreError
from dinkster_registry_service.principals import PrincipalRepository
from dinkster_registry_service.seed import FIXTURE_ROOT
from dinkster_registry_service.settings import ServerSettings


def _archive(tmp_path: Path, name: str, *, native: bool = False) -> bytes:
    source = tmp_path / name
    shutil.copytree(FIXTURE_ROOT / "example-pack", source)
    manifest = source / "dinkster-pack.toml"
    manifest.write_text(
        manifest.read_text()
        .replace('publisher = "dinkster"', 'publisher = "example-org"')
        .replace('name = "example-pack"', f'name = "{name}"')
        .replace('namespaces = ["example"]', f'namespaces = ["{name}"]')
    )
    nodes = source / "nodes.py"
    nodes.write_text(nodes.read_text().replace("example.", f"{name}."))
    if native:
        (source / "extension.so").write_bytes(b"synthetic native inventory fixture")
    return build_registry_fixture_archive(source)


def _client(tmp_path: Path) -> tuple[TestClient, FastAPI, str]:
    app = create_app(
        ServerSettings(
            database_url=f"sqlite:///{tmp_path / 'registry.db'}",
            object_store_root=tmp_path / "objects",
            public_base_url="http://testserver",
            cursor_secret=b"publish-api-test-cursor-secret",
        )
    )
    principals = PrincipalRepository(app.state.database)
    now = datetime.now(UTC)
    principals.register_user("owner")
    principals.add_operator("owner", "owner", now.isoformat())
    principals.register_publisher("example-org", "owner", now.isoformat())
    token, _ = principals.mint_token(
        "example-org",
        "owner",
        now.isoformat(),
        (now + timedelta(hours=1)).isoformat(),
    )
    return TestClient(app, raise_server_exceptions=False), app, token


def test_publish_api_authenticates_and_attributes_a_sqlite_submission(tmp_path: Path) -> None:
    client, app, token = _client(tmp_path)
    archive = _archive(tmp_path, "wire-pack")
    endpoint = "/v1/publish/wire-pack/versions/1.2.3"

    missing = client.post(endpoint, content=archive)
    unknown = client.post(endpoint, content=archive, headers={"Authorization": "Bearer unknown"})
    assert missing.status_code == unknown.status_code == 401
    assert missing.json()["error"]["message"] == unknown.json()["error"]["message"]

    submitted = client.post(endpoint, content=archive, headers={"Authorization": f"Bearer {token}"})
    assert submitted.status_code == 202
    candidate_id = submitted.json()["candidateId"]
    status = client.get(f"/v1/publish/{candidate_id}", headers={"Authorization": f"Bearer {token}"})
    assert status.status_code == 200
    assert status.json()["status"] == "queued"
    assert status.json()["packName"] == "wire-pack"

    principals = PrincipalRepository(app.state.database)
    assert principals.audit()[-1].action == "submit-release"


def _locks(archive: bytes) -> dict[str, object]:
    return {
        variant: {
            "baseId": "sha256:" + digit * 64,
            "artifactDigest": artifact_digest(archive),
            "lock": {
                "format": "dinkster.pack-lock/1",
                "pack": "locked-pack",
                "variant": variant,
                "requiresPython": ">=3.12",
                "requirements": [],
                "indexes": [],
                "packages": [],
            },
        }
        for variant, digit in (("linux-cpu", "1"), ("win-cpu", "2"))
    }


def test_published_locks_bind_archive_base_and_visibility(tmp_path: Path) -> None:
    client, app, token = _client(tmp_path)
    archive = _archive(tmp_path, "locked-pack")
    locks = json.loads(json.dumps(_locks(archive)))
    locks["linux-cpu"]["lock"]["packages"] = [
        {
            "name": "fixture",
            "version": "1.0",
            "wheels": [
                {
                    "filename": "fixture-1.0-py3-none-any.whl",
                    "size": 7,
                    "sha256": "a" * 64,
                    "url": "https://example.test/fixture-1.0-py3-none-any.whl",
                }
            ],
        }
    ]
    endpoint = "/v1/publish/locked-pack/versions/1.2.3"
    headers = {"Authorization": f"Bearer {token}"}

    def publish(payload: dict[str, object]) -> Response:
        return client.post(
            endpoint,
            headers=headers,
            files={"archive": ("pack.zip", archive, "application/zip")},
            data={"locks": json.dumps(payload)},
        )

    submitted = publish(locks)
    assert submitted.status_code == 202, submitted.text
    assert publish(locks).json()["candidateId"] == submitted.json()["candidateId"]
    lock_url = "/v1/packs/locked-pack/versions/1.2.3/locks/linux-cpu"
    query = {"baseId": "sha256:" + "1" * 64}
    assert client.get(lock_url, params=query).status_code == 404
    admission = AdmissionService(
        app.state.database,
        LocalFilesystemObjectStore(tmp_path / "objects"),
        require_isolation=False,
    )
    assert admission.run_once()
    assert admission.status(UUID(submitted.json()["candidateId"])).status == "accepted"
    detail = client.get("/v1/packs/locked-pack/versions/1.2.3").json()
    assert set(detail["installLocks"]) == {"linux-cpu", "win-cpu"}
    download = client.get(lock_url, params=query)
    assert download.status_code == 200
    assert download.json() == locks["linux-cpu"]["lock"]
    windows = client.get(
        lock_url.replace("linux-cpu", "win-cpu"),
        params={"baseId": "sha256:" + "2" * 64},
    )
    assert windows.status_code == 200
    assert windows.json() == locks["win-cpu"]["lock"]
    assert windows.content != download.content
    facts = detail["installLocks"]["linux-cpu"]
    assert facts["artifactDigest"] == artifact_digest(archive)
    assert facts["digest"] == artifact_digest(download.content)
    assert facts["size"] == len(download.content)
    assert facts["baseId"] == query["baseId"]
    assert client.get(lock_url, params={"baseId": "sha256:" + "2" * 64}).status_code == 409
    assert (
        client.get(
            lock_url, params=query, headers={"If-None-Match": download.headers["etag"]}
        ).status_code
        == 304
    )
    assert publish(locks).json()["candidateId"] == submitted.json()["candidateId"]
    changed = json.loads(json.dumps(locks))
    changed["linux-cpu"]["baseId"] = "sha256:" + "3" * 64
    assert publish(changed).status_code == 409
    with app.state.database.session() as session, session.begin():
        from dinkster_registry_service.database import ReleaseRecord

        release = session.scalar(select(ReleaseRecord))
        assert release is not None
        release.state = "yanked"
    assert client.get(lock_url, params=query).content == download.content
    with app.state.database.session() as session, session.begin():
        release = session.scalar(select(ReleaseRecord))
        assert release is not None
        release.state = "quarantined"
    assert client.get(lock_url, params=query).status_code == 404
    with app.state.database.session() as session, session.begin():
        release = session.scalar(select(ReleaseRecord))
        assert release is not None
        release.state = "active"
    digest = facts["digest"].removeprefix("blake3:")
    stored = tmp_path / "objects" / "pack-locks" / "blake3" / digest[:2] / f"{digest}.json"
    stored.write_bytes(b"damaged retained lock")
    assert client.get(lock_url, params=query).status_code == 500


@pytest.mark.parametrize(
    "mutation",
    [
        "base",
        "archive",
        "pack",
        "variant",
        "empty",
        "duplicate",
        "requirements-object",
        "indexes-string",
        "packages-object",
        "python-null",
        "package-name-number",
        "wheel-size-boolean",
        "wheel-url-no-host",
        "wheel-url-credentials",
        "wheel-file-origin",
        "wheel-hash",
        "too-many-variants",
        "oversized-lock",
    ],
)
def test_invalid_published_locks_refuse_before_submission(tmp_path: Path, mutation: str) -> None:
    client, app, token = _client(tmp_path)
    archive = _archive(tmp_path, "locked-pack")
    locks = json.loads(json.dumps(_locks(archive)))
    lock = locks["linux-cpu"]["lock"]
    if mutation == "base":
        locks["linux-cpu"]["baseId"] = "linux-cpu"
    elif mutation == "archive":
        locks["linux-cpu"]["artifactDigest"] = "blake3:" + "0" * 64
    elif mutation == "pack":
        locks["linux-cpu"]["lock"]["pack"] = "other-pack"
    elif mutation == "variant":
        locks["linux-cpu"]["lock"]["variant"] = "win-cpu"
    elif mutation == "empty":
        locks = {}
    elif mutation == "requirements-object":
        lock["requirements"] = {}
    elif mutation == "indexes-string":
        lock["indexes"] = ""
    elif mutation == "packages-object":
        lock["packages"] = {}
    elif mutation == "python-null":
        lock["requiresPython"] = None
    elif mutation == "too-many-variants":
        binding = locks["linux-cpu"]
        locks = {}
        for number in range(33):
            variant = f"variant-{number}"
            locks[variant] = json.loads(json.dumps(binding))
            locks[variant]["lock"]["variant"] = variant
    elif mutation == "oversized-lock":
        lock["indexes"] = ["https://example.test/" + "a" * (1024 * 1024)]
    elif mutation.startswith("package-") or mutation.startswith("wheel-"):
        url = {
            "wheel-url-no-host": "https:///fixture.whl",
            "wheel-url-credentials": "https://user:secret@example.test/fixture.whl",
            "wheel-file-origin": "file:///tmp/fixture.whl",
        }.get(mutation, "https://example.test/fixture.whl")
        lock["packages"] = [
            {
                "name": 1 if mutation == "package-name-number" else "fixture",
                "version": "1.0",
                "wheels": [
                    {
                        "filename": "fixture-1.0-py3-none-any.whl",
                        "size": True if mutation == "wheel-size-boolean" else 7,
                        "sha256": "not-a-hash" if mutation == "wheel-hash" else "a" * 64,
                        "url": url,
                    }
                ],
            }
        ]
    payload = json.dumps(locks)
    if mutation == "duplicate":
        payload = payload.replace('"requiresPython":', '"pack":"other-pack","requiresPython":')
    response = client.post(
        "/v1/publish/locked-pack/versions/1.2.3",
        headers={"Authorization": f"Bearer {token}"},
        files={"archive": ("pack.zip", archive, "application/zip")},
        data={"locks": payload},
    )
    assert response.status_code == 400, response.text
    assert not (tmp_path / "objects").exists()


def test_installation_lock_storage_failure_keeps_release_private_until_retry(
    tmp_path: Path,
) -> None:
    client, app, token = _client(tmp_path)
    archive = _archive(tmp_path, "locked-pack")
    submitted = client.post(
        "/v1/publish/locked-pack/versions/1.2.3",
        headers={"Authorization": f"Bearer {token}"},
        files={"archive": ("pack.zip", archive, "application/zip")},
        data={"locks": json.dumps(_locks(archive))},
    )
    assert submitted.status_code == 202

    class UnavailableLockStorage(LocalFilesystemObjectStore):
        unavailable = True

        def put(self, key: str, data: bytes) -> None:
            if key.startswith("pack-locks/") and self.unavailable:
                raise ObjectStoreError("synthetic lock storage outage")
            super().put(key, data)

    store = UnavailableLockStorage(tmp_path / "objects")
    admission = AdmissionService(app.state.database, store, require_isolation=False)
    candidate = UUID(submitted.json()["candidateId"])
    assert admission.run_once()
    assert admission.status(candidate).status == "promoting"
    endpoint = "/v1/packs/locked-pack/versions/1.2.3"
    assert client.get(endpoint).status_code == 404
    assert (
        client.get(
            endpoint + "/locks/linux-cpu", params={"baseId": "sha256:" + "1" * 64}
        ).status_code
        == 404
    )
    store.unavailable = False
    with app.state.database.session() as session, session.begin():
        event = session.scalar(select(OutboxRecord).where(OutboxRecord.topic == "artifact.promote"))
        assert event is not None
        event.available_at = datetime.now(UTC) - timedelta(seconds=1)
    assert admission.run_once()
    assert admission.status(candidate).status == "accepted"
    detail = client.get(endpoint).json()
    for variant, digit in (("linux-cpu", "1"), ("win-cpu", "2")):
        response = client.get(
            endpoint + f"/locks/{variant}", params={"baseId": "sha256:" + digit * 64}
        )
        assert response.status_code == 200
        assert artifact_digest(response.content) == detail["installLocks"][variant]["digest"]


def test_operator_resolves_review_and_publisher_owns_catalog_grants(tmp_path: Path) -> None:
    client, app, token = _client(tmp_path)
    archive = _archive(tmp_path, "review-pack", native=True)
    submitted = client.post(
        "/v1/publish/review-pack/versions/1.2.3",
        content=archive,
        headers={"Authorization": f"Bearer {token}"},
    )
    candidate_id = UUID(submitted.json()["candidateId"])
    admission = AdmissionService(
        app.state.database,
        LocalFilesystemObjectStore(tmp_path / "objects"),
        require_isolation=False,
    )
    assert admission.run_once()
    assert admission.status(candidate_id).status == "review"

    resolved = client.post(
        f"/v1/reviews/{candidate_id}",
        json={"decision": "accept", "reason": "native component reviewed"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "accepted"
    assert client.get("/v1/packs/review-pack").status_code == 200

    with app.state.database.session() as session:
        pack = session.scalar(select(PackRecord).where(PackRecord.name == "review-pack"))
        assert pack is not None
        grants = list(
            session.scalars(
                select(NamespaceGrantRecord).where(NamespaceGrantRecord.pack_id == pack.id)
            )
        )
        assert pack.publisher_id == "example-org"
        assert grants and {grant.publisher_id for grant in grants} == {"example-org"}
