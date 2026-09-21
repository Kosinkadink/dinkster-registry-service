from __future__ import annotations

import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from dinkster_registry_service.admission import AdmissionService
from dinkster_registry_service.app import create_app
from dinkster_registry_service.artifacts import build_registry_fixture_archive
from dinkster_registry_service.database import NamespaceGrantRecord, PackRecord
from dinkster_registry_service.object_store import LocalFilesystemObjectStore
from dinkster_registry_service.principals import PrincipalRepository
from dinkster_registry_service.seed import FIXTURE_ROOT
from dinkster_registry_service.settings import ServerSettings


def _archive(tmp_path: Path, name: str, *, native: bool = False) -> bytes:
    source = tmp_path / name
    shutil.copytree(FIXTURE_ROOT / "example-pack", source)
    manifest = source / "dinkster-pack.toml"
    manifest.write_text(
        manifest.read_text()
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
