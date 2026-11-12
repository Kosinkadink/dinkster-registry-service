from __future__ import annotations

import json
import shutil
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from dinkster_workers.pack_lock import GenerationPackages, PackLock, plan_pack
from dinkster_workers.provision import ProvisionError
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx2 import Response
from runtime_fixture import RuntimeFixture
from sqlalchemy import select

from dinkster_registry_service.admission import AdmissionService
from dinkster_registry_service.app import create_app
from dinkster_registry_service.artifacts import build_registry_fixture_archive
from dinkster_registry_service.cli import main
from dinkster_registry_service.database import (
    AuditEventRecord,
    Database,
    NamespaceGrantRecord,
    OutboxRecord,
    PackRecord,
)
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


def _client(tmp_path: Path, database_url: str | None = None) -> tuple[TestClient, FastAPI, str]:
    app = create_app(
        ServerSettings(
            database_url=database_url or f"sqlite:///{tmp_path / 'registry.db'}",
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


def _locks(archive: bytes, runtime: RuntimeFixture | None = None) -> dict[str, object]:
    return {
        variant: {
            "baseId": runtime.base_ids[variant] if runtime else "sha256:" + digit * 64,
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


@pytest.mark.parametrize(
    "variant,digit", [("linux-cpu", "1"), ("win-cpu", "2"), ("cpu", "1"), ("cuda", "1")]
)
def test_published_pack_refuses_a_missing_bound_base(
    tmp_path: Path, variant: str, digit: str
) -> None:
    client, app, token = _client(tmp_path)
    archive = _archive(tmp_path, "locked-pack")
    binding = json.loads(json.dumps(_locks(archive)))["linux-cpu"]
    binding["baseId"] = "sha256:" + digit * 64
    binding["lock"]["variant"] = variant
    headers = {"Authorization": f"Bearer {token}"}
    submitted = client.post(
        "/v1/publish/locked-pack/versions/1.2.3",
        headers=headers,
        files={"archive": ("pack.whl", archive, "application/zip")},
        data={"locks": json.dumps({variant: binding})},
    )
    assert submitted.status_code == 202, submitted.text
    admission = AdmissionService(
        app.state.database,
        LocalFilesystemObjectStore(tmp_path / "objects"),
        settings=ServerSettings(
            object_store_root=tmp_path / "objects",
            probe_runtime_mirror=tmp_path / "absent-runtime",
        ),
        require_isolation=False,
    )
    assert admission.run_once()
    status = client.get(f"/v1/publish/{submitted.json()['candidateId']}", headers=headers).json()
    assert status["status"] == "rejected"
    assert any(
        f"missing matching base {binding['baseId']} for {variant}" in finding["message"]
        for finding in status["findings"]
    )
    assert client.get("/v1/packs/locked-pack/versions/1.2.3").status_code == 404


def test_service_refuses_incompatible_lock_with_the_user_install_reason(
    tmp_path: Path, runtime: RuntimeFixture
) -> None:
    client, app, token = _client(tmp_path)
    archive = _archive(tmp_path, "locked-pack")
    bindings = json.loads(json.dumps(_locks(archive, runtime)))
    lock = bindings["linux-cpu"]["lock"]
    lock.update(format="dinkster.pack-lock/2", engine=">=999")
    expected = (
        "pack locked-pack: dinkster-api: generation has 0.0.3, engine needs >=999. "
        "Use an own environment (0 bytes)."
    )
    with pytest.raises(ProvisionError) as refusal:
        plan_pack(
            PackLock.from_json(json.dumps(lock)),
            GenerationPackages.inspect(Path(sys.executable)),
            variant="linux-cpu",
            own_environment_size=0,
        ).require_layering()
    assert str(refusal.value) == expected
    headers = {"Authorization": f"Bearer {token}"}
    submitted = client.post(
        "/v1/publish/locked-pack/versions/1.2.3",
        headers=headers,
        files={"archive": ("pack.whl", archive, "application/zip")},
        data={"locks": json.dumps(bindings)},
    )
    assert submitted.status_code == 202, submitted.text
    admission = AdmissionService(
        app.state.database,
        LocalFilesystemObjectStore(tmp_path / "objects"),
        settings=runtime.settings(tmp_path),
        require_isolation=False,
    )
    assert admission.run_once()
    status = client.get(f"/v1/publish/{submitted.json()['candidateId']}", headers=headers).json()
    assert status["status"] == "rejected"
    assert any(
        finding["code"] == "probe.dependencies-incompatible" and finding["message"] == expected
        for finding in status["findings"]
    )
    assert client.get("/v1/packs/locked-pack/versions/1.2.3").status_code == 404


def test_selected_engine_submission_refuses_missing_dependency_lock(
    tmp_path: Path, runtime: RuntimeFixture
) -> None:
    client, app, token = _client(tmp_path)
    archive = _archive(tmp_path, "locked-pack")
    release = json.loads((runtime.mirror / "engine/index.json").read_bytes())[0]
    headers = {"Authorization": f"Bearer {token}"}
    submitted = client.post(
        "/v1/publish/locked-pack/versions/1.2.3",
        headers=headers,
        files={"archive": ("pack.whl", archive, "application/zip")},
        data={
            "engine": json.dumps(
                {
                    "commit": release["commit"],
                    "manifestDigest": "sha256:" + release["sha256"],
                }
            )
        },
    )
    assert submitted.status_code == 400, submitted.text
    assert "one locks" in submitted.json()["error"]["message"]
    assert not (tmp_path / "objects").exists()


def test_publish_api_binds_exact_engine_and_rejects_changed_or_malformed_binding(
    tmp_path: Path,
) -> None:
    client, app, token = _client(tmp_path)
    archive = _archive(tmp_path, "locked-pack")
    binding = {"commit": "a" * 40, "manifestDigest": "sha256:" + "b" * 64}
    endpoint = "/v1/publish/locked-pack/versions/1.2.3"
    headers = {"Authorization": f"Bearer {token}"}

    def publish(engine: str | None) -> Response:
        data = {"locks": json.dumps(_locks(archive))}
        if engine is not None:
            data["engine"] = engine
        return client.post(
            endpoint,
            headers=headers,
            files={"archive": ("pack.whl", archive, "application/zip")},
            data=data,
        )

    submitted = publish(json.dumps(binding))
    assert submitted.status_code == 202, submitted.text
    assert publish(json.dumps(binding)).json() == submitted.json()
    assert publish(json.dumps({**binding, "commit": "c" * 40})).status_code == 409
    assert publish(None).status_code == 409
    assert publish('{"commit":"short"}').status_code == 400
    assert publish("x" * 1025).status_code == 400
    admission = AdmissionService(
        app.state.database, LocalFilesystemObjectStore(tmp_path / "objects")
    )
    claim = admission.claim()
    assert claim is not None and claim.scan_engine == binding


def test_locked_publication_recovers_rejected_dependency_without_reset(
    tmp_path: Path, database: Database, database_url: str, runtime: RuntimeFixture
) -> None:
    client, app, token = _client(tmp_path, database_url)
    _archive(tmp_path, "locked-pack")
    manifest = tmp_path / "locked-pack" / "dinkster-pack.toml"
    manifest.write_text(manifest.read_text() + '\n[pack.dependencies]\nhelper-pack = ">=1,<2"\n')
    archive = build_registry_fixture_archive(manifest.parent)
    locks = _locks(archive, runtime)
    headers = {"Authorization": f"Bearer {token}"}
    endpoint = "/v1/publish/locked-pack/versions/1.2.3"

    def publish(payload: dict[str, object], data: bytes = archive) -> Response:
        return client.post(
            endpoint,
            headers=headers,
            files={"archive": ("pack.whl", data, "application/zip")},
            data={"locks": json.dumps(payload)},
        )

    admission = AdmissionService(
        app.state.database,
        LocalFilesystemObjectStore(tmp_path / "objects"),
        require_isolation=False,
        settings=runtime.settings(tmp_path),
    )
    first = publish(locks)
    assert first.status_code == 202
    old_id = first.json()["candidateId"]
    assert publish(locks).json() == {"candidateId": old_id, "status": "queued"}
    assert admission.run_once()
    old_url = f"/v1/publish/{old_id}"
    old_status = client.get(old_url, headers=headers).json()
    assert old_status["status"] == "rejected"
    assert any(f["code"] == "manifest.invalid" for f in old_status["findings"])

    changed_locks = json.loads(json.dumps(locks))
    changed_locks["linux-cpu"]["baseId"] = "sha256:" + "3" * 64
    assert publish(changed_locks).status_code == 409
    changed_archive = archive + b"changed"
    assert publish(_locks(changed_archive), changed_archive).status_code == 409

    helper = _archive(tmp_path, "helper-pack")
    helper_submit = client.post(
        "/v1/publish/helper-pack/versions/1.2.3", content=helper, headers=headers
    )
    assert helper_submit.status_code == 202
    assert admission.run_once()
    assert admission.status(UUID(helper_submit.json()["candidateId"])).status == "accepted"

    retry = publish(locks)
    assert retry.status_code == 202
    new_id = retry.json()["candidateId"]
    assert new_id != old_id
    assert retry.json()["status"] == "queued"
    assert publish(locks).json() == retry.json()
    claim = admission.claim()
    assert claim is not None and str(claim.id) == new_id
    assert publish(locks).json() == {"candidateId": new_id, "status": "scanning"}
    admission.process(claim)
    assert admission.status(UUID(new_id)).status == "accepted"
    assert publish(locks).json() == {"candidateId": new_id, "status": "accepted"}
    assert client.get(old_url, headers=headers).json() == old_status
    assert client.get("/v1/packs/locked-pack/versions/1.2.3").json()["state"] == "active"
    with database.session() as session:
        event = session.scalar(
            select(AuditEventRecord).where(
                AuditEventRecord.subject_id == new_id,
                AuditEventRecord.event_type == "release_candidate.submitted",
            )
        )
        assert event is not None and event.data["supersedesCandidateId"] == old_id


def test_published_locks_bind_archive_base_and_visibility(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runtime: RuntimeFixture
) -> None:
    client, app, token = _client(tmp_path)
    archive = _archive(tmp_path, "locked-pack")
    locks = json.loads(json.dumps(_locks(archive, runtime)))
    locks["linux-cpu"]["lock"]["packages"] = [
        {
            "name": "fixture",
            "version": "1.0",
            "wheels": [runtime.wheel_record("fixture", "1.0")],
        }
    ]
    locks["linux-cpu"]["lock"].update(
        format="dinkster.pack-lock/2",
        engine=">=0.0.2,<0.1",
        requirements=["dinkster-api<0.1,>=0.0.2", "fixture==1.0"],
        indexes=[runtime.wheel_origin + "/simple"],
    )
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
    query = {"baseId": runtime.base_ids["linux-cpu"]}
    assert client.get(lock_url, params=query).status_code == 404
    admission = AdmissionService(
        app.state.database,
        LocalFilesystemObjectStore(tmp_path / "objects"),
        require_isolation=False,
        settings=runtime.settings(tmp_path),
    )
    assert admission.run_once()
    assert admission.status(UUID(submitted.json()["candidateId"])).status == "accepted"
    detail = client.get("/v1/packs/locked-pack/versions/1.2.3").json()
    assert set(detail["installLocks"]) == {"linux-cpu", "win-cpu"}
    download = client.get(lock_url, params=query)
    assert download.status_code == 200
    assert download.json() == locks["linux-cpu"]["lock"]
    assert download.content == json.dumps(
        locks["linux-cpu"]["lock"], sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")
    windows = client.get(
        lock_url.replace("linux-cpu", "win-cpu"),
        params={"baseId": runtime.base_ids["win-cpu"]},
    )
    assert windows.status_code == 200
    assert windows.json() == locks["win-cpu"]["lock"]
    assert windows.content == json.dumps(
        locks["win-cpu"]["lock"], sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")
    assert windows.content != download.content
    facts = detail["installLocks"]["linux-cpu"]
    assert facts["artifactDigest"] == artifact_digest(archive)
    assert facts["digest"] == artifact_digest(download.content)
    assert facts["size"] == len(download.content)
    assert facts["baseId"] == query["baseId"]
    assert client.get(lock_url, params={"baseId": runtime.base_ids["win-cpu"]}).status_code == 409
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
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dinkster-registry",
            "admin",
            "--database-url",
            f"sqlite:///{tmp_path / 'registry.db'}",
            "--object-store-root",
            str(tmp_path / "objects"),
            "yank",
            "locked-pack",
            "1.2.3",
            "--reason",
            "Withdrawn",
        ],
    )
    main()
    assert client.get(lock_url, params=query).content == download.content
    assert client.get("/static/packs/index.json").json()["items"] == []
    for variant in ("linux-cpu", "win-cpu"):
        assert "locked_pack-1.2.3" not in client.get(f"/static/{variant}/simple/locked-pack/").text

    with app.state.database.session() as session, session.begin():
        from dinkster_registry_service.database import ReleaseRecord

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


def test_format2_lock_validation_preserves_legacy_exact_locks(
    tmp_path: Path, runtime: RuntimeFixture
) -> None:
    client, app, token = _client(tmp_path)
    archive = _archive(tmp_path, "locked-pack")
    locks = json.loads(json.dumps(_locks(archive, runtime)))
    lock = locks["linux-cpu"]["lock"]
    lock.update(format="dinkster.pack-lock/2", engine=">=0.0.2,<0.1")
    api = {
        "name": "dinkster-api",
        "version": "0.0.3",
        "wheels": [runtime.wheel_record("dinkster-api", "0.0.3")],
    }
    locks["win-cpu"]["lock"]["packages"] = [api]

    def publish(payload: dict[str, object]) -> Response:
        return client.post(
            "/v1/publish/locked-pack/versions/1.2.3",
            headers={"Authorization": f"Bearer {token}"},
            files={"archive": ("pack.whl", archive, "application/zip")},
            data={"locks": json.dumps(payload)},
        )

    for changes, reason in (
        ({"engine": ""}, "engine API requires a nonempty compatibility range"),
        ({"engine": 7}, "engine compatibility range must be a string"),
        ({"packages": [api]}, "engine API must not also be an exact lock package"),
        ({"format": "dinkster.pack-lock/3"}, "unsupported dependency lock format"),
    ):
        invalid = json.loads(json.dumps(locks))
        invalid["linux-cpu"]["lock"].update(changes)
        response = publish(invalid)
        assert response.status_code == 400, response.text
        assert reason in response.json()["error"]["message"]
        assert not (tmp_path / "objects").exists()

    submitted = publish(locks)
    assert submitted.status_code == 202, submitted.text
    admission = AdmissionService(
        app.state.database,
        LocalFilesystemObjectStore(tmp_path / "objects"),
        require_isolation=False,
        settings=runtime.settings(tmp_path),
    )
    assert admission.run_once()
    assert admission.status(UUID(submitted.json()["candidateId"])).status == "accepted"
    for variant, binding in locks.items():
        response = client.get(
            f"/v1/packs/locked-pack/versions/1.2.3/locks/{variant}",
            params={"baseId": binding["baseId"]},
        )
        assert response.status_code == 200
        assert response.json() == binding["lock"]


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
    runtime: RuntimeFixture,
) -> None:
    client, app, token = _client(tmp_path)
    archive = _archive(tmp_path, "locked-pack")
    submitted = client.post(
        "/v1/publish/locked-pack/versions/1.2.3",
        headers={"Authorization": f"Bearer {token}"},
        files={"archive": ("pack.zip", archive, "application/zip")},
        data={"locks": json.dumps(_locks(archive, runtime))},
    )
    assert submitted.status_code == 202

    class UnavailableLockStorage(LocalFilesystemObjectStore):
        unavailable = True

        def put(self, key: str, data: bytes) -> None:
            if key.startswith("pack-locks/") and self.unavailable:
                raise ObjectStoreError("synthetic lock storage outage")
            super().put(key, data)

    store = UnavailableLockStorage(tmp_path / "objects")
    admission = AdmissionService(
        app.state.database, store, require_isolation=False, settings=runtime.settings(tmp_path)
    )
    candidate = UUID(submitted.json()["candidateId"])
    assert admission.run_once()
    assert admission.status(candidate).status == "promoting"
    endpoint = "/v1/packs/locked-pack/versions/1.2.3"
    assert client.get(endpoint).status_code == 404
    assert (
        client.get(
            endpoint + "/locks/linux-cpu", params={"baseId": runtime.base_ids["linux-cpu"]}
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
    for variant, base_id in (
        ("linux-cpu", runtime.base_ids["linux-cpu"]),
        ("win-cpu", runtime.base_ids["win-cpu"]),
    ):
        response = client.get(endpoint + f"/locks/{variant}", params={"baseId": base_id})
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
