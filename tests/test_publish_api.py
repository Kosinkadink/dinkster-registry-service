from __future__ import annotations

import json
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
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
from test_wheels import wheel_bytes

from dinkster_registry_service.admission import AdmissionService, LeaseLost
from dinkster_registry_service.app import create_app
from dinkster_registry_service.artifacts import build_registry_fixture_archive
from dinkster_registry_service.cli import main
from dinkster_registry_service.database import (
    AuditEventRecord,
    Database,
    NamespaceGrantRecord,
    OutboxRecord,
    PackRecord,
    ReleaseCandidateRecord,
    ReleaseRecord,
    ReleaseSetRecord,
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


def _publish_set(
    client: TestClient,
    token: str,
    members: list[tuple[str, bytes]],
) -> Response:
    return client.post(
        "/v1/publish-sets",
        headers={"Authorization": f"Bearer {token}"},
        data={
            "manifest": json.dumps(
                {
                    "members": [
                        {"name": name, "version": "1.2.3", "archive": f"wheel{index}"}
                        for index, (name, _) in enumerate(members)
                    ]
                }
            )
        },
        files={
            f"wheel{index}": (f"{name}.whl", data) for index, (name, data) in enumerate(members)
        },
    )


def test_publish_set_persists_all_members_and_replays_without_changing_expiry(
    tmp_path: Path,
    database: Database,
    database_url: str,
) -> None:
    client, app, token = _client(tmp_path, database_url)
    members = [(name, _archive(tmp_path, name)) for name in ("set-alpha", "set-beta")]
    response = _publish_set(client, token, members)
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "queued"
    assert {row["packName"] for row in body["members"]} == {"set-alpha", "set-beta"}
    assert {row["status"] for row in body["members"]} == {"queued"}
    assert {row["artifactDigest"] for row in body["members"]} == {
        artifact_digest(data) for _, data in members
    }
    replay = _publish_set(client, token, list(reversed(members)))
    assert replay.status_code == 202, replay.text
    assert replay.json() == body
    with app.state.database.session() as session:
        assert len(list(session.scalars(select(ReleaseSetRecord)))) == 1
        assert len(list(session.scalars(select(ReleaseCandidateRecord)))) == 2
    status = client.get(
        f"/v1/publish-sets/{body['setId']}", headers={"Authorization": f"Bearer {token}"}
    )
    assert status.status_code == 200
    assert status.json() == body

    changed = _publish_set(
        client,
        token,
        [
            ("set-rolled-back", _archive(tmp_path, "set-rolled-back")),
            ("set-alpha", members[0][1] + b"changed"),
        ],
    )
    assert changed.status_code == 409
    with app.state.database.session() as session:
        assert len(list(session.scalars(select(ReleaseSetRecord)))) == 1
        assert len(list(session.scalars(select(ReleaseCandidateRecord)))) == 2


@pytest.mark.parametrize("publisher,limit", [("example-org", 8), ("dinkster", 64)])
def test_publish_set_enforces_authenticated_tier_boundaries(
    tmp_path: Path,
    publisher: str,
    limit: int,
) -> None:
    client, app, token = _client(tmp_path)
    if publisher == "dinkster":
        principals = PrincipalRepository(app.state.database)
        now = datetime.now(UTC)
        principals.register_publisher(publisher, "owner", now.isoformat())
        token, _ = principals.mint_token(
            publisher, "owner", now.isoformat(), (now + timedelta(hours=1)).isoformat()
        )
    members = [
        (f"tier-pack-{index}", b"queued for full scanner validation") for index in range(limit + 1)
    ]
    refused = _publish_set(client, token, members)
    assert refused.status_code == 400, refused.text
    assert f"Requested {limit + 1} members; publisher limit is {limit}" in refused.text
    accepted = _publish_set(client, token, members[:-1])
    assert accepted.status_code == 202, accepted.text
    assert len(accepted.json()["members"]) == limit


def test_publish_set_checks_every_scope_and_duplicate_before_persisting(tmp_path: Path) -> None:
    client, app, token = _client(tmp_path)
    principals = PrincipalRepository(app.state.database)
    now = datetime.now(UTC)
    scoped, _ = principals.mint_token(
        "example-org",
        "owner",
        now.isoformat(),
        (now + timedelta(hours=1)).isoformat(),
        pack="set-allowed",
    )
    members = [("set-allowed", b"first"), ("set-forbidden", b"second")]
    assert _publish_set(client, scoped, members).status_code == 409
    duplicate = _publish_set(client, token, [members[0], members[0]])
    assert duplicate.status_code == 400
    assert "duplicate pack identity" in duplicate.text
    with app.state.database.session() as session:
        assert list(session.scalars(select(ReleaseSetRecord))) == []
        assert list(session.scalars(select(ReleaseCandidateRecord))) == []
    assert client.post("/v1/publish-sets", content=b"not authenticated").status_code == 401


@pytest.mark.parametrize("terminal", ["expired", "rejected"])
def test_publish_set_releases_all_members_but_preserves_immutable_bindings(
    tmp_path: Path, database: Database, database_url: str, terminal: str
) -> None:
    client, app, token = _client(tmp_path, database_url)
    members = [(name, _archive(tmp_path, name)) for name in ("set-first", "set-second")]
    submitted = _publish_set(client, token, members).json()
    set_id = UUID(submitted["setId"])
    store = LocalFilesystemObjectStore(tmp_path / "objects")
    admission = AdmissionService(app.state.database, store, require_isolation=False)
    late_claim = admission.claim() if terminal == "expired" else None
    with app.state.database.session() as session, session.begin():
        release_set = session.get(ReleaseSetRecord, set_id)
        assert release_set is not None
        if terminal == "expired":
            release_set.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        else:
            candidate = session.get(ReleaseCandidateRecord, UUID(release_set.members[-1]))
            assert candidate is not None
            candidate.status = "rejected"
            candidate.status_reason = "integrity.invalid"
        old_keys = [
            row.object_key
            for row in session.scalars(
                select(ReleaseCandidateRecord).where(ReleaseCandidateRecord.set_id == set_id)
            )
        ]
    assert admission.run_once(deliver_indexes=False)
    if late_claim is not None:
        with pytest.raises(LeaseLost):
            admission.process(late_claim)
    status = client.get(
        f"/v1/publish-sets/{set_id}", headers={"Authorization": f"Bearer {token}"}
    ).json()
    assert status["status"] == terminal
    assert {member["status"] for member in status["members"]} == {"rejected"}
    if terminal == "rejected":
        assert {member["reason"] for member in status["members"]} == {
            "set.member-rejected",
            "integrity.invalid",
        }
    else:
        assert {member["reason"] for member in status["members"]} == {"set.expired"}
    for name, _ in members:
        assert client.get(f"/v1/packs/{name}").status_code == 404
    assert all(store.exists(key) for key in old_keys)

    replay = _publish_set(client, token, list(reversed(members)))
    assert replay.status_code == 202, replay.text
    assert replay.json()["setId"] != str(set_id)
    assert {member["status"] for member in replay.json()["members"]} == {"queued"}
    changed = _publish_set(client, token, [(members[0][0], members[0][1] + b"changed")])
    assert changed.status_code == 409
    assert admission.run_once(deliver_indexes=False)
    assert not any(store.exists(key) for key in old_keys)
    with app.state.database.session() as session:
        pending = list(
            session.scalars(
                select(ReleaseCandidateRecord).where(
                    ReleaseCandidateRecord.set_id == UUID(replay.json()["setId"])
                )
            )
        )
        assert all(store.exists(row.object_key) for row in pending)
        assert len(pending) == 2
        assert not list(
            session.scalars(select(OutboxRecord).where(OutboxRecord.topic == "indexes.rebuild"))
        )


def test_publish_set_expiry_cleanup_retries_without_blocking_resubmission(tmp_path: Path) -> None:
    client, app, token = _client(tmp_path)
    members = [("set-retry", _archive(tmp_path, "set-retry"))]
    submitted = _publish_set(client, token, members).json()

    class UnavailableCleanup(LocalFilesystemObjectStore):
        unavailable = True

        def remove(self, key: str) -> None:
            if self.unavailable:
                raise ObjectStoreError("synthetic cleanup outage")
            super().remove(key)

    store = UnavailableCleanup(tmp_path / "objects")
    admission = AdmissionService(app.state.database, store, require_isolation=False)
    with app.state.database.session() as session, session.begin():
        release_set = session.get(ReleaseSetRecord, UUID(submitted["setId"]))
        assert release_set is not None
        release_set.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    assert admission.run_once(deliver_indexes=False)
    assert admission.run_once(deliver_indexes=False)
    replay = _publish_set(client, token, members)
    assert replay.status_code == 202, replay.text
    assert replay.json()["setId"] != submitted["setId"]
    store.unavailable = False
    with app.state.database.session() as session, session.begin():
        cleanup = session.scalar(
            select(OutboxRecord).where(OutboxRecord.topic == "release_set.cleanup")
        )
        assert cleanup is not None
        cleanup.available_at = datetime.now(UTC) - timedelta(seconds=1)
    assert admission.run_once(deliver_indexes=False)
    status = client.get(
        f"/v1/publish-sets/{submitted['setId']}", headers={"Authorization": f"Bearer {token}"}
    )
    assert status.json()["status"] == "expired"


@pytest.mark.parametrize("storage_failure", [False, True])
def test_publish_set_keeps_scanned_members_private_until_one_activation_transaction(
    tmp_path: Path, database: Database, database_url: str, storage_failure: bool
) -> None:
    client, app, token = _client(tmp_path, database_url)
    members = [(name, _archive(tmp_path, name)) for name in ("set-alpha", "set-zeta")]
    submitted = _publish_set(client, token, members).json()
    auth = {"Authorization": f"Bearer {token}"}

    class UnavailableSecondArtifact(LocalFilesystemObjectStore):
        unavailable = storage_failure

        def put(self, key: str, data: bytes) -> None:
            if data == members[-1][1] and key.startswith("artifacts/") and self.unavailable:
                raise ObjectStoreError("synthetic second artifact outage")
            super().put(key, data)

    store = UnavailableSecondArtifact(tmp_path / "objects")
    admission = AdmissionService(app.state.database, store, require_isolation=False)
    for _ in members:
        assert admission.run_once(deliver_indexes=False)
        for name, _ in members:
            assert client.get(f"/v1/packs/{name}").status_code == 404
    status = client.get(f"/v1/publish-sets/{submitted['setId']}", headers=auth).json()
    assert status["status"] == "queued"
    assert {row["status"] for row in status["members"]} == {"promoting"}
    assert admission.run_once(deliver_indexes=False)
    if storage_failure:
        assert (
            client.get(f"/v1/publish-sets/{submitted['setId']}", headers=auth).json()["status"]
            == "queued"
        )
        for name, _ in members:
            assert client.get(f"/v1/packs/{name}").status_code == 404
        with app.state.database.session() as session, session.begin():
            event = session.scalar(
                select(OutboxRecord).where(OutboxRecord.topic == "release_set.promote")
            )
            assert event is not None
            event.available_at = datetime.now(UTC) - timedelta(seconds=1)
        store.unavailable = False
        assert admission.run_once(deliver_indexes=False)
    status = client.get(f"/v1/publish-sets/{submitted['setId']}", headers=auth).json()
    assert status["status"] == "accepted"
    assert {row["status"] for row in status["members"]} == {"accepted"}
    for name, data in members:
        detail = client.get(f"/v1/packs/{name}/versions/1.2.3")
        assert detail.status_code == 200, detail.text
        assert artifact_digest(data) in detail.text
    with app.state.database.session() as session:
        events = list(
            session.scalars(select(OutboxRecord).where(OutboxRecord.topic == "indexes.rebuild"))
        )
        assert len(events) == 1
        assert events[0].state == "pending"
    replay = _publish_set(client, token, list(reversed(members)))
    assert replay.status_code == 202
    assert replay.json() == status


@pytest.mark.parametrize("stop", ["expiry", "revocation"])
def test_publish_set_rechecks_deadline_and_authority_before_activation(
    tmp_path: Path, database: Database, database_url: str, stop: str
) -> None:
    client, app, token = _client(tmp_path, database_url)
    members = [(name, _archive(tmp_path, name)) for name in ("set-earlier", "set-later")]
    submitted = _publish_set(client, token, members).json()
    admission = AdmissionService(
        app.state.database,
        LocalFilesystemObjectStore(tmp_path / "objects"),
        require_isolation=False,
    )
    for _ in members:
        assert admission.run_once(deliver_indexes=False)
    if stop == "expiry":
        with app.state.database.session() as session, session.begin():
            release_set = session.get(ReleaseSetRecord, UUID(submitted["setId"]))
            assert release_set is not None
            release_set.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    else:
        principals = PrincipalRepository(app.state.database)
        now = datetime.now(UTC)
        identity = principals.verify_token(token, now.isoformat())
        principals.revoke_token(identity.token_id, "owner", now.isoformat(), "rotated")
        token, _ = principals.mint_token(
            "example-org", "owner", now.isoformat(), (now + timedelta(hours=1)).isoformat()
        )
    assert admission.deliver_one_set_promotion()
    assert admission.run_once(deliver_indexes=False)
    status = client.get(
        f"/v1/publish-sets/{submitted['setId']}", headers={"Authorization": f"Bearer {token}"}
    ).json()
    assert status["status"] == ("expired" if stop == "expiry" else "rejected")
    assert {row["status"] for row in status["members"]} == {"rejected"}
    for name, _ in members:
        assert client.get(f"/v1/packs/{name}").status_code == 404


def test_publish_set_scan_failure_keeps_ready_sibling_private(tmp_path: Path) -> None:
    client, app, token = _client(tmp_path)
    members = [("set-valid", _archive(tmp_path, "set-valid")), ("set-broken", b"not a wheel")]
    submitted = _publish_set(client, token, members).json()
    admission = AdmissionService(
        app.state.database,
        LocalFilesystemObjectStore(tmp_path / "objects"),
        require_isolation=False,
    )
    assert admission.run_once(deliver_indexes=False)
    assert admission.run_once(deliver_indexes=False)
    assert admission.run_once(deliver_indexes=False)
    status = client.get(
        f"/v1/publish-sets/{submitted['setId']}", headers={"Authorization": f"Bearer {token}"}
    ).json()
    assert status["status"] == "rejected"
    assert {row["status"] for row in status["members"]} == {"rejected"}
    broken = next(row for row in status["members"] if row["packName"] == "set-broken")
    assert any(row["effect"] == "block" for row in broken["findings"])
    assert client.get("/v1/packs/set-valid").status_code == 404
    assert client.get("/v1/packs/set-broken").status_code == 404


def test_publish_set_preserves_installation_locks_through_activation_and_cleanup(
    tmp_path: Path, runtime: RuntimeFixture
) -> None:
    client, app, token = _client(tmp_path)
    archive = _archive(tmp_path, "locked-pack")
    submitted = client.post(
        "/v1/publish-sets",
        headers={"Authorization": f"Bearer {token}"},
        files={"wheel": ("locked-pack.whl", archive)},
        data={
            "manifest": json.dumps(
                {
                    "members": [
                        {
                            "name": "locked-pack",
                            "version": "1.2.3",
                            "archive": "wheel",
                            "locks": _locks(archive, runtime),
                        }
                    ]
                }
            ),
        },
    )
    assert submitted.status_code == 202, submitted.text
    admission = AdmissionService(
        app.state.database,
        LocalFilesystemObjectStore(tmp_path / "objects"),
        settings=runtime.settings(tmp_path),
        require_isolation=False,
    )
    for _ in range(3):
        assert admission.run_once(deliver_indexes=False)
    endpoint = "/v1/packs/locked-pack/versions/1.2.3"
    detail = client.get(endpoint)
    assert detail.status_code == 200, detail.text
    for variant, binding in detail.json()["installLocks"].items():
        response = client.get(endpoint + f"/locks/{variant}", params={"baseId": binding["baseId"]})
        assert response.status_code == 200
        assert artifact_digest(response.content) == binding["digest"]
    with app.state.database.session() as session:
        member = session.get(
            ReleaseCandidateRecord, UUID(submitted.json()["members"][0]["candidateId"])
        )
        assert member is not None
        assert not admission.object_store.exists(member.object_key)
        for variant in member.install_locks:
            assert not admission.object_store.exists(f"quarantine/locks/{member.id}/{variant}.json")


@pytest.mark.parametrize("accepted", [False, True])
def test_publish_set_review_decision_never_activates_one_member_alone(
    tmp_path: Path, accepted: bool
) -> None:
    client, app, token = _client(tmp_path)
    members = [
        ("set-clean", _archive(tmp_path, "set-clean")),
        ("set-native", _archive(tmp_path, "set-native", native=True)),
    ]
    submitted = _publish_set(client, token, members).json()
    admission = AdmissionService(
        app.state.database,
        LocalFilesystemObjectStore(tmp_path / "objects"),
        require_isolation=False,
    )
    for _ in members:
        assert admission.run_once(deliver_indexes=False)
    status = client.get(
        f"/v1/publish-sets/{submitted['setId']}", headers={"Authorization": f"Bearer {token}"}
    ).json()
    review = next(row for row in status["members"] if row["packName"] == "set-native")
    assert review["status"] == "review"
    decision = client.post(
        f"/v1/reviews/{review['candidateId']}",
        headers={"Authorization": f"Bearer {token}"},
        json={"decision": "accept" if accepted else "reject", "reason": "native inventory review"},
    )
    assert decision.status_code == 200, decision.text
    assert decision.json()["status"] == ("promoting" if accepted else "rejected")
    for name, _ in members:
        assert client.get(f"/v1/packs/{name}").status_code == 404
    assert admission.run_once(deliver_indexes=False)
    status = client.get(
        f"/v1/publish-sets/{submitted['setId']}", headers={"Authorization": f"Bearer {token}"}
    ).json()
    assert status["status"] == ("accepted" if accepted else "rejected")
    assert {row["status"] for row in status["members"]} == {status["status"]}


def test_publish_set_concurrent_workers_scan_distinct_members_and_activate_once(
    tmp_path: Path, database: Database, database_url: str
) -> None:
    client, app, token = _client(tmp_path, database_url)
    members = [(name, _archive(tmp_path, name)) for name in ("set-early", "set-late")]
    submitted = _publish_set(client, token, members).json()
    services = [
        AdmissionService(
            app.state.database,
            LocalFilesystemObjectStore(tmp_path / "objects"),
            require_isolation=False,
            worker_id=f"worker-{index}",
        )
        for index in range(2)
    ]
    claims = [service.claim() for service in services]
    assert all(claim is not None for claim in claims)
    assert len({claim.id for claim in claims if claim is not None}) == 2
    with ThreadPoolExecutor(max_workers=2) as executor:
        scans = [
            executor.submit(service.process, claim)
            for service, claim in zip(services, claims, strict=True)
            if claim is not None
        ]
        for scan in scans:
            scan.result(timeout=60)
        for name, _ in members:
            assert client.get(f"/v1/packs/{name}").status_code == 404
        activations = [executor.submit(service.deliver_one_set_promotion) for service in services]
        assert sum(activation.result(timeout=30) for activation in activations) == 1
    status = client.get(
        f"/v1/publish-sets/{submitted['setId']}", headers={"Authorization": f"Bearer {token}"}
    ).json()
    assert status["status"] == "accepted"
    assert {row["status"] for row in status["members"]} == {"accepted"}
    with app.state.database.session() as session:
        activation_events = list(
            session.scalars(
                select(AuditEventRecord).where(
                    AuditEventRecord.event_type == "release_set.activated"
                )
            )
        )
        assert len(activation_events) == 1
        assert set(activation_events[0].data["members"]) == {
            row["candidateId"] for row in status["members"]
        }


@pytest.mark.parametrize("failure", [None, "range", "cycle", "other-set"])
def test_publish_set_resolves_transitive_pack_and_library_siblings_without_publication(
    tmp_path: Path, failure: str | None
) -> None:
    client, app, token = _client(tmp_path)
    consumer = "set-consumer"
    helper = "set-helper"
    for name in (consumer, helper):
        _archive(tmp_path, name)
    manifest = tmp_path / consumer / "dinkster-pack.toml"
    manifest.write_text(manifest.read_text() + '\n[pack.dependencies]\nset-helper = ">=1,<2"\n')
    nodes = tmp_path / consumer / "nodes.py"
    nodes.write_text(
        "from set_helper.helpers import VALUE\nassert VALUE == 43\n"
        + nodes.read_text().replace("version=2,", "version=VALUE,")
    )
    manifest = tmp_path / helper / "dinkster-pack.toml"
    manifest.write_text(
        manifest.read_text().replace("[pack]\n", '[pack]\nrequires = ["set-library==1.2.3"]\n')
        + ('\n[pack.dependencies]\nset-consumer = ">=1,<2"\n' if failure == "cycle" else "")
    )
    (tmp_path / helper / "helpers.py").write_text(
        "from set_library import ANSWER\nVALUE = ANSWER + 2\n"
    )
    library = wheel_bytes(
        name="set-library",
        package="set_library",
        library=True,
        requirements=("set-leaf>=2" if failure == "range" else "set-leaf==1.2.3",),
        extra={
            "set_library/__init__.py": b"from set_leaf import ANSWER as LEAF\nANSWER = LEAF + 4\n"
        },
    )
    leaf = wheel_bytes(
        name="set-leaf",
        package="set_leaf",
        library=True,
        requirements=(),
        extra={"set_leaf/__init__.py": b"ANSWER = 37\n"},
    )
    members = [
        (consumer, build_registry_fixture_archive(tmp_path / consumer)),
        (helper, build_registry_fixture_archive(tmp_path / helper)),
        ("set-library", library),
        ("set-leaf", leaf),
    ]
    submitted = _publish_set(
        client, token, members[:1] if failure == "other-set" else members
    ).json()
    if failure == "other-set":
        assert _publish_set(client, token, members[1:]).status_code == 202
    store = LocalFilesystemObjectStore(tmp_path / "objects")
    admission = AdmissionService(app.state.database, store, require_isolation=False)
    auth = {"Authorization": f"Bearer {token}"}
    for _ in range(8):
        assert admission.run_once(deliver_indexes=False)
        status = client.get(f"/v1/publish-sets/{submitted['setId']}", headers=auth).json()
        if status["status"] != "queued":
            break
        assert client.get(f"/v1/packs/{consumer}").status_code == 404
    assert status["status"] == ("rejected" if failure else "accepted"), status
    if failure:
        assert client.get(f"/v1/packs/{consumer}").status_code == 404
        assert any(row["findings"] for row in status["members"])
    else:
        assert {row["status"] for row in status["members"]} == {"accepted"}
        with app.state.database.session() as session:
            release = session.scalar(
                select(ReleaseRecord).join(PackRecord).where(PackRecord.name == consumer)
            )
            assert release is not None
            assert release.manifest["pythonRequirements"] == []
        assert admission.run_once(deliver_indexes=False)
        assert admission.run_once()
        schemas = json.loads(store.read(f"static/packs/{consumer}/1.2.3/schemas.json"))["schemas"]
        assert (
            next(row for row in schemas if row["nodeType"] == consumer + ".resize")["schema"][
                "version"
            ]
            == 43
        )


def test_publish_set_refuses_dependency_withdrawn_after_its_successful_probe(
    tmp_path: Path,
) -> None:
    client, app, token = _client(tmp_path)
    library = wheel_bytes(name="set-lib", package="set_lib", library=True, requirements=())
    admission = AdmissionService(
        app.state.database,
        LocalFilesystemObjectStore(tmp_path / "objects"),
        require_isolation=False,
    )
    candidate = admission.submit(library, pack_name="set-lib", version="1.2.3")
    assert admission.run_once()
    assert admission.status(candidate).status == "accepted"
    name = "set-dependent"
    _archive(tmp_path, name)
    manifest = tmp_path / name / "dinkster-pack.toml"
    manifest.write_text(
        manifest.read_text().replace("[pack]\n", '[pack]\nrequires = ["set-lib==1.2.3"]\n')
    )
    nodes = tmp_path / name / "nodes.py"
    nodes.write_text("from set_lib import ANSWER\nassert ANSWER == 42\n" + nodes.read_text())
    submitted = _publish_set(
        client, token, [(name, build_registry_fixture_archive(tmp_path / name))]
    ).json()
    assert admission.run_once(deliver_indexes=False)
    admission.yank("set-lib", "1.2.3", reason="withdrawn after probe")
    assert admission.run_once(deliver_indexes=False)
    assert admission.run_once(deliver_indexes=False)
    status = client.get(
        f"/v1/publish-sets/{submitted['setId']}", headers={"Authorization": f"Bearer {token}"}
    ).json()
    assert status["status"] == "rejected", status
    assert any(
        "no longer eligible" in finding["message"]
        for row in status["members"]
        for finding in row["findings"]
    )
    assert client.get(f"/v1/packs/{name}").status_code == 404
