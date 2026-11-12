from __future__ import annotations

import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from dinkster_registry.archive_admission import ProbeSettings
from fastapi.testclient import TestClient
from runtime_fixture import RuntimeFixture

from dinkster_registry_service.admission import (
    AdmissionService,
    CandidateClaim,
    quarantine_object_key,
)
from dinkster_registry_service.app import create_app
from dinkster_registry_service.artifacts import build_registry_fixture_archive
from dinkster_registry_service.database import Database, ReleaseCandidateRecord
from dinkster_registry_service.digests import artifact_digest
from dinkster_registry_service.pack_locks import quarantine_lock_key
from dinkster_registry_service.principals import PrincipalRepository
from dinkster_registry_service.scan_execution import ProbeDependencies, run_prepared_probe
from dinkster_registry_service.seed import FIXTURE_ROOT
from dinkster_registry_service.settings import ServerSettings
from dinkster_registry_service.wheels import extracted_wheel, inspect_wheel

TOKEN = "isolated-scanner-test-capability"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
PREFIX = "/internal/scanner"


@pytest.mark.parametrize("backend", ["postgresql", "sqlite"])
def test_assignment_reads_require_a_live_fence_and_cannot_publish(
    database: Database, tmp_path: Path, backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def reject_scan(self: AdmissionService, claim: CandidateClaim) -> None:
        raise AssertionError("Web assignment requests must not execute a scan")

    monkeypatch.setattr(AdmissionService, "process", reject_scan)
    settings = ServerSettings(
        database_url=str(database.engine.url.render_as_string(hide_password=False))
        if backend == "postgresql"
        else f"sqlite:///{tmp_path / 'catalog.db'}",
        object_store_root=tmp_path / "objects",
        scanner_token_sha256=hashlib.sha256(TOKEN.encode()).hexdigest(),
        cursor_secret=b"control-plane-only-cursor-secret",
    )
    app = create_app(settings)
    service = AdmissionService(app.state.database, app.state.object_store, settings=settings)
    principals = PrincipalRepository(app.state.database)
    now = datetime.now(UTC)
    principals.register_user("owner")
    principals.register_publisher("example-org", "owner", now.isoformat())
    publisher_token, _ = principals.mint_token(
        "example-org", "owner", now.isoformat(), (now + timedelta(days=1)).isoformat()
    )
    archive = build_registry_fixture_archive(FIXTURE_ROOT / "example-pack")
    locks = {
        variant: {
            "baseId": "sha256:" + digit * 64,
            "artifactDigest": artifact_digest(archive),
            "lock": {
                "format": "dinkster.pack-lock/1",
                "pack": "example-pack",
                "variant": variant,
                "requiresPython": ">=3.12",
                "requirements": [],
                "indexes": [],
                "packages": [],
            },
        }
        for variant, digit in (("linux-cpu", "1"), ("win-cpu", "2"))
    }
    candidate_id = service.submit(
        archive, pack_name="example-pack", version="1.2.3", locks=json.dumps(locks).encode()
    )
    with TestClient(app) as client:
        assert client.post(f"{PREFIX}/claim").status_code == 401
        assert (
            client.post(
                f"{PREFIX}/claim", headers={"Authorization": f"Bearer {publisher_token}"}
            ).status_code
            == 401
        )
        assert client.post(f"{PREFIX}/claim", headers=HEADERS, json={}).status_code == 400
        assert service.status(candidate_id).attempts == 0
        with ThreadPoolExecutor(max_workers=2) as executor:
            responses = list(
                executor.map(lambda _: client.post(f"{PREFIX}/claim", headers=HEADERS), range(2))
            )
        assert sorted(response.status_code for response in responses) == [200, 204]
        claimed = next(response for response in responses if response.status_code == 200).json()
        assert claimed["candidateId"] == str(candidate_id)
        assert claimed["artifactSize"] == len(archive) and claimed["attempt"] == 1
        assert not {
            "objectKey",
            "database_url",
            "cursor_secret",
            "scanner_token_sha256",
        }.intersection(claimed)
        assert set(claimed["probeSettings"]) == {
            "probe_timeout_seconds",
            "probe_dependency_timeout_seconds",
            "probe_package_index_url",
            "probe_output_limit_bytes",
            "probe_operator_tail_bytes",
            "probe_dependency_source",
        }
        assert settings.cursor_secret.decode() not in json.dumps(claimed)
        headers = {**HEADERS, "X-Scanner-Lease": claimed["leaseToken"]}
        path = f"{PREFIX}/{candidate_id}"
        assert set(claimed["installLocks"]) == set(locks)
        response = client.get(f"{path}/locks", headers=headers)
        assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
        transferred = {variant: base64.b64decode(data) for variant, data in response.json().items()}
        for variant, data in transferred.items():
            assert json.loads(data) == locks[variant]["lock"]
            assert artifact_digest(data) == claimed["installLocks"][variant]["digest"]
            assert len(data) == claimed["installLocks"][variant]["size"]
        assert client.get(f"{path}/locks").status_code == 401
        assert client.get(f"{path}/locks?key=private", headers=headers).status_code == 400
        key = quarantine_lock_key(candidate_id, "linux-cpu")
        app.state.object_store.remove(key)
        app.state.object_store.put(key, b"changed")
        assert client.get(f"{path}/locks", headers=headers).status_code == 503
        assert service.status(candidate_id).status == "scanning"
        app.state.object_store.remove(key)
        assert client.get(f"{path}/locks", headers=headers).status_code == 503
        app.state.object_store.put(key, transferred["linux-cpu"])
        response = client.get(f"{path}/input", headers=headers)
        assert response.status_code == 200 and response.content == archive
        assert response.headers["cache-control"] == "no-store"
        response = client.get(f"{path}/dependencies", headers=headers)
        assert response.status_code == 200
        assert response.json() == {"helperWheels": [], "libraryWheels": [], "requirements": []}
        assert response.headers["cache-control"] == "no-store"
        assert client.get(f"{path}/dependencies").status_code == 401
        assert client.get(f"{path}/dependencies?key=private", headers=headers).status_code == 400
        app.state.object_store.remove(quarantine_object_key(candidate_id))
        unavailable = client.get(f"{path}/input", headers=headers)
        assert unavailable.status_code == 503 and unavailable.json()["error"]["retryable"] is True
        assert client.get(f"{path}/dependencies", headers=headers).status_code == 503
        assert service.status(candidate_id).status == "scanning"
        app.state.object_store.put(quarantine_object_key(candidate_id), archive)
        assert (
            client.get(f"{path}/input?key=static/packs/index.json", headers=headers).status_code
            == 400
        )
        assert client.get(f"{PREFIX}/{uuid4()}/input", headers=headers).status_code == 409
        assert (
            client.get(
                f"{path}/input", headers={**HEADERS, "X-Scanner-Lease": str(uuid4())}
            ).status_code
            == 409
        )
        assert client.get(f"{path}/input").status_code == 401
        with app.state.database.session() as session:
            candidate = session.get(ReleaseCandidateRecord, candidate_id)
            assert candidate is not None
            before_heartbeat = candidate.lease_expires_at
        assert client.post(f"{path}/heartbeat", headers=headers).status_code == 204
        with app.state.database.session() as session:
            candidate = session.get(ReleaseCandidateRecord, candidate_id)
            assert candidate is not None and candidate.lease_expires_at is not None
            assert before_heartbeat is not None
            assert candidate.lease_expires_at > before_heartbeat
        assert (
            client.put("/static/packs/index.json", headers=HEADERS, content=b"changed").status_code
            == 400
        )
        assert not app.state.object_store.exists("static/packs/index.json")
        assert (
            client.post("/v1/publish/example-pack/versions/1.2.3", headers=HEADERS).status_code
            == 401
        )
        with app.state.database.session() as session, session.begin():
            candidate = session.get(ReleaseCandidateRecord, candidate_id)
            assert candidate is not None
            candidate.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        assert client.get(f"{path}/input", headers=headers).status_code == 409
        assert client.get(f"{path}/locks", headers=headers).status_code == 409
        assert client.get(f"{path}/dependencies", headers=headers).status_code == 409
        assert client.post(f"{path}/heartbeat", headers=headers).status_code == 409
        recovered = client.post(f"{PREFIX}/claim", headers=HEADERS).json()
        assert recovered["candidateId"] == str(candidate_id) and recovered["attempt"] == 2
        assert recovered["leaseToken"] != claimed["leaseToken"]
        assert recovered["installLocks"] == claimed["installLocks"]
        assert client.get(f"{path}/locks", headers=headers).status_code == 409
        assert client.post(f"{path}/heartbeat", headers=headers).status_code == 409
        assert client.get(f"{path}/dependencies", headers=headers).status_code == 409
        headers["X-Scanner-Lease"] = recovered["leaseToken"]
        assert client.get(f"{path}/input", headers=headers).content == archive
        with app.state.database.session() as session:
            candidate = session.get(ReleaseCandidateRecord, UUID(recovered["candidateId"]))
            assert candidate is not None
            assert candidate.status == "scanning" and candidate.release_id is None


def test_unconfigured_scanner_token_does_not_enable_worker_access(tmp_path: Path) -> None:
    app = create_app(
        ServerSettings(
            database_url=f"sqlite:///{tmp_path / 'catalog.db'}",
            object_store_root=tmp_path / "objects",
        )
    )
    with TestClient(app) as client:
        assert client.post(f"{PREFIX}/claim", headers=HEADERS).status_code == 401


def test_assigned_locks_execute_without_catalog_or_object_store_authority(
    tmp_path: Path, runtime: RuntimeFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = runtime.settings(
        tmp_path,
        database_url=f"sqlite:///{tmp_path / 'catalog.db'}",
        scanner_token_sha256=hashlib.sha256(TOKEN.encode()).hexdigest(),
    )
    app = create_app(settings)
    service = AdmissionService(app.state.database, app.state.object_store, settings=settings)
    archive = build_registry_fixture_archive(FIXTURE_ROOT / "example-pack")
    locks = {
        variant: {
            "baseId": runtime.base_ids[variant],
            "artifactDigest": artifact_digest(archive),
            "lock": {
                "format": "dinkster.pack-lock/1",
                "pack": "example-pack",
                "variant": variant,
                "requiresPython": ">=3.12",
                "requirements": [],
                "indexes": [],
                "packages": [],
            },
        }
        for variant in ("linux-cpu", "win-cpu")
    }
    service.submit(
        archive, pack_name="example-pack", version="1.2.3", locks=json.dumps(locks).encode()
    )
    with TestClient(app) as client:
        claimed = client.post(f"{PREFIX}/claim", headers=HEADERS).json()
        path = f"{PREFIX}/{claimed['candidateId']}"
        headers = {**HEADERS, "X-Scanner-Lease": claimed["leaseToken"]}
        data = client.get(f"{path}/input", headers=headers).content
        transferred = client.get(f"{path}/locks", headers=headers).json()
        dependencies = client.get(f"{path}/dependencies", headers=headers).json()

    def no_authority(*args: object, **kwargs: object) -> None:
        raise AssertionError("Prepared execution cannot access catalog or object store")

    monkeypatch.setattr(app.state.database, "session", no_authority)
    monkeypatch.setattr(app.state.object_store, "read", no_authority)
    prepared = ProbeDependencies(
        tuple(base64.b64decode(value) for value in dependencies["helperWheels"]),
        tuple(
            (value["filename"], base64.b64decode(value["data"]))
            for value in dependencies["libraryWheels"]
        ),
        tuple(dependencies["requirements"]),
    )
    lock_bytes = {variant: base64.b64decode(value) for variant, value in transferred.items()}
    wheel = inspect_wheel(data, "example-pack", "1.2.3")
    for changed in (False, True):
        with extracted_wheel(data, wheel) as root:
            result = run_prepared_probe(
                root,
                prepared,
                settings=ProbeSettings(**claimed["probeSettings"]),
                require_isolation=False,
                scan_engine=claimed["scanEngine"],
                install_locks=claimed["installLocks"],
                lock_bytes={**lock_bytes, "linux-cpu": b"changed"} if changed else lock_bytes,
                artifact_digest=claimed["artifactDigest"],
                runtime_store=tmp_path / "worker-runtime",
                development_runtime=runtime.mirror,
            )
        if changed:
            assert result.blocked
            assert result.findings[0].code == "probe.pack-dependencies-unavailable"
            assert "submitted dependency lock bytes changed" in result.findings[0].message
        else:
            assert not result.blocked, result
            assert result.data is not None
            assert {schema["nodeType"] for schema in result.data["schemas"]} == {
                "example.resize",
                "example.save",
            }
