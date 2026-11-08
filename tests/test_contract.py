from __future__ import annotations

import hashlib
import logging
from datetime import timedelta
from typing import Any, cast
from uuid import UUID

import pytest
from blake3 import blake3
from dinkster_schema import schema_from_wire, schema_signature, schema_to_wire
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import select, update

from dinkster_registry_service.database import (
    Database,
    PackRecord,
    ReleaseAttestationRecord,
    ReleaseCloudEvaluationRecord,
    ReleaseFindingRecord,
    ReleaseNodeRecord,
    ReleaseRecord,
    ReleaseScanRunRecord,
)
from dinkster_registry_service.digests import artifact_object_key
from dinkster_registry_service.object_store import LocalFilesystemObjectStore
from dinkster_registry_service.versioning import public_version_key
from dinkster_registry_service.wire import (
    DownloadTicket,
    ErrorResponse,
    NodeProvidersResponse,
    PackDetail,
    PackPage,
    ReleaseDetail,
    ReleaseManifest,
    ReleasePage,
    SchemasResponse,
    SecurityBlocksResponse,
)

PUBLIC_CACHE = "public, max-age=60, stale-while-revalidate=300"


def test_healthz_is_uncached_database_readiness(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"


def assert_public_metadata(response: Response) -> None:
    headers = response.headers
    assert headers["cache-control"] == PUBLIC_CACHE
    assert headers["etag"].startswith('"')
    assert headers["etag"].endswith('"')
    assert not headers["etag"].startswith("W/")


def test_browse_catalog_contract(client: TestClient) -> None:
    response = client.get("/v1/packs")
    assert response.status_code == 200
    payload = PackPage.model_validate(response.json())
    assert [pack.name for pack in payload.items] == ["example-pack", "color-tools"]
    assert payload.next_cursor is None
    assert payload.items[0].node_types == ["example.resize", "example.save"]
    assert payload.items[0].pack_id.version == 7
    assert_public_metadata(response)

    search = client.get("/v1/packs?q=color&sort=relevance")
    assert [item["name"] for item in search.json()["items"]] == ["color-tools"]
    assert [item["name"] for item in client.get("/v1/packs?q=").json()["items"]] == [
        "example-pack",
        "color-tools",
    ]
    node_filter = client.get("/v1/packs?nodeType=example.resize")
    assert [item["name"] for item in node_filter.json()["items"]] == ["example-pack"]


def test_pack_release_and_schema_contracts(client: TestClient) -> None:
    pack_response = client.get("/v1/packs/example-pack")
    pack = PackDetail.model_validate(pack_response.json())
    assert pack.name == "example-pack"
    assert pack.owner.type == "org"
    assert pack.pack_notice is None
    assert_public_metadata(pack_response)

    versions_response = client.get("/v1/packs/example-pack/versions")
    versions = ReleasePage.model_validate(versions_response.json())
    assert [release.version for release in versions.items] == ["1.2.3"]
    assert versions.items[0].artifact_digest.startswith("blake3:")
    assert_public_metadata(versions_response)

    release_response = client.get("/v1/packs/example-pack/versions/1.2.3")
    release = ReleaseDetail.model_validate(release_response.json())
    assert release.artifact.digest == versions.items[0].artifact_digest
    assert isinstance(release.manifest, ReleaseManifest)
    assert release.manifest.dinkster == ">=0.9rc1,<1"
    assert release.manifest.license == "Apache-2.0"
    assert release.cloud.registry_eligible
    assert_public_metadata(release_response)

    schemas_response = client.get("/v1/packs/example-pack/versions/1.2.3/schemas")
    schemas = SchemasResponse.model_validate(schemas_response.json())
    assert [schema.node_type for schema in schemas.schemas] == [
        "example.resize",
        "example.save",
    ]
    assert_public_metadata(schemas_response)


def test_template_catalog_and_immutable_body_contract(
    client: TestClient,
) -> None:
    body = b'{"nodes":[]}\n'

    response = client.get("/index/templates?q=start&tag=intro&pack=example-pack")
    assert response.status_code == 200
    assert response.json() == {
        "templates": [
            {
                "pack": "example-pack",
                "version": "1.2.3",
                "id": "starter",
                "name": "Starter",
                "description": "Start here",
                "family": "example.image",
                "tags": ["intro"],
                "models": ["example.safetensors"],
                "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
            }
        ]
    }
    assert "path" not in response.text

    url = "/index/packs/example-pack/versions/1.2.3/templates/starter"
    document = client.get(url)
    assert document.status_code == 200
    assert document.content == body
    assert document.headers["etag"] == f'"sha256:{hashlib.sha256(body).hexdigest()}"'
    assert "immutable" in document.headers["cache-control"]
    conditional = client.get(url, headers={"If-None-Match": document.headers["etag"]})
    assert conditional.status_code == 304
    assert client.get(url.removesuffix("starter") + "missing").status_code == 404


@pytest.mark.parametrize(
    ("pack_name", "version"),
    (("example-pack", "1.2.3"), ("color-tools", "0.4.0")),
)
def test_every_fixture_schema_round_trips_through_dinkster_schema(
    client: TestClient, pack_name: str, version: str
) -> None:
    response = client.get(f"/v1/packs/{pack_name}/versions/{version}/schemas")
    schemas = SchemasResponse.model_validate(response.json())
    for entry in schemas.schemas:
        document = cast(dict[str, Any], entry.schema_document)
        decoded = schema_from_wire(document)
        assert schema_to_wire(decoded) == document
        assert decoded.node_type == entry.node_type
        assert decoded.version == entry.schema_version
        assert schema_signature(decoded) == entry.schema_signature
    assert_public_metadata(response)


def test_node_provider_query_contract(
    client: TestClient,
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore],
) -> None:
    response = client.get("/v1/nodes/example.resize/providers?dinksterVersion=0.9.5")
    assert response.status_code == 200
    payload = NodeProvidersResponse.model_validate(response.json())
    assert payload.node_type == "example.resize"
    assert len(payload.providers) == 1
    provider = payload.providers[0]
    assert provider.pack_name == "example-pack"
    assert provider.version == "1.2.3"
    assert provider.artifact_digest.startswith("blake3:")
    assert_public_metadata(response)

    for include_prerelease in ("false", "true"):
        explicit_prerelease = client.get(
            "/v1/nodes/example.resize/providers"
            f"?dinksterVersion=0.9rc1&includePrerelease={include_prerelease}"
        )
        explicit_payload = NodeProvidersResponse.model_validate(explicit_prerelease.json())
        assert [item.version for item in explicit_payload.providers] == ["1.2.3"]

    database, _ = seeded_catalog
    with database.session() as session, session.begin():
        pack = session.scalar(select(PackRecord).where(PackRecord.name == "example-pack"))
        stable = session.scalar(select(ReleaseRecord).where(ReleaseRecord.version == "1.2.3"))
        assert pack is not None
        assert stable is not None
        stable_node = session.scalar(
            select(ReleaseNodeRecord).where(
                ReleaseNodeRecord.release_id == stable.id,
                ReleaseNodeRecord.node_type == "example.resize",
            )
        )
        stable_scan = session.scalar(
            select(ReleaseScanRunRecord).where(ReleaseScanRunRecord.release_id == stable.id)
        )
        stable_attestation = session.scalar(
            select(ReleaseAttestationRecord).where(ReleaseAttestationRecord.release_id == stable.id)
        )
        stable_cloud = session.scalar(
            select(ReleaseCloudEvaluationRecord).where(
                ReleaseCloudEvaluationRecord.release_id == stable.id
            )
        )
        assert stable_node is not None
        assert stable_scan is not None
        assert stable_attestation is not None
        assert stable_cloud is not None
        prerelease_id = UUID("01990000-0000-7000-8000-000000000042")
        created_at = stable.published_at + timedelta(days=1)
        session.add(
            ReleaseRecord(
                id=prerelease_id,
                pack_id=pack.id,
                version="2.0rc1",
                version_key=public_version_key("2.0rc1"),
                state="active",
                state_reason=None,
                state_changed_at=created_at,
                published_at=created_at,
                published_by_kind=stable.published_by_kind,
                published_by_principal_id=stable.published_by_principal_id,
                artifact_digest=stable.artifact_digest,
                manifest=dict(stable.manifest),
            )
        )
        session.flush()
        session.add(
            ReleaseNodeRecord(
                release_id=prerelease_id,
                node_type=stable_node.node_type,
                schema_version=stable_node.schema_version,
                schema_wire_version=stable_node.schema_wire_version,
                schema_signature=stable_node.schema_signature,
                role=stable_node.role,
                schema=dict(stable_node.schema),
            )
        )
        session.add(
            ReleaseScanRunRecord(
                id=UUID("01990000-0000-7000-8000-000000000043"),
                release_id=prerelease_id,
                created_at=created_at,
                accepted=True,
                doctor=dict(stable_scan.doctor),
                scan=dict(stable_scan.scan),
                provenance=dict(stable_scan.provenance),
                vulnerabilities=dict(stable_scan.vulnerabilities),
            )
        )
        session.add(
            ReleaseAttestationRecord(
                id=UUID("01990000-0000-7000-8000-000000000044"),
                release_id=prerelease_id,
                created_at=created_at,
                status=stable_attestation.status,
                statement_url=stable_attestation.statement_url,
            )
        )
        session.add(
            ReleaseCloudEvaluationRecord(
                id=UUID("01990000-0000-7000-8000-000000000045"),
                release_id=prerelease_id,
                created_at=created_at,
                registry_eligible=stable_cloud.registry_eligible,
                reason_codes=list(stable_cloud.reason_codes),
                policy_version=stable_cloud.policy_version,
            )
        )

    hidden = NodeProvidersResponse.model_validate(
        client.get("/v1/nodes/example.resize/providers?dinksterVersion=0.9rc1").json()
    )
    shown = NodeProvidersResponse.model_validate(
        client.get(
            "/v1/nodes/example.resize/providers?dinksterVersion=0.9rc1&includePrerelease=true"
        ).json()
    )
    assert [item.version for item in hidden.providers] == ["1.2.3"]
    assert [item.version for item in shown.providers] == ["2.0rc1"]


def test_release_detail_projects_latest_accepted_evidence(
    client: TestClient,
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore],
) -> None:
    database, _ = seeded_catalog
    with database.session() as session, session.begin():
        release = session.scalar(select(ReleaseRecord).where(ReleaseRecord.version == "1.2.3"))
        assert release is not None
        created_at = release.published_at + timedelta(days=2)
        session.add(
            ReleaseScanRunRecord(
                id=UUID("01990000-0000-7000-8000-000000000052"),
                release_id=release.id,
                created_at=created_at + timedelta(hours=1),
                accepted=False,
                doctor={
                    "status": "failed",
                    "doctorVersion": "0.9.1",
                    "reportVersion": 1,
                    "errorCount": 1,
                    "warningCount": 0,
                },
                scan={
                    "status": "failed",
                    "policyVersion": "registry-scan/2",
                    "scannedAt": created_at.isoformat(),
                },
                provenance={
                    "kind": "interactive",
                    "verified": False,
                    "repository": None,
                    "commitSha": None,
                    "workflowRef": None,
                },
                vulnerabilities={
                    "status": "unavailable",
                    "critical": 0,
                    "high": 0,
                    "moderate": 0,
                    "low": 0,
                    "databaseAsOf": None,
                },
            )
        )
        accepted_scan_id = UUID("01990000-0000-7000-8000-000000000053")
        session.add(
            ReleaseScanRunRecord(
                id=accepted_scan_id,
                release_id=release.id,
                created_at=created_at,
                accepted=True,
                doctor={
                    "status": "warning",
                    "doctorVersion": "0.9.1",
                    "reportVersion": 1,
                    "errorCount": 0,
                    "warningCount": 1,
                },
                scan={
                    "status": "warning",
                    "policyVersion": "registry-scan/2",
                    "scannedAt": created_at.isoformat(),
                },
                provenance={
                    "kind": "github_actions_oidc",
                    "verified": True,
                    "repository": "example-org/dinkster-example-pack",
                    "commitSha": "1123456789012345678901234567890123456789",
                    "workflowRef": (
                        "example-org/dinkster-example-pack/.github/workflows/publish.yml"
                    ),
                },
                vulnerabilities={
                    "status": "current",
                    "critical": 0,
                    "high": 0,
                    "moderate": 0,
                    "low": 0,
                    "databaseAsOf": created_at.isoformat(),
                },
            )
        )
        session.flush()
        session.add(
            ReleaseFindingRecord(
                id=UUID("01990000-0000-7000-8000-000000000054"),
                scan_run_id=accepted_scan_id,
                created_at=created_at,
                code="fixture-warning",
                severity="warning",
                message="Fixture warning.",
            )
        )
        session.add(
            ReleaseAttestationRecord(
                id=UUID("01990000-0000-7000-8000-000000000055"),
                release_id=release.id,
                created_at=created_at,
                status="invalid",
                statement_url=None,
            )
        )
        session.add(
            ReleaseCloudEvaluationRecord(
                id=UUID("01990000-0000-7000-8000-000000000056"),
                release_id=release.id,
                created_at=created_at,
                registry_eligible=False,
                reason_codes=["fixture-warning"],
                policy_version="cloud-pack/2",
            )
        )

    response = client.get("/v1/packs/example-pack/versions/1.2.3")
    detail = ReleaseDetail.model_validate(response.json())
    assert detail.trust_signals.scan.status == "warning"
    assert [finding.code for finding in detail.trust_signals.findings] == ["fixture-warning"]
    assert detail.trust_signals.attestation.status == "invalid"
    assert not detail.cloud.registry_eligible
    assert detail.cloud.reason_codes == ["fixture-warning"]


def test_conditional_get_returns_304_with_the_same_cache_policy(client: TestClient) -> None:
    first = client.get("/v1/packs")
    conditional = client.get("/v1/packs", headers={"If-None-Match": first.headers["etag"]})
    assert conditional.status_code == 304
    assert conditional.content == b""
    assert conditional.headers["etag"] == first.headers["etag"]
    assert conditional.headers["cache-control"] == first.headers["cache-control"]


def test_download_ticket_and_fixture_artifact_verify_blake3(client: TestClient) -> None:
    ticket_response = client.post("/v1/packs/example-pack/versions/1.2.3/download-tickets")
    assert ticket_response.status_code == 200
    assert ticket_response.headers["cache-control"] == "no-store"
    assert "etag" not in ticket_response.headers
    ticket = DownloadTicket.model_validate(ticket_response.json())

    artifact = client.get(ticket.url)
    assert artifact.status_code == 200
    assert artifact.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert artifact.headers["etag"] == f'"{ticket.artifact_digest}"'
    assert artifact.headers["x-dinkster-artifact-digest"] == ticket.artifact_digest
    assert len(artifact.content) == ticket.artifact_size
    assert "blake3:" + blake3(artifact.content).hexdigest() == ticket.artifact_digest

    conditional = client.get(ticket.url, headers={"If-None-Match": artifact.headers["etag"]})
    assert conditional.status_code == 304
    assert conditional.content == b""
    assert conditional.headers["cache-control"] == artifact.headers["cache-control"]


def test_yanked_release_ticket_remains_downloadable(
    client: TestClient,
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore],
) -> None:
    database, _ = seeded_catalog
    with database.session() as session, session.begin():
        session.execute(
            update(ReleaseRecord)
            .where(ReleaseRecord.version == "1.2.3")
            .values(state="yanked", state_reason="Use a later release.")
        )

    ticket_response = client.post("/v1/packs/example-pack/versions/1.2.3/download-tickets")
    assert ticket_response.status_code == 200
    ticket = DownloadTicket.model_validate(ticket_response.json())
    assert ticket.state == "yanked"
    assert ticket.warning == "Use a later release."
    assert client.get(ticket.url).status_code == 200


def test_tampered_fixture_artifact_fails_verification(
    client: TestClient,
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore],
) -> None:
    _, object_store = seeded_catalog
    ticket = DownloadTicket.model_validate(
        client.post("/v1/packs/example-pack/versions/1.2.3/download-tickets").json()
    )
    object_path = object_store.root / artifact_object_key(ticket.artifact_digest)
    object_path.write_bytes(object_path.read_bytes() + b"tampered")

    response = client.get(ticket.url)
    assert response.status_code == 500
    error = ErrorResponse.model_validate(response.json()).error
    assert error.code == "internal"
    assert not error.retryable
    assert response.headers["x-request-id"] == str(error.request_id)


def test_unexpected_storage_failure_uses_registry_envelope(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    ticket = DownloadTicket.model_validate(
        client.post("/v1/packs/example-pack/versions/1.2.3/download-tickets").json()
    )

    def fail_open(
        store: LocalFilesystemObjectStore,
        key: str,
        *,
        expected_size: int,
        expected_digest: str,
    ) -> bytes:
        del store, key, expected_size, expected_digest
        raise RuntimeError("injected storage failure")

    monkeypatch.setattr(LocalFilesystemObjectStore, "open", fail_open)
    caplog.set_level(logging.ERROR)
    response = client.get(ticket.url)
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/json")
    error = ErrorResponse.model_validate(response.json()).error
    assert error.code == "internal"
    assert error.retryable
    assert error.request_id.version == 7
    assert response.headers["x-request-id"] == str(error.request_id)
    assert str(error.request_id) in caplog.text


def test_errors_use_registry_envelope_and_reject_other_digest_algorithms(
    client: TestClient,
) -> None:
    response = client.get("/v1/artifacts/sha256:" + "0" * 64)
    assert response.status_code == 400
    error = ErrorResponse.model_validate(response.json()).error
    assert error.code == "invalid_request"
    assert not error.retryable
    assert error.request_id.version == 7
    assert "other algorithms are unsupported" in error.message
    assert "rebuild or reinstall" in error.message

    missing = client.get("/v1/packs/missing-pack")
    assert missing.status_code == 404
    missing_error = ErrorResponse.model_validate(missing.json()).error
    assert missing_error.code == "not_found"
    assert missing.headers["cache-control"] == "public, max-age=30"
    assert missing_error.detail == {"packName": "missing-pack"}

    unsupported_method = client.delete("/v1/packs")
    assert unsupported_method.status_code == 400
    assert ErrorResponse.model_validate(unsupported_method.json()).error.code == "invalid_request"


def test_pagination_cursor_is_opaque_and_query_bound(client: TestClient) -> None:
    first = client.get("/v1/packs?limit=1&sort=name")
    page = PackPage.model_validate(first.json())
    assert page.next_cursor is not None
    second = client.get(f"/v1/packs?limit=1&sort=name&cursor={page.next_cursor}")
    assert PackPage.model_validate(second.json()).items[0].name == "example-pack"

    forged = client.get(f"/v1/packs?limit=2&sort=name&cursor={page.next_cursor}")
    assert forged.status_code == 400
    assert ErrorResponse.model_validate(forged.json()).error.code == "invalid_request"


def test_security_block_feed_is_an_exact_empty_public_dto(client: TestClient) -> None:
    response = client.get("/v1/security/blocks")
    payload = SecurityBlocksResponse.model_validate(response.json())
    assert payload.items == []
    assert payload.next_cursor is None
    assert_public_metadata(response)


def test_uuid_strings_are_uuid7(client: TestClient) -> None:
    payload = client.get("/v1/packs").json()
    assert all(UUID(item["packId"]).version == 7 for item in payload["items"])
