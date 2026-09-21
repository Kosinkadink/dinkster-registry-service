from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from dinkster_schema import (
    SCHEMA_WIRE_VERSION,
    NodeSchema,
    canonical_name,
    claim_covers,
    claims_conflict,
    reserved_root,
    schema_signature,
    schema_to_wire,
    validate_name,
)
from sqlalchemy import select

from .artifacts import build_registry_fixture_archive_with_digests
from .database import (
    ArtifactRecord,
    Database,
    NamespaceGrantRecord,
    PackRecord,
    ReleaseAttestationRecord,
    ReleaseCloudEvaluationRecord,
    ReleaseNodeRecord,
    ReleaseRecord,
    ReleaseScanRunRecord,
)
from .digests import artifact_object_key
from .object_store import ObjectStore
from .versioning import public_version_key, require_public_version

MEDIA_TYPE = "application/vnd.dinkster.pack+zip"
FIXTURE_ROOT = Path("fixtures/packs")


@dataclass(frozen=True)
class NodeFixture:
    schema: NodeSchema
    role: str = "executing"


@dataclass(frozen=True)
class TemplateFixture:
    id: str
    name: str
    path: str
    description: str = ""
    tags: tuple[str, ...] = ()
    family: str = ""
    models: tuple[str, ...] = ()
    assets: tuple[str, ...] = ()


@dataclass(frozen=True)
class PackFixture:
    pack_id: UUID
    release_id: UUID
    scan_run_id: UUID
    attestation_id: UUID
    cloud_evaluation_id: UUID
    name: str
    display_name: str
    description: str
    long_description: str
    owner_type: str
    owner_id: UUID
    owner_slug: str
    owner_display_name: str
    homepage: str
    repository: str
    support: str
    tags: tuple[str, ...]
    version: str
    published_at: datetime
    principal_id: str
    namespaces: tuple[str, ...]
    platforms: tuple[str, ...]
    nodes: tuple[NodeFixture, ...]
    python_requirements: tuple[str, ...] = ()
    dependencies: tuple[tuple[str, str], ...] = ()
    templates: tuple[TemplateFixture, ...] = ()


FIXTURES = (
    PackFixture(
        pack_id=UUID("01990000-0000-7000-8000-000000000002"),
        release_id=UUID("01990000-0000-7000-8000-000000000012"),
        scan_run_id=UUID("01990000-0000-7000-8000-000000000013"),
        attestation_id=UUID("01990000-0000-7000-8000-000000000014"),
        cloud_evaluation_id=UUID("01990000-0000-7000-8000-000000000015"),
        name="example-pack",
        display_name="Example Pack",
        description="Example image utility nodes for Dinkster.",
        long_description="A small public fixture pack with resize and save nodes.",
        owner_type="org",
        owner_id=UUID("01990000-0000-7000-8000-000000000003"),
        owner_slug="example-org",
        owner_display_name="Example Org",
        homepage="https://example.invalid/dinkster-pack",
        repository="https://github.com/example-org/dinkster-example-pack",
        support="https://github.com/example-org/dinkster-example-pack/issues",
        tags=("image", "utility"),
        version="1.2.3",
        published_at=datetime(2026, 9, 2, 13, 10, tzinfo=UTC),
        principal_id="w_01990000-0000-7000-8000-000000000004",
        namespaces=("example",),
        platforms=("linux-x86_64", "macos-arm64"),
        nodes=(
            NodeFixture(
                NodeSchema(
                    node_type="example.resize",
                    version=2,
                    display_name="Example Resize",
                    category="image/transform",
                    description="Resize an image to the requested dimensions.",
                )
            ),
            NodeFixture(
                NodeSchema(
                    node_type="example.save",
                    display_name="Example Save",
                    category="image/output",
                    description="Save an image artifact.",
                    idempotent=False,
                    output_node=True,
                )
            ),
        ),
        python_requirements=("pillow>=10,<12",),
        templates=(
            TemplateFixture(
                id="starter",
                name="Starter",
                path="templates/starter.json",
                description="Start here",
                tags=("intro",),
                family="example.image",
                models=("example.safetensors",),
            ),
        ),
    ),
    PackFixture(
        pack_id=UUID("01990000-0000-7000-8000-000000000022"),
        release_id=UUID("01990000-0000-7000-8000-000000000032"),
        scan_run_id=UUID("01990000-0000-7000-8000-000000000033"),
        attestation_id=UUID("01990000-0000-7000-8000-000000000034"),
        cloud_evaluation_id=UUID("01990000-0000-7000-8000-000000000035"),
        name="color-tools",
        display_name="Color Tools",
        description="Color adjustment nodes for Dinkster.",
        long_description="A public fixture pack for deterministic catalog demonstrations.",
        owner_type="user",
        owner_id=UUID("01990000-0000-7000-8000-000000000023"),
        owner_slug="fixture-author",
        owner_display_name="Fixture Author",
        homepage="https://example.invalid/color-tools",
        repository="https://github.com/example-author/dinkster-color-tools",
        support="https://github.com/example-author/dinkster-color-tools/issues",
        tags=("color", "image"),
        version="0.4.0",
        published_at=datetime(2026, 8, 30, 9, 0, tzinfo=UTC),
        principal_id="u_01990000-0000-7000-8000-000000000023",
        namespaces=("color",),
        platforms=("linux-x86_64", "macos-arm64", "windows-x86_64"),
        nodes=(
            NodeFixture(
                NodeSchema(
                    node_type="color.adjust",
                    display_name="Color Adjust",
                    category="image/color",
                    description="Adjust image color properties.",
                )
            ),
        ),
    ),
)


@dataclass(frozen=True)
class SeedResult:
    packs_created: int
    releases_created: int
    artifacts_created: int


def _validate_fixture(fixture: PackFixture) -> None:
    problem = validate_name(fixture.name)
    if problem is not None or canonical_name(fixture.name) != fixture.name:
        raise ValueError(f"fixture pack name is not canonical: {fixture.name!r}: {problem}")
    require_public_version(fixture.version)
    claims = (fixture.name, *fixture.namespaces)
    for claim in claims:
        problem = validate_name(claim)
        if problem is not None:
            raise ValueError(f"fixture namespace {claim!r} {problem}")
        if reserved_root(claim) is not None:
            raise ValueError(f"fixture namespace {claim!r} is reserved")
    for node in fixture.nodes:
        if not any(claim_covers(claim, node.schema.node_type) for claim in claims):
            raise ValueError(
                f"fixture node {node.schema.node_type!r} is not covered by a namespace"
            )


def _validate_cross_fixture_claims() -> None:
    for index, fixture in enumerate(FIXTURES):
        _validate_fixture(fixture)
        for other in FIXTURES[index + 1 :]:
            for claim in (fixture.name, *fixture.namespaces):
                for other_claim in (other.name, *other.namespaces):
                    if claims_conflict(claim, other_claim):
                        raise ValueError(
                            f"fixture namespace {claim!r} conflicts with {other_claim!r}"
                        )


def _manifest(fixture: PackFixture, source: Path) -> dict[str, Any]:
    return {
        "dinkster": ">=0.9rc1,<1",
        "license": "Apache-2.0",
        "contracts": {
            "host": "dinkster-pack-host/1",
            "api": "dinkster-api/v1",
            "inference": None,
        },
        "platforms": list(fixture.platforms),
        "sandbox": {"gpu": False, "network": False, "writableMounts": False},
        "pythonRequirements": list(fixture.python_requirements),
        "dependencies": [
            {"packName": pack_name, "versionRange": version_range}
            for pack_name, version_range in fixture.dependencies
        ],
        "templates": [
            {
                "id": template.id,
                "name": template.name,
                "digest": "sha256:"
                + hashlib.sha256((source / template.path).read_bytes()).hexdigest(),
                "path": template.path,
                "description": template.description,
                "tags": list(template.tags),
                "family": template.family,
                "models": list(template.models),
                "assets": list(template.assets),
                "thumbnailDigest": "",
                "thumbnailMediaType": "",
                "thumbnailPath": "",
            }
            for template in fixture.templates
        ],
    }


def _trust_signals(fixture: PackFixture) -> dict[str, Any]:
    scanned_at = fixture.published_at.isoformat().replace("+00:00", "Z")
    provenance_kind = (
        "github_actions_oidc" if fixture.principal_id.startswith("w_") else "interactive"
    )
    verified = provenance_kind == "github_actions_oidc"
    return {
        "doctor": {
            "status": "passed",
            "doctorVersion": "0.9.0",
            "reportVersion": 1,
            "errorCount": 0,
            "warningCount": 0,
        },
        "scan": {
            "status": "passed",
            "policyVersion": "registry-scan/1",
            "scannedAt": scanned_at,
        },
        "provenance": {
            "kind": provenance_kind,
            "verified": verified,
            "repository": fixture.repository.removeprefix("https://github.com/"),
            "commitSha": "0123456789012345678901234567890123456789" if verified else None,
            "workflowRef": (
                fixture.repository.removeprefix("https://github.com/")
                + "/.github/workflows/publish.yml@refs/tags/v"
                + fixture.version
                if verified
                else None
            ),
        },
        "attestation": {
            "status": "verified" if verified else "missing",
            "statementUrl": (
                "https://registry.dinkster.example/v1/attestations/"
                "01990000-0000-7000-8000-000000000005"
                if verified
                else None
            ),
        },
        "vulnerabilities": {
            "status": "current",
            "critical": 0,
            "high": 0,
            "moderate": 0,
            "low": 0,
            "databaseAsOf": scanned_at,
        },
        "findings": [],
    }


def seed_fixtures(database: Database, object_store: ObjectStore) -> SeedResult:
    _validate_cross_fixture_claims()
    created_packs = 0
    created_releases = 0
    created_artifacts = 0

    for fixture in FIXTURES:
        source = FIXTURE_ROOT / fixture.name
        archive, digest, manifest_digest = build_registry_fixture_archive_with_digests(source)
        object_key = artifact_object_key(digest)
        object_store.put(object_key, archive)

        with database.session() as session, session.begin():
            pack = session.scalar(select(PackRecord).where(PackRecord.name == fixture.name))
            if pack is None:
                pack = PackRecord(
                    id=fixture.pack_id,
                    name=fixture.name,
                    display_name=fixture.display_name,
                    description=fixture.description,
                    long_description=fixture.long_description,
                    owner_type=fixture.owner_type,
                    owner_id=fixture.owner_id,
                    owner_slug=fixture.owner_slug,
                    owner_display_name=fixture.owner_display_name,
                    visibility="public",
                    homepage=fixture.homepage,
                    repository=fixture.repository,
                    support=fixture.support,
                    tags=list(fixture.tags),
                    latest_version=fixture.version,
                    created_at=fixture.published_at,
                    updated_at=fixture.published_at,
                    download_count=0,
                    pack_notice=None,
                )
                session.add(pack)
                session.flush()
                created_packs += 1
                for claim in (fixture.name, *fixture.namespaces):
                    session.add(
                        NamespaceGrantRecord(
                            claim=canonical_name(claim),
                            pack_id=fixture.pack_id,
                            owner_id=fixture.owner_id,
                        )
                    )
            elif pack.id != fixture.pack_id:
                raise ValueError(f"fixture pack name {fixture.name!r} is already occupied")

            artifact = session.get(ArtifactRecord, digest)
            if artifact is None:
                session.add(
                    ArtifactRecord(
                        digest=digest,
                        size=len(archive),
                        media_type=MEDIA_TYPE,
                        manifest_digest=manifest_digest,
                        object_key=object_key,
                    )
                )
                created_artifacts += 1
            elif (
                artifact.size != len(archive)
                or artifact.media_type != MEDIA_TYPE
                or artifact.manifest_digest != manifest_digest
                or artifact.object_key != object_key
            ):
                raise ValueError(f"fixture artifact metadata differs for {digest}")

            release = session.scalar(
                select(ReleaseRecord).where(
                    ReleaseRecord.pack_id == fixture.pack_id,
                    ReleaseRecord.version == fixture.version,
                )
            )
            if release is None:
                release = ReleaseRecord(
                    id=fixture.release_id,
                    pack_id=fixture.pack_id,
                    version=fixture.version,
                    version_key=public_version_key(fixture.version),
                    state="active",
                    state_reason=None,
                    state_changed_at=fixture.published_at,
                    published_at=fixture.published_at,
                    published_by_kind=(
                        "github_actions_oidc"
                        if fixture.principal_id.startswith("w_")
                        else "interactive"
                    ),
                    published_by_principal_id=fixture.principal_id,
                    artifact_digest=digest,
                    manifest=_manifest(fixture, source),
                )
                session.add(release)
                session.flush()
                created_releases += 1
                for node in fixture.nodes:
                    wire = schema_to_wire(node.schema)
                    session.add(
                        ReleaseNodeRecord(
                            release_id=fixture.release_id,
                            node_type=node.schema.node_type,
                            schema_version=node.schema.version,
                            schema_wire_version=SCHEMA_WIRE_VERSION,
                            schema_signature=schema_signature(node.schema),
                            role=node.role,
                            schema=wire,
                        )
                    )
                trust_signals = _trust_signals(fixture)
                session.add(
                    ReleaseScanRunRecord(
                        id=fixture.scan_run_id,
                        release_id=fixture.release_id,
                        created_at=fixture.published_at,
                        accepted=True,
                        doctor=trust_signals["doctor"],
                        scan=trust_signals["scan"],
                        provenance=trust_signals["provenance"],
                        vulnerabilities=trust_signals["vulnerabilities"],
                    )
                )
                attestation = trust_signals["attestation"]
                session.add(
                    ReleaseAttestationRecord(
                        id=fixture.attestation_id,
                        release_id=fixture.release_id,
                        created_at=fixture.published_at,
                        status=attestation["status"],
                        statement_url=attestation["statementUrl"],
                    )
                )
                session.add(
                    ReleaseCloudEvaluationRecord(
                        id=fixture.cloud_evaluation_id,
                        release_id=fixture.release_id,
                        created_at=fixture.published_at,
                        registry_eligible=True,
                        reason_codes=[],
                        policy_version="cloud-pack/1",
                    )
                )
            elif release.artifact_digest != digest:
                raise ValueError(
                    f"fixture release {fixture.name} {fixture.version} has different bytes"
                )

    return SeedResult(created_packs, created_releases, created_artifacts)
