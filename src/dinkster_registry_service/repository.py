from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .cursors import CursorCodec
from .database import (
    ArtifactRecord,
    Database,
    PackRecord,
    ReleaseAttestationRecord,
    ReleaseCloudEvaluationRecord,
    ReleaseFindingRecord,
    ReleaseNodeRecord,
    ReleaseRecord,
    ReleaseScanRunRecord,
)
from .wire import (
    DownloadTicket,
    HealthResponse,
    NodeProvidersResponse,
    PackDetail,
    PackPage,
    ReleaseDetail,
    ReleasePage,
    SchemasResponse,
    SecurityBlocksResponse,
)


class CatalogDataError(RuntimeError):
    """Durable catalog rows violate the public response contract."""


class CatalogRepository:
    def __init__(self, database: Database, cursors: CursorCodec) -> None:
        self.database = database
        self.cursors = cursors

    @staticmethod
    def _pack(session: Session, name: str) -> PackRecord | None:
        return session.scalar(select(PackRecord).where(PackRecord.name == name))

    @staticmethod
    def _release(session: Session, pack_id: UUID, version: str) -> ReleaseRecord | None:
        return session.scalar(
            select(ReleaseRecord).where(
                ReleaseRecord.pack_id == pack_id, ReleaseRecord.version == version
            )
        )

    @staticmethod
    def _artifact(session: Session, digest: str) -> ArtifactRecord:
        artifact = session.get(ArtifactRecord, digest)
        if artifact is None:
            raise CatalogDataError(f"release references absent artifact {digest}")
        return artifact

    @staticmethod
    def _nodes(session: Session, release_id: UUID) -> list[ReleaseNodeRecord]:
        return list(
            session.scalars(
                select(ReleaseNodeRecord)
                .where(ReleaseNodeRecord.release_id == release_id)
                .order_by(ReleaseNodeRecord.node_type, ReleaseNodeRecord.schema_version)
            )
        )

    @staticmethod
    def _owner(pack: PackRecord) -> dict[str, object]:
        return {
            "type": pack.owner_type,
            "id": pack.owner_id,
            "slug": pack.owner_slug,
            "displayName": pack.owner_display_name,
        }

    @staticmethod
    def _trust_signals(session: Session, release_id: UUID) -> dict[str, object]:
        scan_run = session.scalar(
            select(ReleaseScanRunRecord)
            .where(
                ReleaseScanRunRecord.release_id == release_id,
                ReleaseScanRunRecord.accepted.is_(True),
            )
            .order_by(ReleaseScanRunRecord.created_at.desc(), ReleaseScanRunRecord.id.desc())
            .limit(1)
        )
        attestation = session.scalar(
            select(ReleaseAttestationRecord)
            .where(ReleaseAttestationRecord.release_id == release_id)
            .order_by(
                ReleaseAttestationRecord.created_at.desc(), ReleaseAttestationRecord.id.desc()
            )
            .limit(1)
        )
        if scan_run is None or attestation is None:
            raise CatalogDataError("release trust evidence is incomplete")
        findings = session.scalars(
            select(ReleaseFindingRecord)
            .where(ReleaseFindingRecord.scan_run_id == scan_run.id)
            .order_by(ReleaseFindingRecord.created_at, ReleaseFindingRecord.id)
        )
        return {
            "doctor": scan_run.doctor,
            "scan": scan_run.scan,
            "provenance": scan_run.provenance,
            "attestation": {
                "status": attestation.status,
                "statementUrl": attestation.statement_url,
            },
            "vulnerabilities": scan_run.vulnerabilities,
            "findings": [
                {
                    "code": finding.code,
                    "severity": finding.severity,
                    "message": finding.message,
                }
                for finding in findings
            ],
        }

    @classmethod
    def _trust_summary(cls, session: Session, release: ReleaseRecord) -> dict[str, object]:
        signals = cls._trust_signals(session, release.id)
        try:
            scan = signals["scan"]
            provenance = signals["provenance"]
            attestation = signals["attestation"]
            doctor = signals["doctor"]
            if (
                not isinstance(scan, dict)
                or not isinstance(provenance, dict)
                or not isinstance(attestation, dict)
                or not isinstance(doctor, dict)
            ):
                raise TypeError
            return {
                "scanStatus": scan["status"],
                "provenance": provenance["kind"],
                "verifiedAttestation": attestation["status"] == "verified",
                "warningCount": doctor["warningCount"],
            }
        except (KeyError, TypeError) as exc:
            raise CatalogDataError("release trust signals are incomplete") from exc

    @staticmethod
    def _cloud(session: Session, release_id: UUID) -> dict[str, object]:
        evaluation = session.scalar(
            select(ReleaseCloudEvaluationRecord)
            .where(ReleaseCloudEvaluationRecord.release_id == release_id)
            .order_by(
                ReleaseCloudEvaluationRecord.created_at.desc(),
                ReleaseCloudEvaluationRecord.id.desc(),
            )
            .limit(1)
        )
        if evaluation is None:
            raise CatalogDataError("release cloud evidence is incomplete")
        return {
            "registryEligible": evaluation.registry_eligible,
            "reasonCodes": evaluation.reason_codes,
            "policyVersion": evaluation.policy_version,
        }

    @classmethod
    def _release_summary(cls, session: Session, release: ReleaseRecord) -> dict[str, object]:
        artifact = cls._artifact(session, release.artifact_digest)
        manifest = release.manifest
        try:
            return {
                "version": release.version,
                "state": release.state,
                "stateReason": release.state_reason,
                "publishedAt": release.published_at,
                "artifactDigest": artifact.digest,
                "artifactSize": artifact.size,
                "dinkster": manifest["dinkster"],
                "license": manifest["license"],
                "platforms": manifest["platforms"],
                "nodeTypes": [node.node_type for node in cls._nodes(session, release.id)],
                "trustSummary": cls._trust_summary(session, release),
            }
        except KeyError as exc:
            raise CatalogDataError("release manifest is incomplete") from exc

    @classmethod
    def _pack_summary(
        cls, session: Session, pack: PackRecord, release: ReleaseRecord
    ) -> dict[str, object]:
        return {
            "packId": pack.id,
            "name": pack.name,
            "displayName": pack.display_name,
            "description": pack.description,
            "owner": cls._owner(pack),
            "visibility": pack.visibility,
            "latestVersion": pack.latest_version,
            "latestPublishedAt": release.published_at,
            "nodeTypes": [node.node_type for node in cls._nodes(session, release.id)],
            "tags": pack.tags,
            "downloadCount": pack.download_count,
            "trustSummary": cls._trust_summary(session, release),
            "packNotice": pack.pack_notice,
        }

    def browse(
        self,
        *,
        q: str | None,
        owner_type: str | None,
        owner: str | None,
        node_type: str | None,
        sort: str,
        limit: int,
        cursor: str | None,
    ) -> PackPage:
        query: dict[str, object] = {
            "q": q,
            "ownerType": owner_type,
            "owner": owner,
            "nodeType": node_type,
            "sort": sort,
            "limit": limit,
        }
        offset = 0 if cursor is None else self.cursors.verify(cursor, "packs", query)
        with self.database.session() as session:
            packs = list(
                session.scalars(select(PackRecord).where(PackRecord.visibility == "public"))
            )
            selected: list[tuple[PackRecord, ReleaseRecord]] = []
            normalized_q = None if q is None else q.casefold()
            for pack in packs:
                if owner_type is not None and pack.owner_type != owner_type:
                    continue
                if owner is not None and owner not in {pack.owner_slug, str(pack.owner_id)}:
                    continue
                searchable = " ".join(
                    [pack.name, pack.display_name, pack.description, *pack.tags]
                ).casefold()
                if normalized_q is not None and normalized_q not in searchable:
                    continue
                release = self._release(session, pack.id, pack.latest_version)
                if release is None or release.state != "active":
                    continue
                nodes = self._nodes(session, release.id)
                if node_type is not None and all(node.node_type != node_type for node in nodes):
                    continue
                selected.append((pack, release))

            if sort == "name":
                selected.sort(key=lambda item: item[0].name)
            elif sort == "downloads":
                selected.sort(key=lambda item: (-item[0].download_count, item[0].name))
            elif sort == "relevance" and normalized_q is not None:
                selected.sort(
                    key=lambda item: (
                        0
                        if item[0].name == normalized_q
                        else 1
                        if item[0].name.startswith(normalized_q)
                        else 2,
                        -item[1].published_at.timestamp(),
                        item[0].name,
                    )
                )
            else:
                selected.sort(key=lambda item: (-item[1].published_at.timestamp(), item[0].name))

            page = selected[offset : offset + limit]
            next_offset = offset + len(page)
            next_cursor = (
                self.cursors.issue("packs", query, next_offset)
                if next_offset < len(selected)
                else None
            )
            payload = {
                "items": [self._pack_summary(session, pack, release) for pack, release in page],
                "nextCursor": next_cursor,
            }
            return PackPage.model_validate(payload)

    def pack_detail(self, name: str) -> PackDetail | None:
        with self.database.session() as session:
            pack = self._pack(session, name)
            if pack is None or pack.visibility != "public":
                return None
            release = self._release(session, pack.id, pack.latest_version)
            if release is None or release.state != "active":
                return None
            return PackDetail.model_validate(
                {
                    "packId": pack.id,
                    "name": pack.name,
                    "displayName": pack.display_name,
                    "description": pack.description,
                    "longDescription": pack.long_description,
                    "owner": self._owner(pack),
                    "visibility": pack.visibility,
                    "homepage": pack.homepage,
                    "repository": pack.repository,
                    "support": pack.support,
                    "tags": pack.tags,
                    "latestVersion": pack.latest_version,
                    "createdAt": pack.created_at,
                    "updatedAt": pack.updated_at,
                    "packNotice": pack.pack_notice,
                }
            )

    def versions(
        self, name: str, *, include_yanked: bool, limit: int, cursor: str | None
    ) -> ReleasePage | None:
        query: dict[str, object] = {"includeYanked": include_yanked, "limit": limit}
        offset = 0 if cursor is None else self.cursors.verify(cursor, f"versions:{name}", query)
        with self.database.session() as session:
            pack = self._pack(session, name)
            if pack is None or pack.visibility != "public":
                return None
            releases = list(
                session.scalars(select(ReleaseRecord).where(ReleaseRecord.pack_id == pack.id))
            )
            visible_states = {"active", "yanked"} if include_yanked else {"active"}
            releases = [release for release in releases if release.state in visible_states]
            try:
                releases.sort(key=lambda release: Version(release.version), reverse=True)
            except InvalidVersion as exc:
                raise CatalogDataError("stored release version is invalid") from exc
            page = releases[offset : offset + limit]
            next_offset = offset + len(page)
            next_cursor = (
                self.cursors.issue(f"versions:{name}", query, next_offset)
                if next_offset < len(releases)
                else None
            )
            return ReleasePage.model_validate(
                {
                    "items": [self._release_summary(session, release) for release in page],
                    "nextCursor": next_cursor,
                }
            )

    def release_detail(self, name: str, version: str) -> ReleaseDetail | None:
        with self.database.session() as session:
            pack = self._pack(session, name)
            if pack is None or pack.visibility != "public":
                return None
            release = self._release(session, pack.id, version)
            if release is None or release.state not in {"active", "yanked"}:
                return None
            artifact = self._artifact(session, release.artifact_digest)
            nodes = self._nodes(session, release.id)
            return ReleaseDetail.model_validate(
                {
                    "packId": pack.id,
                    "packName": pack.name,
                    "version": release.version,
                    "state": release.state,
                    "stateReason": release.state_reason,
                    "stateChangedAt": release.state_changed_at,
                    "publishedAt": release.published_at,
                    "publishedBy": {
                        "kind": release.published_by_kind,
                        "principalId": release.published_by_principal_id,
                    },
                    "artifact": {
                        "digest": artifact.digest,
                        "size": artifact.size,
                        "mediaType": artifact.media_type,
                        "manifestDigest": artifact.manifest_digest,
                    },
                    "installLocks": {
                        variant: {
                            **lock,
                            "url": f"/v1/packs/{name}/versions/{version}/locks/{variant}",
                        }
                        for variant, lock in release.install_locks.items()
                    },
                    "manifest": release.manifest,
                    "nodes": [
                        {
                            "nodeType": node.node_type,
                            "schemaVersion": node.schema_version,
                            "schemaWireVersion": node.schema_wire_version,
                            "schemaSignature": node.schema_signature,
                            "role": node.role,
                        }
                        for node in nodes
                    ],
                    "trustSignals": self._trust_signals(session, release.id),
                    "cloud": self._cloud(session, release.id),
                }
            )

    def schemas(self, name: str, version: str) -> SchemasResponse | None:
        with self.database.session() as session:
            pack = self._pack(session, name)
            if pack is None or pack.visibility != "public":
                return None
            release = self._release(session, pack.id, version)
            if release is None or release.state not in {"active", "yanked"}:
                return None
            return SchemasResponse.model_validate(
                {
                    "packName": pack.name,
                    "version": release.version,
                    "schemas": [
                        {
                            "nodeType": node.node_type,
                            "schemaVersion": node.schema_version,
                            "schemaWireVersion": node.schema_wire_version,
                            "schemaSignature": node.schema_signature,
                            "role": node.role,
                            "schema": node.schema,
                        }
                        for node in self._nodes(session, release.id)
                    ],
                }
            )

    @staticmethod
    def _template_wire(template: dict[str, Any]) -> dict[str, object]:
        try:
            payload: dict[str, object] = {
                "id": cast(str, template["id"]),
                "name": cast(str, template["name"]),
                "digest": cast(str, template["digest"]),
            }
        except (KeyError, TypeError) as exc:
            raise CatalogDataError("release template metadata is incomplete") from exc
        for key in ("description", "family"):
            if value := template.get(key):
                payload[key] = cast(str, value)
        for key in ("tags", "models", "assets"):
            if value := template.get(key):
                payload[key] = cast(list[str], value)
        if thumbnail_digest := template.get("thumbnailDigest"):
            payload["thumbnail"] = {
                "digest": cast(str, thumbnail_digest),
                "mediaType": cast(str, template.get("thumbnailMediaType", "")),
            }
        return payload

    def templates(
        self,
        *,
        q: str,
        tag: str,
        pack_filter: str,
        limit: int,
        cursor: str | None,
    ) -> dict[str, object]:
        query: dict[str, object] = {"q": q, "tag": tag, "pack": pack_filter, "limit": limit}
        offset = 0 if cursor is None else self.cursors.verify(cursor, "templates", query)
        with self.database.session() as session:
            rows: list[tuple[str, dict[str, object]]] = []
            packs = session.scalars(select(PackRecord).where(PackRecord.visibility == "public"))
            for pack in packs:
                if pack_filter and pack.name != pack_filter:
                    continue
                release = self._release(session, pack.id, pack.latest_version)
                if release is None or release.state != "active":
                    continue
                templates = release.manifest.get("templates", [])
                if not isinstance(templates, list):
                    raise CatalogDataError("release templates must be a list")
                for value in templates:
                    if not isinstance(value, dict):
                        raise CatalogDataError("release template must be an object")
                    template = cast(dict[str, Any], value)
                    try:
                        template_id = cast(str, template["id"])
                        searchable = (
                            template_id,
                            cast(str, template["name"]),
                            cast(str, template.get("description", "")),
                            *cast(list[str], template.get("tags", [])),
                        )
                    except (KeyError, TypeError) as exc:
                        raise CatalogDataError("release template metadata is incomplete") from exc
                    if tag and tag not in template.get("tags", []):
                        continue
                    if q and not any(q in item.casefold() for item in searchable):
                        continue
                    rows.append(
                        (
                            f"{pack.name}/{template_id}",
                            {
                                "pack": pack.name,
                                "version": release.version,
                                **self._template_wire(template),
                            },
                        )
                    )
            rows.sort(key=lambda item: item[0])
            page = rows[offset : offset + limit]
            next_offset = offset + len(page)
            payload: dict[str, object] = {"templates": [row for _, row in page]}
            if next_offset < len(rows):
                payload["cursor"] = self.cursors.issue("templates", query, next_offset)
            return payload

    def template_asset(
        self, name: str, version: str, template_id: str, *, thumbnail: bool = False
    ) -> tuple[dict[str, Any], ArtifactRecord] | None:
        with self.database.session() as session:
            pack = self._pack(session, name)
            if pack is None or pack.visibility != "public":
                return None
            release = self._release(session, pack.id, version)
            if release is None or release.state not in {"active", "yanked"}:
                return None
            templates = release.manifest.get("templates", [])
            if not isinstance(templates, list):
                raise CatalogDataError("release templates must be a list")
            template = next(
                (
                    cast(dict[str, Any], value)
                    for value in templates
                    if isinstance(value, dict) and value.get("id") == template_id
                ),
                None,
            )
            if template is None:
                return None
            path_key = "thumbnailPath" if thumbnail else "path"
            digest_key = "thumbnailDigest" if thumbnail else "digest"
            media_type_key = "thumbnailMediaType" if thumbnail else None
            path = template.get(path_key)
            digest = template.get(digest_key)
            if not isinstance(path, str) or not path or not isinstance(digest, str) or not digest:
                return None
            return (
                {
                    "path": path,
                    "digest": digest,
                    "mediaType": (
                        template.get(media_type_key, "application/octet-stream")
                        if media_type_key
                        else "application/json"
                    ),
                },
                self._artifact(session, release.artifact_digest),
            )

    def providers(
        self, node_type: str, dinkster_version: str | None, include_prerelease: bool
    ) -> NodeProvidersResponse:
        with self.database.session() as session:
            rows = session.execute(
                select(ReleaseNodeRecord, ReleaseRecord, PackRecord, ArtifactRecord)
                .join(ReleaseRecord, ReleaseRecord.id == ReleaseNodeRecord.release_id)
                .join(PackRecord, PackRecord.id == ReleaseRecord.pack_id)
                .join(ArtifactRecord, ArtifactRecord.digest == ReleaseRecord.artifact_digest)
                .where(
                    ReleaseNodeRecord.node_type == node_type,
                    ReleaseRecord.state == "active",
                    PackRecord.visibility == "public",
                )
            ).all()
            candidates: list[
                tuple[Version, ReleaseNodeRecord, ReleaseRecord, PackRecord, ArtifactRecord]
            ] = []
            for node, release, pack, artifact in rows:
                try:
                    parsed_version = Version(release.version)
                    compatible = SpecifierSet(str(release.manifest["dinkster"]))
                except (InvalidVersion, InvalidSpecifier, KeyError) as exc:
                    raise CatalogDataError("stored release compatibility is invalid") from exc
                if parsed_version.is_prerelease and not include_prerelease:
                    continue
                if dinkster_version is not None and not compatible.contains(
                    dinkster_version, prereleases=True
                ):
                    continue
                candidates.append((parsed_version, node, release, pack, artifact))

            candidates.sort(key=lambda item: item[0], reverse=True)
            providers: list[dict[str, object]] = []
            seen_packs: set[UUID] = set()
            for _, node, release, pack, artifact in candidates:
                if pack.id in seen_packs:
                    continue
                seen_packs.add(pack.id)
                providers.append(
                    {
                        "packId": pack.id,
                        "packName": pack.name,
                        "displayName": pack.display_name,
                        "owner": self._owner(pack),
                        "visibility": pack.visibility,
                        "version": release.version,
                        "schemaVersion": node.schema_version,
                        "schemaSignature": node.schema_signature,
                        "role": node.role,
                        "artifactDigest": artifact.digest,
                        "trustSummary": self._trust_summary(session, release),
                    }
                )
            return NodeProvidersResponse.model_validate(
                {"nodeType": node_type, "providers": providers}
            )

    def download_ticket(self, name: str, version: str, base_url: str) -> DownloadTicket | None:
        with self.database.session() as session:
            pack = self._pack(session, name)
            if pack is None or pack.visibility != "public":
                return None
            release = self._release(session, pack.id, version)
            if release is None or release.state not in {"active", "yanked"}:
                return None
            artifact = self._artifact(session, release.artifact_digest)
            return DownloadTicket.model_validate(
                {
                    "packName": pack.name,
                    "version": release.version,
                    "state": release.state,
                    "warning": release.state_reason if release.state == "yanked" else None,
                    "artifactDigest": artifact.digest,
                    "artifactSize": artifact.size,
                    "url": f"{base_url}/v1/artifacts/{artifact.digest}",
                    "expiresAt": None,
                    "requiredHeaders": {},
                }
            )

    def downloadable_artifact(
        self, digest: str
    ) -> tuple[ArtifactRecord, PackRecord, ReleaseRecord] | None:
        with self.database.session() as session:
            row = session.execute(
                select(ArtifactRecord, PackRecord, ReleaseRecord)
                .join(ReleaseRecord, ReleaseRecord.artifact_digest == ArtifactRecord.digest)
                .join(PackRecord, PackRecord.id == ReleaseRecord.pack_id)
                .where(
                    ArtifactRecord.digest == digest,
                    ReleaseRecord.state.in_(("active", "yanked")),
                    PackRecord.visibility == "public",
                )
                .limit(1)
            ).one_or_none()
            return None if row is None else (row[0], row[1], row[2])

    def security_blocks(self) -> SecurityBlocksResponse:
        with self.database.session() as session:
            # A persisted block feed must derive this timestamp from block records.
            generated_at = session.scalar(select(func.max(PackRecord.updated_at)))
            return SecurityBlocksResponse.model_validate(
                {
                    "generatedAt": generated_at or datetime(1970, 1, 1, tzinfo=UTC),
                    "items": [],
                    "nextCursor": None,
                }
            )

    def health(self) -> HealthResponse:
        with self.database.session() as session:
            return HealthResponse(
                status="ok",
                packs=session.scalar(
                    select(func.count(func.distinct(PackRecord.id)))
                    .join(ReleaseRecord, ReleaseRecord.pack_id == PackRecord.id)
                    .where(ReleaseRecord.state.in_(("active", "yanked")))
                )
                or 0,
                releases=session.scalar(
                    select(func.count())
                    .select_from(ReleaseRecord)
                    .where(ReleaseRecord.state.in_(("active", "yanked")))
                )
                or 0,
                artifacts=session.scalar(
                    select(func.count(func.distinct(ArtifactRecord.digest)))
                    .join(ReleaseRecord, ReleaseRecord.artifact_digest == ArtifactRecord.digest)
                    .where(ReleaseRecord.state.in_(("active", "yanked")))
                )
                or 0,
            )
