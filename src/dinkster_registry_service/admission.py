from __future__ import annotations

import io
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

from dinkster_registry.archive_admission import (
    SCAN_POLICY_VERSION,
    AdmissionFinding,
    StageResult,
    run_doctor_static,
    run_executable_probe,
)
from dinkster_schema import (
    canonical_claim,
    canonical_name,
    claims_conflict,
    comfy_alias_registry_problems,
    comfy_group_registry_problems,
    reserved_root,
    schema_from_wire,
)
from dinkster_workers.manifest import load_manifest
from packaging.requirements import Requirement
from packaging.version import Version
from sqlalchemy import and_, or_, select, text
from sqlalchemy.orm import Session

from .admission_checks import check_wheel_catalog, run_manifest_admission
from .database import (
    ArtifactRecord,
    AuditEventRecord,
    Database,
    NamespaceGrantRecord,
    OutboxRecord,
    PackRecord,
    ReleaseAttestationRecord,
    ReleaseCandidateRecord,
    ReleaseCloudEvaluationRecord,
    ReleaseDependencyRecord,
    ReleaseFindingRecord,
    ReleaseNodeRecord,
    ReleaseRecord,
    ReleaseScanRunRecord,
)
from .digests import artifact_digest, artifact_object_key
from .identifiers import require_canonical_pack_name
from .ids import uuid7
from .indexes import StaticIndexes, queue_index_rebuild
from .object_store import MAX_ARTIFACT_SIZE, ObjectStore, ObjectStoreError
from .pack_locks import lock_object_key, parse_pack_locks, quarantine_lock_key
from .seed import MEDIA_TYPE
from .settings import ServerSettings
from .versioning import public_version_key, require_public_version
from .wheels import (
    WheelError,
    extracted_wheel,
    inspect_wheel,
    run_wheel_integrity,
    run_wheel_security,
)

DEFAULT_LEASE_SECONDS = 60
RESCAN_INTERVAL = timedelta(days=30)


class AdmissionError(RuntimeError):
    """An operator admission action cannot be completed."""


class LeaseLost(AdmissionError):
    """A scanner lease was replaced by a newer fencing token."""


class PromotionConflict(AdmissionError):
    """Immutable catalog state conflicts with a scanned candidate."""


@dataclass(frozen=True)
class CandidateClaim:
    id: UUID
    kind: str
    release_id: UUID | None
    pack_name: str
    version: str
    declared_digest: str
    declared_size: int
    object_key: str
    lease_token: UUID
    attempt: int


@dataclass(frozen=True)
class CandidateStatus:
    id: UUID
    kind: str
    pack_name: str
    version: str
    digest: str
    size: int
    status: str
    reason: str | None
    attempts: int
    findings: tuple[AdmissionFinding, ...]


def quarantine_object_key(candidate_id: UUID) -> str:
    return f"quarantine/uploads/{candidate_id}"


def _doctor_pending() -> dict[str, object]:
    return {
        "status": "failed",
        "doctorVersion": "0.0.1",
        "reportVersion": 1,
        "errorCount": 1,
        "warningCount": 0,
    }


def _scan_payload(status: str, now: datetime) -> dict[str, object]:
    return {
        "status": status,
        "policyVersion": SCAN_POLICY_VERSION,
        "scannedAt": now.isoformat(),
    }


def _provenance(principal: str) -> dict[str, object]:
    return {
        "kind": "interactive",
        "verified": False,
        "repository": None,
        "commitSha": None,
        "workflowRef": None,
        "principalId": principal,
    }


def _vulnerabilities() -> dict[str, object]:
    return {
        "status": "unavailable",
        "critical": 0,
        "high": 0,
        "moderate": 0,
        "low": 0,
        "databaseAsOf": None,
    }


class AdmissionService:
    def __init__(
        self,
        database: Database,
        object_store: ObjectStore,
        *,
        settings: ServerSettings | None = None,
        worker_id: str = "registry-scanner",
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
        require_isolation: bool = True,
    ) -> None:
        if lease_seconds < 1:
            raise ValueError("lease_seconds must be positive")
        self.database = database
        self.object_store = object_store
        self.settings = settings or ServerSettings()
        self.indexes = StaticIndexes(database, object_store, self.settings.public_base_url)
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds
        self.require_isolation = require_isolation

    def submit(
        self,
        archive: bytes,
        *,
        pack_name: str,
        version: str,
        submitted_by: str = "operator",
        publisher: str | None = None,
        declared_digest: str | None = None,
        declared_size: int | None = None,
        locks: bytes | None = None,
    ) -> UUID:
        require_canonical_pack_name(pack_name)
        require_public_version(version)
        if not submitted_by or len(submitted_by) > 128:
            raise AdmissionError("submitted_by must contain 1 through 128 characters")
        digest = artifact_digest(archive) if declared_digest is None else declared_digest
        size = len(archive) if declared_size is None else declared_size
        if not 1 <= size <= MAX_ARTIFACT_SIZE:
            raise AdmissionError(f"declared size must be between 1 and {MAX_ARTIFACT_SIZE} bytes")
        prepared = (
            parse_pack_locks(locks, pack=pack_name, digest=digest) if locks is not None else ()
        )
        if prepared and (digest != artifact_digest(archive) or size != len(archive)):
            raise AdmissionError("lock-bearing submission archive identity does not match bytes")
        install_locks = {
            lock.variant: {
                "baseId": lock.base_id,
                "artifactDigest": digest,
                "digest": lock.digest,
                "size": len(lock.data),
            }
            for lock in prepared
        }
        candidate_id = uuid7()
        object_key = quarantine_object_key(candidate_id)
        self.object_store.put(object_key, archive)
        try:
            for lock in prepared:
                self.object_store.put(quarantine_lock_key(candidate_id, lock.variant), lock.data)
            with self.database.session() as session, session.begin():
                if prepared:
                    if self.database.is_postgresql:
                        session.execute(
                            text("SELECT pg_advisory_xact_lock(hashtext(:identity))"),
                            {"identity": f"{pack_name}:{public_version_key(version)}"},
                        )
                    else:
                        session.execute(text("BEGIN IMMEDIATE"))
                    previous = session.scalar(
                        select(ReleaseCandidateRecord)
                        .where(
                            ReleaseCandidateRecord.kind == "upload",
                            ReleaseCandidateRecord.pack_name == pack_name,
                            ReleaseCandidateRecord.version_key == public_version_key(version),
                            ReleaseCandidateRecord.publisher_id == publisher,
                        )
                        .order_by(ReleaseCandidateRecord.submitted_at)
                        .limit(1)
                    )
                    if previous is not None:
                        if (
                            previous.declared_digest != digest
                            or previous.declared_size != size
                            or previous.install_locks != install_locks
                        ):
                            raise AdmissionError(
                                "release already has different archive or lock bindings"
                            )
                        self.object_store.remove(object_key)
                        for lock in prepared:
                            self.object_store.remove(
                                quarantine_lock_key(candidate_id, lock.variant)
                            )
                        return previous.id
                now = datetime.now(UTC)
                session.add(
                    ReleaseCandidateRecord(
                        id=candidate_id,
                        kind="upload",
                        release_id=None,
                        publisher_id=publisher,
                        pack_name=pack_name,
                        version=version,
                        version_key=public_version_key(version),
                        declared_digest=digest,
                        declared_size=size,
                        object_key=object_key,
                        install_locks=install_locks,
                        status="queued",
                        status_reason=None,
                        submitted_at=now,
                        submitted_by=submitted_by,
                        lease_owner=None,
                        lease_token=None,
                        lease_version=0,
                        lease_expires_at=None,
                        attempt_count=0,
                        manifest=None,
                        schemas=None,
                        doctor=None,
                        scan=None,
                    )
                )
                session.add(
                    AuditEventRecord(
                        id=uuid7(),
                        created_at=now,
                        event_type="release_candidate.submitted",
                        subject_type="release_candidate",
                        subject_id=str(candidate_id),
                        data={"packName": pack_name, "version": version, "digest": digest},
                    )
                )
        except BaseException:
            self.object_store.remove(object_key)
            for lock in prepared:
                self.object_store.remove(quarantine_lock_key(candidate_id, lock.variant))
            raise
        return candidate_id

    def schedule_rescan(
        self, pack_name: str, version: str, *, submitted_by: str = "operator"
    ) -> UUID:
        require_canonical_pack_name(pack_name)
        require_public_version(version)
        with self.database.session() as session, session.begin():
            row = session.execute(
                select(ReleaseRecord, PackRecord, ArtifactRecord)
                .join(PackRecord, PackRecord.id == ReleaseRecord.pack_id)
                .join(ArtifactRecord, ArtifactRecord.digest == ReleaseRecord.artifact_digest)
                .where(
                    PackRecord.name == pack_name,
                    ReleaseRecord.version == version,
                    ReleaseRecord.state == "active",
                )
                .with_for_update(of=ReleaseRecord)
            ).one_or_none()
            if row is None:
                raise AdmissionError("rescan requires an active release")
            release, pack, artifact = row
            candidate_id = uuid7()
            now = datetime.now(UTC)
            session.add(
                ReleaseCandidateRecord(
                    id=candidate_id,
                    kind="rescan",
                    release_id=release.id,
                    publisher_id=pack.publisher_id,
                    pack_name=pack_name,
                    version=version,
                    version_key=release.version_key,
                    declared_digest=artifact.digest,
                    declared_size=artifact.size,
                    object_key=artifact.object_key,
                    status="queued",
                    status_reason=None,
                    submitted_at=now,
                    submitted_by=submitted_by,
                    lease_owner=None,
                    lease_token=None,
                    lease_version=0,
                    lease_expires_at=None,
                    attempt_count=0,
                    manifest=dict(release.manifest),
                    schemas=None,
                    doctor=None,
                    scan=None,
                )
            )
            session.add(
                AuditEventRecord(
                    id=uuid7(),
                    created_at=now,
                    event_type="release.rescan_scheduled",
                    subject_type="release",
                    subject_id=str(release.id),
                    data={"candidateId": str(candidate_id)},
                )
            )
        return candidate_id

    def claim(self) -> CandidateClaim | None:
        now = datetime.now(UTC)
        with self.database.session() as session, session.begin():
            while True:
                candidate = session.scalar(
                    select(ReleaseCandidateRecord)
                    .where(
                        or_(
                            ReleaseCandidateRecord.status == "queued",
                            and_(
                                ReleaseCandidateRecord.status == "scanning",
                                ReleaseCandidateRecord.lease_expires_at <= now,
                            ),
                        )
                    )
                    .order_by(ReleaseCandidateRecord.submitted_at, ReleaseCandidateRecord.id)
                    .with_for_update(skip_locked=True)
                    .limit(1)
                )
                if candidate is None:
                    return None
                if candidate.attempt_count < self.settings.scanner_max_attempts:
                    break
                run_id = uuid7()
                session.add(
                    ReleaseScanRunRecord(
                        id=run_id,
                        release_id=None,
                        candidate_id=candidate.id,
                        created_at=now,
                        accepted=False,
                        stage="scanner_attempt_limit",
                        attempt=candidate.attempt_count,
                        policy_version=SCAN_POLICY_VERSION,
                        operator_details={"maxAttempts": self.settings.scanner_max_attempts},
                        doctor=candidate.doctor or _doctor_pending(),
                        scan=_scan_payload("failed", now),
                        provenance=_provenance(candidate.submitted_by),
                        vulnerabilities=_vulnerabilities(),
                    )
                )
                session.flush()
                session.add(
                    ReleaseFindingRecord(
                        id=uuid7(),
                        scan_run_id=run_id,
                        created_at=now,
                        code="scanner.attempt-limit",
                        severity="error",
                        effect="block",
                        message="Scanner recovery attempts were exhausted.",
                    )
                )
                candidate.status = "rejected"
                candidate.status_reason = "scanner.attempt-limit"
                candidate.lease_owner = None
                candidate.lease_token = None
                candidate.lease_expires_at = None
            token = uuid7()
            candidate.lease_owner = self.worker_id
            candidate.lease_token = token
            candidate.lease_version += 1
            candidate.lease_expires_at = now + timedelta(seconds=self.lease_seconds)
            candidate.attempt_count += 1
            candidate.status = "scanning"
            return CandidateClaim(
                id=candidate.id,
                kind=candidate.kind,
                release_id=candidate.release_id,
                pack_name=candidate.pack_name,
                version=candidate.version,
                declared_digest=candidate.declared_digest,
                declared_size=candidate.declared_size,
                object_key=candidate.object_key,
                lease_token=token,
                attempt=candidate.attempt_count,
            )

    @staticmethod
    def _leased_candidate(session: Session, claim: CandidateClaim) -> ReleaseCandidateRecord:
        candidate = session.scalar(
            select(ReleaseCandidateRecord)
            .where(ReleaseCandidateRecord.id == claim.id)
            .with_for_update()
        )
        if candidate is None or candidate.lease_token != claim.lease_token:
            raise LeaseLost(f"candidate {claim.id} lease was replaced")
        return candidate

    def _record_stage(self, claim: CandidateClaim, stage: str, result: StageResult) -> bool:
        with self.database.session() as session, session.begin():
            candidate = self._leased_candidate(session, claim)
            now = datetime.now(UTC)
            doctor = (
                cast("dict[str, object]", result.data)
                if stage == "doctor_static" and result.data is not None
                else candidate.doctor or _doctor_pending()
            )
            scan_status = (
                "failed"
                if result.blocked
                else "warning"
                if result.review
                or any(finding.severity == "warning" for finding in result.findings)
                else "passed"
            )
            scan = _scan_payload(scan_status, now)
            run_id = uuid7()
            session.add(
                ReleaseScanRunRecord(
                    id=run_id,
                    release_id=None,
                    candidate_id=candidate.id,
                    created_at=now,
                    accepted=not result.blocked and not result.review,
                    stage=stage,
                    attempt=claim.attempt,
                    policy_version=SCAN_POLICY_VERSION,
                    operator_details=result.operator_details,
                    doctor=doctor,
                    scan=scan,
                    provenance=_provenance(candidate.submitted_by),
                    vulnerabilities=_vulnerabilities(),
                )
            )
            session.flush()
            for finding in result.findings:
                session.add(
                    ReleaseFindingRecord(
                        id=uuid7(),
                        scan_run_id=run_id,
                        created_at=now,
                        code=finding.code,
                        severity=finding.severity,
                        effect=finding.effect,
                        message=finding.message,
                    )
                )
            if stage == "manifest" and result.data is not None:
                candidate.manifest = result.data
            elif stage == "doctor_static" and result.data is not None:
                candidate.doctor = result.data
            elif stage == "executable_probe" and result.data is not None:
                candidate.schemas = cast("list[dict[str, Any]]", result.data["schemas"])
            elif stage == "fast_security" and result.data is not None:
                candidate.scan = result.data
            candidate.lease_expires_at = now + timedelta(seconds=self.lease_seconds)
            if result.blocked:
                candidate.status = "rejected"
                candidate.status_reason = next(
                    finding.code for finding in result.findings if finding.effect == "block"
                )
                candidate.lease_owner = None
                candidate.lease_token = None
                candidate.lease_expires_at = None
                if candidate.kind == "rescan" and candidate.release_id is not None:
                    self._quarantine_release(
                        session,
                        candidate.release_id,
                        reason=candidate.status_reason,
                        now=now,
                    )
                return False
            return True

    def _mark_review(self, claim: CandidateClaim) -> None:
        with self.database.session() as session, session.begin():
            candidate = self._leased_candidate(session, claim)
            finding = (
                session.execute(
                    select(ReleaseFindingRecord)
                    .join(ReleaseScanRunRecord)
                    .where(
                        ReleaseScanRunRecord.candidate_id == candidate.id,
                        ReleaseScanRunRecord.attempt == claim.attempt,
                        ReleaseFindingRecord.effect == "review",
                    )
                    .order_by(ReleaseFindingRecord.created_at, ReleaseFindingRecord.id)
                )
                .scalars()
                .first()
            )
            candidate.status = "review"
            candidate.status_reason = finding.code if finding is not None else "operator-review"
            candidate.lease_owner = None
            candidate.lease_token = None
            candidate.lease_expires_at = None

    def _candidate_findings(
        self, session: Session, candidate_id: UUID, *, attempt: int | None = None
    ) -> list[ReleaseFindingRecord]:
        statement = (
            select(ReleaseFindingRecord)
            .join(ReleaseScanRunRecord)
            .where(ReleaseScanRunRecord.candidate_id == candidate_id)
            .order_by(ReleaseFindingRecord.created_at, ReleaseFindingRecord.id)
        )
        if attempt is not None:
            statement = statement.where(ReleaseScanRunRecord.attempt == attempt)
        return list(session.scalars(statement))

    @staticmethod
    def _quarantine_release(
        session: Session, release_id: UUID, *, reason: str, now: datetime
    ) -> None:
        release = session.get(ReleaseRecord, release_id, with_for_update=True)
        if release is None:
            return
        release.state = "quarantined"
        release.state_reason = reason
        release.state_changed_at = now
        queue_index_rebuild(session)
        pack = session.get(PackRecord, release.pack_id)
        if pack is None or pack.latest_version != release.version:
            return
        alternatives = session.scalars(
            select(ReleaseRecord).where(
                ReleaseRecord.pack_id == release.pack_id,
                ReleaseRecord.id != release.id,
                ReleaseRecord.state == "active",
            )
        )
        replacement = max(
            alternatives,
            key=lambda value: Version(value.version),
            default=None,
        )
        if replacement is not None:
            pack.latest_version = replacement.version
        pack.updated_at = now

    def _record_promotion_conflict(self, claim: CandidateClaim, message: str) -> None:
        self._record_stage(
            claim,
            "commit",
            StageResult(
                (AdmissionFinding("manifest.version-conflict", "error", "block", message),)
            ),
        )

    def _prepare_promotion(self, claim: CandidateClaim, data: bytes) -> None:
        try:
            wheel = inspect_wheel(data, claim.pack_name, claim.version)
            with self.database.session() as session, session.begin():
                if not self.database.is_postgresql:
                    session.connection().exec_driver_sql("BEGIN IMMEDIATE")
                candidate = self._leased_candidate(session, claim)
                if self.database.is_postgresql:
                    session.execute(
                        text("SELECT pg_advisory_xact_lock(hashtext(:pack_name))"),
                        {"pack_name": candidate.pack_name},
                    )
                    session.execute(text("LOCK TABLE namespace_grants IN SHARE ROW EXCLUSIVE MODE"))
                check_wheel_catalog(wheel, session)
                pack = session.scalar(
                    select(PackRecord)
                    .where(PackRecord.name == candidate.pack_name)
                    .with_for_update()
                )
                if pack is not None:
                    if (
                        candidate.publisher_id is not None
                        and pack.publisher_id != candidate.publisher_id
                    ):
                        raise PromotionConflict(
                            f"pack {candidate.pack_name!r} belongs to another publisher"
                        )
                    conflict = session.scalar(
                        select(ReleaseRecord.id).where(
                            ReleaseRecord.pack_id == pack.id,
                            or_(
                                ReleaseRecord.version == candidate.version,
                                ReleaseRecord.version_key == candidate.version_key,
                            ),
                        )
                    )
                    if conflict is not None:
                        raise PromotionConflict(
                            "release version or semantic collision key already exists"
                        )
                manifest = candidate.manifest
                schemas = candidate.schemas
                if manifest is None or schemas is None or candidate.doctor is None:
                    raise PromotionConflict("candidate scan evidence is incomplete")
                now = datetime.now(UTC)
                if pack is None:
                    pack_id = uuid7()
                    owner_id = uuid7()
                    pack = PackRecord(
                        id=pack_id,
                        name=candidate.pack_name,
                        publisher_id=candidate.publisher_id,
                        display_name=candidate.pack_name.replace("-", " ").title(),
                        description=f"Dinkster pack {candidate.pack_name}.",
                        long_description="",
                        owner_type="org" if candidate.publisher_id is not None else "user",
                        owner_id=owner_id,
                        owner_slug=candidate.publisher_id or "operator",
                        owner_display_name=(candidate.publisher_id or "Registry Operator"),
                        visibility="public",
                        homepage=None,
                        repository=cast("str | None", manifest.get("repository")),
                        support=None,
                        tags=[],
                        latest_version=candidate.version,
                        created_at=now,
                        updated_at=now,
                        download_count=0,
                        pack_notice=None,
                    )
                    session.add(pack)
                    session.flush()
                claims = {
                    canonical_name(candidate.pack_name),
                    *(
                        canonical_claim(value)
                        for value in cast("list[str]", manifest["namespaces"])
                    ),
                }
                if wheel.library:
                    claims = set()
                grants = list(session.scalars(select(NamespaceGrantRecord)))
                for claim_name in sorted(claims):
                    for held_grant in grants:
                        if claims_conflict(claim_name, held_grant.claim) and (
                            held_grant.publisher_id != candidate.publisher_id
                            or (candidate.publisher_id is None and held_grant.pack_id != pack.id)
                        ):
                            raise PromotionConflict(
                                f"namespace claim {claim_name!r} is unavailable"
                            )
                for claim_name in sorted(claims):
                    grant = session.get(NamespaceGrantRecord, claim_name)
                    if grant is None:
                        session.add(
                            NamespaceGrantRecord(
                                claim=claim_name,
                                pack_id=pack.id,
                                publisher_id=candidate.publisher_id,
                                owner_id=pack.owner_id,
                            )
                        )

                final_key = artifact_object_key(candidate.declared_digest)
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    manifest_digest = artifact_digest(
                        archive.read(wheel.manifest_path) if wheel.manifest_path else b""
                    )
                artifact = session.get(ArtifactRecord, candidate.declared_digest)
                if artifact is None:
                    session.add(
                        ArtifactRecord(
                            digest=candidate.declared_digest,
                            size=candidate.declared_size,
                            media_type=MEDIA_TYPE,
                            manifest_digest=manifest_digest,
                            object_key=final_key,
                        )
                    )
                elif (
                    artifact.size != candidate.declared_size
                    or artifact.manifest_digest != manifest_digest
                    or artifact.object_key != final_key
                ):
                    raise PromotionConflict("artifact digest has conflicting immutable metadata")

                release_id = uuid7()
                release = ReleaseRecord(
                    id=release_id,
                    pack_id=pack.id,
                    version=candidate.version,
                    version_key=candidate.version_key,
                    state="pending_scan",
                    state_reason=None,
                    state_changed_at=now,
                    published_at=now,
                    published_by_kind="interactive",
                    published_by_principal_id=candidate.submitted_by,
                    artifact_digest=candidate.declared_digest,
                    manifest=manifest,
                    install_locks=candidate.install_locks,
                    next_scan_at=now + RESCAN_INTERVAL,
                )
                session.add(release)
                session.flush()
                candidate.release_id = release_id
                for schema in schemas:
                    session.add(
                        ReleaseNodeRecord(
                            release_id=release_id,
                            node_type=cast("str", schema["nodeType"]),
                            schema_version=cast("int", schema["schemaVersion"]),
                            schema_wire_version=cast("int", schema["schemaWireVersion"]),
                            schema_signature=cast("str", schema["schemaSignature"]),
                            role=cast("str", schema["role"]),
                            schema=cast("dict[str, Any]", schema["schema"]),
                        )
                    )
                for dependency in cast("list[dict[str, str]]", manifest["dependencies"]):
                    session.add(
                        ReleaseDependencyRecord(
                            release_id=release_id,
                            pack_name=dependency["packName"],
                            version_range=dependency["versionRange"],
                        )
                    )
                accepted_run_id = uuid7()
                candidate_findings = self._candidate_findings(
                    session, candidate.id, attempt=claim.attempt
                )
                warning_count = sum(finding.severity == "warning" for finding in candidate_findings)
                session.add(
                    ReleaseScanRunRecord(
                        id=accepted_run_id,
                        release_id=release_id,
                        candidate_id=None,
                        created_at=now,
                        accepted=True,
                        stage="admission",
                        attempt=claim.attempt,
                        policy_version=SCAN_POLICY_VERSION,
                        doctor=candidate.doctor,
                        scan=_scan_payload("warning" if warning_count else "passed", now),
                        provenance=_provenance(candidate.submitted_by),
                        vulnerabilities=_vulnerabilities(),
                    )
                )
                session.flush()
                for finding in candidate_findings:
                    session.add(
                        ReleaseFindingRecord(
                            id=uuid7(),
                            scan_run_id=accepted_run_id,
                            created_at=now,
                            code=finding.code,
                            severity=finding.severity,
                            effect=finding.effect,
                            message=finding.message,
                        )
                    )
                session.add(
                    ReleaseAttestationRecord(
                        id=uuid7(),
                        release_id=release_id,
                        created_at=now,
                        status="missing",
                        statement_url=None,
                    )
                )
                session.add(
                    ReleaseCloudEvaluationRecord(
                        id=uuid7(),
                        release_id=release_id,
                        created_at=now,
                        registry_eligible=True,
                        reason_codes=[],
                        policy_version="cloud-pack/1",
                    )
                )
                session.add(
                    AuditEventRecord(
                        id=uuid7(),
                        created_at=now,
                        event_type="release.admitted",
                        subject_type="release",
                        subject_id=str(release_id),
                        data={
                            "candidateId": str(candidate.id),
                            "digest": candidate.declared_digest,
                        },
                    )
                )
                session.add(
                    OutboxRecord(
                        id=uuid7(),
                        created_at=now,
                        available_at=now,
                        delivered_at=None,
                        topic="artifact.promote",
                        event_key=f"artifact.promote:{candidate.id}",
                        payload={
                            "candidateId": str(candidate.id),
                            "releaseId": str(release_id),
                            "sourceKey": candidate.object_key,
                            "destinationKey": final_key,
                        },
                        state="pending",
                        attempts=0,
                    )
                )
                candidate.status = "promoting"
                candidate.status_reason = None
        except WheelError as exc:
            self._record_stage(
                claim,
                "commit",
                StageResult((AdmissionFinding(exc.code, "error", "block", str(exc)),)),
            )
            return
        except PromotionConflict as exc:
            self._record_promotion_conflict(claim, str(exc))
            return
        self.deliver_one_promotion()

    def deliver_one_promotion(self) -> bool:
        failure: BaseException | None = None
        source_key = ""
        with self.database.session() as session, session.begin():
            outbox = session.scalar(
                select(OutboxRecord)
                .where(
                    OutboxRecord.topic == "artifact.promote",
                    OutboxRecord.state == "pending",
                    OutboxRecord.available_at <= datetime.now(UTC),
                )
                .order_by(OutboxRecord.created_at, OutboxRecord.id)
                .with_for_update(skip_locked=True)
                .limit(1)
            )
            if outbox is None:
                return False
            payload = outbox.payload
            candidate_id = UUID(cast("str", payload["candidateId"]))
            release_id = UUID(cast("str", payload["releaseId"]))
            source_key = cast("str", payload["sourceKey"])
            destination_key = cast("str", payload["destinationKey"])
            candidate = session.get(ReleaseCandidateRecord, candidate_id)
            release = session.get(ReleaseRecord, release_id)
            if candidate is None or release is None:
                raise AdmissionError("promotion outbox references absent catalog state")
            try:
                if self.object_store.exists(source_key):
                    data = self.object_store.read(source_key, max_size=MAX_ARTIFACT_SIZE)
                    integrity = run_wheel_integrity(
                        data,
                        candidate.declared_size,
                        candidate.declared_digest,
                        candidate.pack_name,
                        candidate.version,
                    )
                    if integrity.blocked:
                        raise AdmissionError("quarantine object changed before promotion")
                    self.object_store.put(destination_key, data)
                else:
                    stored = self.object_store.open(
                        destination_key,
                        expected_size=candidate.declared_size,
                        expected_digest=candidate.declared_digest,
                    )
                    stored.close()
                for variant, lock in release.install_locks.items():
                    source = quarantine_lock_key(candidate_id, variant)
                    destination = lock_object_key(lock["digest"])
                    if self.object_store.exists(source):
                        stored = self.object_store.open(
                            source, expected_size=lock["size"], expected_digest=lock["digest"]
                        )
                        self.object_store.put(destination, b"".join(stored))
                    stored = self.object_store.open(
                        destination, expected_size=lock["size"], expected_digest=lock["digest"]
                    )
                    stored.close()
            except (AdmissionError, FileNotFoundError, ObjectStoreError) as exc:
                failure = exc
                outbox.attempts += 1
                outbox.available_at = datetime.now(UTC) + timedelta(seconds=5)
                candidate.status_reason = "artifact-promotion-retry"
            if failure is None:
                now = datetime.now(UTC)
                pack = session.get(PackRecord, release.pack_id, with_for_update=True)
                if pack is None:
                    raise AdmissionError("promotion release references absent pack")
                release.state = "active"
                release.state_reason = None
                release.state_changed_at = now
                current = session.scalar(
                    select(ReleaseRecord).where(
                        ReleaseRecord.pack_id == pack.id,
                        ReleaseRecord.version == pack.latest_version,
                    )
                )
                if current is None or Version(release.version) >= Version(current.version):
                    pack.latest_version = release.version
                pack.updated_at = now
                candidate.status = "accepted"
                candidate.status_reason = None
                candidate.lease_owner = None
                candidate.lease_token = None
                candidate.lease_expires_at = None
                outbox.state = "delivered"
                outbox.delivered_at = now
                outbox.attempts += 1
                queue_index_rebuild(session)
                session.add(
                    AuditEventRecord(
                        id=uuid7(),
                        created_at=now,
                        event_type="release.activated",
                        subject_type="release",
                        subject_id=str(release.id),
                        data={"candidateId": str(candidate.id)},
                    )
                )
        if failure is not None:
            return True
        self.indexes.deliver_one()
        self.object_store.remove(source_key)
        for variant in release.install_locks:
            self.object_store.remove(quarantine_lock_key(candidate_id, variant))
        return True

    def _finish_rescan(self, claim: CandidateClaim, *, review: bool) -> None:
        with self.database.session() as session, session.begin():
            candidate = self._leased_candidate(session, claim)
            if candidate.release_id is None:
                raise AdmissionError("rescan candidate has no release")
            release = session.get(ReleaseRecord, candidate.release_id, with_for_update=True)
            if release is None:
                raise AdmissionError("rescan release is absent")
            now = datetime.now(UTC)
            findings = self._candidate_findings(session, candidate.id, attempt=claim.attempt)
            run_id = uuid7()
            session.add(
                ReleaseScanRunRecord(
                    id=run_id,
                    release_id=release.id,
                    candidate_id=None,
                    created_at=now,
                    accepted=not review,
                    stage="rescan",
                    attempt=claim.attempt,
                    policy_version=SCAN_POLICY_VERSION,
                    doctor=candidate.doctor or _doctor_pending(),
                    scan=_scan_payload("warning" if findings else "passed", now),
                    provenance=_provenance(candidate.submitted_by),
                    vulnerabilities=_vulnerabilities(),
                )
            )
            session.flush()
            for finding in findings:
                session.add(
                    ReleaseFindingRecord(
                        id=uuid7(),
                        scan_run_id=run_id,
                        created_at=now,
                        code=finding.code,
                        severity=finding.severity,
                        effect=finding.effect,
                        message=finding.message,
                    )
                )
            release.next_scan_at = now + RESCAN_INTERVAL
            candidate.status = "review" if review else "accepted"
            candidate.status_reason = "operator-review" if review else None
            candidate.lease_owner = None
            candidate.lease_token = None
            candidate.lease_expires_at = None
            session.add(
                AuditEventRecord(
                    id=uuid7(),
                    created_at=now,
                    event_type="release.rescanned",
                    subject_type="release",
                    subject_id=str(release.id),
                    data={"candidateId": str(candidate.id), "accepted": not review},
                )
            )

    def _process(self, claim: CandidateClaim) -> None:
        try:
            data = self.object_store.read(claim.object_key, max_size=MAX_ARTIFACT_SIZE)
        except (FileNotFoundError, ObjectStoreError) as exc:
            self._record_stage(
                claim,
                "ingest_integrity",
                StageResult(
                    (AdmissionFinding("integrity.object-unavailable", "error", "block", str(exc)),)
                ),
            )
            return
        review = False
        integrity = run_wheel_integrity(
            data, claim.declared_size, claim.declared_digest, claim.pack_name, claim.version
        )
        if claim.kind == "upload":
            if not self._record_stage(claim, "ingest_integrity", integrity):
                return
            review |= integrity.review
        elif integrity.blocked:
            self._record_stage(claim, "ingest_integrity", integrity)
            return
        wheel = inspect_wheel(data, claim.pack_name, claim.version)
        try:
            with self.database.session() as session:
                check_wheel_catalog(wheel, session)
        except WheelError as exc:
            self._record_stage(
                claim,
                "wheel",
                StageResult((AdmissionFinding(exc.code, "error", "block", str(exc)),)),
            )
            return
        with extracted_wheel(data, wheel) as root:
            if claim.kind == "upload":
                with self.database.session() as session:
                    candidate = self._leased_candidate(session, claim)
                    manifest = (
                        StageResult(
                            data={
                                "kind": "library",
                                "namespaces": [],
                                "dependencies": [],
                                "platforms": [],
                                "pythonRequirements": list(wheel.requirements),
                                "localeCatalogs": [],
                                "templates": [],
                            }
                        )
                        if wheel.library
                        else run_manifest_admission(
                            root,
                            claim.pack_name,
                            claim.version,
                            session,
                            publisher=candidate.publisher_id,
                        )
                    )
                    if (
                        wheel.library
                        and reserved_root(claim.pack_name) is not None
                        and candidate.publisher_id != "dinkster"
                    ):
                        manifest = StageResult(
                            (
                                AdmissionFinding(
                                    "wheel.reserved-name",
                                    "error",
                                    "block",
                                    "This distribution name requires the Dinkster publisher.",
                                ),
                            )
                        )
                if not manifest.blocked and manifest.data is not None:
                    metadata = manifest.data
                    if {Requirement(value) for value in metadata["pythonRequirements"]} != {
                        Requirement(value) for value in wheel.requirements
                    }:
                        manifest = StageResult(
                            (
                                AdmissionFinding(
                                    "wheel.invalid",
                                    "error",
                                    "block",
                                    "Manifest requires and METADATA Requires-Dist differ.",
                                ),
                            )
                        )
                    else:
                        metadata["wheel"] = {
                            "filename": wheel.filename,
                            "sha256": wheel.sha256,
                            "imports": list(wheel.imports),
                            "library": wheel.library,
                            "tags": sorted(str(tag) for tag in wheel.tags),
                            "manifestPath": wheel.manifest_path,
                        }
                if not self._record_stage(claim, "manifest", manifest):
                    return
                review |= manifest.review
            doctor = (
                StageResult(
                    data={
                        "status": "passed",
                        "doctorVersion": "0.0.1",
                        "reportVersion": 1,
                        "errorCount": 0,
                        "warningCount": 0,
                    }
                )
                if wheel.library
                else run_doctor_static(root)
            )
            if not self._record_stage(claim, "doctor_static", doctor):
                return
            review |= doctor.review
            if claim.kind == "upload" and wheel.library:
                self._record_stage(claim, "executable_probe", StageResult(data={"schemas": []}))
            if claim.kind == "upload" and not wheel.library:
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(
                        run_executable_probe,
                        root,
                        settings=self.settings,
                        require_isolation=self.require_isolation,
                    )
                    while not wait((future,), timeout=self.lease_seconds / 3).done:
                        with self.database.session() as session, session.begin():
                            candidate = self._leased_candidate(session, claim)
                            candidate.lease_expires_at = datetime.now(UTC) + timedelta(
                                seconds=self.lease_seconds
                            )
                    probe = future.result()
                if not self._record_stage(claim, "executable_probe", probe):
                    return
                review |= probe.review
                assert probe.data is not None
                parsed = load_manifest(root / "dinkster-pack.toml")
                schemas = {
                    item["nodeType"]: schema_from_wire(item["schema"])
                    for item in probe.data["schemas"]
                }
                problems: list[str] = []
                if parsed.comfy_aliases is not None:
                    problems.extend(comfy_alias_registry_problems(parsed.comfy_aliases, schemas))
                if parsed.comfy_groups is not None:
                    problems.extend(comfy_group_registry_problems(parsed.comfy_groups, schemas))
                if problems and not self._record_stage(
                    claim,
                    "translations",
                    StageResult(
                        tuple(
                            AdmissionFinding("translations.invalid", "error", "block", problem)
                            for problem in problems
                        )
                    ),
                ):
                    return
            security = run_wheel_security(data)
            if not self._record_stage(claim, "fast_security", security):
                return
            review |= security.review
        if review:
            if claim.kind == "rescan":
                self._finish_rescan(claim, review=True)
            else:
                self._mark_review(claim)
            return
        if claim.kind == "rescan":
            self._finish_rescan(claim, review=False)
        else:
            self._prepare_promotion(claim, data)

    def process(self, claim: CandidateClaim) -> None:
        try:
            self._process(claim)
        except LeaseLost:
            raise
        except Exception as exc:
            self._record_stage(
                claim,
                "scanner_internal",
                StageResult(
                    (
                        AdmissionFinding(
                            "scanner.unexpected-error",
                            "error",
                            "block",
                            "The scanner could not safely complete this candidate.",
                        ),
                    ),
                    operator_details={"exceptionType": type(exc).__name__},
                ),
            )

    def run_once(self) -> bool:
        if self.indexes.deliver_one():
            return True
        if self.deliver_one_promotion():
            return True
        claim = self.claim()
        if claim is None:
            return False
        self.process(claim)
        return True

    def run(self, *, poll_seconds: float = 1.0) -> None:
        if poll_seconds <= 0:
            raise ValueError("poll_seconds must be positive")
        while True:
            try:
                worked = self.run_once()
            except LeaseLost:
                continue
            if not worked:
                time.sleep(poll_seconds)

    def resolve_review(
        self, candidate_id: UUID, *, accepted: bool, actor: str, reason: str
    ) -> CandidateStatus:
        if not actor or not reason:
            raise AdmissionError("review resolution requires an actor and reason")
        claim: CandidateClaim | None = None
        with self.database.session() as session, session.begin():
            candidate = session.get(ReleaseCandidateRecord, candidate_id, with_for_update=True)
            if candidate is None:
                raise AdmissionError(f"candidate {candidate_id} was not found")
            if candidate.status != "review":
                raise AdmissionError("only a candidate awaiting review can be resolved")
            now = datetime.now(UTC)
            session.add(
                AuditEventRecord(
                    id=uuid7(),
                    created_at=now,
                    event_type=(
                        "release_candidate.review_accepted"
                        if accepted
                        else "release_candidate.review_rejected"
                    ),
                    subject_type="release_candidate",
                    subject_id=str(candidate.id),
                    data={"actor": actor, "reason": reason},
                )
            )
            if not accepted:
                candidate.status = "rejected"
                candidate.status_reason = reason
                if candidate.kind == "rescan" and candidate.release_id is not None:
                    self._quarantine_release(session, candidate.release_id, reason=reason, now=now)
            elif candidate.kind == "rescan":
                candidate.status = "accepted"
                candidate.status_reason = None
            else:
                token = uuid7()
                candidate.status = "scanning"
                candidate.status_reason = None
                candidate.lease_owner = actor
                candidate.lease_token = token
                candidate.lease_version += 1
                candidate.lease_expires_at = now + timedelta(seconds=self.lease_seconds)
                claim = CandidateClaim(
                    id=candidate.id,
                    kind=candidate.kind,
                    release_id=candidate.release_id,
                    pack_name=candidate.pack_name,
                    version=candidate.version,
                    declared_digest=candidate.declared_digest,
                    declared_size=candidate.declared_size,
                    object_key=candidate.object_key,
                    lease_token=token,
                    attempt=candidate.attempt_count,
                )
        if claim is not None:
            data = self.object_store.read(claim.object_key, max_size=MAX_ARTIFACT_SIZE)
            self._prepare_promotion(claim, data)
        return self.status(candidate_id)

    def status(self, candidate_id: UUID) -> CandidateStatus:
        with self.database.session() as session:
            candidate = session.get(ReleaseCandidateRecord, candidate_id)
            if candidate is None:
                raise AdmissionError(f"candidate {candidate_id} was not found")
            findings = self._candidate_findings(session, candidate_id)
            return CandidateStatus(
                id=candidate.id,
                kind=candidate.kind,
                pack_name=candidate.pack_name,
                version=candidate.version,
                digest=candidate.declared_digest,
                size=candidate.declared_size,
                status=candidate.status,
                reason=candidate.status_reason,
                attempts=candidate.attempt_count,
                findings=tuple(
                    AdmissionFinding(
                        finding.code,
                        cast("Any", finding.severity),
                        cast("Any", finding.effect),
                        finding.message,
                    )
                    for finding in findings
                ),
            )
