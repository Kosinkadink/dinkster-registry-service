from __future__ import annotations

import io
import socket
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from dinkster_registry import RegistryError, TokenRecord
from dinkster_registry.archive_admission import (
    SCAN_POLICY_VERSION,
    AdmissionFinding,
    StageResult,
    run_doctor_static,
)
from dinkster_schema import (
    canonical_claim,
    canonical_name,
    claims_conflict,
    reserved_root,
)
from dinkster_workers.manifest import load_manifest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version
from sqlalchemy import and_, func, or_, select, text
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
from .principals import PrincipalRepository
from .scan_engine import parse_scan_engine
from .scan_execution import ProbeDependencies, run_prepared_probe
from .security_publication import SecurityPublication
from .security_repository import (
    SecurityRepository,
    UploadAuthorization,
    UploadStopped,
    lock_security,
)
from .seed import MEDIA_TYPE
from .settings import ServerSettings
from .versioning import public_version_key, require_public_version
from .wheels import (
    Wheel,
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
    scan_engine: dict[str, str] | None = None


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
    def yank(
        self, pack_name: str, version: str, *, reason: str, token: TokenRecord | None = None
    ) -> None:
        """Withdraw a release without deleting files or changing security classification.

        HTTP callers supply a verified publisher token. The local operator CLI
        uses the same transaction without a publishing credential.
        """
        if not reason.strip():
            raise RegistryError("yank reason must not be blank")
        with self.database.session() as session, session.begin():
            lock_security(session)
            pack = session.scalar(select(PackRecord).where(PackRecord.name == pack_name))
            if token is not None:
                PrincipalRepository.require_current_token(
                    session,
                    token,
                    pack.publisher_id if pack is not None and pack.publisher_id else "",
                    pack_name,
                )
            release = session.scalar(
                select(ReleaseRecord)
                .join(PackRecord)
                .where(PackRecord.name == pack_name, ReleaseRecord.version == version)
                .with_for_update(of=ReleaseRecord)
            )
            if release is None:
                raise RegistryError(f"unknown release {pack_name} {version}")
            if release.state != "active":
                raise RegistryError(f"release is {release.state}; only active can be yanked")
            now = datetime.now(UTC)
            release.state = "yanked"
            release.state_reason = reason
            release.state_changed_at = now
            pack = session.get(PackRecord, release.pack_id, with_for_update=True)
            assert pack is not None
            if pack.latest_version == release.version:
                alternatives = session.scalars(
                    select(ReleaseRecord).where(
                        ReleaseRecord.pack_id == pack.id, ReleaseRecord.state == "active"
                    )
                )
                latest = max(alternatives, key=lambda row: Version(row.version), default=None)
                if latest is not None:
                    pack.latest_version = latest.version
            pack.updated_at = now
            session.add(
                AuditEventRecord(
                    id=uuid7(),
                    created_at=now,
                    event_type="release.yanked",
                    subject_type="release",
                    subject_id=str(release.id),
                    data={
                        "actor": token.minted_by if token is not None else "operator",
                        "reason": reason,
                    },
                )
            )
            queue_index_rebuild(session)
        try:
            self.indexes.rebuild()
        except ObjectStoreError as exc:
            raise RegistryError(
                "release yanked, but index rebuild failed; durable rebuild remains queued"
            ) from exc

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
        engine: bytes | None = None,
        authorization: UploadAuthorization | None = None,
    ) -> UUID:
        require_canonical_pack_name(pack_name)
        require_public_version(version)
        scan_engine = parse_scan_engine(engine)
        if authorization is not None:
            publisher = authorization.publisher
            submitted_by = authorization.actor
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
                lock_security(session)
                if authorization is not None:
                    SecurityRepository.require_authorization(session, authorization, pack_name)
                SecurityRepository.require_uploads(session, pack_name, publisher)
                supersedes = None
                if self.database.is_postgresql:
                    session.execute(
                        text("SELECT pg_advisory_xact_lock(hashtext(:identity))"),
                        {"identity": f"{pack_name}:{public_version_key(version)}"},
                    )
                previous_candidates = session.scalars(
                    select(ReleaseCandidateRecord)
                    .where(
                        ReleaseCandidateRecord.kind == "upload",
                        ReleaseCandidateRecord.pack_name == pack_name,
                        ReleaseCandidateRecord.version_key == public_version_key(version),
                        ReleaseCandidateRecord.publisher_id == publisher,
                    )
                    .order_by(ReleaseCandidateRecord.submitted_at.desc())
                ).all()
                if (
                    prepared
                    or scan_engine is not None
                    or any(item.scan_engine is not None for item in previous_candidates)
                ):
                    for recorded in previous_candidates:
                        if (
                            recorded.declared_digest != digest
                            or recorded.declared_size != size
                            or recorded.install_locks != install_locks
                            or recorded.scan_engine != scan_engine
                        ):
                            raise AdmissionError(
                                "release already has different archive, lock or engine bindings"
                            )
                    previous = next(
                        (item for item in previous_candidates if item.status != "rejected"), None
                    )
                    if previous is not None:
                        if previous.status not in {"queued", "retrying", "scanning", "accepted"}:
                            raise AdmissionError(f"release candidate is {previous.status}")
                        self.object_store.remove(object_key)
                        for lock in prepared:
                            self.object_store.remove(
                                quarantine_lock_key(candidate_id, lock.variant)
                            )
                        return previous.id
                    if previous_candidates:
                        supersedes = str(previous_candidates[0].id)
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
                        scan_engine=scan_engine,
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
                        data={
                            "packName": pack_name,
                            "version": version,
                            "digest": digest,
                            "authorization": authorization.model_dump()
                            if authorization is not None
                            else None,
                            **({"supersedesCandidateId": supersedes} if supersedes else {}),
                        },
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
                    scan_engine=release.scan_engine,
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
            if not self.database.is_postgresql:
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            candidate = session.scalar(
                select(ReleaseCandidateRecord)
                .where(
                    or_(
                        ReleaseCandidateRecord.status.in_(("queued", "retrying")),
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
            token = uuid7()
            candidate.lease_owner = self.worker_id
            candidate.lease_token = token
            candidate.lease_version += 1
            candidate.lease_expires_at = now + timedelta(seconds=self.lease_seconds)
            candidate.attempt_count += 1
            candidate.status = "scanning"
            candidate.status_reason = None
            session.add(
                AuditEventRecord(
                    id=uuid7(),
                    created_at=now,
                    event_type="release_candidate.claimed",
                    subject_type="release_candidate",
                    subject_id=str(candidate.id),
                    data={"worker": self.worker_id, "attempt": candidate.attempt_count},
                )
            )
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
                scan_engine=candidate.scan_engine,
            )

    def leased_claim(
        self, candidate_id: UUID, lease_token: UUID, *, renew: bool = False
    ) -> CandidateClaim:
        with self.database.session() as session, session.begin():
            if not self.database.is_postgresql:
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            candidate = session.get(ReleaseCandidateRecord, candidate_id, with_for_update=True)
            now = datetime.now(UTC)
            expiry = candidate.lease_expires_at if candidate is not None else None
            if expiry is not None and expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=UTC)
            if (
                candidate is None
                or candidate.status != "scanning"
                or candidate.lease_token != lease_token
                or expiry is None
                or expiry <= now
            ):
                raise LeaseLost("Scanner assignment is absent, expired or replaced.")
            if renew:
                candidate.lease_expires_at = now + timedelta(seconds=self.lease_seconds)
            return CandidateClaim(
                id=candidate.id,
                kind=candidate.kind,
                release_id=candidate.release_id,
                pack_name=candidate.pack_name,
                version=candidate.version,
                declared_digest=candidate.declared_digest,
                declared_size=candidate.declared_size,
                object_key=candidate.object_key,
                lease_token=lease_token,
                attempt=candidate.attempt_count,
                scan_engine=candidate.scan_engine,
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
            operator_details = result.operator_details
            if stage == "executable_probe":
                operator_details = {
                    **(operator_details or {}),
                    "scannerHost": socket.gethostname(),
                    "scannerWorker": self.worker_id,
                }
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
                    operator_details=operator_details,
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
                blocks = {finding.code for finding in result.findings if finding.effect == "block"}
                probe_timeout = blocks == {"probe.timeout"}
                install_timeout = (
                    blocks == {"probe.dependencies-unresolved"}
                    and (result.operator_details or {}).get("timedOut") is True
                )
                if stage == "executable_probe" and (probe_timeout or install_timeout):
                    # A lost worker has no timeout result and must not spend this budget.
                    timed_out_attempts = session.scalar(
                        select(func.count(ReleaseScanRunRecord.id.distinct()))
                        .join(ReleaseFindingRecord)
                        .where(
                            ReleaseScanRunRecord.candidate_id == candidate.id,
                            ReleaseScanRunRecord.stage == "executable_probe",
                            ReleaseFindingRecord.effect == "block",
                            or_(
                                ReleaseFindingRecord.code == "probe.timeout",
                                and_(
                                    ReleaseFindingRecord.code == "probe.dependencies-unresolved",
                                    ReleaseScanRunRecord.operator_details["timedOut"]
                                    .as_boolean()
                                    .is_(True),
                                ),
                            ),
                        )
                    )
                    assert timed_out_attempts is not None
                    limit = (
                        self.settings.probe_timeout_seconds
                        if probe_timeout
                        else self.settings.probe_dependency_timeout_seconds
                    )
                    candidate.status_reason = (
                        f"{candidate.status_reason}: {limit}s time limit exceeded "
                        f"after {timed_out_attempts} attempts"
                    )
                    if timed_out_attempts < self.settings.scanner_max_attempts:
                        candidate.status = "retrying"
                candidate.lease_owner = None
                candidate.lease_token = None
                candidate.lease_expires_at = None
                if (
                    candidate.status == "rejected"
                    and candidate.kind == "rescan"
                    and candidate.release_id is not None
                ):
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
                lock_security(session)
                candidate = self._leased_candidate(session, claim)
                authorization = SecurityRepository.require_candidate_upload(session, candidate)
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
                    published_by_kind="registry"
                    if authorization is not None and authorization.security_reason is not None
                    else "interactive",
                    published_by_principal_id=self.settings.public_base_url
                    if authorization is not None and authorization.security_reason is not None
                    else candidate.submitted_by,
                    artifact_digest=candidate.declared_digest,
                    manifest=manifest,
                    install_locks=candidate.install_locks,
                    scan_engine=candidate.scan_engine,
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
                            "authorization": authorization.model_dump()
                            if authorization is not None
                            else None,
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
        except (PromotionConflict, RegistryError) as exc:
            self._record_promotion_conflict(claim, str(exc))
            return
        self.deliver_one_promotion()

    def deliver_one_promotion(self) -> bool:
        failure: BaseException | None = None
        source_key = ""
        with self.database.session() as session, session.begin():
            lock_security(session)
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
                SecurityRepository.require_candidate_upload(session, candidate)
            except UploadStopped:
                outbox.available_at = datetime.now(UTC) + timedelta(seconds=60)
                candidate.status_reason = "uploads-stopped"
                return True
            except RegistryError as exc:
                now = datetime.now(UTC)
                candidate.status = "rejected"
                candidate.status_reason = "publication-unauthorized"
                release.state = "rejected"
                release.state_reason = "publication-unauthorized"
                release.state_changed_at = now
                outbox.state = "delivered"
                outbox.delivered_at = now
                session.add(
                    AuditEventRecord(
                        id=uuid7(),
                        created_at=now,
                        event_type="release.publication_refused",
                        subject_type="release",
                        subject_id=str(release.id),
                        data={"candidateId": str(candidate.id), "reason": str(exc)},
                    )
                )
                return True
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

    def _probe_library_wheels(self, requirements: set[str]) -> tuple[tuple[str, bytes], ...]:
        with self.database.session() as session:
            rows = session.execute(
                select(PackRecord, ReleaseRecord).join(
                    ReleaseRecord, ReleaseRecord.pack_id == PackRecord.id
                )
            ).all()
            libraries = {
                canonicalize_name(pack.name)
                for pack, release in rows
                if release.manifest.get("kind") == "library"
            }
            available: dict[str, list[ReleaseRecord]] = {name: [] for name in libraries}
            for pack, release in rows:
                name = canonicalize_name(pack.name)
                if name in libraries and pack.visibility == "public" and release.state == "active":
                    available[name].append(release)
            for releases in available.values():
                releases.sort(key=lambda release: Version(release.version), reverse=True)
            artifacts: dict[UUID, tuple[Wheel, bytes]] = {}

            def read(release: ReleaseRecord, name: str) -> tuple[Wheel, bytes]:
                if release.id not in artifacts:
                    artifact = session.get(ArtifactRecord, release.artifact_digest)
                    assert artifact is not None
                    data = self.object_store.read(artifact.object_key, max_size=MAX_ARTIFACT_SIZE)
                    if artifact_digest(data) != artifact.digest or len(data) != artifact.size:
                        raise ValueError(f"Library artifact changed for {name!r}.")
                    wheel = inspect_wheel(data, name, release.version)
                    if not wheel.library:
                        raise ValueError(f"Requirement {name!r} names a pack, not a library.")
                    if any(Requirement(value).url is not None for value in wheel.requirements):
                        raise ValueError(
                            f"Library {name!r} dependencies must use the package index."
                        )
                    artifacts[release.id] = wheel, data
                return artifacts[release.id]

            def resolve(
                pending: list[tuple[Requirement, frozenset[str]]],
                selected: dict[str, ReleaseRecord],
                expanded: frozenset[tuple[str, frozenset[str]]],
            ) -> dict[str, ReleaseRecord]:
                while pending:
                    requirement, parent_extras = pending.pop(0)
                    if requirement.marker is not None and not any(
                        requirement.marker.evaluate({"extra": extra})
                        for extra in parent_extras | {""}
                    ):
                        continue
                    name = canonicalize_name(requirement.name)
                    if name not in libraries:
                        continue
                    if requirement.url is not None:
                        raise ValueError(
                            f"Library requirement {requirement} must use the registry."
                        )
                    candidates = [selected[name]] if name in selected else available[name]
                    failure = ValueError(
                        f"No active public library {name!r} satisfies "
                        f"{str(requirement.specifier)!r}."
                    )
                    for release in candidates:
                        if not requirement.specifier.contains(release.version, prereleases=True):
                            continue
                        wheel, _ = read(release, name)
                        extras = frozenset(requirement.extras)
                        key = name, extras
                        children = (
                            [(Requirement(value), extras) for value in wheel.requirements]
                            if key not in expanded
                            else []
                        )
                        try:
                            return resolve(
                                [*pending, *children],
                                {**selected, name: release},
                                expanded | {key},
                            )
                        except ValueError as exc:
                            failure = exc
                    raise failure
                return selected

            selected = resolve(
                [(Requirement(value), frozenset()) for value in sorted(requirements)],
                {},
                frozenset(),
            )
            wheels = []
            for library_name, release in sorted(selected.items()):
                wheel, data = read(release, library_name)
                wheels.append((wheel.filename, data))
            return tuple(wheels)

    def _resolve_probe_dependencies(self, root: Path) -> ProbeDependencies:
        manifest_path = root / "dinkster-pack.toml"
        manifest = load_manifest(manifest_path)
        pending = list(manifest.dependencies)
        selected: dict[str, str] = {}
        requirements = set(manifest.requires_for("cpu"))
        helpers = []
        with self.database.session() as session:
            while pending:
                dependency = pending.pop(0)
                if dependency.pack in selected:
                    if not dependency.accepts(selected[dependency.pack]):
                        raise ValueError(f"Conflicting helper dependency {dependency.pack!r}.")
                    continue
                releases = session.scalars(
                    select(ReleaseRecord)
                    .join(PackRecord, PackRecord.id == ReleaseRecord.pack_id)
                    .where(
                        PackRecord.name == dependency.pack,
                        PackRecord.visibility == "public",
                        ReleaseRecord.state == "active",
                    )
                )
                release = max(
                    (item for item in releases if dependency.accepts(item.version)),
                    key=lambda item: Version(item.version),
                    default=None,
                )
                if release is None:
                    raise ValueError(f"No active helper dependency {dependency.pack!r}.")
                selected[dependency.pack] = release.version
                artifact = session.get(ArtifactRecord, release.artifact_digest)
                assert artifact is not None
                data = self.object_store.read(artifact.object_key, max_size=MAX_ARTIFACT_SIZE)
                if artifact_digest(data) != artifact.digest or len(data) != artifact.size:
                    raise ValueError(f"Helper artifact changed for {dependency.pack!r}.")
                wheel = inspect_wheel(data, dependency.pack, release.version)
                if wheel.library:
                    raise ValueError("Pack dependencies must name packs, not libraries.")
                with extracted_wheel(data, wheel) as dependency_root:
                    helper = load_manifest(dependency_root / "dinkster-pack.toml")
                    pending.extend(helper.dependencies)
                    requirements.update(helper.requires_for("cpu"))
                helpers.append(data)
        return ProbeDependencies(
            tuple(helpers), self._probe_library_wheels(requirements), tuple(sorted(requirements))
        )

    def probe_dependencies(self, root: Path) -> ProbeDependencies | StageResult:
        try:
            return self._resolve_probe_dependencies(root)
        except (ValueError, ObjectStoreError, FileNotFoundError) as exc:
            return StageResult(
                (
                    AdmissionFinding(
                        "probe.pack-dependencies-unavailable", "error", "block", str(exc)
                    ),
                )
            )

    def _probe_with_dependencies(
        self, root: Path, scan_engine: dict[str, str] | None = None
    ) -> StageResult:
        dependencies = self.probe_dependencies(root)
        if isinstance(dependencies, StageResult):
            return dependencies
        return run_prepared_probe(
            root,
            dependencies,
            settings=self.settings.probe_settings(),
            require_isolation=self.require_isolation,
            scan_engine=scan_engine,
            development_release=self.settings.probe_engine_release,
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
                    future = executor.submit(self._probe_with_dependencies, root, claim.scan_engine)
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

    def run_once(self, *, deliver_indexes: bool = True) -> bool:
        if SecurityPublication(
            self.database,
            self.object_store,
            self.settings.public_base_url,
            self.settings.security_signing_key_path,
        ).deliver_one():
            return True
        if self.deliver_one_promotion():
            return True
        claim = self.claim()
        if claim is None:
            return self.indexes.deliver_one() if deliver_indexes else False
        self.process(claim)
        return True

    def run(self, *, poll_seconds: float = 1.0) -> None:
        if poll_seconds <= 0:
            raise ValueError("poll_seconds must be positive")
        stopped = threading.Event()

        def deliver_indexes() -> None:
            while not stopped.is_set():
                if not self.indexes.deliver_one():
                    stopped.wait(poll_seconds)

        # A long-running scan must not prevent accepted releases reaching static storage.
        # The existing database lock still serializes writers across replicas.
        with ThreadPoolExecutor(max_workers=1) as executor:
            delivery = executor.submit(deliver_indexes)
            try:
                while True:
                    if delivery.done():
                        delivery.result()
                    try:
                        worked = self.run_once(deliver_indexes=False)
                    except LeaseLost:
                        continue
                    if not worked:
                        time.sleep(poll_seconds)
            finally:
                stopped.set()

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
