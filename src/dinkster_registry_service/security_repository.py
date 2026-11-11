"""Transactional security authority and append-only release notice history."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Literal

from dinkster_registry import RegistryError, TokenRecord
from pydantic import Field, model_validator
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .accounts import PublisherIdentity
from .database import (
    AuditEventRecord,
    Database,
    OutboxRecord,
    PackRecord,
    PublisherFreezeRecord,
    PublisherRecord,
    PublisherTokenRecord,
    RegistryUserRecord,
    ReleaseCandidateRecord,
    ReleaseRecord,
)
from .identifiers import require_canonical_pack_name
from .ids import uuid7
from .principals import PrincipalRepository
from .security import (
    Digest,
    OwnershipNotice,
    SecurityDocument,
    SecurityModel,
    SecurityNotice,
    SecurityRelease,
    Text,
)


class NoticeChange(SecurityModel):
    operation: Literal["issue", "confirm", "correct", "lift", "withdraw"]
    release: SecurityRelease
    expected_revision: int = Field(ge=0)
    state: Literal["malicious", "vulnerable", "affected"]
    reason: Text
    message: Text
    incident: Text
    fixed_release: SecurityRelease | None = None
    fixed_lock_digest: Digest | None = None
    causes: tuple[Digest, ...] = Field(default=(), strict=False)


class UploadChange(SecurityModel):
    subject_type: Literal["pack", "publisher"]
    subject: Text
    stopped: bool
    reason: Text


class OwnershipChange(SecurityModel):
    expected_owner: Text | None
    target_owner: Text
    reason: Text


class UploadAuthorization(SecurityModel):
    publisher: str | None
    actor: Text
    token_id: str | None
    security_reason: Text | None

    @model_validator(mode="after")
    def credential_kind(self) -> UploadAuthorization:
        if (self.token_id is None) == (self.security_reason is None):
            raise ValueError("upload requires either a publishing token or human security intent")
        if self.security_reason is not None and not self.security_reason.strip():
            raise ValueError("security publication requires a nonblank reason")
        return self


class SecurityRepository:
    def __init__(self, database: Database, registry: str) -> None:
        self.database = database
        self.registry = registry

    @contextmanager
    def transaction(self) -> Iterator[Session]:
        with self.database.session() as session, session.begin():
            lock_security(session)
            yield session

    def set_role(self, *, actor: str, user: str, enabled: bool, reason: str) -> None:
        if not reason.strip():
            raise RegistryError("a security role change requires a reason")
        with self.transaction() as session:
            _, operators = PrincipalRepository._load(session)
            if actor not in operators:
                raise RegistryError("security role assignment requires a registry operator")
            if session.get(RegistryUserRecord, user) is None:
                raise RegistryError("security role requires a registered user")
            session.add(
                AuditEventRecord(
                    id=uuid7(),
                    created_at=datetime.now(UTC),
                    event_type="security.role",
                    subject_type="user",
                    subject_id=user,
                    data={
                        "actor": actor,
                        "enabled": enabled,
                        "reason": reason,
                        "revision": self.revision(session) + 1,
                    },
                )
            )

    @staticmethod
    def is_security(session: Session, actor: str) -> bool:
        records = session.scalars(
            select(AuditEventRecord).where(
                AuditEventRecord.event_type == "security.role",
                AuditEventRecord.subject_id == actor,
            )
        ).all()
        latest = max(records, key=lambda row: row.data["revision"], default=None)
        return latest is not None and latest.data["enabled"] is True

    @staticmethod
    def revision(session: Session) -> int:
        return max(
            (
                int(row.data["revision"])
                for row in session.scalars(
                    select(AuditEventRecord).where(AuditEventRecord.event_type.like("security.%"))
                )
            ),
            default=1,
        )

    @staticmethod
    def _history(session: Session) -> list[SecurityNotice]:
        return sorted(
            (
                SecurityNotice.model_validate_json(row.data["notice"])
                for row in session.scalars(
                    select(AuditEventRecord).where(AuditEventRecord.event_type == "security.notice")
                )
            ),
            key=lambda notice: notice.revision,
        )

    @staticmethod
    def _release(session: Session, identity: SecurityRelease) -> tuple[PackRecord, ReleaseRecord]:
        pack = session.scalar(select(PackRecord).where(PackRecord.name == identity.pack))
        release = (
            session.scalar(
                select(ReleaseRecord).where(
                    ReleaseRecord.pack_id == pack.id, ReleaseRecord.version == identity.version
                )
            )
            if pack is not None
            else None
        )
        if pack is None or release is None or release.artifact_digest != identity.artifact_digest:
            raise RegistryError("security report must identify an exact published release")
        return pack, release

    def change(
        self, *, actor: str, change: NoticeChange, token: TokenRecord | None = None
    ) -> SecurityNotice:
        with self.transaction() as session:
            pack, release = self._release(session, change.release)
            security = token is None and self.is_security(session, actor)
            if token is not None:
                if token.minted_by != actor:
                    raise RegistryError("publisher token actor does not match its issuer")
                PrincipalRepository.require_current_token(
                    session, token, pack.publisher_id or "", pack.name
                )
            if not security:
                directory, _ = PrincipalRepository._load(session)
                if pack.publisher_id is None:
                    raise RegistryError("release has no publisher authority")
                directory.authorize(actor, pack.publisher_id, "publish")
            history = self._history(session)
            previous = next(
                (notice for notice in reversed(history) if notice.release == change.release), None
            )
            if change.expected_revision != (previous.revision if previous else 0):
                raise RegistryError("security notice changed; read its current revision")
            if change.operation == "issue":
                if previous is not None and previous.status == "active":
                    raise RegistryError("active notice requires confirmation, correction or lift")
            elif previous is None or previous.status != "active":
                raise RegistryError("security operation requires an active notice")
            if change.operation == "withdraw":
                reporting_publisher = session.scalar(
                    select(AuditEventRecord.data["publisherId"].as_string()).where(
                        AuditEventRecord.event_type == "security.notice",
                        AuditEventRecord.data["revision"].as_integer() == change.expected_revision,
                    )
                )
                if (
                    security
                    or previous is None
                    or reporting_publisher != pack.publisher_id
                    or previous.state != "vulnerable"
                    or previous.security_confirmed
                ):
                    raise RegistryError(
                        "only the reporting publisher may withdraw an unconfirmed vulnerability"
                    )
            elif not security and (change.operation != "issue" or change.state == "affected"):
                raise RegistryError("security role authority is required")
            if change.operation in {"confirm", "lift", "withdraw"} and previous is not None:
                if change.state != previous.state:
                    raise RegistryError("confirmation or clearing cannot change classification")
            if change.fixed_release is not None:
                self._release(session, change.fixed_release)
            revision = self.revision(session) + 1
            notice = SecurityNotice(
                id=previous.id if previous else uuid7(),
                revision=revision,
                previous_revision=previous.revision if previous else None,
                release=change.release,
                state=change.state,
                status="cleared" if change.operation in {"lift", "withdraw"} else "active",
                actor=actor,
                authority="security" if security else "publisher",
                security_confirmed=security,
                changed_at=datetime.now(UTC),
                reason=change.reason,
                message=change.message,
                incident=change.incident,
                fixed_release=change.fixed_release,
                fixed_lock_digest=change.fixed_lock_digest,
                causes=change.causes,
            )
            session.add(
                AuditEventRecord(
                    id=uuid7(),
                    created_at=notice.changed_at,
                    event_type="security.notice",
                    subject_type="release",
                    subject_id=str(release.id),
                    data={
                        "operation": change.operation,
                        "notice": notice.model_dump_json(),
                        "revision": revision,
                        "publisherId": pack.publisher_id,
                    },
                )
            )
            queue_security_publication(session, revision)
            return notice

    def history(self) -> tuple[SecurityNotice, ...]:
        with self.database.session() as session:
            return tuple(self._history(session))

    def set_uploads(
        self, *, actor: str, change: UploadChange, token: TokenRecord | None = None
    ) -> None:
        with self.transaction() as session:
            security = token is None and self.is_security(session, actor)
            publisher = change.subject
            if change.subject_type == "pack":
                pack = session.scalar(select(PackRecord).where(PackRecord.name == change.subject))
                if pack is None:
                    raise RegistryError("unknown pack")
                publisher = pack.publisher_id or ""
            elif session.get(PublisherRecord, publisher) is None:
                raise RegistryError("unknown publisher")
            if token is not None and token.minted_by != actor:
                raise RegistryError("publisher token actor does not match its issuer")
            if not security:
                if change.subject_type != "pack":
                    raise RegistryError("publisher-wide control requires the security role")
                directory, _ = PrincipalRepository._load(session)
                directory.authorize(actor, publisher, "publish")
                if token is not None:
                    PrincipalRepository.require_current_token(
                        session, token, publisher, change.subject
                    )
                previous = self.upload_control(session, "pack", change.subject)
                if previous is not None and previous.data["stopped"] and not change.stopped:
                    if previous.data["authority"] == "security":
                        raise RegistryError("security role must resume its upload stop")
            previous = self.upload_control(session, change.subject_type, change.subject)
            # Repeating a publisher stop must not replace the security authority holding it.
            authority = "security" if security else "publisher"
            if previous is not None and previous.data["stopped"] and change.stopped:
                if previous.data["authority"] == "security":
                    authority = "security"
            session.add(
                AuditEventRecord(
                    id=uuid7(),
                    created_at=datetime.now(UTC),
                    event_type="security.upload",
                    subject_type=change.subject_type,
                    subject_id=change.subject,
                    data={
                        "actor": actor,
                        "authority": authority,
                        "stopped": change.stopped,
                        "reason": change.reason,
                        "revision": self.revision(session) + 1,
                    },
                )
            )

    @staticmethod
    def upload_control(session: Session, kind: str, subject: str) -> AuditEventRecord | None:
        rows = session.scalars(
            select(AuditEventRecord).where(
                AuditEventRecord.event_type == "security.upload",
                AuditEventRecord.subject_type == kind,
                AuditEventRecord.subject_id == subject,
            )
        )
        return max(rows, key=lambda row: row.data["revision"], default=None)

    @classmethod
    def require_uploads(cls, session: Session, pack_name: str, publisher: str | None) -> None:
        pack = session.scalar(select(PackRecord).where(PackRecord.name == pack_name))
        publishers = {publisher, pack.publisher_id if pack is not None else None} - {None}
        controls = [cls.upload_control(session, "pack", pack_name)]
        controls.extend(
            cls.upload_control(session, "publisher", item) for item in publishers if item
        )
        if any(control is not None and control.data["stopped"] for control in controls):
            raise UploadStopped("uploads are stopped for this pack or publisher")

    @classmethod
    def authorize_upload(
        cls,
        session: Session,
        credential: TokenRecord | PublisherIdentity,
        pack_name: str,
        security_reason: str | None,
    ) -> UploadAuthorization:
        """Authorize in a caller transaction holding lock_security, without committing."""
        require_canonical_pack_name(pack_name)
        if security_reason is not None:
            if not security_reason.strip() or not isinstance(credential, PublisherIdentity):
                raise RegistryError("security publication requires a verified human and reason")
            pack = session.scalar(select(PackRecord).where(PackRecord.name == pack_name))
            if pack is None:
                raise RegistryError("security publication requires an existing pack")
            authorization = UploadAuthorization(
                publisher=pack.publisher_id,
                actor=credential.actor,
                token_id=None,
                security_reason=security_reason,
            )
        else:
            if not isinstance(credential, TokenRecord):
                raise RegistryError("ordinary publishing requires a publishing token")
            directory, _ = PrincipalRepository._load(session)
            current = next(
                (row for row in directory.tokens(credential.publisher) if row == credential), None
            )
            if current is None:
                raise RegistryError("publishing credential changed")
            authorization = UploadAuthorization(
                publisher=credential.publisher,
                actor=credential.minted_by,
                token_id=credential.token_id,
                security_reason=None,
            )
        cls.require_authorization(session, authorization, pack_name)
        return authorization

    @classmethod
    def require_authorization(
        cls, session: Session, authorization: UploadAuthorization, pack_name: str
    ) -> None:
        if authorization.publisher is not None:
            session.get(PublisherRecord, authorization.publisher, with_for_update=True)
        if authorization.token_id is not None:
            session.get(PublisherTokenRecord, authorization.token_id, with_for_update=True)
        pack = session.scalar(select(PackRecord).where(PackRecord.name == pack_name))
        if pack is not None and pack.publisher_id != authorization.publisher:
            raise RegistryError("pack ownership changed before publication")
        if authorization.security_reason is not None:
            if pack is None or not cls.is_security(session, authorization.actor):
                raise RegistryError("security publication requires the current security role")
        else:
            directory, _ = PrincipalRepository._load(session)
            publisher = authorization.publisher or ""
            token = next(
                (
                    row
                    for row in directory.tokens(publisher)
                    if row.token_id == authorization.token_id
                ),
                None,
            )
            if (
                token is None
                or token.revoked
                or token.minted_by != authorization.actor
                or datetime.fromisoformat(token.expires_at) <= datetime.now(UTC)
                or session.get(PublisherFreezeRecord, publisher) is not None
            ):
                raise RegistryError("publishing credential is no longer authorized")
            directory.authorize(authorization.actor, publisher, "publish")
            directory.authorize_token(token, publisher, pack_name)
        cls.require_uploads(session, pack_name, authorization.publisher)

    @classmethod
    def require_candidate_upload(
        cls, session: Session, candidate: ReleaseCandidateRecord
    ) -> UploadAuthorization | None:
        submission = session.scalar(
            select(AuditEventRecord).where(
                AuditEventRecord.event_type == "release_candidate.submitted",
                AuditEventRecord.subject_id == str(candidate.id),
            )
        )
        raw = submission.data.get("authorization") if submission is not None else None
        authorization = UploadAuthorization.model_validate(raw) if raw is not None else None
        if authorization is not None:
            if (
                authorization.actor != candidate.submitted_by
                or authorization.publisher != candidate.publisher_id
            ):
                raise RegistryError("candidate does not match its authenticated submission")
            cls.require_authorization(session, authorization, candidate.pack_name)
        else:
            pack = session.scalar(select(PackRecord).where(PackRecord.name == candidate.pack_name))
            if pack is not None and pack.publisher_id != candidate.publisher_id:
                raise RegistryError("pack ownership changed before publication")
            cls.require_uploads(session, candidate.pack_name, candidate.publisher_id)
        return authorization

    def document(self, *, issued_at: datetime, expires_at: datetime) -> SecurityDocument:
        with self.transaction() as session:
            return self.document_in_transaction(session, issued_at=issued_at, expires_at=expires_at)

    def document_in_transaction(
        self, session: Session, *, issued_at: datetime, expires_at: datetime
    ) -> SecurityDocument:
        history = self._history(session)
        current = {notice.id: notice for notice in history}
        ownership = sorted(
            (
                OwnershipNotice.model_validate_json(row.data["notice"])
                for row in session.scalars(
                    select(AuditEventRecord).where(
                        AuditEventRecord.event_type == "security.ownership"
                    )
                )
            ),
            key=lambda notice: notice.revision,
        )
        return SecurityDocument(
            registry=self.registry,
            revision=self.revision(session),
            issued_at=issued_at,
            expires_at=expires_at,
            notices=tuple(current.values()),
            ownership_changes=tuple(ownership),
        )


def queue_security_publication(session: Session, revision: int) -> None:
    now = datetime.now(UTC)
    session.add(
        OutboxRecord(
            id=uuid7(),
            created_at=now,
            available_at=now,
            delivered_at=None,
            topic="security.publish",
            event_key=f"security:{revision}",
            payload={"revision": revision},
            state="pending",
            attempts=0,
        )
    )


class UploadStopped(RegistryError):
    pass


def lock_security(session: Session) -> None:
    """Serialize authority, reports and upload activation across service processes."""
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        session.execute(text("SELECT pg_advisory_xact_lock(hashtext('registry-security'))"))
    else:
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")
