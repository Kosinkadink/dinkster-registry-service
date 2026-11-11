from datetime import datetime
from uuid import UUID

from dinkster_registry import RegistryError
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from .database import (
    AuditEventRecord,
    NamespaceGrantRecord,
    OutboxRecord,
    PackRecord,
    PublisherBindingRecord,
    PublisherFreezeRecord,
    PublisherMembershipRecord,
    PublisherRecord,
    PublisherTokenRecord,
    RegistryOperatorRecord,
    RegistryUserRecord,
)
from .identifiers import require_canonical_pack_name
from .ids import uuid7
from .indexes import queue_index_rebuild
from .security import OwnershipNotice
from .security_repository import SecurityRepository, lock_security


def transfer_ownership(
    session: Session,
    *,
    actor: str,
    subject_kind: str,
    subject_id: str,
    expected_owner: str | None,
    target_owner: str,
    reason: str,
    at: datetime,
) -> UUID:
    """Change ownership and append its audit event in the caller's transaction."""
    if not reason.strip():
        raise RegistryError("ownership transfer requires a reason")
    if at.utcoffset() is None:
        raise RegistryError("ownership transfer time requires a timezone")
    if subject_kind == "pack":
        lock_security(session)
        if not SecurityRepository.is_security(session, actor):
            raise RegistryError("pack transfer requires the security role")
        try:
            pack_id = UUID(subject_id)
        except ValueError:
            raise RegistryError("pack transfer requires a pack UUID") from None
        target = session.get(PublisherRecord, target_owner, with_for_update=True)
        if target is None:
            raise RegistryError("unknown target publisher")
        pack = session.get(PackRecord, pack_id, with_for_update=True)
        if pack is None:
            raise RegistryError("unknown pack")
        previous = pack.publisher_id
        if previous != expected_owner:
            raise RegistryError("pack owner changed; confirm the current publisher")
        if previous == target_owner:
            raise RegistryError("pack already has that publisher")
        event_id = uuid7()
        notice = OwnershipNotice(
            id=event_id,
            revision=SecurityRepository.revision(session) + 1,
            pack_id=pack.id,
            pack=pack.name,
            previous_publisher=previous,
            publisher=target_owner,
            actor=actor,
            changed_at=at,
            reason=reason,
        )
        pack.publisher_id = target_owner
        pack.owner_type = "org"
        pack.owner_id = uuid7()
        pack.owner_slug = target_owner
        pack.owner_display_name = target.display_name
        pack.updated_at = at
        for grant in session.scalars(
            select(NamespaceGrantRecord)
            .where(NamespaceGrantRecord.pack_id == pack.id)
            .with_for_update()
        ):
            grant.publisher_id = target_owner
            grant.owner_id = pack.owner_id
        session.execute(
            update(PublisherTokenRecord)
            .where(
                PublisherTokenRecord.publisher_id == previous,
                PublisherTokenRecord.pack_name == pack.name,
                ~PublisherTokenRecord.revoked,
            )
            .values(revoked=True, revoked_reason=reason)
        )
        session.add(
            AuditEventRecord(
                id=event_id,
                created_at=at,
                event_type="ownership.transferred",
                subject_type="pack",
                subject_id=subject_id,
                data={
                    "actor": actor,
                    "subjectKind": subject_kind,
                    "subjectId": subject_id,
                    "previousOwner": previous,
                    "owner": target_owner,
                    "reason": reason,
                    "time": at.isoformat(),
                },
            )
        )
        session.add(
            AuditEventRecord(
                id=uuid7(),
                created_at=at,
                event_type="security.ownership",
                subject_type="pack",
                subject_id=subject_id,
                data={"notice": notice.model_dump_json(), "revision": notice.revision},
            )
        )
        session.add(
            OutboxRecord(
                id=uuid7(),
                created_at=at,
                available_at=at,
                delivered_at=None,
                topic="security.publish",
                event_key=f"security:{event_id}",
                payload={"revision": notice.revision, "auditId": str(event_id)},
                state="pending",
                attempts=0,
            )
        )
        queue_index_rebuild(session)
        session.flush()
        return event_id
    if subject_kind != "publisher":
        raise RegistryError("unsupported ownership subject")
    if session.get(RegistryOperatorRecord, actor) is None:
        raise RegistryError("publisher binding requires a registry operator")
    try:
        require_canonical_pack_name(subject_id)
        prefix = "u_" if target_owner.startswith("u_") else "org:"
        value = UUID(target_owner.removeprefix(prefix))
        if target_owner != f"{prefix}{value}":
            raise ValueError("noncanonical identity subject")
    except ValueError:
        raise RegistryError(
            "target must be an immutable Dinkster user or organization id"
        ) from None
    publisher = session.get(PublisherRecord, subject_id, with_for_update=True)
    if publisher is None:
        raise RegistryError("unknown publisher")
    binding = session.get(PublisherBindingRecord, subject_id, with_for_update=True)
    previous = binding.identity_subject if binding is not None else None
    if previous != expected_owner:
        raise RegistryError("publisher owner changed; confirm the current binding")
    if previous == target_owner:
        raise RegistryError("publisher already has that owner")
    if (
        session.scalar(
            select(PublisherBindingRecord.publisher_id).where(
                PublisherBindingRecord.identity_subject == target_owner
            )
        )
        is not None
    ):
        raise RegistryError("target identity already has a publisher")
    if binding is None:
        session.add(PublisherBindingRecord(publisher_id=subject_id, identity_subject=target_owner))
    else:
        binding.identity_subject = target_owner
        session.execute(
            update(PublisherTokenRecord)
            .where(PublisherTokenRecord.publisher_id == subject_id, ~PublisherTokenRecord.revoked)
            .values(revoked=True, revoked_reason=reason)
        )
    if previous is not None:
        session.execute(
            delete(PublisherMembershipRecord).where(
                PublisherMembershipRecord.publisher_id == subject_id
            )
        )
    if session.get(RegistryUserRecord, target_owner) is None:
        session.add(RegistryUserRecord(id=target_owner))
        session.flush()
    session.add(
        PublisherMembershipRecord(publisher_id=subject_id, user_id=target_owner, role="owner")
    )
    session.execute(
        delete(PublisherFreezeRecord).where(PublisherFreezeRecord.publisher_id == subject_id)
    )
    event_id = uuid7()
    session.add(
        AuditEventRecord(
            id=event_id,
            created_at=at,
            event_type="ownership.transferred",
            subject_type=subject_kind,
            subject_id=subject_id,
            data={
                "actor": actor,
                "subjectKind": subject_kind,
                "subjectId": subject_id,
                "previousOwner": previous,
                "owner": target_owner,
                "reason": reason,
                "time": at.isoformat(),
            },
        )
    )
    session.flush()
    return event_id
