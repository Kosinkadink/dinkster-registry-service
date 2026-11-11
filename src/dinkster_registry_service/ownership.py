from datetime import datetime
from uuid import UUID

from dinkster_registry import RegistryError
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from .database import (
    AuditEventRecord,
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
