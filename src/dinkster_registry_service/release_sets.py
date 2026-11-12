"""Authenticated wheel sets with immutable per-member bindings."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from dinkster_registry import TokenRecord
from sqlalchemy import select

from .database import AuditEventRecord, ReleaseCandidateRecord, ReleaseSetRecord
from .digests import artifact_digest
from .identifiers import require_canonical_pack_name
from .ids import uuid7
from .object_store import MAX_ARTIFACT_SIZE
from .pack_locks import MAX_LOCKS_SIZE, parse_pack_locks, quarantine_lock_key
from .scan_engine import parse_scan_engine
from .security_repository import SecurityRepository, lock_security
from .versioning import public_version_key, require_public_version

if TYPE_CHECKING:
    from .admission import AdmissionService

MAX_SET_BODY = 128 * 1024 * 1024
SET_LIFETIME = timedelta(hours=24)


class ReleaseSetError(ValueError):
    """A wheel set cannot be submitted without changing its contract."""


def member_limit(publisher: str) -> int:
    return 64 if publisher == "dinkster" else 8


@dataclass(frozen=True)
class SetUpload:
    name: str
    version: str
    archive: bytes
    locks: bytes | None = None
    engine: bytes | None = None


def submit_set(service: AdmissionService, uploads: list[SetUpload], token: TokenRecord) -> UUID:
    limit = member_limit(token.publisher)
    if not 1 <= len(uploads) <= limit:
        raise ReleaseSetError(f"Requested {len(uploads)} members; publisher limit is {limit}.")
    if sum(len(row.archive) + len(row.locks or b"") for row in uploads) > MAX_SET_BODY:
        raise ReleaseSetError("Set exceeds the 128 MiB aggregate size limit.")
    names = set()
    bindings = []
    for row in uploads:
        require_canonical_pack_name(row.name)
        require_public_version(row.version)
        if row.name in names:
            raise ReleaseSetError(f"Set has duplicate pack identity {row.name!r}.")
        names.add(row.name)
        if not 1 <= len(row.archive) <= MAX_ARTIFACT_SIZE:
            raise ReleaseSetError(f"{row.name}: wheel size must be 1 through 64 MiB.")
        if row.locks is not None and len(row.locks) > MAX_LOCKS_SIZE:
            raise ReleaseSetError(f"{row.name}: locks exceed the 8 MiB size limit.")
        digest = artifact_digest(row.archive)
        locks = parse_pack_locks(row.locks, pack=row.name, digest=digest) if row.locks else ()
        bindings.append(
            {
                "name": row.name,
                "version": public_version_key(row.version),
                "digest": digest,
                "size": len(row.archive),
                "locks": {lock.variant: lock.digest for lock in locks},
                "engine": parse_scan_engine(row.engine),
            }
        )
    binding_digest = hashlib.sha256(
        json.dumps(sorted(bindings, key=lambda row: str(row["name"])), sort_keys=True).encode()
    ).hexdigest()
    cleanup: list[tuple[UUID, tuple[str, ...]]] = []
    try:
        with service.database.session() as session, session.begin():
            lock_security(session)
            authorizations = [
                SecurityRepository.authorize_upload(session, token, row.name, None)
                for row in uploads
            ]
            previous = session.scalar(
                select(ReleaseSetRecord)
                .where(
                    ReleaseSetRecord.publisher_id == token.publisher,
                    ReleaseSetRecord.binding_digest == binding_digest,
                    ReleaseSetRecord.status.in_(("queued", "accepted")),
                )
                .order_by(ReleaseSetRecord.submitted_at.desc())
                .with_for_update()
            )
            now = datetime.now(UTC)
            if previous is not None:
                if previous.status == "accepted" or previous.expires_at.replace(tzinfo=UTC) > now:
                    return previous.id
                raise ReleaseSetError("Previous set has expired and awaits scanner cleanup.")
            release_set = ReleaseSetRecord(
                id=uuid7(),
                publisher_id=token.publisher,
                binding_digest=binding_digest,
                members=[],
                status="queued",
                status_reason=None,
                submitted_at=now,
                expires_at=now + SET_LIFETIME,
            )
            session.add(release_set)
            session.flush()
            members = []
            for row, authorization in zip(uploads, authorizations, strict=True):
                candidate_id = service.submit(
                    row.archive,
                    pack_name=row.name,
                    version=row.version,
                    authorization=authorization,
                    locks=row.locks,
                    engine=row.engine,
                    session=session,
                    set_id=release_set.id,
                )
                candidate = session.get(ReleaseCandidateRecord, candidate_id)
                assert candidate is not None
                cleanup.append((candidate_id, tuple(candidate.install_locks)))
                members.append(str(candidate_id))
            release_set.members = members
            session.add(
                AuditEventRecord(
                    id=uuid7(),
                    created_at=now,
                    event_type="release_set.submitted",
                    subject_type="release_set",
                    subject_id=str(release_set.id),
                    data={"members": members, "publisher": token.publisher},
                )
            )
            return release_set.id
    except BaseException:
        for candidate_id, variants in cleanup:
            service.object_store.remove(f"quarantine/uploads/{candidate_id}")
            for variant in variants:
                service.object_store.remove(quarantine_lock_key(candidate_id, variant))
        raise
