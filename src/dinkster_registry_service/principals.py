from __future__ import annotations

from typing import cast

from dinkster_registry import (
    Action,
    AuditRecord,
    Membership,
    PrincipalDirectory,
    RegistryError,
    Role,
    TokenRecord,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import (
    Database,
    PrincipalAuditRecord,
    PublisherMembershipRecord,
    PublisherRecord,
    PublisherTokenRecord,
    RegistryOperatorRecord,
    RegistryUserRecord,
)


class PrincipalRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    @staticmethod
    def _load(session: Session) -> tuple[PrincipalDirectory, set[str]]:
        users = list(session.scalars(select(RegistryUserRecord.id)))
        publishers = {row.id: row.display_name for row in session.scalars(select(PublisherRecord))}
        memberships = [
            Membership(row.user_id, row.publisher_id, cast("Role", row.role))
            for row in session.scalars(select(PublisherMembershipRecord))
        ]
        tokens = [
            TokenRecord(
                token_id=row.token_id,
                publisher=row.publisher_id,
                minted_by=row.minted_by,
                pack=row.pack_name,
                secret_hash=row.secret_hash,
                created_at=row.created_at,
                expires_at=row.expires_at,
                revoked=row.revoked,
                revoked_reason=row.revoked_reason,
            )
            for row in session.scalars(select(PublisherTokenRecord))
        ]
        audit = [
            AuditRecord(row.actor, row.action, row.subject, row.at, row.details)
            for row in session.scalars(
                select(PrincipalAuditRecord).order_by(PrincipalAuditRecord.sequence)
            )
        ]
        directory = PrincipalDirectory.restore(
            users=users,
            publishers=publishers,
            memberships=memberships,
            tokens=tokens,
            audit=audit,
        )
        operators = set(session.scalars(select(RegistryOperatorRecord.user_id)))
        if unknown := operators - set(users):
            raise RegistryError(f"operators reference unknown users: {sorted(unknown)}")
        return directory, operators

    @staticmethod
    def _append_audit(session: Session, directory: PrincipalDirectory, since: int) -> None:
        for record in directory.audit()[since:]:
            session.add(
                PrincipalAuditRecord(
                    actor=record.actor,
                    action=record.action,
                    subject=record.subject,
                    at=record.at,
                    details=record.details,
                )
            )

    def register_user(self, user: str) -> None:
        with self.database.session() as session, session.begin():
            directory, _ = self._load(session)
            directory.register_user(user)
            if session.get(RegistryUserRecord, user) is None:
                session.add(RegistryUserRecord(id=user))

    def add_operator(self, user: str, actor: str, at: str) -> None:
        with self.database.session() as session, session.begin():
            directory, operators = self._load(session)
            if session.get(RegistryUserRecord, user) is None:
                raise RegistryError(f"unknown user {user!r}; register the account first")
            if operators and actor not in operators:
                raise RegistryError(f"user {actor!r} is not a registry operator")
            if user in operators:
                return
            audit_count = len(directory.audit())
            directory.record(actor, "add-operator", user, at)
            session.add(RegistryOperatorRecord(user_id=user))
            self._append_audit(session, directory, audit_count)

    def register_publisher(self, publisher: str, owner: str, at: str) -> str:
        with self.database.session() as session, session.begin():
            directory, _ = self._load(session)
            audit_count = len(directory.audit())
            canonical = directory.register_publisher(publisher, owner, at)
            session.add(PublisherRecord(id=canonical, display_name=canonical))
            session.flush()
            session.add(
                PublisherMembershipRecord(
                    publisher_id=canonical,
                    user_id=owner,
                    role="owner",
                )
            )
            self._append_audit(session, directory, audit_count)
            return canonical

    def mint_token(
        self,
        publisher: str,
        minted_by: str,
        at: str,
        expires_at: str,
        *,
        pack: str | None = None,
        secret: str | None = None,
    ) -> tuple[str, TokenRecord]:
        with self.database.session() as session, session.begin():
            directory, _ = self._load(session)
            audit_count = len(directory.audit())
            plaintext, token = directory.mint_token(
                publisher,
                minted_by,
                at,
                expires_at,
                pack=pack,
                secret=secret,
            )
            session.add(
                PublisherTokenRecord(
                    token_id=token.token_id,
                    publisher_id=token.publisher,
                    minted_by=token.minted_by,
                    pack_name=token.pack,
                    secret_hash=token.secret_hash,
                    created_at=token.created_at,
                    expires_at=token.expires_at,
                    revoked=token.revoked,
                    revoked_reason=token.revoked_reason,
                )
            )
            self._append_audit(session, directory, audit_count)
            return plaintext, token

    def revoke_token(self, token_id: str, actor: str, at: str, reason: str) -> None:
        with self.database.session() as session, session.begin():
            directory, _ = self._load(session)
            audit_count = len(directory.audit())
            directory.revoke_token(token_id, actor, at, reason)
            token = session.get(PublisherTokenRecord, token_id)
            if token is None:
                raise RegistryError(f"no token {token_id!r}")
            updated = next(
                record
                for record in directory.tokens(token.publisher_id)
                if record.token_id == token_id
            )
            token.revoked = updated.revoked
            token.revoked_reason = updated.revoked_reason
            self._append_audit(session, directory, audit_count)

    def verify_token(self, presented: str, at: str) -> TokenRecord:
        with self.database.session() as session:
            directory, _ = self._load(session)
            return directory.verify_token(presented, at)

    def authorize(self, user: str, publisher: str, action: Action) -> None:
        with self.database.session() as session:
            directory, _ = self._load(session)
            directory.authorize(user, publisher, action)

    def authorize_token(self, token: TokenRecord, publisher: str, pack: str) -> None:
        with self.database.session() as session:
            directory, _ = self._load(session)
            directory.authorize_token(token, publisher, pack)

    def administered_tokens(self, publisher: str, actor: str) -> tuple[TokenRecord, ...]:
        with self.database.session() as session:
            directory, _ = self._load(session)
            directory.authorize(actor, publisher, "manage-members")
            return directory.tokens(publisher)

    def is_operator(self, user: str) -> bool:
        with self.database.session() as session:
            _, operators = self._load(session)
            return user in operators

    def record(self, actor: str, action: str, subject: str, at: str, details: str = "") -> None:
        with self.database.session() as session, session.begin():
            directory, _ = self._load(session)
            audit_count = len(directory.audit())
            directory.record(actor, action, subject, at, details)
            self._append_audit(session, directory, audit_count)

    def audit(self) -> tuple[AuditRecord, ...]:
        with self.database.session() as session:
            directory, _ = self._load(session)
            return directory.audit()


__all__ = ["PrincipalRepository"]
