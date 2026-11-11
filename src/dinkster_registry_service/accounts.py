import time
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated

from dinkster_registry import RegistryError
from dinkster_token_verifier import TokenVerifier
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from starlette.responses import JSONResponse

from .database import (
    Database,
    PrincipalAuditRecord,
    PublisherBindingRecord,
    PublisherFreezeRecord,
    PublisherMembershipRecord,
    PublisherRecord,
    RegistryUserRecord,
)
from .identifiers import require_canonical_pack_name
from .principals import PrincipalRepository
from .settings import ServerSettings


class AccountError(Exception):
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = message


@dataclass(frozen=True)
class PublisherIdentity:
    subject: str
    actor: str
    name: str


class TokenCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expires_at: datetime
    pack: str | None = None

    @field_validator("expires_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("Expiry must include a timezone")
        return value

    @field_validator("pack")
    @classmethod
    def canonical_pack(cls, value: str | None) -> str | None:
        return require_canonical_pack_name(value) if value is not None else None


class TokenRevoke(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=500)


def _json(value: object, status: int = 200) -> JSONResponse:
    return JSONResponse(value, status_code=status, headers={"Cache-Control": "no-store"})


def management_identity(
    settings: ServerSettings,
) -> Callable[[Request], Awaitable[PublisherIdentity]]:
    verifier = TokenVerifier(
        issuer=settings.identity_issuer,
        audience=settings.identity_audience,
        jwks_url=f"{settings.identity_issuer}/.well-known/jwks.json",
    )

    async def identity(request: Request) -> PublisherIdentity:
        scheme, _, credential = request.headers.get("authorization", "").partition(" ")
        principal = await verifier.verify(credential) if scheme == "Bearer" else None
        if (
            principal is None
            or principal.kind != "human"
            or not principal.principal_id.startswith("u_")
            or principal.api_key_id is not None
            or principal.expires_at <= int(time.time())
            or len(principal.grants) != 1
        ):
            raise AccountError(
                401, "A current identity-service human management token is required."
            )
        context, capabilities = next(iter(principal.grants.items()))
        names = [
            c.removeprefix("registry:publisher:")
            for c in capabilities
            if c.startswith("registry:publisher:")
        ]
        if len(names) != 1 or "registry:manage" not in capabilities:
            raise AccountError(403, "The token does not grant publisher management.")
        try:
            name = require_canonical_pack_name(names[0])
        except ValueError:
            raise AccountError(403, "The attested publisher name is not canonical.") from None
        if principal.organization_id is not None:
            if context != f"org:{principal.organization_id}":
                raise AccountError(403, "Organization management context is required.")
            subject = f"org:{principal.organization_id}"
        else:
            if not context.startswith("project:") or str(principal.account_id) != (
                principal.principal_id.removeprefix("u_")
            ):
                raise AccountError(403, "Personal management context is required.")
            subject = principal.principal_id
        return PublisherIdentity(subject, principal.principal_id, name)

    return identity


def account_router(database: Database, settings: ServerSettings) -> APIRouter:
    router = APIRouter(prefix="/v1/account", tags=["publisher account"])
    principals = PrincipalRepository(database)
    identity = management_identity(settings)

    def publisher(identity: PublisherIdentity, *, claim: bool = False) -> str:
        now = datetime.now(UTC).isoformat()
        try:
            with database.session() as session, session.begin():
                if not database.is_postgresql:
                    session.connection().exec_driver_sql("BEGIN IMMEDIATE")
                binding = session.scalar(
                    select(PublisherBindingRecord).where(
                        PublisherBindingRecord.identity_subject == identity.subject
                    )
                )
                if binding is not None:
                    session.get(PublisherRecord, binding.publisher_id, with_for_update=True)
                    session.refresh(binding, with_for_update=True)
                    if binding.identity_subject != identity.subject:
                        raise AccountError(403, "The publisher identity binding changed.")
                if binding is None:
                    if not claim:
                        raise AccountError(404, "Claim a publisher before managing tokens.")
                    if (
                        identity.name == "dinkster"
                        or session.get(PublisherRecord, identity.name) is not None
                    ):
                        raise AccountError(
                            409, "This publisher name is reserved or already claimed."
                        )
                    if session.get(RegistryUserRecord, identity.actor) is None:
                        session.add(RegistryUserRecord(id=identity.actor))
                        session.flush()
                    session.add(PublisherRecord(id=identity.name, display_name=identity.name))
                    session.flush()
                    binding = PublisherBindingRecord(
                        publisher_id=identity.name, identity_subject=identity.subject
                    )
                    session.add(binding)
                    session.add(
                        PrincipalAuditRecord(
                            actor=identity.actor,
                            action="claim-publisher",
                            subject=identity.name,
                            at=now,
                            details=identity.subject,
                        )
                    )
                name = binding.publisher_id
                if session.get(PublisherFreezeRecord, name) is not None:
                    raise AccountError(403, "This publisher is frozen; contact registry support.")
                if session.get(RegistryUserRecord, identity.actor) is None:
                    session.add(RegistryUserRecord(id=identity.actor))
                    session.flush()
                member = session.get(PublisherMembershipRecord, (name, identity.actor))
                if member is None:
                    session.add(
                        PublisherMembershipRecord(
                            publisher_id=name, user_id=identity.actor, role="owner"
                        )
                    )
                    session.add(
                        PrincipalAuditRecord(
                            actor=identity.actor,
                            action="identity-owner",
                            subject=name,
                            at=now,
                            details=identity.subject,
                        )
                    )
                return name
        except IntegrityError:
            raise AccountError(409, "Publisher claim conflicts with an existing binding.") from None

    @router.post("/publisher")
    def claim_publisher(who: Annotated[PublisherIdentity, Depends(identity)]) -> JSONResponse:
        return _json({"publisher": publisher(who, claim=True)}, 201)

    @router.get("/tokens")
    def list_tokens(who: Annotated[PublisherIdentity, Depends(identity)]) -> JSONResponse:
        name = publisher(who)
        try:
            records = principals.administered_tokens(name, who.actor, identity_subject=who.subject)
        except RegistryError:
            raise AccountError(403, "Token listing is forbidden.") from None
        return _json(
            {
                "publisher": name,
                "tokens": [
                    {k: v for k, v in asdict(record).items() if k != "secret_hash"}
                    for record in records
                ],
            }
        )

    @router.post("/tokens")
    def create_token(
        body: TokenCreate, who: Annotated[PublisherIdentity, Depends(identity)]
    ) -> JSONResponse:
        now = datetime.now(UTC)
        if not now < body.expires_at <= now + timedelta(days=90):
            raise AccountError(400, "Expiry must be in the future and at most 90 days away.")
        name = publisher(who)
        try:
            secret, record = principals.mint_token(
                name,
                who.actor,
                now.isoformat(),
                body.expires_at.isoformat(),
                pack=body.pack,
                identity_subject=who.subject,
            )
        except RegistryError:
            raise AccountError(403, "Token creation is forbidden.") from None
        return _json(
            {
                "secret": secret,
                "id": record.token_id,
                "publisher": name,
                "pack": record.pack,
                "expires_at": record.expires_at,
            },
            201,
        )

    @router.post("/tokens/{token_id}/revoke")
    def revoke_token(
        token_id: str, body: TokenRevoke, who: Annotated[PublisherIdentity, Depends(identity)]
    ) -> JSONResponse:
        name = publisher(who)
        if not body.reason.strip():
            raise AccountError(400, "A revocation reason is required.")
        try:
            records = principals.administered_tokens(name, who.actor, identity_subject=who.subject)
            if token_id not in {t.token_id for t in records}:
                raise RegistryError("token belongs to another publisher")
            principals.revoke_token(
                token_id,
                who.actor,
                datetime.now(UTC).isoformat(),
                body.reason,
                identity_subject=who.subject,
            )
        except RegistryError:
            raise AccountError(403, "Token revocation is forbidden.") from None
        return _json({"revoked": token_id})

    return router
