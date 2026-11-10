"""Signed release notices and independently anchored security trust."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
from typing import Annotated, Literal, Self, cast
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.alias_generators import to_camel

from .identifiers import require_canonical_pack_name
from .versioning import require_public_version

Digest = Annotated[str, Field(pattern=r"^(?:blake3|sha256):[0-9a-f]{64}$")]
KeyId = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Text = Annotated[str, Field(min_length=1)]


class SecurityError(ValueError):
    """A security document cannot be authenticated or accepted."""


class SecurityModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
        frozen=True,
        strict=True,
    )


class SecurityRelease(SecurityModel):
    pack: str
    version: str
    artifact_digest: Digest

    @field_validator("pack")
    @classmethod
    def canonical_pack(cls, value: str) -> str:
        require_canonical_pack_name(value)
        return value

    @field_validator("version")
    @classmethod
    def public_version(cls, value: str) -> str:
        require_public_version(value)
        return value


class SecurityNotice(SecurityModel):
    id: UUID
    revision: int = Field(gt=0)
    previous_revision: int | None = Field(default=None, gt=0)
    release: SecurityRelease
    state: Literal["malicious", "vulnerable", "affected"]
    status: Literal["active", "cleared"]
    actor: Text
    authority: Literal["security", "publisher"]
    security_confirmed: bool
    changed_at: datetime
    reason: Text
    message: Text
    incident: Text
    fixed_release: SecurityRelease | None = None
    fixed_lock_digest: Digest | None = None
    causes: tuple[Digest, ...] = ()

    @model_validator(mode="after")
    def notice_identity(self) -> Self:
        if self.changed_at.utcoffset() is None:
            raise ValueError("notice time must include its timezone")
        if self.previous_revision is not None and self.previous_revision >= self.revision:
            raise ValueError("previous notice revision must precede its replacement")
        if self.state == "affected" and not self.causes:
            raise ValueError("an affected notice must identify its malicious dependency digests")
        if self.state != "affected" and self.causes:
            raise ValueError("only affected notices carry dependency causes")
        if len(set(self.causes)) != len(self.causes):
            raise ValueError("dependency cause digests must be distinct")
        if self.authority == "publisher" and self.security_confirmed:
            raise ValueError("a publisher cannot confirm a security classification")
        if self.fixed_release is not None and self.fixed_release.pack != self.release.pack:
            raise ValueError("a suggested fixed release must belong to the affected pack")
        return self


class SecurityPayload(SecurityModel):
    registry: Text
    revision: int = Field(gt=0)
    issued_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def validity_period(self) -> Self:
        if self.issued_at.utcoffset() is None or self.expires_at.utcoffset() is None:
            raise ValueError("security document times must include their timezones")
        if self.expires_at <= self.issued_at:
            raise ValueError("expiry must follow issue time")
        return self


class OwnershipNotice(SecurityModel):
    kind: Literal["ownership_transferred"] = "ownership_transferred"
    id: UUID
    revision: int = Field(gt=0)
    pack_id: UUID
    pack: str
    previous_publisher: Text
    publisher: Text
    actor: Text
    changed_at: datetime
    reason: Text

    @model_validator(mode="after")
    def ownership_identity(self) -> Self:
        require_canonical_pack_name(self.pack)
        if self.changed_at.utcoffset() is None:
            raise ValueError("ownership change time must include its timezone")
        if self.publisher == self.previous_publisher:
            raise ValueError("ownership change must name a different publisher")
        return self


class SecurityDocument(SecurityPayload):
    format: Literal["dinkster.security/1"] = "dinkster.security/1"
    notices: tuple[SecurityNotice, ...]
    ownership_changes: tuple[OwnershipNotice, ...] = ()

    @model_validator(mode="after")
    def notice_revisions(self) -> Self:
        if len({notice.id for notice in self.notices}) != len(self.notices):
            raise ValueError("notice identities must be distinct")
        if any(notice.revision > self.revision for notice in self.notices):
            raise ValueError("notice revision exceeds document revision")
        if len({change.id for change in self.ownership_changes}) != len(self.ownership_changes):
            raise ValueError("ownership change identities must be distinct")
        if any(change.revision > self.revision for change in self.ownership_changes):
            raise ValueError("ownership change revision exceeds document revision")
        return self


def _decode(value: str, size: int) -> bytes:
    try:
        data = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError("invalid security base64 value") from exc
    if len(data) != size or base64.b64encode(data).decode("ascii") != value:
        raise ValueError("security base64 value has invalid size or encoding")
    return data


def security_key_id(public_key: bytes) -> str:
    Ed25519PublicKey.from_public_bytes(public_key)
    return "sha256:" + hashlib.sha256(public_key).hexdigest()


class SecurityKey(SecurityModel):
    key_id: KeyId
    public_key: str

    @model_validator(mode="after")
    def key_identity(self) -> Self:
        if security_key_id(_decode(self.public_key, 32)) != self.key_id:
            raise ValueError("security key identifier does not match its public bytes")
        return self


class SecurityTrust(SecurityPayload):
    format: Literal["dinkster.security-trust/1"] = "dinkster.security-trust/1"
    keys: tuple[SecurityKey, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_keys(self) -> Self:
        if len({key.key_id for key in self.keys}) != len(self.keys):
            raise ValueError("trusted security key identifiers must be distinct")
        return self


class SecuritySignature(SecurityModel):
    key_id: KeyId
    signature: str

    @field_validator("signature")
    @classmethod
    def signature_bytes(cls, value: str) -> str:
        _decode(value, 64)
        return value


class SecurityEnvelope(SecurityModel):
    signed: Annotated[SecurityDocument | SecurityTrust, Field(discriminator="format")]
    signatures: tuple[SecuritySignature, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def distinct_signers(self) -> Self:
        if len({signature.key_id for signature in self.signatures}) != len(self.signatures):
            raise ValueError("security signers must be distinct")
        return self


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def sign_security_document(
    document: SecurityDocument | SecurityTrust, key: Ed25519PrivateKey
) -> bytes:
    payload = document.model_dump(mode="json", by_alias=True)
    public = key.public_key().public_bytes_raw()
    return _canonical(
        {
            "signed": payload,
            "signatures": [
                {
                    "keyId": security_key_id(public),
                    "signature": base64.b64encode(key.sign(_canonical(payload))).decode("ascii"),
                }
            ],
        }
    )


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SecurityError("duplicate security document field")
        result[key] = value
    return result


def _authenticated(data: bytes, trust: SecurityTrust) -> SecurityDocument | SecurityTrust:
    try:
        raw = cast("dict[str, object]", json.loads(data, object_pairs_hook=_unique_fields))
        envelope = SecurityEnvelope.model_validate_json(data)
        if envelope.signed.registry != trust.registry:
            raise SecurityError("security document registry differs from trusted registry")
        payload = _canonical(raw["signed"])
        keys = {key.key_id: _decode(key.public_key, 32) for key in trust.keys}
        for signature in envelope.signatures:
            if signature.key_id not in keys:
                continue
            try:
                Ed25519PublicKey.from_public_bytes(keys[signature.key_id]).verify(
                    _decode(signature.signature, 64), payload
                )
            except InvalidSignature:
                continue
            return envelope.signed
    except (ValueError, TypeError, KeyError) as exc:
        raise SecurityError("invalid security document; update for unsupported formats") from exc
    raise SecurityError("security document has no valid independently trusted signature")


def verify_security_document(
    data: bytes, trust: SecurityTrust, *, previous: SecurityDocument | None = None
) -> SecurityDocument:
    document = _authenticated(data, trust)
    if not isinstance(document, SecurityDocument):
        raise SecurityError("expected release security notices, not a trust update")
    if previous is not None:
        if previous.registry != trust.registry:
            raise SecurityError("cached security document belongs to another registry")
        if document.revision < previous.revision:
            raise SecurityError("security document revision rolled back")
        if document.revision == previous.revision and document != previous:
            raise SecurityError("security document changed without a new revision")
        current = {notice.id: notice for notice in document.notices}
        for old in previous.notices:
            updated = current.get(old.id)
            if updated is None or updated.revision < old.revision:
                raise SecurityError("security update dropped a notice or its clearing record")
            if updated.release != old.release:
                raise SecurityError("security notice replacement changed its release identity")
            if updated != old and (
                updated.revision <= old.revision
                or updated.previous_revision is None
                or updated.previous_revision < old.revision
            ):
                raise SecurityError("security notice replacement does not name its predecessor")
        ownership = {change.id: change for change in document.ownership_changes}
        if any(ownership.get(change.id) != change for change in previous.ownership_changes):
            raise SecurityError("security update dropped or changed an ownership record")
    return document


def verify_security_trust(data: bytes, trust: SecurityTrust) -> SecurityTrust:
    replacement = _authenticated(data, trust)
    if not isinstance(replacement, SecurityTrust):
        raise SecurityError("expected a security trust update")
    if replacement.revision <= trust.revision:
        raise SecurityError("security trust update must increase its revision")
    return replacement
