from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from dinkster_registry_service.security import (
    OwnershipNotice,
    SecurityDocument,
    SecurityError,
    SecurityKey,
    SecurityNotice,
    SecurityRelease,
    SecurityTrust,
    security_key_id,
    sign_security_document,
    verify_security_document,
    verify_security_trust,
)

NOW = datetime(2026, 11, 10, tzinfo=UTC)


def _trust(key: Ed25519PrivateKey, revision: int = 1) -> SecurityTrust:
    public = key.public_key().public_bytes_raw()
    return SecurityTrust(
        registry="https://registry.example",
        revision=revision,
        issued_at=NOW,
        expires_at=NOW + timedelta(days=30),
        keys=(
            SecurityKey(
                key_id=security_key_id(public), public_key=base64.b64encode(public).decode("ascii")
            ),
        ),
    )


def _notice() -> SecurityNotice:
    return SecurityNotice(
        id=UUID("9d21499e-03fc-45c1-bce3-0f1dc84c4a77"),
        revision=1,
        release=SecurityRelease(
            pack="example-pack", version="1.2.3", artifact_digest="blake3:" + "a" * 64
        ),
        state="malicious",
        status="active",
        actor="security-responder",
        authority="security",
        security_confirmed=True,
        changed_at=NOW,
        reason="compromised-release",
        message="Do not execute this artifact.",
        incident="https://registry.example/incidents/example",
    )


def _document(notice: SecurityNotice | None = None, revision: int = 1) -> SecurityDocument:
    return SecurityDocument(
        registry="https://registry.example",
        revision=revision,
        issued_at=NOW,
        expires_at=NOW + timedelta(days=1),
        notices=(_notice() if notice is None else notice,),
    )


def test_authenticated_notices_reject_tampering_unknown_keys_and_registry() -> None:
    key = Ed25519PrivateKey.generate()
    trust = _trust(key)
    document = _document()
    signed = sign_security_document(document, key)
    assert verify_security_document(signed, trust) == document
    changed = json.loads(signed)
    changed["signed"]["notices"][0]["status"] = "cleared"
    with pytest.raises(SecurityError, match="trusted signature"):
        verify_security_document(json.dumps(changed).encode(), trust)
    with pytest.raises(SecurityError, match="trusted signature"):
        verify_security_document(signed, _trust(Ed25519PrivateKey.generate()))
    other = SecurityTrust.model_validate_json(
        trust.model_dump_json().replace("https://registry.example", "https://unrelated.example")
    )
    with pytest.raises(SecurityError):
        verify_security_document(signed, other)
    with pytest.raises(SecurityError):
        verify_security_document(
            signed.replace(b'"revision":1', b'"revision":1,"revision":2'), trust
        )


def test_cached_notice_needs_explicit_newer_correction_and_cannot_disappear() -> None:
    key = Ed25519PrivateKey.generate()
    trust = _trust(key)
    previous = _document()
    correction = SecurityNotice(
        **{
            **_notice().model_dump(),
            "revision": 2,
            "previous_revision": 1,
            "status": "cleared",
        }
    )
    document = _document(correction, revision=2)
    assert (
        verify_security_document(sign_security_document(document, key), trust, previous=previous)
        .notices[0]
        .status
        == "cleared"
    )
    missing = SecurityDocument(**{**document.model_dump(), "notices": ()})
    with pytest.raises(SecurityError, match="dropped"):
        verify_security_document(sign_security_document(missing, key), trust, previous=previous)
    with pytest.raises(SecurityError, match="rolled back"):
        verify_security_document(sign_security_document(previous, key), trust, previous=document)
    equivocation = _document(SecurityNotice(**{**_notice().model_dump(), "message": "Different"}))
    with pytest.raises(SecurityError, match="new revision"):
        verify_security_document(
            sign_security_document(equivocation, key), trust, previous=previous
        )
    skipped = SecurityNotice(**{**correction.model_dump(), "revision": 5, "previous_revision": 4})
    assert verify_security_document(
        sign_security_document(_document(skipped, revision=5), key), trust, previous=previous
    ).notices == (skipped,)


def test_trust_rotation_requires_existing_authority_and_preserves_cached_block() -> None:
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate()
    trusted = _trust(old)
    replacement = _trust(new, revision=2)
    with pytest.raises(SecurityError, match="trusted signature"):
        verify_security_trust(sign_security_document(replacement, new), trusted)
    rotated = verify_security_trust(sign_security_document(replacement, old), trusted)
    assert rotated == replacement
    cached = _document()
    assert (
        verify_security_document(sign_security_document(cached, new), rotated, previous=cached)
        == cached
    )
    with pytest.raises(SecurityError, match="trusted signature"):
        verify_security_document(sign_security_document(cached, old), rotated, previous=cached)
    with pytest.raises(SecurityError, match="increase"):
        verify_security_trust(sign_security_document(trusted, old), trusted)


def test_notice_validation_distinguishes_affected_dependencies_and_bad_inputs() -> None:
    data = _notice().model_dump()
    with pytest.raises(ValidationError, match="dependency digests"):
        SecurityNotice(**{**data, "state": "affected"})
    affected = SecurityNotice(**{**data, "state": "affected", "causes": ("sha256:" + "b" * 64,)})
    assert affected.state == "affected" and affected.release == _notice().release
    with pytest.raises(ValidationError):
        SecurityNotice(**{**data, "authority": "publisher"})
    with pytest.raises(ValidationError):
        SecurityNotice(**{**data, "changed_at": NOW.replace(tzinfo=None)})
    with pytest.raises(ValidationError):
        SecurityDocument(**{**_document().model_dump(), "revision": True})
    with pytest.raises(ValidationError):
        SecurityDocument(**{**_document().model_dump(), "notices": (_notice(), _notice())})


def test_signed_ownership_change_preserves_pack_identity_and_audit_event() -> None:
    key = Ed25519PrivateKey.generate()
    change = OwnershipNotice(
        id=UUID("85edcc7a-04e5-4c95-a48a-9bb336ad7025"),
        revision=2,
        pack_id=UUID("935eeec6-a540-47cb-898d-c06c3ff63e36"),
        pack="example-pack",
        previous_publisher="original",
        publisher="replacement",
        actor="security-responder",
        changed_at=NOW,
        reason="Abandoned pack needs a security update.",
    )
    document = SecurityDocument(
        **{**_document(revision=2).model_dump(), "ownership_changes": (change,)}
    )
    assert verify_security_document(sign_security_document(document, key), _trust(key)) == document
    operator_change = OwnershipNotice.model_validate(
        {**change.model_dump(), "previous_publisher": None}
    )
    operator_document = SecurityDocument(
        **{**document.model_dump(), "ownership_changes": (operator_change,)}
    )
    assert (
        verify_security_document(sign_security_document(operator_document, key), _trust(key))
        == operator_document
    )
    missing = change.model_dump()
    del missing["previous_publisher"]
    with pytest.raises(ValidationError):
        OwnershipNotice.model_validate(missing)
    for invalid in ("", "original"):
        with pytest.raises(ValidationError):
            OwnershipNotice.model_validate({**change.model_dump(), "publisher": invalid})
    with pytest.raises(SecurityError, match="ownership"):
        verify_security_document(
            sign_security_document(_document(revision=3), key), _trust(key), previous=document
        )
