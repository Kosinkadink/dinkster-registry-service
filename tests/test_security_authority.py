from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from typing import Any
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dinkster_registry import RegistryError
from dinkster_token_verifier import TokenVerifier
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import OKPKey
from sqlalchemy import delete, event, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from dinkster_registry_service import accounts
from dinkster_registry_service.app import create_app
from dinkster_registry_service.artifacts import build_registry_fixture_archive
from dinkster_registry_service.database import (
    AuditEventRecord,
    Database,
    NamespaceGrantRecord,
    OutboxRecord,
    PackRecord,
    PublisherMembershipRecord,
    PublisherTokenRecord,
    ReleaseRecord,
)
from dinkster_registry_service.object_store import LocalFilesystemObjectStore
from dinkster_registry_service.ownership import transfer_ownership
from dinkster_registry_service.principals import PrincipalRepository
from dinkster_registry_service.security import SecurityRelease, sign_security_document
from dinkster_registry_service.security_repository import (
    NoticeChange,
    SecurityRepository,
    UploadChange,
)
from dinkster_registry_service.seed import FIXTURE_ROOT, seed_fixtures
from dinkster_registry_service.settings import ServerSettings


@pytest.fixture
def management_headers(monkeypatch: pytest.MonkeyPatch) -> Callable[..., dict[str, str]]:
    key = OKPKey.generate_key("Ed25519", auto_kid=True)
    jwk = {**key.as_dict(private=False), "alg": "Ed25519", "use": "sig"}
    verifier = TokenVerifier(
        issuer="https://id.dinkster.org",
        audience="dinkster-registry",
        jwks_url="https://id.dinkster.org/.well-known/jwks.json",
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"keys": [jwk]}))
        ),
    )
    monkeypatch.setattr(accounts, "TokenVerifier", lambda **kwargs: verifier)
    project = uuid4()

    def credential(actor: str, name: str, **overrides: Any) -> dict[str, str]:
        now = int(datetime.now(UTC).timestamp())
        claims = {
            "iss": "https://id.dinkster.org",
            "aud": "dinkster-registry",
            "sub": actor,
            "kind": "human",
            "org": None,
            "acct": actor.removeprefix("u_"),
            "key": None,
            "key_scopes": None,
            "grants": {f"project:{project}": ["registry:manage", f"registry:publisher:{name}"]},
            "iat": now,
            "exp": now + 60,
            "jti": str(uuid4()),
            **overrides,
        }
        token = jwt.encode({"alg": "Ed25519", "kid": key.kid}, claims, key, algorithms=["Ed25519"])
        return {"Authorization": f"Bearer {token}"}

    return credential


def test_security_authority_history_and_clearing_survive_reopen(
    tmp_path: Path, management_headers: Callable[..., dict[str, str]]
) -> None:
    settings = ServerSettings(
        database_url=f"sqlite:///{tmp_path / 'security.db'}",
        object_store_root=tmp_path / "objects",
        public_base_url="http://testserver",
    )
    app = create_app(settings)
    database = app.state.database
    seed_fixtures(database, app.state.object_store)
    principals = PrincipalRepository(database)
    now = datetime.now(UTC)
    headers = {}
    publish_headers = {}
    actors = {}
    for user in ("operator", "publisher", "responder", "outsider", "colleague"):
        actors[user] = actor = f"u_{uuid4()}"
        principals.register_user(actor)
        principals.register_publisher(user, actor, now.isoformat())
        plaintext, _ = principals.mint_token(
            user, actor, now.isoformat(), (now + timedelta(hours=1)).isoformat()
        )
        publish_headers[user] = {"Authorization": f"Bearer {plaintext}"}
        headers[user] = (
            management_headers(actor, user)
            if user in {"operator", "responder", "outsider"}
            else publish_headers[user]
        )
    principals.add_operator(actors["operator"], actors["operator"], now.isoformat())
    with database.session() as session, session.begin():
        pack = session.scalar(select(PackRecord).where(PackRecord.name == "example-pack"))
        assert pack is not None
        pack.publisher_id = "publisher"
        session.add(
            PublisherMembershipRecord(
                publisher_id="publisher", user_id=actors["colleague"], role="member"
            )
        )
        release = session.scalar(select(ReleaseRecord).where(ReleaseRecord.pack_id == pack.id))
        assert release is not None
        identity = {
            "pack": pack.name,
            "version": release.version,
            "artifactDigest": release.artifact_digest,
        }
        original_state = release.state
    change = {
        "operation": "issue",
        "release": identity,
        "expectedRevision": 0,
        "state": "vulnerable",
        "reason": "unsafe-input",
        "message": "A fix is available.",
        "incident": "https://example.test/incidents/1",
    }
    client = TestClient(app)
    endpoint = "/v1/security/notices"
    role = {"enabled": True, "reason": "incident responder"}
    assert client.post(endpoint, json=change).status_code == 401
    assert (
        client.put(
            f"/v1/security/roles/{actors['outsider']}", json=role, headers=headers["outsider"]
        ).status_code
        == 403
    )
    assert (
        client.put(
            f"/v1/security/roles/{actors['responder']}", json=role, headers=headers["operator"]
        ).status_code
        == 200
    )
    assert (
        client.put(
            f"/v1/security/roles/{actors['outsider']}",
            json=role,
            headers=publish_headers["operator"],
        ).status_code
        == 401
    )
    assert (
        client.post(endpoint, json=change, headers=publish_headers["responder"]).status_code == 403
    )
    for overrides in (
        {"aud": "another-service"},
        {"kind": "agent"},
        {"key": str(uuid4())},
        {"exp": int(now.timestamp()) - 1},
    ):
        assert (
            client.post(
                endpoint,
                json=change,
                headers=management_headers(actors["responder"], "responder", **overrides),
            ).status_code
            == 401
        )
    assert client.post(endpoint, json=change, headers=headers["outsider"]).status_code == 403
    for invalid in (
        {**identity, "artifactDigest": "blake3:" + "0" * 64},
        {**identity, "pack": "missing-pack"},
        {**identity, "version": "999.0"},
    ):
        assert (
            client.post(
                endpoint, json={**change, "release": invalid}, headers=headers["publisher"]
            ).status_code
            == 403
        )
    scoped, _ = principals.mint_token(
        "publisher",
        actors["publisher"],
        now.isoformat(),
        (now + timedelta(hours=1)).isoformat(),
        pack="color-tools",
    )
    assert (
        client.post(
            endpoint, json=change, headers={"Authorization": f"Bearer {scoped}"}
        ).status_code
        == 403
    )
    assert (
        client.put(
            f"/v1/security/roles/{actors['publisher']}", json=role, headers=headers["operator"]
        ).status_code
        == 200
    )
    issued = client.post(endpoint, json=change, headers=headers["publisher"])
    assert issued.status_code == 200, issued.text
    first = issued.json()
    assert first["status"] == "active" and first["authority"] == "publisher"
    withdraw = {**change, "operation": "withdraw", "expectedRevision": first["revision"]}
    colleague, _ = principals.mint_token(
        "publisher", actors["colleague"], now.isoformat(), (now + timedelta(hours=1)).isoformat()
    )
    cleared = client.post(endpoint, json=withdraw, headers={"Authorization": f"Bearer {colleague}"})
    assert cleared.status_code == 200 and cleared.json()["status"] == "cleared"
    reissue = {**change, "expectedRevision": cleared.json()["revision"]}
    active = client.post(endpoint, json=reissue, headers=headers["publisher"]).json()
    confirmed = client.post(
        endpoint,
        json={**change, "operation": "confirm", "expectedRevision": active["revision"]},
        headers=headers["responder"],
    )
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["securityConfirmed"] is True
    stale = client.post(endpoint, json=withdraw, headers=headers["publisher"])
    assert stale.status_code == 403
    assert (
        client.post(
            endpoint,
            json={**withdraw, "expectedRevision": confirmed.json()["revision"]},
            headers=headers["publisher"],
        ).status_code
        == 403
    )
    correction = client.post(
        endpoint,
        json={
            **change,
            "operation": "correct",
            "state": "malicious",
            "expectedRevision": confirmed.json()["revision"],
        },
        headers=headers["responder"],
    )
    assert correction.status_code == 200, correction.text
    for user in ("publisher", "operator"):
        assert (
            client.post(
                endpoint,
                json={
                    **change,
                    "operation": "lift",
                    "state": "malicious",
                    "expectedRevision": correction.json()["revision"],
                },
                headers=headers[user],
            ).status_code
            == 403
        )
    lifted = client.post(
        endpoint,
        json={
            **change,
            "operation": "lift",
            "state": "malicious",
            "expectedRevision": correction.json()["revision"],
        },
        headers=headers["responder"],
    )
    assert lifted.status_code == 200 and lifted.json()["status"] == "cleared"
    history = client.get(endpoint + "/history", headers=headers["publisher"]).json()["notices"]
    assert [row["status"] for row in history] == [
        "active",
        "cleared",
        "active",
        "active",
        "active",
        "cleared",
    ]
    assert [row["state"] for row in history] == ["vulnerable"] * 4 + ["malicious"] * 2
    assert len({row["id"] for row in history}) == 1
    assert all(a["revision"] < b["revision"] for a, b in zip(history, history[1:], strict=False))
    database.dispose()
    reopened = create_app(settings)
    repository = SecurityRepository(reopened.state.database, settings.public_base_url)
    assert [row.model_dump(mode="json", by_alias=True) for row in repository.history()] == history
    document = repository.document(issued_at=now, expires_at=now + timedelta(hours=1))
    assert len(document.notices) == 1 and document.notices[0].status == "cleared"
    assert b'"cleared"' in sign_security_document(document, Ed25519PrivateKey.generate())
    with reopened.state.database.session() as session:
        stored = session.scalar(
            select(ReleaseRecord).where(ReleaseRecord.artifact_digest == identity["artifactDigest"])
        )
        assert stored is not None and stored.state == original_state
    for mutation in (
        update(AuditEventRecord)
        .where(AuditEventRecord.event_type == "security.notice")
        .values(data={}),
        delete(AuditEventRecord).where(AuditEventRecord.event_type == "security.notice"),
    ):
        with pytest.raises(IntegrityError, match="immutable"):
            with reopened.state.database.session() as session, session.begin():
                session.execute(mutation)
    assert [row.model_dump(mode="json", by_alias=True) for row in repository.history()] == history
    malicious = client.post(
        endpoint,
        json={**change, "state": "malicious", "expectedRevision": history[-1]["revision"]},
        headers=headers["publisher"],
    )
    assert malicious.status_code == 200, malicious.text
    assert (
        client.post(
            endpoint,
            json={
                **change,
                "operation": "withdraw",
                "state": "malicious",
                "expectedRevision": malicious.json()["revision"],
            },
            headers=headers["publisher"],
        ).status_code
        == 403
    )
    reopened.state.database.dispose()


def test_upload_stops_cover_pack_and_publisher_without_changing_published_releases(
    tmp_path: Path, management_headers: Callable[..., dict[str, str]]
) -> None:
    settings = ServerSettings(
        database_url=f"sqlite:///{tmp_path / 'security.db'}",
        object_store_root=tmp_path / "objects",
        public_base_url="http://testserver",
    )
    app = create_app(settings)
    database = app.state.database
    seed_fixtures(database, app.state.object_store)
    principals = PrincipalRepository(database)
    now = datetime.now(UTC)
    headers = {}
    actors = {}
    publish_headers = {}
    for user in ("owner", "responder", "other"):
        actors[user] = actor = f"u_{uuid4()}"
        principals.register_user(actor)
        principals.register_publisher(user, actor, now.isoformat())
        plaintext, _ = principals.mint_token(
            user, actor, now.isoformat(), (now + timedelta(hours=1)).isoformat()
        )
        publish_headers[user] = {"Authorization": f"Bearer {plaintext}"}
        headers[user] = (
            management_headers(actor, user) if user == "responder" else publish_headers[user]
        )
    principals.add_operator(actors["owner"], actors["owner"], now.isoformat())
    repository = SecurityRepository(database, settings.public_base_url)
    repository.set_role(
        actor=actors["owner"], user=actors["responder"], enabled=True, reason="response"
    )
    with database.session() as session, session.begin():
        for pack in session.scalars(select(PackRecord)):
            pack.publisher_id = "owner"
        original = {
            row.id: (row.state, row.artifact_digest)
            for row in session.scalars(select(ReleaseRecord))
        }
    client = TestClient(app)
    archive = build_registry_fixture_archive(FIXTURE_ROOT / "example-pack")
    endpoint = "/v1/security/uploads"
    stop = {"subjectType": "pack", "subject": "example-pack", "stopped": True, "reason": "review"}
    assert client.put(endpoint, json=stop, headers=publish_headers["responder"]).status_code == 403
    assert client.put(endpoint, json=stop, headers=headers["other"]).status_code == 403
    assert client.put(endpoint, json=stop, headers=headers["owner"]).status_code == 200
    assert (
        client.post(
            "/v1/publish/example-pack/versions/1.2.4", content=archive, headers=headers["owner"]
        ).status_code
        == 409
    )
    assert (
        client.put(
            endpoint, json={**stop, "stopped": False}, headers=headers["responder"]
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/v1/publish/example-pack/versions/1.2.4", content=archive, headers=headers["owner"]
        ).status_code
        == 202
    )
    assert client.put(endpoint, json=stop, headers=headers["responder"]).status_code == 200
    # Repeating the stop cannot downgrade security authority to publisher authority.
    assert client.put(endpoint, json=stop, headers=headers["owner"]).status_code == 200
    assert (
        client.put(endpoint, json={**stop, "stopped": False}, headers=headers["owner"]).status_code
        == 403
    )
    assert (
        client.put(
            endpoint, json={**stop, "stopped": False}, headers=headers["responder"]
        ).status_code
        == 200
    )
    publisher_stop = {**stop, "subjectType": "publisher", "subject": "owner"}
    assert client.put(endpoint, json=publisher_stop, headers=headers["owner"]).status_code == 403
    assert (
        client.put(endpoint, json=publisher_stop, headers=headers["responder"]).status_code == 200
    )
    for name in ("example-pack", "color-tools", "new-pack"):
        assert (
            client.post(
                f"/v1/publish/{name}/versions/2.0", content=archive, headers=headers["owner"]
            ).status_code
            == 409
        )
    assert (
        client.post(
            "/v1/publish/unrelated-pack/versions/2.0", content=archive, headers=headers["other"]
        ).status_code
        == 202
    )
    assert (
        client.put(
            endpoint, json={**publisher_stop, "stopped": False}, headers=headers["responder"]
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/v1/publish/new-pack/versions/2.0", content=archive, headers=headers["owner"]
        ).status_code
        == 202
    )
    with database.session() as session:
        assert {
            row.id: (row.state, row.artifact_digest)
            for row in session.scalars(select(ReleaseRecord))
        } == original
    database.dispose()


def test_concurrent_security_changes_have_one_winner_and_role_revocation_is_effective(
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore],
) -> None:
    database, _ = seeded_catalog
    principals = PrincipalRepository(database)
    now = datetime.now(UTC).isoformat()
    for user in ("operator", "responder"):
        principals.register_user(user)
    principals.add_operator("operator", "operator", now)
    repository = SecurityRepository(database, "https://registry.example")
    repository.set_role(actor="operator", user="responder", enabled=True, reason="response")
    with database.session() as session:
        pack = session.scalar(select(PackRecord).where(PackRecord.name == "example-pack"))
        assert pack is not None
        release = session.scalar(select(ReleaseRecord).where(ReleaseRecord.pack_id == pack.id))
        assert release is not None
        identity = SecurityRelease(
            pack=pack.name, version=release.version, artifact_digest=release.artifact_digest
        )
    change = NoticeChange(
        operation="issue",
        release=identity,
        expected_revision=0,
        state="vulnerable",
        reason="review",
        message="Details",
        incident="case1",
    )
    original = repository.change(actor="responder", change=change)
    start = Barrier(2)

    def update(operation: str) -> str:
        body = NoticeChange.model_validate_json(change.model_dump_json())
        body = NoticeChange.model_validate_json(
            body.model_copy(
                update={"operation": operation, "expected_revision": original.revision}
            ).model_dump_json()
        )
        start.wait(timeout=10)
        try:
            repository.change(actor="responder", change=body)
        except RegistryError as exc:
            assert "current revision" in str(exc)
            return "conflict"
        return "changed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(update, ("confirm", "lift")))
    assert sorted(results) == ["changed", "conflict"]
    history = repository.history()
    assert len(history) == 2
    assert history[1].previous_revision == history[0].revision
    assert history[1].revision > history[0].revision
    repository.set_role(actor="operator", user="responder", enabled=False, reason="shift ended")
    next_change = change.model_copy(update={"expected_revision": history[-1].revision})
    with pytest.raises(RegistryError):
        repository.change(actor="responder", change=next_change)


def test_pack_transfer_return_and_atomic_notice(
    tmp_path: Path,
    management_headers: Callable[..., dict[str, str]],
) -> None:
    app = create_app(
        ServerSettings(
            database_url=f"sqlite:///{tmp_path / 'transfer.db'}",
            object_store_root=tmp_path / "objects",
            public_base_url="http://testserver",
        )
    )
    database = app.state.database
    seed_fixtures(database, app.state.object_store)
    principals = PrincipalRepository(database)
    now = datetime.now(UTC)
    actors = {name: f"u_{uuid4()}" for name in ("original", "replacement", "responder")}
    for name, actor in actors.items():
        principals.register_user(actor)
        principals.register_publisher(name, actor, now.isoformat())
    principals.add_operator(actors["responder"], actors["responder"], now.isoformat())
    security = SecurityRepository(database, "http://testserver")
    security.set_role(
        actor=actors["responder"], user=actors["responder"], enabled=True, reason="response"
    )
    tokens = {}
    for scope in (None, "example-pack", "another-pack"):
        _, tokens[scope] = principals.mint_token(
            "original",
            actors["original"],
            now.isoformat(),
            (now + timedelta(hours=1)).isoformat(),
            pack=scope,
        )
    with database.session() as session:
        pack = session.scalar(select(PackRecord).where(PackRecord.name == "example-pack"))
        assert pack is not None
        pack_id = pack.id
        releases = {
            row.id: (row.artifact_digest, row.state, row.manifest)
            for row in session.scalars(
                select(ReleaseRecord).where(ReleaseRecord.pack_id == pack_id)
            )
        }
    endpoint = f"/v1/security/packs/{pack_id}/ownership"
    client = TestClient(app)
    headers = management_headers(actors["responder"], "responder")
    body = {"expectedOwner": None, "targetOwner": "original", "reason": "case review"}
    assert client.post(endpoint, json=body).status_code == 401
    assert (
        client.post(
            endpoint, json=body, headers=management_headers(actors["original"], "original")
        ).status_code
        == 403
    )
    missing = {key: value for key, value in body.items() if key != "expectedOwner"}
    assert client.post(endpoint, json=missing, headers=headers).status_code == 400
    first = client.post(endpoint, json=body, headers=headers)
    assert first.status_code == 200, first.text
    assert client.post(endpoint, json=body, headers=headers).status_code == 403
    body.update(expectedOwner="original", targetOwner="replacement")
    second = client.post(endpoint, json=body, headers=headers)
    assert second.status_code == 200, second.text
    with database.session() as session:
        pack = session.get(PackRecord, pack_id)
        assert pack is not None and pack.publisher_id == "replacement"
        for grant in session.scalars(
            select(NamespaceGrantRecord).where(NamespaceGrantRecord.pack_id == pack_id)
        ):
            assert (grant.publisher_id, grant.owner_id) == ("replacement", pack.owner_id)
        for scope, token in tokens.items():
            stored = session.get(PublisherTokenRecord, token.token_id)
            assert stored is not None and stored.revoked == (scope == "example-pack")
        assert session.get(PublisherMembershipRecord, ("original", actors["original"])) is not None
        assert {
            row.id: (row.artifact_digest, row.state, row.manifest)
            for row in session.scalars(
                select(ReleaseRecord).where(ReleaseRecord.pack_id == pack_id)
            )
        } == releases
    with pytest.raises(RegistryError), security.transaction() as session:
        security.authorize_upload(session, tokens[None], "example-pack", None)
    body.update(expectedOwner="replacement", targetOwner="original")
    assert (
        client.post(
            endpoint, json=body, headers=management_headers(actors["original"], "original")
        ).status_code
        == 403
    )
    returned = client.post(endpoint, json=body, headers=headers)
    assert returned.status_code == 200, returned.text
    document = security.document(issued_at=now, expires_at=now + timedelta(days=1))
    assert [notice.previous_publisher for notice in document.ownership_changes] == [
        None,
        "original",
        "replacement",
    ]
    assert [str(notice.id) for notice in document.ownership_changes] == [
        response.json()["auditId"] for response in (first, second, returned)
    ]
    with database.session() as session:
        rows = session.scalars(select(OutboxRecord).where(OutboxRecord.topic == "security.publish"))
        assert [row.payload["auditId"] for row in rows] == [
            str(notice.id) for notice in document.ownership_changes
        ]

    # A persistence failure after ownership mutation must roll back every part.
    def fail_outbox(session: Session, *_args: Any) -> None:
        if any(
            isinstance(row, OutboxRecord) and row.topic == "security.publish" for row in session.new
        ):
            raise RuntimeError("outbox unavailable")

    event.listen(Session, "before_flush", fail_outbox)
    try:
        with pytest.raises(RuntimeError, match="outbox unavailable"):
            with database.session() as session, session.begin():
                transfer_ownership(
                    session,
                    actor=actors["responder"],
                    subject_kind="pack",
                    subject_id=str(pack_id),
                    expected_owner="original",
                    target_owner="replacement",
                    reason="retry",
                    at=now,
                )
    finally:
        event.remove(Session, "before_flush", fail_outbox)
    assert security.document(issued_at=now, expires_at=now + timedelta(days=1)) == document
    with database.session() as session:
        pack = session.get(PackRecord, pack_id)
        assert pack is not None and pack.publisher_id == "original"
        assert (
            len(
                session.scalars(
                    select(AuditEventRecord).where(
                        AuditEventRecord.event_type == "ownership.transferred"
                    )
                ).all()
            )
            == 3
        )
        release = session.scalar(select(ReleaseRecord).where(ReleaseRecord.pack_id == pack_id))
        assert release is not None
        identity = SecurityRelease(
            pack="example-pack", version=release.version, artifact_digest=release.artifact_digest
        )
    principals.revoke_token(tokens[None].token_id, actors["original"], now.isoformat(), "removed")
    with pytest.raises(RegistryError):
        security.change(
            actor=actors["original"],
            token=tokens[None],
            change=NoticeChange(
                operation="issue",
                release=identity,
                expected_revision=0,
                state="vulnerable",
                reason="report",
                message="details",
                incident="case",
            ),
        )
    with pytest.raises(RegistryError):
        security.set_uploads(
            actor=actors["original"],
            token=tokens[None],
            change=UploadChange(
                subject_type="pack", subject="example-pack", stopped=True, reason="stop"
            ),
        )
    database.dispose()


def test_concurrent_pack_transfers_have_one_winner(
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore],
) -> None:
    database, _ = seeded_catalog
    principals = PrincipalRepository(database)
    now = datetime.now(UTC)
    principals.register_user("responder")
    principals.add_operator("responder", "responder", now.isoformat())
    for name in ("first", "second"):
        principals.register_user(name)
        principals.register_publisher(name, name, now.isoformat())
    security = SecurityRepository(database, "https://registry.example")
    security.set_role(actor="responder", user="responder", enabled=True, reason="response")
    with database.session() as session:
        pack = session.scalar(select(PackRecord).where(PackRecord.name == "example-pack"))
        assert pack is not None
        pack_id = pack.id
    start = Barrier(2)

    def transfer(target: str) -> str:
        start.wait(timeout=10)
        try:
            with database.session() as session, session.begin():
                transfer_ownership(
                    session,
                    actor="responder",
                    subject_kind="pack",
                    subject_id=str(pack_id),
                    expected_owner=None,
                    target_owner=target,
                    reason="case-specific takeover",
                    at=now,
                )
        except RegistryError as exc:
            assert "owner changed" in str(exc)
            return "conflict"
        return "changed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(transfer, ("first", "second"))) == ["changed", "conflict"]
    document = security.document(issued_at=now, expires_at=now + timedelta(days=1))
    assert len(document.ownership_changes) == 1
    with database.session() as session:
        pack = session.get(PackRecord, pack_id)
        assert pack is not None and pack.publisher_id == document.ownership_changes[0].publisher
